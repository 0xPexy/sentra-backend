package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/accounts/abi"
)

type Reader struct {
	repo *store.Repository
}

func NewReader(repo *store.Repository) *Reader {
	return &Reader{repo: repo}
}

const selectorSentinel = "-"

func sanitizeSelector(sel string) string {
	if sel == "" || sel == selectorSentinel {
		return ""
	}
	return strings.ToLower(sel)
}

func weiToGweiString(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "0"
	}
	wei, ok := new(big.Int).SetString(raw, 10)
	if !ok || wei.Sign() == 0 {
		return "0"
	}
	f := new(big.Float).SetInt(wei)
	gwei := new(big.Float).Quo(f, big.NewFloat(1e9))
	text := strings.TrimRight(strings.TrimRight(gwei.Text('f', 9), "0"), ".")
	if text == "" {
		return "0"
	}
	return text
}

type Status struct {
	ChainID     uint64 `json:"chainId"`
	CurrentHead uint64 `json:"currentHead"`
	SafeHead    uint64 `json:"safeHead"`
	LastIndexed uint64 `json:"lastIndexed"`
	LagBlocks   uint64 `json:"lagBlocks"`
	IngestLagMs int64  `json:"ingestLagMs"`
	LastEventAt *time.Time
}

func (r *Reader) Status(ctx context.Context, chainID uint64) (*Status, error) {
	statusRow, err := r.repo.GetIndexerStatus(ctx, chainID)
	if err != nil {
		return nil, err
	}
	latest, err := r.repo.LatestUserOperation(ctx, chainID)
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	var currentHead uint64
	var eventTime *time.Time
	if latest != nil {
		currentHead = latest.BlockNumber
		if !latest.BlockTime.IsZero() {
			t := latest.BlockTime
			eventTime = &t
		}
	}

	lastIndexed := statusRow.LastIndexed
	safeHead := currentHead
	if safeHead == 0 {
		safeHead = lastIndexed
	}
	var lagBlocks uint64
	if currentHead > lastIndexed {
		lagBlocks = currentHead - lastIndexed
	}
	var ingestLagMs int64
	if eventTime != nil {
		ingestLagMs = time.Since(*eventTime).Milliseconds()
	}

	return &Status{
		ChainID:     chainID,
		CurrentHead: currentHead,
		SafeHead:    safeHead,
		LastIndexed: lastIndexed,
		LagBlocks:   lagBlocks,
		IngestLagMs: ingestLagMs,
		LastEventAt: eventTime,
	}, nil
}

type ListUserOpsParams struct {
	ChainID   uint64
	Sender    string
	Paymaster string
	Status    string
	FromBlock *uint64
	ToBlock   *uint64
	Page      int
	Limit     int
	SortDesc  bool
}

type UserOperationItem struct {
	UserOpHash                    string    `json:"userOpHash"`
	Sender                        string    `json:"sender"`
	Paymaster                     string    `json:"paymaster,omitempty"`
	Target                        string    `json:"target,omitempty"`
	Selector                      string    `json:"selector,omitempty"`
	Status                        string    `json:"status"`
	BlockNumber                   uint64    `json:"blockNumber"`
	LogIndex                      uint      `json:"logIndex"`
	TxHash                        string    `json:"txHash"`
	ActualGasUsed                 string    `json:"actualGasUsed"`
	ActualGasCost                 string    `json:"actualGasCost"`
	Beneficiary                   string    `json:"beneficiary,omitempty"`
	CallGasLimit                  string    `json:"callGasLimit"`
	VerificationGasLimit          string    `json:"verificationGasLimit"`
	PreVerificationGas            string    `json:"preVerificationGas"`
	MaxFeePerGas                  string    `json:"maxFeePerGas"`
	MaxPriorityFeePerGas          string    `json:"maxPriorityFeePerGas"`
	PaymasterVerificationGasLimit string    `json:"paymasterVerificationGasLimit"`
	PaymasterPostOpGasLimit       string    `json:"paymasterPostOpGasLimit"`
	RevertReason                  string    `json:"revertReason,omitempty"`
	BlockTime                     time.Time `json:"blockTime"`
}

type GasBreakdown struct {
	Stage   string `json:"stage"`
	Method  string `json:"method,omitempty"`
	Type    string `json:"type,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Gas     string `json:"gas"`
	GasUsed string `json:"gasUsed"`
}

type AssetMovement struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	TokenID string `json:"tokenId,omitempty"`
	Delta   string `json:"delta"`
}

type PhaseGas struct {
	Phase    string `json:"phase"`
	GasUsed  string `json:"gasUsed"`
	GasLimit string `json:"gasLimit,omitempty"`
}

type UserOperationGas struct {
	UserOpHash                    string     `json:"userOpHash"`
	TxHash                        string     `json:"txHash"`
	ActualGasUsed                 string     `json:"actualGasUsed"`
	ActualGasCost                 string     `json:"actualGasCost"`
	CallGasLimit                  string     `json:"callGasLimit"`
	VerificationGasLimit          string     `json:"verificationGasLimit"`
	PreVerificationGas            string     `json:"preVerificationGas"`
	MaxFeePerGas                  string     `json:"maxFeePerGas"`
	MaxPriorityFeePerGas          string     `json:"maxPriorityFeePerGas"`
	PaymasterVerificationGasLimit string     `json:"paymasterVerificationGasLimit"`
	PaymasterPostOpGasLimit       string     `json:"paymasterPostOpGasLimit"`
	Phases                        []PhaseGas `json:"phases"`
}

type ListUserOpsResult struct {
	Items    []UserOperationItem `json:"items"`
	Page     int                 `json:"page"`
	Limit    int                 `json:"limit"`
	Total    int64               `json:"total"`
	HasNext  bool                `json:"hasNext"`
	NextPage int                 `json:"nextPage,omitempty"`
}

type NFTTokenItem struct {
	TokenID  string `json:"tokenId"`
	Contract string `json:"contract"`
	Owner    string `json:"owner"`
}

type NFTListResult struct {
	Items []NFTTokenItem `json:"items"`
}

type ListNFTsParams struct {
	ChainID  uint64
	Contract string
	Owner    string
}

func (r *Reader) ListUserOperations(ctx context.Context, params ListUserOpsParams) (*ListUserOpsResult, error) {
	rows, total, err := r.repo.ListUserOperationEvents(ctx, store.UserOpListParams{
		ChainID:   params.ChainID,
		Sender:    params.Sender,
		Paymaster: params.Paymaster,
		Status:    params.Status,
		FromBlock: params.FromBlock,
		ToBlock:   params.ToBlock,
		Page:      params.Page,
		Limit:     params.Limit,
		SortDesc:  params.SortDesc,
	})
	if err != nil {
		return nil, err
	}
	items := make([]UserOperationItem, 0, len(rows))
	for _, row := range rows {
		status := "failed"
		if row.Success {
			status = "success"
		}
		items = append(items, UserOperationItem{
			UserOpHash:                    row.UserOpHash,
			Sender:                        row.Sender,
			Paymaster:                     row.Paymaster,
			Target:                        strings.ToLower(row.Target),
			Selector:                      sanitizeSelector(row.CallSelector),
			Status:                        status,
			BlockNumber:                   row.BlockNumber,
			LogIndex:                      row.LogIndex,
			TxHash:                        row.TxHash,
			ActualGasUsed:                 row.ActualGasUsed,
			ActualGasCost:                 row.ActualGasCost,
			Beneficiary:                   row.Beneficiary,
			CallGasLimit:                  row.CallGasLimit,
			VerificationGasLimit:          row.VerificationGasLimit,
			PreVerificationGas:            row.PreVerificationGas,
			MaxFeePerGas:                  row.MaxFeePerGas,
			MaxPriorityFeePerGas:          row.MaxPriorityFeePerGas,
			PaymasterVerificationGasLimit: row.PaymasterVerificationGasLimit,
			PaymasterPostOpGasLimit:       row.PaymasterPostOpGasLimit,
			RevertReason:                  row.RevertReason,
			BlockTime:                     row.BlockTime,
		})
	}
	page := params.Page
	if page <= 0 {
		page = 1
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	hasNext := int64(page*limit) < total
	var nextPage int
	if hasNext {
		nextPage = page + 1
	}
	return &ListUserOpsResult{
		Items:    items,
		Page:     page,
		Limit:    limit,
		Total:    total,
		HasNext:  hasNext,
		NextPage: nextPage,
	}, nil
}

type UserOperationDetail struct {
	UserOperationItem
	Nonce        string            `json:"nonce"`
	Events       []UserOpEventInfo `json:"events"`
	Revert       *RevertInfo       `json:"revert,omitempty"`
	Sponsorship  *SponsorshipInfo  `json:"sponsorship,omitempty"`
	GasBreakdown []GasBreakdown    `json:"gasBreakdown,omitempty"`
	AssetMoves   []AssetMovement   `json:"assetMovements,omitempty"`
	MintedNFTs   []NFTTokenItem    `json:"mintedNfts,omitempty"`
}

type UserOpEventInfo struct {
	Name        string `json:"name"`
	BlockNumber uint64 `json:"blockNumber"`
	TxHash      string `json:"txHash"`
}

type RevertInfo struct {
	Selector string `json:"selector"`
	Message  string `json:"message,omitempty"`
	Raw      string `json:"raw"`
}

type SponsorshipInfo struct {
	ValidUntil string `json:"validUntil"`
	ValidAfter string `json:"validAfter"`
}

type PaymasterOverview struct {
	TotalSponsoredOps     int64   `json:"totalSponsoredOps"`
	SuccessRatePercent    float64 `json:"successRate"`
	TotalSponsoredGasGwei string  `json:"totalSponsoredGasCost"`
	AvgActualGasUsed      float64 `json:"avgActualGasUsed"`
}

type SponsoredOpsParams struct {
	ChainID   uint64
	Paymaster string
	Cursor    string
	Limit     int
}

type SponsoredOpItem struct {
	UserOpHash  string    `json:"userOpHash"`
	Sender      string    `json:"sender"`
	Target      string    `json:"target,omitempty"`
	Selector    string    `json:"selector,omitempty"`
	Status      string    `json:"status"`
	BlockNumber uint64    `json:"blockNumber"`
	LogIndex    uint      `json:"logIndex"`
	BlockTime   time.Time `json:"blockTime"`
}

type SponsoredOpsResult struct {
	Items      []SponsoredOpItem `json:"items"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

func (r *Reader) GetUserOperation(ctx context.Context, chainID uint64, userOpHash string) (*UserOperationDetail, error) {
	row, err := r.repo.GetUserOperationDetail(ctx, chainID, userOpHash)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}
	status := "failed"
	if row.Success {
		status = "success"
	}
	item := UserOperationItem{
		UserOpHash:                    row.UserOpHash,
		Sender:                        row.Sender,
		Paymaster:                     row.Paymaster,
		Target:                        strings.ToLower(row.Target),
		Selector:                      sanitizeSelector(row.CallSelector),
		Status:                        status,
		BlockNumber:                   row.BlockNumber,
		LogIndex:                      row.LogIndex,
		TxHash:                        row.TxHash,
		ActualGasUsed:                 row.ActualGasUsed,
		ActualGasCost:                 row.ActualGasCost,
		Beneficiary:                   row.Beneficiary,
		CallGasLimit:                  row.CallGasLimit,
		VerificationGasLimit:          row.VerificationGasLimit,
		PreVerificationGas:            row.PreVerificationGas,
		MaxFeePerGas:                  row.MaxFeePerGas,
		MaxPriorityFeePerGas:          row.MaxPriorityFeePerGas,
		PaymasterVerificationGasLimit: row.PaymasterVerificationGasLimit,
		PaymasterPostOpGasLimit:       row.PaymasterPostOpGasLimit,
		RevertReason:                  row.RevertReason,
		BlockTime:                     row.BlockTime,
	}
	var revertInfo *RevertInfo
	if row.RevertReason != "" {
		selector, message := decodeRevert(row.RevertReason)
		revertInfo = &RevertInfo{
			Selector: selector,
			Message:  message,
			Raw:      row.RevertReason,
		}
		if message != "" {
			item.RevertReason = message
		}
	}
	if revertInfo == nil && item.Status == "failed" {
		item.RevertReason = "Execution reverted with empty data or OOG"
		revertInfo = &RevertInfo{
			Message: item.RevertReason,
			Raw:     "",
		}
	}
	var sponsorship *SponsorshipInfo
	if row.ValidAfter != "" || row.ValidUntil != "" {
		sponsorship = &SponsorshipInfo{
			ValidAfter: row.ValidAfter,
			ValidUntil: row.ValidUntil,
		}
	}
	eventLog := []UserOpEventInfo{{
		Name:        "UserOperationEvent",
		BlockNumber: row.BlockNumber,
		TxHash:      row.TxHash,
	}}
	if revertInfo != nil {
		eventLog = append(eventLog, UserOpEventInfo{
			Name:        "UserOperationRevertReason",
			BlockNumber: row.BlockNumber,
			TxHash:      row.TxHash,
		})
	}
	var gasBreakdown []GasBreakdown
	if raw := strings.TrimSpace(row.TraceSummary); raw != "" && raw != "null" {
		if err := json.Unmarshal([]byte(raw), &gasBreakdown); err != nil {
			var phases []PhaseGas
			if err2 := json.Unmarshal([]byte(raw), &phases); err2 == nil {
				gasBreakdown = phasesToBreakdown(phases)
			} else {
				gasBreakdown = nil
			}
		}
	}

	var assetMoves []AssetMovement
	cost := strings.TrimSpace(row.ActualGasCost)
	if cost != "" && cost != "0" {
		beneficiary := strings.ToLower(row.Beneficiary)
		if beneficiary != "" {
			assetMoves = append(assetMoves, AssetMovement{
				Address: beneficiary,
				Token:   "ETH",
				Delta:   "+" + cost,
			})
		}
		entryPoint := strings.ToLower(row.EntryPoint)
		if entryPoint != "" {
			assetMoves = append(assetMoves, AssetMovement{
				Address: entryPoint,
				Token:   "ETH",
				Delta:   "-" + cost,
			})
		}
	}

	var mintedNFTs []NFTTokenItem
	if tokens, err := r.repo.ListNFTMintsByTx(ctx, row.ChainID, row.TxHash); err == nil {
		for _, token := range tokens {
			mintedNFTs = append(mintedNFTs, NFTTokenItem{
				TokenID:  token.TokenID,
				Contract: token.Contract,
				Owner:    token.Owner,
			})
			assetMoves = append(assetMoves, AssetMovement{
				Address: strings.ToLower(token.Owner),
				Token:   strings.ToLower(token.Contract),
				TokenID: token.TokenID,
				Delta:   "+1",
			})
		}
	} else {
		return nil, err
	}

	return &UserOperationDetail{
		UserOperationItem: item,
		Nonce:             row.Nonce,
		Events:            eventLog,
		Revert:            revertInfo,
		Sponsorship:       sponsorship,
		GasBreakdown:      gasBreakdown,
		AssetMoves:        assetMoves,
		MintedNFTs:        mintedNFTs,
	}, nil
}

func (r *Reader) GetUserOperationGas(ctx context.Context, chainID uint64, userOpHash string) (*UserOperationGas, error) {
	row, err := r.repo.GetUserOperationDetail(ctx, chainID, userOpHash)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}
	var phases []PhaseGas
	if raw := strings.TrimSpace(row.TraceSummary); raw != "" && raw != "null" {
		data := []byte(raw)
		useLegacy := false
		if err := json.Unmarshal(data, &phases); err != nil {
			useLegacy = true
		} else {
			allEmpty := len(phases) > 0
			if allEmpty {
				for _, p := range phases {
					if strings.TrimSpace(p.Phase) != "" {
						allEmpty = false
						break
					}
				}
			}
			if allEmpty {
				useLegacy = true
			}
		}
		if useLegacy {
			var legacy []GasBreakdown
			if err2 := json.Unmarshal(data, &legacy); err2 == nil {
				phases = convertLegacyBreakdown(legacy)
			} else {
				phases = nil
			}
		}
	}
	return &UserOperationGas{
		UserOpHash:                    row.UserOpHash,
		TxHash:                        row.TxHash,
		ActualGasUsed:                 row.ActualGasUsed,
		ActualGasCost:                 row.ActualGasCost,
		CallGasLimit:                  row.CallGasLimit,
		VerificationGasLimit:          row.VerificationGasLimit,
		PreVerificationGas:            row.PreVerificationGas,
		MaxFeePerGas:                  row.MaxFeePerGas,
		MaxPriorityFeePerGas:          row.MaxPriorityFeePerGas,
		PaymasterVerificationGasLimit: row.PaymasterVerificationGasLimit,
		PaymasterPostOpGasLimit:       row.PaymasterPostOpGasLimit,
		Phases:                        phases,
	}, nil
}

func convertLegacyBreakdown(items []GasBreakdown) []PhaseGas {
	if len(items) == 0 {
		return nil
	}
	totals := map[string]*big.Int{
		"validation": big.NewInt(0),
		"execution":  big.NewInt(0),
		"postOp":     big.NewInt(0),
	}
	for _, item := range items {
		phase := stageToPhase(item.Stage)
		if phase == "" {
			continue
		}
		if val := parseBigIntString(item.GasUsed); val != nil {
			totals[phase].Add(totals[phase], val)
		}
	}
	order := []string{"validation", "execution", "postOp"}
	var phases []PhaseGas
	for _, phase := range order {
		total := totals[phase]
		if total == nil {
			total = big.NewInt(0)
		}
		phases = append(phases, PhaseGas{
			Phase:    phase,
			GasUsed:  total.String(),
			GasLimit: "0",
		})
	}
	return phases
}

func phasesToBreakdown(phases []PhaseGas) []GasBreakdown {
	if len(phases) == 0 {
		return nil
	}
	out := make([]GasBreakdown, 0, len(phases))
	for _, phase := range phases {
		out = append(out, GasBreakdown{
			Stage:   phase.Phase,
			Gas:     phase.GasLimit,
			GasUsed: phase.GasUsed,
		})
	}
	return out
}

func stageToPhase(stage string) string {
	s := strings.ToLower(stage)
	switch {
	case strings.Contains(s, "validate"):
		return "validation"
	case strings.Contains(s, "post"):
		return "postOp"
	default:
		return "execution"
	}
}

func parseBigIntString(v string) *big.Int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		value := strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
		if value == "" {
			return nil
		}
		num, ok := new(big.Int).SetString(value, 16)
		if !ok {
			return nil
		}
		return num
	}
	if num, ok := new(big.Int).SetString(v, 10); ok {
		return num
	}
	return nil
}

func (r *Reader) ListNFTs(ctx context.Context, params ListNFTsParams) (*NFTListResult, error) {
	if params.ChainID == 0 {
		return &NFTListResult{Items: []NFTTokenItem{}}, nil
	}
	tokens, err := r.repo.ListNFTTokensByOwner(ctx, params.ChainID, params.Contract, params.Owner)
	if err != nil {
		return nil, err
	}
	items := make([]NFTTokenItem, 0, len(tokens))
	for _, token := range tokens {
		items = append(items, NFTTokenItem{
			TokenID:  token.TokenID,
			Contract: token.Contract,
			Owner:    token.Owner,
		})
	}
	return &NFTListResult{Items: items}, nil
}

type PaymasterOpsParams struct {
	ChainID   uint64
	Paymaster string
	Status    string
	FromTime  *time.Time
	ToTime    *time.Time
	Page      int
	Limit     int
}

func (r *Reader) ListPaymasterOperations(ctx context.Context, params PaymasterOpsParams) (*ListUserOpsResult, error) {
	rows, total, err := r.repo.ListPaymasterOperations(ctx, store.PaymasterOpsParams{
		ChainID:   params.ChainID,
		Paymaster: params.Paymaster,
		Status:    params.Status,
		FromTime:  params.FromTime,
		ToTime:    params.ToTime,
		Page:      params.Page,
		Limit:     params.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]UserOperationItem, 0, len(rows))
	for _, row := range rows {
		status := "failed"
		if row.Success {
			status = "success"
		}
		items = append(items, UserOperationItem{
			UserOpHash:                    row.UserOpHash,
			Sender:                        row.Sender,
			Paymaster:                     row.Paymaster,
			Target:                        strings.ToLower(row.Target),
			Selector:                      sanitizeSelector(row.CallSelector),
			Status:                        status,
			BlockNumber:                   row.BlockNumber,
			LogIndex:                      row.LogIndex,
			TxHash:                        row.TxHash,
			ActualGasUsed:                 row.ActualGasUsed,
			ActualGasCost:                 row.ActualGasCost,
			Beneficiary:                   row.Beneficiary,
			CallGasLimit:                  row.CallGasLimit,
			VerificationGasLimit:          row.VerificationGasLimit,
			PreVerificationGas:            row.PreVerificationGas,
			MaxFeePerGas:                  row.MaxFeePerGas,
			MaxPriorityFeePerGas:          row.MaxPriorityFeePerGas,
			PaymasterVerificationGasLimit: row.PaymasterVerificationGasLimit,
			PaymasterPostOpGasLimit:       row.PaymasterPostOpGasLimit,
			RevertReason:                  row.RevertReason,
			BlockTime:                     row.BlockTime,
		})
	}
	page := params.Page
	if page <= 0 {
		page = 1
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	hasNext := int64(page*limit) < total
	var nextPage int
	if hasNext {
		nextPage = page + 1
	}
	return &ListUserOpsResult{
		Items:    items,
		Page:     page,
		Limit:    limit,
		Total:    total,
		HasNext:  hasNext,
		NextPage: nextPage,
	}, nil
}

func (r *Reader) PaymasterOverview(ctx context.Context, chainID uint64, paymaster string) (*PaymasterOverview, error) {
	row, err := r.repo.GetPaymasterOverviewStats(ctx, chainID, paymaster)
	if err != nil {
		return nil, err
	}
	successRate := 0.0
	if row.TotalOps > 0 {
		successRate = float64(row.SuccessOps) / float64(row.TotalOps) * 100
		successRate = math.Round(successRate*100) / 100
	}
	totalGwei := "0"
	if row.TotalGasCost > 0 {
		wei := big.NewInt(row.TotalGasCost)
		gwei := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e9))
		totalGwei = strings.TrimRight(strings.TrimRight(gwei.Text('f', 6), "0"), ".")
		if totalGwei == "" {
			totalGwei = "0"
		}
	}
	return &PaymasterOverview{
		TotalSponsoredOps:     row.TotalOps,
		SuccessRatePercent:    successRate,
		TotalSponsoredGasGwei: totalGwei,
		AvgActualGasUsed:      row.AvgGasUsed,
	}, nil
}

func (r *Reader) SponsoredOps(ctx context.Context, params SponsoredOpsParams) (*SponsoredOpsResult, error) {
	var cursorBlock *uint64
	var cursorLog *uint
	if params.Cursor != "" {
		block, logIdx, err := parseCursor(params.Cursor)
		if err != nil {
			return nil, err
		}
		cursorBlock = &block
		cursorLog = &logIdx
	}
	limit := params.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.repo.ListSponsoredOps(ctx, store.SponsoredOpsParams{
		ChainID:     params.ChainID,
		Paymaster:   params.Paymaster,
		Limit:       limit + 1,
		CursorBlock: cursorBlock,
		CursorLog:   cursorLog,
	})
	if err != nil {
		return nil, err
	}
	var nextCursor string
	if len(rows) > limit {
		last := rows[len(rows)-1]
		nextCursor = formatCursor(last.BlockNumber, last.LogIndex)
		rows = rows[:limit]
	}
	items := make([]SponsoredOpItem, 0, len(rows))
	for _, row := range rows {
		status := "failed"
		if row.Success {
			status = "success"
		}
		selector := sanitizeSelector(row.CallSelector)
		if selector == "" && len(row.OpSelector) > 0 {
			selector = "0x" + hex.EncodeToString(row.OpSelector)
		}
		target := strings.ToLower(row.Target)
		if row.OpTarget != nil && *row.OpTarget != "" {
			target = strings.ToLower(*row.OpTarget)
		}
		items = append(items, SponsoredOpItem{
			UserOpHash:  row.UserOpHash,
			Sender:      row.Sender,
			Target:      target,
			Selector:    selector,
			Status:      status,
			BlockNumber: row.BlockNumber,
			LogIndex:    row.LogIndex,
			BlockTime:   row.BlockTime,
		})
	}
	return &SponsoredOpsResult{Items: items, NextCursor: nextCursor}, nil
}

type OverviewStatsParams struct {
	ChainID uint64
	From    time.Time
	To      time.Time
	GroupBy string
}

type OverviewStats struct {
	RangeFrom    time.Time        `json:"from"`
	RangeTo      time.Time        `json:"to"`
	GroupBy      string           `json:"groupBy"`
	Buckets      []BucketStats    `json:"buckets"`
	Total        int64            `json:"totalOps"`
	SuccessRate  float64          `json:"successRate"`
	ByStatus     map[string]int64 `json:"byStatus"`
	TotalGasUsed float64          `json:"totalGasUsed"`
	TotalGasCost float64          `json:"totalGasCost"`
}

type BucketStats struct {
	Start   time.Time `json:"start"`
	Total   int64     `json:"total"`
	Success int64     `json:"success"`
	Failed  int64     `json:"failed"`
}

func (r *Reader) OverviewStats(ctx context.Context, params OverviewStatsParams) (*OverviewStats, error) {
	rows, err := r.repo.StatsOverview(ctx, store.StatsOverviewParams{
		ChainID: params.ChainID,
		From:    params.From,
		To:      params.To,
		GroupBy: params.GroupBy,
	})
	if err != nil {
		return nil, err
	}
	stats := &OverviewStats{
		RangeFrom: params.From,
		RangeTo:   params.To,
		GroupBy:   params.GroupBy,
		ByStatus:  map[string]int64{"success": 0, "failed": 0},
	}
	for _, row := range rows {
		start, _ := time.Parse(time.RFC3339, row.Bucket)
		bucket := BucketStats{
			Start:   start,
			Total:   row.TotalOps,
			Success: row.SuccessOps,
			Failed:  row.FailedOps,
		}
		stats.Buckets = append(stats.Buckets, bucket)
		stats.Total += row.TotalOps
		stats.ByStatus["success"] += row.SuccessOps
		stats.ByStatus["failed"] += row.FailedOps
		stats.TotalGasUsed += row.TotalGasUsed
		stats.TotalGasCost += row.TotalGasCost
	}
	if stats.Total > 0 {
		stats.SuccessRate = float64(stats.ByStatus["success"]) / float64(stats.Total)
	}
	return stats, nil
}

func (r *Reader) SenderReport(ctx context.Context, params store.SenderOpsParams) ([]UserOperationItem, error) {
	rows, err := r.repo.ListOpsBySender(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]UserOperationItem, 0, len(rows))
	for _, row := range rows {
		status := "failed"
		if row.Success {
			status = "success"
		}
		items = append(items, UserOperationItem{
			UserOpHash:    row.UserOpHash,
			Sender:        row.Sender,
			Paymaster:     row.Paymaster,
			Target:        strings.ToLower(row.Target),
			Selector:      sanitizeSelector(row.CallSelector),
			Status:        status,
			BlockNumber:   row.BlockNumber,
			LogIndex:      row.LogIndex,
			TxHash:        row.TxHash,
			ActualGasUsed: row.ActualGasUsed,
			ActualGasCost: row.ActualGasCost,
			RevertReason:  row.RevertReason,
			BlockTime:     row.BlockTime,
		})
	}
	return items, nil
}

func (r *Reader) ContractReport(ctx context.Context, params store.ContractOpsParams) ([]UserOperationItem, error) {
	rows, err := r.repo.ListOpsByContract(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]UserOperationItem, 0, len(rows))
	for _, row := range rows {
		status := "failed"
		if row.Success {
			status = "success"
		}
		items = append(items, UserOperationItem{
			UserOpHash:    row.UserOpHash,
			Sender:        row.Sender,
			Paymaster:     row.Paymaster,
			Target:        strings.ToLower(row.Target),
			Selector:      sanitizeSelector(row.CallSelector),
			Status:        status,
			BlockNumber:   row.BlockNumber,
			LogIndex:      row.LogIndex,
			TxHash:        row.TxHash,
			ActualGasUsed: row.ActualGasUsed,
			ActualGasCost: row.ActualGasCost,
			RevertReason:  row.RevertReason,
			BlockTime:     row.BlockTime,
		})
	}
	return items, nil
}

func decodeRevert(raw string) (string, string) {
	hexStr := strings.TrimPrefix(raw, "0x")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) < 4 {
		return "", ""
	}
	selector := "0x" + hex.EncodeToString(data[:4])
	if len(data) <= 4 {
		return selector, ""
	}
	out, err := revertErrorArgs.Unpack(data[4:])
	if err == nil && len(out) > 0 {
		if msg, ok := out[0].(string); ok {
			return selector, msg
		}
	}
	return selector, ""
}

func parseCursor(raw string) (uint64, uint, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid cursor")
	}
	block, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid cursor block")
	}
	idx, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid cursor index")
	}
	return block, uint(idx), nil
}

func formatCursor(block uint64, logIndex uint) string {
	return strconv.FormatUint(block, 10) + ":" + strconv.FormatUint(uint64(logIndex), 10)
}

var revertErrorArgs = abi.Arguments{{Type: mustABIType("string")}}

func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return typ
}
