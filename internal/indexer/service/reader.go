package service

import (
	"context"
	"encoding/hex"
	"errors"
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
	UserOpHash    string    `json:"userOpHash"`
	Sender        string    `json:"sender"`
	Paymaster     string    `json:"paymaster,omitempty"`
	Status        string    `json:"status"`
	BlockNumber   uint64    `json:"blockNumber"`
	LogIndex      uint      `json:"logIndex"`
	TxHash        string    `json:"txHash"`
	ActualGasUsed string    `json:"actualGasUsed"`
	ActualGasCost string    `json:"actualGasCost"`
	RevertReason  string    `json:"revertReason,omitempty"`
	BlockTime     time.Time `json:"blockTime"`
}

type ListUserOpsResult struct {
	Items    []UserOperationItem `json:"items"`
	Page     int                 `json:"page"`
	Limit    int                 `json:"limit"`
	Total    int64               `json:"total"`
	HasNext  bool                `json:"hasNext"`
	NextPage int                 `json:"nextPage,omitempty"`
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
			UserOpHash:    row.UserOpHash,
			Sender:        row.Sender,
			Paymaster:     row.Paymaster,
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
	Nonce  string            `json:"nonce"`
	Events []UserOpEventInfo `json:"events"`
	Revert *RevertInfo       `json:"revert,omitempty"`
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
		UserOpHash:    row.UserOpHash,
		Sender:        row.Sender,
		Paymaster:     row.Paymaster,
		Status:        status,
		BlockNumber:   row.BlockNumber,
		LogIndex:      row.LogIndex,
		TxHash:        row.TxHash,
		ActualGasUsed: row.ActualGasUsed,
		ActualGasCost: row.ActualGasCost,
		RevertReason:  row.RevertReason,
		BlockTime:     row.BlockTime,
	}
	var revertInfo *RevertInfo
	if row.RevertReason != "" {
		selector, message := decodeRevert(row.RevertReason)
		revertInfo = &RevertInfo{
			Selector: selector,
			Message:  message,
			Raw:      row.RevertReason,
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

	return &UserOperationDetail{
		UserOperationItem: item,
		Nonce:             row.Nonce,
		Events:            eventLog,
		Revert:            revertInfo,
	}, nil
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
			UserOpHash:    row.UserOpHash,
			Sender:        row.Sender,
			Paymaster:     row.Paymaster,
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

var revertErrorArgs = abi.Arguments{{Type: mustABIType("string")}}

func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return typ
}
