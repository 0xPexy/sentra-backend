package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type IndexerStatusRow struct {
	ChainID         uint64
	LastIndexed     uint64
	LastIndexedTime *time.Time
}

type UserOpListParams struct {
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

type UserOpListRow struct {
	UserOperationEvent
	RevertReason string
}

type UserOpDetailRow struct {
	UserOperationEvent
	RevertReason string
	ValidUntil   string
	ValidAfter   string
	TraceSummary string
}

type RangeQuery struct {
	From time.Time
	To   time.Time
}

type AggregatedStat struct {
	Key   string
	Count int64
	Value string
}

type PaymasterOverviewRow struct {
	TotalOps     int64
	SuccessOps   int64
	TotalGasCost int64
	AvgGasUsed   float64
}

func (r *Repository) GetPaymasterOverviewStats(ctx context.Context, chainID uint64, paymaster string) (*PaymasterOverviewRow, error) {
	addr := normalizeAddr(paymaster)
	var row PaymasterOverviewRow
	err := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("COUNT(*) AS total_ops, SUM(CASE WHEN e.success THEN 1 ELSE 0 END) AS success_ops, COALESCE(SUM(CAST(e.actual_gas_cost AS INTEGER)), 0) AS total_gas_cost, COALESCE(AVG(CAST(e.actual_gas_used AS REAL)), 0) AS avg_gas_used").
		Where("e.chain_id = ? AND e.paymaster = ?", chainID, addr).
		Scan(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

type SponsoredOpsParams struct {
	ChainID     uint64
	Paymaster   string
	Limit       int
	CursorBlock *uint64
	CursorLog   *uint
}

type SponsoredOpRow struct {
	UserOperationEvent
	OpSelector []byte  `gorm:"column:op_selector"`
	OpTarget   *string `gorm:"column:op_target"`
}

func (r *Repository) ListSponsoredOps(ctx context.Context, params SponsoredOpsParams) ([]SponsoredOpRow, error) {
	addr := normalizeAddr(params.Paymaster)
	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, o.selector AS op_selector, o.target AS op_target").
		Joins("LEFT JOIN operations AS o ON o.user_op_hash = e.user_op_hash").
		Where("e.chain_id = ? AND e.paymaster = ?", params.ChainID, addr)

	if params.CursorBlock != nil && params.CursorLog != nil {
		query = query.Where("(e.block_number < ?) OR (e.block_number = ? AND e.log_index < ?)", *params.CursorBlock, *params.CursorBlock, *params.CursorLog)
	}

	limit := params.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	var rows []SponsoredOpRow
	err := query.
		Order("e.block_number DESC, e.log_index DESC").
		Limit(limit).
		Scan(&rows).Error
	return rows, err
}

func normalizeAddr(s string) string {
	ss := strings.TrimSpace(s)
	if ss == "" {
		return ""
	}
	if !strings.HasPrefix(ss, "0x") {
		ss = "0x" + ss
	}
	return strings.ToLower(ss)
}

func (r *Repository) ListUserOpsMissingCallData(ctx context.Context, chainID uint64, limit int) ([]UserOperationEvent, error) {
	query := r.db.WithContext(ctx).
		Where("chain_id = ? AND (call_selector IS NULL OR call_selector = '')", chainID).
		Order("block_number ASC, log_index ASC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	var rows []UserOperationEvent
	if err := query.Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *Repository) ListUserOpsMissingTrace(ctx context.Context, chainID uint64, limit int) ([]UserOperationEvent, error) {
	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*").
		Joins("LEFT JOIN user_operation_traces AS t ON t.user_op_hash = e.user_op_hash AND t.chain_id = e.chain_id").
		Where("e.chain_id = ? AND t.user_op_hash IS NULL", chainID).
		Order("e.block_number ASC, e.log_index ASC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	var rows []UserOperationEvent
	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *Repository) GetIndexerStatus(ctx context.Context, chainID uint64) (*IndexerStatusRow, error) {
	var cursor LogCursor
	err := r.db.WithContext(ctx).
		Where("chain_id = ?", chainID).
		Order("updated_at DESC").
		First(&cursor).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &IndexerStatusRow{ChainID: chainID}, nil
		}
		return nil, err
	}
	return &IndexerStatusRow{
		ChainID:         chainID,
		LastIndexed:     cursor.LastBlock,
		LastIndexedTime: &cursor.UpdatedAt,
	}, nil
}

func (r *Repository) ListUserOperationEvents(ctx context.Context, params UserOpListParams) ([]UserOpListRow, int64, error) {
	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, r.revert_reason").
		Joins("LEFT JOIN user_operation_reverts AS r ON r.user_op_hash = e.user_op_hash AND r.chain_id = e.chain_id").
		Where("e.chain_id = ?", params.ChainID)

	if addr := normalizeAddr(params.Sender); addr != "" {
		query = query.Where("e.sender = ?", addr)
	}
	if addr := normalizeAddr(params.Paymaster); addr != "" {
		query = query.Where("e.paymaster = ?", addr)
	}
	switch strings.ToLower(params.Status) {
	case "success":
		query = query.Where("e.success = ?", true)
	case "failed":
		query = query.Where("e.success = ?", false)
	}
	if params.FromBlock != nil && *params.FromBlock > 0 {
		query = query.Where("e.block_number >= ?", *params.FromBlock)
	}
	if params.ToBlock != nil && *params.ToBlock > 0 {
		query = query.Where("e.block_number <= ?", *params.ToBlock)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	page := params.Page
	if page <= 0 {
		page = 1
	}
	order := "e.block_number ASC, e.log_index ASC"
	if params.SortDesc {
		order = "e.block_number DESC, e.log_index DESC"
	}

	var rows []UserOpListRow
	err := query.
		Order(order).
		Offset((page - 1) * limit).
		Limit(limit).
		Scan(&rows).Error
	return rows, total, err
}

func (r *Repository) GetUserOperationDetail(ctx context.Context, chainID uint64, userOpHash string) (*UserOpDetailRow, error) {
	hash := strings.ToLower(userOpHash)
	var row UserOpDetailRow
	err := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, r.revert_reason, s.valid_until, s.valid_after, t.trace_summary").
		Joins("LEFT JOIN user_operation_reverts AS r ON r.user_op_hash = e.user_op_hash AND r.chain_id = e.chain_id").
		Joins("LEFT JOIN sponsorships AS s ON s.user_op_hash = e.user_op_hash AND s.chain_id = e.chain_id").
		Joins("LEFT JOIN user_operation_traces AS t ON t.user_op_hash = e.user_op_hash AND t.chain_id = e.chain_id").
		Where("e.chain_id = ? AND e.user_op_hash = ?", chainID, hash).
		First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &row, nil
}

func (r *Repository) LatestUserOperation(ctx context.Context, chainID uint64) (*UserOpListRow, error) {
	var row UserOpListRow
	err := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, r.revert_reason").
		Joins("LEFT JOIN user_operation_reverts AS r ON r.user_op_hash = e.user_op_hash AND r.chain_id = e.chain_id").
		Where("e.chain_id = ?", chainID).
		Order("e.block_number DESC, e.log_index DESC").
		Limit(1).
		Scan(&row).Error
	if err != nil {
		return nil, err
	}
	if row.UserOpHash == "" {
		return nil, nil
	}
	return &row, nil
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

func (r *Repository) ListPaymasterOperations(ctx context.Context, params PaymasterOpsParams) ([]UserOpListRow, int64, error) {
	addr := normalizeAddr(params.Paymaster)
	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, r.revert_reason").
		Joins("LEFT JOIN user_operation_reverts AS r ON r.user_op_hash = e.user_op_hash AND r.chain_id = e.chain_id").
		Where("e.chain_id = ? AND e.paymaster = ?", params.ChainID, addr)

	switch strings.ToLower(params.Status) {
	case "success":
		query = query.Where("e.success = ?", true)
	case "failed":
		query = query.Where("e.success = ?", false)
	}

	if params.FromTime != nil {
		query = query.Where("e.block_time >= ?", *params.FromTime)
	}
	if params.ToTime != nil {
		query = query.Where("e.block_time <= ?", *params.ToTime)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	page := params.Page
	if page <= 0 {
		page = 1
	}

	var rows []UserOpListRow
	err := query.
		Order("e.block_time DESC, e.block_number DESC").
		Offset((page - 1) * limit).
		Limit(limit).
		Scan(&rows).Error
	return rows, total, err
}

type StatsOverviewParams struct {
	ChainID uint64
	From    time.Time
	To      time.Time
	GroupBy string
}

type StatsOverviewRow struct {
	Bucket       string
	TotalOps     int64
	SuccessOps   int64
	FailedOps    int64
	TotalGasUsed float64
	TotalGasCost float64
}

func (r *Repository) StatsOverview(ctx context.Context, params StatsOverviewParams) ([]StatsOverviewRow, error) {
	trunc := "strftime('%Y-%m-%dT%H:00:00Z', e.block_time)"
	if params.GroupBy == "day" {
		trunc = "strftime('%Y-%m-%dT00:00:00Z', e.block_time)"
	}
	if params.GroupBy == "month" {
		trunc = "strftime('%Y-%m-01T00:00:00Z', e.block_time)"
	}

	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select(fmt.Sprintf("%s AS bucket, COUNT(*) AS total_ops, SUM(CASE WHEN e.success THEN 1 ELSE 0 END) AS success_ops, SUM(CASE WHEN e.success THEN 0 ELSE 1 END) AS failed_ops, SUM(CAST(e.actual_gas_used AS REAL)) AS total_gas_used, SUM(CAST(e.actual_gas_cost AS REAL)) AS total_gas_cost", trunc)).
		Where("e.chain_id = ? AND e.block_time BETWEEN ? AND ?", params.ChainID, params.From, params.To).
		Group("bucket").
		Order("bucket ASC")

	var rows []StatsOverviewRow
	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

type SenderOpsParams struct {
	ChainID uint64
	Address string
	From    *time.Time
	To      *time.Time
}

func (r *Repository) ListOpsBySender(ctx context.Context, params SenderOpsParams) ([]UserOpListRow, error) {
	addr := normalizeAddr(params.Address)
	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, r.revert_reason").
		Joins("LEFT JOIN user_operation_reverts AS r ON r.user_op_hash = e.user_op_hash AND r.chain_id = e.chain_id").
		Where("e.chain_id = ? AND e.sender = ?", params.ChainID, addr).
		Order("e.block_time DESC")
	if params.From != nil {
		query = query.Where("e.block_time >= ?", *params.From)
	}
	if params.To != nil {
		query = query.Where("e.block_time <= ?", *params.To)
	}
	var rows []UserOpListRow
	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

type ContractOpsParams struct {
	ChainID  uint64
	Contract string
	From     *time.Time
	To       *time.Time
}

func (r *Repository) ListOpsByContract(ctx context.Context, params ContractOpsParams) ([]UserOpListRow, error) {
	addr := normalizeAddr(params.Contract)
	query := r.db.WithContext(ctx).
		Table("user_operation_events AS e").
		Select("e.*, r.revert_reason").
		Joins("LEFT JOIN user_operation_reverts AS r ON r.user_op_hash = e.user_op_hash AND r.chain_id = e.chain_id").
		Where("e.chain_id = ? AND e.target = ?", params.ChainID, addr).
		Order("e.block_time DESC")
	if params.From != nil {
		query = query.Where("e.block_time >= ?", *params.From)
	}
	if params.To != nil {
		query = query.Where("e.block_time <= ?", *params.To)
	}
	var rows []UserOpListRow
	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *Repository) UpsertIndexerMetric(ctx context.Context, metricID string, value string) error {
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "metric_id"}},
		DoUpdates: clause.Assignments(map[string]any{"value": value, "updated_at": time.Now()}),
	}).Table("indexer_metrics").Create(map[string]any{
		"metric_id":  metricID,
		"value":      value,
		"created_at": time.Now(),
		"updated_at": time.Now(),
	}).Error
}
