package store

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *DB) *Repository { return &Repository{db: db.DB} }

func (r *Repository) CreatePaymaster(ctx context.Context, pm *Paymaster) error {
	if pm.AdminID != 0 {
		var count int64
		if err := r.db.WithContext(ctx).Model(&Paymaster{}).Where("admin_id = ?", pm.AdminID).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrConflict
		}
	}
	return r.db.WithContext(ctx).Create(pm).Error
}

func (r *Repository) ListPaymasters(ctx context.Context, adminID uint) ([]Paymaster, error) {
	var out []Paymaster
	query := r.db.WithContext(ctx).Order("id desc").Preload("Users")
	if adminID != 0 {
		query = query.Where("admin_id = ?", adminID)
	}
	err := query.Find(&out).Error
	return out, err
}

func (r *Repository) GetPaymaster(ctx context.Context, id uint) (*Paymaster, error) {
	var pm Paymaster
	err := r.db.WithContext(ctx).Preload("Users").First(&pm, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &pm, nil
}

func (r *Repository) GetPaymasterByAdmin(ctx context.Context, adminID uint) (*Paymaster, error) {
	if adminID == 0 {
		return nil, nil
	}
	var pm Paymaster
	err := r.db.WithContext(ctx).Preload("Users").Where("admin_id = ?", adminID).First(&pm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &pm, nil
}

func (r *Repository) SavePaymaster(ctx context.Context, pm *Paymaster) error {
	return r.db.WithContext(ctx).Save(pm).Error
}

func (r *Repository) AddContract(ctx context.Context, contract *ContractWhitelist) error {
	return r.db.WithContext(ctx).Create(contract).Error
}

func (r *Repository) SaveContract(ctx context.Context, contract *ContractWhitelist) error {
	return r.db.WithContext(ctx).Save(contract).Error
}

func (r *Repository) GetContractByAddress(ctx context.Context, paymasterID uint, address string) (*ContractWhitelist, error) {
	addr := strings.ToLower(address)
	var contract ContractWhitelist
	err := r.db.WithContext(ctx).
		Where("paymaster_id = ? AND address = ?", paymasterID, addr).
		Preload("Functions").
		Preload("Functions.Contract").
		First(&contract).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &contract, nil
}

func (r *Repository) DeleteContract(ctx context.Context, paymasterID, contractID uint) error {
	res := r.db.WithContext(ctx).Where("paymaster_id = ? AND id = ?", paymasterID, contractID).Delete(&ContractWhitelist{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) ListContracts(ctx context.Context, paymasterID uint) ([]ContractWhitelist, error) {
	var contracts []ContractWhitelist
	err := r.db.WithContext(ctx).
		Where("paymaster_id = ?", paymasterID).
		Order("id desc").
		Preload("Functions").
		Find(&contracts).Error
	return contracts, err
}

func (r *Repository) GetContract(ctx context.Context, paymasterID, contractID uint) (*ContractWhitelist, error) {
	var contract ContractWhitelist
	err := r.db.WithContext(ctx).
		Where("paymaster_id = ? AND id = ?", paymasterID, contractID).
		First(&contract).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &contract, nil
}

func (r *Repository) ListFunctions(ctx context.Context, paymasterID uint) ([]FunctionWhitelist, error) {
	var functions []FunctionWhitelist
	err := r.db.WithContext(ctx).
		Joins("JOIN contract_whitelists ON contract_whitelists.id = function_whitelists.contract_id").
		Where("contract_whitelists.paymaster_id = ?", paymasterID).
		Order("function_whitelists.id desc").
		Preload("Contract").
		Find(&functions).Error
	return functions, err
}

func (r *Repository) ListFunctionsByContract(ctx context.Context, paymasterID uint, address string) ([]FunctionWhitelist, error) {
	addr := strings.ToLower(address)
	var functions []FunctionWhitelist
	err := r.db.WithContext(ctx).
		Joins("JOIN contract_whitelists ON contract_whitelists.id = function_whitelists.contract_id").
		Where("contract_whitelists.paymaster_id = ? AND contract_whitelists.address = ?", paymasterID, addr).
		Order("function_whitelists.id desc").
		Preload("Contract").
		Find(&functions).Error
	return functions, err
}

func (r *Repository) ReplaceFunctionsForContract(ctx context.Context, contractID uint, fns []FunctionWhitelist) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("contract_id = ?", contractID).Delete(&FunctionWhitelist{}).Error; err != nil {
			return err
		}
		if len(fns) == 0 {
			return nil
		}
		for i := range fns {
			fns[i].ContractID = contractID
		}
		if err := tx.Create(&fns).Error; err != nil {
			return err
		}
		return nil
	})
}

func (r *Repository) ListUsers(ctx context.Context, paymasterID uint) ([]UserWhitelist, error) {
	var users []UserWhitelist
	err := r.db.WithContext(ctx).Where("paymaster_id = ?", paymasterID).Order("id desc").Find(&users).Error
	return users, err
}

func (r *Repository) ReplaceUsersForPaymaster(ctx context.Context, paymasterID uint, users []UserWhitelist) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("paymaster_id = ?", paymasterID).Delete(&UserWhitelist{}).Error; err != nil {
			return err
		}
		if len(users) == 0 {
			return nil
		}
		for i := range users {
			users[i].PaymasterID = paymasterID
		}
		if err := tx.Create(&users).Error; err != nil {
			return err
		}
		return nil
	})
}

func (r *Repository) AddUser(ctx context.Context, user *UserWhitelist) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *Repository) DeleteUserByAddress(ctx context.Context, paymasterID uint, address string) error {
	res := r.db.WithContext(ctx).Where("paymaster_id = ? AND sender = ?", paymasterID, address).Delete(&UserWhitelist{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) GetLogCursor(ctx context.Context, chainID uint64, address string) (*LogCursor, error) {
	addr := strings.ToLower(address)
	var cursor LogCursor
	err := r.db.WithContext(ctx).
		Where("chain_id = ? AND address = ?", chainID, addr).
		First(&cursor).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &cursor, nil
}

func (r *Repository) UpsertLogCursor(ctx context.Context, cursor *LogCursor) error {
	cursor.Address = strings.ToLower(cursor.Address)
	cursor.LastTxHash = strings.ToLower(cursor.LastTxHash)
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "chain_id"}, {Name: "address"}},
		DoUpdates: clause.Assignments(map[string]any{
			"last_block":     cursor.LastBlock,
			"last_tx_hash":   cursor.LastTxHash,
			"last_log_index": cursor.LastLogIndex,
			"updated_at":     gorm.Expr("CURRENT_TIMESTAMP"),
		}),
	}).Create(cursor).Error
}

func (r *Repository) UpsertUserOperationEvent(ctx context.Context, event *UserOperationEvent) error {
	event.EntryPoint = strings.ToLower(event.EntryPoint)
	event.Sender = strings.ToLower(event.Sender)
	event.Paymaster = strings.ToLower(event.Paymaster)
	event.Target = strings.ToLower(event.Target)
	event.CallSelector = strings.ToLower(event.CallSelector)
	event.TxHash = strings.ToLower(event.TxHash)
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_op_hash"}},
		DoUpdates: clause.Assignments(map[string]any{
			"sender":          event.Sender,
			"paymaster":       event.Paymaster,
			"target":          event.Target,
			"call_selector":   event.CallSelector,
			"nonce":           event.Nonce,
			"success":         event.Success,
			"actual_gas_cost": event.ActualGasCost,
			"actual_gas_used": event.ActualGasUsed,
			"tx_hash":         event.TxHash,
			"block_number":    event.BlockNumber,
			"log_index":       event.LogIndex,
			"block_time":      event.BlockTime,
			"updated_at":      gorm.Expr("CURRENT_TIMESTAMP"),
		}),
	}).Create(event).Error
}

func (r *Repository) UpsertUserOperationRevert(ctx context.Context, revert *UserOperationRevert) error {
	revert.EntryPoint = strings.ToLower(revert.EntryPoint)
	revert.Sender = strings.ToLower(revert.Sender)
	revert.TxHash = strings.ToLower(revert.TxHash)
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_op_hash"}},
		DoUpdates: clause.Assignments(map[string]any{
			"sender":        revert.Sender,
			"nonce":         revert.Nonce,
			"revert_reason": revert.RevertReason,
			"tx_hash":       revert.TxHash,
			"block_number":  revert.BlockNumber,
			"log_index":     revert.LogIndex,
			"updated_at":    gorm.Expr("CURRENT_TIMESTAMP"),
		}),
	}).Create(revert).Error
}

func (r *Repository) UpsertAccountDeployment(ctx context.Context, dep *AccountDeployment) error {
	dep.EntryPoint = strings.ToLower(dep.EntryPoint)
	dep.Sender = strings.ToLower(dep.Sender)
	dep.Factory = strings.ToLower(dep.Factory)
	dep.Paymaster = strings.ToLower(dep.Paymaster)
	dep.TxHash = strings.ToLower(dep.TxHash)
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_op_hash"}},
		DoUpdates: clause.Assignments(map[string]any{
			"sender":       dep.Sender,
			"factory":      dep.Factory,
			"paymaster":    dep.Paymaster,
			"tx_hash":      dep.TxHash,
			"block_number": dep.BlockNumber,
			"log_index":    dep.LogIndex,
			"updated_at":   gorm.Expr("CURRENT_TIMESTAMP"),
		}),
	}).Create(dep).Error
}

func (r *Repository) UpsertSimpleAccountInitialization(ctx context.Context, init *SimpleAccountInitialization) error {
	init.Account = strings.ToLower(init.Account)
	init.EntryPoint = strings.ToLower(init.EntryPoint)
	init.Owner = strings.ToLower(init.Owner)
	init.TxHash = strings.ToLower(init.TxHash)
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account"}},
		DoUpdates: clause.Assignments(map[string]any{
			"entry_point":  init.EntryPoint,
			"owner":        init.Owner,
			"tx_hash":      init.TxHash,
			"block_number": init.BlockNumber,
			"log_index":    init.LogIndex,
			"updated_at":   gorm.Expr("CURRENT_TIMESTAMP"),
		}),
	}).Create(init).Error
}

func (r *Repository) UpsertSponsorship(ctx context.Context, s *Sponsorship) error {
	s.Paymaster = strings.ToLower(s.Paymaster)
	s.Sender = strings.ToLower(s.Sender)
	s.TxHash = strings.ToLower(s.TxHash)
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_op_hash"}},
		DoUpdates: clause.Assignments(map[string]any{
			"paymaster":    s.Paymaster,
			"sender":       s.Sender,
			"valid_until":  s.ValidUntil,
			"valid_after":  s.ValidAfter,
			"tx_hash":      s.TxHash,
			"block_number": s.BlockNumber,
			"log_index":    s.LogIndex,
			"updated_at":   gorm.Expr("CURRENT_TIMESTAMP"),
		}),
	}).Create(s).Error
}

func (r *Repository) ListOperations(ctx context.Context, paymasterID uint) ([]Operation, error) {
	var ops []Operation
	err := r.db.WithContext(ctx).Where("paymaster_id = ?", paymasterID).Order("created_at desc").Find(&ops).Error
	return ops, err
}

func (r *Repository) GetAdminByUsername(ctx context.Context, username string) (*Admin, error) {
	var admin Admin
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&admin).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &admin, nil
}
