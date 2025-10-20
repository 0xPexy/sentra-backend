package store

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
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
