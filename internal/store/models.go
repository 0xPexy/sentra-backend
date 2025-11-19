package store

import "time"

type Admin struct {
	ID        uint      `gorm:"primaryKey"`
	Address   string    `gorm:"size:66;uniqueIndex"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type Paymaster struct {
	ID          uint            `gorm:"primaryKey"`
	AdminID     uint            `gorm:"index"`
	ChainID     uint64          `gorm:"index;not null"`
	EntryPoint  string          `gorm:"size:66;not null"`
	Address     string          `gorm:"size:66;not null"`
	USDPerMaxOp int64           `gorm:"not null"`
	Users       []UserWhitelist `gorm:"foreignKey:PaymasterID"`
	CreatedAt   time.Time       `gorm:"autoCreateTime"`
	UpdatedAt   time.Time       `gorm:"autoUpdateTime"`
}

type ContractWhitelist struct {
	ID          uint                `gorm:"primaryKey"`
	PaymasterID uint                `gorm:"index;not null"`
	Address     string              `gorm:"size:66;not null"`
	Name        string              `gorm:"size:255"`
	Functions   []FunctionWhitelist `gorm:"foreignKey:ContractID"`
	CreatedAt   time.Time           `gorm:"autoCreateTime"`
	UpdatedAt   time.Time           `gorm:"autoUpdateTime"`
}

type FunctionWhitelist struct {
	ID         uint   `gorm:"primaryKey"`
	ContractID uint   `gorm:"index;not null"`
	Selector   []byte `gorm:"size:4;not null"`
	Signature  *string
	Contract   ContractWhitelist `gorm:"foreignKey:ContractID"`
	CreatedAt  time.Time         `gorm:"autoCreateTime"`
	UpdatedAt  time.Time         `gorm:"autoUpdateTime"`
}

type UserWhitelist struct {
	ID          uint      `gorm:"primaryKey"`
	PaymasterID uint      `gorm:"index;not null"`
	Sender      string    `gorm:"size:66;not null"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

type Operation struct {
	ID          uint `gorm:"primaryKey"`
	PaymasterID uint `gorm:"index;not null"`
	ChainID     uint64
	UserOpHash  string `gorm:"size:66;uniqueIndex"`
	TxHash      string `gorm:"size:66"`
	Sender      string `gorm:"size:66"`
	Target      string `gorm:"size:66"`
	Selector    []byte `gorm:"size:4"`
	Status      string `gorm:"size:64"`
	Reason      string `gorm:"size:255"`
	GasUsed     string
	GasCostWei  string
	USDCCharged string
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

type LogCursor struct {
	ID           uint   `gorm:"primaryKey"`
	ChainID      uint64 `gorm:"uniqueIndex:idx_log_cursor"`
	Address      string `gorm:"size:66;uniqueIndex:idx_log_cursor"`
	LastBlock    uint64
	LastTxHash   string `gorm:"size:66"`
	LastLogIndex uint
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

type UserOperationEvent struct {
	ID                            uint   `gorm:"primaryKey"`
	ChainID                       uint64 `gorm:"uniqueIndex:idx_userop_txlog"`
	EntryPoint                    string `gorm:"size:66;index"`
	UserOpHash                    string `gorm:"size:66;uniqueIndex"`
	Sender                        string `gorm:"size:66;index"`
	Paymaster                     string `gorm:"size:66"`
	Target                        string `gorm:"size:66"`
	Nonce                         string `gorm:"size:78"`
	Success                       bool   `gorm:"index"`
	ActualGasCost                 string `gorm:"size:78"`
	ActualGasUsed                 string `gorm:"size:78"`
	Beneficiary                   string `gorm:"size:66"`
	CallGasLimit                  string `gorm:"size:78"`
	VerificationGasLimit          string `gorm:"size:78"`
	PreVerificationGas            string `gorm:"size:78"`
	MaxFeePerGas                  string `gorm:"size:78"`
	MaxPriorityFeePerGas          string `gorm:"size:78"`
	PaymasterVerificationGasLimit string `gorm:"size:78"`
	PaymasterPostOpGasLimit       string `gorm:"size:78"`
	TxHash                        string `gorm:"size:66;uniqueIndex:idx_userop_txlog"`
	BlockNumber                   uint64 `gorm:"uniqueIndex:idx_userop_txlog"`
	LogIndex                      uint   `gorm:"uniqueIndex:idx_userop_txlog"`
	CallSelector                  string `gorm:"size:10"`
	BlockTime                     time.Time
	CreatedAt                     time.Time `gorm:"autoCreateTime"`
	UpdatedAt                     time.Time `gorm:"autoUpdateTime"`
}

type UserOperationTrace struct {
	ID           uint      `gorm:"primaryKey"`
	ChainID      uint64    `gorm:"index"`
	UserOpHash   string    `gorm:"size:66;uniqueIndex"`
	TxHash       string    `gorm:"size:66"`
	TraceSummary string    `gorm:"type:text"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

type UserOperationRevert struct {
	ID           uint   `gorm:"primaryKey"`
	ChainID      uint64 `gorm:"uniqueIndex:idx_useroprev_txlog"`
	EntryPoint   string `gorm:"size:66;index"`
	UserOpHash   string `gorm:"size:66;uniqueIndex"`
	Sender       string `gorm:"size:66"`
	Nonce        string `gorm:"size:78"`
	RevertReason string
	TxHash       string    `gorm:"size:66;uniqueIndex:idx_useroprev_txlog"`
	BlockNumber  uint64    `gorm:"uniqueIndex:idx_useroprev_txlog"`
	LogIndex     uint      `gorm:"uniqueIndex:idx_useroprev_txlog"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

type AccountDeployment struct {
	ID          uint      `gorm:"primaryKey"`
	ChainID     uint64    `gorm:"uniqueIndex:idx_accountdeploy_txlog"`
	EntryPoint  string    `gorm:"size:66;index"`
	UserOpHash  string    `gorm:"size:66;uniqueIndex"`
	Sender      string    `gorm:"size:66;index"`
	Factory     string    `gorm:"size:66"`
	Paymaster   string    `gorm:"size:66"`
	TxHash      string    `gorm:"size:66;uniqueIndex:idx_accountdeploy_txlog"`
	BlockNumber uint64    `gorm:"uniqueIndex:idx_accountdeploy_txlog"`
	LogIndex    uint      `gorm:"uniqueIndex:idx_accountdeploy_txlog"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

type SimpleAccountInitialization struct {
	ID          uint      `gorm:"primaryKey"`
	ChainID     uint64    `gorm:"uniqueIndex:idx_simpleaccount_init"`
	Account     string    `gorm:"size:66;uniqueIndex"`
	EntryPoint  string    `gorm:"size:66;index"`
	Owner       string    `gorm:"size:66"`
	TxHash      string    `gorm:"size:66;uniqueIndex:idx_simpleaccount_init"`
	BlockNumber uint64    `gorm:"uniqueIndex:idx_simpleaccount_init"`
	LogIndex    uint      `gorm:"uniqueIndex:idx_simpleaccount_init"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

type Sponsorship struct {
	ID          uint      `gorm:"primaryKey"`
	ChainID     uint64    `gorm:"uniqueIndex:idx_sponsorship_txlog"`
	Paymaster   string    `gorm:"size:66;index"`
	UserOpHash  string    `gorm:"size:66;uniqueIndex"`
	Sender      string    `gorm:"size:66"`
	ValidUntil  string    `gorm:"size:78"`
	ValidAfter  string    `gorm:"size:78"`
	TxHash      string    `gorm:"size:66;uniqueIndex:idx_sponsorship_txlog"`
	BlockNumber uint64    `gorm:"uniqueIndex:idx_sponsorship_txlog"`
	LogIndex    uint      `gorm:"uniqueIndex:idx_sponsorship_txlog"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

type IndexerMetric struct {
	MetricID  string    `gorm:"primaryKey;size:128"`
	Value     string    `gorm:"type:text"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type NFTToken struct {
	ID              uint   `gorm:"primaryKey"`
	ChainID         uint64 `gorm:"uniqueIndex:idx_nft_token"`
	Contract        string `gorm:"size:66;uniqueIndex:idx_nft_token"`
	TokenID         string `gorm:"size:78;uniqueIndex:idx_nft_token"`
	Owner           string `gorm:"size:66;index"`
	MintTxHash      string `gorm:"size:66"`
	MintBlockNumber uint64
	CreatedAt       time.Time `gorm:"autoCreateTime"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime"`
}
