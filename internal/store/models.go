package store

import "time"

type Admin struct {
	ID        uint      `gorm:"primaryKey"`
	Username  string    `gorm:"uniqueIndex;size:120;not null"`
	PassHash  string    `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type Paymaster struct {
	ID          uint            `gorm:"primaryKey"`
	AdminID     uint            `gorm:"uniqueIndex;not null"`
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
