package admin

import (
	"encoding/json"
	"time"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type CreatePaymasterRequest struct {
	ChainID     *uint64  `json:"chainId"`
	EntryPoint  *string  `json:"entryPoint"`
	Address     string   `json:"address"`
	USDPerMaxOp *int64   `json:"usdPerMaxOp"`
	Users       []string `json:"users"`
}

type UpdatePaymasterRequest struct {
	Address     *string   `json:"address"`
	USDPerMaxOp *int64    `json:"usdPerMaxOp"`
	Users       *[]string `json:"users"`
}

type AddContractRequest struct {
	Address   string                  `json:"address"`
	Name      *string                 `json:"name"`
	Functions []ContractFunctionInput `json:"functions"`
}

type ContractFunctionInput struct {
	Selector  string  `json:"selector"`
	Signature *string `json:"signature"`
}

type UpdateContractRequest struct {
	Address   *string                 `json:"address"`
	Name      *string                 `json:"name"`
	Functions []ContractFunctionInput `json:"functions"`
}

type ReplaceUsersRequest struct {
	Users []string `json:"users"`
}

type AddUserRequest struct {
	Address string `json:"address"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type MeResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type FunctionResponse struct {
	ID        uint      `json:"id"`
	Selector  string    `json:"selector"`
	Signature *string   `json:"signature,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type ContractResponse struct {
	ID        uint               `json:"id"`
	Address   string             `json:"address"`
	Name      string             `json:"name"`
	Functions []FunctionResponse `json:"functions"`
	CreatedAt time.Time          `json:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt"`
}

type PaymasterResponse struct {
	ID          uint               `json:"id"`
	AdminID     uint               `json:"adminId"`
	ChainID     uint64             `json:"chainId"`
	EntryPoint  string             `json:"entryPoint"`
	Address     string             `json:"address"`
	USDPerMaxOp int64              `json:"usdPerMaxOp"`
	Users       []string           `json:"users"`
	Contracts   []ContractResponse `json:"contracts,omitempty"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
}

type OperationResponse struct {
	ID          uint      `json:"id"`
	PaymasterID uint      `json:"paymasterId"`
	ChainID     uint64    `json:"chainId"`
	UserOpHash  string    `json:"userOpHash"`
	TxHash      string    `json:"txHash"`
	Sender      string    `json:"sender"`
	Target      string    `json:"target"`
	Selector    string    `json:"selector"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason"`
	GasUsed     string    `json:"gasUsed"`
	GasCostWei  string    `json:"gasCostWei"`
	USDCCharged string    `json:"usdcCharged"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type UserAddressResponse struct {
	Address string `json:"address"`
}

type ContractArtifactResponse struct {
	Name string          `json:"name"`
	ABI  json.RawMessage `json:"abi"`
}
