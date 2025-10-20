package admin

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
