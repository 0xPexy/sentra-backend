package erc7677

import "encoding/json"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      any         `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *rpcErrBody `json:"error,omitempty"`
}

type rpcErrBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func rpcOK(id any, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}
func rpcErr(id any, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcErrBody{Code: code, Message: msg}}
}

const (
	errInvalidRequest = -32600
	errInvalidParams  = -32602
	errMethodNotFound = -32601
)

// 7677 result types
type Sponsor struct {
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
}

type PaymasterStubResult struct {
	Sponsor                       *Sponsor `json:"sponsor,omitempty"`
	Paymaster                     string   `json:"paymaster,omitempty"`
	PaymasterData                 string   `json:"paymasterData,omitempty"`
	PaymasterVerificationGasLimit string   `json:"paymasterVerificationGasLimit,omitempty"`
	PaymasterPostOpGasLimit       string   `json:"paymasterPostOpGasLimit,omitempty"`
	IsFinal                       bool     `json:"isFinal,omitempty"`
}

type PaymasterDataResult struct {
	Sponsor                       *Sponsor `json:"sponsor,omitempty"`
	Paymaster                     string   `json:"paymaster,omitempty"`
	PaymasterData                 string   `json:"paymasterData,omitempty"`
	PaymasterVerificationGasLimit string   `json:"paymasterVerificationGasLimit,omitempty"`
	PaymasterPostOpGasLimit       string   `json:"paymasterPostOpGasLimit,omitempty"`
}

// Policy inputs (from context)
type PolicyInput struct {
	Target      string
	Selector    string
	SubsidyBps  uint16
	ValidForSec uint32
}
