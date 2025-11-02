package erc7677

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

type stubRepo struct {
	paymaster   *store.Paymaster
	pmErr       error
	contract    *store.ContractWhitelist
	contractErr error
}

func (s *stubRepo) GetPaymasterByAdmin(ctx context.Context, adminID uint) (*store.Paymaster, error) {
	if s.pmErr != nil {
		return nil, s.pmErr
	}
	return s.paymaster, nil
}

func (s *stubRepo) GetContractByAddress(ctx context.Context, paymasterID uint, address string) (*store.ContractWhitelist, error) {
	if s.contractErr != nil {
		return nil, s.contractErr
	}
	return s.contract, nil
}

type stubSigner struct {
	sig []byte
	err error
}

func (s stubSigner) signPolicyMessage(common.Hash) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	cp := make([]byte, len(s.sig))
	copy(cp, s.sig)
	return cp, nil
}

type stubValidity struct{ d time.Duration }

func (s stubValidity) DefaultValidity() time.Duration { return s.d }

type stubEthClient struct {
	latestNumber uint64
	latestTime   uint64
	parentTime   uint64
	callResp     []byte
	callErr      error
}

func (s *stubEthClient) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	switch {
	case number == nil:
		header := &types.Header{
			Number: big.NewInt(int64(s.latestNumber)),
			Time:   s.latestTime,
		}
		return types.NewBlockWithHeader(header), nil
	case number.Sign() >= 0 && number.Uint64() == s.latestNumber-1:
		header := &types.Header{
			Number: big.NewInt(int64(s.latestNumber - 1)),
			Time:   s.parentTime,
		}
		return types.NewBlockWithHeader(header), nil
	default:
		return nil, errors.New("unexpected block request")
	}
}

func (s *stubEthClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if s.callErr != nil {
		return nil, s.callErr
	}
	cp := make([]byte, len(s.callResp))
	copy(cp, s.callResp)
	return cp, nil
}

func newTestHandler(t *testing.T, repo paymasterRepo, signer policySigner, eth ethClient) *Handler {
	t.Helper()
	cfg := config.Config{
		PMValGas:  120_000,
		PostOpGas: 80_000,
	}
	logger := log.New(io.Discard, "", 0)
	return newHandler(cfg, repo, stubValidity{d: 2 * time.Minute}, signer, eth, logger)
}

func TestPaymasterStubDataSuccess(t *testing.T) {
	repo := &stubRepo{
		paymaster: &store.Paymaster{
			ID:      1,
			Address: "0xabc0000000000000000000000000000000000001",
		},
		contract: &store.ContractWhitelist{
			PaymasterID: 1,
			Address:     strings.ToLower("0x0000000000000000000000000000000000001000"),
			Functions: []store.FunctionWhitelist{
				{Selector: []byte{0x12, 0x34, 0x56, 0x78}},
			},
		},
	}
	ethStub := &stubEthClient{
		latestNumber: 10,
		latestTime:   1_700_000_000,
		parentTime:   1_699_999_940,
		callResp:     nil,
		callErr:      errors.New("force fallback"),
	}
	handler := newTestHandler(t, repo, stubSigner{sig: bytes.Repeat([]byte{0xbb}, 65)}, ethStub)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "pm_getPaymasterStubData",
		"params": []any{
			baseUserOperation(),
			"",
			"0x1",
			map[string]any{
				"target":   "0x0000000000000000000000000000000000001000",
				"selector": "0x12345678",
			},
		},
	}
	resp := performRequest(t, handler, reqBody)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", resp.Result)
	}
	pmdHex, _ := result["paymasterData"].(string)
	if pmdHex == "" {
		t.Fatalf("missing paymasterData: %+v", result)
	}
	pmd, err := hexutil.Decode(pmdHex)
	if err != nil {
		t.Fatalf("decode paymasterData: %v", err)
	}
	if len(pmd) != 36+65 {
		t.Fatalf("unexpected paymasterData length=%d", len(pmd))
	}
	sig := pmd[len(pmd)-65:]
	for i := 0; i < 64; i++ {
		if sig[i] != 0xaa {
			t.Fatalf("expected stub signature byte 0xaa, got 0x%x at index %d", sig[i], i)
		}
	}
	if pmd[len(pmd)-1] != 0x1c {
		t.Fatalf("expected stub signature v-byte 0x1c, got 0x%x", pmd[len(pmd)-1])
	}
}

func TestPaymasterDataSuccess(t *testing.T) {
	repo := &stubRepo{
		paymaster: &store.Paymaster{
			ID:      1,
			Address: "0xabc0000000000000000000000000000000000001",
		},
		contract: &store.ContractWhitelist{
			PaymasterID: 1,
			Address:     strings.ToLower("0x0000000000000000000000000000000000001000"),
			Functions: []store.FunctionWhitelist{
				{Selector: []byte{0x12, 0x34, 0x56, 0x78}},
			},
		},
	}
	ethStub := &stubEthClient{
		latestNumber: 10,
		latestTime:   1_700_000_000,
		parentTime:   1_699_999_940,
		callErr:      errors.New("force fallback"),
	}
	sig := append(bytes.Repeat([]byte{0xcd}, 64), byte(0x1c))
	handler := newTestHandler(t, repo, stubSigner{sig: sig}, ethStub)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "pm_getPaymasterData",
		"params": []any{
			baseUserOperation(),
			"0x00000000000000000000000000000000000000ee",
			"0x1",
			map[string]any{
				"target":   "0x0000000000000000000000000000000000001000",
				"selector": "0x12345678",
			},
		},
	}
	resp := performRequest(t, handler, reqBody)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	pmdHex := result["paymasterData"].(string)
	pmd, err := hexutil.Decode(pmdHex)
	if err != nil {
		t.Fatalf("decode paymasterData: %v", err)
	}
	if len(pmd) != 36+65 {
		t.Fatalf("unexpected paymasterData len=%d", len(pmd))
	}
	signature := pmd[len(pmd)-65:]
	if !bytes.Equal(signature, sig) {
		t.Fatalf("signature mismatch")
	}
}

func TestPaymasterDataFunctionNotAllowed(t *testing.T) {
	repo := &stubRepo{
		paymaster: &store.Paymaster{
			ID:      1,
			Address: "0xabc0000000000000000000000000000000000001",
		},
		contract: &store.ContractWhitelist{
			PaymasterID: 1,
			Address:     strings.ToLower("0x0000000000000000000000000000000000001000"),
			Functions: []store.FunctionWhitelist{
				{Selector: []byte{0xfe, 0xdc, 0xba, 0x98}},
			},
		},
	}
	handler := newTestHandler(t, repo, stubSigner{sig: bytes.Repeat([]byte{0xcd}, 65)}, &stubEthClient{
		latestNumber: 10,
		latestTime:   1_700_000_000,
		parentTime:   1_699_999_940,
	})

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "pm_getPaymasterData",
		"params": []any{
			baseUserOperation(),
			"0x00000000000000000000000000000000000000ee",
			"0x1",
			map[string]any{
				"target":   "0x0000000000000000000000000000000000001000",
				"selector": "0x12345678",
			},
		},
	}
	resp := performRequest(t, handler, reqBody)
	if resp.Error == nil {
		t.Fatalf("expected error")
	}
	if resp.Error.Code != -32000 || resp.Error.Message != "function not allowed" {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
}

func TestParseUserOperationFactory(t *testing.T) {
	raw := baseUserOperation()
	raw["factory"] = "0x1111111111111111111111111111111111111111"
	raw["factoryData"] = "0xabcdef"

	op, err := parseUserOperation(raw)
	if err != nil {
		t.Fatalf("parse user operation: %v", err)
	}
	expectedData, _ := hexutil.Decode("0xabcdef")
	expected := append(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(), expectedData...)
	if !bytes.Equal(op.InitCode, expected) {
		t.Fatalf("initCode mismatch: got %x expected %x", op.InitCode, expected)
	}
}

func baseUserOperation() map[string]any {
	return map[string]any{
		"sender":               "0x0000000000000000000000000000000000000001",
		"nonce":                "0x0",
		"initCode":             "0x",
		"callData":             "0x",
		"callGasLimit":         "0x1",
		"verificationGasLimit": "0x1",
		"preVerificationGas":   "0x1",
		"maxFeePerGas":         "0x1",
		"maxPriorityFeePerGas": "0x1",
		"paymasterAndData":     "0x",
		"signature":            "0x",
	}
}

func performRequest(t *testing.T, handler *Handler, payload map[string]any) rpcResponse {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("adminID", uint(1))

	handler.HandleJSONRPC(c)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	var resp rpcResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}
