package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	indexersvc "github.com/0xPexy/sentra-backend/internal/indexer/service"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/gin-gonic/gin"
)

func TestUserOperationDetailIncludesDecodedRevert(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := store.OpenSQLite(":memory:")
	store.AutoMigrate(db)
	repo := store.NewRepository(db)

	userOpHash := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	txHash := "0xtxhashdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	entryPoint := "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"

	event := &store.UserOperationEvent{
		ChainID:       1,
		EntryPoint:    entryPoint,
		UserOpHash:    userOpHash,
		Sender:        "0x1",
		Paymaster:     "0x2",
		Target:        "0x3",
		CallSelector:  "0x12345678",
		Success:       false,
		ActualGasCost: "1000000000",
		ActualGasUsed: "100000",
		TxHash:        txHash,
		BlockNumber:   1,
		LogIndex:      0,
		BlockTime:     time.Now(),
	}
	if err := repo.UpsertUserOperationEvent(context.Background(), event); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	revertMsg := "AccessDenied"
	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		t.Fatalf("new type: %v", err)
	}
	args := abi.Arguments{abi.Argument{Type: stringType}}
	payload, err := args.Pack(revertMsg)
	if err != nil {
		t.Fatalf("pack revert: %v", err)
	}
	rawRevert := append([]byte{0x08, 0xc3, 0x79, 0xa0}, payload...)

	revert := &store.UserOperationRevert{
		ChainID:      1,
		EntryPoint:   entryPoint,
		UserOpHash:   userOpHash,
		Sender:       "0x1",
		Nonce:        "0x0",
		RevertReason: "0x" + hex.EncodeToString(rawRevert),
		TxHash:       txHash,
		BlockNumber:  1,
		LogIndex:     0,
	}
	if err := repo.UpsertUserOperationRevert(context.Background(), revert); err != nil {
		t.Fatalf("insert revert: %v", err)
	}

	reader := indexersvc.NewReader(repo)
	handler := &indexerHandler{
		cfg:    config.Config{Chain: config.ChainConfig{ChainID: 1}},
		repo:   repo,
		reader: reader,
		hub:    NewEventHub(logDiscard()),
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/ops/"+userOpHash, nil)
	c.Request = req
	c.Params = gin.Params{gin.Param{Key: "userOpHash", Value: userOpHash}}

	handler.UserOperationDetail(c)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		RevertReason string `json:"revertReason"`
		Revert       struct {
			Selector string `json:"selector"`
			Message  string `json:"message"`
			Raw      string `json:"raw"`
		} `json:"revert"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.RevertReason != revertMsg {
		t.Fatalf("expected revertReason %q, got %q", revertMsg, resp.RevertReason)
	}
	if resp.Revert.Message != revertMsg {
		t.Fatalf("expected nested revert message %q, got %q", revertMsg, resp.Revert.Message)
	}
	if resp.Revert.Selector != "0x08c379a0" {
		t.Fatalf("expected selector 0x08c379a0, got %s", resp.Revert.Selector)
	}
	if resp.Revert.Raw == "" {
		t.Fatalf("expected raw revert data")
	}
}

func logDiscard() *log.Logger {
	return log.New(io.Discard, "", 0)
}
