package service

import (
	"context"
	"testing"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestReaderQueries(t *testing.T) {
	ctx := context.Background()
	gormDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db := &store.DB{DB: gormDB}
	store.AutoMigrate(db)

	repo := store.NewRepository(db)
	reader := NewReader(repo)

	chainID := uint64(8453)
	now := time.Now().UTC()

	events := []store.UserOperationEvent{
		{
			ChainID:       chainID,
			EntryPoint:    "0xentrypoint",
			UserOpHash:    "0xaaa",
			Sender:        "0xsender1",
			Paymaster:     "0xpaymaster1",
			Target:        "0xtarget1",
			Nonce:         "1",
			Success:       true,
			ActualGasCost: "1000",
			ActualGasUsed: "500",
			TxHash:        "0xtx1",
			BlockNumber:   100,
			LogIndex:      0,
			BlockTime:     now.Add(-2 * time.Minute),
		},
		{
			ChainID:       chainID,
			EntryPoint:    "0xentrypoint",
			UserOpHash:    "0xbbb",
			Sender:        "0xsender2",
			Paymaster:     "0xpaymaster1",
			Target:        "0xtarget2",
			Nonce:         "2",
			Success:       false,
			ActualGasCost: "2000",
			ActualGasUsed: "800",
			TxHash:        "0xtx2",
			BlockNumber:   101,
			LogIndex:      0,
			BlockTime:     now.Add(-1 * time.Minute),
		},
		{
			ChainID:       chainID,
			EntryPoint:    "0xentrypoint",
			UserOpHash:    "0xccc",
			Sender:        "0xsender1",
			Paymaster:     "0xpaymaster2",
			Target:        "0xtarget2",
			Nonce:         "3",
			Success:       true,
			ActualGasCost: "1500",
			ActualGasUsed: "600",
			TxHash:        "0xtx3",
			BlockNumber:   102,
			LogIndex:      0,
			BlockTime:     now.Add(-30 * time.Second),
		},
	}
	for _, ev := range events {
		if err := repo.UpsertUserOperationEvent(ctx, &ev); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}

	revert := store.UserOperationRevert{
		ChainID:      chainID,
		EntryPoint:   "0xentrypoint",
		UserOpHash:   "0xbbb",
		Sender:       "0xsender2",
		Nonce:        "2",
		RevertReason: "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001b4552433732313a206e6f7420524543323152656365697665720000000000000000",
		TxHash:       "0xtx2",
		BlockNumber:  101,
		LogIndex:     0,
	}
	if err := repo.UpsertUserOperationRevert(ctx, &revert); err != nil {
		t.Fatalf("seed revert: %v", err)
	}

	cursor := store.LogCursor{
		ChainID:      chainID,
		Address:      "0xentrypoint",
		LastBlock:    102,
		LastTxHash:   "0xtx3",
		LastLogIndex: 0,
	}
	if err := repo.UpsertLogCursor(ctx, &cursor); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	status, err := reader.Status(ctx, chainID)
	if err != nil {
		t.Fatalf("status err: %v", err)
	}
	if status.CurrentHead != 102 || status.LastIndexed != 102 {
		t.Fatalf("unexpected status: %+v", status)
	}

	listRes, err := reader.ListUserOperations(ctx, ListUserOpsParams{ChainID: chainID, Limit: 10})
	if err != nil {
		t.Fatalf("list err: %v", err)
	}
	if len(listRes.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(listRes.Items))
	}

	detail, err := reader.GetUserOperation(ctx, chainID, "0xbbb")
	if err != nil {
		t.Fatalf("detail err: %v", err)
	}
	if detail == nil || detail.Revert == nil || detail.Revert.Message == "" {
		t.Fatalf("expected revert info")
	}

	pmRes, err := reader.ListPaymasterOperations(ctx, PaymasterOpsParams{
		ChainID:   chainID,
		Paymaster: "0xpaymaster1",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("pm err: %v", err)
	}
	if len(pmRes.Items) != 2 {
		t.Fatalf("expected 2 paymaster items")
	}

	stats, err := reader.OverviewStats(ctx, OverviewStatsParams{
		ChainID: chainID,
		From:    now.Add(-10 * time.Minute),
		To:      now,
		GroupBy: "hour",
	})
	if err != nil {
		t.Fatalf("stats err: %v", err)
	}
	if stats.Total != 3 {
		t.Fatalf("expected total 3, got %d", stats.Total)
	}

	senderItems, err := reader.SenderReport(ctx, store.SenderOpsParams{ChainID: chainID, Address: "0xsender1"})
	if err != nil {
		t.Fatalf("sender err: %v", err)
	}
	if len(senderItems) != 2 {
		t.Fatalf("expected sender 2 items")
	}

	contractItems, err := reader.ContractReport(ctx, store.ContractOpsParams{ChainID: chainID, Contract: "0xtarget2"})
	if err != nil {
		t.Fatalf("contract err: %v", err)
	}
	if len(contractItems) != 2 {
		t.Fatalf("expected contract 2 items")
	}
}

func TestReaderGetUserOperationGas(t *testing.T) {
	ctx := context.Background()
	gormDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db := &store.DB{DB: gormDB}
	store.AutoMigrate(db)

	repo := store.NewRepository(db)
	reader := NewReader(repo)

	chainID := uint64(8453)
	userOpHash := "0xaaa"
	txHash := "0xtx1"

	event := store.UserOperationEvent{
		ChainID:                       chainID,
		EntryPoint:                    "0xentrypoint",
		UserOpHash:                    userOpHash,
		Sender:                        "0xsender1",
		Paymaster:                     "0xpaymaster1",
		Target:                        "0xtarget1",
		Nonce:                         "1",
		Success:                       true,
		ActualGasCost:                 "1000",
		ActualGasUsed:                 "500",
		Beneficiary:                   "0xbeneficiary",
		CallGasLimit:                  "10000",
		VerificationGasLimit:          "20000",
		PreVerificationGas:            "3000",
		MaxFeePerGas:                  "40",
		MaxPriorityFeePerGas:          "2",
		PaymasterVerificationGasLimit: "4000",
		PaymasterPostOpGasLimit:       "5000",
		TxHash:                        txHash,
		BlockNumber:                   100,
		LogIndex:                      0,
		BlockTime:                     time.Now().UTC(),
	}
	if err := repo.UpsertUserOperationEvent(ctx, &event); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	trace := store.UserOperationTrace{
		ChainID:      chainID,
		UserOpHash:   userOpHash,
		TxHash:       txHash,
		TraceSummary: `[{"phase":"validation","gasUsed":"800","gasLimit":"2000"},{"phase":"execution","gasUsed":"4500","gasLimit":"10000"}]`,
	}
	if err := repo.UpsertUserOperationTrace(ctx, &trace); err != nil {
		t.Fatalf("seed trace: %v", err)
	}

	resp, err := reader.GetUserOperationGas(ctx, chainID, userOpHash)
	if err != nil {
		t.Fatalf("GetUserOperationGas err: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
	if len(resp.Phases) != 2 {
		t.Fatalf("expected 2 phase entries, got %d", len(resp.Phases))
	}
	if resp.Phases[0].Phase != "validation" {
		t.Fatalf("unexpected first phase: %s", resp.Phases[0].Phase)
	}
	if resp.CallGasLimit != "10000" || resp.ActualGasUsed != "500" {
		t.Fatalf("unexpected limits or usage")
	}
}
