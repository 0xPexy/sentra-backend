package pipeline

import (
	"context"
	"io"
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestIndexerPersistsUserOperationEvents(t *testing.T) {
	t.Helper()

	entryPoint := common.HexToAddress("0x4337084d9e255ff0702461cf8895ce9e3b5ff108")
	paymaster := common.HexToAddress("0xa566b84cc8e917a553c854a8503a0d3afbc93e88")
	factory := common.HexToAddress("0x1ac65df2a1d1ac5b66c32daf500fe5218f6cea7b")
	sender := common.HexToAddress("0xe9eb4a51414de92c4dbe5a46f6259cb4f456d7f9")
	userOpHash := common.HexToHash("0x2ec96abe5b14d8dcd0c98b447776505013a45eafc065d4a68e81d92d5689f7b4")
	txHash := common.HexToHash("0x70438b8950da5c757b4c4cee11330c31619d3158c4e1b64eb7ee16fd4ba0f720")

	successData, err := userOperationEvent.Inputs.NonIndexed().Pack(
		big.NewInt(1),
		true,
		big.NewInt(5_000_000),
		big.NewInt(200_000),
	)
	if err != nil {
		t.Fatalf("pack success event: %v", err)
	}

	revertReason := []byte("execution reverted: custom error")
	revertData, err := userOperationRevertEvent.Inputs.NonIndexed().Pack(
		big.NewInt(1),
		revertReason,
	)
	if err != nil {
		t.Fatalf("pack revert event: %v", err)
	}

	const blockNumber = uint64(0x1689818)
	blockTime := uint64(1_700_000_000)

	accountDeployData, err := accountDeployedEvent.Inputs.NonIndexed().Pack(paymaster)
	if err != nil {
		t.Fatalf("pack account deploy event: %v", err)
	}
	validUntil := big.NewInt(0).SetUint64(blockTime + 600)
	validAfter := big.NewInt(0).SetUint64(blockTime - 120)
	sponsoredData, err := sponsoredEvent.Inputs.NonIndexed().Pack(validUntil, validAfter)
	if err != nil {
		t.Fatalf("pack sponsorship event: %v", err)
	}

	logs := []types.Log{
		{
			Address:     entryPoint,
			Topics:      []common.Hash{userOperationEvent.ID, userOpHash, topicFromAddress(sender), topicFromAddress(paymaster)},
			Data:        successData,
			BlockNumber: blockNumber,
			TxHash:      txHash,
			Index:       0,
		},
		{
			Address:     entryPoint,
			Topics:      []common.Hash{userOperationRevertEvent.ID, userOpHash, topicFromAddress(sender)},
			Data:        revertData,
			BlockNumber: blockNumber,
			TxHash:      txHash,
			Index:       1,
		},
		{
			Address:     entryPoint,
			Topics:      []common.Hash{accountDeployedEvent.ID, userOpHash},
			Data:        []byte{},
			BlockNumber: blockNumber,
			TxHash:      txHash,
			Index:       2,
		},
		{
			Address:     entryPoint,
			Topics:      []common.Hash{accountDeployedEvent.ID, userOpHash, topicFromAddress(sender), topicFromAddress(factory)},
			Data:        accountDeployData,
			BlockNumber: blockNumber,
			TxHash:      txHash,
			Index:       3,
		},
		{
			Address:     paymaster,
			Topics:      []common.Hash{sponsoredEvent.ID, userOpHash, topicFromAddress(sender)},
			Data:        sponsoredData,
			BlockNumber: blockNumber,
			TxHash:      txHash,
			Index:       4,
		},
	}

	repo := newMockRepo()
	client := newStubEthClient(logs, blockNumber+2, map[uint64]uint64{
		blockNumber:     blockTime,
		blockNumber + 2: blockTime + 30,
	})

	cfg := Config{
		ChainID:           1,
		EntryPoint:        entryPoint,
		DeploymentBlock:   blockNumber - 5,
		ChunkSize:         64,
		Confirmations:     0,
		PollInterval:      10 * time.Millisecond,
		DecodeWorkerCount: 1,
		WriteWorkerCount:  1,
		ResubscribeDelay:  10 * time.Millisecond,
	}

	idx := New(cfg, repo, client, log.New(io.Discard, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- idx.Run(ctx)
	}()

	waitFor(t, 2*time.Second, func() bool {
		return repo.eventCount() == 1 && repo.revertCount() == 1 && repo.deployCount() == 1 && repo.sponsorshipCount() == 1
	})

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("indexer did not stop in time")
	}

	event := repo.eventByHash(userOpHash.Hex())
	if event == nil {
		t.Fatalf("event with hash %s not persisted", userOpHash.Hex())
	}
	if !event.Success {
		t.Fatalf("expected success=true, got %v", event.Success)
	}
	if event.TxHash != txHash.Hex() {
		t.Fatalf("unexpected tx hash: %s", event.TxHash)
	}
	if event.BlockNumber != blockNumber {
		t.Fatalf("unexpected block number: %d", event.BlockNumber)
	}
	if event.BlockTime.IsZero() {
		t.Fatalf("block time should be set")
	}

	revert := repo.revertByHash(userOpHash.Hex())
	if revert == nil {
		t.Fatalf("revert with hash %s not persisted", userOpHash.Hex())
	}
	if revert.RevertReason == "" {
		t.Fatalf("expected revert reason to be recorded")
	}

	deployment := repo.deploymentByHash(userOpHash.Hex())
	if deployment == nil {
		t.Fatalf("deployment with hash %s not persisted", userOpHash.Hex())
	}
	if !strings.EqualFold(deployment.Factory, factory.Hex()) {
		t.Fatalf("unexpected deployment factory: %s", deployment.Factory)
	}
	if !strings.EqualFold(deployment.Paymaster, paymaster.Hex()) {
		t.Fatalf("unexpected deployment paymaster: %s", deployment.Paymaster)
	}

	sponsorship := repo.sponsorshipByHash(userOpHash.Hex())
	if sponsorship == nil {
		t.Fatalf("sponsorship with hash %s not persisted", userOpHash.Hex())
	}

	cursor := repo.cursorFor(1, entryPoint.Hex())
	if cursor == nil {
		t.Fatalf("cursor not persisted")
	}
	if cursor.LastBlock < blockNumber {
		t.Fatalf("unexpected cursor last block: %d", cursor.LastBlock)
	}
	if cursor.LastTxHash != txHash.Hex() {
		t.Fatalf("unexpected cursor tx: %s", cursor.LastTxHash)
	}
}

func TestIndexerHandlesNewBlocks(t *testing.T) {
	t.Helper()

	entryPoint := common.HexToAddress("0x4337084d9e255ff0702461cf8895ce9e3b5ff108")
	sender := common.HexToAddress("0xe9eb4a51414de92c4dbe5a46f6259cb4f456d7f9")
	paymaster := common.HexToAddress("0xa566b84cc8e917a553c854a8503a0d3afbc93e88")

	block1 := uint64(10)
	block2 := uint64(12)
	tx1 := common.HexToHash("0x1")
	tx2 := common.HexToHash("0x2")
	userOp1 := common.HexToHash("0xaa")
	userOp2 := common.HexToHash("0xbb")

	evData1, err := userOperationEvent.Inputs.NonIndexed().Pack(
		big.NewInt(1),
		true,
		big.NewInt(1000),
		big.NewInt(500),
	)
	if err != nil {
		t.Fatalf("pack event1: %v", err)
	}
	evData2, err := userOperationEvent.Inputs.NonIndexed().Pack(
		big.NewInt(2),
		true,
		big.NewInt(2000),
		big.NewInt(700),
	)
	if err != nil {
		t.Fatalf("pack event2: %v", err)
	}

	initialLogs := []types.Log{
		{
			Address:     entryPoint,
			Topics:      []common.Hash{userOperationEvent.ID, userOp1, topicFromAddress(sender), topicFromAddress(paymaster)},
			Data:        evData1,
			BlockNumber: block1,
			TxHash:      tx1,
			Index:       0,
		},
	}

	repo := newMockRepo()
	client := newStubEthClient(initialLogs, block1, map[uint64]uint64{
		block1: uint64(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()),
		block2: uint64(time.Date(2025, 1, 1, 0, 0, 5, 0, time.UTC).Unix()),
	})

	cfg := Config{
		ChainID:           1,
		EntryPoint:        entryPoint,
		DeploymentBlock:   block1,
		ChunkSize:         64,
		Confirmations:     0,
		PollInterval:      10 * time.Millisecond,
		DecodeWorkerCount: 1,
		WriteWorkerCount:  1,
		ResubscribeDelay:  10 * time.Millisecond,
	}

	idx := New(cfg, repo, client, log.New(io.Discard, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- idx.Run(ctx) }()

	waitFor(t, 2*time.Second, func() bool {
		return repo.eventCount() == 1
	})

	newLogs := []types.Log{
		{
			Address:     entryPoint,
			Topics:      []common.Hash{userOperationEvent.ID, userOp2, topicFromAddress(sender), topicFromAddress(paymaster)},
			Data:        evData2,
			BlockNumber: block2,
			TxHash:      tx2,
			Index:       0,
		},
	}
	client.appendLogs(newLogs)
	client.setSafeHead(block2)

	waitFor(t, 2*time.Second, func() bool {
		return repo.eventCount() == 2
	})

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("indexer did not stop")
	}

	event2 := repo.eventByHash(userOp2.Hex())
	if event2 == nil {
		t.Fatalf("second event not persisted")
	}
	if event2.BlockNumber != block2 {
		t.Fatalf("expected block %d, got %d", block2, event2.BlockNumber)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func topicFromAddress(addr common.Address) common.Hash {
	return common.HexToHash("0x000000000000000000000000" + addr.Hex()[2:])
}

type stubEthClient struct {
	mu         sync.Mutex
	batches    [][]types.Log
	safeHead   uint64
	blockTimes map[uint64]uint64
}

func newStubEthClient(logs []types.Log, safeHead uint64, blockTimes map[uint64]uint64) *stubEthClient {
	batches := make([][]types.Log, 0, 1)
	if len(logs) > 0 {
		batches = append(batches, append([]types.Log(nil), logs...))
	}
	return &stubEthClient{
		batches:    batches,
		safeHead:   safeHead,
		blockTimes: blockTimes,
	}
}

func (s *stubEthClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		return nil, nil
	}
	out := append([]types.Log(nil), s.batches[0]...)
	s.batches = s.batches[1:]
	return out, nil
}

func (s *stubEthClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if number == nil {
		ts := s.blockTimes[s.safeHead]
		if ts == 0 {
			ts = uint64(time.Now().Unix())
		}
		return &types.Header{
			Number: new(big.Int).SetUint64(s.safeHead),
			Time:   ts,
		}, nil
	}
	bn := number.Uint64()
	ts := s.blockTimes[bn]
	if ts == 0 {
		ts = uint64(time.Now().Unix())
	}
	return &types.Header{
		Number: new(big.Int).SetUint64(bn),
		Time:   ts,
	}, nil
}

func (s *stubEthClient) appendLogs(logs []types.Log) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, append([]types.Log(nil), logs...))
}

func (s *stubEthClient) setSafeHead(head uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.safeHead = head
}

type mockRepo struct {
	mu       sync.Mutex
	cursors  map[string]*store.LogCursor
	events   map[string]*store.UserOperationEvent
	reverts  map[string]*store.UserOperationRevert
	deploys  map[string]*store.AccountDeployment
	inits    map[string]*store.SimpleAccountInitialization
	sponsors map[string]*store.Sponsorship
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		cursors:  make(map[string]*store.LogCursor),
		events:   make(map[string]*store.UserOperationEvent),
		reverts:  make(map[string]*store.UserOperationRevert),
		deploys:  make(map[string]*store.AccountDeployment),
		inits:    make(map[string]*store.SimpleAccountInitialization),
		sponsors: make(map[string]*store.Sponsorship),
	}
}

func (m *mockRepo) cursorKey(chainID uint64, address string) string {
	return strconv.FormatUint(chainID, 10) + "|" + address
}

func (m *mockRepo) GetLogCursor(ctx context.Context, chainID uint64, address string) (*store.LogCursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cursor, ok := m.cursors[m.cursorKey(chainID, address)]; ok {
		cloned := *cursor
		return &cloned, nil
	}
	return nil, nil
}

func (m *mockRepo) UpsertLogCursor(ctx context.Context, cursor *store.LogCursor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.cursorKey(cursor.ChainID, cursor.Address)
	cloned := *cursor
	m.cursors[key] = &cloned
	return nil
}

func (m *mockRepo) UpsertUserOperationEvent(ctx context.Context, event *store.UserOperationEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := *event
	m.events[event.UserOpHash] = &cloned
	return nil
}

func (m *mockRepo) UpsertUserOperationRevert(ctx context.Context, revert *store.UserOperationRevert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := *revert
	m.reverts[revert.UserOpHash] = &cloned
	return nil
}

func (m *mockRepo) UpsertAccountDeployment(ctx context.Context, dep *store.AccountDeployment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := *dep
	m.deploys[dep.UserOpHash] = &cloned
	return nil
}

func (m *mockRepo) UpsertSimpleAccountInitialization(ctx context.Context, init *store.SimpleAccountInitialization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := *init
	m.inits[init.Account] = &cloned
	return nil
}

func (m *mockRepo) UpsertSponsorship(ctx context.Context, s *store.Sponsorship) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := *s
	m.sponsors[s.UserOpHash] = &cloned
	return nil
}

func (m *mockRepo) eventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *mockRepo) revertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reverts)
}

func (m *mockRepo) deployCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.deploys)
}

func (m *mockRepo) sponsorshipCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sponsors)
}

func (m *mockRepo) eventByHash(hash string) *store.UserOperationEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ev, ok := m.events[hash]; ok {
		cloned := *ev
		return &cloned
	}
	return nil
}

func (m *mockRepo) revertByHash(hash string) *store.UserOperationRevert {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rv, ok := m.reverts[hash]; ok {
		cloned := *rv
		return &cloned
	}
	return nil
}

func (m *mockRepo) deploymentByHash(hash string) *store.AccountDeployment {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dep, ok := m.deploys[hash]; ok {
		cloned := *dep
		return &cloned
	}
	return nil
}

func (m *mockRepo) sponsorshipByHash(hash string) *store.Sponsorship {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sponsors[hash]; ok {
		cloned := *s
		return &cloned
	}
	return nil
}

func (m *mockRepo) cursorFor(chainID uint64, address string) *store.LogCursor {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cursor, ok := m.cursors[m.cursorKey(chainID, address)]; ok {
		cloned := *cursor
		return &cloned
	}
	return nil
}
