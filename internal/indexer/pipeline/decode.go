package pipeline

import (
	"context"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

type decodeHandler func(ctx context.Context, lg types.Log) ([]writeRequest, error)

type decoder struct {
	cfg      Config
	blocks   *blockTimeCache
	logger   *log.Logger
	handlers map[common.Hash]decodeHandler
	topics   []common.Hash
}

func newDecoder(cfg Config, client EthClient, logger *log.Logger) *decoder {
	d := &decoder{
		cfg:    cfg,
		blocks: newBlockTimeCache(client),
		logger: logger,
	}
	d.handlers = map[common.Hash]decodeHandler{
		userOperationEvent.ID:       d.decodeUserOperationEvent,
		userOperationRevertEvent.ID: d.decodeUserOperationRevert,
		accountDeployedEvent.ID:     d.decodeAccountDeployed,
		simpleAccountInitEvent.ID:   d.decodeSimpleAccountInit,
		sponsoredEvent.ID:           d.decodeSponsored,
	}
	d.topics = make([]common.Hash, 0, len(d.handlers))
	for topic := range d.handlers {
		d.topics = append(d.topics, topic)
	}
	return d
}

func (d *decoder) topicsList() []common.Hash {
	return d.topics
}

func (d *decoder) decode(ctx context.Context, lg types.Log) ([]writeRequest, error) {
	if len(lg.Topics) == 0 {
		return nil, nil
	}
	handler, ok := d.handlers[lg.Topics[0]]
	if !ok {
		return nil, nil
	}
	return handler(ctx, lg)
}

func (d *decoder) decodeUserOperationEvent(ctx context.Context, lg types.Log) ([]writeRequest, error) {
	if len(lg.Topics) < 4 {
		d.logf("Skipping UserOperationEvent: insufficient topics (got %d)", len(lg.Topics))
		return nil, nil
	}
	values, err := userOperationEvent.Inputs.NonIndexed().Unpack(lg.Data)
	if err != nil {
		d.logf("Failed to unpack UserOperationEvent: %v", err)
		return nil, nil
	}
	if len(values) != 4 {
		d.logf("Unexpected UserOperationEvent decode length: %d", len(values))
		return nil, nil
	}
	nonce, _ := values[0].(*big.Int)
	success, _ := values[1].(bool)
	actualGasCost, _ := values[2].(*big.Int)
	actualGasUsed, _ := values[3].(*big.Int)

	var blockTime time.Time
	if ts, err := d.blocks.Time(ctx, lg.BlockNumber); err == nil {
		blockTime = ts
	} else {
		d.logf("indexer: failed block time for %d: %v", lg.BlockNumber, err)
	}

	paymaster := common.BytesToAddress(lg.Topics[3].Bytes())
	event := &store.UserOperationEvent{
		ChainID:       d.cfg.ChainID,
		EntryPoint:    lg.Address.Hex(),
		UserOpHash:    lg.Topics[1].Hex(),
		Sender:        common.BytesToAddress(lg.Topics[2].Bytes()).Hex(),
		Paymaster:     normalizeOptionalAddress(paymaster),
		Nonce:         bigString(nonce),
		Success:       success,
		ActualGasCost: bigString(actualGasCost),
		ActualGasUsed: bigString(actualGasUsed),
		TxHash:        lg.TxHash.Hex(),
		BlockNumber:   lg.BlockNumber,
		LogIndex:      uint(lg.Index),
		BlockTime:     blockTime,
	}
	d.logf("UserOp event: hash=%s tx=%s success=%t block=%d", event.UserOpHash, event.TxHash, event.Success, event.BlockNumber)

	req := writeRequest{
		name: "user_operation_event",
		apply: func(ctx context.Context, repo Repo) error {
			return repo.UpsertUserOperationEvent(ctx, event)
		},
	}
	return []writeRequest{req}, nil
}

func (d *decoder) decodeUserOperationRevert(ctx context.Context, lg types.Log) ([]writeRequest, error) {
	if len(lg.Topics) < 3 {
		d.logf("Skipping UserOperationRevertReason: insufficient topics (got %d)", len(lg.Topics))
		return nil, nil
	}
	values, err := userOperationRevertEvent.Inputs.NonIndexed().Unpack(lg.Data)
	if err != nil {
		d.logf("Failed to unpack UserOperationRevertReason: %v", err)
		return nil, nil
	}
	if len(values) != 2 {
		d.logf("Unexpected UserOperationRevertReason decode length: %d", len(values))
		return nil, nil
	}
	nonce, _ := values[0].(*big.Int)
	rawReason, _ := values[1].([]byte)
	reason := hexutil.Encode(rawReason)

	revert := &store.UserOperationRevert{
		ChainID:      d.cfg.ChainID,
		EntryPoint:   lg.Address.Hex(),
		UserOpHash:   lg.Topics[1].Hex(),
		Sender:       common.BytesToAddress(lg.Topics[2].Bytes()).Hex(),
		Nonce:        bigString(nonce),
		RevertReason: reason,
		TxHash:       lg.TxHash.Hex(),
		BlockNumber:  lg.BlockNumber,
		LogIndex:     uint(lg.Index),
	}
	d.logf("UserOp revert: hash=%s tx=%s block=%d revertLen=%d", revert.UserOpHash, revert.TxHash, revert.BlockNumber, len(rawReason))

	req := writeRequest{
		name: "user_operation_revert",
		apply: func(ctx context.Context, repo Repo) error {
			return repo.UpsertUserOperationRevert(ctx, revert)
		},
	}
	return []writeRequest{req}, nil
}

func (d *decoder) decodeAccountDeployed(ctx context.Context, lg types.Log) ([]writeRequest, error) {
	if len(lg.Topics) < 3 {
		d.logf("Skipping AccountDeployed: insufficient topics (got %d)", len(lg.Topics))
		return nil, nil
	}
	values, err := accountDeployedEvent.Inputs.NonIndexed().Unpack(lg.Data)
	if err != nil {
		d.logf("Failed to unpack AccountDeployed: %v", err)
		return nil, nil
	}
	if len(values) != 1 {
		d.logf("Unexpected AccountDeployed decode length: %d", len(values))
		return nil, nil
	}
	pmAddr, _ := values[0].(common.Address)

	dep := &store.AccountDeployment{
		ChainID:    d.cfg.ChainID,
		EntryPoint: lg.Address.Hex(),
		UserOpHash: lg.Topics[1].Hex(),
		Sender:     common.BytesToAddress(lg.Topics[2].Bytes()).Hex(),
		Factory: func() string {
			if len(lg.Topics) >= 4 {
				return common.BytesToAddress(lg.Topics[3].Bytes()).Hex()
			}
			return ""
		}(),
		Paymaster:   normalizeOptionalAddress(pmAddr),
		TxHash:      lg.TxHash.Hex(),
		BlockNumber: lg.BlockNumber,
		LogIndex:    uint(lg.Index),
	}

	req := writeRequest{
		name: "account_deployment",
		apply: func(ctx context.Context, repo Repo) error {
			return repo.UpsertAccountDeployment(ctx, dep)
		},
	}
	return []writeRequest{req}, nil
}

func (d *decoder) decodeSimpleAccountInit(ctx context.Context, lg types.Log) ([]writeRequest, error) {
	if len(lg.Topics) < 3 {
		d.logf("Skipping SimpleAccountInitialized: insufficient topics (got %d)", len(lg.Topics))
		return nil, nil
	}
	entryPoint := common.BytesToAddress(lg.Topics[1].Bytes())
	if !strings.EqualFold(entryPoint.Hex(), d.cfg.EntryPoint.Hex()) {
		return nil, nil
	}
	init := &store.SimpleAccountInitialization{
		ChainID:     d.cfg.ChainID,
		Account:     lg.Address.Hex(),
		EntryPoint:  entryPoint.Hex(),
		Owner:       common.BytesToAddress(lg.Topics[2].Bytes()).Hex(),
		TxHash:      lg.TxHash.Hex(),
		BlockNumber: lg.BlockNumber,
		LogIndex:    uint(lg.Index),
	}
	req := writeRequest{
		name: "simple_account_initialization",
		apply: func(ctx context.Context, repo Repo) error {
			return repo.UpsertSimpleAccountInitialization(ctx, init)
		},
	}
	return []writeRequest{req}, nil
}

func (d *decoder) decodeSponsored(ctx context.Context, lg types.Log) ([]writeRequest, error) {
	if len(lg.Topics) < 3 {
		d.logf("Skipping Sponsored: insufficient topics (got %d)", len(lg.Topics))
		return nil, nil
	}
	values, err := sponsoredEvent.Inputs.NonIndexed().Unpack(lg.Data)
	if err != nil {
		d.logf("Failed to unpack Sponsored: %v", err)
		return nil, nil
	}
	if len(values) != 2 {
		d.logf("Unexpected Sponsored decode length: %d", len(values))
		return nil, nil
	}
	validUntil, _ := values[0].(*big.Int)
	validAfter, _ := values[1].(*big.Int)

	sponsorship := &store.Sponsorship{
		ChainID:     d.cfg.ChainID,
		Paymaster:   strings.ToLower(lg.Address.Hex()),
		UserOpHash:  lg.Topics[1].Hex(),
		Sender:      common.BytesToAddress(lg.Topics[2].Bytes()).Hex(),
		ValidUntil:  bigString(validUntil),
		ValidAfter:  bigString(validAfter),
		TxHash:      lg.TxHash.Hex(),
		BlockNumber: lg.BlockNumber,
		LogIndex:    uint(lg.Index),
	}

	req := writeRequest{
		name: "sponsorship",
		apply: func(ctx context.Context, repo Repo) error {
			return repo.UpsertSponsorship(ctx, sponsorship)
		},
	}
	return []writeRequest{req}, nil
}

func (d *decoder) logf(format string, args ...any) {
	if d.logger != nil {
		d.logger.Printf(format, args...)
	}
}

func bigString(x *big.Int) string {
	if x == nil {
		return "0"
	}
	return x.String()
}

func normalizeOptionalAddress(addr common.Address) string {
	if addr == (common.Address{}) {
		return ""
	}
	return addr.Hex()
}

func mustParseABI(jsonStr string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(jsonStr))
	if err != nil {
		panic(err)
	}
	return parsed
}

var (
	entryPointEventsABI = mustParseABI(`[
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"userOpHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":true,"internalType":"address","name":"paymaster","type":"address"},{"indexed":false,"internalType":"uint256","name":"nonce","type":"uint256"},{"indexed":false,"internalType":"bool","name":"success","type":"bool"},{"indexed":false,"internalType":"uint256","name":"actualGasCost","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"actualGasUsed","type":"uint256"}],"name":"UserOperationEvent","type":"event"},
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"userOpHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint256","name":"nonce","type":"uint256"},{"indexed":false,"internalType":"bytes","name":"revertReason","type":"bytes"}],"name":"UserOperationRevertReason","type":"event"},
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"userOpHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":true,"internalType":"address","name":"factory","type":"address"},{"indexed":false,"internalType":"address","name":"paymaster","type":"address"}],"name":"AccountDeployed","type":"event"}
	]`)

	simpleAccountABI = mustParseABI(`[
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entryPoint","type":"address"},{"indexed":true,"internalType":"address","name":"owner","type":"address"}],"name":"SimpleAccountInitialized","type":"event"}
	]`)

	paymasterABI = mustParseABI(`[
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"userOpHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint48","name":"validUntil","type":"uint48"},{"indexed":false,"internalType":"uint48","name":"validAfter","type":"uint48"}],"name":"Sponsored","type":"event"}
	]`)

	userOperationEvent       = entryPointEventsABI.Events["UserOperationEvent"]
	userOperationRevertEvent = entryPointEventsABI.Events["UserOperationRevertReason"]
	accountDeployedEvent     = entryPointEventsABI.Events["AccountDeployed"]
	simpleAccountInitEvent   = simpleAccountABI.Events["SimpleAccountInitialized"]
	sponsoredEvent           = paymasterABI.Events["Sponsored"]
)
