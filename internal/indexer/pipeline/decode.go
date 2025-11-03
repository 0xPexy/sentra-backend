package pipeline

import (
	"bytes"
	"context"
	"encoding/hex"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type decodeHandler func(ctx context.Context, lg types.Log) ([]writeRequest, error)

type decoder struct {
	cfg      Config
	blocks   *blockTimeCache
	client   EthClient
	callDec  *userOpCallDecoder
	logger   *log.Logger
	handlers map[common.Hash]decodeHandler
	topics   []common.Hash
}

func newDecoder(cfg Config, client EthClient, logger *log.Logger) *decoder {
	d := &decoder{
		cfg:    cfg,
		blocks: newBlockTimeCache(client),
		client: client,
		logger: logger,
	}
	d.callDec = newUserOpCallDecoder(cfg, client, logger)
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
	if d.callDec != nil {
		if target, selector, err := d.callDec.extract(ctx, lg.TxHash, event.UserOpHash); err != nil {
			d.logf("call metadata decode failed: hash=%s err=%v", event.UserOpHash, err)
		} else {
			if target != "" {
				event.Target = target
			}
			if selector != "" {
				event.CallSelector = selector
			}
		}
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

type callMetadata struct {
	target   string
	selector string
}

type userOpCallDecoder struct {
	cfg             Config
	client          EthClient
	logger          *log.Logger
	entryPoint      common.Address
	entryPointLower string
	chainID         *big.Int
	handleABI       abi.ABI
	simpleExecABI   abi.ABI
	handleOpsID     []byte
	handleOpID      []byte
	simpleExecID    []byte
}

func newUserOpCallDecoder(cfg Config, client EthClient, logger *log.Logger) *userOpCallDecoder {
	if client == nil {
		return nil
	}
	dec := &userOpCallDecoder{
		cfg:             cfg,
		client:          client,
		logger:          logger,
		entryPoint:      cfg.EntryPoint,
		entryPointLower: strings.ToLower(cfg.EntryPoint.Hex()),
		chainID:         new(big.Int).SetUint64(cfg.ChainID),
		handleABI:       entryPointHandleABI,
		simpleExecABI:   simpleAccountExecABI,
		handleOpsID:     entryPointHandleABI.Methods["handleOps"].ID,
		simpleExecID:    simpleAccountExecABI.Methods["execute"].ID,
	}
	if method, ok := entryPointHandleABI.Methods["handleOp"]; ok {
		dec.handleOpID = method.ID
	}
	return dec
}

func (d *userOpCallDecoder) extract(ctx context.Context, txHash common.Hash, userOpHash string) (string, string, error) {
	if d == nil {
		return "", "", nil
	}
	meta, err := d.decodeTransaction(ctx, txHash)
	if err != nil {
		return "", "", err
	}
	if meta == nil {
		return "", "", nil
	}
	key := strings.ToLower(userOpHash)
	if info, ok := meta[key]; ok {
		return info.target, info.selector, nil
	}
	return "", "", nil
}

func (d *userOpCallDecoder) decodeTransaction(ctx context.Context, txHash common.Hash) (map[string]callMetadata, error) {
	tx, _, err := d.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, nil
	}
	to := tx.To()
	if to == nil || strings.ToLower(to.Hex()) != d.entryPointLower {
		return nil, nil
	}
	data := tx.Data()
	if len(data) < 4 {
		return nil, nil
	}
	selector := data[:4]
	switch {
	case bytes.Equal(selector, d.handleOpsID):
		method := d.handleABI.Methods["handleOps"]
		values, err := method.Inputs.Unpack(data[4:])
		if err != nil {
			return nil, err
		}
		var input struct {
			Ops []abiUserOperation
		}
		if err := method.Inputs.Copy(&input, values); err != nil {
			return nil, err
		}
		return d.buildMetadata(input.Ops)
	case d.handleOpID != nil && bytes.Equal(selector, d.handleOpID):
		method := d.handleABI.Methods["handleOp"]
		values, err := method.Inputs.Unpack(data[4:])
		if err != nil {
			return nil, err
		}
		var input struct {
			Op abiUserOperation
		}
		if err := method.Inputs.Copy(&input, values); err != nil {
			return nil, err
		}
		return d.buildMetadata([]abiUserOperation{input.Op})
	default:
		return nil, nil
	}
}

func (d *userOpCallDecoder) buildMetadata(ops []abiUserOperation) (map[string]callMetadata, error) {
	out := make(map[string]callMetadata, len(ops))
	for _, op := range ops {
		hash, err := d.computeUserOpHash(op)
		if err != nil {
			if d.logger != nil {
				d.logger.Printf("call decoder: compute hash failed: %v", err)
			}
			continue
		}
		target, selector := d.decodeCallData(op.CallData)
		out[strings.ToLower(hash.Hex())] = callMetadata{
			target:   target,
			selector: selector,
		}
	}
	return out, nil
}

func (d *userOpCallDecoder) decodeCallData(callData []byte) (string, string) {
	if len(callData) < 4 {
		return "", ""
	}
	selector := "0x" + strings.ToLower(hex.EncodeToString(callData[:4]))
	target := ""
	if bytes.Equal(callData[:4], d.simpleExecID) {
		method := d.simpleExecABI.Methods["execute"]
		values, err := method.Inputs.Unpack(callData[4:])
		if err == nil {
			var input struct {
				Dest  common.Address
				Value *big.Int
				Func  []byte
			}
			if err := method.Inputs.Copy(&input, values); err == nil {
				target = strings.ToLower(input.Dest.Hex())
			}
		}
	}
	return target, selector
}

func (d *userOpCallDecoder) computeUserOpHash(op abiUserOperation) (common.Hash, error) {
	accountGas := new(big.Int).SetBytes(op.AccountGasLimits[:])
	gasFees := new(big.Int).SetBytes(op.GasFees[:])
	encoded, err := userOpHashArgs.Pack(
		userOpTypeHash,
		op.Sender,
		ensureBigInt(op.Nonce),
		hashBytes(op.InitCode),
		hashBytes(op.CallData),
		accountGas,
		ensureBigInt(op.PreVerificationGas),
		gasFees,
		hashBytes(op.PaymasterAndData),
		hashBytes(op.Signature),
	)
	if err != nil {
		return common.Hash{}, err
	}
	userOpHash := crypto.Keccak256Hash(encoded)
	domainEncoded, err := domainHashArgs.Pack(domainTypeHash, ensureBigInt(d.chainID), d.entryPoint)
	if err != nil {
		return common.Hash{}, err
	}
	domainHash := crypto.Keccak256Hash(domainEncoded)
	finalBytes := append([]byte{0x19, 0x01}, domainHash.Bytes()...)
	finalBytes = append(finalBytes, userOpHash.Bytes()...)
	return crypto.Keccak256Hash(finalBytes), nil
}

type abiUserOperation struct {
	Sender             common.Address `abi:"sender"`
	Nonce              *big.Int       `abi:"nonce"`
	InitCode           []byte         `abi:"initCode"`
	CallData           []byte         `abi:"callData"`
	AccountGasLimits   [32]byte       `abi:"accountGasLimits"`
	PreVerificationGas *big.Int       `abi:"preVerificationGas"`
	GasFees            [32]byte       `abi:"gasFees"`
	PaymasterAndData   []byte         `abi:"paymasterAndData"`
	Signature          []byte         `abi:"signature"`
}

func hashBytes(data []byte) common.Hash {
	if len(data) == 0 {
		return common.Hash{}
	}
	return crypto.Keccak256Hash(data)
}

func ensureBigInt(v *big.Int) *big.Int {
	if v == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(v)
}

func mustArguments(types ...string) abi.Arguments {
	args := make(abi.Arguments, len(types))
	for i, t := range types {
		typ, err := abi.NewType(t, "", nil)
		if err != nil {
			panic(err)
		}
		args[i] = abi.Argument{Type: typ}
	}
	return args
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

	entryPointHandleABI = mustParseABI(`[
		{"inputs":[{"components":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"bytes","name":"initCode","type":"bytes"},{"internalType":"bytes","name":"callData","type":"bytes"},{"internalType":"bytes32","name":"accountGasLimits","type":"bytes32"},{"internalType":"uint256","name":"preVerificationGas","type":"uint256"},{"internalType":"bytes32","name":"gasFees","type":"bytes32"},{"internalType":"bytes","name":"paymasterAndData","type":"bytes"},{"internalType":"bytes","name":"signature","type":"bytes"}],"internalType":"struct UserOperation[]","name":"ops","type":"tuple[]"},{"internalType":"address","name":"beneficiary","type":"address"}],"name":"handleOps","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"inputs":[{"components":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"bytes","name":"initCode","type":"bytes"},{"internalType":"bytes","name":"callData","type":"bytes"},{"internalType":"bytes32","name":"accountGasLimits","type":"bytes32"},{"internalType":"uint256","name":"preVerificationGas","type":"uint256"},{"internalType":"bytes32","name":"gasFees","type":"bytes32"},{"internalType":"bytes","name":"paymasterAndData","type":"bytes"},{"internalType":"bytes","name":"signature","type":"bytes"}],"internalType":"struct UserOperation","name":"op","type":"tuple"},{"internalType":"address","name":"beneficiary","type":"address"}],"name":"handleOp","outputs":[],"stateMutability":"payable","type":"function"}
	]`)

	simpleAccountABI = mustParseABI(`[
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entryPoint","type":"address"},{"indexed":true,"internalType":"address","name":"owner","type":"address"}],"name":"SimpleAccountInitialized","type":"event"}
	]`)

	simpleAccountExecABI = mustParseABI(`[
		{"inputs":[{"internalType":"address","name":"dest","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"func","type":"bytes"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"}
	]`)

	paymasterABI = mustParseABI(`[
		{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"userOpHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"uint48","name":"validUntil","type":"uint48"},{"indexed":false,"internalType":"uint48","name":"validAfter","type":"uint48"}],"name":"Sponsored","type":"event"}
	]`)

	userOperationEvent       = entryPointEventsABI.Events["UserOperationEvent"]
	userOperationRevertEvent = entryPointEventsABI.Events["UserOperationRevertReason"]
	accountDeployedEvent     = entryPointEventsABI.Events["AccountDeployed"]
	simpleAccountInitEvent   = simpleAccountABI.Events["SimpleAccountInitialized"]
	sponsoredEvent           = paymasterABI.Events["Sponsored"]

	userOpTypeHash = crypto.Keccak256Hash([]byte("PackedUserOperation(address sender,uint256 nonce,bytes32 initCodeHash,bytes32 callDataHash,uint256 accountGasLimits,uint256 preVerificationGas,uint256 gasFees,bytes32 paymasterAndDataHash,bytes32 signatureHash)"))
	domainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(uint256 chainId,address verifyingContract)"))
	userOpHashArgs = mustArguments("bytes32", "address", "uint256", "bytes32", "bytes32", "uint256", "uint256", "uint256", "bytes32", "bytes32")
	domainHashArgs = mustArguments("bytes32", "uint256", "address")
)
