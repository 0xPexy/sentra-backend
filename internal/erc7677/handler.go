package erc7677

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
)

type paymasterRepo interface {
	GetCurrentPaymaster(ctx context.Context) (*store.Paymaster, error)
	GetContractByAddress(ctx context.Context, paymasterID uint, address string) (*store.ContractWhitelist, error)
}

type policySigner interface {
	signPolicyMessage(common.Hash) ([]byte, error)
}

type ethClient interface {
	BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

type validityProvider interface {
	DefaultValidity() time.Duration
}

const defaultValidityWindow = 10 * time.Minute

type Handler struct {
	cfg             config.Config
	repo            paymasterRepo
	signer          policySigner
	eth             ethClient
	logger          *log.Logger
	defaultValidFor time.Duration
}

var stubSignatureBytes = func() []byte {
	buf := make([]byte, 65)
	for i := 0; i < 64; i++ {
		buf[i] = 0xaa
	}
	buf[64] = 0x1c
	return buf
}()

type rpcError struct {
	code    int
	message string
}

func (e rpcError) Error() string {
	return e.message
}

func newRPCError(code int, msg string) error {
	return rpcError{code: code, message: msg}
}

type userOperation struct {
	Sender               common.Address
	Nonce                *big.Int
	InitCode             []byte
	CallData             []byte
	CallGasLimit         *big.Int
	VerificationGasLimit *big.Int
	PreVerificationGas   *big.Int
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	PaymasterAndData     []byte
	Signature            []byte
}

type packedUserOperation struct {
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

func (op *userOperation) toPacked() *packedUserOperation {
	return &packedUserOperation{
		Sender:             op.Sender,
		Nonce:              ensureBigInt(op.Nonce),
		InitCode:           op.InitCode,
		CallData:           op.CallData,
		AccountGasLimits:   packUint128Bytes(op.VerificationGasLimit, op.CallGasLimit),
		PreVerificationGas: ensureBigInt(op.PreVerificationGas),
		GasFees:            packUint128Bytes(op.MaxPriorityFeePerGas, op.MaxFeePerGas),
		PaymasterAndData:   op.PaymasterAndData,
		Signature:          op.Signature,
	}
}

func NewHandler(cfg config.Config, repo *store.Repository, p *Policy, s *Signer, eth *ethclient.Client, logger *log.Logger) *Handler {
	return newHandler(cfg, repo, p, s, eth, logger)
}

func newHandler(cfg config.Config, repo paymasterRepo, p validityProvider, signer policySigner, eth ethClient, logger *log.Logger) *Handler {
	if logger == nil {
		logger = log.New(log.Writer(), "erc7677: ", log.LstdFlags)
	}
	validFor := defaultValidityWindow
	if p != nil {
		if dur := p.DefaultValidity(); dur > 0 {
			validFor = dur
		}
	}
	return &Handler{
		cfg:             cfg,
		repo:            repo,
		signer:          signer,
		eth:             eth,
		logger:          logger,
		defaultValidFor: validFor,
	}
}

const entryPointABIJSON = `[{"inputs":[{"components":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"bytes","name":"initCode","type":"bytes"},{"internalType":"bytes","name":"callData","type":"bytes"},{"internalType":"bytes32","name":"accountGasLimits","type":"bytes32"},{"internalType":"uint256","name":"preVerificationGas","type":"uint256"},{"internalType":"bytes32","name":"gasFees","type":"bytes32"},{"internalType":"bytes","name":"paymasterAndData","type":"bytes"},{"internalType":"bytes","name":"signature","type":"bytes"}],"internalType":"struct PackedUserOperation","name":"userOp","type":"tuple"}],"name":"getUserOpHash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"}]`

var entryPointABI = mustParseABI(entryPointABIJSON)

func mustParseABI(jsonStr string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(jsonStr))
	if err != nil {
		panic(err)
	}
	return parsed
}

func (h *Handler) logf(format string, args ...any) {
	if h.logger == nil {
		return
	}
	h.logger.Printf(format, args...)
}

func (h *Handler) logUserOperation(prefix string, op *userOperation) {
	if h.logger == nil {
		return
	}
	if op == nil {
		h.logger.Printf("%s userOp=nil", prefix)
		return
	}
	h.logger.Printf("%s sender=%s nonce=%s initCodeLen=%d callDataLen=%d callGas=%s verifyGas=%s preVerif=%s maxFee=%s maxPriority=%s paymasterLen=%d",
		prefix,
		op.Sender.Hex(),
		ensureBigInt(op.Nonce).String(),
		len(op.InitCode),
		len(op.CallData),
		ensureBigInt(op.CallGasLimit).String(),
		ensureBigInt(op.VerificationGasLimit).String(),
		ensureBigInt(op.PreVerificationGas).String(),
		ensureBigInt(op.MaxFeePerGas).String(),
		ensureBigInt(op.MaxPriorityFeePerGas).String(),
		len(op.PaymasterAndData),
	)
}

func (h *Handler) logPackedUserOperation(prefix string, packed *packedUserOperation) {
	if h.logger == nil {
		return
	}
	if packed == nil {
		h.logger.Printf("%s packedUserOp=nil", prefix)
		return
	}
	h.logger.Printf("%s sender=%s nonce=%s accountGasLimits=%s gasFees=%s paymasterLen=%d signatureLen=%d",
		prefix,
		packed.Sender.Hex(),
		fmt.Sprintf("0x%s", ensureBigInt(packed.Nonce).Text(16)),
		hex.EncodeToString(packed.AccountGasLimits[:]),
		hex.EncodeToString(packed.GasFees[:]),
		len(packed.PaymasterAndData),
		len(packed.Signature),
	)
}

func (h *Handler) writeError(c *gin.Context, id any, err error) {
	var rerr rpcError
	if errors.As(err, &rerr) {
		c.JSON(http.StatusOK, rpcErr(id, rerr.code, rerr.message))
		return
	}
	if err != nil {
		h.logf("internal error: %v", err)
	}
	c.JSON(http.StatusOK, rpcErr(id, -32000, "internal error"))
}

var (
	userOpTypeHash = crypto.Keccak256Hash([]byte("PackedUserOperation(address sender,uint256 nonce,bytes32 initCodeHash,bytes32 callDataHash,uint256 accountGasLimits,uint256 preVerificationGas,uint256 gasFees,bytes32 paymasterAndDataHash,bytes32 signatureHash)"))
	domainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(uint256 chainId,address verifyingContract)"))
	userOpHashArgs = mustArguments(
		"bytes32", "address", "uint256", "bytes32", "bytes32", "uint256", "uint256", "uint256", "bytes32", "bytes32",
	)
	domainHashArgs  = mustArguments("bytes32", "uint256", "address")
	mask128         = new(big.Int).Lsh(big.NewInt(1), 128)
	mask128MinusOne = new(big.Int).Sub(mask128, big.NewInt(1))
)

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

func appendUint128(buf []byte, value uint64) []byte {
	var tmp [16]byte
	binary.BigEndian.PutUint64(tmp[8:], value)
	return append(buf, tmp[:]...)
}

func writeUint128(dst []byte, value *big.Int) {
	for i := range dst {
		dst[i] = 0
	}
	val := new(big.Int).And(ensureBigInt(value), mask128MinusOne)
	bytes := val.Bytes()
	if len(bytes) > len(dst) {
		bytes = bytes[len(bytes)-len(dst):]
	}
	copy(dst[len(dst)-len(bytes):], bytes)
}

func packUint128Bytes(high, low *big.Int) [32]byte {
	var out [32]byte
	writeUint128(out[0:16], high)
	writeUint128(out[16:32], low)
	return out
}

func (h *Handler) resolveValidDuration(ctxMap map[string]any) time.Duration {
	valid := h.defaultValidFor
	if valid <= 0 {
		valid = defaultValidityWindow
	}
	if s, ok := ctxMap["validForSec"].(float64); ok && s > 0 {
		valid = time.Duration(uint64(s)) * time.Second
	}
	return valid
}

func (h *Handler) computeValidity(ctx context.Context, validFor time.Duration) (uint64, uint64) {
	if validFor <= 0 {
		validFor = h.defaultValidFor
		if validFor <= 0 {
			validFor = defaultValidityWindow
		}
	}
	parentTs, latestTs := h.blockTimestamps(ctx)
	validAfter := parentTs
	if validAfter > 60 {
		validAfter -= 60
	} else {
		validAfter = 0
	}
	if latestTs > 0 && validAfter > latestTs {
		validAfter = latestTs
	}
	validUntil := uint64(time.Now().Add(validFor).Unix())
	if validUntil <= validAfter {
		validUntil = validAfter + uint64(validFor/time.Second)
		if validUntil <= validAfter {
			validUntil = validAfter + 600
		}
	}
	return validAfter, validUntil
}

func (h *Handler) wrapPolicyData(payload []byte) []byte {
	out := make([]byte, 0, 32+len(payload))
	out = appendUint128(out, h.cfg.Paymaster.ValidationGas)
	out = appendUint128(out, h.cfg.Paymaster.PostOpGas)
	out = append(out, payload...)
	return out
}

func hashUserOperationLocal(entryPoint common.Address, chainID *big.Int, op *userOperation) (common.Hash, error) {
	initHash := hashBytes(op.InitCode)
	callHash := hashBytes(op.CallData)
	paymasterHash := hashBytes(op.PaymasterAndData)
	sigHash := hashBytes(op.Signature)
	accountGasBytes := packUint128Bytes(op.VerificationGasLimit, op.CallGasLimit)
	gasFeesBytes := packUint128Bytes(op.MaxPriorityFeePerGas, op.MaxFeePerGas)
	accountGas := new(big.Int).SetBytes(accountGasBytes[:])
	gasFees := new(big.Int).SetBytes(gasFeesBytes[:])

	encoded, err := userOpHashArgs.Pack(
		userOpTypeHash,
		op.Sender,
		ensureBigInt(op.Nonce),
		initHash,
		callHash,
		accountGas,
		ensureBigInt(op.PreVerificationGas),
		gasFees,
		paymasterHash,
		sigHash,
	)
	if err != nil {
		return common.Hash{}, err
	}
	userOpHash := crypto.Keccak256Hash(encoded)

	domainEncoded, err := domainHashArgs.Pack(domainTypeHash, chainID, entryPoint)
	if err != nil {
		return common.Hash{}, err
	}
	domainHash := crypto.Keccak256Hash(domainEncoded)

	finalBytes := append([]byte{0x19, 0x01}, domainHash.Bytes()...)
	finalBytes = append(finalBytes, userOpHash.Bytes()...)
	return crypto.Keccak256Hash(finalBytes), nil
}

type rpcCallParams struct {
	userOpRaw  map[string]any
	entryPoint string
	chain      any
	ctx        map[string]any
}

func parseRPCParams(raw json.RawMessage) (rpcCallParams, error) {
	var in []any
	if err := json.Unmarshal(raw, &in); err != nil {
		return rpcCallParams{}, newRPCError(errInvalidParams, "invalid params")
	}
	if len(in) != 4 {
		return rpcCallParams{}, newRPCError(errInvalidParams, "invalid params")
	}
	userOp, ok := in[0].(map[string]any)
	if !ok {
		return rpcCallParams{}, newRPCError(errInvalidParams, "userOp must be an object")
	}
	entryPoint, _ := in[1].(string)
	ctxMap, _ := in[3].(map[string]any)
	return rpcCallParams{
		userOpRaw:  userOp,
		entryPoint: strings.TrimSpace(entryPoint),
		chain:      in[2],
		ctx:        ctxMap,
	}, nil
}

// HandleJSONRPC godoc
// @Summary Execute ERC-7677 paymaster JSON-RPC methods
// @Description Handles pm_getPaymasterData and pm_getPaymasterStubData for the configured paymaster.
// @Tags Paymaster
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body JSONRPCRequest true "JSON-RPC request"
// @Success 200 {object} JSONRPCResponse
// @Router /api/v1/erc7677 [post]
func (h *Handler) HandleJSONRPC(c *gin.Context) {
	var req rpcRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, rpcErr(nil, errInvalidRequest, "invalid json"))
		return
	}
	switch req.Method {
	case "pm_getPaymasterStubData":
		h.stub(c, req)
	case "pm_getPaymasterData":
		h.data(c, req)
	default:
		c.JSON(http.StatusOK, rpcErr(req.ID, errMethodNotFound, "method not found"))
	}
}

func (h *Handler) stub(c *gin.Context, req rpcRequest) {
	params, err := parseRPCParams(req.Params)
	if err != nil {
		h.writeError(c, req.ID, err)
		return
	}
	policy := PolicyInput{
		Target:   strOr(params.ctx["target"], ""),
		Selector: strOr(params.ctx["selector"], ""),
	}
	validFor := h.resolveValidDuration(params.ctx)
	pm, err := h.resolvePaymaster(c)
	if err != nil {
		h.writeError(c, req.ID, err)
		return
	}
	if err := h.ensureAllowedTarget(c.Request.Context(), pm, &policy); err != nil {
		h.writeError(c, req.ID, err)
		return
	}
	validAfter, validUntil := h.computeValidity(c.Request.Context(), validFor)

	userOp, err := parseUserOperation(params.userOpRaw)
	if err != nil {
		h.writeError(c, req.ID, newRPCError(errInvalidParams, err.Error()))
		return
	}
	pmAddr := common.HexToAddress(pm.Address)
	policyData := append([]byte(nil), buildPMDPrefix(validAfter, validUntil, policy)...)
	policyWithStubSig := append(policyData, stubSignatureBytes...)
	envelope := h.wrapPolicyData(policyWithStubSig)
	userOp.PaymasterAndData = append(pmAddr.Bytes(), envelope...)

	h.logUserOperation("pm_getPaymasterStubData", userOp)

	out := PaymasterStubResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     pm.Address,
		PaymasterData:                 hex0x(policyWithStubSig),
		PaymasterVerificationGasLimit: hexUint(h.cfg.Paymaster.ValidationGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.Paymaster.PostOpGas),
		IsFinal:                       false,
	}
	c.JSON(http.StatusOK, rpcOK(req.ID, out))
}

func (h *Handler) data(c *gin.Context, req rpcRequest) {
	params, err := parseRPCParams(req.Params)
	if err != nil {
		h.writeError(c, req.ID, err)
		return
	}
	if params.entryPoint == "" {
		h.writeError(c, req.ID, newRPCError(errInvalidParams, "entryPoint required"))
		return
	}
	chainID, err := parseChainID(params.chain)
	if err != nil {
		h.writeError(c, req.ID, newRPCError(errInvalidParams, err.Error()))
		return
	}
	policy := PolicyInput{
		Target:   strOr(params.ctx["target"], ""),
		Selector: strOr(params.ctx["selector"], ""),
	}
	validFor := h.resolveValidDuration(params.ctx)
	pm, err := h.resolvePaymaster(c)
	if err != nil {
		h.writeError(c, req.ID, err)
		return
	}
	if err := h.ensureAllowedTarget(c.Request.Context(), pm, &policy); err != nil {
		h.writeError(c, req.ID, err)
		return
	}
	validAfter, validUntil := h.computeValidity(c.Request.Context(), validFor)

	userOp, err := parseUserOperation(params.userOpRaw)
	if err != nil {
		h.writeError(c, req.ID, newRPCError(errInvalidParams, err.Error()))
		return
	}
	pmAddr := common.HexToAddress(pm.Address)
	policyData := append([]byte(nil), buildPMDPrefix(validAfter, validUntil, policy)...)
	unsignedEnvelope := h.wrapPolicyData(policyData)
	userOp.PaymasterAndData = append(pmAddr.Bytes(), unsignedEnvelope...)

	h.logUserOperation("pm_getPaymasterData", userOp)

	hash, err := h.userOpHash(c.Request.Context(), params.entryPoint, chainID, userOp)
	if err != nil {
		h.writeError(c, req.ID, newRPCError(-32000, err.Error()))
		return
	}
	sig, err := h.signer.signPolicyMessage(hash)
	if err != nil {
		h.writeError(c, req.ID, newRPCError(-32000, "signing failed"))
		return
	}
	h.logf("pm_getPaymasterData sig=%s", hex0x(sig))
	policyDataWithSig := append(append([]byte(nil), policyData...), sig...)
	signedEnvelope := h.wrapPolicyData(policyDataWithSig)
	userOp.PaymasterAndData = append(pmAddr.Bytes(), signedEnvelope...)

	out := PaymasterDataResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     pm.Address,
		PaymasterData:                 hex0x(policyDataWithSig),
		PaymasterVerificationGasLimit: hexUint(h.cfg.Paymaster.ValidationGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.Paymaster.PostOpGas),
	}
	c.JSON(http.StatusOK, rpcOK(req.ID, out))
}

func (h *Handler) resolvePaymaster(c *gin.Context) (*store.Paymaster, error) {
	adminID := c.GetUint("adminID")
	pm, err := h.repo.GetCurrentPaymaster(c.Request.Context())
	if err != nil {
		h.logf("load paymaster failed: adminID=%d err=%v", adminID, err)
		return nil, newRPCError(-32000, "failed to load paymaster")
	}
	if pm == nil || pm.Address == "" {
		return nil, newRPCError(-32000, "paymaster not registered")
	}
	pm.Address = strings.ToLower(pm.Address)
	return pm, nil
}

func parseUserOperation(raw any) (*userOperation, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("userOp must be an object")
	}
	getString := func(key string) string {
		if v, ok := m[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	senderHex := getString("sender")
	if senderHex == "" {
		return nil, errors.New("userOp.sender missing")
	}
	op := &userOperation{Sender: common.HexToAddress(senderHex)}

	var err error
	if op.Nonce, err = decodeBig(getString("nonce")); err != nil {
		return nil, err
	}
	if op.InitCode, err = decodeAnyBytes(m, "initCode"); err != nil {
		return nil, err
	}
	if op.CallData, err = decodeAnyBytes(m, "callData"); err != nil {
		return nil, err
	}
	if op.CallGasLimit, err = decodeBig(getString("callGasLimit")); err != nil {
		return nil, err
	}
	if op.VerificationGasLimit, err = decodeBig(getString("verificationGasLimit")); err != nil {
		return nil, err
	}
	if op.PreVerificationGas, err = decodeBig(getString("preVerificationGas")); err != nil {
		return nil, err
	}
	if op.MaxFeePerGas, err = decodeBig(getString("maxFeePerGas")); err != nil {
		return nil, err
	}
	if op.MaxPriorityFeePerGas, err = decodeBig(getString("maxPriorityFeePerGas")); err != nil {
		return nil, err
	}
	if op.PaymasterAndData, err = decodeAnyBytes(m, "paymasterAndData"); err != nil {
		return nil, err
	}
	if op.Signature, err = decodeAnyBytes(m, "signature"); err != nil {
		return nil, err
	}
	if factory := getString("factory"); factory != "" {
		if !common.IsHexAddress(factory) {
			return nil, fmt.Errorf("invalid factory address")
		}
		init := common.HexToAddress(factory).Bytes()
		if factoryData, err := decodeAnyBytes(m, "factoryData"); err != nil {
			return nil, err
		} else if len(factoryData) > 0 {
			init = append(init, factoryData...)
		}
		op.InitCode = init
	}
	return op, nil
}

func decodeBytes(s string) ([]byte, error) {
	if s == "" || s == "0x" {
		return []byte{}, nil
	}
	return hexutil.Decode(s)
}

func decodeAnyBytes(m map[string]any, key string) ([]byte, error) {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return decodeBytes(strings.TrimSpace(val))
		case []byte:
			return val, nil
		case []any:
			buf := make([]byte, 0)
			for _, part := range val {
				str, ok := part.(string)
				if !ok {
					return nil, fmt.Errorf("%s must be hex string", key)
				}
				b, err := decodeBytes(strings.TrimSpace(str))
				if err != nil {
					return nil, err
				}
				buf = append(buf, b...)
			}
			return buf, nil
		case map[string]any:
			if hexStr, ok := val["hex"].(string); ok {
				return decodeBytes(strings.TrimSpace(hexStr))
			}
			if data, ok := val["data"].([]any); ok {
				buf := make([]byte, 0)
				for _, piece := range data {
					num, ok := piece.(float64)
					if !ok {
						return nil, fmt.Errorf("%s data must be byte array", key)
					}
					buf = append(buf, byte(num))
				}
				return buf, nil
			}
			return nil, fmt.Errorf("unsupported %s object", key)
		default:
			return nil, fmt.Errorf("unsupported %s type", key)
		}
	}
	return []byte{}, nil
}

func (h *Handler) ensureAllowedTarget(ctx context.Context, pm *store.Paymaster, policy *PolicyInput) error {
	target := strings.ToLower(strings.TrimSpace(policy.Target))
	if target == "" {
		return newRPCError(errInvalidParams, "target required")
	}
	if !common.IsHexAddress(target) {
		return newRPCError(errInvalidParams, "invalid target address")
	}
	contract, err := h.repo.GetContractByAddress(ctx, pm.ID, target)
	if err != nil {
		h.logf("allowlist lookup failed: paymasterID=%d target=%s err=%v", pm.ID, target, err)
		return newRPCError(-32000, "allowlist lookup failed")
	}
	if contract == nil {
		return newRPCError(-32000, "contract not allowed")
	}
	policy.Target = target
	selector := strings.TrimSpace(policy.Selector)
	if selector == "" || len(contract.Functions) == 0 {
		return nil
	}
	selector = strings.TrimPrefix(selector, "0x")
	if len(selector) != 8 {
		return newRPCError(errInvalidParams, "selector must be 4 bytes")
	}
	allowed := false
	for _, fn := range contract.Functions {
		if strings.EqualFold(hex.EncodeToString(fn.Selector), selector) {
			allowed = true
			break
		}
	}
	if !allowed {
		return newRPCError(-32000, "function not allowed")
	}
	policy.Selector = "0x" + selector
	return nil
}

func decodeBig(s string) (*big.Int, error) {
	if s == "" || s == "0x" {
		return big.NewInt(0), nil
	}
	b, err := hexutil.DecodeBig(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func parseChainID(v any) (*big.Int, error) {
	switch val := v.(type) {
	case float64:
		return big.NewInt(int64(val)), nil
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return nil, err
		}
		return big.NewInt(i), nil
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return nil, errors.New("chainId required")
		}
		if strings.HasPrefix(s, "0x") {
			b, err := hexutil.DecodeBig(s)
			if err != nil {
				return nil, err
			}
			return b, nil
		}
		i, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, errors.New("invalid chainId")
		}
		return i, nil
	default:
		return nil, errors.New("unsupported chainId type")
	}
}

func (h *Handler) blockTimestamps(ctx context.Context) (uint64, uint64) {
	if h.eth != nil {
		block, err := h.eth.BlockByNumber(ctx, nil)
		if err == nil && block != nil {
			latest := block.Time()
			parent := latest
			if block.NumberU64() > 0 {
				prevNum := new(big.Int).Sub(block.Number(), big.NewInt(1))
				if prev, perr := h.eth.BlockByNumber(ctx, prevNum); perr == nil && prev != nil {
					parent = prev.Time()
				}
			}
			return parent, latest
		}
		if err != nil {
			h.logf("eth_getBlockByNumber latest failed: %v", err)
		} else {
			h.logf("eth_getBlockByNumber latest returned nil block")
		}
	}
	now := uint64(time.Now().Unix())
	return now, now
}

func (h *Handler) userOpHash(ctx context.Context, entryPoint string, chainID *big.Int, op *userOperation) (common.Hash, error) {
	if entryPoint == "" {
		return common.Hash{}, errors.New("entryPoint required")
	}
	packed := op.toPacked()
	h.logPackedUserOperation("pm_getPaymasterData", packed)
	data, err := entryPointABI.Pack("getUserOpHash", *packed)
	if err == nil {
		h.logf("pm_getPaymasterData packedBytes=%s", hex.EncodeToString(data))
	}
	if err != nil {
		return common.Hash{}, err
	}
	addr := common.HexToAddress(entryPoint)
	if h.eth != nil {
		res, callErr := h.eth.CallContract(ctx, ethereum.CallMsg{To: &addr, Data: data}, nil)
		if callErr == nil {
			if len(res) != 32 {
				return common.Hash{}, errors.New("invalid hash response")
			}
			hash := common.BytesToHash(res)
			h.logf("entrypoint hash result=%s", hash.Hex())
			return hash, nil
		}
		err = callErr
	}
	if err != nil {
		h.logf("entrypoint call failed (%v), using local hash", err)
	}
	hash, localErr := hashUserOperationLocal(addr, chainID, op)
	if localErr != nil {
		return common.Hash{}, localErr
	}
	h.logf("local userOpHash=%s", hash.Hex())
	return hash, nil
}
