package erc7677

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg    config.Config
	policy *Policy
	signer *Signer
	repo   *store.Repository
	eth    *ethclient.Client
}

var stubSignatureBytes = func() []byte {
	buf := make([]byte, 65)
	for i := 0; i < 64; i++ {
		buf[i] = 0xaa
	}
	buf[64] = 0x1c
	return buf
}()

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

func NewHandler(cfg config.Config, repo *store.Repository, p *Policy, s *Signer, eth *ethclient.Client) *Handler {
	return &Handler{cfg: cfg, policy: p, signer: s, repo: repo, eth: eth}
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

func ginLogf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(gin.DefaultWriter, msg)
}

func logUserOperation(prefix string, op *userOperation) {
	if op == nil {
		ginLogf("%s userOp=<nil>", prefix)
		return
	}
	payload := map[string]any{
		"sender":               op.Sender.Hex(),
		"nonce":                ensureBigInt(op.Nonce).String(),
		"initCode":             fmt.Sprintf("0x%x", op.InitCode),
		"callData":             fmt.Sprintf("0x%x", op.CallData),
		"callGasLimit":         ensureBigInt(op.CallGasLimit).String(),
		"verificationGasLimit": ensureBigInt(op.VerificationGasLimit).String(),
		"preVerificationGas":   ensureBigInt(op.PreVerificationGas).String(),
		"maxFeePerGas":         ensureBigInt(op.MaxFeePerGas).String(),
		"maxPriorityFeePerGas": ensureBigInt(op.MaxPriorityFeePerGas).String(),
		"paymasterAndData":     fmt.Sprintf("0x%x", op.PaymasterAndData),
		"signature":            fmt.Sprintf("0x%x", op.Signature),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		ginLogf("%s userOp log error: %v", prefix, err)
		return
	}
	ginLogf("%s userOp=%s", prefix, string(data))
}

func logPackedUserOperation(prefix string, packed *packedUserOperation) {
	if packed == nil {
		ginLogf("%s packedUserOp=<nil>", prefix)
		return
	}
	payload := map[string]any{
		"sender":             packed.Sender.Hex(),
		"nonce":              fmt.Sprintf("0x%s", ensureBigInt(packed.Nonce).Text(16)),
		"initCode":           fmt.Sprintf("0x%x", packed.InitCode),
		"callData":           fmt.Sprintf("0x%x", packed.CallData),
		"accountGasLimits":   fmt.Sprintf("0x%s", hex.EncodeToString(packed.AccountGasLimits[:])),
		"preVerificationGas": fmt.Sprintf("0x%s", ensureBigInt(packed.PreVerificationGas).Text(16)),
		"gasFees":            fmt.Sprintf("0x%s", hex.EncodeToString(packed.GasFees[:])),
		"paymasterAndData":   fmt.Sprintf("0x%x", packed.PaymasterAndData),
		"signature":          fmt.Sprintf("0x%x", packed.Signature),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		ginLogf("%s packedUserOp log error: %v", prefix, err)
		return
	}
	ginLogf("%s packedUserOp=%s", prefix, string(data))
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
	var in []any
	if err := json.Unmarshal(req.Params, &in); err != nil || len(in) != 4 {
		c.JSON(http.StatusOK, rpcErr(req.ID, errInvalidParams, "invalid params"))
		return
	}
	rawUserOp := in[0]
	// entryPoint := in[1]
	// chainId := in[2]
	ctxMap, _ := in[3].(map[string]any)

	policy := PolicyInput{
		Target:   strOr(ctxMap["target"], ""),
		Selector: strOr(ctxMap["selector"], ""),
	}
	validFor := h.policy.defDur

	parentTs, latestTs := h.blockTimestamps(c.Request.Context())
	pm, ok := h.resolvePaymasterAddress(c, req.ID)
	if !ok {
		return
	}
	if !h.ensureAllowedTarget(c, req.ID, pm, &policy) {
		return
	}
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
	pmdPrefix := buildPMDPrefix(validAfter, validUntil, policy)
	policyData := append([]byte(nil), pmdPrefix...)
	stubResponse := append(append([]byte(nil), policyData...), stubSignatureBytes...)

	userOp, err := parseUserOperation(rawUserOp)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, errInvalidParams, err.Error()))
		return
	}
	pmAddr := common.HexToAddress(pm.Address)
	userOp.PaymasterAndData = append(pmAddr.Bytes(), stubResponse...)
	logUserOperation("pm_getPaymasterStubData", userOp)

	out := PaymasterStubResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     pm.Address,
		PaymasterData:                 hex0x(stubResponse),
		PaymasterVerificationGasLimit: hexUint(h.cfg.PMValGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.PostOpGas),
		IsFinal:                       false,
	}
	c.JSON(http.StatusOK, rpcOK(req.ID, out))
}

func (h *Handler) data(c *gin.Context, req rpcRequest) {
	var in []any
	if err := json.Unmarshal(req.Params, &in); err != nil || len(in) != 4 {
		c.JSON(http.StatusOK, rpcErr(req.ID, errInvalidParams, "invalid params"))
		return
	}
	rawUserOp := in[0]
	entryPoint, _ := in[1].(string)
	chainInput := in[2]
	entryPoint = strings.TrimSpace(entryPoint)
	if entryPoint == "" {
		c.JSON(http.StatusOK, rpcErr(req.ID, errInvalidParams, "entryPoint required"))
		return
	}
	chainID, err := parseChainID(chainInput)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, errInvalidParams, err.Error()))
		return
	}
	ctxMap, _ := in[3].(map[string]any)
	policy := PolicyInput{
		Target:   strOr(ctxMap["target"], ""),
		Selector: strOr(ctxMap["selector"], ""),
	}
	validFor := h.policy.defDur
	if s, ok := ctxMap["validForSec"].(float64); ok && s > 0 {
		validFor = time.Duration(uint64(s)) * time.Second
	}

	parentTs, latestTs := h.blockTimestamps(c.Request.Context())
	pm, ok := h.resolvePaymasterAddress(c, req.ID)
	if !ok {
		return
	}
	if !h.ensureAllowedTarget(c, req.ID, pm, &policy) {
		return
	}
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
	pmdPrefix := buildPMDPrefix(validAfter, validUntil, policy)
	policyData := append([]byte(nil), pmdPrefix...)
	unsignedPayload := make([]byte, 0, 32+len(policyData))
	unsignedPayload = appendUint128(unsignedPayload, h.cfg.PMValGas)
	unsignedPayload = appendUint128(unsignedPayload, h.cfg.PostOpGas)
	unsignedPayload = append(unsignedPayload, policyData...)
	ginLogf("paymaster data")
	userOp, err := parseUserOperation(rawUserOp)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, errInvalidParams, err.Error()))
		return
	}
	ginLogf("paymaster data11")
	pmAddr := common.HexToAddress(pm.Address)
	paymasterAndData := append(pmAddr.Bytes(), unsignedPayload...)
	userOp.PaymasterAndData = paymasterAndData

	logUserOperation("pm_getPaymasterData", userOp)

	hash, err := h.userOpHash(c.Request.Context(), entryPoint, chainID, userOp)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, -32000, err.Error()))
		return
	}
	ginLogf("paymaster data112")
	sig, err := h.signer.signPolicyMessage(hash)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, -32000, "signing failed"))
		return
	}
	ginLogf("pm_getPaymasterData sig=%s", hex0x(sig))
	policyDataWithSig := append(append([]byte(nil), policyData...), sig...)
	signedPayload := make([]byte, 0, 32+len(policyDataWithSig))
	signedPayload = appendUint128(signedPayload, h.cfg.PMValGas)
	signedPayload = appendUint128(signedPayload, h.cfg.PostOpGas)
	signedPayload = append(signedPayload, policyDataWithSig...)

	userOp.PaymasterAndData = append(pmAddr.Bytes(), signedPayload...)

	out := PaymasterDataResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     pm.Address,
		PaymasterData:                 hex0x(policyDataWithSig),
		PaymasterVerificationGasLimit: hexUint(h.cfg.PMValGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.PostOpGas),
	}
	c.JSON(http.StatusOK, rpcOK(req.ID, out))
}

func (h *Handler) resolvePaymasterAddress(c *gin.Context, id any) (*store.Paymaster, bool) {
	adminID := c.GetUint("adminID")
	if adminID == 0 {
		c.JSON(http.StatusOK, rpcErr(id, errInvalidRequest, "admin context required"))
		return nil, false
	}
	pm, err := h.repo.GetPaymasterByAdmin(c.Request.Context(), adminID)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(id, -32000, "failed to load paymaster"))
		return nil, false
	}
	if pm == nil || pm.Address == "" {
		c.JSON(http.StatusOK, rpcErr(id, -32000, "paymaster not registered"))
		return nil, false
	}
	pm.Address = strings.ToLower(pm.Address)
	return pm, true
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

func (h *Handler) ensureAllowedTarget(c *gin.Context, reqID any, pm *store.Paymaster, policy *PolicyInput) bool {
	target := strings.ToLower(strings.TrimSpace(policy.Target))
	if target == "" {
		c.JSON(http.StatusOK, rpcErr(reqID, errInvalidParams, "target required"))
		return false
	}
	if !common.IsHexAddress(target) {
		c.JSON(http.StatusOK, rpcErr(reqID, errInvalidParams, "invalid target address"))
		return false
	}
	contract, err := h.repo.GetContractByAddress(c.Request.Context(), pm.ID, target)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(reqID, -32000, "allowlist lookup failed"))
		return false
	}
	if contract == nil {
		c.JSON(http.StatusOK, rpcErr(reqID, -32000, "contract not allowed"))
		return false
	}
	policy.Target = target
	selector := strings.TrimSpace(policy.Selector)
	if selector == "" || len(contract.Functions) == 0 {
		return true
	}
	selector = strings.TrimPrefix(selector, "0x")
	if len(selector) != 8 {
		c.JSON(http.StatusOK, rpcErr(reqID, errInvalidParams, "selector must be 4 bytes"))
		return false
	}
	allowed := false
	for _, fn := range contract.Functions {
		if strings.EqualFold(hex.EncodeToString(fn.Selector), selector) {
			allowed = true
			break
		}
	}
	if !allowed {
		c.JSON(http.StatusOK, rpcErr(reqID, -32000, "function not allowed"))
		return false
	}
	policy.Selector = "0x" + selector
	return true
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
		println("block", block, block.Time())
		if err == nil && block != nil {
			latest := block.Time()
			parent := latest
			if block.NumberU64() > 0 {
				if prev, err := h.eth.BlockByNumber(ctx, new(big.Int).Sub(block.Number(), big.NewInt(1))); err == nil && prev != nil {
					parent = prev.Time()
				}
			}
			return parent, latest
		}
		ginLogf("eth_getBlockByNumber latest failed, fallback to local time")
	}
	now := uint64(time.Now().Unix())
	return now, now
}

func (h *Handler) userOpHash(ctx context.Context, entryPoint string, chainID *big.Int, op *userOperation) (common.Hash, error) {
	if entryPoint == "" {
		return common.Hash{}, errors.New("entryPoint required")
	}
	packed := op.toPacked()
	logPackedUserOperation("pm_getPaymasterData", packed)
	data, err := entryPointABI.Pack("getUserOpHash", *packed)
	if err == nil {
		ginLogf("pm_getPaymasterData packedBytes=%s", hex.EncodeToString(data))
	}
	if err != nil {
		return common.Hash{}, err
	}
	addr := common.HexToAddress(entryPoint)
	res, err := h.eth.CallContract(ctx, ethereum.CallMsg{To: &addr, Data: data}, nil)
	if err == nil {
		if len(res) != 32 {
			return common.Hash{}, errors.New("invalid hash response")
		}
		hash := common.BytesToHash(res)
		ginLogf("entrypoint hash result=%s", hash.Hex())
		return hash, nil
	}
	ginLogf("entrypoint call failed (%v), using local hash", err)
	hash, localErr := hashUserOperationLocal(addr, chainID, op)
	if localErr != nil {
		return common.Hash{}, localErr
	}
	ginLogf("local userOpHash=%s", hash.Hex())
	return hash, nil
}
