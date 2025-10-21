package erc7677

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg    config.Config
	policy *Policy
	signer *Signer
	repo   *store.Repository
}

var stubSignatureBytes = func() []byte {
	buf := make([]byte, 65)
	for i := 0; i < 64; i++ {
		buf[i] = 0xaa
	}
	buf[64] = 0x1c
	return buf
}()

func NewHandler(cfg config.Config, repo *store.Repository, p *Policy, s *Signer) *Handler {
	return &Handler{cfg: cfg, policy: p, signer: s, repo: repo}
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
	// userOp := in[0]
	// entryPoint := in[1]
	// chainId := in[2]
	ctxMap, _ := in[3].(map[string]any)

	policy := PolicyInput{
		Target:     strOr(ctxMap["target"], ""),
		Selector:   strOr(ctxMap["selector"], ""),
		SubsidyBps: uint16Or(ctxMap["subsidyBps"], 10_000),
	}
	validFor := h.policy.defDur
	if s, ok := ctxMap["validForSec"].(float64); ok && s > 0 {
		validFor = time.Duration(uint64(s)) * time.Second
	}

	now := uint64(time.Now().Unix())
	paymasterAddr, ok := h.resolvePaymasterAddress(c, req.ID)
	if !ok {
		return
	}
	pmdPrefix := buildPMDPrefix(paymasterAddr, h.cfg.PMValGas, h.cfg.PostOpGas, now, validFor, policy)
	prefix := make([]byte, 0, len(pmdPrefix)+len(stubSignatureBytes))
	prefix = append(prefix, pmdPrefix...)
	prefix = append(prefix, stubSignatureBytes...)
	paymasterData := prefix

	out := PaymasterStubResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     paymasterAddr,
		PaymasterData:                 hex0x(paymasterData),
		PaymasterVerificationGasLimit: hexUint(h.cfg.PMValGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.PostOpGas),
		CallGasLimit:                  "0xc350",
		PreVerificationGas:            "0x4e20",
		VerificationGasLimit:          hexUint(500000),
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
	ctxMap, _ := in[3].(map[string]any)
	policy := PolicyInput{
		Target:     strOr(ctxMap["target"], ""),
		Selector:   strOr(ctxMap["selector"], ""),
		SubsidyBps: uint16Or(ctxMap["subsidyBps"], 10_000),
	}
	validFor := h.policy.defDur
	if s, ok := ctxMap["validForSec"].(float64); ok && s > 0 {
		validFor = time.Duration(uint64(s)) * time.Second
	}

	now := uint64(time.Now().Unix())
	paymasterAddr, ok := h.resolvePaymasterAddress(c, req.ID)
	if !ok {
		return
	}
	pmdPrefix := buildPMDPrefix(paymasterAddr, h.cfg.PMValGas, h.cfg.PostOpGas, now, validFor, policy)

	tmpHash, _ := extractTmpUserOpHash(ctxMap)
	vu := now + uint64(validFor/time.Second)
	va := now

	sig, err := h.signer.signPolicyMessage(tmpHash, policy, vu, va, h.cfg.PMValGas, h.cfg.PostOpGas)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, -32000, "signing failed"))
		return
	}
	prefix := make([]byte, 0, len(pmdPrefix)+len(sig))
	prefix = append(prefix, pmdPrefix...)
	prefix = append(prefix, sig...)
	paymasterData := prefix

	out := PaymasterDataResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     paymasterAddr,
		PaymasterData:                 hex0x(paymasterData),
		PaymasterVerificationGasLimit: hexUint(h.cfg.PMValGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.PostOpGas),
	}
	c.JSON(http.StatusOK, rpcOK(req.ID, out))
}

func (h *Handler) resolvePaymasterAddress(c *gin.Context, id any) (string, bool) {
	adminID := c.GetUint("adminID")
	if adminID == 0 {
		c.JSON(http.StatusOK, rpcErr(id, errInvalidRequest, "admin context required"))
		return "", false
	}
	pm, err := h.repo.GetPaymasterByAdmin(c.Request.Context(), adminID)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(id, -32000, "failed to load paymaster"))
		return "", false
	}
	if pm == nil || pm.Address == "" {
		c.JSON(http.StatusOK, rpcErr(id, -32000, "paymaster not registered"))
		return "", false
	}
	return pm.Address, true
}
