package erc7677

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg    config.Config
	policy *Policy
	signer *Signer
}

func NewHandler(cfg config.Config, p *Policy, s *Signer) *Handler {
	return &Handler{cfg: cfg, policy: p, signer: s}
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
	pmdPrefix := buildPMDPrefix(now, validFor, policy)

	out := PaymasterStubResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     h.cfg.PaymasterAddr,
		PaymasterData:                 hex0x(pmdPrefix),
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
	pmdPrefix := buildPMDPrefix(now, validFor, policy)

	tmpHash, _ := extractTmpUserOpHash(ctxMap)
	vu := now + uint64(validFor/time.Second)
	va := now

	sig, err := h.signer.signPolicyMessage(tmpHash, policy, vu, va, h.cfg.PMValGas, h.cfg.PostOpGas)
	if err != nil {
		c.JSON(http.StatusOK, rpcErr(req.ID, -32000, "signing failed"))
		return
	}
	paymasterData := append(pmdPrefix, sig...)

	out := PaymasterDataResult{
		Sponsor:                       &Sponsor{Name: "Sentra"},
		Paymaster:                     h.cfg.PaymasterAddr,
		PaymasterData:                 hex0x(paymasterData),
		PaymasterVerificationGasLimit: hexUint(h.cfg.PMValGas),
		PaymasterPostOpGasLimit:       hexUint(h.cfg.PostOpGas),
	}
	c.JSON(http.StatusOK, rpcOK(req.ID, out))
}
