package admin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/auth"
	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	auth *auth.Service
	repo *store.Repository
	cfg  config.Config
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

func NewHandler(a *auth.Service, r *store.Repository, c config.Config) *Handler {
	return &Handler{auth: a, repo: r, cfg: c}
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	token, err := h.auth.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, LoginResponse{Token: token})
}

func (h *Handler) Me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":       c.GetUint("adminID"),
		"username": c.GetString("adminUsername"),
	})
}

func (h *Handler) CreatePaymaster(c *gin.Context) {
	var req CreatePaymasterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	adminID := c.GetUint("adminID")
	if adminID == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin context required"})
		return
	}
	addr := strings.ToLower(strings.TrimSpace(req.Address))
	if addr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
		return
	}
	chainID, err := h.resolveChainID(c.Request.Context(), req.ChainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entryPoint := strings.ToLower(h.cfg.EntryPoint)
	if entryPoint == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "entry point not configured"})
		return
	}
	if req.EntryPoint != nil && strings.TrimSpace(*req.EntryPoint) != "" {
		entryPoint = strings.ToLower(strings.TrimSpace(*req.EntryPoint))
	}
	usdPer := h.cfg.DefaultUSDPer
	if usdPer <= 0 {
		usdPer = 1
	}
	if req.USDPerMaxOp != nil {
		if *req.USDPerMaxOp <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "usdPerMaxOp must be positive"})
			return
		}
		usdPer = *req.USDPerMaxOp
	}
	pm := store.Paymaster{
		AdminID:     adminID,
		ChainID:     chainID,
		EntryPoint:  entryPoint,
		Address:     addr,
		USDPerMaxOp: usdPer,
	}
	if err := h.repo.CreatePaymaster(c.Request.Context(), &pm); err != nil {
		if errors.Is(err, store.ErrConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "paymaster already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if users, err := h.upsertUsers(c, pm.ID, &req.Users); err == nil {
		pm.Users = users
	} else {
		return
	}
	c.JSON(http.StatusCreated, paymasterDTO(pm))
}

func (h *Handler) ListPaymasters(c *gin.Context) {
	adminID := c.GetUint("adminID")
	list, err := h.repo.ListPaymasters(c.Request.Context(), adminID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]gin.H, 0, len(list))
	for _, pm := range list {
		out = append(out, paymasterDTO(pm))
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handler) GetPaymaster(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	contracts, err := h.repo.ListContracts(c.Request.Context(), pm.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	users, err := h.repo.ListUsers(c.Request.Context(), pm.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	pm.Users = users
	resp := paymasterDTO(*pm)
	contractDtos := make([]gin.H, 0, len(contracts))
	for _, contract := range contracts {
		contractDtos = append(contractDtos, contractDTO(contract))
	}
	resp["contracts"] = contractDtos
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) UpdatePaymaster(c *gin.Context) {
	var req UpdatePaymasterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	if req.Address != nil {
		addr := strings.ToLower(strings.TrimSpace(*req.Address))
		if addr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
			return
		}
		pm.Address = addr
	}
	if req.USDPerMaxOp != nil {
		if *req.USDPerMaxOp <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "usdPerMaxOp must be positive"})
			return
		}
		pm.USDPerMaxOp = *req.USDPerMaxOp
	}
	if err := h.repo.SavePaymaster(c.Request.Context(), pm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req.Users != nil {
		users, err := h.upsertUsers(c, pm.ID, req.Users)
		if err != nil {
			return
		}
		pm.Users = users
	}
	c.JSON(http.StatusOK, paymasterDTO(*pm))
}

func (h *Handler) AddContract(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	var req AddContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	addr := normalizeAddress(req.Address)
	if addr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
		return
	}
	contract, err := h.repo.GetContractByAddress(c.Request.Context(), pm.ID, addr)
	if err != nil {
		statusFromStoreError(c, err)
		return
	}
	created := false
	if contract == nil {
		contract = &store.ContractWhitelist{
			PaymasterID: pm.ID,
			Address:     addr,
		}
		created = true
	}
	if req.Name != nil {
		contract.Name = strings.TrimSpace(*req.Name)
	} else if created {
		contract.Name = ""
	}
	if created {
		if err := h.repo.AddContract(c.Request.Context(), contract); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		if err := h.repo.SaveContract(c.Request.Context(), contract); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	functions, err := h.upsertFunctions(c, pm.ID, contract.ID, addr, req.Functions)
	if err != nil {
		return
	}
	contract.Functions = functions
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, contractDTO(*contract))
}

func (h *Handler) ListContracts(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	list, err := h.repo.ListContracts(c.Request.Context(), pm.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]gin.H, 0, len(list))
	for _, contract := range list {
		out = append(out, contractDTO(contract))
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handler) UpdateContract(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	contractID, ok := parseUintParam(c, "contractId")
	if !ok {
		return
	}
	contract, err := h.repo.GetContract(c.Request.Context(), pm.ID, contractID)
	if err != nil {
		statusFromStoreError(c, err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}
	var req UpdateContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Address != nil {
		addr := normalizeAddress(*req.Address)
		if addr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
			return
		}
		contract.Address = addr
	}
	if req.Name != nil {
		contract.Name = strings.TrimSpace(*req.Name)
	}
	if err := h.repo.SaveContract(c.Request.Context(), contract); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	functions, err := h.upsertFunctions(c, pm.ID, contract.ID, contract.Address, req.Functions)
	if err != nil {
		return
	}
	contract.Functions = functions
	c.JSON(http.StatusOK, contractDTO(*contract))
}

func (h *Handler) DeleteContract(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	contractID, ok := parseUintParam(c, "contractId")
	if !ok {
		return
	}
	contract, err := h.repo.GetContract(c.Request.Context(), pm.ID, contractID)
	if err != nil {
		statusFromStoreError(c, err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}
	if err := h.repo.ReplaceFunctionsForContract(c.Request.Context(), contract.ID, nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.DeleteContract(c.Request.Context(), pm.ID, contractID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) ListUsers(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	users, err := h.repo.ListUsers(c.Request.Context(), pm.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	addresses := usersToSlice(users)
	c.JSON(http.StatusOK, addresses)
}

func (h *Handler) AddUser(c *gin.Context) {
	var req AddUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	addr := normalizeAddress(req.Address)
	if addr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
		return
	}
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	// prevent duplicates
	existing, err := h.repo.ListUsers(c.Request.Context(), pm.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, u := range existing {
		if strings.EqualFold(u.Sender, addr) {
			c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
			return
		}
	}
	user := store.UserWhitelist{
		PaymasterID: pm.ID,
		Sender:      addr,
	}
	if err := h.repo.AddUser(c.Request.Context(), &user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"address": addr})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	addr := normalizeAddress(c.Param("address"))
	if addr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address is required"})
		return
	}
	if err := h.repo.DeleteUserByAddress(c.Request.Context(), pm.ID, addr); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) ReplaceUsers(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	var req ReplaceUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	users, err := h.upsertUsers(c, pm.ID, &req.Users)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, usersToSlice(users))
}

func (h *Handler) ListOperations(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	ops, err := h.repo.ListOperations(c.Request.Context(), pm.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]gin.H, 0, len(ops))
	for _, op := range ops {
		out = append(out, operationDTO(op))
	}
	c.JSON(http.StatusOK, out)
}

func parseUintParam(c *gin.Context, key string) (uint, bool) {
	raw := c.Param(key)
	if strings.TrimSpace(raw) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("%s is required", key)})
		return 0, false
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid %s", key)})
		return 0, false
	}
	return uint(value), true
}

func normalizeAddress(addr string) string {
	s := strings.TrimSpace(strings.ToLower(addr))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	return s
}

func (h *Handler) upsertUsers(c *gin.Context, paymasterID uint, usersInput *[]string) ([]store.UserWhitelist, error) {
	if usersInput == nil {
		list, err := h.repo.ListUsers(c.Request.Context(), paymasterID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return nil, err
		}
		return list, nil
	}
	seen := make(map[string]struct{})
	users := make([]store.UserWhitelist, 0, len(*usersInput))
	for _, raw := range *usersInput {
		addr := normalizeAddress(raw)
		if addr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user address cannot be empty"})
			return nil, errors.New("empty user address")
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		users = append(users, store.UserWhitelist{PaymasterID: paymasterID, Sender: addr})
	}
	if err := h.repo.ReplaceUsersForPaymaster(c.Request.Context(), paymasterID, users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}
	list, err := h.repo.ListUsers(c.Request.Context(), paymasterID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}
	return list, nil
}

func (h *Handler) upsertFunctions(c *gin.Context, paymasterID, contractID uint, contractAddr string, inputs []ContractFunctionInput) ([]store.FunctionWhitelist, error) {
	if inputs == nil {
		functions, err := h.repo.ListFunctionsByContract(c.Request.Context(), paymasterID, contractAddr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return nil, err
		}
		return functions, nil
	}
	funcs := make([]store.FunctionWhitelist, 0, len(inputs))
	for _, input := range inputs {
		selector := strings.TrimSpace(input.Selector)
		if selector == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "selector is required"})
			return nil, errors.New("selector required")
		}
		bytes, err := decodeSelector(selector)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return nil, err
		}
		funcs = append(funcs, store.FunctionWhitelist{
			ContractID: contractID,
			Selector:   bytes,
			Signature:  input.Signature,
		})
	}
	if err := h.repo.ReplaceFunctionsForContract(c.Request.Context(), contractID, funcs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}
	functions, err := h.repo.ListFunctionsByContract(c.Request.Context(), paymasterID, contractAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}
	return functions, nil
}

func decodeSelector(sel string) ([]byte, error) {
	sel = strings.TrimPrefix(sel, "0x")
	b, err := hex.DecodeString(sel)
	if err != nil {
		return nil, err
	}
	if len(b) != 4 {
		return nil, errors.New("selector must be 4 bytes")
	}
	return b, nil
}

func paymasterDTO(pm store.Paymaster) gin.H {
	return gin.H{
		"id":          pm.ID,
		"adminId":     pm.AdminID,
		"chainId":     pm.ChainID,
		"entryPoint":  pm.EntryPoint,
		"address":     pm.Address,
		"usdPerMaxOp": pm.USDPerMaxOp,
		"users":       usersToSlice(pm.Users),
		"createdAt":   pm.CreatedAt,
		"updatedAt":   pm.UpdatedAt,
	}
}

func functionDTO(fn store.FunctionWhitelist) gin.H {
	return gin.H{
		"id":        fn.ID,
		"selector":  "0x" + hex.EncodeToString(fn.Selector),
		"signature": fn.Signature,
		"createdAt": fn.CreatedAt,
		"updatedAt": fn.UpdatedAt,
	}
}

func contractDTO(contract store.ContractWhitelist) gin.H {
	functions := make([]gin.H, 0, len(contract.Functions))
	for _, fn := range contract.Functions {
		functions = append(functions, functionDTO(fn))
	}
	return gin.H{
		"id":        contract.ID,
		"address":   contract.Address,
		"name":      contract.Name,
		"functions": functions,
		"createdAt": contract.CreatedAt,
		"updatedAt": contract.UpdatedAt,
	}
}

func operationDTO(op store.Operation) gin.H {
	return gin.H{
		"id":          op.ID,
		"paymasterId": op.PaymasterID,
		"chainId":     op.ChainID,
		"userOpHash":  op.UserOpHash,
		"txHash":      op.TxHash,
		"sender":      op.Sender,
		"target":      op.Target,
		"selector":    "0x" + hex.EncodeToString(op.Selector),
		"status":      op.Status,
		"reason":      op.Reason,
		"gasUsed":     op.GasUsed,
		"gasCostWei":  op.GasCostWei,
		"usdcCharged": op.USDCCharged,
		"createdAt":   op.CreatedAt,
		"updatedAt":   op.UpdatedAt,
	}
}

func statusFromStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

func (h *Handler) loadMyPaymaster(c *gin.Context) (*store.Paymaster, bool) {
	adminID := c.GetUint("adminID")
	if adminID == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin context required"})
		return nil, false
	}
	pm, err := h.repo.GetPaymasterByAdmin(c.Request.Context(), adminID)
	if err != nil {
		statusFromStoreError(c, err)
		return nil, false
	}
	if pm == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "paymaster not found"})
		return nil, false
	}
	return pm, true
}

func (h *Handler) resolveChainID(ctx context.Context, override *uint64) (uint64, error) {
	if override != nil && *override != 0 {
		return *override, nil
	}
	if h.cfg.ChainRPCURL == "" {
		return 0, errors.New("chain rpc url not configured")
	}
	return h.fetchChainID(ctx)
}

func (h *Handler) fetchChainID(ctx context.Context) (uint64, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_chainId",
		"params":  []any{},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal chainId payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.ChainRPCURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build chainId request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("chainId request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return 0, fmt.Errorf("chainId rpc status %d", resp.StatusCode)
	}
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode chainId response: %w", err)
	}
	if out.Error != nil {
		return 0, fmt.Errorf("chainId rpc error: %s", out.Error.Message)
	}
	trimmed := strings.TrimPrefix(strings.TrimSpace(out.Result), "0x")
	if trimmed == "" {
		return 0, errors.New("empty chain id")
	}
	value, err := strconv.ParseUint(trimmed, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse chain id: %w", err)
	}
	return value, nil
}

func usersToSlice(users []store.UserWhitelist) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, normalizeAddress(u.Sender))
	}
	return out
}

func (h *Handler) GetContractArtifact(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract name is required"})
		return
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid contract name"})
		return
	}
	base := filepath.Join("artifacts", "contracts", name)
	abiPath := filepath.Join(base, fmt.Sprintf("%s.abi.json", name))
	bytePath := filepath.Join(base, fmt.Sprintf("%s.bytecode.txt", name))

	abiBytes, err := os.ReadFile(abiPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "contract artifact not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read abi"})
		return
	}
	var abi json.RawMessage
	if err := json.Unmarshal(abiBytes, &abi); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid abi json"})
		return
	}
	byteFile, err := os.Open(bytePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "bytecode not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read bytecode"})
		return
	}
	defer byteFile.Close()
	b, err := io.ReadAll(byteFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read bytecode"})
		return
	}
	bytecode := strings.TrimSpace(string(b))
	if bytecode != "" && !strings.HasPrefix(bytecode, "0x") {
		bytecode = "0x" + bytecode
	}

	c.JSON(http.StatusOK, gin.H{
		"name":     name,
		"abi":      abi,
		"bytecode": bytecode,
	})
}
