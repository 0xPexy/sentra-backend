package admin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// Nonce godoc
// @Summary Issue SIWE nonce
// @Description Returns a short-lived nonce for SIWE authentication.
// @Tags Auth
// @Produce json
// @Success 200 {object} admin.NonceResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /auth/nonce [get]
func (h *Handler) Nonce(c *gin.Context) {
	nonce, err := h.auth.IssueNonce()
	if err != nil {
		writeError(c, http.StatusInternalServerError, "failed to issue nonce")
		return
	}
	c.JSON(http.StatusOK, NonceResponse{Nonce: nonce})
}

// Login godoc
// @Summary Admin login
// @Description Authenticates an admin via SIWE and returns a JWT access token.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login request"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 401 {object} admin.ErrorResponse
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	token, err := h.auth.LoginWithSIWE(c.Request.Context(), req.Message, req.Signature)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "invalid credentials")
		return
	}
	c.JSON(http.StatusOK, LoginResponse{Token: token})
}

// Me godoc
// @Summary Get current admin profile
// @Description Returns the authenticated admin's identifier and wallet address.
// @Tags Admin
// @Security BearerAuth
// @Produce json
// @Success 200 {object} admin.MeResponse
// @Failure 401 {object} admin.ErrorResponse
// @Router /api/v1/me [get]
func (h *Handler) Me(c *gin.Context) {
	c.JSON(http.StatusOK, MeResponse{
		ID:      c.GetUint("adminID"),
		Address: c.GetString("adminAddress"),
	})
}

// CreatePaymaster godoc
// @Summary Create a new paymaster configuration
// @Description Registers a paymaster entry-point association and optional user whitelist.
// @Tags Paymasters
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreatePaymasterRequest true "Paymaster payload"
// @Success 201 {object} admin.PaymasterResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 401 {object} admin.ErrorResponse
// @Failure 409 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters [post]
func (h *Handler) CreatePaymaster(c *gin.Context) {
	var req CreatePaymasterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	adminID := c.GetUint("adminID")
	if adminID == 0 {
		writeError(c, http.StatusForbidden, "admin context required")
		return
	}
	existing, err := h.repo.GetCurrentPaymaster(c.Request.Context())
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if existing != nil {
		writeError(c, http.StatusConflict, "paymaster already exists")
		return
	}
	addr := strings.ToLower(strings.TrimSpace(req.Address))
	if addr == "" {
		writeError(c, http.StatusBadRequest, "address is required")
		return
	}
	chainID, err := h.resolveChainID(c.Request.Context(), req.ChainID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	entryPoint := strings.ToLower(h.cfg.Chain.EntryPoint)
	if entryPoint == "" {
		writeError(c, http.StatusInternalServerError, "entry point not configured")
		return
	}
	if req.EntryPoint != nil && strings.TrimSpace(*req.EntryPoint) != "" {
		entryPoint = strings.ToLower(strings.TrimSpace(*req.EntryPoint))
	}
	usdPer := h.cfg.Paymaster.DefaultUSDPer
	if usdPer <= 0 {
		usdPer = 1
	}
	if req.USDPerMaxOp != nil {
		if *req.USDPerMaxOp <= 0 {
			writeError(c, http.StatusBadRequest, "usdPerMaxOp must be positive")
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
			writeError(c, http.StatusConflict, "paymaster already exists")
			return
		}
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if users, err := h.upsertUsers(c, pm.ID, &req.Users); err == nil {
		pm.Users = users
	} else {
		return
	}
	c.JSON(http.StatusCreated, paymasterDTO(pm))
}

// ListPaymasters godoc
// @Summary List paymasters for the authenticated admin
// @Tags Paymasters
// @Security BearerAuth
// @Produce json
// @Success 200 {array} admin.PaymasterResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters [get]
func (h *Handler) ListPaymasters(c *gin.Context) {
	list, err := h.repo.ListPaymasters(c.Request.Context())
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]PaymasterResponse, 0, len(list))
	for _, pm := range list {
		out = append(out, paymasterDTO(pm))
	}
	c.JSON(http.StatusOK, out)
}

// GetPaymaster godoc
// @Summary Get the authenticated admin's paymaster details
// @Tags Paymasters
// @Security BearerAuth
// @Produce json
// @Success 200 {object} admin.PaymasterResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me [get]
func (h *Handler) GetPaymaster(c *gin.Context) {
	pm, err := h.repo.GetCurrentPaymaster(c.Request.Context())
	if err != nil {
		statusFromStoreError(c, err)
		return
	}
	if pm == nil {
		writeError(c, http.StatusNotFound, "paymaster not found")
		return
	}
	contracts, err := h.repo.ListContracts(c.Request.Context(), pm.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	users, err := h.repo.ListUsers(c.Request.Context(), pm.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	pm.Users = users
	resp := paymasterDTO(*pm)
	contractDtos := make([]ContractResponse, 0, len(contracts))
	for _, contract := range contracts {
		contractDtos = append(contractDtos, contractDTO(contract))
	}
	resp.Contracts = contractDtos
	c.JSON(http.StatusOK, resp)
}

// UpdatePaymaster godoc
// @Summary Update paymaster configuration
// @Tags Paymasters
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body UpdatePaymasterRequest true "Update payload"
// @Success 200 {object} admin.PaymasterResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me [patch]
func (h *Handler) UpdatePaymaster(c *gin.Context) {
	var req UpdatePaymasterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	pm.AdminID = c.GetUint("adminID")
	if req.Address != nil {
		addr := strings.ToLower(strings.TrimSpace(*req.Address))
		if addr == "" {
			writeError(c, http.StatusBadRequest, "address is required")
			return
		}
		pm.Address = addr
	}
	if req.USDPerMaxOp != nil {
		if *req.USDPerMaxOp <= 0 {
			writeError(c, http.StatusBadRequest, "usdPerMaxOp must be positive")
			return
		}
		pm.USDPerMaxOp = *req.USDPerMaxOp
	}
	if err := h.repo.SavePaymaster(c.Request.Context(), pm); err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
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

// AddContract godoc
// @Summary Add or update a contract whitelist entry
// @Tags Contracts
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body AddContractRequest true "Contract payload"
// @Success 200 {object} admin.ContractResponse
// @Success 201 {object} admin.ContractResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/contracts [post]
func (h *Handler) AddContract(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	var req AddContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	addr := store.NormalizeAddress(req.Address)
	if addr == "" {
		writeError(c, http.StatusBadRequest, "address is required")
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
			writeError(c, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		if err := h.repo.SaveContract(c.Request.Context(), contract); err != nil {
			writeError(c, http.StatusInternalServerError, err.Error())
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

// ListContracts godoc
// @Summary List whitelisted contracts for the paymaster
// @Tags Contracts
// @Security BearerAuth
// @Produce json
// @Success 200 {array} admin.ContractResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/contracts [get]
func (h *Handler) ListContracts(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	list, err := h.repo.ListContracts(c.Request.Context(), pm.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]ContractResponse, 0, len(list))
	for _, contract := range list {
		out = append(out, contractDTO(contract))
	}
	c.JSON(http.StatusOK, out)
}

// UpdateContract godoc
// @Summary Update a contract whitelist entry
// @Tags Contracts
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param contractId path int true "Contract ID"
// @Param request body UpdateContractRequest true "Update payload"
// @Success 200 {object} admin.ContractResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/contracts/{contractId} [patch]
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
		writeError(c, http.StatusNotFound, "contract not found")
		return
	}
	var req UpdateContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	if req.Address != nil {
		addr := store.NormalizeAddress(*req.Address)
		if addr == "" {
			writeError(c, http.StatusBadRequest, "address is required")
			return
		}
		contract.Address = addr
	}
	if req.Name != nil {
		contract.Name = strings.TrimSpace(*req.Name)
	}
	if err := h.repo.SaveContract(c.Request.Context(), contract); err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	functions, err := h.upsertFunctions(c, pm.ID, contract.ID, contract.Address, req.Functions)
	if err != nil {
		return
	}
	contract.Functions = functions
	c.JSON(http.StatusOK, contractDTO(*contract))
}

// DeleteContract godoc
// @Summary Remove a contract whitelist entry
// @Tags Contracts
// @Security BearerAuth
// @Produce json
// @Param contractId path int true "Contract ID"
// @Success 204 {string} string ""
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/contracts/{contractId} [delete]
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
		writeError(c, http.StatusNotFound, "contract not found")
		return
	}
	if err := h.repo.ReplaceFunctionsForContract(c.Request.Context(), contract.ID, nil); err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.repo.DeleteContract(c.Request.Context(), pm.ID, contractID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(c, http.StatusNotFound, "contract not found")
			return
		}
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

// ListUsers godoc
// @Summary List whitelisted user addresses
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {array} string
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/users [get]
func (h *Handler) ListUsers(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	users, err := h.repo.ListUsers(c.Request.Context(), pm.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	addresses := usersToSlice(users)
	c.JSON(http.StatusOK, addresses)
}

// AddUser godoc
// @Summary Add a user to the paymaster whitelist
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body AddUserRequest true "User payload"
// @Success 201 {object} admin.UserAddressResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 409 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/users [post]
func (h *Handler) AddUser(c *gin.Context) {
	var req AddUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	addr := store.NormalizeAddress(req.Address)
	if addr == "" {
		writeError(c, http.StatusBadRequest, "address is required")
		return
	}
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	// prevent duplicates
	existing, err := h.repo.ListUsers(c.Request.Context(), pm.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	for _, u := range existing {
		if strings.EqualFold(u.Sender, addr) {
			writeError(c, http.StatusConflict, "user already exists")
			return
		}
	}
	user := store.UserWhitelist{
		PaymasterID: pm.ID,
		Sender:      addr,
	}
	if err := h.repo.AddUser(c.Request.Context(), &user); err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusCreated, UserAddressResponse{Address: addr})
}

// DeleteUser godoc
// @Summary Remove a user from the paymaster whitelist
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param address path string true "User address"
// @Success 204 {string} string ""
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/users/{address} [delete]
func (h *Handler) DeleteUser(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	addr := store.NormalizeAddress(c.Param("address"))
	if addr == "" {
		writeError(c, http.StatusBadRequest, "address is required")
		return
	}
	if err := h.repo.DeleteUserByAddress(c.Request.Context(), pm.ID, addr); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(c, http.StatusNotFound, "user not found")
			return
		}
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

// ReplaceUsers godoc
// @Summary Replace the entire paymaster user whitelist
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body ReplaceUsersRequest true "User addresses"
// @Success 200 {array} string
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/users [patch]
func (h *Handler) ReplaceUsers(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	var req ReplaceUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	users, err := h.upsertUsers(c, pm.ID, &req.Users)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, usersToSlice(users))
}

// ListOperations godoc
// @Summary List recorded user operations for the paymaster
// @Tags Operations
// @Security BearerAuth
// @Produce json
// @Success 200 {array} admin.OperationResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/me/operations [get]
func (h *Handler) ListOperations(c *gin.Context) {
	pm, ok := h.loadMyPaymaster(c)
	if !ok {
		return
	}
	ops, err := h.repo.ListOperations(c.Request.Context(), pm.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]OperationResponse, 0, len(ops))
	for _, op := range ops {
		out = append(out, operationDTO(op))
	}
	c.JSON(http.StatusOK, out)
}

func parseUintParam(c *gin.Context, key string) (uint, bool) {
	raw := c.Param(key)
	if strings.TrimSpace(raw) == "" {
		writeError(c, http.StatusBadRequest, fmt.Sprintf("%s is required", key))
		return 0, false
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		writeError(c, http.StatusBadRequest, fmt.Sprintf("invalid %s", key))
		return 0, false
	}
	return uint(value), true
}

func writeError(c *gin.Context, status int, msg string) {
	c.JSON(status, ErrorResponse{Error: msg})
}

func (h *Handler) upsertUsers(c *gin.Context, paymasterID uint, usersInput *[]string) ([]store.UserWhitelist, error) {
	if usersInput == nil {
		list, err := h.repo.ListUsers(c.Request.Context(), paymasterID)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err.Error())
			return nil, err
		}
		return list, nil
	}
	seen := make(map[string]struct{})
	users := make([]store.UserWhitelist, 0, len(*usersInput))
	for _, raw := range *usersInput {
		addr := store.NormalizeAddress(raw)
		if addr == "" {
			writeError(c, http.StatusBadRequest, "user address cannot be empty")
			return nil, errors.New("empty user address")
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		users = append(users, store.UserWhitelist{PaymasterID: paymasterID, Sender: addr})
	}
	if err := h.repo.ReplaceUsersForPaymaster(c.Request.Context(), paymasterID, users); err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return nil, err
	}
	list, err := h.repo.ListUsers(c.Request.Context(), paymasterID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return nil, err
	}
	return list, nil
}

func (h *Handler) upsertFunctions(c *gin.Context, paymasterID, contractID uint, contractAddr string, inputs []ContractFunctionInput) ([]store.FunctionWhitelist, error) {
	if inputs == nil {
		functions, err := h.repo.ListFunctionsByContract(c.Request.Context(), paymasterID, contractAddr)
		if err != nil {
			writeError(c, http.StatusInternalServerError, err.Error())
			return nil, err
		}
		return functions, nil
	}
	funcs := make([]store.FunctionWhitelist, 0, len(inputs))
	for _, input := range inputs {
		selector := strings.TrimSpace(input.Selector)
		if selector == "" {
			writeError(c, http.StatusBadRequest, "selector is required")
			return nil, errors.New("selector required")
		}
		bytes, err := decodeSelector(selector)
		if err != nil {
			writeError(c, http.StatusBadRequest, err.Error())
			return nil, err
		}
		funcs = append(funcs, store.FunctionWhitelist{
			ContractID: contractID,
			Selector:   bytes,
			Signature:  input.Signature,
		})
	}
	if err := h.repo.ReplaceFunctionsForContract(c.Request.Context(), contractID, funcs); err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
		return nil, err
	}
	functions, err := h.repo.ListFunctionsByContract(c.Request.Context(), paymasterID, contractAddr)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err.Error())
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

func paymasterDTO(pm store.Paymaster) PaymasterResponse {
	return PaymasterResponse{
		ID:          pm.ID,
		AdminID:     pm.AdminID,
		ChainID:     pm.ChainID,
		EntryPoint:  pm.EntryPoint,
		Address:     pm.Address,
		USDPerMaxOp: pm.USDPerMaxOp,
		Users:       usersToSlice(pm.Users),
		CreatedAt:   pm.CreatedAt,
		UpdatedAt:   pm.UpdatedAt,
	}
}

func functionDTO(fn store.FunctionWhitelist) FunctionResponse {
	selector := "0x" + hex.EncodeToString(fn.Selector)
	return FunctionResponse{
		ID:        fn.ID,
		Selector:  selector,
		Signature: fn.Signature,
		CreatedAt: fn.CreatedAt,
		UpdatedAt: fn.UpdatedAt,
	}
}

func contractDTO(contract store.ContractWhitelist) ContractResponse {
	functions := make([]FunctionResponse, 0, len(contract.Functions))
	for _, fn := range contract.Functions {
		functions = append(functions, functionDTO(fn))
	}
	return ContractResponse{
		ID:        contract.ID,
		Address:   contract.Address,
		Name:      contract.Name,
		Functions: functions,
		CreatedAt: contract.CreatedAt,
		UpdatedAt: contract.UpdatedAt,
	}
}

func operationDTO(op store.Operation) OperationResponse {
	selector := "0x" + hex.EncodeToString(op.Selector)
	return OperationResponse{
		ID:          op.ID,
		PaymasterID: op.PaymasterID,
		ChainID:     op.ChainID,
		UserOpHash:  op.UserOpHash,
		TxHash:      op.TxHash,
		Sender:      op.Sender,
		Target:      op.Target,
		Selector:    selector,
		Status:      op.Status,
		Reason:      op.Reason,
		GasUsed:     op.GasUsed,
		GasCostWei:  op.GasCostWei,
		USDCCharged: op.USDCCharged,
		CreatedAt:   op.CreatedAt,
		UpdatedAt:   op.UpdatedAt,
	}
}

func statusFromStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(c, http.StatusNotFound, "not found")
	default:
		writeError(c, http.StatusInternalServerError, err.Error())
	}
}

func (h *Handler) loadMyPaymaster(c *gin.Context) (*store.Paymaster, bool) {
	adminID := c.GetUint("adminID")
	if adminID == 0 {
		writeError(c, http.StatusForbidden, "admin context required")
		return nil, false
	}
	pm, err := h.repo.GetCurrentPaymaster(c.Request.Context())
	if err != nil {
		statusFromStoreError(c, err)
		return nil, false
	}
	if pm == nil {
		writeError(c, http.StatusNotFound, "paymaster not found")
		return nil, false
	}
	return pm, true
}

func (h *Handler) resolveChainID(ctx context.Context, override *uint64) (uint64, error) {
	if override != nil && *override != 0 {
		return *override, nil
	}
	if h.cfg.Chain.RPCURL == "" {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.Chain.RPCURL, bytes.NewReader(body))
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
		out = append(out, store.NormalizeAddress(u.Sender))
	}
	return out
}

// GetContractArtifact godoc
// @Summary Retrieve compiled contract artifacts by name
// @Tags Contracts
// @Security BearerAuth
// @Produce json
// @Param name path string true "Contract name"
// @Success 200 {object} admin.ContractArtifactResponse
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/contracts/{name} [get]
func (h *Handler) GetContractArtifact(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		writeError(c, http.StatusBadRequest, "contract name is required")
		return
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		writeError(c, http.StatusBadRequest, "invalid contract name")
		return
	}
	base := filepath.Join("artifacts", "contracts", name)
	abiPath := filepath.Join(base, fmt.Sprintf("%s.json", name))

	abiBytes, err := os.ReadFile(abiPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(c, http.StatusNotFound, "contract artifact not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "failed to read abi")
		return
	}
	var abi json.RawMessage
	if err := json.Unmarshal(abiBytes, &abi); err != nil {
		writeError(c, http.StatusInternalServerError, "invalid abi json")
		return
	}

	c.JSON(http.StatusOK, ContractArtifactResponse{
		Name: name,
		ABI:  abi,
	})
}
