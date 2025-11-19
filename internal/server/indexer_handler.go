package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/0xPexy/sentra-backend/internal/admin"
	"github.com/0xPexy/sentra-backend/internal/config"
	indexersvc "github.com/0xPexy/sentra-backend/internal/indexer/service"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/gin-gonic/gin"
)

type indexerHandler struct {
	cfg    config.Config
	repo   *store.Repository
	reader *indexersvc.Reader
	hub    *EventHub
}

func newIndexerHandler(cfg config.Config, repo *store.Repository, reader *indexersvc.Reader, hub *EventHub) *indexerHandler {
	return &indexerHandler{
		cfg:    cfg,
		repo:   repo,
		reader: reader,
		hub:    hub,
	}
}

// StatsOverview godoc
// @Summary Paymaster stats overview
// @Tags Stats
// @Produce json
// @Success 200 {object} indexersvc.PaymasterOverview
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/stats/overview [get]
func (h *indexerHandler) StatsOverview(c *gin.Context) {
	pm, err := h.repo.GetCurrentPaymaster(c.Request.Context())
	if err != nil {
		writeAPIError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if pm == nil {
		writeAPIError(c, http.StatusNotFound, "paymaster not found")
		return
	}
	stats, err := h.reader.PaymasterOverview(c.Request.Context(), pm.ChainID, pm.Address)
	if err != nil {
		writeAPIError(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, stats)
}

// SponsoredOps godoc
// @Summary List sponsored user operations for a paymaster
// @Tags Operations
// @Security BearerAuth
// @Produce json
// @Param chain_id query uint64 false "Chain ID override"
// @Param limit query int false "Page size (1-100)"
// @Param cursor query string false "Cursor in blockNumber:logIndex format"
// @Success 200 {object} indexersvc.SponsoredOpsResult
// @Failure 400 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/paymasters/ops [get]
func (h *indexerHandler) SponsoredOps(c *gin.Context) {
	pm, err := h.repo.GetCurrentPaymaster(c.Request.Context())
	if err != nil {
		writeAPIError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if pm == nil || strings.TrimSpace(pm.Address) == "" {
		writeAPIError(c, http.StatusNotFound, "paymaster not found")
		return
	}
	chainID := pm.ChainID
	if chainID == 0 {
		chainID = h.cfg.Chain.ChainID
	}
	if raw := strings.TrimSpace(c.Query("chain_id")); raw != "" {
		val, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeAPIError(c, http.StatusBadRequest, "invalid chain_id")
			return
		}
		chainID = val
	}
	if chainID == 0 {
		writeAPIError(c, http.StatusBadRequest, "chain id required")
		return
	}
	limit := 0
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil || val < 0 {
			writeAPIError(c, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = val
	}
	cursor := strings.TrimSpace(c.Query("cursor"))
	result, err := h.reader.SponsoredOps(c.Request.Context(), indexersvc.SponsoredOpsParams{
		ChainID:   chainID,
		Paymaster: strings.ToLower(pm.Address),
		Cursor:    cursor,
		Limit:     limit,
	})
	if err != nil {
		writeAPIError(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, result)
}

// UserOperationDetail godoc
// @Summary Get user operation detail
// @Tags Operations
// @Security BearerAuth
// @Produce json
// @Param userOpHash path string true "User operation hash"
// @Param chain_id query uint64 false "Chain ID override"
// @Success 200 {object} indexersvc.UserOperationDetail
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/ops/{userOpHash} [get]
func (h *indexerHandler) UserOperationDetail(c *gin.Context) {
	hash := strings.ToLower(strings.TrimSpace(c.Param("userOpHash")))
	if hash == "" {
		writeAPIError(c, http.StatusBadRequest, "userOpHash is required")
		return
	}
	chainID := h.cfg.Chain.ChainID
	if raw := strings.TrimSpace(c.Query("chain_id")); raw != "" {
		val, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeAPIError(c, http.StatusBadRequest, "invalid chain_id")
			return
		}
		chainID = val
	}
	if chainID == 0 {
		writeAPIError(c, http.StatusBadRequest, "chain id required")
		return
	}
	detail, err := h.reader.GetUserOperation(c.Request.Context(), chainID, hash)
	if err != nil {
		writeAPIError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if detail == nil {
		writeAPIError(c, http.StatusNotFound, "user operation not found")
		return
	}
	c.JSON(http.StatusOK, detail)
}

// UserOperationGas godoc
// @Summary Get user operation gas breakdown
// @Tags Operations
// @Security BearerAuth
// @Produce json
// @Param userOpHash path string true "User operation hash"
// @Param chain_id query uint64 false "Chain ID override"
// @Success 200 {object} indexersvc.UserOperationGas
// @Failure 400 {object} admin.ErrorResponse
// @Failure 404 {object} admin.ErrorResponse
// @Failure 500 {object} admin.ErrorResponse
// @Router /api/v1/ops/{userOpHash}/gas [get]
func (h *indexerHandler) UserOperationGas(c *gin.Context) {
	hash := strings.ToLower(strings.TrimSpace(c.Param("userOpHash")))
	if hash == "" {
		writeAPIError(c, http.StatusBadRequest, "userOpHash is required")
		return
	}
	chainID := h.cfg.Chain.ChainID
	if raw := strings.TrimSpace(c.Query("chain_id")); raw != "" {
		val, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeAPIError(c, http.StatusBadRequest, "invalid chain_id")
			return
		}
		chainID = val
	}
	if chainID == 0 {
		writeAPIError(c, http.StatusBadRequest, "chain id required")
		return
	}
	gas, err := h.reader.GetUserOperationGas(c.Request.Context(), chainID, hash)
	if err != nil {
		writeAPIError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if gas == nil {
		writeAPIError(c, http.StatusNotFound, "user operation not found")
		return
	}
	c.JSON(http.StatusOK, gas)
}

// StreamEvents godoc
// @Summary Stream user operation events
// @Tags Events
// @Produce json
// @Router /api/v1/events [get]
func (h *indexerHandler) StreamEvents(c *gin.Context) {
	h.hub.ServeWS(c)
}

func writeAPIError(c *gin.Context, status int, msg string) {
	c.JSON(status, admin.ErrorResponse{Error: msg})
}
