package server

import (
	"net/http"
	"strings"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/gin-gonic/gin"
)

type addressHandler struct {
	cfg config.Config
}

type AddressLookupResponse struct {
	Address string `json:"address"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func newAddressHandler(cfg config.Config) *addressHandler {
	return &addressHandler{cfg: cfg}
}

// LookupAddress godoc
// @Summary Lookup configured contract address
// @Description Returns the configured address for supported contracts: entrypoint, simple_account_factory, erc721.
// @Tags Addresses
// @Produce json
// @Param contract query string true "Contract identifier" Enums(entrypoint,entry_point,simple_account_factory,factory,erc721,nft,playground_nft)
// @Success 200 {object} AddressLookupResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/addresses [get]
func (h *addressHandler) LookupAddress(c *gin.Context) {
	contract := strings.ToLower(strings.TrimSpace(c.Query("contract")))
	switch contract {
	case "entrypoint", "entry_point":
		if h.cfg.Chain.EntryPointAddress == "" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "entry point address not configured"})
			return
		}
		c.JSON(http.StatusOK, AddressLookupResponse{Address: h.cfg.Chain.EntryPointAddress})
	case "simple_account_factory", "factory":
		if h.cfg.Chain.SimpleAccountFactory == "" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "factory address not configured"})
			return
		}
		c.JSON(http.StatusOK, AddressLookupResponse{Address: h.cfg.Chain.SimpleAccountFactory})
	case "erc721", "nft", "playground_nft":
		if h.cfg.Chain.ERC721Address == "" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "erc721 address not configured"})
			return
		}
		c.JSON(http.StatusOK, AddressLookupResponse{Address: h.cfg.Chain.ERC721Address})
	default:
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "unsupported contract query"})
	}
}
