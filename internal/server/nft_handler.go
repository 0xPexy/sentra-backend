package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/0xPexy/sentra-backend/internal/config"
	indexersvc "github.com/0xPexy/sentra-backend/internal/indexer/service"
	"github.com/gin-gonic/gin"
)

type nftHandler struct {
	cfg    config.Config
	reader *indexersvc.Reader
}

func newNFTHandler(cfg config.Config, reader *indexersvc.Reader) *nftHandler {
	return &nftHandler{cfg: cfg, reader: reader}
}

// ListAccountNFTs godoc
// @Summary List NFTs owned by address
// @Tags Playground
// @Produce json
// @Param address path string true "Owner address"
// @Param chain_id query uint64 false "Chain ID override"
// @Param contract query string false "ERC721 contract address override"
// @Success 200 {object} indexersvc.NFTListResult
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/nfts/{address} [get]
func (h *nftHandler) ListAccountNFTs(c *gin.Context) {
	owner := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if owner == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "owner address required"})
		return
	}
	chainID := h.cfg.Chain.ChainID
	if raw := strings.TrimSpace(c.Query("chain_id")); raw != "" {
		val, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid chain_id"})
			return
		}
		chainID = val
	}
	if chainID == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "chain id required"})
		return
	}
	contract := strings.TrimSpace(c.Query("contract"))
	if contract == "" {
		contract = h.cfg.Chain.ERC721Address
	}
	result, err := h.reader.ListNFTs(c.Request.Context(), indexersvc.ListNFTsParams{
		ChainID:  chainID,
		Contract: contract,
		Owner:    owner,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
