package server

import (
	"fmt"
	"net/http"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/gin-gonic/gin"
)

type playgroundHandler struct {
	cfg config.Config
}

func newPlaygroundHandler(cfg config.Config) *playgroundHandler {
	return &playgroundHandler{cfg: cfg}
}

type playgroundNFTResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Image       string `json:"image"`
	ExternalURL string `json:"external_url,omitempty"`
}

// PlaygroundNFT godoc
// @Summary Playground demo NFT metadata
// @Tags Playground
// @Produce json
// @Success 200 {object} playgroundNFTResponse
// @Router /api/v1/playground/nft [get]
func (h *playgroundHandler) NFTMetadata(c *gin.Context) {
	scheme := c.Request.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if c.Request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := c.Request.Host
	imageURL := fmt.Sprintf("%s://%s/static/playground.png", scheme, host)
	c.JSON(http.StatusOK, playgroundNFTResponse{
		Name:        "Sentra Playground NFT",
		Description: "Demo metadata served by Sentinel backend playground endpoint.",
		Image:       imageURL,
		ExternalURL: fmt.Sprintf("%s://%s", scheme, host),
	})
}
