package server

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/gin-gonic/gin"
)

type bundlerHandler struct {
	url    string
	client *http.Client
}

func newBundlerHandler(cfg config.Config) *bundlerHandler {
	return &bundlerHandler{
		url: cfg.Chain.BundlerURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type bundlerProxyResponse struct {
	Error string `json:"error"`
}

// BundlerProxy godoc
// @Summary Proxy JSON-RPC requests to configured bundler
// @Tags Bundler
// @Accept json
// @Produce json
// @Param request body interface{} true "JSON-RPC payload"
// @Success 200 {object} interface{}
// @Failure 502 {object} bundlerProxyResponse
// @Failure 500 {object} bundlerProxyResponse
// @Router /api/v1/bundler [post]
func (h *bundlerHandler) Proxy(c *gin.Context) {
	if h.url == "" {
		c.JSON(http.StatusBadGateway, bundlerProxyResponse{Error: "bundler URL not configured"})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, bundlerProxyResponse{Error: "failed to read request body"})
		return
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, bundlerProxyResponse{Error: "failed to create bundler request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, bundlerProxyResponse{Error: err.Error()})
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, bundlerProxyResponse{Error: "failed to read bundler response"})
		return
	}
	for k, vals := range resp.Header {
		for _, v := range vals {
			c.Writer.Header().Add(k, v)
		}
	}
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
}
