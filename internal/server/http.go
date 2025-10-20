package server

import (
	"context"
	"net/http"
)

type HTTP struct {
	addr   string
	engine http.Handler
	srv    *http.Server
}

func NewHTTP(addr string, h http.Handler) *HTTP {
	return &HTTP{addr: addr, engine: h}
}

func (h *HTTP) Start() error {
	h.srv = &http.Server{Addr: h.addr, Handler: h.engine}
	return h.srv.ListenAndServe()
}

func (h *HTTP) Stop(ctx context.Context) error {
	if h.srv == nil {
		return nil
	}
	return h.srv.Shutdown(ctx)
}
