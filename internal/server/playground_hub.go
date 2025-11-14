package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type playgroundHub struct {
	mu       sync.RWMutex
	clients  map[*playgroundClient]struct{}
	upgrader websocket.Upgrader
	logger   *log.Logger
}

type playgroundClient struct {
	conn *websocket.Conn
	send chan []byte
}

type PlaygroundHub struct {
	*playgroundHub
}

type playgroundEvent struct {
	UserOpHash string `json:"userOpHash"`
	TxHash     string `json:"txHash"`
	Status     string `json:"status"`
	DetailURL  string `json:"detailUrl"`
}

func NewPlaygroundHub(logger *log.Logger) *PlaygroundHub {
	return &PlaygroundHub{playgroundHub: &playgroundHub{
		clients: make(map[*playgroundClient]struct{}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		logger: logger,
	}}
}

func (h *PlaygroundHub) PublishUserOperation(event *store.UserOperationEvent) {
	if h == nil || event == nil {
		return
	}
	status := "failed"
	if event.Success {
		status = "success"
	}
	msg := playgroundEvent{
		UserOpHash: strings.ToLower(event.UserOpHash),
		TxHash:     strings.ToLower(event.TxHash),
		Status:     status,
		DetailURL:  fmt.Sprintf("/ops/%s", strings.ToLower(event.UserOpHash)),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		h.logf("playground marshal: %v", err)
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		select {
		case client.send <- payload:
		default:
			go h.closeClient(client)
		}
	}
}

func (h *PlaygroundHub) ServeWS(c *gin.Context) {
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logf("playground upgrade: %v", err)
		return
	}
	client := &playgroundClient{
		conn: conn,
		send: make(chan []byte, 32),
	}
	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()

	go client.writePump()
	go client.readPump(func() {
		h.closeClient(client)
	})
}

func (h *PlaygroundHub) Run(ctx context.Context) {
	if h == nil {
		return
	}
	<-ctx.Done()
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		client.conn.Close()
		delete(h.clients, client)
	}
}

func (h *PlaygroundHub) closeClient(client *playgroundClient) {
	h.mu.Lock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
	}
	h.mu.Unlock()
	client.conn.Close()
	close(client.send)
}

func (h *PlaygroundHub) logf(format string, args ...any) {
	if h.logger != nil {
		h.logger.Printf("playground: "+format, args...)
	}
}

func (c *playgroundClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *playgroundClient) readPump(onClose func()) {
	defer onClose()
	c.conn.SetReadLimit(1024)
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}
