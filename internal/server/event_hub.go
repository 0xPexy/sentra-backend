package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	indexersvc "github.com/0xPexy/sentra-backend/internal/indexer/service"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type eventClient struct {
	conn *websocket.Conn
	send chan []byte
}

type EventHub struct {
	mu       sync.RWMutex
	clients  map[*eventClient]struct{}
	upgrader websocket.Upgrader
	logger   *log.Logger
}

func NewEventHub(logger *log.Logger) *EventHub {
	return &EventHub{
		clients: make(map[*eventClient]struct{}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		logger: logger,
	}
}

func (h *EventHub) PublishUserOperation(event *store.UserOperationEvent) {
	target := strings.ToLower(event.Target)
	selector := event.CallSelector
	if selector == "-" {
		selector = ""
	}
	msg := indexersvc.UserOperationItem{
		UserOpHash:    event.UserOpHash,
		Sender:        event.Sender,
		Paymaster:     event.Paymaster,
		Target:        target,
		Selector:      selector,
		Status:        map[bool]string{true: "success", false: "failed"}[event.Success],
		BlockNumber:   event.BlockNumber,
		LogIndex:      event.LogIndex,
		TxHash:        event.TxHash,
		ActualGasUsed: event.ActualGasUsed,
		ActualGasCost: event.ActualGasCost,
		BlockTime:     event.BlockTime,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		h.logf("marshal event: %v", err)
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

func (h *EventHub) ServeWS(c *gin.Context) {
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logf("upgrade websocket: %v", err)
		return
	}
	client := &eventClient{
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

func (h *EventHub) Run(ctx context.Context) {
	<-ctx.Done()
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		client.conn.Close()
		delete(h.clients, client)
	}
}

func (h *EventHub) closeClient(client *eventClient) {
	h.mu.Lock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
	}
	h.mu.Unlock()
	client.conn.Close()
	close(client.send)
}

func (h *EventHub) logf(format string, args ...any) {
	if h.logger != nil {
		h.logger.Printf("eventhub: "+format, args...)
	}
}

func (c *eventClient) writePump() {
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

func (c *eventClient) readPump(onClose func()) {
	defer onClose()
	c.conn.SetReadLimit(1024)
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}
