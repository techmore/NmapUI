package websocket

import (
	"log"
	"sync"
)

// Hub manages active websocket clients.
type Hub struct {
	clients     map[*Client]bool
	clientsByID map[string]*Client
	broadcast   chan Message
	register    chan *Client
	unregister  chan *Client
	mu          sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		clients:     make(map[*Client]bool),
		clientsByID: make(map[string]*Client),
		broadcast:   make(chan Message, 128),
		register:    make(chan *Client, 64),
		unregister:  make(chan *Client, 64),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.clientsByID[client.id] = client
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
			}
			if existing, ok := h.clientsByID[client.id]; ok && existing == client {
				delete(h.clientsByID, client.id)
			}
			h.mu.Unlock()
			client.Close()
		case message := <-h.broadcast:
			h.broadcastToClients(message)
		}
	}
}

func (h *Hub) Register(client *Client) {
	h.register <- client
}

func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}

func (h *Hub) Broadcast(message Message) {
	select {
	case h.broadcast <- message:
	default:
		log.Printf("websocket hub broadcast dropped event=%s", message.Event)
	}
}

func (h *Hub) SendTo(id string, message Message) {
	h.mu.RLock()
	client := h.clientsByID[id]
	h.mu.RUnlock()
	if client == nil {
		return
	}

	client.Send(message)
}

func (h *Hub) broadcastToClients(message Message) {
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()

	for _, client := range clients {
		client.Send(message)
	}
}
