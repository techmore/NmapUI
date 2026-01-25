package websocket

import (
	"log"
	"sync"
	"time"

	fiberws "github.com/gofiber/contrib/websocket"
	"github.com/google/uuid"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = 30 * time.Second
	maxMessageSize = 512 * 1024
	sendBufferSize = 256
)

type Client struct {
	id        string
	hub       *Hub
	conn      *fiberws.Conn
	send      chan Message
	router    *Router
	done      chan struct{}
	closeOnce sync.Once
}

func NewClient(hub *Hub, conn *fiberws.Conn, router *Router) *Client {
	return &Client{
		id:     uuid.NewString(),
		hub:    hub,
		conn:   conn,
		send:   make(chan Message, sendBufferSize),
		router: router,
		done:   make(chan struct{}),
	}
}

func (c *Client) ID() string {
	return c.id
}

func (c *Client) Start() {
	go c.writePump()
	go c.readPump()
}

func (c *Client) Done() <-chan struct{} {
	return c.done
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		close(c.send)
		if c.conn != nil {
			if err := c.conn.Close(); err != nil {
				log.Printf("websocket close error client=%s err=%v", c.id, err)
			}
		}
	})
}

func (c *Client) Send(message Message) {
	select {
	case c.send <- message:
	default:
		log.Printf("websocket send buffer full client=%s event=%s", c.id, message.Event)
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.Unregister(c)
	}()

	c.conn.SetReadLimit(maxMessageSize)
	if err := c.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		log.Printf("websocket read deadline error client=%s err=%v", c.id, err)
	}
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		var message Message
		if err := c.conn.ReadJSON(&message); err != nil {
			if fiberws.IsUnexpectedCloseError(err, fiberws.CloseGoingAway, fiberws.CloseAbnormalClosure) {
				log.Printf("websocket read error client=%s err=%v", c.id, err)
			}
			break
		}

		if message.Event == "" {
			continue
		}

		if message.To != "" {
			c.hub.SendTo(message.To, message)
			continue
		}

		if err := c.router.Handle(c, message); err != nil {
			log.Printf("websocket handle error client=%s event=%s err=%v", c.id, message.Event, err)
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
				_ = c.conn.WriteMessage(fiberws.CloseMessage, []byte{})
				return
			}

			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Printf("websocket write deadline error client=%s err=%v", c.id, err)
			}
			if err := c.conn.WriteJSON(message); err != nil {
				log.Printf("websocket write error client=%s err=%v", c.id, err)
				return
			}
		case <-ticker.C:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Printf("websocket ping deadline error client=%s err=%v", c.id, err)
			}
			if err := c.conn.WriteMessage(fiberws.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
