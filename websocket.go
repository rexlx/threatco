package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

// Notification defines the structure for a real-time message.
type Notification struct {
	Created time.Time `json:"created"`
	Info    string    `json:"info"`
	Error   bool      `json:"error"`
}

// upgrader holds the websocket configuration.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// CheckOrigin should be configured for your production domain.
	CheckOrigin: func(r *http.Request) bool {
		return true // Allowing all origins for development.
	},
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub
	// The user's unique identifier (e.g., email or a UUID).
	userID string
	// The websocket connection.
	conn *websocket.Conn
	// Buffered channel of outbound messages.
	send chan []byte
}

// Hub maintains the set of active clients and broadcasts messages to them.
type Hub struct {
	// Registered clients. We use a map where keys are userIDs.
	// The value is another map of clients, allowing a user to have multiple connections (e.g., from different tabs).
	clients map[string]map[*Client]bool
	// Inbound messages from the clients.
	broadcast chan []byte
	// Register requests from the clients.
	register chan *Client
	// Unregister requests from clients.
	unregister chan *Client
	// Mutex to protect the clients map during concurrent access.
	mu sync.RWMutex
}

// NewHub creates and returns a new Hub.
func NewHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[string]map[*Client]bool),
	}
}

// Run starts the hub's event loop.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			// If this is the first connection for the user, initialize their client map.
			if _, ok := h.clients[client.userID]; !ok {
				h.clients[client.userID] = make(map[*Client]bool)
			}
			h.clients[client.userID][client] = true
			log.Printf("Client registered for user: %s", client.userID)
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			// Check if the user and the specific client connection exist before trying to delete.
			if userClients, ok := h.clients[client.userID]; ok {
				if _, ok := userClients[client]; ok {
					delete(userClients, client)
					close(client.send)
					// If this was the user's last connection, remove their entry from the main map.
					if len(userClients) == 0 {
						delete(h.clients, client.userID)
					}
					log.Printf("Client unregistered for user: %s", client.userID)
				}
			}
			h.mu.Unlock()
		}
	}
}

type jsonNotification struct {
	Created string `json:"created"`
	Info    string `json:"info"`
	Error   bool   `json:"error"`
}

// SendToUser sends a notification to all active connections for a specific user.
func (h *Hub) SendToUser(userID string, notification Notification) {
	jsonMsg := jsonNotification{
		Created: notification.Created.Format(time.RFC3339),
		Info:    notification.Info,
		Error:   notification.Error,
	}
	message, err := json.Marshal(jsonMsg)
	if err != nil {
		log.Printf("Error marshalling notification for user %s: %v", userID, err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	if userClients, ok := h.clients[userID]; ok {
		log.Printf("Sending notification to %d client(s) for user %s", len(userClients), userID)
		for client := range userClients {
			// Use a select statement to prevent blocking if the client's send channel is full.
			select {
			case client.send <- message:
			default:
				// Assume client is dead or stuck, so we unregister and close the connection.
				log.Printf("Client send channel full for user %s. Closing connection.", userID)
				go func(c *Client) { h.unregister <- c }(client)
			}
		}
	} else {
		log.Printf("No active clients found for user: %s", userID)
		fmt.Println(h.clients)
	}
}

// ServeWs handles websocket requests from the peer.
func (s *Server) ServeWs(w http.ResponseWriter, r *http.Request) {
	tkn, err := s.GetTokenFromSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tk, err := s.DB.GetTokenByValue(tkn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u, err := s.DB.GetUserByEmail(tk.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}

	client := &Client{hub: s.Hub, userID: u.Email, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in new goroutines.
	go client.writePump()
	go client.readPump()
}

// writePump pumps messages from the hub to the websocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(512) // Set a read limit on incoming messages
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })

	// The client's read loop. In this design, we don't expect messages from the client,
	// but this loop is necessary to detect when the client closes the connection.
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Unexpected close error: %v", err)
			}
			break
		}
	}
}
