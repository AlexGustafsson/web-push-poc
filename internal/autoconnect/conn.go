package autoconnect

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gorilla/websocket"
)

type Message interface {
	Type() string
}

type HelloMessageRequest struct {
	MessageType string         `json:"messageType"`
	UseWebPush  bool           `json:"use_webpush"`
	Broadcasts  map[string]any `json:"broadcasts"`
}

func (r *HelloMessageRequest) Type() string {
	return "hello"
}

type HelloMessageResponse struct {
	MessageType string         `json:"messageType"`
	UAID        string         `json:"uaid"`
	Status      int            `json:"status"`
	UseWebPush  bool           `json:"use_webpush"`
	Broadcasts  map[string]any `json:"broadcasts"`
}

func (r *HelloMessageResponse) Type() string {
	return "hello"
}

type RegisterMessageRequest struct {
	MessageType string `json:"messageType"`
	ChannelID   string `json:"channelID"`
	Key         string `json:"key"`
}

func (r *RegisterMessageRequest) Type() string {
	return "register"
}

type RegisterMessageResponse struct {
	MessageType  string `json:"messageType"`
	ChannelID    string `json:"channelID"`
	Status       int    `json:"status"`
	PushEndpoint string `json:"pushEndpoint"`
}

func (r *RegisterMessageResponse) Type() string {
	return "register"
}

type NotificationMessage struct {
	MessageType string            `json:"messageType"`
	ChannelID   string            `json:"channelID"`
	Version     string            `json:"version"`
	Data        string            `json:"data"`
	Headers     map[string]string `json:"headers"`
}

func (r *NotificationMessage) Type() string {
	return "notification"
}

// Conn provides "low-level" means of interacting with Mozilla's autoconnect
// service.
type Conn struct {
	mutex     sync.Mutex
	conn      *websocket.Conn
	onMessage func(Message)
}

// Dial connects to a autoconnect server.
//
// Example:
//
//	Dial("wss://push.services.mozilla.com/")
func Dial(url string) (*Conn, error) {
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		conn: conn,
	}

	// TODO: Pinging?

	// Read pump
	go func() {
		defer conn.Close()

		for {
			// Assume text messages for now
			_, data, err := conn.ReadMessage()
			if err != nil {
				slog.Error("Failed to read message", slog.Any("error", err))
				return
			}
			slog.Debug("Read message", slog.String("message", string(data)))

			var envelope struct {
				MessageType string `json:"messageType"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				slog.Warn("Failed to parse message", slog.Any("error", err))
				continue
			}

			var message Message
			switch envelope.MessageType {
			case "hello":
				message = &HelloMessageResponse{}
			case "notification":
				message = &NotificationMessage{}
			case "register":
				message = &RegisterMessageResponse{}
			default:
				slog.Warn("Got unknown message", slog.String("messageType", envelope.MessageType))
				continue
			}
			if err := json.Unmarshal(data, message); err != nil {
				slog.Warn("Failed to parse message", slog.Any("error", err))
				continue
			}

			handler := c.onMessage
			if handler == nil {
				slog.Warn("Dropped message", slog.Any("message", message))
			} else {
				handler(message)
			}
		}
	}()

	return c, nil
}

// OnMessage sets a handler to be invoked on each received message.
func (c *Conn) OnMessage(handler func(Message)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.onMessage = handler
}

func (c *Conn) Write(message Message) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.conn.WriteJSON(message)
}

func (c *Conn) Send(message Message) (Message, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	handler := c.onMessage
	defer func() {
		c.onMessage = handler
	}()

	messages := make(chan Message)
	defer close(messages)
	c.onMessage = func(m Message) {
		messages <- m
	}

	if err := c.conn.WriteJSON(message); err != nil {
		return nil, err
	}

	response, ok := <-messages
	if !ok {
		return nil, fmt.Errorf("no response received")
	}

	if response.Type() != message.Type() {
		return nil, fmt.Errorf("got unexpected message type: %s", response.Type())
	}

	return response, nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}
