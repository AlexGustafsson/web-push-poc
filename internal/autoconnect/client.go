package autoconnect

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/AlexGustafsson/web-push-poc/internal/webpush"
	"github.com/google/uuid"
)

var _ webpush.Subscriber = (*Client)(nil)

// Client implements a autoconnect client for interacting with Mozilla's
// Web Push service.
type Client struct {
	conn *Conn
	uaid string
}

func NewClient(url string) (*Client, error) {
	conn, err := Dial(url)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn: conn,
	}

	response, err := conn.Send(&HelloMessageRequest{
		MessageType: "hello",
		UseWebPush:  true,
		Broadcasts:  make(map[string]any),
	})
	if err != nil {
		conn.Close()
		return nil, err
	}

	helloResponse := response.(*HelloMessageResponse)
	if helloResponse.Status != 200 {
		return nil, fmt.Errorf("got unexpected status: %d", helloResponse.Status)
	}

	return c, nil
}

func (c *Client) OnMessage(handler func(Message)) {
	c.conn.OnMessage(handler)
}

// Register registers a subscription.
func (c *Client) Register(channelID string, key string) (string, error) {
	response, err := c.conn.Send(&RegisterMessageRequest{
		MessageType: "register",
		ChannelID:   channelID,
		Key:         key,
	})
	if err != nil {
		return "", err
	}

	registerResponse := response.(*RegisterMessageResponse)
	if registerResponse.Status != 200 {
		return "", fmt.Errorf("got unexpected status: %d", registerResponse.Status)
	}

	if registerResponse.Status != 200 {
		return "", fmt.Errorf("got unexpected status: %d", registerResponse.Status)
	}

	return registerResponse.PushEndpoint, nil
}

// Subscribe implements webpush.PushService.
func (c *Client) Subscribe(userAgentPrivateKey *ecdh.PrivateKey, _ *ecdh.PublicKey) (string, string, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", "", nil
	}

	channelID := uuid.String()

	endpoint, err := c.Register(channelID, base64.RawURLEncoding.EncodeToString(userAgentPrivateKey.PublicKey().Bytes()))
	if err != nil {
		return "", "", err
	}

	return channelID, endpoint, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}
