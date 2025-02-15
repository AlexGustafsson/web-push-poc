package webpush

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/AlexGustafsson/web-push-poc/internal/aes128gcm"
)

// Subscription is a Web Push subscription received from a Push Service via a
// Push Manager.
// SEE: https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription.
type Subscription struct {
	ID             string           `json:"-"`
	Endpoint       string           `json:"endpoint"`
	ExpirationTime *time.Time       `json:"expirationTime"`
	Keys           SubscriptionKeys `json:"keys"`

	applicationServerPublicKey *ecdh.PublicKey
	userAgentPrivateKey        *ecdh.PrivateKey
}

// PushTarget returns a [PushTarget] for use when pushing messages from an
// [ApplicationServer].
func (s *Subscription) PushTarget() (*PushTarget, error) {
	userAgentPublicKey, err := s.Keys.PublicKey()
	if err != nil {
		return nil, err
	}

	authenticationSecret, err := s.Keys.AuthenticationSecret()
	if err != nil {
		return nil, err
	}

	return &PushTarget{
		Endpoint:             s.Endpoint,
		UserAgentPublicKey:   userAgentPublicKey,
		AuthenticationSecret: authenticationSecret,
	}, nil
}

type SubscriptionKeys struct {
	Auth   string `json:"auth"`
	P256DH string `json:"p256dh"`
}

func (s *SubscriptionKeys) PublicKey() (*ecdh.PublicKey, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(s.P256DH)
	if err != nil {
		return nil, err
	}

	return ecdh.P256().NewPublicKey(publicKey)
}

func (s *SubscriptionKeys) AuthenticationSecret() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s.Auth)
}

// PushManager handles Web Push subscriptions.
// SEE: https://developer.mozilla.org/en-US/docs/Web/API/PushManager.
// SEE: Generic Event Delivery Using HTTP Push - https://datatracker.ietf.org/doc/html/rfc8030.
// SEE: VAPID - https://datatracker.ietf.org/doc/html/rfc8292#section-3.2.
// SEE: Message Encryption for Web Push - https://www.rfc-editor.org/rfc/rfc8291.html
type PushManager struct {
	subscriber Subscriber

	mutex         sync.RWMutex
	subscriptions map[string]*Subscription
}

// NewPushManager creates a new [PushManager] using the given [Subscriber] to
// handle subscriptions.
func NewPushManager(subscriber Subscriber) *PushManager {
	return &PushManager{
		subscriber:    subscriber,
		subscriptions: make(map[string]*Subscription),
	}
}

func (p *PushManager) Subscribe(applicationServerPublicKey *ecdh.PublicKey) (*Subscription, error) {
	userAgentPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	p256dh := base64.RawURLEncoding.EncodeToString(userAgentPrivateKey.PublicKey().Bytes())

	subscriptionID, endpoint, err := p.subscriber.Subscribe(userAgentPrivateKey, applicationServerPublicKey)
	if err != nil {
		return nil, err
	}

	authenticationSecret := make([]byte, 16)
	if _, err := rand.Read(authenticationSecret); err != nil {
		return nil, err
	}

	subscription := &Subscription{
		ID:             subscriptionID,
		Endpoint:       endpoint,
		ExpirationTime: nil,
		Keys: SubscriptionKeys{
			Auth:   base64.RawURLEncoding.EncodeToString(authenticationSecret),
			P256DH: p256dh,
		},

		applicationServerPublicKey: applicationServerPublicKey,
		userAgentPrivateKey:        userAgentPrivateKey,
	}

	p.mutex.Lock()
	p.subscriptions[subscriptionID] = subscription
	p.mutex.Unlock()

	return subscription, nil
}

// HandleMessage handles a message for a subscription.
// Returns the message's content.
func (p *PushManager) HandleMessage(subscriptionID string, message []byte) ([]byte, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	subscription, ok := p.subscriptions[subscriptionID]
	if !ok {
		return nil, fmt.Errorf("unknown subscription")
	}

	authenticationSecret, err := subscription.Keys.AuthenticationSecret()
	if err != nil {
		return nil, err
	}

	var header aes128gcm.Header
	if err := header.UnmarshalBinary(message); err != nil {
		return nil, err
	}

	// Ephemeral sender key
	senderPublicKey, err := ecdh.P256().NewPublicKey(header.KeyID)
	if err != nil {
		return nil, err
	}

	ikm, err := DeriveInputKeyingMaterial(
		subscription.userAgentPrivateKey, senderPublicKey,
		subscription.userAgentPrivateKey.PublicKey(), subscription.applicationServerPublicKey,
		authenticationSecret,
	)
	if err != nil {
		return nil, err
	}

	return aes128gcm.Decrypt(message, ikm)
}
