package webpush

import "crypto/ecdh"

// Subscriber provides means to interact with a Web Push Push Service.
// TODO: Should users that want to write a Push Service "server" implement this
// interface as well?
type Subscriber interface {
	// Subscribe registers a subscription.
	// Returns a subscription ID and the endpoint to which push messages can be
	// sent.
	// NOTE: The private key is not required by implementations that use an
	// upstream push service. It is exposed for more advanced use cases, like a
	// user agent / push service combo.
	Subscribe(userAgentPrivateKey *ecdh.PrivateKey, applicationServerPublicKey *ecdh.PublicKey) (string, string, error)
}

type PushRequest struct {
	Token       string
	TTL         int
	Topic       string
	ContentType string
	Content     []byte
}

type Pusher interface {
	Push(request *PushRequest) error
}
