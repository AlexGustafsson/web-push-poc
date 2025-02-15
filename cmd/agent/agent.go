package main

import (
	"crypto/ecdh"
	"fmt"

	"github.com/AlexGustafsson/web-push-poc/internal/webpush"
	"github.com/google/uuid"
)

var _ webpush.Subscriber = (*Agent)(nil)
var _ webpush.Pusher = (*Agent)(nil)

type Agent struct {
	Secret       []byte
	PushEndpoint string
	Manager      *webpush.PushManager
}

// Subscribe implements webpush.PushService.
func (a *Agent) Subscribe(userAgentPrivateKey *ecdh.PrivateKey, applicationServerPublicKey *ecdh.PublicKey) (string, string, error) {
	subscriptionID, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	token := Token{
		Version:                    1,
		SubscriptionID:             subscriptionID,
		ApplicationServerPublicKey: applicationServerPublicKey,
		UserAgentPrivateKey:        userAgentPrivateKey,
	}

	sealedToken, err := token.SealString(a.Secret)
	if err != nil {
		return "", "", err
	}

	return subscriptionID.String(), a.PushEndpoint + "/" + sealedToken, nil
}

// Push implements webpush.Pusher.
func (a *Agent) Push(request *webpush.PushRequest) error {
	var token Token
	if err := token.OpenString(request.Token, a.Secret); err != nil {
		return err
	}

	// NOTE: In our case we don't really care about the rest of the fields...
	// TODO: Again, this interface isn't really that nice for our stateless use
	// case. In practice we have the state in the token above
	plaintext, err := a.Manager.HandleMessage(token.SubscriptionID.String(), request.Content)
	if err != nil {
		return err
	}

	// In practice, this message would likely be sent to some other service like
	// Gotify
	fmt.Println("Received message")
	fmt.Printf("%s\n", plaintext)

	return nil
}
