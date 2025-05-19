package webpush

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AlexGustafsson/web-push-poc/internal/aes128gcm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplicationServerPushContent(t *testing.T) {
	userAgentPrivateKey := "yE4NtfUtgIgt-LfsBGMZqQkbR0UJsxdwWY4W3CS-fC4"
	userAgentPublicKey := "BAgmPAlNFAEASIyxob47Ov6ftM2f1Cb6WR60zKP5UZSA9ah507JHtsUA0GsOxkMo6KUgwHc1pU7Gj5UlSESITTg"
	authenticationSecret := "uEMWDVY9OhnL-QwUZlKNRg"
	content := []byte(`{"web_push":8030,"notification":{"title":"Hello, World!","navigate":"https://example.com"}}`)

	applicationServer, err := NewApplicationServer()
	require.NoError(t, err)

	// The server acts as the push service and user agent, receiving push messages
	// sent by the application server and decrypting them
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ciphertext, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var header aes128gcm.Header
		err = header.UnmarshalBinary(ciphertext)
		require.NoError(t, err)

		// Ephemeral sender key
		senderPublicKey, err := ecdh.P256().NewPublicKey(header.KeyID)
		require.NoError(t, err)

		ikm, err := DeriveInputKeyingMaterial(
			parsePrivateKey(t, userAgentPrivateKey), senderPublicKey,
			parsePublicKey(t, userAgentPublicKey), senderPublicKey,
			parseBytes(t, authenticationSecret),
		)
		require.NoError(t, err)

		actualContent, err := aes128gcm.Decrypt(ciphertext, ikm)
		require.NoError(t, err)
		assert.Equal(t, content, actualContent)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	subscription := Subscription{
		Endpoint: server.URL,
		Keys: SubscriptionKeys{
			P256DH: userAgentPublicKey,
			Auth:   authenticationSecret,
		},
	}

	target, err := subscription.PushTarget()
	require.NoError(t, err)

	err = applicationServer.Push(context.TODO(), target, content, nil)
	require.NoError(t, err)
}

func parsePrivateKey(t *testing.T, k string) *ecdh.PrivateKey {
	bytes := parseBytes(t, k)

	key, err := ecdh.P256().NewPrivateKey(bytes)
	require.NoError(t, err)

	return key
}

func parsePublicKey(t *testing.T, k string) *ecdh.PublicKey {
	bytes := parseBytes(t, k)

	key, err := ecdh.P256().NewPublicKey(bytes)
	require.NoError(t, err)

	return key
}

func parseBytes(t *testing.T, v string) []byte {
	bytes, err := base64.RawURLEncoding.DecodeString(v)
	require.NoError(t, err)

	return bytes
}
