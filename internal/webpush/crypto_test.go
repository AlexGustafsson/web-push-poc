package webpush

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveInputKeyingMaterial(t *testing.T) {
	// All values are Base64 URL-encoded, without padding
	testCases := []struct {
		Name                        string
		SenderPrivateKey            string
		RecipientPublicKey          string
		AuthenticationSecret        string
		ExpectedInputKeyingMaterial string
	}{
		{
			Name:                        "RFC 8291 4",
			SenderPrivateKey:            "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
			RecipientPublicKey:          "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
			AuthenticationSecret:        "BTBZMqHH6r4Tts7J_aSIgg",
			ExpectedInputKeyingMaterial: "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			senderPrivateKeyBytes, err := base64.RawURLEncoding.DecodeString(testCase.SenderPrivateKey)
			require.NoError(t, err)

			senderPrivateKey, err := ecdh.P256().NewPrivateKey(senderPrivateKeyBytes)
			require.NoError(t, err)

			recipientPublicKeyBytes, err := base64.RawURLEncoding.DecodeString(testCase.RecipientPublicKey)
			require.NoError(t, err)

			recipientPublicKey, err := ecdh.P256().NewPublicKey(recipientPublicKeyBytes)
			require.NoError(t, err)

			authenticationSecret, err := base64.RawURLEncoding.DecodeString(testCase.AuthenticationSecret)
			require.NoError(t, err)

			expectedIKM, err := base64.RawURLEncoding.DecodeString(testCase.ExpectedInputKeyingMaterial)
			require.NoError(t, err)

			ikm, err := DeriveInputKeyingMaterial(
				senderPrivateKey, recipientPublicKey,
				recipientPublicKey, senderPrivateKey.PublicKey(),
				authenticationSecret,
			)
			require.NoError(t, err)
			assert.Equal(t, expectedIKM, ikm)
		})
	}
}
