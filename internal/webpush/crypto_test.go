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
		{
			Name:                        "gauntface/simple-push-demo",
			SenderPrivateKey:            "Na-Ni-q9g4-2nsWRM_H8mRIetaU7g7B3Ro5r7qFoabA",
			RecipientPublicKey:          "BPrMBzUIc82DkzcwuHj5G71Z3VwqKgGRyrJn2zztT8SnuPuWRLr8FtAEEi8wUv_qCMhck6BqYUED7Giq7LX7we8",
			AuthenticationSecret:        "WQPDDSyc6zuWFh4uf-j_iA",
			ExpectedInputKeyingMaterial: "b6zpwBJpyjx2c3Dq5QAYzgJZX-R59KpfBBNglKExK3I",
		},
		{
			Name:                        "web-push-libs",
			SenderPrivateKey:            "PIS4Ddm0laePFLtaIFceRKingIT7-wtmrfC1In4Qdk8",
			RecipientPublicKey:          "BGjMKZb-kF3YvQ1PE0zXQM2iOCpRD-9ZEVMM3TUU9SUr_mVhIIdbBY1-0XMZ03NrSqgP3tmycvwRsdnD8w5YpCA",
			AuthenticationSecret:        "uEMWDVY9OhnL-QwUZlKNRg",
			ExpectedInputKeyingMaterial: "t_zK2QcuRXCEmECTCyzIa_gsfUuLGXsqx91rOa2oRYM",
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
