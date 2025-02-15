package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRoundtrip(t *testing.T) {
	subscriptionID, err := uuid.Parse("597cd1af-0686-47ba-959f-c6d7b49149b2")
	require.NoError(t, err)

	applicationServerPublicKeyBytes, err := base64.RawURLEncoding.DecodeString("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
	require.NoError(t, err)

	applicationServerPublicKey, err := ecdh.P256().NewPublicKey(applicationServerPublicKeyBytes)
	require.NoError(t, err)

	userAgentPrivateKeyBytes, err := base64.RawURLEncoding.DecodeString("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
	require.NoError(t, err)

	userAgentPrivateKey, err := ecdh.P256().NewPrivateKey(userAgentPrivateKeyBytes)
	require.NoError(t, err)

	secret, err := base64.RawURLEncoding.DecodeString("OPMLk5kfCaEEVMz1cleOM8VdlCCThTlBv55f8ZsNnro")
	require.NoError(t, err)

	token := Token{
		Version:                    1,
		SubscriptionID:             subscriptionID,
		ApplicationServerPublicKey: applicationServerPublicKey,
		UserAgentPrivateKey:        userAgentPrivateKey,
	}

	ciphertext, err := token.SealString(secret)
	require.NoError(t, err)

	fmt.Println(ciphertext)

	var actualToken Token
	require.NoError(t, actualToken.OpenString(ciphertext, secret))

	assert.Equal(t, token, actualToken)
}
