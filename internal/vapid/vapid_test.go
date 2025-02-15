package vapid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatAuthorizationHeader(t *testing.T) {
	testCases := []struct {
		Name     string
		Token    string
		Key      string
		Expected string
	}{
		{
			Name:     "RFC 8292 2.4",
			Token:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA",
			Key:      "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs",
			Expected: "vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA, k=BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			keyBytes, err := base64.RawURLEncoding.DecodeString(testCase.Key)
			require.NoError(t, err)

			x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
			require.NotNil(t, x)

			key := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			}

			actual := FormatAuthorizationHeader(testCase.Token, key)
			assert.Equal(t, testCase.Expected, actual)
		})
	}
}

func TestNewToken(t *testing.T) {
	// This test is for manually verifying with a third party
	if testing.Short() {
		t.SkipNow()
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	fmt.Printf("%s\n", pem.EncodeToMemory(keyBlock))

	der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	keyBlock = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	fmt.Printf("%s\n", pem.EncodeToMemory(keyBlock))

	token, err := NewToken("test", time.Now().Add(1*time.Hour), "", key)
	require.NoError(t, err)

	fmt.Println(token)
	fmt.Println()
}
