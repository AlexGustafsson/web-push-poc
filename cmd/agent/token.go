package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

// Token holds everything required to handle push messages in a stateless way.
// Note that we don't target the same scale as major vendors, so we don't need
// to consider things like partitioning keys. We assume that a single backend
// instance is used.
// Once sealed, all contents of the token, but the version is encrypted.
// TODO: The intention is that exposing subscription ids or public keys would
// greater risk fingerprinting? Why the private key is encrypted is obvious.
// TODO: We need the authentication secret as well for this to properly survive
// restarts
type Token struct {
	Version                    uint8
	SubscriptionID             uuid.UUID
	ApplicationServerPublicKey *ecdh.PublicKey
	UserAgentPrivateKey        *ecdh.PrivateKey
}

func (t *Token) Seal(secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// TODO: We could probably derive the nonce to save a few bytes, for example
	// by using the private key, as it's known to be ephemeral and unique to this
	// subscription. It would be somewhat similar to the "sealed_box" crypto_box
	// adaptation with ephemeral sender keys.
	// nonce = blake2b(ephemeral_pk || subscription id)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Size assumes P-256
	data := make([]byte, 16+65+32)
	copy(data[0:16], t.SubscriptionID[:])
	copy(data[16:81], t.ApplicationServerPublicKey.Bytes())
	copy(data[81:113], t.UserAgentPrivateKey.Bytes())

	// Include the version in the AD as we don't intend to encrypt it, but like to
	// verify it
	info := fmt.Sprintf("Web Push PoC Version %d\x00", t.Version)

	// Encrypt all fields but the version
	data = aead.Seal(data[:0], nonce, data, []byte(info))

	ciphertext := []byte{t.Version}
	ciphertext = append(ciphertext, data...)
	ciphertext = append(ciphertext, nonce...)

	return ciphertext, nil
}

func (t *Token) SealString(secret []byte) (string, error) {
	ciphertext, err := t.Seal(secret)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (t *Token) Open(ciphertext []byte, secret []byte) error {
	version := ciphertext[0]
	if version != 0x01 {
		return fmt.Errorf("unsupported token version")
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	info := fmt.Sprintf("Web Push PoC Version %d\x00", version)

	nonce := ciphertext[len(ciphertext)-aead.NonceSize():]
	data := ciphertext[1 : len(ciphertext)-aead.NonceSize()]

	plaintext, err := aead.Open(data[:0], nonce, data, []byte(info))
	if err != nil {
		return err
	}

	token := Token{}
	token.Version = version
	copy(token.SubscriptionID[:], plaintext[0:16])

	applicationServerPublicKey, err := ecdh.P256().NewPublicKey(plaintext[16:81])
	if err != nil {
		return err
	}
	token.ApplicationServerPublicKey = applicationServerPublicKey

	userAgentPrivateKey, err := ecdh.P256().NewPrivateKey(plaintext[81:113])
	if err != nil {
		return err
	}
	token.UserAgentPrivateKey = userAgentPrivateKey

	*t = token
	return nil
}

func (t *Token) OpenString(ciphertext string, secret []byte) error {
	bytes, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return err
	}

	return t.Open(bytes, secret)
}
