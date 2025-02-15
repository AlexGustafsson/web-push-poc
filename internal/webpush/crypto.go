package webpush

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
)

// TODO: Rewrite? Split up?
// Weird the way it's written now with the different ways to call it.
// Also, technically, shouldn't the application server public key be an ecdsa
// public key? So far in go, ecdh has much nicer ergonomics.
// SEE: https://github.com/golang/go/issues/63963
// SEE: https://www.rfc-editor.org/rfc/rfc8291.html#section-3.4
func DeriveInputKeyingMaterial(
	privateKey *ecdh.PrivateKey,
	publicKey *ecdh.PublicKey,
	userAgentPublicKey *ecdh.PublicKey,
	applicationServerPublicKey *ecdh.PublicKey,
	authenticationSecret []byte,
) ([]byte, error) {
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}

	// "WebPush: info" || 0x00 || ua_public || as_public
	var info bytes.Buffer
	info.WriteString("WebPush: info")
	info.WriteRune(0x00)
	info.Write(userAgentPublicKey.Bytes())
	info.Write(applicationServerPublicKey.Bytes())

	return hkdf.Key(sha256.New, sharedSecret, authenticationSecret, info.String(), 32)
}
