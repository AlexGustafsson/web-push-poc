package vapid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const AuthorizationScheme = "vapid"

func FormatAuthorizationHeader(token string, key *ecdsa.PublicKey) string {
	k := base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	return fmt.Sprintf("%s t=%s, k=%s", AuthorizationScheme, token, k)
}

// NewToken creates a new VAPID JWT.
// - expires MUST be less than 24 hours.
func NewToken(audience string, expires time.Time, subject string, key *ecdsa.PrivateKey) (string, error) {
	// SEE: https://datatracker.ietf.org/doc/html/rfc7519#section-5
	header := map[string]any{
		"typ": "JWT",
		"alg": "ES256",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	// SEE: https://datatracker.ietf.org/doc/html/rfc7519#section-4
	claims := map[string]any{
		"aud": audience,
		"exp": expires.Unix(),
		"sub": subject,
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// SEE: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
	jwt := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)

	hash := sha256.Sum256([]byte(jwt))

	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return jwt + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
