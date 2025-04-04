package webpush

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/AlexGustafsson/web-push-poc/internal/aes128gcm"
	"github.com/AlexGustafsson/web-push-poc/internal/vapid"
)

// ApplicationServer implements a Web Push Application Server.
// SEE: Generic Event Delivery Using HTTP Push - https://datatracker.ietf.org/doc/html/rfc8030.
// SEE: VAPID - https://datatracker.ietf.org/doc/html/rfc8292#section-3.2.
// SEE: Message Encryption for Web Push - https://www.rfc-editor.org/rfc/rfc8291.html
type ApplicationServer struct {
	Subject string
	Client  http.Client

	ecdsa *ecdsa.PrivateKey
	ecdh  *ecdh.PrivateKey
}

func NewApplicationServer() (*ApplicationServer, error) {
	ecdsa, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	ecdh, err := ecdsa.ECDH()
	if err != nil {
		return nil, err
	}

	return &ApplicationServer{
		Client: *http.DefaultClient,

		ecdsa: ecdsa,
		ecdh:  ecdh,
	}, nil
}

func (a *ApplicationServer) PublicECDH() *ecdh.PublicKey {
	return a.ecdh.PublicKey()
}

func (a *ApplicationServer) PublicECDSA() *ecdsa.PublicKey {
	return &a.ecdsa.PublicKey
}

func (a *ApplicationServer) PublicKeyString() string {
	return base64.RawURLEncoding.EncodeToString(a.ecdh.PublicKey().Bytes())
}

type PushOptions struct {
	TTL         int64
	ContentType string
	Urgency     string
	Topic       string
}

type PushTarget struct {
	Endpoint             string
	UserAgentPublicKey   *ecdh.PublicKey
	AuthenticationSecret []byte
}

func (p PushTarget) Audience() (string, error) {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return "", err
	}

	return u.Scheme + "://" + u.Host, nil
}

func (a *ApplicationServer) Push(ctx context.Context, target *PushTarget, content []byte, options *PushOptions) error {
	audience, err := target.Audience()
	if err != nil {
		return err
	}

	vapidToken, err := vapid.NewToken(audience, time.Now().Add(5*time.Minute), a.Subject, a.ecdsa)
	if err != nil {
		return err
	}

	// Ephemeral sender key
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	ikm, err := DeriveInputKeyingMaterial(
		privateKey, target.UserAgentPublicKey,
		target.UserAgentPublicKey, a.ecdh.PublicKey(),
		target.AuthenticationSecret,
	)
	if err != nil {
		return err
	}

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}

	// An application server MUST set the "rs" parameter in the "aes128gcm"
	// content coding header to a size that is greater than the sum of the lengths
	// of the plaintext, the padding delimiter (1 octet), any padding, and the
	// authentication tag (16 octets).
	recordSize := len(content) + 16 + 1 + 1
	if recordSize > 4096 {
		slog.Warn("Record size is large, exceeds what's required to be supported by push services")
	}

	ciphertext, err := aes128gcm.Encrypt(content, ikm, salt[:], privateKey.PublicKey().Bytes(), recordSize)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, target.Endpoint, bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}

	req.Header.Set("TTL", "30")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Authorization", vapid.FormatAuthorizationHeader(vapidToken, &a.ecdsa.PublicKey))

	res, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		x, err := io.ReadAll(res.Body)
		if err == nil {
			fmt.Printf("%s\n", x)
		}
		fmt.Println(res.Header)

		// TODO: Parse body and create a proper error
		return fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	return nil
}
