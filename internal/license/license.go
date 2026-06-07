// Package license implements OATD's commercial license workflow: the vendor
// issues Ed25519-signed license tokens with a private key; deployments verify
// them with the vendor public key. No private key ever ships with the product,
// so licenses cannot be forged.
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type License struct {
	Org       string    `json:"org"`
	Edition   string    `json:"edition"`
	Features  []string  `json:"features,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type Status struct {
	License
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

func (l License) HasFeature(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, f := range l.Features {
		if strings.ToLower(strings.TrimSpace(f)) == name {
			return true
		}
	}
	return false
}

// GenerateKeyPair returns base64 (std) encoded ed25519 public and private keys.
func GenerateKeyPair() (publicKey string, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// Issue signs a license with the base64 private key and returns a
// "<payload>.<sig>" token (both segments base64url, no padding).
func Issue(lic License, privateKey string) (string, error) {
	priv, err := decodePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	if lic.IssuedAt.IsZero() {
		lic.IssuedAt = time.Now().UTC()
	}
	if strings.TrimSpace(lic.Edition) == "" {
		lic.Edition = "commercial"
	}
	payload, err := json.Marshal(lic)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks the token signature against the base64 public key.
func Verify(token string, publicKey string) (License, error) {
	pub, err := decodePublicKey(publicKey)
	if err != nil {
		return License{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(token), ".", 2)
	if len(parts) != 2 {
		return License{}, errors.New("malformed license token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return License{}, errors.New("malformed license payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return License{}, errors.New("malformed license signature")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return License{}, errors.New("license signature is invalid")
	}
	var lic License
	if err := json.Unmarshal(payload, &lic); err != nil {
		return License{}, err
	}
	return lic, nil
}

// Evaluate verifies signature and expiry and returns a Status.
func Evaluate(token string, publicKey string, now time.Time) Status {
	lic, err := Verify(token, publicKey)
	if err != nil {
		return Status{Valid: false, Reason: err.Error()}
	}
	if !lic.ExpiresAt.IsZero() && now.After(lic.ExpiresAt) {
		return Status{License: lic, Valid: false, Reason: "license expired"}
	}
	return Status{License: lic, Valid: true}
}

// Community is the default status when no commercial license is configured.
func Community() Status {
	return Status{License: License{Edition: "community"}, Valid: false, Reason: "no commercial license configured"}
}

func decodePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errors.New("invalid base64 private key")
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	return ed25519.PrivateKey(raw), nil
}

func decodePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errors.New("invalid base64 public key")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key size")
	}
	return ed25519.PublicKey(raw), nil
}
