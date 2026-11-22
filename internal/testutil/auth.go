// Package testutil contains helpers shared by tests. It is not imported by the
// production server.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/NablaShell/LastChance-server/internal/auth"
)

// Identity is a generated Ed25519 key with its wire representations.
type Identity struct {
	Private   ed25519.PrivateKey
	PublicHex string
	Hash      string
}

// NewIdentity generates a fresh identity.
func NewIdentity(t testing.TB) Identity {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return Identity{
		Private:   private,
		PublicHex: hex.EncodeToString(public),
		Hash:      auth.IdentityHash(public),
	}
}

// RandomNonce returns a fresh 24-byte base64url nonce.
func RandomNonce(t testing.TB) string {
	t.Helper()
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// Headers builds X-Auth-* headers with the current timestamp and a fresh nonce.
func (id Identity) Headers(t testing.TB, method, path, query string, body []byte) map[string]string {
	t.Helper()
	return id.HeadersAt(t, method, path, query, time.Now().Unix(), RandomNonce(t), body)
}

// HeadersAt builds X-Auth-* headers with explicit timestamp and nonce.
func (id Identity) HeadersAt(t testing.TB, method, path, query string, timestamp int64, nonce string, body []byte) map[string]string {
	t.Helper()
	signature := ed25519.Sign(id.Private, auth.CanonicalRequest(method, path, query, timestamp, nonce, body))
	return map[string]string{
		auth.HeaderIdentityKey: id.PublicHex,
		auth.HeaderIdentity:    id.Hash,
		auth.HeaderTimestamp:   strconv.FormatInt(timestamp, 10),
		auth.HeaderNonce:       nonce,
		auth.HeaderSignature:   base64.RawURLEncoding.EncodeToString(signature),
	}
}
