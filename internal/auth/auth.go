// Package auth implements the LastChance request signature contract.
//
// Canonical envelope (must match the Rust client):
//
//	METHOD \n PATH \n CANONICAL_QUERY \n TIMESTAMP \n NONCE \n SHA256(body)
//
// Nonces are base64url without padding and are accepted once per identity.
package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NablaShell/LastChance-server/internal/store"
)

const (
	// Authentication headers sent by the release client.
	HeaderIdentity    = "X-Auth-Identity"
	HeaderTimestamp   = "X-Auth-Timestamp"
	HeaderNonce       = "X-Auth-Nonce"
	HeaderSignature   = "X-Auth-Signature"
	HeaderIdentityKey = "X-Identity-Key"

	// TimestampWindowSecs is how far a request may lag behind the server.
	TimestampWindowSecs int64 = 60
	// TimestampSkewSecs is how far a request may lead the server.
	TimestampSkewSecs int64 = 30
	// NonceTTL keeps a nonce longer than the whole timestamp window so a nonce
	// cannot be reused after its store entry expires.
	NonceTTL = time.Duration(TimestampWindowSecs+TimestampSkewSecs+60) * time.Second
	// MinNonceBytes and MaxNonceBytes bound the decoded nonce length.
	MinNonceBytes = 16
	MaxNonceBytes = 32

	// AuthRejectedBody is returned for every auth failure.
	AuthRejectedBody = "unauthorized"
)

// Failure is the internal reason for a rejected request. Clients always see
// the same body; the reason is only written to the audit log.
type Failure int

const (
	MissingHeaders Failure = iota
	MalformedTimestamp
	InvalidIdentity
	MalformedNonce
	TimestampOutOfWindow
	InvalidSignature
	ReplayedNonce
	NonceCacheFull
)

func (f Failure) Error() string { return f.Reason() }

// Reason is the audit-log label. It never reaches the client.
func (f Failure) Reason() string {
	switch f {
	case MissingHeaders:
		return "missing_headers"
	case MalformedTimestamp:
		return "malformed_timestamp"
	case InvalidIdentity:
		return "invalid_identity"
	case MalformedNonce:
		return "malformed_nonce"
	case TimestampOutOfWindow:
		return "timestamp_out_of_window"
	case InvalidSignature:
		return "invalid_signature"
	case ReplayedNonce:
		return "replayed_nonce"
	case NonceCacheFull:
		return "nonce_cache_full"
	default:
		return "unknown"
	}
}

// Status maps a failure to HTTP. A full store is an availability failure (503),
// everything else is an authentication failure (401).
func (f Failure) Status() int {
	if f == NonceCacheFull {
		return http.StatusServiceUnavailable
	}
	return http.StatusUnauthorized
}

// Status returns the HTTP status for an authentication error.
func Status(err error) int {
	var failure Failure
	if errors.As(err, &failure) {
		return failure.Status()
	}
	return http.StatusUnauthorized
}

// Request is one request in the canonical form expected by the verifier.
type Request struct {
	Method    string
	Path      string
	Query     string
	Timestamp int64
	Nonce     string
	Signature string
	Body      []byte
	// BodyHash is an optional precomputed lowercase hex SHA256(Body). It lets
	// the file listener hash a large upload while streaming it to disk.
	BodyHash string
}

// BodyHash returns the lowercase hex SHA-256 of body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// IdentityHash returns hex(SHA256(public_key)), the identity used by the
// client and the server.
func IdentityHash(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// CanonicalRequest builds the signed envelope. It must stay byte-identical to
// canonical_request() in the Rust client.
func CanonicalRequest(method, path, query string, timestamp int64, nonce string, body []byte) []byte {
	return CanonicalRequestWithBodyHash(method, path, query, timestamp, nonce, BodyHash(body))
}

// CanonicalRequestWithBodyHash builds the signed envelope from an already
// computed body hash.
func CanonicalRequestWithBodyHash(method, path, query string, timestamp int64, nonce, bodyHashHex string) []byte {
	return []byte(strings.ToUpper(method) + "\n" +
		canonicalPath(path) + "\n" +
		canonicalQuery(query) + "\n" +
		strconv.FormatInt(timestamp, 10) + "\n" +
		nonce + "\n" +
		bodyHashHex)
}

// Verifier checks canonical request signatures and replay-protects nonces.
type Verifier struct {
	nonces   store.NonceStore
	nonceTTL time.Duration
	now      func() time.Time
}

// NewVerifier returns a verifier backed by the supplied nonce store.
func NewVerifier(nonces store.NonceStore) *Verifier {
	return NewVerifierWithClock(nonces, time.Now)
}

// NewVerifierWithClock is NewVerifier with an injectable clock for tests.
func NewVerifierWithClock(nonces store.NonceStore, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{nonces: nonces, nonceTTL: NonceTTL, now: now}
}

// Verify validates a request using the supplied server timestamp.
func (v *Verifier) Verify(verifyingKey ed25519.PublicKey, identityHash string, request Request, nowUnix int64) error {
	return v.verifyAt(verifyingKey, identityHash, request, nowUnix, v.now())
}

func (v *Verifier) verifyAt(verifyingKey ed25519.PublicKey, identityHash string, request Request, nowUnix int64, now time.Time) error {
	if err := v.check(verifyingKey, identityHash, request, nowUnix, now); err != nil {
		reason := err.Error()
		var failure Failure
		if errors.As(err, &failure) {
			reason = failure.Reason()
		}
		slog.Warn("auth reject",
			"identity", shortForLog(identityHash),
			"method", request.Method,
			"path", request.Path,
			"reason", reason,
		)
		return err
	}

	slog.Debug("auth accept",
		"identity", shortForLog(identityHash),
		"method", request.Method,
		"path", request.Path,
	)
	return nil
}

func (v *Verifier) check(verifyingKey ed25519.PublicKey, identityHash string, request Request, nowUnix int64, now time.Time) error {
	expectedHash := IdentityHash(verifyingKey)
	if !EqualFoldConstantTime(identityHash, expectedHash) {
		return InvalidIdentity
	}

	nonceBytes, err := decodeBase64URL(request.Nonce)
	if err != nil || len(nonceBytes) < MinNonceBytes || len(nonceBytes) > MaxNonceBytes {
		return MalformedNonce
	}

	earliest := nowUnix - TimestampWindowSecs
	latest := nowUnix + TimestampSkewSecs
	if request.Timestamp < earliest || request.Timestamp > latest {
		return TimestampOutOfWindow
	}

	signatureBytes, err := decodeBase64URL(request.Signature)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return InvalidSignature
	}

	bodyHashHex := request.BodyHash
	if bodyHashHex == "" {
		bodyHashHex = BodyHash(request.Body)
	}
	canonical := CanonicalRequestWithBodyHash(
		request.Method,
		request.Path,
		request.Query,
		request.Timestamp,
		request.Nonce,
		bodyHashHex,
	)
	if !ed25519.Verify(verifyingKey, canonical, signatureBytes) {
		return InvalidSignature
	}

	if v.nonces == nil {
		return NonceCacheFull
	}
	// Insert only after every check: junk nonces must not fill the store.
	if err := v.nonces.Consume(identityHash, request.Nonce, now.Add(v.nonceTTL)); err != nil {
		if errors.Is(err, store.ErrNonceReplayed) {
			return ReplayedNonce
		}
		return NonceCacheFull
	}
	return nil
}

// VerifyRequest authenticates the X-Auth-* headers of an HTTP request.
func (v *Verifier) VerifyRequest(r *http.Request, body []byte) error {
	return v.VerifyRequestWithBodyHash(r, BodyHash(body))
}

// VerifyRequestWithBodyHash is VerifyRequest for streamed bodies.
func (v *Verifier) VerifyRequestWithBodyHash(r *http.Request, bodyHashHex string) error {
	identityKeyHex := strings.TrimSpace(r.Header.Get(HeaderIdentityKey))
	identityHash := strings.TrimSpace(r.Header.Get(HeaderIdentity))
	timestampRaw := strings.TrimSpace(r.Header.Get(HeaderTimestamp))
	nonce := r.Header.Get(HeaderNonce)
	signature := r.Header.Get(HeaderSignature)

	if identityKeyHex == "" || identityHash == "" || timestampRaw == "" || nonce == "" || signature == "" {
		return MissingHeaders
	}

	publicKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return InvalidIdentity
	}

	timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		return MalformedTimestamp
	}

	request := Request{
		Method:    r.Method,
		Path:      r.URL.EscapedPath(),
		Query:     r.URL.RawQuery,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
		BodyHash:  bodyHashHex,
	}
	return v.Verify(ed25519.PublicKey(publicKey), identityHash, request, v.now().Unix())
}

// EqualFoldConstantTime compares two ASCII strings case-insensitively without
// an early exit.
func EqualFoldConstantTime(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := 0; i < len(left); i++ {
		diff |= foldASCII(left[i]) ^ foldASCII(right[i])
	}
	return diff == 0
}

func canonicalPath(path string) string {
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	return path
}

func canonicalQuery(query string) string {
	query = strings.TrimPrefix(query, "?")
	if query == "" {
		return ""
	}

	parts := strings.Split(query, "&")
	pairs := make([][2]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			value = ""
		}
		pairs = append(pairs, [2]string{key, value})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})

	var builder strings.Builder
	for i, pair := range pairs {
		if i > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(pair[0])
		builder.WriteByte('=')
		builder.WriteString(pair[1])
	}
	return builder.String()
}

func isBase64URLAlphabet(input string) bool {
	for i := 0; i < len(input); i++ {
		ch := input[i]
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

func decodeBase64URL(input string) ([]byte, error) {
	if !isBase64URLAlphabet(input) {
		return nil, errors.New("invalid base64url alphabet")
	}
	return base64.RawURLEncoding.Strict().DecodeString(input)
}

func foldASCII(ch byte) byte {
	if ch >= 'A' && ch <= 'Z' {
		return ch + ('a' - 'A')
	}
	return ch
}

func shortForLog(value string) string {
	const limit = 64
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
