// Authentication for the LastChance network API (H-4).
//
// This file mirrors src/network/auth.rs from the 1.0 client release and the
// node/auth.go verifier. Keep the canonical envelope, header names and nonce
// rules in sync with the Rust code and with the text relay.
//
//	METHOD \n PATH \n CANONICAL_QUERY \n TIMESTAMP \n NONCE \n SHA256(body)
//
// The signature is base64url (no padding) over that envelope. A nonce is a
// fresh base64url value of 16..=32 decoded bytes and is accepted only once.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	// NonceTTL keeps a nonce longer than the whole timestamp window so a
	// nonce cannot be reused after its cache entry expires.
	NonceTTL = time.Duration(TimestampWindowSecs+TimestampSkewSecs+60) * time.Second
	// MaxNoncesPerIdentity bounds the replay cache per identity.
	MaxNoncesPerIdentity = 1024
	// MinNonceBytes/MaxNonceBytes bound the decoded nonce length.
	MinNonceBytes = 16
	MaxNonceBytes = 32

	// AuthRejectedBody is returned for every auth failure.
	AuthRejectedBody = "unauthorized"
)

var (
	errNonceReplayed  = errors.New("replayed nonce")
	errNonceCacheFull = errors.New("nonce cache full")
)

// AuthFailure is the internal reason for a rejected request. The client always
// receives the same body; the reason is written to the audit log.
type AuthFailure int

const (
	AuthMissingHeaders AuthFailure = iota
	AuthMalformedTimestamp
	AuthInvalidIdentity
	AuthMalformedNonce
	AuthTimestampOutOfWindow
	AuthInvalidSignature
	AuthReplayedNonce
	AuthNonceCacheFull
)

func (f AuthFailure) Error() string {
	return f.Reason()
}

// Reason is the audit-log label. It never reaches the client.
func (f AuthFailure) Reason() string {
	switch f {
	case AuthMissingHeaders:
		return "missing_headers"
	case AuthMalformedTimestamp:
		return "malformed_timestamp"
	case AuthInvalidIdentity:
		return "invalid_identity"
	case AuthMalformedNonce:
		return "malformed_nonce"
	case AuthTimestampOutOfWindow:
		return "timestamp_out_of_window"
	case AuthInvalidSignature:
		return "invalid_signature"
	case AuthReplayedNonce:
		return "replayed_nonce"
	case AuthNonceCacheFull:
		return "nonce_cache_full"
	default:
		return "unknown"
	}
}

// Status maps a failure to HTTP. A full cache is an availability failure (503),
// everything else is an authentication failure (401).
func (f AuthFailure) Status() int {
	if f == AuthNonceCacheFull {
		return http.StatusServiceUnavailable
	}
	return http.StatusUnauthorized
}

// AuthRequest is one request in the canonical form expected by the verifier.
type AuthRequest struct {
	Method    string
	Path      string
	Query     string
	Timestamp int64
	Nonce     string
	Signature string
	Body      []byte
	// BodyHash is an optional precomputed lowercase hex SHA256(Body). It lets
	// the file service hash a large upload while streaming it to disk without
	// buffering the whole body in memory. When empty, Body is hashed.
	BodyHash string
}

// bodyHash returns the lowercase hex SHA-256 of body.
func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// hashEd25519Public returns hex(SHA256(public_key)), the identity hash used by
// the client and the server.
func hashEd25519Public(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// canonicalPath normalizes the path exactly like the Rust client: remove any
// query part, add a leading slash and drop trailing slashes (except root).
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

// canonicalQuery sorts query pairs by key and then value. Percent-encoding is
// preserved byte-for-byte, as received from the client.
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

// canonicalRequestWithBodyHash builds the signed envelope from an already
// computed body hash. It must stay byte-identical to the Rust client.
func canonicalRequestWithBodyHash(method, path, query string, timestamp int64, nonce, bodyHashHex string) []byte {
	return []byte(strings.ToUpper(method) + "\n" +
		canonicalPath(path) + "\n" +
		canonicalQuery(query) + "\n" +
		strconv.FormatInt(timestamp, 10) + "\n" +
		nonce + "\n" +
		bodyHashHex)
}

// canonicalRequest builds the signed envelope. It must stay byte-identical to
// canonical_request() in src/network/auth.rs.
func canonicalRequest(method, path, query string, timestamp int64, nonce string, body []byte) []byte {
	return canonicalRequestWithBodyHash(method, path, query, timestamp, nonce, bodyHash(body))
}

// stripProxyPrefix removes the public Caddy path prefix before verification.
//
// Caddy forwards /api-v1/* without stripping it, while the client signs the
// API path (/push/<hash>, /pull/<hash>). A direct request to /push/<hash>
// verifies unchanged.
func stripProxyPrefix(path, prefix string) string {
	if prefix == "" {
		return path
	}
	if path == prefix {
		return "/"
	}
	if strings.HasPrefix(path, prefix) && len(path) > len(prefix) && path[len(prefix)] == '/' {
		return path[len(prefix):]
	}
	return path
}

// isBase64URLAlphabet enforces the exact alphabet used by base64url without
// padding. Go's decoder ignores CR/LF, so reject anything else first.
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

// decodeBase64URL decodes canonical base64url without padding.
func decodeBase64URL(input string) ([]byte, error) {
	if !isBase64URLAlphabet(input) {
		return nil, errors.New("invalid base64url alphabet")
	}
	return base64.RawURLEncoding.Strict().DecodeString(input)
}

// foldASCII lowercases only ASCII letters.
func foldASCII(ch byte) byte {
	if ch >= 'A' && ch <= 'Z' {
		return ch + ('a' - 'A')
	}
	return ch
}

// equalFoldConstantTime compares two ASCII strings case-insensitively without
// an early exit. Lengths are public and compared directly.
func equalFoldConstantTime(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := 0; i < len(left); i++ {
		diff |= foldASCII(left[i]) ^ foldASCII(right[i])
	}
	return diff == 0
}

type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

// nonceCache is a per-identity FIFO of accepted nonces with a TTL. It is safe
// for concurrent use.
type nonceCache struct {
	mu       sync.Mutex
	entries  map[string][]nonceEntry
	capacity int
	ttl      time.Duration
}

func newNonceCache(capacity int, ttl time.Duration) *nonceCache {
	return &nonceCache{
		entries:  make(map[string][]nonceEntry),
		capacity: capacity,
		ttl:      ttl,
	}
}

// insert records a nonce. Expired entries are pruned lazily; a full cache
// fails closed instead of evicting an unexpired nonce.
func (c *nonceCache) insert(identity, nonce string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := c.entries[identity]
	cut := 0
	for cut < len(entries) && !entries[cut].expiresAt.After(now) {
		cut++
	}
	if cut > 0 {
		entries = append([]nonceEntry(nil), entries[cut:]...)
	}

	// Replay is checked before capacity: an already-used nonce must never
	// turn into a 503 just because the cache happens to be full.
	for _, entry := range entries {
		if entry.nonce == nonce {
			c.entries[identity] = entries
			return errNonceReplayed
		}
	}
	if len(entries) >= c.capacity {
		c.entries[identity] = entries
		return errNonceCacheFull
	}

	entries = append(entries, nonceEntry{
		nonce:     nonce,
		expiresAt: now.Add(c.ttl),
	})
	c.entries[identity] = entries
	return nil
}

func (c *nonceCache) nonceCount(identity string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries[identity])
}

func (c *nonceCache) totalNonceCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, entries := range c.entries {
		total += len(entries)
	}
	return total
}

// purgeExpired drops all expired entries. Call it from the periodic cleanup.
func (c *nonceCache) purgeExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for identity, entries := range c.entries {
		cut := 0
		for cut < len(entries) && !entries[cut].expiresAt.After(now) {
			cut++
		}
		if cut >= len(entries) {
			delete(c.entries, identity)
			continue
		}
		if cut > 0 {
			c.entries[identity] = append([]nonceEntry(nil), entries[cut:]...)
		}
	}
}

// AuthVerifier checks canonical request signatures and replay-protects nonces.
type AuthVerifier struct {
	cache    *nonceCache
	rejected atomic.Uint64
}

func NewAuthVerifier() *AuthVerifier {
	return &AuthVerifier{
		cache: newNonceCache(MaxNoncesPerIdentity, NonceTTL),
	}
}

// Verify validates a request using the current server time.
func (v *AuthVerifier) Verify(verifyingKey ed25519.PublicKey, identityHash string, request AuthRequest, nowUnix int64) error {
	return v.VerifyAt(verifyingKey, identityHash, request, nowUnix, time.Now())
}

// VerifyAt is Verify with an explicit clock, for TTL tests.
func (v *AuthVerifier) VerifyAt(verifyingKey ed25519.PublicKey, identityHash string, request AuthRequest, nowUnix int64, now time.Time) error {
	if err := v.check(verifyingKey, identityHash, request, nowUnix, now); err != nil {
		v.rejected.Add(1)
		reason := err.Error()
		if failure, ok := err.(AuthFailure); ok {
			reason = failure.Reason()
		}
		// The signature, body and nonce never reach the log.
		log.Printf("[AUTH] reject identity=%s method=%s path=%s reason=%s",
			shortForLog(identityHash),
			request.Method,
			request.Path,
			reason,
		)
		return err
	}

	log.Printf("[AUTH] accept identity=%s method=%s path=%s",
		shortForLog(identityHash), request.Method, request.Path)
	return nil
}

func (v *AuthVerifier) check(verifyingKey ed25519.PublicKey, identityHash string, request AuthRequest, nowUnix int64, now time.Time) error {
	expectedHash := hashEd25519Public(verifyingKey)
	if !equalFoldConstantTime(identityHash, expectedHash) {
		return AuthInvalidIdentity
	}

	nonceBytes, err := decodeBase64URL(request.Nonce)
	if err != nil || len(nonceBytes) < MinNonceBytes || len(nonceBytes) > MaxNonceBytes {
		return AuthMalformedNonce
	}

	earliest := nowUnix - TimestampWindowSecs
	latest := nowUnix + TimestampSkewSecs
	if request.Timestamp < earliest || request.Timestamp > latest {
		return AuthTimestampOutOfWindow
	}

	signatureBytes, err := decodeBase64URL(request.Signature)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return AuthInvalidSignature
	}

	bodyHashHex := request.BodyHash
	if bodyHashHex == "" {
		bodyHashHex = bodyHash(request.Body)
	}
	canonical := canonicalRequestWithBodyHash(
		request.Method,
		request.Path,
		request.Query,
		request.Timestamp,
		request.Nonce,
		bodyHashHex,
	)
	if !ed25519.Verify(verifyingKey, canonical, signatureBytes) {
		return AuthInvalidSignature
	}

	// Insert only after every check: junk nonces must not fill the cache.
	if err := v.cache.insert(identityHash, request.Nonce, now); err != nil {
		if errors.Is(err, errNonceReplayed) {
			return AuthReplayedNonce
		}
		return AuthNonceCacheFull
	}
	return nil
}

// VerifyRequest authenticates the X-Auth-* headers of an HTTP request.
//
// proxyPrefix is the public Caddy prefix that is not part of the signed path
// (for example "/api-v1").
func (v *AuthVerifier) VerifyRequest(r *http.Request, body []byte, proxyPrefix string) error {
	return v.VerifyRequestWithBodyHash(r, bodyHash(body), proxyPrefix)
}

// VerifyRequestWithBodyHash is VerifyRequest for streamed bodies: the caller
// supplies hex(SHA256(body)) instead of keeping the body in memory.
func (v *AuthVerifier) VerifyRequestWithBodyHash(r *http.Request, bodyHashHex, proxyPrefix string) error {
	identityKeyHex := strings.TrimSpace(r.Header.Get(HeaderIdentityKey))
	identityHash := strings.TrimSpace(r.Header.Get(HeaderIdentity))
	timestampRaw := strings.TrimSpace(r.Header.Get(HeaderTimestamp))
	nonce := r.Header.Get(HeaderNonce)
	signature := r.Header.Get(HeaderSignature)

	if identityKeyHex == "" || identityHash == "" || timestampRaw == "" || nonce == "" || signature == "" {
		v.rejected.Add(1)
		log.Printf("[AUTH] reject method=%s path=%s reason=missing_headers",
			r.Method, r.URL.Path)
		return AuthMissingHeaders
	}

	publicKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		v.rejected.Add(1)
		log.Printf("[AUTH] reject method=%s path=%s reason=invalid_identity_key",
			r.Method, r.URL.Path)
		return AuthInvalidIdentity
	}

	timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		v.rejected.Add(1)
		log.Printf("[AUTH] reject method=%s path=%s reason=malformed_timestamp",
			r.Method, r.URL.Path)
		return AuthMalformedTimestamp
	}

	request := AuthRequest{
		Method:    r.Method,
		Path:      stripProxyPrefix(r.URL.EscapedPath(), proxyPrefix),
		Query:     r.URL.RawQuery,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
		BodyHash:  bodyHashHex,
	}
	return v.Verify(ed25519.PublicKey(publicKey), identityHash, request, time.Now().Unix())
}

func (v *AuthVerifier) NonceCount(identityHash string) int {
	return v.cache.nonceCount(identityHash)
}

func (v *AuthVerifier) TotalNonceCount() int {
	return v.cache.totalNonceCount()
}

func (v *AuthVerifier) RejectionCount() uint64 {
	return v.rejected.Load()
}

func (v *AuthVerifier) PurgeExpired() {
	v.cache.purgeExpired(time.Now())
}

// writeAuthError returns the uniform auth rejection body.
func writeAuthError(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	if failure, ok := err.(AuthFailure); ok {
		status = failure.Status()
	}
	http.Error(w, AuthRejectedBody, status)
}

func shortForLog(value string) string {
	const limit = 64
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
