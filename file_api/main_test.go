package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

const (
	testGuardName  = "X-Test-Guard"
	testGuardValue = "test-secret"
)

// newFileTestServer wires the production routes and isolates the stealth
// header and vault path for one test.
func newFileTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	oldName, oldValue := effectiveHeaderName, effectiveHeaderValue
	oldVaultPath := vaultPath

	effectiveHeaderName = testGuardName
	effectiveHeaderValue = testGuardValue
	vaultPath = t.TempDir()

	srv := NewServer()
	ts := httptest.NewServer(srv.routes())

	t.Cleanup(func() {
		ts.Close()
		effectiveHeaderName = oldName
		effectiveHeaderValue = oldValue
		vaultPath = oldVaultPath
	})

	return srv, ts
}

func newTestIdentity(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return privateKey, publicKey, hashEd25519Public(publicKey)
}

func randomTestNonce(t *testing.T) string {
	t.Helper()

	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// signedFileHeaders builds the canonical X-Auth-* headers used by the release
// client. path/query/body must match the actual request.
func signedFileHeaders(t *testing.T, privateKey ed25519.PrivateKey, method, path, query string, body []byte) map[string]string {
	t.Helper()

	publicKey := privateKey.Public().(ed25519.PublicKey)
	timestamp := time.Now().Unix()
	nonce := randomTestNonce(t)
	signature := ed25519.Sign(privateKey, canonicalRequest(method, path, query, timestamp, nonce, body))

	return map[string]string{
		HeaderIdentityKey: hex.EncodeToString(publicKey),
		HeaderIdentity:    hashEd25519Public(publicKey),
		HeaderTimestamp:   strconv.FormatInt(timestamp, 10),
		HeaderNonce:       nonce,
		HeaderSignature:   base64.RawURLEncoding.EncodeToString(signature),
	}
}

func fileRequest(t *testing.T, method, url string, body []byte, headers map[string]string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(testGuardName, testGuardValue)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func uploadPayload(t *testing.T, ts *httptest.Server, privateKey ed25519.PrivateKey, payload []byte) string {
	t.Helper()

	resp := fileRequest(t, http.MethodPost, ts.URL+"/upload", payload,
		signedFileHeaders(t, privateKey, http.MethodPost, "/upload", "", payload))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload status = %d, want 200 (%s)", resp.StatusCode, body)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read upload response: %v", err)
	}
	return string(raw)
}

func TestPrefixedRoutesUseUnprefixedSignature(t *testing.T) {
	_, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0x99}, 512)
	fileHash := generateFileHash(payload)

	upload := fileRequest(t, http.MethodPost, ts.URL+"/file-api/upload", payload,
		signedFileHeaders(t, privateKey, http.MethodPost, "/upload", "", payload))
	upload.Body.Close()
	if upload.StatusCode != http.StatusOK {
		t.Fatalf("prefixed upload status = %d, want 200", upload.StatusCode)
	}

	downloadPath := "/download/" + fileHash
	download := fileRequest(t, http.MethodGet, ts.URL+"/file-api"+downloadPath, nil,
		signedFileHeaders(t, privateKey, http.MethodGet, downloadPath, "", nil))
	defer download.Body.Close()
	if download.StatusCode != http.StatusOK {
		t.Fatalf("prefixed download status = %d, want 200", download.StatusCode)
	}
}

func TestFileAuthUploadDownloadRoundTrip(t *testing.T) {
	_, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0x5A}, 2048)
	wantHash := generateFileHash(payload)

	if got := uploadPayload(t, ts, privateKey, payload); got != wantHash {
		t.Fatalf("upload hash = %q, want %q", got, wantHash)
	}

	downloadPath := "/download/" + wantHash
	resp := fileRequest(t, http.MethodGet, ts.URL+downloadPath, nil,
		signedFileHeaders(t, privateKey, http.MethodGet, downloadPath, "", nil))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("download status = %d, want 200 (%s)", resp.StatusCode, body)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded payload does not match the uploaded one")
	}

	// The one-time policy still applies: a second authenticated download
	// finds nothing.
	again := fileRequest(t, http.MethodGet, ts.URL+downloadPath, nil,
		signedFileHeaders(t, privateKey, http.MethodGet, downloadPath, "", nil))
	defer again.Body.Close()
	if again.StatusCode != http.StatusNotFound {
		t.Fatalf("second download status = %d, want 404", again.StatusCode)
	}
}

func TestUploadRequiresCanonicalSignature(t *testing.T) {
	srv, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0x11}, 1024)
	fileHash := generateFileHash(payload)

	unsigned := fileRequest(t, http.MethodPost, ts.URL+"/upload", payload, nil)
	unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned upload status = %d, want 401", unsigned.StatusCode)
	}
	if _, exists := srv.store.Peek(fileHash); exists {
		t.Fatal("unsigned upload was stored")
	}

	headers := signedFileHeaders(t, privateKey, http.MethodPost, "/upload", "", payload)
	signed := fileRequest(t, http.MethodPost, ts.URL+"/upload", payload, headers)
	signed.Body.Close()
	if signed.StatusCode != http.StatusOK {
		t.Fatalf("signed upload status = %d, want 200", signed.StatusCode)
	}

	replay := fileRequest(t, http.MethodPost, ts.URL+"/upload", payload, headers)
	replay.Body.Close()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed upload status = %d, want 401", replay.StatusCode)
	}
}

func TestUploadRejectsTamperedBody(t *testing.T) {
	srv, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	signedPayload := bytes.Repeat([]byte{0x22}, 1024)
	sentPayload := bytes.Repeat([]byte{0x23}, 1024)

	headers := signedFileHeaders(t, privateKey, http.MethodPost, "/upload", "", signedPayload)
	resp := fileRequest(t, http.MethodPost, ts.URL+"/upload", sentPayload, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered upload status = %d, want 401", resp.StatusCode)
	}
	if _, exists := srv.store.Peek(generateFileHash(sentPayload)); exists {
		t.Fatal("tampered upload was stored")
	}
	temps, err := filepath.Glob(filepath.Join(vaultPath, "upload-*.tmp"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(temps) != 0 {
		t.Fatalf("rejected upload left %d temp file(s): %v", len(temps), temps)
	}
}

func TestLargeUploadUsesDiskWithoutBuffering(t *testing.T) {
	srv, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0xAB}, RAMLimit+4096)
	wantHash := generateFileHash(payload)

	if got := uploadPayload(t, ts, privateKey, payload); got != wantHash {
		t.Fatalf("upload hash = %q, want %q", got, wantHash)
	}

	entry, exists := srv.store.Peek(wantHash)
	if !exists {
		t.Fatal("large upload was not registered")
	}
	if !entry.IsDisk {
		t.Fatal("large upload was stored in RAM")
	}
	if entry.Size != int64(len(payload)) {
		t.Fatalf("stored size = %d, want %d", entry.Size, len(payload))
	}
	temps, err := filepath.Glob(filepath.Join(vaultPath, "upload-*.tmp"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(temps) != 0 {
		t.Fatalf("successful upload left %d temp file(s): %v", len(temps), temps)
	}
}

func TestDownloadRequiresSignatureBeforeConsuming(t *testing.T) {
	srv, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0x66}, 512)
	fileHash := uploadPayload(t, ts, privateKey, payload)
	downloadPath := "/download/" + fileHash

	unsigned := fileRequest(t, http.MethodGet, ts.URL+downloadPath, nil, nil)
	unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned download status = %d, want 401", unsigned.StatusCode)
	}
	if _, exists := srv.store.Peek(fileHash); !exists {
		t.Fatal("unsigned download consumed the file")
	}

	signed := fileRequest(t, http.MethodGet, ts.URL+downloadPath, nil,
		signedFileHeaders(t, privateKey, http.MethodGet, downloadPath, "", nil))
	defer signed.Body.Close()
	if signed.StatusCode != http.StatusOK {
		t.Fatalf("signed download status = %d, want 200", signed.StatusCode)
	}
}

func TestDownloadRejectsTamperedPath(t *testing.T) {
	_, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0x77}, 512)
	fileHash := uploadPayload(t, ts, privateKey, payload)

	otherHash := generateFileHash([]byte("other"))
	headers := signedFileHeaders(t, privateKey, http.MethodGet, "/download/"+otherHash, "", nil)
	resp := fileRequest(t, http.MethodGet, ts.URL+"/download/"+fileHash, nil, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered path status = %d, want 401", resp.StatusCode)
	}
}

func TestInfoRequiresCanonicalSignature(t *testing.T) {
	_, ts := newFileTestServer(t)
	privateKey, _, _ := newTestIdentity(t)
	payload := bytes.Repeat([]byte{0x88}, 256)
	fileHash := uploadPayload(t, ts, privateKey, payload)
	infoPath := "/info/" + fileHash

	unsigned := fileRequest(t, http.MethodGet, ts.URL+infoPath, nil, nil)
	unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned info status = %d, want 401", unsigned.StatusCode)
	}

	signed := fileRequest(t, http.MethodGet, ts.URL+infoPath, nil,
		signedFileHeaders(t, privateKey, http.MethodGet, infoPath, "", nil))
	defer signed.Body.Close()
	if signed.StatusCode != http.StatusOK {
		t.Fatalf("signed info status = %d, want 200", signed.StatusCode)
	}
	if got := signed.Header.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(payload))
	}
}

// TestCanonicalVectorsMatchSharedFixture keeps the file service in sync with
// the same language-independent vectors used by the text node.
func TestCanonicalVectorsMatchSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../testdata/auth_vectors.json")
	if err != nil {
		t.Fatalf("read auth vectors: %v", err)
	}

	var vectors struct {
		Canonical []struct {
			Name      string `json:"name"`
			Method    string `json:"method"`
			Path      string `json:"path"`
			Query     string `json:"query"`
			Timestamp int64  `json:"timestamp"`
			Nonce     string `json:"nonce"`
			Body      string `json:"body"`
			Canonical string `json:"canonical"`
		} `json:"canonical"`
		Signature struct {
			Seed      string `json:"seed"`
			PublicKey string `json:"public_key"`
			Identity  string `json:"identity"`
			Method    string `json:"method"`
			Path      string `json:"path"`
			Query     string `json:"query"`
			Timestamp int64  `json:"timestamp"`
			Nonce     string `json:"nonce"`
			Body      string `json:"body"`
			Canonical string `json:"canonical"`
			Signature string `json:"signature"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse auth vectors: %v", err)
	}

	for _, vector := range vectors.Canonical {
		got := string(canonicalRequest(
			vector.Method, vector.Path, vector.Query,
			vector.Timestamp, vector.Nonce, []byte(vector.Body),
		))
		if got != vector.Canonical {
			t.Fatalf("%s: canonical envelope = %q, want %q", vector.Name, got, vector.Canonical)
		}
	}

	vector := vectors.Signature
	seed, err := hex.DecodeString(vector.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("invalid vector seed: %v", err)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if got := hashEd25519Public(publicKey); got != vector.Identity {
		t.Fatalf("identity = %s, want %s", got, vector.Identity)
	}

	verifier := NewAuthVerifier()
	request := AuthRequest{
		Method:    vector.Method,
		Path:      vector.Path,
		Query:     vector.Query,
		Timestamp: vector.Timestamp,
		Nonce:     vector.Nonce,
		Signature: vector.Signature,
		Body:      []byte(vector.Body),
	}
	if err := verifier.VerifyAt(publicKey, vector.Identity, request, vector.Timestamp, time.Now()); err != nil {
		t.Fatalf("verifier rejected a valid vector: %v", err)
	}
}

func TestClientIPIgnoresForwardingHeadersFromDirectClients(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		header string
		want   string
	}{
		{
			name:   "public peer with spoofed X-Real-IP",
			remote: "203.0.113.7:5555",
			header: "1.2.3.4",
			want:   "203.0.113.7",
		},
		{
			name:   "private proxy supplies X-Real-IP",
			remote: "172.18.0.5:40000",
			header: "198.51.100.9",
			want:   "198.51.100.9",
		},
		{
			name:   "trusted proxy with malformed header falls back to peer",
			remote: "172.18.0.5:40000",
			header: "not-an-ip",
			want:   "172.18.0.5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ping", nil)
			req.RemoteAddr = tc.remote
			if tc.header != "" {
				req.Header.Set("X-Real-IP", tc.header)
				req.Header.Set("X-Forwarded-For", tc.header+", 10.0.0.1")
			}
			if got := getClientIP(req); got != tc.want {
				t.Fatalf("getClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTrustedProxyCIDRNarrowsTrust keeps the file relay consistent with the
// text node: an explicit allow-list must replace the broad private default.
func TestTrustedProxyCIDRNarrowsTrust(t *testing.T) {
	old := trustedProxyNets
	t.Cleanup(func() { trustedProxyNets = old })

	nets, err := loadTrustedProxies("172.18.0.0/16, 2001:db8::/32")
	if err != nil {
		t.Fatalf("loadTrustedProxies: %v", err)
	}
	trustedProxyNets = nets

	cases := []struct {
		name   string
		remote string
		header string
		want   string
	}{
		{"allow-listed IPv4 proxy", "172.18.0.5:40000", "198.51.100.9", "198.51.100.9"},
		{"allow-listed IPv6 proxy", "[2001:db8::5]:40000", "198.51.100.9", "198.51.100.9"},
		{"other private peer is not a proxy", "10.1.2.3:40000", "198.51.100.9", "10.1.2.3"},
		{"public peer is not a proxy", "203.0.113.7:40000", "198.51.100.9", "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ping", nil)
			req.RemoteAddr = tc.remote
			req.Header.Set("X-Real-IP", tc.header)
			if got := getClientIP(req); got != tc.want {
				t.Fatalf("getClientIP = %q, want %q", got, tc.want)
			}
		})
	}

	host, err := loadTrustedProxies("172.18.0.2")
	if err != nil {
		t.Fatalf("loadTrustedProxies(bare IP): %v", err)
	}
	if len(host) != 1 || !host[0].Contains(net.ParseIP("172.18.0.2")) {
		t.Fatalf("bare IP did not produce a single-host network: %v", host)
	}
	if _, err := loadTrustedProxies("not-a-cidr"); err == nil {
		t.Fatal("invalid TRUSTED_PROXY_CIDR was accepted")
	}
}

// TestRateLimiterCleanupKeepsActiveBuckets guards the old bug where Cleanup
// replaced the whole map and handed every client a fresh burst.
func TestRateLimiterCleanupKeepsActiveBuckets(t *testing.T) {
	rl := NewRateLimiter()
	for i := 0; i < rateLimitBurst; i++ {
		if !rl.Allow("198.51.100.1") {
			t.Fatalf("request %d unexpectedly limited", i)
		}
	}
	if rl.Allow("198.51.100.1") {
		t.Fatal("burst was not exhausted")
	}

	rl.Cleanup()
	if rl.Allow("198.51.100.1") {
		t.Fatal("cleanup reset an active bucket")
	}

	rl.limiters["198.51.100.2"] = &rateEntry{
		limiter:  rate.NewLimiter(rateLimitRPS, rateLimitBurst),
		lastSeen: time.Now().Add(-2 * rateLimitIdleTTL),
	}
	rl.Cleanup()
	if _, exists := rl.limiters["198.51.100.2"]; exists {
		t.Fatal("idle bucket was not removed")
	}
}
