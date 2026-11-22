package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

const (
	testGuardName  = "X-Test-Guard"
	testGuardValue = "test-secret"
)

// newTestServer starts an httptest server wired to the production routes.
func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	oldName, oldValue := effectiveHeaderName, effectiveHeaderValue
	effectiveHeaderName = testGuardName
	effectiveHeaderValue = testGuardValue

	db, err := NewDB()
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	srv := &Server{
		db:          db,
		rateLimiter: NewRateLimiter(),
		notifier:    NewNotifyRegistry(),
		auth:        NewAuthVerifier(),
	}

	ts := httptest.NewServer(srv.routes())
	t.Cleanup(func() {
		ts.Close()
		db.Close()
		effectiveHeaderName = oldName
		effectiveHeaderValue = oldValue
	})

	return srv, ts
}

// newIdentity creates an Ed25519 identity and returns its private key, the
// hex-encoded public key, and the identity hash derived from the public key.
func newIdentity(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return priv, hex.EncodeToString(pub), hashEd25519Public(pub)
}

// randomNonce returns a fresh base64url nonce with 24 bytes of entropy, like
// generate_nonce() in the release client.
func randomNonce(t *testing.T) string {
	t.Helper()

	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// signedHeaders builds the canonical X-Auth-* headers accepted by
// AuthVerifier. path/query/body must match what the HTTP request carries.
func signedHeaders(t *testing.T, priv ed25519.PrivateKey, method, path, query string, body []byte) map[string]string {
	t.Helper()

	pub := priv.Public().(ed25519.PublicKey)
	timestamp := time.Now().Unix()
	nonce := randomNonce(t)
	signature := ed25519.Sign(priv, canonicalRequest(method, path, query, timestamp, nonce, body))

	return map[string]string{
		HeaderIdentityKey: hex.EncodeToString(pub),
		HeaderIdentity:    hashEd25519Public(pub),
		HeaderTimestamp:   strconv.FormatInt(timestamp, 10),
		HeaderNonce:       nonce,
		HeaderSignature:   base64.RawURLEncoding.EncodeToString(signature),
	}
}

func applyHeaders(req *http.Request, headers map[string]string) {
	// Every request that reaches a relay handler through Caddy carries the
	// stealth header; the handlers now re-check it.
	req.Header.Set(testGuardName, testGuardValue)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// readMultipartPayloads extracts the raw payload of every part in a multipart
// response body, mirroring what the Rust client does.
func readMultipartPayloads(t *testing.T, resp *http.Response) [][]byte {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	payloads, err := parseMultipartPayloads(resp.Header.Get("Content-Type"), body)
	if err != nil {
		t.Fatalf("parse multipart: %v", err)
	}
	return payloads
}

// parseMultipartPayloads parses a multipart body without touching testing.T,
// so it is safe to call from helper goroutines.
func parseMultipartPayloads(contentType string, body []byte) ([][]byte, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("parse content type: %w", err)
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, errors.New("missing multipart boundary")
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var payloads [][]byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("next part: %w", err)
		}

		data, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("read part: %w", err)
		}
		payloads = append(payloads, data)
	}

	return payloads, nil
}

// fetchPull performs an authenticated long-poll GET and returns the response.
func fetchPull(t *testing.T, ts *httptest.Server, targetHash string, waitSeconds int, headers map[string]string) *http.Response {
	t.Helper()

	url := ts.URL + "/pull/" + targetHash + "?wait=" + strconv.Itoa(waitSeconds)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new pull request: %v", err)
	}
	applyHeaders(req, headers)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull request: %v", err)
	}
	return resp
}

// waitForWaiters blocks until at least one long-poll waiter is registered for
// the hash, so the test cannot race the push ahead of the pull.
func waitForWaiters(t *testing.T, srv *Server, targetHash string, want int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if srv.notifier.Waiters(targetHash) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d waiter(s) on %s", want, shortHash(targetHash))
}

// waitForNoWaiters blocks until the registry has no waiters for the hash.
func waitForNoWaiters(t *testing.T, srv *Server, targetHash string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if srv.notifier.Waiters(targetHash) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%d waiter(s) still registered for %s", srv.notifier.Waiters(targetHash), shortHash(targetHash))
}

func TestLongPollWakesUpOnPush(t *testing.T) {
	srv, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)

	// Payloads must match the fixed packet-size grid (256, 1024, 4096, 65536).
	payload := bytes.Repeat([]byte{0xA5}, SizeVeryTiny)

	pullPath := "/pull/" + targetHash
	pullQuery := "wait=5"
	pullHeaders := signedHeaders(t, priv, http.MethodGet, pullPath, pullQuery, nil)

	type pullResult struct {
		status      int
		contentType string
		body        []byte
		err         error
	}

	pullDone := make(chan pullResult, 1)

	// Start the long-polling pull in the background: it must block because
	// the bucket is still empty.
	pullStart := time.Now()
	go func() {
		url := ts.URL + pullPath + "?" + pullQuery
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			pullDone <- pullResult{err: err}
			return
		}
		applyHeaders(req, pullHeaders)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			pullDone <- pullResult{err: err}
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		pullDone <- pullResult{
			status:      resp.StatusCode,
			contentType: resp.Header.Get("Content-Type"),
			body:        body,
			err:         err,
		}
	}()

	// Make sure the pull is actually waiting before pushing.
	waitForWaiters(t, srv, targetHash, 1, 2*time.Second)

	pushStart := time.Now()
	pushPath := "/push/" + targetHash
	pushReq, err := http.NewRequest(http.MethodPost, ts.URL+pushPath, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new push request: %v", err)
	}
	applyHeaders(pushReq, signedHeaders(t, priv, http.MethodPost, pushPath, "", payload))
	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil {
		t.Fatalf("push request: %v", err)
	}
	defer pushResp.Body.Close()
	if pushResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(pushResp.Body)
		t.Fatalf("push status = %d, want 200 (%s)", pushResp.StatusCode, body)
	}

	select {
	case result := <-pullDone:
		if result.err != nil {
			t.Fatalf("pull failed: %v", result.err)
		}
		if result.status != http.StatusOK {
			t.Fatalf("pull status = %d, want 200", result.status)
		}

		payloads, err := parseMultipartPayloads(result.contentType, result.body)
		if err != nil {
			t.Fatalf("parse pull response: %v", err)
		}
		if len(payloads) != 1 {
			t.Fatalf("got %d packages, want 1", len(payloads))
		}
		if !bytes.Equal(payloads[0], payload) {
			t.Fatalf("delivered payload does not match the pushed one")
		}

		// The response must arrive right after the push, not after the
		// 5-second wait expires.
		if elapsed := time.Since(pushStart); elapsed > 2*time.Second {
			t.Fatalf("long-poll answered after %v, want an immediate wake-up", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll did not wake up after push")
	}

	if elapsed := time.Since(pullStart); elapsed >= 5*time.Second {
		t.Fatalf("pull waited %v, want less than the 5s timeout", elapsed)
	}

	// The registry entry must be released once the request finishes.
	waitForNoWaiters(t, srv, targetHash, 2*time.Second)
}

func TestPullWithExistingDataReturnsImmediately(t *testing.T) {
	srv, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	headers := signedHeaders(t, priv, http.MethodGet, "/pull/"+targetHash, "wait=5", nil)

	payload := bytes.Repeat([]byte{0x5A}, SizeTiny)
	if err := srv.db.SavePackage(targetHash, payload, len(payload)); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	start := time.Now()
	resp := fetchPull(t, ts, targetHash, 5, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	payloads := readMultipartPayloads(t, resp)
	if len(payloads) != 1 || !bytes.Equal(payloads[0], payload) {
		t.Fatalf("unexpected payloads: %d", len(payloads))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pull with data took %v, want immediate response", elapsed)
	}
}

func TestPullWithoutWaitReturns204(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	headers := signedHeaders(t, priv, http.MethodGet, "/pull/"+targetHash, "wait=0", nil)

	start := time.Now()
	resp := fetchPull(t, ts, targetHash, 0, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("legacy pull took %v, want an immediate 204", elapsed)
	}
}

func TestPullWaitTimeoutReturns204(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	headers := signedHeaders(t, priv, http.MethodGet, "/pull/"+targetHash, "wait=1", nil)

	start := time.Now()
	resp := fetchPull(t, ts, targetHash, 1, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("pull returned after %v, want it to wait ~1s", elapsed)
	}
}

func TestParseLongPollWait(t *testing.T) {
	tests := []struct {
		query string
		want  time.Duration
	}{
		{"", 0},
		{"?wait=", 0},
		{"?wait=0", 0},
		{"?wait=-3", 0},
		{"?wait=abc", 0},
		{"?wait=1", time.Second},
		{"?wait=25", 25 * time.Second},
		{"?wait=30", MaxLongPollWait},
		{"?wait=999", MaxLongPollWait},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/pull/deadbeef"+tt.query, nil)
		if got := parseLongPollWait(req); got != tt.want {
			t.Errorf("parseLongPollWait(%q) = %v, want %v", tt.query, got, tt.want)
		}
	}
}

func TestServerWriteTimeoutExceedsMaxWait(t *testing.T) {
	if ServerWriteTimeout <= MaxLongPollWait {
		t.Fatalf("ServerWriteTimeout (%v) must exceed MaxLongPollWait (%v)",
			ServerWriteTimeout, MaxLongPollWait,
		)
	}
}

func TestNotifyRegistryReleasesIdleBuckets(t *testing.T) {
	reg := NewNotifyRegistry()

	ch1, cancel1 := reg.Subscribe("hash")
	ch2, cancel2 := reg.Subscribe("hash")
	if n := reg.Waiters("hash"); n != 2 {
		t.Fatalf("Waiters = %d, want 2", n)
	}
	if ch1 != ch2 {
		t.Fatal("waiters for the same hash must share one notification channel")
	}

	// A single non-blocking signal is enough: the woken waiter re-checks the
	// bucket, and extra signals are dropped rather than queued.
	reg.Notify("hash")
	select {
	case <-ch1:
	default:
		t.Fatal("waiter was not notified")
	}
	select {
	case <-ch1:
		t.Fatal("more than one signal was queued for the same push")
	default:
	}

	cancel1()
	if n := reg.Waiters("hash"); n != 1 {
		t.Fatalf("Waiters = %d after one cancel, want 1", n)
	}
	cancel2()
	if n := reg.Waiters("hash"); n != 0 {
		t.Fatalf("Waiters = %d after all cancels, want 0", n)
	}

	reg.mu.Lock()
	_, exists := reg.buckets["hash"]
	reg.mu.Unlock()
	if exists {
		t.Fatal("idle bucket was not removed from the registry")
	}

	// Notify for an unknown hash must be a no-op and must not panic.
	reg.Notify("unknown")
}

func TestCanonicalRequestMatchesRustClient(t *testing.T) {
	const timestamp int64 = 1_700_000_000

	got := string(canonicalRequest("get", "/pull/abc/", "b=2&a=1", timestamp, "nonce", nil))
	want := "GET\n/pull/abc\na=1&b=2\n1700000000\nnonce\n" + bodyHash(nil)
	if got != want {
		t.Fatalf("canonical envelope = %q, want %q", got, want)
	}

	// Query encoding is preserved and sorted by key, then value.
	encoded := string(canonicalRequest("GET", "/pull/x", "b=%2F&a=%20", timestamp, "n", nil))
	if !bytes.Contains([]byte(encoded), []byte("\na=%20&b=%2F\n")) {
		t.Fatalf("query encoding was not preserved: %q", encoded)
	}
}

func TestPushRequiresCanonicalSignature(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	payload := bytes.Repeat([]byte{0x33}, SizeVeryTiny)
	pushURL := ts.URL + "/push/" + targetHash

	unsigned, err := http.NewRequest(http.MethodPost, pushURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new unsigned push: %v", err)
	}
	applyHeaders(unsigned, nil)
	unsignedResp, err := http.DefaultClient.Do(unsigned)
	if err != nil {
		t.Fatalf("unsigned push: %v", err)
	}
	unsignedResp.Body.Close()
	if unsignedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned push status = %d, want 401", unsignedResp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodPost, pushURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new signed push: %v", err)
	}
	applyHeaders(req, signedHeaders(t, priv, http.MethodPost, "/push/"+targetHash, "", payload))
	signed, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("signed push: %v", err)
	}
	defer signed.Body.Close()
	if signed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(signed.Body)
		t.Fatalf("signed push status = %d, want 200 (%s)", signed.StatusCode, body)
	}
}

func TestPushAcceptsInBucketPadding(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	pushURL := ts.URL + "/push/" + targetHash

	push := func(size int) int {
		payload := bytes.Repeat([]byte{0x5A}, size)
		req, err := http.NewRequest(http.MethodPost, pushURL, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("new push (%d bytes): %v", size, err)
		}
		applyHeaders(req, signedHeaders(t, priv, http.MethodPost, "/push/"+targetHash, "", payload))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push (%d bytes): %v", size, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The client sends bucket + rand(0..=bucket/8); the production log showed
	// "invalid size 283", which is a 256 bucket plus 27 padding bytes.
	accepted := []int{SizeVeryTiny, SizeVeryTiny + SizeVeryTiny/8, SizeTiny + 37, MaxPacketSize}
	for _, size := range accepted {
		if status := push(size); status != http.StatusOK {
			t.Fatalf("padded push of %d bytes status = %d, want 200", size, status)
		}
	}

	// One byte outside the grid on either side must still be rejected.
	rejected := []int{SizeVeryTiny - 1, SizeVeryTiny + SizeVeryTiny/8 + 1, SizeTiny - 1, MaxPacketSize + 1}
	for _, size := range rejected {
		if status := push(size); status != http.StatusBadRequest {
			t.Fatalf("out-of-grid push of %d bytes status = %d, want 400", size, status)
		}
	}
}

func TestPushRejectsReplayedNonce(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	payload := bytes.Repeat([]byte{0x44}, SizeVeryTiny)
	pushURL := ts.URL + "/push/" + targetHash
	headers := signedHeaders(t, priv, http.MethodPost, "/push/"+targetHash, "", payload)

	send := func() int {
		req, err := http.NewRequest(http.MethodPost, pushURL, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("new push: %v", err)
		}
		applyHeaders(req, headers)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if status := send(); status != http.StatusOK {
		t.Fatalf("first push status = %d, want 200", status)
	}
	if status := send(); status != http.StatusUnauthorized {
		t.Fatalf("replayed push status = %d, want 401", status)
	}
}

func TestPullRejectsTamperedQuery(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	path := "/pull/" + targetHash
	headers := signedHeaders(t, priv, http.MethodGet, path, "wait=25", nil)

	resp := fetchPull(t, ts, targetHash, 10, headers)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered query status = %d, want 401", resp.StatusCode)
	}
}

func TestPullRejectsReplayedNonce(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	headers := signedHeaders(t, priv, http.MethodGet, "/pull/"+targetHash, "wait=0", nil)

	first := fetchPull(t, ts, targetHash, 0, headers)
	first.Body.Close()
	if first.StatusCode != http.StatusNoContent {
		t.Fatalf("first pull status = %d, want 204", first.StatusCode)
	}

	second := fetchPull(t, ts, targetHash, 0, headers)
	second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed pull status = %d, want 401", second.StatusCode)
	}
}

func TestPullRejectsIdentityThatDoesNotOwnBucket(t *testing.T) {
	_, ts := newTestServer(t)
	sender, _, _ := newIdentity(t)
	_, _, otherTarget := newIdentity(t)

	// The signature itself is valid, but the signed identity is not the
	// recipient bucket from the URL.
	headers := signedHeaders(t, sender, http.MethodGet, "/pull/"+otherTarget, "wait=0", nil)
	resp := fetchPull(t, ts, otherTarget, 0, headers)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("foreign identity status = %d, want 401", resp.StatusCode)
	}
}

func TestApiV1PrefixUsesUnprefixedSignature(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	payload := bytes.Repeat([]byte{0x55}, SizeVeryTiny)

	pushPath := "/push/" + targetHash
	pushReq, err := http.NewRequest(
		http.MethodPost,
		ts.URL+"/api-v1"+pushPath,
		bytes.NewReader(payload),
	)
	if err != nil {
		t.Fatalf("new prefixed push: %v", err)
	}
	applyHeaders(pushReq, signedHeaders(t, priv, http.MethodPost, pushPath, "", payload))
	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil {
		t.Fatalf("prefixed push: %v", err)
	}
	pushResp.Body.Close()
	if pushResp.StatusCode != http.StatusOK {
		t.Fatalf("prefixed push status = %d, want 200", pushResp.StatusCode)
	}

	pullPath := "/pull/" + targetHash
	pullReq, err := http.NewRequest(
		http.MethodGet,
		ts.URL+"/api-v1"+pullPath+"?wait=0",
		nil,
	)
	if err != nil {
		t.Fatalf("new prefixed pull: %v", err)
	}
	applyHeaders(pullReq, signedHeaders(t, priv, http.MethodGet, pullPath, "wait=0", nil))
	pullResp, err := http.DefaultClient.Do(pullReq)
	if err != nil {
		t.Fatalf("prefixed pull: %v", err)
	}
	defer pullResp.Body.Close()
	if pullResp.StatusCode != http.StatusOK {
		t.Fatalf("prefixed pull status = %d, want 200", pullResp.StatusCode)
	}
}

func TestPrefixedSignatureIsRejected(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	payload := bytes.Repeat([]byte{0x56}, SizeVeryTiny)
	externalPath := "/api-v1/push/" + targetHash

	req, err := http.NewRequest(http.MethodPost, ts.URL+externalPath, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The client signs the unprefixed path; a signature over the external
	// path must not be accepted as an alternative contract.
	applyHeaders(req, signedHeaders(t, priv, http.MethodPost, externalPath, "", payload))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("prefixed-signature push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestInvalidSignaturesDoNotPolluteNonceCache(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	identity := hashEd25519Public(publicKey)
	timestamp := time.Now().Unix()
	bogusSignature := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	verifier := NewAuthVerifier()
	for i := 0; i < 10; i++ {
		request := AuthRequest{
			Method:    http.MethodGet,
			Path:      "/pull/abc",
			Timestamp: timestamp,
			Nonce:     randomNonce(t),
			Signature: bogusSignature,
		}
		if err := verifier.Verify(publicKey, identity, request, timestamp); err != AuthInvalidSignature {
			t.Fatalf("request %d error = %v, want %v", i, err, AuthInvalidSignature)
		}
	}
	if verifier.TotalNonceCount() != 0 {
		t.Fatalf("nonce cache grew to %d after invalid signatures", verifier.TotalNonceCount())
	}
	if verifier.RejectionCount() != 10 {
		t.Fatalf("rejection count = %d, want 10", verifier.RejectionCount())
	}
}

func TestAuthVerifierTimestampWindowAndNonceReplay(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	identity := hashEd25519Public(publicKey)

	nowUnix := time.Now().Unix()
	nonce := randomNonce(t)
	body := []byte("packet")
	makeRequest := func(timestamp int64) AuthRequest {
		return AuthRequest{
			Method:    http.MethodPost,
			Path:      "/push/abc",
			Query:     "",
			Timestamp: timestamp,
			Nonce:     nonce,
			Signature: base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(privateKey, canonicalRequest(http.MethodPost, "/push/abc", "", timestamp, nonce, body)),
			),
			Body: body,
		}
	}

	for _, timestamp := range []int64{nowUnix - TimestampWindowSecs, nowUnix + TimestampSkewSecs} {
		verifier := NewAuthVerifier()
		if err := verifier.Verify(publicKey, identity, makeRequest(timestamp), nowUnix); err != nil {
			t.Fatalf("boundary timestamp %d rejected: %v", timestamp, err)
		}
	}

	for _, timestamp := range []int64{nowUnix - TimestampWindowSecs - 1, nowUnix + TimestampSkewSecs + 1} {
		verifier := NewAuthVerifier()
		err := verifier.Verify(publicKey, identity, makeRequest(timestamp), nowUnix)
		if err != AuthTimestampOutOfWindow {
			t.Fatalf("timestamp %d error = %v, want %v", timestamp, err, AuthTimestampOutOfWindow)
		}
	}

	verifier := NewAuthVerifier()
	if err := verifier.Verify(publicKey, identity, makeRequest(nowUnix), nowUnix); err != nil {
		t.Fatalf("first signed request: %v", err)
	}
	if err := verifier.Verify(publicKey, identity, makeRequest(nowUnix), nowUnix); err != AuthReplayedNonce {
		t.Fatalf("replay error = %v, want %v", err, AuthReplayedNonce)
	}
	if verifier.TotalNonceCount() != 1 {
		t.Fatalf("nonce count = %d, want 1", verifier.TotalNonceCount())
	}
}

func TestNonceCacheFailsClosedAndPurges(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	identity := hashEd25519Public(publicKey)

	now := time.Now()
	nowUnix := now.Unix()
	verifier := &AuthVerifier{cache: newNonceCache(2, 10*time.Second)}

	signed := func(nonce string) AuthRequest {
		return AuthRequest{
			Method:    http.MethodGet,
			Path:      "/pull/abc",
			Timestamp: nowUnix,
			Nonce:     nonce,
			Signature: base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(privateKey, canonicalRequest(http.MethodGet, "/pull/abc", "", nowUnix, nonce, nil)),
			),
		}
	}

	first := randomNonce(t)
	second := randomNonce(t)
	if err := verifier.VerifyAt(publicKey, identity, signed(first), nowUnix, now); err != nil {
		t.Fatalf("first nonce: %v", err)
	}
	if err := verifier.VerifyAt(publicKey, identity, signed(second), nowUnix, now); err != nil {
		t.Fatalf("second nonce: %v", err)
	}

	// Replay wins over capacity on a full cache.
	if err := verifier.VerifyAt(publicKey, identity, signed(first), nowUnix, now); err != AuthReplayedNonce {
		t.Fatalf("replay on a full cache = %v, want %v", err, AuthReplayedNonce)
	}
	if err := verifier.VerifyAt(publicKey, identity, signed(randomNonce(t)), nowUnix, now); err != AuthNonceCacheFull {
		t.Fatalf("full cache error = %v, want %v", err, AuthNonceCacheFull)
	}
	if AuthNonceCacheFull.Status() != http.StatusServiceUnavailable {
		t.Fatalf("full cache status = %d, want 503", AuthNonceCacheFull.Status())
	}

	verifier.cache.purgeExpired(now.Add(11 * time.Second))
	if verifier.TotalNonceCount() != 0 {
		t.Fatalf("nonce count after purge = %d, want 0", verifier.TotalNonceCount())
	}
}

type authVectorCase struct {
	Name      string `json:"name"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Body      string `json:"body"`
	Canonical string `json:"canonical"`
}

type authVectors struct {
	Canonical []authVectorCase `json:"canonical"`
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

func loadAuthVectors(t *testing.T) authVectors {
	t.Helper()

	raw, err := os.ReadFile("../testdata/auth_vectors.json")
	if err != nil {
		t.Fatalf("read auth vectors: %v", err)
	}

	var vectors authVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse auth vectors: %v", err)
	}
	return vectors
}

// TestCanonicalVectorsMatchSharedFixture pins the canonical envelope and one
// Ed25519 signature to language-independent vectors. The signature vector was
// produced with a fixed seed, so a client/server divergence fails here.
func TestCanonicalVectorsMatchSharedFixture(t *testing.T) {
	vectors := loadAuthVectors(t)

	for _, vector := range vectors.Canonical {
		got := string(canonicalRequest(
			vector.Method, vector.Path, vector.Query,
			vector.Timestamp, vector.Nonce, []byte(vector.Body),
		))
		if got != vector.Canonical {
			t.Fatalf("%s: canonical envelope = %q, want %q", vector.Name, got, vector.Canonical)
		}

		withHash := string(canonicalRequestWithBodyHash(
			vector.Method, vector.Path, vector.Query,
			vector.Timestamp, vector.Nonce, bodyHash([]byte(vector.Body)),
		))
		if withHash != vector.Canonical {
			t.Fatalf("%s: precomputed body hash diverged: %q", vector.Name, withHash)
		}
	}

	vector := vectors.Signature
	seed, err := hex.DecodeString(vector.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("invalid vector seed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	if got := hex.EncodeToString(publicKey); got != vector.PublicKey {
		t.Fatalf("public key = %s, want %s", got, vector.PublicKey)
	}
	if got := hashEd25519Public(publicKey); got != vector.Identity {
		t.Fatalf("identity = %s, want %s", got, vector.Identity)
	}

	canonical := canonicalRequest(
		vector.Method, vector.Path, vector.Query,
		vector.Timestamp, vector.Nonce, []byte(vector.Body),
	)
	if string(canonical) != vector.Canonical {
		t.Fatalf("signature vector canonical = %q, want %q", canonical, vector.Canonical)
	}

	signature, err := decodeBase64URL(vector.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("decode vector signature: %v", err)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		t.Fatal("signature vector does not verify")
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
			name:   "public IPv6 peer with spoofed X-Real-IP",
			remote: "[2001:db8::7]:5555",
			header: "1.2.3.4",
			want:   "2001:db8::7",
		},
		{
			name:   "private proxy supplies X-Real-IP",
			remote: "172.18.0.5:40000",
			header: "198.51.100.9",
			want:   "198.51.100.9",
		},
		{
			name:   "loopback proxy supplies IPv6 X-Real-IP",
			remote: "[::1]:40000",
			header: "2001:db8::99",
			want:   "2001:db8::99",
		},
		{
			name:   "trusted proxy without header falls back to peer",
			remote: "172.18.0.5:40000",
			header: "",
			want:   "172.18.0.5",
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

// TestTrustedProxyCIDRNarrowsTrust verifies that an explicit allow-list replaces
// the broad loopback/RFC1918/ULA default, so a non-Caddy host on the same
// private network can no longer inject X-Real-IP.
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

	// A bare IP is accepted and means a single host.
	host, err := loadTrustedProxies("172.18.0.2")
	if err != nil {
		t.Fatalf("loadTrustedProxies(bare IP): %v", err)
	}
	if len(host) != 1 || !host[0].Contains(net.ParseIP("172.18.0.2")) {
		t.Fatalf("bare IP did not produce a single-host network: %v", host)
	}

	// Invalid entries must fail loudly instead of silently widening trust.
	if _, err := loadTrustedProxies("not-a-cidr"); err == nil {
		t.Fatal("invalid TRUSTED_PROXY_CIDR was accepted")
	}
	// An unset value keeps the legacy default.
	if nets, err := loadTrustedProxies("  "); err != nil || nets != nil {
		t.Fatalf("empty spec = (%v, %v), want (nil, nil)", nets, err)
	}
}

// TestRejectionBodiesAreGeneric keeps the stealth (403) and auth (401) bodies
// free of details about which check failed.
func TestRejectionBodiesAreGeneric(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	payload := bytes.Repeat([]byte{0x58}, SizeVeryTiny)
	pushPath := "/push/" + targetHash

	readBody := func(resp *http.Response) string {
		t.Helper()
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read rejection body: %v", err)
		}
		return string(body)
	}

	// 403: valid signature but no stealth header.
	stealthReq, err := http.NewRequest(http.MethodPost, ts.URL+pushPath, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new stealth request: %v", err)
	}
	for name, value := range signedHeaders(t, priv, http.MethodPost, pushPath, "", payload) {
		stealthReq.Header.Set(name, value)
	}
	stealthResp, err := http.DefaultClient.Do(stealthReq)
	if err != nil {
		t.Fatalf("stealth request: %v", err)
	}
	stealthBody := readBody(stealthResp)
	if stealthResp.StatusCode != http.StatusForbidden {
		t.Fatalf("stealth status = %d, want 403", stealthResp.StatusCode)
	}

	// 401: stealth header present but auth headers missing.
	authReq, err := http.NewRequest(http.MethodPost, ts.URL+pushPath, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new auth request: %v", err)
	}
	applyHeaders(authReq, nil)
	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatalf("auth request: %v", err)
	}
	authBody := readBody(authResp)
	if authResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth status = %d, want 401", authResp.StatusCode)
	}

	for _, body := range []string{stealthBody, authBody} {
		lower := strings.ToLower(body)
		for _, leak := range []string{"signature", "nonce", "timestamp", "header", "identity"} {
			if strings.Contains(lower, leak) {
				t.Fatalf("rejection body %q leaks %q", body, leak)
			}
		}
	}
}

// TestRateLimitIsKeyedByRealIPNotForwardedHeader pins K3: rotating a forged
// X-Real-IP must not create a fresh bucket for every request.
func TestRateLimitIsKeyedByRealIPNotForwardedHeader(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.routes()
	_, _, targetHash := newIdentity(t)

	var lastStatus int
	for i := 0; i < rateLimitBurst+1; i++ {
		req := httptest.NewRequest(http.MethodGet, "/pull/"+targetHash, nil)
		req.RemoteAddr = "203.0.113.50:40000"
		req.Header.Set("X-Real-IP", "198.51.100."+strconv.Itoa(i+1))
		req.Header.Set(testGuardName, testGuardValue)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		lastStatus = recorder.Code
		if i < rateLimitBurst && recorder.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status = %d, want 401 before the bucket is empty",
				i, recorder.Code)
		}
	}

	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("request %d status = %d, want 429", rateLimitBurst+1, lastStatus)
	}
}

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

func TestRateLimiterIsBounded(t *testing.T) {
	rl := NewRateLimiter()
	for i := 0; i < rateLimitMaxEntries+50; i++ {
		rl.Allow("10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256))
	}
	if got := rl.Len(); got > rateLimitMaxEntries {
		t.Fatalf("rate limiter holds %d buckets, want <= %d", got, rateLimitMaxEntries)
	}
}

func TestPushRejectsMissingStealthHeader(t *testing.T) {
	_, ts := newTestServer(t)
	priv, _, targetHash := newIdentity(t)
	payload := bytes.Repeat([]byte{0x57}, SizeVeryTiny)
	pushPath := "/push/" + targetHash

	req, err := http.NewRequest(http.MethodPost, ts.URL+pushPath, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new push: %v", err)
	}
	// Signed but without the stealth header: the relay must reject it before
	// spending CPU on signature verification.
	for name, value := range signedHeaders(t, priv, http.MethodPost, pushPath, "", payload) {
		req.Header.Set(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestCaddyfileOverwritesForwardingHeaders keeps K3 fixed at the proxy layer:
// Caddy must overwrite X-Real-IP with the real peer address, and the file
// route must enforce the same 128 MiB cap as the Go service.
func TestCaddyfileOverwritesForwardingHeaders(t *testing.T) {
	raw, err := os.ReadFile("../Caddyfile")
	if err != nil {
		t.Fatalf("read Caddyfile: %v", err)
	}
	config := string(raw)

	if got := strings.Count(config, "header_up X-Real-IP {remote_host}"); got != 2 {
		t.Fatalf("header_up X-Real-IP count = %d, want 2", got)
	}
	if got := strings.Count(config, "header_up X-Forwarded-For {remote_host}"); got != 2 {
		t.Fatalf("header_up X-Forwarded-For count = %d, want 2", got)
	}
	if strings.Contains(config, "header_up +X-Real-IP") || strings.Contains(config, "header_up +X-Forwarded-For") {
		t.Fatal("forwarding headers must overwrite the client value, not append to it")
	}
	// "TLS 1.3" in the README must be guaranteed by the config, not just a
	// default: protocols pins the allowed versions to 1.3 only.
	if !strings.Contains(config, "protocols tls1.3") {
		t.Fatal("TLS listener is not pinned to TLS 1.3")
	}
	if strings.Contains(config, "protocols tls1.2") {
		t.Fatal("TLS 1.2 is explicitly allowed, contract says TLS 1.3 only")
	}
	if !strings.Contains(config, "max_size 134217728") {
		t.Fatal("file route is missing the 128 MiB request body cap")
	}
	if !strings.Contains(config, "max_size 1048576") {
		t.Fatal("text route is missing the 1 MiB request body cap")
	}
}

// TestCaddyfileValidates runs Caddy's real parser when the binary is present.
// The Caddyfile is env-driven, and Caddy expands an unset variable to an empty
// string, which turns e.g. `email` into a parse error. Validating with the
// shipped template catches both syntax regressions and a broken env contract.
func TestCaddyfileValidates(t *testing.T) {
	caddyBin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy binary is not installed")
	}

	home := t.TempDir()
	cmd := exec.Command(caddyBin, "validate",
		"--config", "../Caddyfile",
		"--adapter", "caddyfile",
		"--envfile", "../env.example",
	)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_DATA_HOME="+filepath.Join(home, "data"),
		"XDG_CONFIG_HOME="+filepath.Join(home, "config"),
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("caddy validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Valid configuration") {
		t.Fatalf("caddy validate did not accept the config:\n%s", out)
	}
}
