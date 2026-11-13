package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// newTestServer starts an httptest server wired to the production routes.
func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	db, err := NewDB()
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	srv := &Server{
		db:          db,
		rateLimiter: NewRateLimiter(),
		notifier:    NewNotifyRegistry(),
	}

	ts := httptest.NewServer(srv.routes())
	t.Cleanup(func() {
		ts.Close()
		db.Close()
	})

	return srv, ts
}

// newIdentity creates an Ed25519 identity and returns its private key, the
// hex-encoded public key, and the target hash derived from the public key.
func newIdentity(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	hash := sha256.Sum256(pub)
	return priv, hex.EncodeToString(pub), hex.EncodeToString(hash[:])
}

// authHeaders builds the signed headers accepted by verifyAuth.
func authHeaders(t *testing.T, priv ed25519.PrivateKey, identityKey, targetHash string) map[string]string {
	t.Helper()

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := ed25519.Sign(priv, []byte(timestamp+targetHash))

	return map[string]string{
		"X-Identity-Key": identityKey,
		"X-Timestamp":    timestamp,
		"X-Signature":    hex.EncodeToString(signature),
	}
}

func applyHeaders(req *http.Request, headers map[string]string) {
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
	priv, identityKey, targetHash := newIdentity(t)
	headers := authHeaders(t, priv, identityKey, targetHash)

	// Payloads must match the fixed packet-size grid (256, 1024, 4096, 65536).
	payload := bytes.Repeat([]byte{0xA5}, SizeVeryTiny)

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
		url := ts.URL + "/pull/" + targetHash + "?wait=5"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			pullDone <- pullResult{err: err}
			return
		}
		applyHeaders(req, headers)

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
	pushReq, err := http.NewRequest(http.MethodPost, ts.URL+"/push/"+targetHash, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new push request: %v", err)
	}
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
	priv, identityKey, targetHash := newIdentity(t)
	headers := authHeaders(t, priv, identityKey, targetHash)

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
	priv, identityKey, targetHash := newIdentity(t)
	headers := authHeaders(t, priv, identityKey, targetHash)

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
	priv, identityKey, targetHash := newIdentity(t)
	headers := authHeaders(t, priv, identityKey, targetHash)

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
