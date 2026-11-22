package api

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/NablaShell/LastChance-server/internal/auth"
	"github.com/NablaShell/LastChance-server/internal/middleware"
	"github.com/NablaShell/LastChance-server/internal/store"
	"github.com/NablaShell/LastChance-server/internal/testutil"
	"golang.org/x/time/rate"
)

const (
	testGuardName  = "X-Test-Guard"
	testGuardValue = "test-secret"
)

type fixture struct {
	relayHandler http.Handler
	filesHandler http.Handler
	relay        *httptest.Server
	files        *httptest.Server
	store        *store.Store
	identity     testutil.Identity
	notifier     *Notifier
}

func newFixture(t *testing.T, relayMaxBody, filesMaxFile int64, pullTimeout time.Duration, maxConcurrent int) *fixture {
	t.Helper()
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "lc.db"), filepath.Join(root, "files"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	identity := testutil.NewIdentity(t)
	verifier := auth.NewVerifier(st)
	notifier := NewNotifier()
	limiter := func() *middleware.RateLimiter {
		return middleware.NewRateLimiter(rate.Limit(1000), 1000, 1000, time.Minute)
	}

	relayHandler := NewRelayMux(RelayOptions{
		Queues:             st,
		Auth:               verifier,
		Notifier:           notifier,
		MaxBodyBytes:       relayMaxBody,
		PullTimeout:        pullTimeout,
		MaxConcurrentPulls: maxConcurrent,
		GuardHeader:        testGuardName,
		GuardValue:         testGuardValue,
		RateLimiter:        limiter(),
	})
	filesHandler := NewFilesMux(FilesOptions{
		Files:        st,
		Auth:         verifier,
		MaxFileBytes: filesMaxFile,
		GuardHeader:  testGuardName,
		GuardValue:   testGuardValue,
		RateLimiter:  limiter(),
	})

	relay := httptest.NewServer(relayHandler)
	files := httptest.NewServer(filesHandler)
	t.Cleanup(func() {
		relay.Close()
		files.Close()
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})

	return &fixture{
		relayHandler: relayHandler,
		filesHandler: filesHandler,
		relay:        relay,
		files:        files,
		store:        st,
		identity:     identity,
		notifier:     notifier,
	}
}

func (f *fixture) request(t *testing.T, base *httptest.Server, method, path, query string, body []byte, identity testutil.Identity, guard bool) *http.Request {
	t.Helper()
	url := base.URL + path
	if query != "" {
		url += "?" + query
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if query != "" {
		req.URL.RawQuery = query
	}
	for key, value := range identity.Headers(t, method, path, query, body) {
		req.Header.Set(key, value)
	}
	if guard {
		req.Header.Set(testGuardName, testGuardValue)
	}
	return req
}

func doRequest(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readMultipartPayloads(t *testing.T, resp *http.Response) [][]byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("content type = %q (%v)", resp.Header.Get("Content-Type"), err)
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var payloads [][]byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		payload, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func waitForWaiters(t *testing.T, notifier *Notifier, recipient string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if notifier.Waiters(recipient) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waiters = %d, want %d", notifier.Waiters(recipient), want)
}

func TestRelayPushPullRoundTrip(t *testing.T) {
	f := newFixture(t, 1<<20, 128<<20, 5*time.Second, 8)
	payload := bytes.Repeat([]byte{0x41}, 256)

	push := f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", payload, f.identity, true)
	if resp := doRequest(t, push); resp.StatusCode != http.StatusOK {
		t.Fatalf("push status = %d", resp.StatusCode)
	}

	pull := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "", nil, f.identity, true)
	resp := doRequest(t, pull)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull status = %d", resp.StatusCode)
	}
	parts := readMultipartPayloads(t, resp)
	if len(parts) != 1 || !bytes.Equal(parts[0], payload) {
		t.Fatalf("pulled payload mismatch: %d parts", len(parts))
	}
}

func TestRelayRejectsOversizedAndMisalignedBodies(t *testing.T) {
	f := newFixture(t, 1024, 128<<20, time.Second, 4)

	t.Run("max body", func(t *testing.T) {
		body := bytes.Repeat([]byte{0x41}, 4096)
		req := f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", body, f.identity, true)
		if resp := doRequest(t, req); resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
	})

	t.Run("not a packet bucket", func(t *testing.T) {
		body := bytes.Repeat([]byte{0x41}, 100)
		req := f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", body, f.identity, true)
		if resp := doRequest(t, req); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})
}

func TestRelayGuardAndHealth(t *testing.T) {
	f := newFixture(t, 1<<20, 128<<20, time.Second, 4)

	req := f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", []byte("x"), f.identity, false)
	if resp := doRequest(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing guard status = %d, want 403", resp.StatusCode)
	}

	req = f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", []byte("x"), f.identity, true)
	req.Header.Set(testGuardName, "wrong")
	if resp := doRequest(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong guard status = %d, want 403", resp.StatusCode)
	}

	// Health checks must not require the stealth header.
	resp, err := http.Get(f.relay.URL + "/healthz")
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
}

func TestRelayLongPollWakesOnPush(t *testing.T) {
	f := newFixture(t, 1<<20, 128<<20, 5*time.Second, 8)
	payload := bytes.Repeat([]byte{0x42}, 256)

	type result struct {
		resp *http.Response
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		req := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "wait=5", nil, f.identity, true)
		resp, err := http.DefaultClient.Do(req)
		resultCh <- result{resp: resp, err: err}
	}()

	waitForWaiters(t, f.notifier, f.identity.Hash, 1)

	push := f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", payload, f.identity, true)
	if resp := doRequest(t, push); resp.StatusCode != http.StatusOK {
		t.Fatalf("push status = %d", resp.StatusCode)
	}

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("pull: %v", result.err)
		}
		defer result.resp.Body.Close()
		if result.resp.StatusCode != http.StatusOK {
			t.Fatalf("pull status = %d", result.resp.StatusCode)
		}
		parts := readMultipartPayloads(t, result.resp)
		if len(parts) != 1 || !bytes.Equal(parts[0], payload) {
			t.Fatalf("pull payload mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long poll did not wake")
	}
}

func TestRelayLongPollTimeout(t *testing.T) {
	f := newFixture(t, 1<<20, 128<<20, time.Second, 4)
	start := time.Now()
	req := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "wait=1", nil, f.identity, true)
	resp := doRequest(t, req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("long poll returned too early: %v", elapsed)
	}
}

func TestRelayLongPollCancelReleasesWaiter(t *testing.T) {
	f := newFixture(t, 1<<20, 128<<20, 30*time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		req := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "wait=30", nil, f.identity, true).WithContext(ctx)
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		errCh <- err
	}()

	waitForWaiters(t, f.notifier, f.identity.Hash, 1)
	cancel()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled pull did not return")
	}
	waitForWaiters(t, f.notifier, f.identity.Hash, 0)

	// A later pull must get a semaphore slot, proving the cancelled request
	// released it.
	req := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "wait=1", nil, f.identity, true)
	if resp := doRequest(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("post-cancel status = %d, want 204", resp.StatusCode)
	}
}

func TestRelayLongPollConcurrencyLimit(t *testing.T) {
	f := newFixture(t, 1<<20, 128<<20, 5*time.Second, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		req := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "wait=5", nil, f.identity, true).WithContext(ctx)
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		_ = err
	}()

	waitForWaiters(t, f.notifier, f.identity.Hash, 1)

	second := f.request(t, f.relay, http.MethodGet, "/pull/"+f.identity.Hash, "wait=5", nil, f.identity, true)
	if resp := doRequest(t, second); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d, want 503", resp.StatusCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("first pull did not stop")
	}
}

func TestFilesUploadDownloadRoundTrip(t *testing.T) {
	f := newFixture(t, 1<<20, 1<<20, time.Second, 4)
	payload := bytes.Repeat([]byte{0x43}, 1024)

	upload := f.request(t, f.files, http.MethodPost, "/upload", "", payload, f.identity, true)
	resp := doRequest(t, upload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d", resp.StatusCode)
	}
	idBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read id: %v", err)
	}
	id := string(idBytes)
	if !store.ValidFileID(id) {
		t.Fatalf("invalid id %q", id)
	}

	download := f.request(t, f.files, http.MethodGet, "/download/"+id, "", nil, f.identity, true)
	resp = doRequest(t, download)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("download mismatch: %d bytes", len(data))
	}

	// One-time download: the second request must be 404.
	again := f.request(t, f.files, http.MethodGet, "/download/"+id, "", nil, f.identity, true)
	if resp := doRequest(t, again); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second download status = %d, want 404", resp.StatusCode)
	}
}

func TestPerPortLimitsAreIndependent(t *testing.T) {
	f := newFixture(t, 1024, 4096, time.Second, 4)

	// 2048 bytes is valid for files (<= 4096) but too large for relay
	// (4096 is a valid packet bucket, so this exercises max_body_bytes).
	filePayload := bytes.Repeat([]byte{0x44}, 2048)
	upload := f.request(t, f.files, http.MethodPost, "/upload", "", filePayload, f.identity, true)
	if resp := doRequest(t, upload); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d", resp.StatusCode)
	}

	relayPayload := bytes.Repeat([]byte{0x45}, 4096)
	push := f.request(t, f.relay, http.MethodPost, "/push/"+f.identity.Hash, "", relayPayload, f.identity, true)
	if resp := doRequest(t, push); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("push status = %d, want 413", resp.StatusCode)
	}

	tooLarge := bytes.Repeat([]byte{0x46}, 8192)
	upload = f.request(t, f.files, http.MethodPost, "/upload", "", tooLarge, f.identity, true)
	if resp := doRequest(t, upload); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload status = %d, want 413", resp.StatusCode)
	}
}

func TestFilesGuardHealthAndInvalidID(t *testing.T) {
	f := newFixture(t, 1<<20, 1<<20, time.Second, 4)

	req := f.request(t, f.files, http.MethodPost, "/upload", "", []byte("x"), f.identity, false)
	if resp := doRequest(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing guard status = %d", resp.StatusCode)
	}

	resp, err := http.Get(f.files.URL + "/healthz")
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}

	bad := f.request(t, f.files, http.MethodGet, "/download/not-a-hash", "", nil, f.identity, true)
	if resp := doRequest(t, bad); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid id status = %d, want 400", resp.StatusCode)
	}
}

func TestUploadRejectsTamperedBody(t *testing.T) {
	f := newFixture(t, 1<<20, 1<<20, time.Second, 4)
	signed := bytes.Repeat([]byte{0x47}, 512)
	tampered := bytes.Repeat([]byte{0x48}, 512)

	req := f.request(t, f.files, http.MethodPost, "/upload", "", tampered, f.identity, true)
	// Re-sign the request for the *other* body: the upload hashes what it
	// receives, so the signature must not match.
	for key, value := range f.identity.Headers(t, http.MethodPost, "/upload", "", signed) {
		req.Header.Set(key, value)
	}
	if resp := doRequest(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered upload status = %d, want 401", resp.StatusCode)
	}
}

func TestUploadRequiresContentLength(t *testing.T) {
	f := newFixture(t, 1<<20, 1<<20, time.Second, 4)
	body := bytes.Repeat([]byte{0x49}, 512)
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.ContentLength = -1
	for key, value := range f.identity.Headers(t, http.MethodPost, "/upload", "", body) {
		req.Header.Set(key, value)
	}
	req.Header.Set(testGuardName, testGuardValue)

	rec := httptest.NewRecorder()
	f.filesHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusLengthRequired {
		t.Fatalf("status = %d, want 411", rec.Code)
	}
}
