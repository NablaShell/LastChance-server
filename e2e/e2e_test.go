package e2e

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/NablaShell/LastChance-server/internal/api"
	"github.com/NablaShell/LastChance-server/internal/auth"
	"github.com/NablaShell/LastChance-server/internal/middleware"
	"github.com/NablaShell/LastChance-server/internal/store"
	"github.com/NablaShell/LastChance-server/internal/testutil"
	"golang.org/x/time/rate"
)

const (
	guardName  = "X-E2E-Guard"
	guardValue = "e2e-secret"
)

func TestSmokeBothPorts(t *testing.T) {
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "lc.db"), filepath.Join(root, "files"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	identity := testutil.NewIdentity(t)
	verifier := auth.NewVerifier(st)
	notifier := api.NewNotifier()
	limiter := func() *middleware.RateLimiter {
		return middleware.NewRateLimiter(rate.Limit(1000), 1000, 1000, time.Minute)
	}

	relay := httptest.NewServer(api.NewRelayMux(api.RelayOptions{
		Queues:             st,
		Auth:               verifier,
		Notifier:           notifier,
		MaxBodyBytes:       1 << 20,
		PullTimeout:        5 * time.Second,
		MaxConcurrentPulls: 8,
		GuardHeader:        guardName,
		GuardValue:         guardValue,
		RateLimiter:        limiter(),
	}))
	defer relay.Close()

	files := httptest.NewServer(api.NewFilesMux(api.FilesOptions{
		Files:        st,
		Auth:         verifier,
		MaxFileBytes: 1 << 20,
		GuardHeader:  guardName,
		GuardValue:   guardValue,
		RateLimiter:  limiter(),
	}))
	defer files.Close()

	if relay.URL == files.URL {
		t.Fatal("relay and files servers share an address")
	}

	// Health checks need no secret.
	for _, base := range []string{relay.URL, files.URL} {
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			t.Fatalf("health %s: %v", base, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
			t.Fatalf("health %s = %d %q", base, resp.StatusCode, body)
		}
	}

	recipient := identity.Hash
	payload := bytes.Repeat([]byte{0x51}, 256)

	push := signedRequest(t, identity, http.MethodPost, relay.URL+"/push/"+recipient, "/push/"+recipient, "", payload)
	resp, err := http.DefaultClient.Do(push)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push status = %d", resp.StatusCode)
	}

	pull := signedRequest(t, identity, http.MethodGet, relay.URL+"/pull/"+recipient, "/pull/"+recipient, "", nil)
	resp, err = http.DefaultClient.Do(pull)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	parts := readMultipart(t, resp)
	resp.Body.Close()
	if len(parts) != 1 || !bytes.Equal(parts[0], payload) {
		t.Fatalf("pull payload mismatch")
	}

	fileData := bytes.Repeat([]byte{0x52}, 2048)
	upload := signedRequest(t, identity, http.MethodPost, files.URL+"/upload", "/upload", "", fileData)
	resp, err = http.DefaultClient.Do(upload)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	id, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d, %v", resp.StatusCode, err)
	}
	if !store.ValidFileID(string(id)) {
		t.Fatalf("invalid file id %q", id)
	}

	download := signedRequest(t, identity, http.MethodGet, files.URL+"/download/"+string(id), "/download/"+string(id), "", nil)
	resp, err = http.DefaultClient.Do(download)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	downloaded, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d, %v", resp.StatusCode, err)
	}
	if !bytes.Equal(downloaded, fileData) {
		t.Fatalf("download payload mismatch")
	}
}

func signedRequest(t *testing.T, identity testutil.Identity, method, url, path, query string, body []byte) *http.Request {
	t.Helper()
	if query != "" {
		url += "?" + query
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range identity.Headers(t, method, path, query, body) {
		req.Header.Set(key, value)
	}
	req.Header.Set(guardName, guardValue)
	return req
}

func readMultipart(t *testing.T, resp *http.Response) [][]byte {
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

func TestCaddyfileValidates(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy binary not available")
	}
	cmd := exec.Command(caddy,
		"validate",
		"--config", filepath.Join("..", "Caddyfile"),
		"--adapter", "caddyfile",
		"--envfile", filepath.Join("..", "env.example"),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("caddy validate failed: %v\n%s", err, output)
	}
}
