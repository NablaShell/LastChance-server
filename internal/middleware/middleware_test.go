package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestGuard(t *testing.T) {
	handler := Guard("X-Guard", "secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		value  string
		status int
	}{
		{name: "missing", value: "", status: http.StatusForbidden},
		{name: "wrong", value: "nope", status: http.StatusForbidden},
		{name: "correct", value: "secret", status: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.value != "" {
				req.Header.Set("X-Guard", test.value)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != test.status {
				t.Fatalf("status = %d, want %d", rec.Code, test.status)
			}
		})
	}
}

func TestGuardFailsClosedWithoutConfiguration(t *testing.T) {
	handler := Guard("", "")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequestIDGeneratedAndEchoed(t *testing.T) {
	var seen string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" {
		t.Fatal("request id not stored in context")
	}
	if rec.Header().Get(requestIDHeader) != seen {
		t.Fatalf("response request id = %q, context = %q", rec.Header().Get(requestIDHeader), seen)
	}
}

func TestRequestIDPreservesSaneInboundValue(t *testing.T) {
	var seen string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(requestIDHeader, "client-request_1.2")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seen != "client-request_1.2" {
		t.Fatalf("request id = %q", seen)
	}
}

func TestRequestIDRejectsUnsafeInboundValue(t *testing.T) {
	var seen string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(requestIDHeader, "bad value!\n")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seen == "bad value!\n" || seen == "" {
		t.Fatalf("unsafe request id accepted: %q", seen)
	}
}

func TestClientIPDirectPeerIgnoresForwardingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Real-IP", "198.51.100.20")
	if got := ClientIP(req, nil); got != "203.0.113.10" {
		t.Fatalf("ClientIP = %q", got)
	}
}

func TestClientIPTrustedProxyUsesRealIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Real-IP", "198.51.100.20")
	if got := ClientIP(req, trusted); got != "198.51.100.20" {
		t.Fatalf("ClientIP = %q", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	if _, err := ParseTrustedProxies(""); err != nil {
		t.Fatalf("empty spec: %v", err)
	}
	nets, err := ParseTrustedProxies("10.0.0.0/8, 192.168.1.1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("nets = %d", len(nets))
	}
	if _, err := ParseTrustedProxies("not-a-cidr"); err == nil {
		t.Fatal("invalid spec accepted")
	}
}

func TestRateLimiterBurstAndCleanup(t *testing.T) {
	rl := NewRateLimiter(rate.Limit(1), 2, 10, time.Minute)
	now := time.Now()
	rl.now = func() time.Time { return now }

	if !rl.Allow("ip") || !rl.Allow("ip") {
		t.Fatal("burst should be allowed")
	}
	if rl.Allow("ip") {
		t.Fatal("third immediate request should be limited")
	}

	now = now.Add(2 * time.Minute)
	rl.Cleanup()
	if rl.Len() != 0 {
		t.Fatalf("len after cleanup = %d, want 0", rl.Len())
	}
}

func TestRateLimiterIsBounded(t *testing.T) {
	rl := NewRateLimiter(rate.Limit(1), 1, 2, time.Minute)
	rl.Allow("a")
	rl.Allow("b")
	rl.Allow("c")
	if rl.Len() > 2 {
		t.Fatalf("len = %d, want <= 2", rl.Len())
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rl := NewRateLimiter(rate.Limit(1), 1, 10, time.Minute)
	handler := RateLimit(rl, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	handler.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", second.Code)
	}
}

func TestParseTrustedProxiesAllowsBareIPv6(t *testing.T) {
	nets, err := ParseTrustedProxies("::1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(nets) != 1 || !nets[0].Contains(net.ParseIP("::1")) {
		t.Fatal("IPv6 loopback not parsed")
	}
}
