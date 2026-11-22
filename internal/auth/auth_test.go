package auth_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NablaShell/LastChance-server/internal/auth"
	"github.com/NablaShell/LastChance-server/internal/store"
	"github.com/NablaShell/LastChance-server/internal/testutil"
)

type canonicalVector struct {
	Name      string `json:"name"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Body      string `json:"body"`
	Canonical string `json:"canonical"`
}

type signatureVector struct {
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
}

type fixture struct {
	Canonical []canonicalVector `json:"canonical"`
	Signature signatureVector   `json:"signature"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "auth_vectors.json"))
	if err != nil {
		t.Fatalf("read auth vectors: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse auth vectors: %v", err)
	}
	return f
}

func TestCanonicalVectorsMatchSharedFixture(t *testing.T) {
	f := loadFixture(t)
	for _, vector := range f.Canonical {
		t.Run(vector.Name, func(t *testing.T) {
			got := auth.CanonicalRequest(vector.Method, vector.Path, vector.Query, vector.Timestamp, vector.Nonce, []byte(vector.Body))
			if string(got) != vector.Canonical {
				t.Fatalf("canonical mismatch\n got: %q\nwant: %q", got, vector.Canonical)
			}
		})
	}
}

func TestSignatureVectorMatchesSharedFixture(t *testing.T) {
	f := loadFixture(t)
	seed, err := hex.DecodeString(f.Signature.Seed)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)

	if got := hex.EncodeToString(public); got != f.Signature.PublicKey {
		t.Fatalf("public key = %s, want %s", got, f.Signature.PublicKey)
	}
	if got := auth.IdentityHash(public); got != f.Signature.Identity {
		t.Fatalf("identity = %s, want %s", got, f.Signature.Identity)
	}

	canonical := auth.CanonicalRequest(
		f.Signature.Method,
		f.Signature.Path,
		f.Signature.Query,
		f.Signature.Timestamp,
		f.Signature.Nonce,
		[]byte(f.Signature.Body),
	)
	if string(canonical) != f.Signature.Canonical {
		t.Fatalf("canonical mismatch")
	}
	signature, err := base64.RawURLEncoding.DecodeString(f.Signature.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(public, canonical, signature) {
		t.Fatal("fixture signature does not verify")
	}
}

func newVerifier(t *testing.T) *auth.Verifier {
	t.Helper()
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "lc.db"), filepath.Join(root, "files"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return auth.NewVerifier(st)
}

func signedRequest(t *testing.T, identity testutil.Identity, method, path, query string, body []byte) *http.Request {
	t.Helper()
	url := "http://relay.test" + path
	if query != "" {
		url += "?" + query
	}
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, url, reader)
	for key, value := range identity.Headers(t, method, path, query, body) {
		req.Header.Set(key, value)
	}
	return req
}

func TestVerifyRequestAcceptsValidSignature(t *testing.T) {
	verifier := newVerifier(t)
	identity := testutil.NewIdentity(t)
	body := []byte("payload")
	req := signedRequest(t, identity, http.MethodPost, "/push/abc", "b=2&a=1", body)

	if err := verifier.VerifyRequest(req, body); err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
}

func TestVerifyRequestRejectsReplay(t *testing.T) {
	verifier := newVerifier(t)
	identity := testutil.NewIdentity(t)
	body := []byte("payload")
	req := signedRequest(t, identity, http.MethodPost, "/push/abc", "", body)

	if err := verifier.VerifyRequest(req, body); err != nil {
		t.Fatalf("first VerifyRequest: %v", err)
	}
	if err := verifier.VerifyRequest(req, body); !errors.Is(err, auth.ReplayedNonce) {
		t.Fatalf("replay = %v, want ReplayedNonce", err)
	}
}

func TestTimestampSkew(t *testing.T) {
	verifier := newVerifier(t)
	identity := testutil.NewIdentity(t)
	now := time.Now().Unix()

	tests := []struct {
		name      string
		timestamp int64
		want      error
	}{
		{name: "old edge", timestamp: now - 59, want: nil},
		{name: "future edge", timestamp: now + 29, want: nil},
		{name: "too old", timestamp: now - 61, want: auth.TimestampOutOfWindow},
		{name: "too far in future", timestamp: now + 31, want: auth.TimestampOutOfWindow},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nonce := testutil.RandomNonce(t)
			headers := identity.HeadersAt(t, http.MethodGet, "/pull/abc", "", test.timestamp, nonce, nil)
			req := httptest.NewRequest(http.MethodGet, "http://relay.test/pull/abc", nil)
			for key, value := range headers {
				req.Header.Set(key, value)
			}

			err := verifier.VerifyRequest(req, nil)
			if test.want == nil {
				if err != nil {
					t.Fatalf("VerifyRequest: %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("VerifyRequest = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyRequestRejectsTampering(t *testing.T) {
	verifier := newVerifier(t)
	identity := testutil.NewIdentity(t)

	t.Run("body", func(t *testing.T) {
		signed := []byte("signed")
		req := signedRequest(t, identity, http.MethodPost, "/push/abc", "", signed)
		if err := verifier.VerifyRequest(req, []byte("tampered")); !errors.Is(err, auth.InvalidSignature) {
			t.Fatalf("VerifyRequest = %v, want InvalidSignature", err)
		}
	})

	t.Run("path", func(t *testing.T) {
		req := signedRequest(t, identity, http.MethodGet, "/pull/aaa", "", nil)
		req.URL.Path = "/pull/bbb"
		if err := verifier.VerifyRequest(req, nil); !errors.Is(err, auth.InvalidSignature) {
			t.Fatalf("VerifyRequest = %v, want InvalidSignature", err)
		}
	})

	t.Run("query", func(t *testing.T) {
		req := signedRequest(t, identity, http.MethodGet, "/pull/abc", "wait=1", nil)
		req.URL.RawQuery = "wait=2"
		if err := verifier.VerifyRequest(req, nil); !errors.Is(err, auth.InvalidSignature) {
			t.Fatalf("VerifyRequest = %v, want InvalidSignature", err)
		}
	})

	t.Run("identity", func(t *testing.T) {
		other := testutil.NewIdentity(t)
		req := signedRequest(t, identity, http.MethodGet, "/pull/abc", "", nil)
		req.Header.Set(auth.HeaderIdentity, other.Hash)
		if err := verifier.VerifyRequest(req, nil); !errors.Is(err, auth.InvalidIdentity) {
			t.Fatalf("VerifyRequest = %v, want InvalidIdentity", err)
		}
	})

	t.Run("nonce", func(t *testing.T) {
		req := signedRequest(t, identity, http.MethodGet, "/pull/abc", "", nil)
		req.Header.Set(auth.HeaderNonce, "!!!")
		if err := verifier.VerifyRequest(req, nil); !errors.Is(err, auth.MalformedNonce) {
			t.Fatalf("VerifyRequest = %v, want MalformedNonce", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/pull/abc", nil)
		if err := verifier.VerifyRequest(req, nil); !errors.Is(err, auth.MissingHeaders) {
			t.Fatalf("VerifyRequest = %v, want MissingHeaders", err)
		}
	})
}

func TestNonceStoreFailureMapsTo503(t *testing.T) {
	verifier := auth.NewVerifier(nil)
	identity := testutil.NewIdentity(t)
	req := signedRequest(t, identity, http.MethodGet, "/pull/abc", "", nil)

	err := verifier.VerifyRequest(req, nil)
	if !errors.Is(err, auth.NonceCacheFull) {
		t.Fatalf("VerifyRequest = %v, want NonceCacheFull", err)
	}
	if status := auth.Status(err); status != http.StatusServiceUnavailable {
		t.Fatalf("Status = %d, want 503", status)
	}
}
