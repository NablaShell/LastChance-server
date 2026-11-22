package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const requestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// RequestID accepts a sane inbound X-Request-ID or generates one, stores it in
// the request context and echoes it in the response.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFromContext returns the request id stored by RequestID.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(raw[:])
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-', ch == '_', ch == '.':
		default:
			return false
		}
	}
	return true
}
