package middleware

import (
	"crypto/subtle"
	"net/http"
)

// StealthRejectedBody is the uniform body for a missing or invalid stealth
// header. It never describes what was wrong.
const StealthRejectedBody = "forbidden"

// Guard enforces the anti-scanning header with a constant-time comparison. An
// empty configured name or value fails closed.
func Guard(headerName, headerValue string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if headerName == "" || headerValue == "" {
				http.Error(w, StealthRejectedBody, http.StatusForbidden)
				return
			}
			got := r.Header.Get(headerName)
			if subtle.ConstantTimeCompare([]byte(got), []byte(headerValue)) != 1 {
				http.Error(w, StealthRejectedBody, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Chain applies middleware so the first argument is the outermost layer.
func Chain(handler http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	return handler
}
