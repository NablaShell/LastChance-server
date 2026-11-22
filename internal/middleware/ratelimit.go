package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultRateLimitRPS        = 5
	defaultRateLimitBurst      = 10
	defaultRateLimitIdleTTL    = 10 * time.Minute
	defaultRateLimitMaxEntries = 4096
)

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is a bounded per-key token bucket. Evicting an idle bucket only
// grants one key one extra burst; replay protection lives in the nonce store,
// which fails closed instead.
type RateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*rateEntry
	rps        rate.Limit
	burst      int
	idleTTL    time.Duration
	maxEntries int
	lastSweep  time.Time
	now        func() time.Time
}

// NewRateLimiter builds a limiter with explicit bounds.
func NewRateLimiter(rps rate.Limit, burst, maxEntries int, idleTTL time.Duration) *RateLimiter {
	if maxEntries <= 0 {
		maxEntries = defaultRateLimitMaxEntries
	}
	if idleTTL <= 0 {
		idleTTL = defaultRateLimitIdleTTL
	}
	return &RateLimiter{
		limiters:   make(map[string]*rateEntry),
		rps:        rps,
		burst:      burst,
		idleTTL:    idleTTL,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// DefaultRateLimiter returns the shipped 5 rps / burst 10 policy.
func DefaultRateLimiter() *RateLimiter {
	return NewRateLimiter(defaultRateLimitRPS, defaultRateLimitBurst, defaultRateLimitMaxEntries, defaultRateLimitIdleTTL)
}

// Allow reports whether key may perform one request now.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	if rl.lastSweep.IsZero() || now.Sub(rl.lastSweep) >= time.Minute {
		rl.cleanupLocked(now)
		rl.lastSweep = now
	}

	entry, exists := rl.limiters[key]
	if !exists {
		if len(rl.limiters) >= rl.maxEntries {
			rl.evictOldestLocked()
		}
		entry = &rateEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[key] = entry
	}
	entry.lastSeen = now
	return entry.limiter.Allow()
}

// Cleanup drops buckets that have not seen traffic for the idle TTL.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.cleanupLocked(rl.now())
}

func (rl *RateLimiter) cleanupLocked(now time.Time) {
	cutoff := now.Add(-rl.idleTTL)
	for key, entry := range rl.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.limiters, key)
		}
	}
}

func (rl *RateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range rl.limiters {
		if oldestKey == "" || entry.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(rl.limiters, oldestKey)
	}
}

// Len reports the number of tracked keys.
func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.limiters)
}

// RateLimit enforces the limiter per resolved client IP.
func RateLimit(limiter *RateLimiter, trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(ClientIP(r, trusted)) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
