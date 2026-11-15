package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

// --- Protocol constants (must match the Rust client) ---

const (
	// The client accepts exactly this grid of message packet sizes.
	SizeVeryTiny = 256
	SizeTiny     = 1024
	SizeSmall    = 4096
	SizeMax      = 65536

	MaxMessagesPerHash = 100
	MessageTTL         = 24 * time.Hour
	CleanupInterval    = 10 * time.Minute

	// MaxLongPollWait is the upper bound for ?wait=N on GET /pull.
	MaxLongPollWait = 30 * time.Second
	// ServerWriteTimeout must exceed MaxLongPollWait so the HTTP server
	// does not cut a hanging long-poll short.
	ServerWriteTimeout = 45 * time.Second

	// Rate limiter: 5 requests/second with a burst of 10 per client IP.
	// The map is capped with oldest-entry eviction. That is safe here because
	// dropping a bucket only grants one extra burst to one IP; it cannot enable
	// a replay. The replay (nonce) cache is a separate structure that fails
	// closed instead of evicting; never reuse this policy for it (see auth.go).
	rateLimitRPS        = 5
	rateLimitBurst      = 10
	rateLimitIdleTTL    = 10 * time.Minute
	rateLimitMaxEntries = 4096

	// StealthRejectedBody is the uniform body for a missing or invalid stealth
	// header. Like AuthRejectedBody it must never describe what was wrong.
	StealthRejectedBody = "forbidden"
)

// allowedSizes — O(1) lookup for the allowed packet-size grid.
var allowedSizes = map[int64]bool{
	SizeVeryTiny: true,
	SizeTiny:     true,
	SizeSmall:    true,
	SizeMax:      true,
}

// Stealth header configured by the deployment. Caddy enforces the same pair
// at the edge; the relay re-checks it as defence in depth.
var (
	effectiveHeaderName  = os.Getenv("STEALTH_HEADER_NAME")
	effectiveHeaderValue = os.Getenv("STEALTH_HEADER_VALUE")
)

// ErrQueueFull is returned when the queue for a target hash is full.
var ErrQueueFull = errors.New("queue full")

// --- In-memory database ---

type DB struct {
	conn *sql.DB
}

func NewDB() (*DB, error) {
	// :memory: is pure RAM, as required by the relay design.
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// A :memory: database is per-connection. Keep a single connection so
	// every query sees the same data.
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	if _, err := conn.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}

	query := `
	CREATE TABLE IF NOT EXISTS queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_hash TEXT NOT NULL,
		payload BLOB NOT NULL,
		size INTEGER NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_target_hash ON queue(target_hash);
	CREATE INDEX IF NOT EXISTS idx_created_at ON queue(created_at);
	`
	if _, err := conn.Exec(query); err != nil {
		conn.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &DB{conn: conn}, nil
}

// SavePackage stores a package in the recipient's queue.
func (db *DB) SavePackage(targetHash string, payload []byte, size int) error {
	var count int
	if err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM queue WHERE target_hash = ?",
		targetHash,
	).Scan(&count); err != nil {
		return fmt.Errorf("count queue: %w", err)
	}
	if count >= MaxMessagesPerHash {
		return ErrQueueFull
	}

	if _, err := db.conn.Exec(
		"INSERT INTO queue (target_hash, payload, size, created_at) VALUES (?, ?, ?, ?)",
		targetHash, payload, size, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("insert package: %w", err)
	}
	return nil
}

// PullPackages atomically fetches and deletes all packages for a hash.
func (db *DB) PullPackages(targetHash string) ([][]byte, []int, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		"SELECT payload, size FROM queue WHERE target_hash = ? ORDER BY id ASC",
		targetHash,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("select packages: %w", err)
	}

	var payloads [][]byte
	var sizes []int
	for rows.Next() {
		var payload []byte
		var size int
		if err := rows.Scan(&payload, &size); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan package: %w", err)
		}
		payloads = append(payloads, payload)
		sizes = append(sizes, size)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("rows iteration: %w", err)
	}
	rows.Close()

	// Delete only after the rows have been fully read.
	if _, err := tx.Exec(
		"DELETE FROM queue WHERE target_hash = ?",
		targetHash,
	); err != nil {
		return nil, nil, fmt.Errorf("delete packages: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit tx: %w", err)
	}

	return payloads, sizes, nil
}

// Cleanup removes old packages (older than TTL).
func (db *DB) Cleanup(olderThan time.Time) (int64, error) {
	result, err := db.conn.Exec(
		"DELETE FROM queue WHERE created_at < ?",
		olderThan.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup: %w", err)
	}
	removed, _ := result.RowsAffected()
	return removed, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// --- Rate limiter ---

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateEntry
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rateEntry),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		if len(rl.limiters) >= rateLimitMaxEntries {
			rl.evictOldestLocked()
		}
		entry = &rateEntry{limiter: rate.NewLimiter(rateLimitRPS, rateLimitBurst)}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter.Allow()
}

// Cleanup drops buckets that have not seen traffic for rateLimitIdleTTL. It
// does not reset active buckets, so a cleanup tick can never hand an attacker
// a fresh burst.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rateLimitIdleTTL)
	for ip, entry := range rl.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
}

// evictOldestLocked drops the least-recently-seen bucket when the map is full.
// Eviction only resets a rate limit for one IP; replay protection lives in the
// separate nonce cache, which fails closed instead (auth.go).
func (rl *RateLimiter) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	for ip, entry := range rl.limiters {
		if oldestIP == "" || entry.lastSeen.Before(oldest) {
			oldestIP = ip
			oldest = entry.lastSeen
		}
	}
	if oldestIP != "" {
		delete(rl.limiters, oldestIP)
	}
}

func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.limiters)
}

// --- Long-poll notification registry ---

// NotifyRegistry wakes up long-polling GET /pull requests when a new package
// is written to a target bucket. It is safe for concurrent use.
//
// A channel is created lazily for a hash that has at least one waiter and is
// removed once the last waiter leaves, so idle hashes do not leak memory.
// Channels are never closed: Notify only sends non-blocking signals and a
// removed channel is simply left for the garbage collector.
type NotifyRegistry struct {
	mu      sync.Mutex
	buckets map[string]*notifyBucket
}

type notifyBucket struct {
	ch      chan struct{}
	waiters int
}

func NewNotifyRegistry() *NotifyRegistry {
	return &NotifyRegistry{
		buckets: make(map[string]*notifyBucket),
	}
}

// Subscribe registers interest in a hash. The returned cancel function must
// be called when the waiter stops waiting.
func (n *NotifyRegistry) Subscribe(targetHash string) (<-chan struct{}, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()

	b, ok := n.buckets[targetHash]
	if !ok {
		b = &notifyBucket{ch: make(chan struct{}, 1)}
		n.buckets[targetHash] = b
	}
	b.waiters++

	cancel := func() {
		n.mu.Lock()
		defer n.mu.Unlock()

		b.waiters--
		if b.waiters <= 0 {
			if cur, ok := n.buckets[targetHash]; ok && cur == b {
				delete(n.buckets, targetHash)
			}
		}
	}

	return b.ch, cancel
}

// Notify performs a non-blocking wake-up signal for a hash. It is a no-op
// when nobody is currently waiting.
func (n *NotifyRegistry) Notify(targetHash string) {
	n.mu.Lock()
	b, ok := n.buckets[targetHash]
	n.mu.Unlock()

	if !ok {
		return
	}

	select {
	case b.ch <- struct{}{}:
	default:
		// A signal is already pending; one wake-up is enough because waiters
		// always re-check the bucket after waking up.
	}
}

// Waiters reports how many pull requests are currently waiting on a hash.
func (n *NotifyRegistry) Waiters(targetHash string) int {
	n.mu.Lock()
	defer n.mu.Unlock()

	if b, ok := n.buckets[targetHash]; ok {
		return b.waiters
	}
	return 0
}

// --- HTTP server ---

type Server struct {
	db          *DB
	rateLimiter *RateLimiter
	notifier    *NotifyRegistry
	auth        *AuthVerifier
}

// handlePush — POST /api-v1/push/{target_hash}
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	targetHash := strings.TrimSpace(r.PathValue("target_hash"))
	ip := getClientIP(r)

	if !checkGuard(r) {
		log.Printf("[PUSH] %s: missing stealth header", ip)
		http.Error(w, StealthRejectedBody, http.StatusForbidden)
		return
	}

	// The Rust client always sends Content-Length and a packet from the
	// fixed size grid.
	if r.ContentLength < 0 {
		log.Printf("[PUSH] %s: unknown Content-Length", ip)
		http.Error(w, "Invalid Payload Size", http.StatusBadRequest)
		return
	}
	if !allowedSizes[r.ContentLength] {
		log.Printf("[PUSH] %s: invalid size %d", ip, r.ContentLength)
		http.Error(w, "Invalid Payload Size", http.StatusBadRequest)
		return
	}

	payload, err := io.ReadAll(io.LimitReader(r.Body, SizeMax+1))
	if err != nil {
		log.Printf("[PUSH] %s: read error: %v", ip, err)
		http.Error(w, "Payload read error", http.StatusBadRequest)
		return
	}
	if int64(len(payload)) != r.ContentLength {
		log.Printf("[PUSH] %s: size mismatch", ip)
		http.Error(w, "Payload size mismatch", http.StatusBadRequest)
		return
	}

	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// H-4: /push carries the same canonical signature as /pull, with
	// body_hash = SHA256(packet) bound into the envelope.
	if err := s.auth.VerifyRequest(r, payload, "/api-v1"); err != nil {
		writeAuthError(w, err)
		return
	}

	if err := s.db.SavePackage(targetHash, payload, len(payload)); err != nil {
		if errors.Is(err, ErrQueueFull) {
			http.Error(w, "Queue full", http.StatusTooManyRequests)
			return
		}
		log.Printf("[PUSH] %s: db error: %v", ip, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[PUSH] %s: ACCEPTED %d bytes to bucket %s", ip, len(payload), shortHash(targetHash))

	// Wake up a long-polling GET /pull for this recipient, if any.
	s.notifier.Notify(targetHash)

	w.WriteHeader(http.StatusOK)
}

// handlePull — GET /api-v1/pull/{target_hash}
//
// Supports HTTP long-polling via ?wait=<seconds> (clamped to MaxLongPollWait).
// With no wait (or wait=0) it keeps the legacy behaviour: return 204 No Content
// immediately when the bucket is empty.
func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	targetHash := strings.TrimSpace(r.PathValue("target_hash"))
	ip := getClientIP(r)

	if !checkGuard(r) {
		log.Printf("[PULL] %s: missing stealth header", ip)
		http.Error(w, StealthRejectedBody, http.StatusForbidden)
		return
	}

	// Rate-limit before touching the replay cache: a 429 must not consume the
	// client's nonce, otherwise its retry would look like a replay.
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// The release client signs the whole request and sends the recipient
	// identity both in the URL and in X-Auth-Identity.
	if err := s.auth.VerifyRequest(r, nil, "/api-v1"); err != nil {
		writeAuthError(w, err)
		return
	}
	if !equalFoldConstantTime(strings.TrimSpace(r.Header.Get(HeaderIdentity)), targetHash) {
		log.Printf("[PULL] %s: identity does not match target bucket %s", ip, shortHash(targetHash))
		http.Error(w, AuthRejectedBody, http.StatusUnauthorized)
		return
	}

	wait := parseLongPollWait(r)

	// Subscribe before checking the bucket: a push that lands between the
	// check and the wait then leaves a signal in the buffered channel and the
	// waiter still wakes up.
	notifyCh, unsubscribe := s.notifier.Subscribe(targetHash)
	defer unsubscribe()

	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}

	for {
		payloads, sizes, err := s.db.PullPackages(targetHash)
		if err != nil {
			log.Printf("[PULL] %s: db error: %v", ip, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if len(payloads) > 0 {
			s.writePackages(w, ip, targetHash, payloads, sizes)
			return
		}

		// Legacy mode: no long-polling requested.
		if wait <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		select {
		case <-notifyCh:
			// A package may have arrived. If another puller already drained
			// the bucket this is a stale signal; just re-check and keep
			// waiting for the remaining time.
		case <-timeout:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			// The client dropped the connection (e.g. it is switching Tor
			// circuits). Return without writing anything; the deferred
			// unsubscribe releases the registry entry.
			log.Printf("[PULL] %s: client disconnected while waiting for bucket %s",
				ip, shortHash(targetHash),
			)
			return
		}
	}
}

// parseLongPollWait parses the optional ?wait=<seconds> parameter and clamps
// it to [0, MaxLongPollWait]. Missing or invalid values mean "do not wait".
func parseLongPollWait(r *http.Request) time.Duration {
	raw := strings.TrimSpace(r.URL.Query().Get("wait"))
	if raw == "" {
		return 0
	}

	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return 0
	}

	wait := time.Duration(seconds) * time.Second
	if wait > MaxLongPollWait {
		return MaxLongPollWait
	}
	return wait
}

// writePackages sends the pulled packages as a multipart response.
func (s *Server) writePackages(w http.ResponseWriter, ip, targetHash string, payloads [][]byte, sizes []int) {
	// Build a multipart response. The Rust client only extracts the raw
	// payload of each part, so any valid multipart/form-data layout works.
	writer := multipart.NewWriter(w)
	w.Header().Set("Content-Type", writer.FormDataContentType())

	for i, payload := range payloads {
		part, err := writer.CreateFormFile(
			fmt.Sprintf("package_%d", i),
			fmt.Sprintf("package_%d_size_%d.bin", i, sizes[i]),
		)
		if err != nil {
			log.Printf("[PULL] %s: multipart error: %v", ip, err)
			return
		}
		if _, err := part.Write(payload); err != nil {
			log.Printf("[PULL] %s: write part error: %v", ip, err)
			return
		}
	}

	if err := writer.Close(); err != nil {
		log.Printf("[PULL] %s: close multipart error: %v", ip, err)
		return
	}

	log.Printf("[PULL] %s: DELIVERED %d packages to bucket %s",
		ip, len(payloads), shortHash(targetHash),
	)
}

// handlePing — health check.
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("pong"))
}

// --- Helpers ---

func getClientIP(r *http.Request) string {
	host := remoteHost(r)

	// Only a peer on loopback or a private network can be the Caddy proxy.
	// Anything else is a direct client, and its forwarding headers are
	// attacker-controlled (K3: rate-limit evasion via a forged X-Real-IP).
	if !isTrustedProxy(host) {
		return host
	}

	// Caddy overwrites X-Real-IP with header_up, so this value is never the
	// one supplied by the client. X-Forwarded-For is deliberately ignored:
	// one canonical header is easier to reason about and to test.
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}
	return host
}

// remoteHost returns the peer address without the ephemeral port. Unlike a
// LastIndex(":") split it also handles IPv6 literals correctly.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return host
}

// trustedProxyNets is the parsed TRUSTED_PROXY_CIDR allow-list. A nil slice
// means the variable is unset, in which case isTrustedProxy keeps the legacy
// loopback/RFC1918/ULA behaviour for backward compatibility.
var trustedProxyNets []*net.IPNet

// loadTrustedProxies parses a comma- or whitespace-separated list of CIDRs or
// bare IPs. An empty spec returns (nil, nil), meaning "use the default".
func loadTrustedProxies(spec string) ([]*net.IPNet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})

	nets := make([]*net.IPNet, 0, len(fields))
	for _, field := range fields {
		if strings.Contains(field, "/") {
			_, network, err := net.ParseCIDR(field)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", field, err)
			}
			nets = append(nets, network)
			continue
		}

		ip := net.ParseIP(field)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", field)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}

	if len(nets) == 0 {
		return nil, fmt.Errorf("no valid CIDR or IP in %q", spec)
	}
	return nets, nil
}

// isTrustedProxy reports whether host may supply proxy headers. The relays
// are only reachable through Caddy on the internal Docker bridge, so loopback
// and RFC1918/ULA peers are the only legitimate proxies by default.
//
// Set TRUSTED_PROXY_CIDR to Caddy's address or bridge subnet to stop trusting
// every private peer: otherwise any other host on the same RFC1918 network
// could forge X-Real-IP.
func isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if trustedProxyNets == nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// checkGuard checks the secret stealth header. Caddy already enforces it,
// but the relay re-checks it so a container that can reach the backend
// directly cannot bypass the proxy layer.
func checkGuard(r *http.Request) bool {
	if effectiveHeaderName == "" || effectiveHeaderValue == "" {
		return false
	}
	got := r.Header.Get(effectiveHeaderName)
	return subtle.ConstantTimeCompare([]byte(got), []byte(effectiveHeaderValue)) == 1
}

// shortHash safely truncates a hash for logging.
func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// routes builds the HTTP routing table shared by main and tests.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Public routes used through Caddy (/api-v1/* is forwarded as-is).
	mux.HandleFunc("POST /api-v1/push/{target_hash}", s.handlePush)
	mux.HandleFunc("GET /api-v1/pull/{target_hash}", s.handlePull)
	mux.HandleFunc("GET /api-v1/ping", s.handlePing)

	// Direct/internal aliases, useful for testing and non-proxied clients.
	mux.HandleFunc("POST /push/{target_hash}", s.handlePush)
	mux.HandleFunc("GET /pull/{target_hash}", s.handlePull)
	mux.HandleFunc("GET /ping", s.handlePing)

	return mux
}

// --- Main ---

func main() {
	nets, err := loadTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDR"))
	if err != nil {
		log.Fatalf("Invalid TRUSTED_PROXY_CIDR: %v", err)
	}
	trustedProxyNets = nets
	if nets == nil {
		log.Printf("TRUSTED_PROXY_CIDR is not set: trusting every loopback/RFC1918/ULA peer as a proxy. " +
			"Set it to Caddy's address or bridge subnet to narrow this.")
	}

	db, err := NewDB()
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}
	defer db.Close()

	server := &Server{
		db:          db,
		rateLimiter: NewRateLimiter(),
		notifier:    NewNotifyRegistry(),
		auth:        NewAuthVerifier(),
	}

	mux := server.routes()

	httpSrv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: ServerWriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	go func() {
		ticker := time.NewTicker(CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				removed, err := db.Cleanup(time.Now().Add(-MessageTTL))
				if err != nil {
					log.Printf("[CLEANUP] Error: %v", err)
				} else if removed > 0 {
					log.Printf("[CLEANUP] Removed %d expired packages", removed)
				}
				server.rateLimiter.Cleanup()
				server.auth.PurgeExpired()
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Println("LastChance Text Node starting on :8080")
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
