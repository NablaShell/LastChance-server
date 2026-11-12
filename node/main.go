package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
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
	MaxTimestampDiff   = 60 // seconds, replay protection
)

// allowedSizes — O(1) lookup for the allowed packet-size grid.
var allowedSizes = map[int64]bool{
	SizeVeryTiny: true,
	SizeTiny:     true,
	SizeSmall:    true,
	SizeMax:      true,
}

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

// --- Cryptography and authorization ---

// verifyAuth validates the Ed25519 signature exactly as the Rust client
// produces it:
//
//	identity hash = hex(SHA256(ed25519_public_key_bytes))
//	signed message = decimal_timestamp_string + identity_hash
//
// X-Identity-Key contains hex(ed25519_public_key), not the hash itself.
func verifyAuth(identityKeyHex, timestampStr, signatureHex, targetHash string) error {
	identityKeyHex = strings.TrimSpace(identityKeyHex)
	timestampStr = strings.TrimSpace(timestampStr)
	signatureHex = strings.TrimSpace(signatureHex)
	targetHash = strings.TrimSpace(targetHash)

	if identityKeyHex == "" || timestampStr == "" || signatureHex == "" || targetHash == "" {
		return errors.New("missing authorization headers")
	}

	// 1. Timestamp check (±60 seconds).
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp format")
	}
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > MaxTimestampDiff {
		return errors.New("timestamp expired")
	}

	// 2. Decode the Ed25519 public key from hex.
	pubKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key format")
	}

	// 3. The URL target hash must be SHA256 of the raw Ed25519 public key.
	hash := sha256.Sum256(pubKey)
	computedHash := hex.EncodeToString(hash[:])
	if subtle.ConstantTimeCompare([]byte(computedHash), []byte(targetHash)) != 1 {
		return errors.New("identity key does not match target hash")
	}

	// 4. Signed message: timestamp + identity_hash with no separator.
	message := timestampStr + targetHash

	// 5. Decode the signature.
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature format")
	}

	// 6. Verify the Ed25519 signature.
	if !ed25519.Verify(pubKey, []byte(message), signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// --- Rate limiter ---

type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	l, exists := rl.limiters[ip]
	if !exists {
		// 5 requests per second with a burst of 10.
		l = rate.NewLimiter(rate.Limit(5), 10)
		rl.limiters[ip] = l
	}
	return l.Allow()
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	// Reserved for future idle-limiter tracking.
}

// --- HTTP server ---

type Server struct {
	db          *DB
	rateLimiter *RateLimiter
}

// handlePush — POST /api-v1/push/{target_hash}
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	targetHash := strings.TrimSpace(r.PathValue("target_hash"))
	ip := getClientIP(r)

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
	w.WriteHeader(http.StatusOK)
}

// handlePull — GET /api-v1/pull/{target_hash}
func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	targetHash := strings.TrimSpace(r.PathValue("target_hash"))
	ip := getClientIP(r)

	// The Rust client (and the current Go client) uses X-Identity-Key.
	// X-Public-Key is accepted as an alias for documentation-era clients.
	identityKey := r.Header.Get("X-Identity-Key")
	if identityKey == "" {
		identityKey = r.Header.Get("X-Public-Key")
	}
	timestamp := r.Header.Get("X-Timestamp")
	signature := r.Header.Get("X-Signature")

	if err := verifyAuth(identityKey, timestamp, signature, targetHash); err != nil {
		log.Printf("[PULL] %s: auth failed: %v", ip, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	payloads, sizes, err := s.db.PullPackages(targetHash)
	if err != nil {
		log.Printf("[PULL] %s: db error: %v", ip, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// No packages — the client expects 204 No Content.
	if len(payloads) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

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
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if idx := strings.IndexByte(ip, ','); idx >= 0 {
			ip = ip[:idx]
		}
		return strings.TrimSpace(ip)
	}
	return r.RemoteAddr
}

// shortHash safely truncates a hash for logging.
func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// --- Main ---

func main() {
	db, err := NewDB()
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}
	defer db.Close()

	server := &Server{
		db:          db,
		rateLimiter: NewRateLimiter(),
	}

	mux := http.NewServeMux()

	// Public routes used through Caddy (/api-v1/* is forwarded as-is).
	mux.HandleFunc("POST /api-v1/push/{target_hash}", server.handlePush)
	mux.HandleFunc("GET /api-v1/pull/{target_hash}", server.handlePull)
	mux.HandleFunc("GET /api-v1/ping", server.handlePing)

	// Direct/internal aliases, useful for testing and non-proxied clients.
	mux.HandleFunc("POST /push/{target_hash}", server.handlePush)
	mux.HandleFunc("GET /pull/{target_hash}", server.handlePull)
	mux.HandleFunc("GET /ping", server.handlePing)

	httpSrv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
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
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Println("NablaShell Relay Node starting on :8080")
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
