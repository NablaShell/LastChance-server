// Copyright (C) 2026 NablaShell
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

const (
	// Files up to RAMLimit stay in memory; larger files go to the vault.
	RAMLimit  = 1 * 1024 * 1024   // 1 MB
	DiskLimit = 128 * 1024 * 1024 // 128 MiB — the Rust client's FILE_MAX_ENVELOPE

	// TTL
	RAMTTL  = 30 * time.Minute
	DiskTTL = 1 * time.Hour

	// Cleanup
	CleanupInterval = 5 * time.Minute

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

var (
	// Global variables for protection, initialized in main().
	effectiveHeaderName  string
	effectiveHeaderValue string

	// VaultPath is /tmp/lastchance_vault by default. VAULT_PATH may be used
	// by a deployment, but the Docker configuration remains untouched.
	vaultPath = func() string {
		if p := strings.TrimSpace(os.Getenv("VAULT_PATH")); p != "" {
			return p
		}
		return "/tmp/lastchance_vault"
	}()
)

// FileEntry — record of a file in storage.
type FileEntry struct {
	Data      []byte    // Data for RAM files
	FilePath  string    // Path for disk files
	Size      int64     // File size
	IsDisk    bool      // true = on disk, false = in memory
	CreatedAt time.Time // Creation time
}

// FileStore manages files in memory and on disk with thread safety.
type FileStore struct {
	mu    sync.RWMutex
	files map[string]*FileEntry // key = fileHash
}

func NewFileStore() *FileStore {
	return &FileStore{
		files: make(map[string]*FileEntry),
	}
}

// SaveToRAM saves a file in memory.
func (fs *FileStore) SaveToRAM(fileHash string, data []byte) error {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	now := time.Now().UTC()
	fs.mu.Lock()
	fs.files[fileHash] = &FileEntry{
		Data:      dataCopy,
		Size:      int64(len(data)),
		IsDisk:    false,
		CreatedAt: now,
	}
	fs.mu.Unlock()

	return nil
}

// SaveTempToDisk moves an already-written, authenticated temp file into the
// vault. The caller owns tempPath until this call returns.
func (fs *FileStore) SaveTempToDisk(fileHash, tempPath string, size int64) error {
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	finalPath := filepath.Join(vaultPath, fileHash+".bin")
	if err := os.Rename(tempPath, finalPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}
	// Only the service owner may read the stored file.
	if err := os.Chmod(finalPath, 0600); err != nil {
		os.Remove(finalPath)
		return fmt.Errorf("failed to chmod file: %w", err)
	}

	now := time.Now().UTC()
	fs.mu.Lock()
	fs.files[fileHash] = &FileEntry{
		FilePath:  finalPath,
		Size:      size,
		IsDisk:    true,
		CreatedAt: now,
	}
	fs.mu.Unlock()

	return nil
}

// Take atomically removes and returns a file. This guarantees the
// one-time-download policy even if two requests arrive simultaneously.
func (fs *FileStore) Take(fileHash string) (*FileEntry, bool) {
	fs.mu.Lock()
	entry, exists := fs.files[fileHash]
	if exists {
		delete(fs.files, fileHash)
	}
	fs.mu.Unlock()

	return entry, exists
}

// Restore puts an entry back if serving it failed before any bytes were sent.
func (fs *FileStore) Restore(fileHash string, entry *FileEntry) {
	fs.mu.Lock()
	if _, exists := fs.files[fileHash]; !exists {
		fs.files[fileHash] = entry
	}
	fs.mu.Unlock()
}

// Peek returns a file entry without consuming it.
func (fs *FileStore) Peek(fileHash string) (*FileEntry, bool) {
	fs.mu.RLock()
	entry, exists := fs.files[fileHash]
	fs.mu.RUnlock()
	return entry, exists
}

// Destroy securely removes the backing file of an entry.
func (fs *FileStore) Destroy(entry *FileEntry) {
	if entry == nil || !entry.IsDisk || entry.FilePath == "" {
		return
	}
	shredPath(entry.FilePath, 3)
}

// Cleanup removes expired files and returns how many were removed.
func (fs *FileStore) Cleanup() int {
	now := time.Now().UTC()
	removed := 0
	toDelete := make([]string, 0)

	fs.mu.Lock()
	for hash, entry := range fs.files {
		expired := false
		if entry.IsDisk {
			expired = now.Sub(entry.CreatedAt) > DiskTTL
		} else {
			expired = now.Sub(entry.CreatedAt) > RAMTTL
		}

		if expired {
			delete(fs.files, hash)
			removed++
			if entry.IsDisk && entry.FilePath != "" {
				toDelete = append(toDelete, entry.FilePath)
			}
		}
	}
	fs.mu.Unlock()

	for _, path := range toDelete {
		go shredPath(path, 3)
	}

	return removed
}

// shredPath overwrites and unlinks a file when `shred` is available.
func shredPath(path string, passes int) {
	if _, err := exec.LookPath("shred"); err == nil {
		if err := exec.Command("shred", "-u", "-n", fmt.Sprintf("%d", passes), path).Run(); err == nil {
			return
		}
		log.Printf("Shred failed for %s, falling back to remove", filepath.Base(path))
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("Remove failed for %s: %v", filepath.Base(path), err)
	}
}

// RateLimiter — brute-force protection.
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

// Cleanup drops buckets that have not seen traffic for rateLimitIdleTTL. The
// old implementation replaced the whole map, which reset every bucket and
// handed clients a fresh burst every CleanupInterval.
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

// Server — file relay.
type Server struct {
	store       *FileStore
	rateLimiter *RateLimiter
	auth        *AuthVerifier
}

func NewServer() *Server {
	return &Server{
		store:       NewFileStore(),
		rateLimiter: NewRateLimiter(),
		auth:        NewAuthVerifier(),
	}
}

// getClientIP retrieves the original client IP.
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

// checkGuard checks the secret stealth header. The Rust client sends the
// same header that Caddy uses (mask_header_name / mask_header_value).
func checkGuard(r *http.Request) bool {
	if effectiveHeaderName == "" || effectiveHeaderValue == "" {
		return false
	}
	got := r.Header.Get(effectiveHeaderName)
	return subtle.ConstantTimeCompare([]byte(got), []byte(effectiveHeaderValue)) == 1
}

// generateFileHash returns the lowercase hex SHA-256 of the stored bytes.
func generateFileHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// pathHash extracts the hash after one of the accepted route prefixes.
func pathHash(path string, prefixes ...string) (string, bool) {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			hash := strings.TrimPrefix(path, prefix)
			hash = strings.Trim(hash, "/")
			if hash == "" || strings.Contains(hash, "/") {
				return "", false
			}
			return hash, true
		}
	}
	return "", false
}

func shortHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

// UploadHandler — POST /file-api/upload (and POST /upload).
func (s *Server) UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkGuard(r) {
		log.Printf("REJECTED: missing guard header from %s", getClientIP(r))
		http.Error(w, StealthRejectedBody, http.StatusForbidden)
		return
	}

	ip := getClientIP(r)
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// The Rust client always sends Content-Length explicitly.
	if r.ContentLength < 0 {
		http.Error(w, "Missing Content-Length", http.StatusLengthRequired)
		return
	}
	if r.ContentLength == 0 {
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return
	}
	if r.ContentLength > DiskLimit {
		log.Printf("REJECTED: file too large (%d bytes) from %s", r.ContentLength, ip)
		http.Error(w, fmt.Sprintf("File too large: max %d bytes", DiskLimit),
			http.StatusRequestEntityTooLarge)
		return
	}

	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		log.Printf("ERROR: create vault: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Hash and spool the body in one pass. The body is never buffered in
	// memory, so a 100 MiB upload costs one disk temp file, not 100 MiB of
	// heap (K5).
	tempFile, err := os.CreateTemp(vaultPath, "upload-*.tmp")
	if err != nil {
		log.Printf("ERROR: create temp upload: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	hasher := sha256.New()
	body := http.MaxBytesReader(w, r.Body, DiskLimit+1)
	written, copyErr := io.Copy(io.MultiWriter(tempFile, hasher), body)
	if copyErr == nil {
		copyErr = tempFile.Sync()
	}
	closeErr := tempFile.Close()

	if copyErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(copyErr, &maxErr) {
			http.Error(w, fmt.Sprintf("File too large: max %d bytes", DiskLimit),
				http.StatusRequestEntityTooLarge)
			return
		}
		log.Printf("ERROR: read failed from %s: %v", ip, copyErr)
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	if closeErr != nil {
		log.Printf("ERROR: close temp upload failed from %s: %v", ip, closeErr)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if written != r.ContentLength {
		log.Printf("REJECTED: size mismatch (expected %d, got %d) from %s",
			r.ContentLength, written, ip)
		http.Error(w, "Size mismatch", http.StatusBadRequest)
		return
	}

	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// L-6/H-4: the signature binds the method, path, timestamp, nonce and
	// SHA256(body). Verify before publishing anything.
	if err := s.auth.VerifyRequestWithBodyHash(r, fileHash, "/file-api"); err != nil {
		writeAuthError(w, err)
		return
	}

	if written <= RAMLimit {
		data, err := os.ReadFile(tempPath)
		if err != nil {
			log.Printf("ERROR: read temp upload failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if err := s.store.SaveToRAM(fileHash, data); err != nil {
			log.Printf("ERROR: RAM save failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("UPLOADED: %d bytes to RAM (hash: %s) from %s",
			written, shortHash(fileHash), ip)
	} else {
		if err := s.store.SaveTempToDisk(fileHash, tempPath, written); err != nil {
			log.Printf("ERROR: Disk save failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("UPLOADED: %d bytes to DISK (hash: %s) from %s",
			written, shortHash(fileHash), ip)
	}

	// The Rust client expects the bare hash as text/plain.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fileHash))
}

// DownloadHandler — GET /file-api/download/{hash} (and GET /download/{hash}).
func (s *Server) DownloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkGuard(r) {
		log.Printf("REJECTED: missing guard header from %s", getClientIP(r))
		http.Error(w, StealthRejectedBody, http.StatusForbidden)
		return
	}

	ip := getClientIP(r)
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Verify the canonical signature before consuming the one-time file.
	if err := s.auth.VerifyRequest(r, nil, "/file-api"); err != nil {
		writeAuthError(w, err)
		return
	}

	hash, ok := pathHash(r.URL.Path, "/file-api/download/", "/download/")
	if !ok {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	// Atomically take the file so a concurrent second request gets 404.
	entry, exists := s.store.Take(hash)
	if !exists {
		log.Printf("NOT FOUND: hash %s from %s", shortHash(hash), ip)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	var data []byte
	if entry.IsDisk {
		var err error
		data, err = os.ReadFile(entry.FilePath)
		if err != nil {
			log.Printf("ERROR: read disk file failed: %v", err)
			s.store.Restore(hash, entry)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	} else {
		data = entry.Data
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		log.Printf("ERROR: write failed for %s: %v", shortHash(hash), err)
	}

	// One-time download: securely remove the file after delivery.
	go s.store.Destroy(entry)

	log.Printf("DOWNLOADED: %d bytes (hash: %s) to %s", len(data), shortHash(hash), ip)
}

// InfoHandler — HEAD/GET /file-api/info/{hash} (and /info/{hash}).
func (s *Server) InfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkGuard(r) {
		log.Printf("REJECTED: missing guard header from %s", getClientIP(r))
		http.Error(w, StealthRejectedBody, http.StatusForbidden)
		return
	}

	// /info is not used by the 1.0 client, but keep the existence oracle
	// behind the same canonical signature as /upload and /download.
	if err := s.auth.VerifyRequest(r, nil, "/file-api"); err != nil {
		writeAuthError(w, err)
		return
	}

	hash, ok := pathHash(r.URL.Path, "/file-api/info/", "/info/")
	if !ok {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	entry, exists := s.store.Peek(hash)
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", entry.Size))
	storage := "ram"
	if entry.IsDisk {
		storage = "disk"
	}
	w.Header().Set("X-File-Storage", storage)
	w.WriteHeader(http.StatusOK)
}

// PingHandler — liveness check.
func (s *Server) PingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("pong"))
}

// routes builds the HTTP routing table shared by main and tests. Caddy
// forwards /file-api/* without stripping the prefix, but the client signs the
// unprefixed /upload and /download paths; the verifier removes the prefix
// before checking the canonical envelope.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /file-api/upload", s.UploadHandler)
	mux.HandleFunc("GET /file-api/download/", s.DownloadHandler)
	mux.HandleFunc("HEAD /file-api/info/", s.InfoHandler)
	mux.HandleFunc("GET /file-api/info/", s.InfoHandler)
	mux.HandleFunc("GET /file-api/ping", s.PingHandler)

	// Direct/internal aliases.
	mux.HandleFunc("POST /upload", s.UploadHandler)
	mux.HandleFunc("GET /download/", s.DownloadHandler)
	mux.HandleFunc("HEAD /info/", s.InfoHandler)
	mux.HandleFunc("GET /info/", s.InfoHandler)
	mux.HandleFunc("GET /ping", s.PingHandler)

	return mux
}

// startCleanupWorker — background cleanup of expired files.
func (s *Server) startCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := s.store.Cleanup()
			if removed > 0 {
				log.Printf("CLEANUP: removed %d files", removed)
			}
			s.rateLimiter.Cleanup()
			s.auth.PurgeExpired()
		case <-ctx.Done():
			return
		}
	}
}

func main() {
	// Values come from the deployment environment, as configured by Docker.
	effectiveHeaderName = os.Getenv("STEALTH_HEADER_NAME")
	effectiveHeaderValue = os.Getenv("STEALTH_HEADER_VALUE")

	if effectiveHeaderName == "" || effectiveHeaderValue == "" {
		log.Fatalf("CRITICAL: Stealth security headers (STEALTH_HEADER_NAME/VALUE) not set in environment")
	}

	nets, err := loadTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDR"))
	if err != nil {
		log.Fatalf("CRITICAL: Invalid TRUSTED_PROXY_CIDR: %v", err)
	}
	trustedProxyNets = nets
	if nets == nil {
		log.Printf("TRUSTED_PROXY_CIDR is not set: trusting every loopback/RFC1918/ULA peer as a proxy. " +
			"Set it to Caddy's address or bridge subnet to narrow this.")
	}

	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		log.Fatalf("FAILED: Could not create vault directory [%s]: %v", vaultPath, err)
	}

	// Purge stale data from previous sessions.
	log.Printf("STARTUP: Purging old data in %s", vaultPath)
	for _, pattern := range []string{"*.bin", "*.tmp"} {
		files, _ := filepath.Glob(filepath.Join(vaultPath, pattern))
		for _, f := range files {
			os.Remove(f)
		}
	}

	server := NewServer()

	httpServer := &http.Server{
		Addr:           ":8081", // Internal Docker-network port
		Handler:        server.routes(),
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   120 * time.Second,
		IdleTimeout:    180 * time.Second,
		MaxHeaderBytes: 1 << 12,
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	go server.startCleanupWorker(ctx)

	go func() {
		log.Printf("SUCCESS: File Relay Service active on :8081")
		log.Printf("RESOURCE LIMITS: RAM: %d MB, Disk: %d MB", RAMLimit/(1024*1024), DiskLimit/(1024*1024))
		log.Printf("STORAGE PATH: %s", vaultPath)
		log.Printf("STEALTH MODE: Guarding with header [%s]", effectiveHeaderName)

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("FATAL: Server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("SHUTDOWN: Signal received, stopping services...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("ERROR: Shutdown failure: %v", err)
	}

	log.Println("CLEANUP: Securely erasing vault files...")
	files, _ := filepath.Glob(filepath.Join(vaultPath, "*.bin"))
	for _, f := range files {
		shredPath(f, 3)
	}

	log.Println("EXIT: Last Chance server stopped")
}
