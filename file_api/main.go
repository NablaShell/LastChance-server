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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
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
	DiskLimit = 100 * 1024 * 1024 // 100 MB — the Rust client's maximum upload

	// TTL
	RAMTTL  = 30 * time.Minute
	DiskTTL = 1 * time.Hour

	// Cleanup
	CleanupInterval = 5 * time.Minute
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

// SaveToDisk saves a file in the vault directory.
func (fs *FileStore) SaveToDisk(fileHash string, data []byte) error {
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	tmpFile, err := os.CreateTemp(vaultPath, "file-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmpFile, bytes.NewReader(data)); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	finalPath := filepath.Join(vaultPath, fileHash+".bin")
	if err := os.Rename(tmpName, finalPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}
	// Only the service owner may read the stored file.
	if err := os.Chmod(finalPath, 0600); err != nil {
		return fmt.Errorf("failed to chmod file: %w", err)
	}

	now := time.Now().UTC()
	fs.mu.Lock()
	fs.files[fileHash] = &FileEntry{
		FilePath:  finalPath,
		Size:      int64(len(data)),
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

	limiter, exists := rl.limiters[ip]
	if !exists {
		// 5 requests per second, burst 10.
		limiter = rate.NewLimiter(5, 10)
		rl.limiters[ip] = limiter
	}

	return limiter.Allow()
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limiters = make(map[string]*rate.Limiter)
}

// Server — file relay.
type Server struct {
	store       *FileStore
	rateLimiter *RateLimiter
}

func NewServer() *Server {
	return &Server{
		store:       NewFileStore(),
		rateLimiter: NewRateLimiter(),
	}
}

// getClientIP retrieves the original client IP.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// checkGuard checks the secret stealth header. The Rust client sends the
// same header that Caddy uses (mask_header_name / mask_header_value).
func checkGuard(r *http.Request) bool {
	if effectiveHeaderName == "" || effectiveHeaderValue == "" {
		return false
	}
	return r.Header.Get(effectiveHeaderName) == effectiveHeaderValue
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
		http.Error(w, "Forbidden", http.StatusForbidden)
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

	body := http.MaxBytesReader(w, r.Body, DiskLimit+1)
	data, err := io.ReadAll(body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, fmt.Sprintf("File too large: max %d bytes", DiskLimit),
				http.StatusRequestEntityTooLarge)
			return
		}
		log.Printf("ERROR: read failed from %s: %v", ip, err)
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	if int64(len(data)) != r.ContentLength {
		log.Printf("REJECTED: size mismatch (expected %d, got %d) from %s",
			r.ContentLength, len(data), ip)
		http.Error(w, "Size mismatch", http.StatusBadRequest)
		return
	}

	fileHash := generateFileHash(data)

	if len(data) <= RAMLimit {
		if err := s.store.SaveToRAM(fileHash, data); err != nil {
			log.Printf("ERROR: RAM save failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("UPLOADED: %d bytes to RAM (hash: %s) from %s",
			len(data), shortHash(fileHash), ip)
	} else {
		if err := s.store.SaveToDisk(fileHash, data); err != nil {
			log.Printf("ERROR: Disk save failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("UPLOADED: %d bytes to DISK (hash: %s) from %s",
			len(data), shortHash(fileHash), ip)
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
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	ip := getClientIP(r)
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
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
		http.Error(w, "Forbidden", http.StatusForbidden)
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

	mux := http.NewServeMux()

	// Caddy forwards /file-api/* without stripping the prefix.
	mux.HandleFunc("POST /file-api/upload", server.UploadHandler)
	mux.HandleFunc("GET /file-api/download/", server.DownloadHandler)
	mux.HandleFunc("HEAD /file-api/info/", server.InfoHandler)
	mux.HandleFunc("GET /file-api/info/", server.InfoHandler)
	mux.HandleFunc("GET /file-api/ping", server.PingHandler)

	// Direct/internal aliases.
	mux.HandleFunc("POST /upload", server.UploadHandler)
	mux.HandleFunc("GET /download/", server.DownloadHandler)
	mux.HandleFunc("HEAD /info/", server.InfoHandler)
	mux.HandleFunc("GET /info/", server.InfoHandler)
	mux.HandleFunc("GET /ping", server.PingHandler)

	httpServer := &http.Server{
		Addr:           ":8081", // Internal Docker-network port
		Handler:        mux,
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
