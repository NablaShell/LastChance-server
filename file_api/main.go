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
	// Limit size
	RAMLimit  = 1 * 1024 * 1024   // 1 MB - store in memory
	DiskLimit = 100 * 1024 * 1024 // 100 MB - maximum file size

	// TTL
	RAMTTL  = 30 * time.Minute // Time to live in memory
	DiskTTL = 1 * time.Hour    // Time to live on disk

	// Paths
	VaultPath = "/tmp/lastchance_vault" // Temporary storage

	// Cleanup
	CleanupInterval = 5 * time.Minute

	// Header guard
)

var (
	// Global variables for protection, initialized in main()
	effectiveHeaderName  string
	effectiveHeaderValue string
)

// FileEntry - record of a file in storage
type FileEntry struct {
	Data       []byte    // Data for RAM files
	FilePath   string    // Path for Disk files
	Size       int64     // File size
	IsDisk     bool      // true = on disk, false = in memory
	CreatedAt  time.Time // Creation time
	Downloaded bool      // Has it been downloaded?
}

// FileStore - manages file storage in memory and on disk with thread safety
type FileStore struct {
	mu    sync.RWMutex
	files map[string]*FileEntry // key = fileHash
}

func NewFileStore() *FileStore {
	return &FileStore{
		files: make(map[string]*FileEntry),
	}
}

// SaveToRAM - saves file in memory
func (fs *FileStore) SaveToRAM(fileHash string, data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Copy data
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	now := time.Now().UTC()
	fs.files[fileHash] = &FileEntry{
		Data:       dataCopy,
		Size:       int64(len(data)),
		IsDisk:     false,
		CreatedAt:  now,
		Downloaded: false,
	}

	return nil
}

// SaveToDisk - saves file on disk
func (fs *FileStore) SaveToDisk(fileHash string, reader io.Reader, size int64) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(VaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp(VaultPath, "file-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Copy data
	written, err := io.Copy(tmpFile, reader)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}

	if written != size {
		tmpFile.Close()
		return fmt.Errorf("size mismatch: expected %d, wrote %d", size, written)
	}

	// Sync to disk
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Close before renaming
	tmpFile.Close()

	finalPath := filepath.Join(VaultPath, fileHash+".bin")
	if err := os.Rename(tmpFile.Name(), finalPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	//We set rights only for the owner
	os.Chmod(finalPath, 0600)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now().UTC()
	fs.files[fileHash] = &FileEntry{
		FilePath:   finalPath,
		Size:       size,
		IsDisk:     true,
		CreatedAt:  now,
		Downloaded: false,
	}

	return nil
}

// Get - retrieves a file
func (fs *FileStore) Get(fileHash string) (*FileEntry, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	entry, exists := fs.files[fileHash]
	if !exists {
		return nil, errors.New("file not found")
	}

	entry.Downloaded = true

	return entry, nil
}

// Delete - deletes a file with shredding
func (fs *FileStore) Delete(fileHash string) {
	fs.mu.Lock()
	entry, exists := fs.files[fileHash]
	if exists {
		delete(fs.files, fileHash)
	}
	fs.mu.Unlock()

	if !exists {
		return
	}

	// If the file is on disk, overwrite it using shred
	if entry.IsDisk && entry.FilePath != "" {
		// We try to use shred if available
		if _, err := exec.LookPath("shred"); err == nil {
			cmd := exec.Command("shred", "-u", "-n", "3", entry.FilePath)
			if err := cmd.Run(); err != nil {
				log.Printf("Shred failed for %s: %v, falling back to remove", fileHash[:8], err)
				os.Remove(entry.FilePath)
			}
		} else {
			// Fallback - easy removal
			os.Remove(entry.FilePath)
		}
	}
}

// Cleanup - cleans outdated files
func (fs *FileStore) Cleanup() int {
	now := time.Now().UTC()
	removed := 0
	toDelete := make([]string, 0)

	fs.mu.Lock()
	for hash, entry := range fs.files {
		shouldRemove := false

		if entry.Downloaded {
			// Delete immediately after downloading
			shouldRemove = true
		} else if entry.IsDisk && now.Sub(entry.CreatedAt) > DiskTTL {
			shouldRemove = true
		} else if !entry.IsDisk && now.Sub(entry.CreatedAt) > RAMTTL {
			shouldRemove = true
		}

		if shouldRemove {
			delete(fs.files, hash)
			removed++

			if entry.IsDisk && entry.FilePath != "" {
				toDelete = append(toDelete, entry.FilePath)
			}
		}
	}
	fs.mu.Unlock()

	// Asynchronously deleting files from disk
	for _, path := range toDelete {
		go func(p string) {
			if _, err := exec.LookPath("shred"); err == nil {
				exec.Command("shred", "-u", "-n", "10", p).Run()
			} else {
				os.Remove(p)
			}
		}(path)
	}

	return removed
}

// RateLimiter - brute force protection
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
		// 5 requests per second, burst 10
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

// Server - file server
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

// getClientIP - retrieves client IP
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

// checkGuard - checks the guard header
func checkGuard(r *http.Request) bool {
	// If the variables are not set (e.g., forgot to set .env),
	// by default access will be closed for all for security reasons
	if effectiveHeaderName == "" || effectiveHeaderValue == "" {
		return false
	}
	return r.Header.Get(effectiveHeaderName) == effectiveHeaderValue
}

// generateFileHash - generates a hash for a file
func generateFileHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// UploadHandler - POST /file-api/upload
func (s *Server) UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check the guard header
	if !checkGuard(r) {
		log.Printf("REJECTED: missing guard header from %s", getClientIP(r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Rate limiting
	ip := getClientIP(r)
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Check Content-Length
	if r.ContentLength <= 0 {
		http.Error(w, "Missing Content-Length", http.StatusLengthRequired)
		return
	}

	if r.ContentLength > DiskLimit {
		log.Printf("REJECTED: file too large (%d bytes) from %s", r.ContentLength, ip)
		http.Error(w, fmt.Sprintf("File too large: max %d bytes", DiskLimit),
			http.StatusRequestEntityTooLarge)
		return
	}

	// Read the request body with a limit
	var buf bytes.Buffer
	written, err := io.CopyN(&buf, r.Body, DiskLimit+1)
	if err != nil && err != io.EOF {
		log.Printf("ERROR: read failed from %s: %v", ip, err)
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}

	if written != r.ContentLength {
		log.Printf("REJECTED: size mismatch (expected %d, got %d) from %s",
			r.ContentLength, written, ip)
		http.Error(w, "Size mismatch", http.StatusBadRequest)
		return
	}

	data := buf.Bytes()
	fileHash := generateFileHash(data)

	// Save depending on size
	if len(data) <= RAMLimit {
		if err := s.store.SaveToRAM(fileHash, data); err != nil {
			log.Printf("ERROR: RAM save failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("UPLOADED: %d bytes to RAM (hash: %s) from %s",
			len(data), fileHash[:8], ip)
	} else {
		reader := bytes.NewReader(data)
		if err := s.store.SaveToDisk(fileHash, reader, int64(len(data))); err != nil {
			log.Printf("ERROR: Disk save failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("UPLOADED: %d bytes to DISK (hash: %s) from %s",
			len(data), fileHash[:8], ip)
	}

	// Return the hash to the client
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fileHash))
}

// DownloadHandler - GET /file-api/download/{hash}
func (s *Server) DownloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check the guard header
	if !checkGuard(r) {
		log.Printf("REJECTED: missing guard header from %s", getClientIP(r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Rate limiting
	ip := getClientIP(r)
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Extract the hash from the path (nginx proxies /file-api/download/xxx to /download/xxx)
	path := r.URL.Path
	hash := strings.TrimPrefix(path, "/download/")
	if hash == "" || hash == path {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	// Get the file
	entry, err := s.store.Get(hash)
	if err != nil {
		log.Printf("NOT FOUND: hash %s from %s", hash[:8], ip)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	var data []byte

	if entry.IsDisk {
		// Read from disk
		data, err = os.ReadFile(entry.FilePath)
		if err != nil {
			log.Printf("ERROR: read disk file failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	} else {
		// Serve from memory
		data = entry.Data
	}

	// Delete the file after delivery (one-time download)
	go s.store.Delete(hash)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)

	log.Printf("DOWNLOADED: %d bytes (hash: %s) to %s", len(data), hash[:8], ip)
}

// InfoHandler - HEAD /file-api/info/{hash} - liveness check
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

	path := r.URL.Path
	hash := strings.TrimPrefix(path, "/info/")
	if hash == "" || hash == path {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	s.store.mu.RLock()
	entry, exists := s.store.files[hash]
	s.store.mu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", entry.Size))
	w.Header().Set("X-File-Storage", map[bool]string{true: "disk", false: "ram"}[entry.IsDisk])
	w.WriteHeader(http.StatusOK)
}

// PingHandler - liveness check
func (s *Server) PingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// startCleanupWorker - background cleaning
func (s *Server) startCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	// First cleaning a minute after start
	time.Sleep(1 * time.Minute)

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
	// --- Environment Variables Initialization ---
	// Fetching values from .env (passed via Docker)

	effectiveHeaderName = os.Getenv("STEALTH_HEADER_NAME")
	effectiveHeaderValue = os.Getenv("STEALTH_HEADER_VALUE")

	// Critical check: stop if security credentials are missing
	if effectiveHeaderName == "" || effectiveHeaderValue == "" {
		log.Fatalf("CRITICAL: Stealth security headers (STEALTH_HEADER_NAME/VALUE) not set in environment")
	}

	// --- Directory Setup ---
	// Create vault directory if it doesn't exist
	if err := os.MkdirAll(VaultPath, 0700); err != nil {
		log.Fatalf("FAILED: Could not create vault directory [%s]: %v", VaultPath, err)
	}

	// --- Startup Cleanup ---
	// Purge stale data from previous sessions
	log.Printf("STARTUP: Purging old data in %s", VaultPath)
	cleanupPatterns := []string{"*.bin", "*.tmp"}
	for _, pattern := range cleanupPatterns {
		files, _ := filepath.Glob(filepath.Join(VaultPath, pattern))
		for _, f := range files {
			os.Remove(f)
		}
	}

	server := NewServer()

	// --- Router Configuration ---
	// Note: Caddy proxies /file-api/* to these internal endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("POST /upload", server.UploadHandler)
	mux.HandleFunc("GET /download/", server.DownloadHandler)
	mux.HandleFunc("HEAD /info/", server.InfoHandler)
	mux.HandleFunc("GET /info/", server.InfoHandler)
	mux.HandleFunc("GET /ping", server.PingHandler)

	httpServer := &http.Server{
		Addr:           ":8081", // Internal port for Docker network
		Handler:        mux,
		ReadTimeout:    60 * time.Second,  // Increased for large file uploads
		WriteTimeout:   120 * time.Second, // Increased for downloads
		IdleTimeout:    180 * time.Second,
		MaxHeaderBytes: 1 << 12,
	}

	// --- Graceful Shutdown Setup ---
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Launch cleanup worker to manage file TTLs
	go server.startCleanupWorker(ctx)

	// --- Server Start ---
	go func() {
		log.Printf("SUCCESS: File Relay Service active on :8081")
		log.Printf("RESOURCE LIMITS: RAM: %d MB, Disk: %d MB", RAMLimit/(1024*1024), DiskLimit/(1024*1024))
		log.Printf("STORAGE PATH: %s", VaultPath)
		log.Printf("STEALTH MODE: Guarding with header [%s]", effectiveHeaderName)

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("FATAL: Server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("SHUTDOWN: Signal received, stopping services...")

	// Force shutdown after 15 seconds if requests are hanging
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("ERROR: Shutdown failure: %v", err)
	}

	// --- Final Secure Cleanup ---
	// Use 'shred' if available for secure file deletion on disk
	log.Println("CLEANUP: Securely erasing vault files...")
	files, _ := filepath.Glob(filepath.Join(VaultPath, "*.bin"))
	for _, f := range files {
		if _, err := exec.LookPath("shred"); err == nil {
			// 3 passes overwriting before deleting
			exec.Command("shred", "-u", "-n", "3", f).Run()
		} else {
			os.Remove(f)
		}
	}

	log.Println("EXIT: Last Chance Server stopped")
}
