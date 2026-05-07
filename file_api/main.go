// main.go - File Relay Service for Messenger Last Chance
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
	// Размерные лимиты
	RAMLimit    = 1 * 1024 * 1024   // 1 MB - храним в памяти
	DiskLimit   = 100 * 1024 * 1024 // 100 MB - максимальный размер файла
	
	// TTL
	RAMTTL  = 30 * time.Minute // Время жизни в памяти
	DiskTTL = 1 * time.Hour    // Время жизни на диске
	
	// Пути
	VaultPath = "/tmp/lastchance_vault" // Временное хранилище
	
	// Очистка
	CleanupInterval = 5 * time.Minute
	
	// Заголовок-оберег
	HeaderGuard = "X-DNS-Connect"
)

// FileEntry - запись о файле в хранилище
type FileEntry struct {
	Data       []byte    // Данные для RAM-файлов
	FilePath   string    // Путь для Disk-файлов
	Size       int64     // Размер файла
	IsDisk     bool      // true = на диске, false = в памяти
	CreatedAt  time.Time // Время создания
	Downloaded bool      // Был ли скачан
}

// FileStore - хранилище файлов
type FileStore struct {
	mu    sync.RWMutex
	files map[string]*FileEntry // key = fileHash
}

func NewFileStore() *FileStore {
	return &FileStore{
		files: make(map[string]*FileEntry),
	}
}

// SaveToRAM - сохраняет файл в памяти
func (fs *FileStore) SaveToRAM(fileHash string, data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	// Копируем данные
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

// SaveToDisk - сохраняет файл на диск
func (fs *FileStore) SaveToDisk(fileHash string, reader io.Reader, size int64) error {
	// Создаём директорию если нет
	if err := os.MkdirAll(VaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}
	
	// Создаём временный файл
	tmpFile, err := os.CreateTemp(VaultPath, "file-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	
	// Копируем данные
	written, err := io.Copy(tmpFile, reader)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	if written != size {
		tmpFile.Close()
		return fmt.Errorf("size mismatch: expected %d, wrote %d", size, written)
	}
	
	// Синхронизируем на диск
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync file: %w", err)
	}
	
	// Закрываем перед переименованием
	tmpFile.Close()
	
	finalPath := filepath.Join(VaultPath, fileHash+".bin")
	if err := os.Rename(tmpFile.Name(), finalPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}
	
	// Устанавливаем права только для владельца
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

// Get - получает файл
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

// Delete - удаляет файл с затиркой
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
	
	// Если файл на диске - затираем через shred
	if entry.IsDisk && entry.FilePath != "" {
		// Пытаемся использовать shred, если есть
		if _, err := exec.LookPath("shred"); err == nil {
			cmd := exec.Command("shred", "-u", "-n", "3", entry.FilePath)
			if err := cmd.Run(); err != nil {
				log.Printf("Shred failed for %s: %v, falling back to remove", fileHash[:8], err)
				os.Remove(entry.FilePath)
			}
		} else {
			// Fallback - простое удаление
			os.Remove(entry.FilePath)
		}
	}
}

// Cleanup - очищает устаревшие файлы
func (fs *FileStore) Cleanup() int {
	now := time.Now().UTC()
	removed := 0
	toDelete := make([]string, 0)
	
	fs.mu.Lock()
	for hash, entry := range fs.files {
		shouldRemove := false
		
		if entry.Downloaded {
			// Удаляем сразу после скачивания
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
	
	// Асинхронно удаляем файлы с диска
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

// RateLimiter - защита от перебора
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
		// 5 запросов в секунду, burst 10
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

// Server - файловый сервер
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

// getClientIP - извлекает IP клиента
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

// checkGuard - проверяет защитный заголовок
func checkGuard(r *http.Request) bool {
	return r.Header.Get(HeaderGuard) == "We_Are_Not_Legion"
}

// generateFileHash - генерирует хеш для файла
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
	
	// Проверяем защитный заголовок
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
	
	// Проверяем Content-Length
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
	
	// Читаем тело запроса с ограничением
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
	
	// Сохраняем в зависимости от размера
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
	
	// Возвращаем хеш клиенту
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
	
	// Проверяем защитный заголовок
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
	
	// Извлекаем хеш из пути (nginx проксирует /file-api/download/xxx в /download/xxx)
	path := r.URL.Path
	hash := strings.TrimPrefix(path, "/download/")
	if hash == "" || hash == path {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}
	
	// Получаем файл
	entry, err := s.store.Get(hash)
	if err != nil {
		log.Printf("NOT FOUND: hash %s from %s", hash[:8], ip)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	var data []byte
	
	if entry.IsDisk {
		// Читаем с диска
		data, err = os.ReadFile(entry.FilePath)
		if err != nil {
			log.Printf("ERROR: read disk file failed: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	} else {
		// Отдаём из памяти
		data = entry.Data
	}
	
	// Удаляем файл после отдачи (one-time download)
	go s.store.Delete(hash)
	
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	
	log.Printf("DOWNLOADED: %d bytes (hash: %s) to %s", len(data), hash[:8], ip)
}

// InfoHandler - HEAD /file-api/info/{hash} - проверка существования
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

// PingHandler - проверка живости
func (s *Server) PingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// startCleanupWorker - фоновая очистка
func (s *Server) startCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()
	
	// Первая очистка через минуту после старта
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
	// Создаём директорию для файлов
	if err := os.MkdirAll(VaultPath, 0700); err != nil {
		log.Fatalf("Failed to create vault directory: %v", err)
	}
	
	// Очищаем старые файлы при старте
	files, _ := filepath.Glob(filepath.Join(VaultPath, "*.bin"))
	for _, f := range files {
		os.Remove(f)
	}
	files, _ = filepath.Glob(filepath.Join(VaultPath, "*.tmp"))
	for _, f := range files {
		os.Remove(f)
	}
	
	server := NewServer()
	
	// Роутер - nginx будет проксировать /file-api/* на наши эндпоинты
	mux := http.NewServeMux()
	mux.HandleFunc("POST /upload", server.UploadHandler)
	mux.HandleFunc("GET /download/", server.DownloadHandler)
	mux.HandleFunc("HEAD /info/", server.InfoHandler)
	mux.HandleFunc("GET /info/", server.InfoHandler)
	mux.HandleFunc("GET /ping", server.PingHandler)
	
	httpServer := &http.Server{
		Addr:           ":8081", // Только localhost
		Handler:        mux,
		ReadTimeout:    60 * time.Second,  // Увеличено для больших файлов
		WriteTimeout:   120 * time.Second, // Увеличено для отдачи
		IdleTimeout:    180 * time.Second,
		MaxHeaderBytes: 1 << 12,
	}
	
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()
	
	go server.startCleanupWorker(ctx)
	
	go func() {
		log.Printf("File Relay Service started on 127.0.0.1:8081")
		log.Printf("RAM limit: %d MB, Disk limit: %d MB", RAMLimit/(1024*1024), DiskLimit/(1024*1024))
		log.Printf("Vault: %s", VaultPath)
		log.Printf("Endpoints: /upload, /download/{hash}, /info/{hash}")
		
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	
	<-ctx.Done()
	log.Println("Shutting down...")
	
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	
	// Финальная очистка
	log.Println("Final cleanup...")
	files, _ = filepath.Glob(filepath.Join(VaultPath, "*.bin"))
	for _, f := range files {
		if _, err := exec.LookPath("shred"); err == nil {
			exec.Command("shred", "-u", "-n", "3", f).Run()
		} else {
			os.Remove(f)
		}
	}
	
	log.Println("Server stopped")
}
