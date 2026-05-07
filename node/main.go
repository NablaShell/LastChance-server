package main

import (
	"crypto/ed25519"
	"crypto/sha256"
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
	"sync"
	"syscall"
	"time"
	"context"

	_ "modernc.org/sqlite"
	"golang.org/x/time/rate"
)

// --- Константы по ТЗ ---

const (
	// Сетка разрешённых размеров пакетов
	SizeVeryTiny = 256
	SizeTiny     = 1024
	SizeSmall    = 4096
	SizeMax      = 65536

	MaxMessagesPerHash = 100
	MessageTTL         = 24 * time.Hour
	CleanupInterval    = 10 * time.Minute
	MaxTimestampDiff   = 60 // секунд, защита от повторов
)

// allowedSizes — карта для быстрой проверки O(1)
var allowedSizes = map[int]bool{
	SizeVeryTiny: true,
	SizeTiny:     true,
	SizeSmall:    true,
	SizeMax:      true,
}

// --- База данных в памяти ---

type DB struct {
	conn *sql.DB
}

func NewDB() (*DB, error) {
	// mode=memory — чистая RAM, без файла
	// _journal_mode=WAL — конкурентный доступ
	conn, err := sql.Open("sqlite", ":memory:?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Включаем WAL (в памяти это не обязательно, но для привычки)
	conn.Exec("PRAGMA journal_mode=WAL;")
	conn.Exec("PRAGMA busy_timeout=5000;")

	// Создаём таблицу строго по ТЗ
	query := `
	CREATE TABLE IF NOT EXISTS queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_hash TEXT NOT NULL,
		payload BLOB NOT NULL,
		size INTEGER NOT NULL,
		created_at DATETIME DEFAULT (datetime('now'))
	);
	CREATE INDEX IF NOT EXISTS idx_target_hash ON queue(target_hash);
	CREATE INDEX IF NOT EXISTS idx_created_at ON queue(created_at);
	`
	if _, err := conn.Exec(query); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &DB{conn: conn}, nil
}

// SavePackage сохраняет пакет в очередь получателя
func (db *DB) SavePackage(targetHash string, payload []byte, size int) error {
	// Проверяем лимит очереди для этого хеша
	var count int
	err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM queue WHERE target_hash = ?",
		targetHash,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("count queue: %w", err)
	}
	if count >= MaxMessagesPerHash {
		return errors.New("queue full")
	}

	// Вставляем пакет
	_, err = db.conn.Exec(
		"INSERT INTO queue (target_hash, payload, size) VALUES (?, ?, ?)",
		targetHash, payload, size,
	)
	if err != nil {
		return fmt.Errorf("insert package: %w", err)
	}
	return nil
}

// PullPackages атомарно забирает и удаляет пакеты для хеша
// Возвращает слайс payload'ов и их размеры
func (db *DB) PullPackages(targetHash string) ([][]byte, []int, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Читаем всё для этого хеша
	rows, err := tx.Query(
		"SELECT payload, size FROM queue WHERE target_hash = ? ORDER BY id ASC",
		targetHash,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("select packages: %w", err)
	}
	defer rows.Close()

	var payloads [][]byte
	var sizes []int

	for rows.Next() {
		var payload []byte
		var size int
		if err := rows.Scan(&payload, &size); err != nil {
			return nil, nil, fmt.Errorf("scan package: %w", err)
		}
		payloads = append(payloads, payload)
		sizes = append(sizes, size)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("rows iteration: %w", err)
	}

	// Удаляем всё для этого хеша
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

// Cleanup удаляет старые пакеты (старше TTL)
func (db *DB) Cleanup(olderThan time.Time) (int64, error) {
	result, err := db.conn.Exec(
		"DELETE FROM queue WHERE created_at < ?",
		olderThan.UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup: %w", err)
	}
	removed, _ := result.RowsAffected()
	return removed, nil
}

// Close закрывает соединение с БД
func (db *DB) Close() error {
	return db.conn.Close()
}

// --- Криптография и авторизация ---

// verifyAuth проверяет подпись Ed25519 по ТЗ
func verifyAuth(identityKeyHex, timestampStr, signatureHex, targetHash string) error {
	// 1. Проверка времени (±60 секунд)
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

	// 2. Декодируем публичный ключ из hex
	pubKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key format")
	}

	// 3. Проверяем соответствие хеша
	hash := sha256.Sum256(pubKey)
	computedHash := hex.EncodeToString(hash[:])
	if computedHash != targetHash {
		return errors.New("identity key does not match target hash")
	}

	// 4. Формируем сообщение: timestamp + identity_hash
	message := fmt.Sprintf("%s%s", timestampStr, targetHash)

	// 5. Декодируем подпись
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature format")
	}

	// 6. Проверяем Ed25519 подпись
	if !ed25519.Verify(pubKey, []byte(message), signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// --- Rate Limiter ---

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
		// 5 запросов в секунду с burst 10
		l = rate.NewLimiter(rate.Limit(5), 10)
		rl.limiters[ip] = l
	}
	return l.Allow()
}

// Очистка старых лимитеров каждые 10 минут
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	// Можно реализовать удаление давно неактивных IP
	// Пока оставляем как есть
}

// --- HTTP Server ---

type Server struct {
	db          *DB
	rateLimiter *RateLimiter
}

// handlePush — POST /push/{target_hash}
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	targetHash := r.PathValue("target_hash")
	ip := getClientIP(r)

	// Проверка размера по сетке
	if !allowedSizes[int(r.ContentLength)] {
		log.Printf("[PUSH] %s: invalid size %d", ip, r.ContentLength)
		http.Error(w, "Invalid Payload Size", http.StatusBadRequest)
		return
	}

	// Читаем тело
	payload, err := io.ReadAll(io.LimitReader(r.Body, SizeMax+1))
	if err != nil {
		log.Printf("[PUSH] %s: read error: %v", ip, err)
		http.Error(w, "Payload read error", http.StatusBadRequest)
		return
	}

	if len(payload) != int(r.ContentLength) {
		log.Printf("[PUSH] %s: size mismatch", ip)
		http.Error(w, "Payload size mismatch", http.StatusBadRequest)
		return
	}

	// Rate limiting
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Сохраняем в БД
	size := len(payload)
	if err := s.db.SavePackage(targetHash, payload, size); err != nil {
		if err.Error() == "queue full" {
			http.Error(w, "Queue full", http.StatusTooManyRequests)
			return
		}
		log.Printf("[PUSH] %s: db error: %v", ip, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[PUSH] %s: ACCEPTED %d bytes to bucket %s", ip, size, targetHash[:16])
	w.WriteHeader(http.StatusOK)
}

// handlePull — GET /pull/{target_hash}
func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	targetHash := r.PathValue("target_hash")
	ip := getClientIP(r)

	// Читаем заголовки авторизации
	identityKey := r.Header.Get("X-Identity-Key")
	timestamp := r.Header.Get("X-Timestamp")
	signature := r.Header.Get("X-Signature")

	// Проверка авторизации
	if err := verifyAuth(identityKey, timestamp, signature, targetHash); err != nil {
		log.Printf("[PULL] %s: auth failed: %v", ip, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Rate limiting
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Забираем пакеты из БД
	payloads, sizes, err := s.db.PullPackages(targetHash)
	if err != nil {
		log.Printf("[PULL] %s: db error: %v", ip, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Если нет пакетов — 204 No Content
	if len(payloads) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Формируем multipart ответ
	writer := multipart.NewWriter(w)
	w.Header().Set("Content-Type", writer.FormDataContentType())

	for i, payload := range payloads {
		part, err := writer.CreateFormFile(
			fmt.Sprintf("package_%d", i),
			fmt.Sprintf("package_%d_size_%d.bin", i, sizes[i]),
		)
		if err != nil {
			log.Printf("[PULL] %s: multipart error: %v", ip, err)
			http.Error(w, "Response formatting error", http.StatusInternalServerError)
			return
		}
		if _, err := part.Write(payload); err != nil {
			log.Printf("[PULL] %s: write part error: %v", ip, err)
			return
		}
	}

	if err := writer.Close(); err != nil {
		log.Printf("[PULL] %s: close multipart error: %v", ip, err)
	}

	log.Printf("[PULL] %s: DELIVERED %d packages to bucket %s",
		ip, len(payloads), targetHash[:16],
	)
}

// handlePing — проверка здоровья сервера
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong"))
}

// --- Вспомогательные функции ---

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// --- Main ---

func main() {
	// Инициализация БД в памяти
	db, err := NewDB()
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}
	defer db.Close()

	// Сервер
	server := &Server{
		db:          db,
		rateLimiter: NewRateLimiter(),
	}

	// Роутинг
	mux := http.NewServeMux()
	// main.go серверного нода — меняем только роутинг
	mux.HandleFunc("POST /api-v1/push/{target_hash}", server.handlePush)
	mux.HandleFunc("GET /api-v1/pull/{target_hash}", server.handlePull)
	mux.HandleFunc("GET /api-v1/ping", server.handlePing)

	httpSrv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Контекст для graceful shutdown
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	// Фоновая очистка старых пакетов
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

	// Запуск сервера
	log.Println("NablaShell Relay Node starting on :8080")
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Ожидание сигнала
	<-ctx.Done()
	log.Println("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
