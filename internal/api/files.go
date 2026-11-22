package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/NablaShell/LastChance-server/internal/auth"
	"github.com/NablaShell/LastChance-server/internal/middleware"
	"github.com/NablaShell/LastChance-server/internal/store"
)

// FilesOptions configures the file listener.
type FilesOptions struct {
	Files          store.FileStore
	Auth           *auth.Verifier
	MaxFileBytes   int64
	GuardHeader    string
	GuardValue     string
	TrustedProxies []*net.IPNet
	RateLimiter    *middleware.RateLimiter
	Logger         *slog.Logger
}

type filesServer struct {
	files   store.FileStore
	auth    *auth.Verifier
	maxFile int64
	logger  *slog.Logger
}

// NewFilesMux builds the file HTTP handler. /healthz is deliberately outside
// the guard and rate limiter.
func NewFilesMux(opts FilesOptions) http.Handler {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 128 << 20
	}
	if opts.RateLimiter == nil {
		opts.RateLimiter = middleware.DefaultRateLimiter()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	server := &filesServer{
		files:   opts.Files,
		auth:    opts.Auth,
		maxFile: opts.MaxFileBytes,
		logger:  opts.Logger,
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /upload", server.handleUpload)
	apiMux.HandleFunc("GET /download/{id}", server.handleDownload)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", healthz)
	root.Handle("/", middleware.Chain(
		apiMux,
		middleware.RequestID,
		middleware.Logger(opts.Logger),
		middleware.Guard(opts.GuardHeader, opts.GuardValue),
		middleware.RateLimit(opts.RateLimiter, opts.TrustedProxies),
	))
	return root
}

func (s *filesServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength < 0 {
		http.Error(w, "Missing Content-Length", http.StatusLengthRequired)
		return
	}
	if r.ContentLength == 0 {
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return
	}
	if r.ContentLength > s.maxFile {
		http.Error(w, fmt.Sprintf("File too large: max %d bytes", s.maxFile), http.StatusRequestEntityTooLarge)
		return
	}

	temp, err := s.files.CreateTemp()
	if err != nil {
		s.logger.Error("create temp upload failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	hasher := sha256.New()
	body := http.MaxBytesReader(w, r.Body, s.maxFile+1)
	written, copyErr := io.Copy(io.MultiWriter(temp, hasher), body)
	if copyErr == nil {
		copyErr = temp.Sync()
	}
	closeErr := temp.Close()

	if copyErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(copyErr, &maxErr) {
			http.Error(w, fmt.Sprintf("File too large: max %d bytes", s.maxFile), http.StatusRequestEntityTooLarge)
			return
		}
		s.logger.Error("read upload failed", "error", copyErr)
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	if closeErr != nil {
		s.logger.Error("close upload failed", "error", closeErr)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if written != r.ContentLength {
		http.Error(w, "Size mismatch", http.StatusBadRequest)
		return
	}

	id := hex.EncodeToString(hasher.Sum(nil))
	if err := s.auth.VerifyRequestWithBodyHash(r, id); err != nil {
		writeAuthError(w, err)
		return
	}

	if err := s.files.Commit(id, tempPath, written, time.Now().UTC()); err != nil {
		s.logger.Error("commit upload failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	committed = true

	s.logger.Info("upload stored", "id", shortHash(id), "bytes", written)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, id)
}

func (s *filesServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !store.ValidFileID(id) {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	if err := s.auth.VerifyRequest(r, nil); err != nil {
		writeAuthError(w, err)
		return
	}

	meta, err := s.files.Take(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		s.logger.Error("take file metadata failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	file, err := s.files.Open(id)
	if err != nil {
		_ = s.files.Restore(id, meta)
		s.logger.Error("open file failed", "error", err, "id", shortHash(id))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		s.logger.Error("write download failed", "error", err, "id", shortHash(id))
	}

	if err := s.files.Remove(id); err != nil {
		s.logger.Error("remove delivered file failed", "error", err, "id", shortHash(id))
	}
	s.logger.Info("download delivered", "id", shortHash(id), "bytes", meta.Size)
}
