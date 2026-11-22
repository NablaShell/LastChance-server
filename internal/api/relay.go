package api

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NablaShell/LastChance-server/internal/auth"
	"github.com/NablaShell/LastChance-server/internal/middleware"
	"github.com/NablaShell/LastChance-server/internal/store"
)

// Text packet buckets produced by the client: a bucket plus up to bucket/8
// bytes of random in-bucket padding.
const (
	sizeVeryTiny = 256
	sizeTiny     = 1024
	sizeSmall    = 4096
	sizeMax      = 65536

	sizePaddingDivisor = 8
	maxPacketSize      = sizeMax + sizeMax/sizePaddingDivisor
)

var allowedPacketSizes = [...]int64{sizeVeryTiny, sizeTiny, sizeSmall, sizeMax}

func isValidPacketSize(size int64) bool {
	for _, bucket := range allowedPacketSizes {
		if size >= bucket && size <= bucket+bucket/sizePaddingDivisor {
			return true
		}
	}
	return false
}

// RelayOptions configures the relay listener.
type RelayOptions struct {
	Queues             store.QueueStore
	Auth               *auth.Verifier
	Notifier           *Notifier
	MaxBodyBytes       int64
	PullTimeout        time.Duration
	MaxConcurrentPulls int
	GuardHeader        string
	GuardValue         string
	TrustedProxies     []*net.IPNet
	RateLimiter        *middleware.RateLimiter
	Logger             *slog.Logger
}

type relayServer struct {
	queues      store.QueueStore
	auth        *auth.Verifier
	notifier    *Notifier
	maxBody     int64
	pullTimeout time.Duration
	pullSem     chan struct{}
	logger      *slog.Logger
}

// NewRelayMux builds the relay HTTP handler. /healthz is deliberately outside
// the guard and rate limiter so container health checks work without secrets.
func NewRelayMux(opts RelayOptions) http.Handler {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 1 << 20
	}
	if opts.PullTimeout <= 0 {
		opts.PullTimeout = 30 * time.Second
	}
	if opts.MaxConcurrentPulls <= 0 {
		opts.MaxConcurrentPulls = 64
	}
	if opts.Notifier == nil {
		opts.Notifier = NewNotifier()
	}
	if opts.RateLimiter == nil {
		opts.RateLimiter = middleware.DefaultRateLimiter()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	server := &relayServer{
		queues:      opts.Queues,
		auth:        opts.Auth,
		notifier:    opts.Notifier,
		maxBody:     opts.MaxBodyBytes,
		pullTimeout: opts.PullTimeout,
		pullSem:     make(chan struct{}, opts.MaxConcurrentPulls),
		logger:      opts.Logger,
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /push/{target_hash}", server.handlePush)
	apiMux.HandleFunc("GET /pull/{target_hash}", server.handlePull)

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

func (s *relayServer) handlePush(w http.ResponseWriter, r *http.Request) {
	targetHash := strings.TrimSpace(r.PathValue("target_hash"))
	if targetHash == "" {
		http.Error(w, "Missing recipient", http.StatusBadRequest)
		return
	}

	if r.ContentLength < 0 {
		http.Error(w, "Invalid Payload Size", http.StatusBadRequest)
		return
	}
	if r.ContentLength > s.maxBody {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !isValidPacketSize(r.ContentLength) {
		http.Error(w, "Invalid Payload Size", http.StatusBadRequest)
		return
	}

	body := http.MaxBytesReader(w, r.Body, s.maxBody)
	payload, err := io.ReadAll(io.LimitReader(body, maxPacketSize+1))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Payload read error", http.StatusBadRequest)
		return
	}
	if int64(len(payload)) != r.ContentLength {
		http.Error(w, "Payload size mismatch", http.StatusBadRequest)
		return
	}

	if err := s.auth.VerifyRequest(r, payload); err != nil {
		writeAuthError(w, err)
		return
	}

	if err := s.queues.Push(targetHash, payload); err != nil {
		if errors.Is(err, store.ErrQueueFull) {
			http.Error(w, "Queue full", http.StatusTooManyRequests)
			return
		}
		s.logger.Error("queue push failed", "error", err, "recipient", shortHash(targetHash))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	s.notifier.Notify(targetHash)
	s.logger.Info("push accepted", "recipient", shortHash(targetHash), "bytes", len(payload))
	w.WriteHeader(http.StatusOK)
}

func (s *relayServer) handlePull(w http.ResponseWriter, r *http.Request) {
	targetHash := strings.TrimSpace(r.PathValue("target_hash"))
	if targetHash == "" {
		http.Error(w, "Missing recipient", http.StatusBadRequest)
		return
	}

	if err := s.auth.VerifyRequest(r, nil); err != nil {
		writeAuthError(w, err)
		return
	}
	identity := strings.TrimSpace(r.Header.Get(auth.HeaderIdentity))
	if !auth.EqualFoldConstantTime(identity, targetHash) {
		http.Error(w, auth.AuthRejectedBody, http.StatusUnauthorized)
		return
	}

	wait := parseLongPollWait(r, s.pullTimeout)

	// Subscribe before checking the queue: a push between the check and the
	// wait leaves a buffered signal, so the waiter still wakes up.
	notifyCh, unsubscribe := s.notifier.Subscribe(targetHash)
	defer unsubscribe()

	payloads, err := s.queues.Pull(targetHash)
	if err != nil {
		s.logger.Error("queue pull failed", "error", err, "recipient", shortHash(targetHash))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if len(payloads) > 0 {
		s.writePackages(w, targetHash, payloads)
		return
	}
	if wait <= 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Bound the number of requests that actually hold a long poll. Emerging
	// clients get a retryable 503 instead of unbounded goroutines.
	select {
	case s.pullSem <- struct{}{}:
		defer func() { <-s.pullSem }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too many waiting pulls", http.StatusServiceUnavailable)
		return
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		payloads, err := s.queues.Pull(targetHash)
		if err != nil {
			s.logger.Error("queue pull failed", "error", err, "recipient", shortHash(targetHash))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if len(payloads) > 0 {
			s.writePackages(w, targetHash, payloads)
			return
		}

		select {
		case <-notifyCh:
			// Re-check; another puller may have drained a stale signal.
		case <-timer.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			w.WriteHeader(499)
			return
		}
	}
}

func parseLongPollWait(r *http.Request, maximum time.Duration) time.Duration {
	raw := strings.TrimSpace(r.URL.Query().Get("wait"))
	if raw == "" {
		return 0
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return 0
	}
	wait := time.Duration(seconds) * time.Second
	if wait > maximum {
		return maximum
	}
	return wait
}

func (s *relayServer) writePackages(w http.ResponseWriter, targetHash string, payloads [][]byte) {
	writer := multipart.NewWriter(w)
	w.Header().Set("Content-Type", writer.FormDataContentType())

	for i, payload := range payloads {
		part, err := writer.CreateFormFile(
			fmt.Sprintf("package_%d", i),
			fmt.Sprintf("package_%d_size_%d.bin", i, len(payload)),
		)
		if err != nil {
			s.logger.Error("multipart create failed", "error", err)
			return
		}
		if _, err := part.Write(payload); err != nil {
			s.logger.Error("multipart write failed", "error", err)
			return
		}
	}
	if err := writer.Close(); err != nil {
		s.logger.Error("multipart close failed", "error", err)
		return
	}
	s.logger.Info("pull delivered", "recipient", shortHash(targetHash), "packages", len(payloads))
}

func writeAuthError(w http.ResponseWriter, err error) {
	http.Error(w, auth.AuthRejectedBody, auth.Status(err))
}

func shortHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16]
	}
	return hash
}
