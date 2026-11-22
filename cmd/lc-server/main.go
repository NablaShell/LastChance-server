// Command lc-server runs the LastChance relay and file listeners in one
// process. Relay defaults to 127.0.0.1:8080; files defaults to 127.0.0.1:8081.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/NablaShell/LastChance-server/internal/api"
	"github.com/NablaShell/LastChance-server/internal/auth"
	"github.com/NablaShell/LastChance-server/internal/config"
	"github.com/NablaShell/LastChance-server/internal/middleware"
	"github.com/NablaShell/LastChance-server/internal/store"
)

var version = "dev"

const (
	relayShutdownTimeout = 10 * time.Second
	filesShutdownTimeout = 30 * time.Second
	gcInterval           = 5 * time.Minute
)

func main() {
	var configPath string
	var showVersion bool
	flag.StringVar(&configPath, "config", "", "path to config.toml (default: XDG config directory)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("lc-server %s\n", version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

func run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	st, err := store.Open(cfg.Storage.DBPath, cfg.Storage.FileDir)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer st.Close()

	trustedProxies, err := middleware.ParseTrustedProxies(cfg.Server.TrustedProxyCIDR)
	if err != nil {
		return fmt.Errorf("parse trusted proxy CIDR: %w", err)
	}

	verifier := auth.NewVerifier(st)
	notifier := api.NewNotifier()
	relayLimiter := middleware.DefaultRateLimiter()
	filesLimiter := middleware.DefaultRateLimiter()

	relayHandler := api.NewRelayMux(api.RelayOptions{
		Queues:             st,
		Auth:               verifier,
		Notifier:           notifier,
		MaxBodyBytes:       cfg.Server.MaxBodyBytes,
		PullTimeout:        cfg.Server.PullTimeout(),
		MaxConcurrentPulls: cfg.Server.RelayPullMaxConcurrent,
		GuardHeader:        cfg.Server.StealthHeaderName,
		GuardValue:         cfg.Server.StealthHeaderValue,
		TrustedProxies:     trustedProxies,
		RateLimiter:        relayLimiter,
		Logger:             logger,
	})
	filesHandler := api.NewFilesMux(api.FilesOptions{
		Files:          st,
		Auth:           verifier,
		MaxFileBytes:   cfg.Server.MaxFileBytes,
		GuardHeader:    cfg.Server.StealthHeaderName,
		GuardValue:     cfg.Server.StealthHeaderValue,
		TrustedProxies: trustedProxies,
		RateLimiter:    filesLimiter,
		Logger:         logger,
	})

	relayWriteTimeout := cfg.Server.PullTimeout() + 15*time.Second
	relaySrv := &http.Server{
		Addr:              cfg.Server.RelayAddr,
		Handler:           relayHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      relayWriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	filesSrv := &http.Server{
		Addr:              cfg.Server.FilesAddr,
		Handler:           filesHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       3 * time.Minute,
		MaxHeaderBytes:    8 << 10,
	}

	if cfg.Server.StealthHeaderName == "" || cfg.Server.StealthHeaderValue == "" {
		logger.Warn("stealth header is not configured; every guarded request will be rejected")
	}

	errCh := make(chan error, 2)
	serve := func(name string, srv *http.Server) {
		logger.Info("listener starting", "name", name, "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("%s listener: %w", name, err)
		}
	}
	go serve("relay", relaySrv)
	go serve("files", filesSrv)

	gcCtx, cancelGC := context.WithCancel(ctx)
	gcDone := startGC(gcCtx, st, cfg, relayLimiter, filesLimiter, logger)

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		runErr = err
		logger.Error("listener failed", "error", err)
	}

	cancelGC()
	<-gcDone

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		shutdownServer(relaySrv, "relay", relayShutdownTimeout, logger)
	}()
	go func() {
		defer wg.Done()
		shutdownServer(filesSrv, "files", filesShutdownTimeout, logger)
	}()
	wg.Wait()

	return runErr
}

func shutdownServer(srv *http.Server, name string, timeout time.Duration, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logger.Info("listener shutting down", "name", name, "timeout", timeout)
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "name", name, "error", err)
		if closeErr := srv.Close(); closeErr != nil {
			logger.Error("forced close failed", "name", name, "error", closeErr)
		}
	}
}

func startGC(ctx context.Context, st *store.Store, cfg config.Config, relayLimiter, filesLimiter *middleware.RateLimiter, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)

		runGC(st, cfg, relayLimiter, filesLimiter, logger)
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				runGC(st, cfg, relayLimiter, filesLimiter, logger)
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}

func runGC(st *store.Store, cfg config.Config, relayLimiter, filesLimiter *middleware.RateLimiter, logger *slog.Logger) {
	now := time.Now()
	messages, err := st.PurgeExpiredMessages(now.Add(-cfg.Storage.MessageTTL()))
	if err != nil {
		logger.Error("message GC failed", "error", err)
	}
	files, err := st.PurgeExpiredFiles(now.Add(-cfg.Storage.FileTTL()))
	if err != nil {
		logger.Error("file GC failed", "error", err)
	}
	nonces, err := st.PurgeExpiredNonces(now)
	if err != nil {
		logger.Error("nonce GC failed", "error", err)
	}
	relayLimiter.Cleanup()
	filesLimiter.Cleanup()

	if messages > 0 || files > 0 || nonces > 0 {
		logger.Info("storage GC", "messages", messages, "files", files, "nonces", nonces)
	}
}
