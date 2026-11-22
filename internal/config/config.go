// Package config loads the LastChance server configuration from TOML with
// environment overrides. The file lives in the XDG configuration directory by
// default and is created from an embedded template with mode 0600 when absent.
package config

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

//go:embed template.toml
var template string

const (
	// DefaultMaxBodyBytes is the relay request cap (1 MiB).
	DefaultMaxBodyBytes int64 = 1 << 20
	// DefaultMaxFileBytes is the upload cap (128 MiB), matching the client's
	// FILE_MAX_ENVELOPE.
	DefaultMaxFileBytes int64 = 128 << 20
)

// Config is the complete TOML document.
type Config struct {
	Server  ServerConfig  `toml:"server"`
	Storage StorageConfig `toml:"storage"`
}

// ServerConfig holds listener and request limits.
type ServerConfig struct {
	RelayAddr              string `toml:"relay_addr"`
	FilesAddr              string `toml:"files_addr"`
	MaxBodyBytes           int64  `toml:"max_body_bytes"`
	MaxFileBytes           int64  `toml:"max_file_bytes"`
	PullTimeoutSec         int    `toml:"pull_timeout_sec"`
	RelayPullMaxConcurrent int    `toml:"relay_pull_max_concurrent"`
	StealthHeaderName      string `toml:"stealth_header_name"`
	StealthHeaderValue     string `toml:"stealth_header_value"`
	TrustedProxyCIDR       string `toml:"trusted_proxy_cidr"`
}

// StorageConfig holds bbolt and file storage settings.
type StorageConfig struct {
	DBPath          string `toml:"db_path"`
	FileDir         string `toml:"file_dir"`
	FileTTLHours    int    `toml:"file_ttl_hours"`
	MessageTTLHours int    `toml:"message_ttl_hours"`
}

// Default returns the built-in defaults. The embedded template is kept in sync
// with these values and is used for first-run file creation.
func Default() Config {
	return Config{
		Server: ServerConfig{
			RelayAddr:              "127.0.0.1:8080",
			FilesAddr:              "127.0.0.1:8081",
			MaxBodyBytes:           DefaultMaxBodyBytes,
			MaxFileBytes:           DefaultMaxFileBytes,
			PullTimeoutSec:         30,
			RelayPullMaxConcurrent: 64,
			StealthHeaderName:      "X-DNS-Connect",
		},
		Storage: StorageConfig{
			DBPath:          "~/.local/share/lc-server/lc.db",
			FileDir:         "~/.local/share/lc-server/files",
			FileTTLHours:    1,
			MessageTTLHours: 24,
		},
	}
}

// PullTimeout returns the long-poll timeout as a duration.
func (s ServerConfig) PullTimeout() time.Duration {
	return time.Duration(s.PullTimeoutSec) * time.Second
}

// FileTTL returns the file retention duration.
func (s StorageConfig) FileTTL() time.Duration {
	return time.Duration(s.FileTTLHours) * time.Hour
}

// MessageTTL returns the queue retention duration.
func (s StorageConfig) MessageTTL() time.Duration {
	return time.Duration(s.MessageTTLHours) * time.Hour
}

// DefaultPath returns $XDG_CONFIG_HOME/lc-server/config.toml (usually
// ~/.config/lc-server/config.toml).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", fmt.Errorf("resolve config directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "lc-server", "config.toml"), nil
}

// ResolvePath applies the precedence --config > LC_SERVER_CONFIG > XDG default.
func ResolvePath(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return expandHome(explicit), nil
	}
	if envPath, ok := os.LookupEnv("LC_SERVER_CONFIG"); ok && strings.TrimSpace(envPath) != "" {
		return expandHome(envPath), nil
	}
	return DefaultPath()
}

// Load resolves, creates when missing, parses, applies env overrides and
// validates the configuration.
func Load(path string) (Config, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return Config{}, err
	}
	if err := ensureTemplate(resolved); err != nil {
		return Config{}, err
	}

	cfg := Default()
	if _, err := toml.DecodeFile(resolved, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", resolved, err)
	}
	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	expandPaths(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %s: %w", resolved, err)
	}
	return cfg, nil
}

// Validate rejects configurations that cannot run correctly.
func (c Config) Validate() error {
	var errs []error

	relayPort, relayErr := validateAddr("server.relay_addr", c.Server.RelayAddr)
	if relayErr != nil {
		errs = append(errs, relayErr)
	}
	filesPort, filesErr := validateAddr("server.files_addr", c.Server.FilesAddr)
	if filesErr != nil {
		errs = append(errs, filesErr)
	}
	if strings.TrimSpace(c.Server.RelayAddr) == strings.TrimSpace(c.Server.FilesAddr) {
		errs = append(errs, errors.New("server.relay_addr and server.files_addr must differ"))
	} else if relayErr == nil && filesErr == nil && relayPort == filesPort {
		errs = append(errs, fmt.Errorf("server.relay_addr and server.files_addr must use different ports (both %d)", relayPort))
	}

	if c.Server.MaxBodyBytes <= 0 {
		errs = append(errs, errors.New("server.max_body_bytes must be positive"))
	}
	if c.Server.MaxFileBytes <= 0 {
		errs = append(errs, errors.New("server.max_file_bytes must be positive"))
	}
	if c.Server.MaxFileBytes < c.Server.MaxBodyBytes {
		errs = append(errs, errors.New("server.max_file_bytes must be >= server.max_body_bytes"))
	}
	if c.Server.PullTimeoutSec <= 0 {
		errs = append(errs, errors.New("server.pull_timeout_sec must be positive"))
	}
	if c.Server.RelayPullMaxConcurrent <= 0 {
		errs = append(errs, errors.New("server.relay_pull_max_concurrent must be positive"))
	}
	if c.Storage.FileTTLHours <= 0 {
		errs = append(errs, errors.New("storage.file_ttl_hours must be positive"))
	}
	if c.Storage.MessageTTLHours <= 0 {
		errs = append(errs, errors.New("storage.message_ttl_hours must be positive"))
	}
	if strings.TrimSpace(c.Storage.DBPath) == "" {
		errs = append(errs, errors.New("storage.db_path must not be empty"))
	}
	if strings.TrimSpace(c.Storage.FileDir) == "" {
		errs = append(errs, errors.New("storage.file_dir must not be empty"))
	}

	return errors.Join(errs...)
}

func validateAddr(key, addr string) (int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	_ = host // an empty host (" :8080") is valid and binds all interfaces
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("%s: invalid port %q", key, portText)
	}
	return port, nil
}

func ensureTemplate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory for %s: %w", path, err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("create config %s: %w (for Docker, install deploy/config.toml at this path)", path, err)
	}

	_, writeErr := io.WriteString(file, template)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if writeErr != nil {
			return fmt.Errorf("write config template %s: %w", path, writeErr)
		}
		return fmt.Errorf("close config template %s: %w", path, closeErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod config template %s: %w", path, err)
	}
	return nil
}

func applyEnv(c *Config) error {
	c.Server.RelayAddr = envString("LC_RELAY_ADDR", c.Server.RelayAddr)
	c.Server.FilesAddr = envString("LC_FILES_ADDR", c.Server.FilesAddr)

	if value, ok := firstEnv("LC_STEALTH_HEADER_NAME", "STEALTH_HEADER_NAME"); ok {
		c.Server.StealthHeaderName = value
	}
	if value, ok := firstEnv("LC_STEALTH_HEADER_VALUE", "STEALTH_HEADER_VALUE"); ok {
		c.Server.StealthHeaderValue = value
	}
	if value, ok := firstEnv("LC_TRUSTED_PROXY_CIDR", "TRUSTED_PROXY_CIDR"); ok {
		c.Server.TrustedProxyCIDR = value
	}

	if err := setInt64(&c.Server.MaxBodyBytes, "LC_MAX_BODY_BYTES"); err != nil {
		return err
	}
	if err := setInt64(&c.Server.MaxFileBytes, "LC_MAX_FILE_BYTES"); err != nil {
		return err
	}
	if err := setInt(&c.Server.PullTimeoutSec, "LC_PULL_TIMEOUT_SEC"); err != nil {
		return err
	}
	if err := setInt(&c.Server.RelayPullMaxConcurrent, "LC_RELAY_PULL_MAX_CONCURRENT"); err != nil {
		return err
	}

	c.Storage.DBPath = envString("LC_DB_PATH", c.Storage.DBPath)
	if value, ok := firstEnv("LC_FILE_DIR", "VAULT_PATH"); ok {
		c.Storage.FileDir = value
	}
	if err := setInt(&c.Storage.FileTTLHours, "LC_FILE_TTL_HOURS"); err != nil {
		return err
	}
	if err := setInt(&c.Storage.MessageTTLHours, "LC_MESSAGE_TTL_HOURS"); err != nil {
		return err
	}
	return nil
}

func envString(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func firstEnv(names ...string) (string, bool) {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			return value, true
		}
	}
	return "", false
}

func setInt64(dst *int64, name string) error {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	*dst = value
	return nil
}

func setInt(dst *int, name string) error {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	*dst = value
	return nil
}

func expandPaths(c *Config) {
	c.Storage.DBPath = expandHome(c.Storage.DBPath)
	c.Storage.FileDir = expandHome(c.Storage.FileDir)
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}
