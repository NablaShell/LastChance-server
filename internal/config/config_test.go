package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var envNames = []string{
	"LC_SERVER_CONFIG", "LC_RELAY_ADDR", "LC_FILES_ADDR",
	"LC_MAX_BODY_BYTES", "LC_MAX_FILE_BYTES", "LC_PULL_TIMEOUT_SEC",
	"LC_RELAY_PULL_MAX_CONCURRENT", "LC_STEALTH_HEADER_NAME",
	"LC_STEALTH_HEADER_VALUE", "LC_TRUSTED_PROXY_CIDR", "LC_DB_PATH",
	"LC_FILE_DIR", "LC_FILE_TTL_HOURS", "LC_MESSAGE_TTL_HOURS",
	"STEALTH_HEADER_NAME", "STEALTH_HEADER_VALUE", "TRUSTED_PROXY_CIDR",
	"VAULT_PATH",
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range envNames {
		name := name
		value, ok := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
		t.Cleanup(func() {
			if ok {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadCreatesTemplateWithPrivateMode(t *testing.T) {
	clearEnv(t)
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("HOME", t.TempDir())

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.RelayAddr != "127.0.0.1:8080" {
		t.Fatalf("relay addr = %q", cfg.Server.RelayAddr)
	}
	if cfg.Server.FilesAddr != "127.0.0.1:8081" {
		t.Fatalf("files addr = %q", cfg.Server.FilesAddr)
	}

	path := filepath.Join(configHome, "lc-server", "config.toml")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat template: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("template mode = %o, want 600", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("config dir mode = %o, want 700", mode)
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `
[server]
relay_addr = "127.0.0.1:9000"
files_addr = "127.0.0.1:9001"
max_body_bytes = 2048
max_file_bytes = 4096
pull_timeout_sec = 7
relay_pull_max_concurrent = 3
stealth_header_name = "X-Test"
stealth_header_value = "secret"

[storage]
db_path = "/tmp/lc-test.db"
file_dir = "/tmp/lc-test-files"
file_ttl_hours = 4
message_ttl_hours = 8
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.RelayAddr != "127.0.0.1:9000" || cfg.Server.FilesAddr != "127.0.0.1:9001" {
		t.Fatalf("addresses not loaded: %+v", cfg.Server)
	}
	if cfg.Server.MaxBodyBytes != 2048 || cfg.Server.MaxFileBytes != 4096 {
		t.Fatalf("limits not loaded: %+v", cfg.Server)
	}
	if cfg.Server.PullTimeout() != 7*time.Second {
		t.Fatalf("pull timeout = %v", cfg.Server.PullTimeout())
	}
	if cfg.Server.RelayPullMaxConcurrent != 3 {
		t.Fatalf("concurrency = %d", cfg.Server.RelayPullMaxConcurrent)
	}
	if cfg.Storage.FileTTL().Hours() != 4 || cfg.Storage.MessageTTL().Hours() != 8 {
		t.Fatalf("TTL not loaded: %+v", cfg.Storage)
	}
}

func TestEnvOverridesFileAndLegacyAliases(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `
[server]
relay_addr = "127.0.0.1:8080"
files_addr = "127.0.0.1:8081"
stealth_header_name = "X-File"
stealth_header_value = "file-secret"

[storage]
db_path = "/tmp/lc-test.db"
file_dir = "/tmp/lc-test-files"
file_ttl_hours = 1
message_ttl_hours = 24
`)
	t.Setenv("LC_RELAY_ADDR", "127.0.0.1:7000")
	t.Setenv("LC_FILES_ADDR", "127.0.0.1:7001")
	t.Setenv("LC_MAX_BODY_BYTES", "3000")
	t.Setenv("LC_MAX_FILE_BYTES", "5000")
	t.Setenv("LC_PULL_TIMEOUT_SEC", "9")
	t.Setenv("LC_RELAY_PULL_MAX_CONCURRENT", "5")
	t.Setenv("LC_STEALTH_HEADER_NAME", "X-Env")
	t.Setenv("LC_STEALTH_HEADER_VALUE", "env-secret")
	t.Setenv("LC_TRUSTED_PROXY_CIDR", "127.0.0.1/32")
	t.Setenv("LC_FILE_TTL_HOURS", "6")
	t.Setenv("LC_MESSAGE_TTL_HOURS", "12")
	t.Setenv("LC_FILE_DIR", "/tmp/lc-env-files")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.RelayAddr != "127.0.0.1:7000" || cfg.Server.FilesAddr != "127.0.0.1:7001" {
		t.Fatalf("env addresses not applied: %+v", cfg.Server)
	}
	if cfg.Server.MaxBodyBytes != 3000 || cfg.Server.MaxFileBytes != 5000 {
		t.Fatalf("env limits not applied: %+v", cfg.Server)
	}
	if cfg.Server.StealthHeaderName != "X-Env" || cfg.Server.StealthHeaderValue != "env-secret" {
		t.Fatalf("LC stealth env not applied: %+v", cfg.Server)
	}
	if cfg.Server.TrustedProxyCIDR != "127.0.0.1/32" {
		t.Fatalf("trusted proxy env not applied")
	}
	if cfg.Storage.FileTTLHours != 6 || cfg.Storage.MessageTTLHours != 12 {
		t.Fatalf("TTL env not applied: %+v", cfg.Storage)
	}
	if cfg.Storage.FileDir != "/tmp/lc-env-files" {
		t.Fatalf("file dir env not applied: %q", cfg.Storage.FileDir)
	}
}

func TestLegacyEnvAliases(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, "[server]\n[storage]\n")
	t.Setenv("STEALTH_HEADER_NAME", "X-Legacy")
	t.Setenv("STEALTH_HEADER_VALUE", "legacy-secret")
	t.Setenv("TRUSTED_PROXY_CIDR", "10.0.0.0/8")
	t.Setenv("VAULT_PATH", "/tmp/legacy-vault")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.StealthHeaderName != "X-Legacy" || cfg.Server.StealthHeaderValue != "legacy-secret" {
		t.Fatalf("legacy stealth env not applied: %+v", cfg.Server)
	}
	if cfg.Server.TrustedProxyCIDR != "10.0.0.0/8" {
		t.Fatalf("legacy proxy env not applied")
	}
	if cfg.Storage.FileDir != "/tmp/legacy-vault" {
		t.Fatalf("legacy vault env not applied: %q", cfg.Storage.FileDir)
	}
}

func TestValidationRejectsBadConfigurations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{
			name: "same address",
			mutate: func(c *Config) {
				c.Server.FilesAddr = c.Server.RelayAddr
			},
			wantSub: "must differ",
		},
		{
			name: "same port",
			mutate: func(c *Config) {
				c.Server.FilesAddr = "0.0.0.0:8080"
			},
			wantSub: "different ports",
		},
		{
			name: "file smaller than body",
			mutate: func(c *Config) {
				c.Server.MaxFileBytes = c.Server.MaxBodyBytes - 1
			},
			wantSub: "max_file_bytes",
		},
		{
			name: "bad relay address",
			mutate: func(c *Config) {
				c.Server.RelayAddr = "not-an-address"
			},
			wantSub: "relay_addr",
		},
		{
			name: "zero concurrency",
			mutate: func(c *Config) {
				c.Server.RelayPullMaxConcurrent = 0
			},
			wantSub: "relay_pull_max_concurrent",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("Validate() = %v, want substring %q", err, test.wantSub)
			}
		})
	}
}

func TestLoadExpandsTilde(t *testing.T) {
	clearEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeConfig(t, `
[storage]
db_path = "~/data/lc.db"
file_dir = "~/files"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.DBPath != filepath.Join(home, "data", "lc.db") {
		t.Fatalf("db path = %q", cfg.Storage.DBPath)
	}
	if cfg.Storage.FileDir != filepath.Join(home, "files") {
		t.Fatalf("file dir = %q", cfg.Storage.FileDir)
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	clearEnv(t)
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	path, err := ResolvePath("/tmp/explicit.toml")
	if err != nil || path != "/tmp/explicit.toml" {
		t.Fatalf("explicit path = %q, %v", path, err)
	}

	t.Setenv("LC_SERVER_CONFIG", "/tmp/from-env.toml")
	path, err = ResolvePath("")
	if err != nil || path != "/tmp/from-env.toml" {
		t.Fatalf("env path = %q, %v", path, err)
	}

	if err := os.Unsetenv("LC_SERVER_CONFIG"); err != nil {
		t.Fatal(err)
	}
	path, err = ResolvePath("")
	want := filepath.Join(configHome, "lc-server", "config.toml")
	if err != nil || path != want {
		t.Fatalf("default path = %q, %v; want %q", path, err, want)
	}
}
