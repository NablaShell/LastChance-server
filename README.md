# Last Chance Server

A privacy-focused relay for the Last Chance client. A single `lc-server`
binary opens two listeners and shares one bbolt database:

- **relay** (`127.0.0.1:8080` by default) — `POST /push/{recipient}`,
  `GET /pull/{recipient}`, `GET /healthz`;
- **files** (`127.0.0.1:8081` by default) — `POST /upload`,
  `GET /download/{id}`, `GET /healthz`.

Caddy terminates TLS 1.3 and is the only container reachable from the host.
The server ports are never published.

The documented build is static and CGO-free. The previous `smg-relay/` and
`file_api/` modules, their in-memory SQLite queue and the separate file vault
are replaced by one process and one persistent bbolt database.

## Architecture

```text
client ──TLS──> Caddy ──/push, /pull──────────> lc-server:8080 ─┐
                       └─/upload, /download──> lc-server:8081 ─┴─ bbolt + files
```

- `cmd/lc-server` starts two `http.Server` instances, handles `SIGINT` /
  `SIGTERM`, and shuts them down with separate deadlines (relay 10 s, files
  30 s). It also owns the background storage GC worker.
- Listener timeouts are asymmetric: relay uses a 5 s read-header timeout, 10 s
  read timeout, `pull_timeout_sec + 15 s` write timeout and 60 s idle timeout;
  files uses 10 s read-header, 2-minute read/write and 3-minute idle timeouts.
  Both cap request headers at 8 KiB.
- `internal/config` loads TOML from the XDG config path with `LC_*` overrides
  and creates a `0600` template on first run.
- `internal/auth` verifies the Ed25519 request envelope and keeps replay state
  in the nonce store.
- `internal/store` defines `QueueStore`, `NonceStore` and `FileStore`; the
  bbolt implementation provides atomic pull/take and TTL garbage collection.
  Both listeners share the same `*store.Store` instance.
- `internal/api` builds the two muxes, the long-poll notifier and the per-port
  `MaxBytesReader` limits; `internal/middleware` provides the constant-time
  stealth guard, request id, structured logging, client IP resolution and
  per-listener rate limiting.
- `internal/testutil` generates Ed25519 identities and signed headers for the
  unit and end-to-end tests.

## Configuration

Default path: `$XDG_CONFIG_HOME/lc-server/config.toml`, usually
`~/.config/lc-server/config.toml`. Precedence:

1. `--config /path/config.toml`
2. `LC_SERVER_CONFIG=/path/config.toml`
3. XDG default.

`LC_SERVER_CONFIG` selects the file path; it does not override a field. The
binary has two flags: `--config /path/config.toml` and `--version` (print and
exit).

If the file is absent, `lc-server` creates it with mode `0600` (directory
`0700`) from the embedded template. `db_path` and `file_dir` expand a leading
`~`; other paths are used as given. The file uses two sections:

```toml
[server]
relay_addr = "127.0.0.1:8080"
files_addr = "127.0.0.1:8081"
max_body_bytes = 1048576
max_file_bytes = 134217728
pull_timeout_sec = 30
relay_pull_max_concurrent = 64
stealth_header_name = "X-DNS-Connect"
stealth_header_value = ""
trusted_proxy_cidr = ""

[storage]
db_path = "~/.local/share/lc-server/lc.db"
file_dir = "~/.local/share/lc-server/files"
file_ttl_hours = 1
message_ttl_hours = 24
```

Every value can be overridden with an environment variable:

| Variable | Field |
| :--- | :--- |
| `LC_RELAY_ADDR` | `server.relay_addr` |
| `LC_FILES_ADDR` | `server.files_addr` |
| `LC_MAX_BODY_BYTES` | `server.max_body_bytes` |
| `LC_MAX_FILE_BYTES` | `server.max_file_bytes` |
| `LC_PULL_TIMEOUT_SEC` | `server.pull_timeout_sec` |
| `LC_RELAY_PULL_MAX_CONCURRENT` | `server.relay_pull_max_concurrent` |
| `LC_STEALTH_HEADER_NAME` / `LC_STEALTH_HEADER_VALUE` | stealth |
| `LC_TRUSTED_PROXY_CIDR` | `server.trusted_proxy_cidr` |
| `LC_DB_PATH`, `LC_FILE_DIR` | storage paths |
| `LC_FILE_TTL_HOURS`, `LC_MESSAGE_TTL_HOURS` | retention |

Legacy aliases are accepted for `STEALTH_HEADER_NAME`,
`STEALTH_HEADER_VALUE`, `TRUSTED_PROXY_CIDR` and `VAULT_PATH` (→
`storage.file_dir`). `LC_*` wins over a legacy alias.

Validation rejects identical listener addresses, a shared port, malformed
addresses, `max_file_bytes < max_body_bytes`, non-positive limits/TTLs and
empty storage paths. An empty stealth header name or value is allowed by
validation but fails closed: every guarded request gets `403`. An invalid
`trusted_proxy_cidr` aborts startup instead of silently widening trust.

Inside Docker the same file is mounted read-only at `/config/config.toml`;
environment variables still take precedence over its values.

Examples: `config.example.toml` (local, loopback) and `deploy/config.toml`
(container, `0.0.0.0:8080` / `0.0.0.0:8081`, storage in `/var/lib/lc-server`).

## Build

Requires Go 1.26.2 or newer. The standard build produces a static, stripped
binary:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/lc-server ./cmd/lc-server
```

On a weak VPS, build one package at a time:

```bash
CGO_ENABLED=0 GOMAXPROCS=1 go build -p 1 -trimpath -ldflags="-s -w" -o bin/lc-server ./cmd/lc-server
```

`bbolt`, the TOML parser and `golang.org/x/time` are pure Go, so
`CGO_ENABLED=0` is fully supported; no SQLite or C toolchain is involved. Run
locally with the default loopback listeners:

```bash
./bin/lc-server --config ./config.example.toml
# or with the automatic XDG template:
./bin/lc-server
```

`--version` prints the build version (`lc-server dev` for a build without
`-ldflags "-X main.version=..."`).

The Dockerfile is a hybrid builder. If `bin/lc-server` exists it is copied into
the image (it must match the target architecture); otherwise the
`golang:1.26-alpine` builder compiles it with the same `CGO_ENABLED=0` flags.
The runtime stage is `alpine:latest` with `ca-certificates` and `tzdata`, a
non-root uid/gid 10001, `EXPOSE 8080 8081`, and
`LC_SERVER_CONFIG=/config/config.toml`.

## Deployment

1. Copy `env.example` to `.env` and set `DOMAIN`, `ACME_EMAIL`,
   `STEALTH_HEADER_NAME` and `STEALTH_HEADER_VALUE`.
2. Install the container config once:

   ```bash
   mkdir -p ~/.config/lc-server
   cp deploy/config.toml ~/.config/lc-server/config.toml
   # edit stealth_header_value if you prefer TOML over the env variable
   ```

3. Start the stack:

   ```bash
   docker compose up -d --build
   ```

The compose file mounts `${HOME}/.config/lc-server:/config:ro` and
`./data:/var/lib/lc-server`, publishes only Caddy's `80/443`, and health-checks
`http://127.0.0.1:8080/healthz` inside the container. Caddy starts only after
that check passes. lc-server is limited to 512 MiB, both containers use the
`json-file` driver rotated at 10 MiB × 3, and the process runs as uid/gid
10001, so `./data` must be writable by that uid.

`deploy.sh` performs a cross-compile for `linux/$ARCH`, copies `bin/lc-server`,
installs `deploy/config.toml` only when absent, and runs
`docker compose up -d --build` on the remote host. The remote directory must
already contain `docker-compose.yml`, `Caddyfile` and the rest of the deployment
files; the script creates `bin/`, `data/` and `~/.config/lc-server`, and chowns
`data/` to 10001 (warning if it lacks permission).

```bash
HOST=relay.example.com REMOTE_DIR=/opt/lastchance-server ./deploy.sh
# REMOTE_USER=deploy is optional (default: current local user)
# ARM host: ARCH=arm64 ... ; weak VPS: WEAK_VPS=1 ...
```

`ARCH` defaults to `amd64` and must match the remote host; otherwise the
container fails to exec the copied binary. Leave `bin/lc-server` absent from the
build context to let the Docker builder compile inside the image instead.

### Caddy variants

`Caddyfile` ships with one public domain:

- `/push*`, `/pull*` → `lc-server:8080`;
- `/upload*`, `/download*` → `lc-server:8081`.

Caddy applies `request_body max_size` from `LC_MAX_BODY_BYTES` /
`LC_MAX_FILE_BYTES` to the push, pull and upload routes before proxying,
overwrites `X-Real-IP` and `X-Forwarded-For` with `{remote_host}`, and streams
downloads with `flush_interval -1`. The admin API is disabled, TLS is pinned to
1.3, plain HTTP requests (including direct IP) get `403`, and requests without
the stealth header are rejected with `403` at the edge.

It also contains an active legacy mapping (`/api-v1/*`, `/file-api/*`) using
`handle_path`, so clients that still send the old prefixes keep working: the
prefix is stripped before proxying, and the signature is over the unprefixed
path. The documented API surface stays `/push`, `/pull`, `/upload`,
`/download` and `/healthz`; the old `/ping` and `/info` endpoints are not
implemented (see [Migration](#migration-from-the-two-binary-layout)). A
commented Variant B block routes files through a separate `FILES_DOMAIN`
subdomain. Enable one variant at a time.

Validate the Caddyfile with the same environment used for deployment:

```bash
caddy validate --config Caddyfile --adapter caddyfile --envfile .env
```

## API

| Listener | Method | Path | Auth | Behaviour |
| :--- | :--- | :--- | :--- | :--- |
| relay | `POST` | `/push/{recipient}` | Signed, body hash | Accepts one text packet. `Content-Length` is required, must match the bytes read, and must fall inside a client padding bucket: 256–288 B, 1 KiB–1152 B, 4 KiB–4608 B or 64 KiB–72 KiB. Returns `200`; `400` for a missing/misaligned size, `413` above `max_body_bytes`, `429` when the recipient queue holds 100 messages. |
| relay | `GET` | `/pull/{recipient}` | Signed | Atomically takes and deletes every queued packet and returns it as `multipart/form-data`. `X-Auth-Identity` must equal `{recipient}` (case-insensitive). Empty queue returns `204`; supports `?wait=N` long-polling. |
| relay | `GET` | `/healthz` | None | `200` with `ok\n`, used by Docker. It is outside the guard and rate limiter. |
| files | `POST` | `/upload` | Signed, body hash | Requires `Content-Length` (`411` otherwise) and a non-empty body. Hashes while streaming to a temp file, then returns the lowercase hex SHA-256 as `text/plain`; `413` above `max_file_bytes`. |
| files | `GET` | `/download/{id}` | Signed | `{id}` must be a 64-character lowercase hex SHA-256 (`400` otherwise). One-time download: metadata is taken atomically, the body is streamed as `application/octet-stream`, then removed. A second or unknown request gets `404`. |
| files | `GET` | `/healthz` | None | `200` with `ok\n`, used by Docker. It is outside the guard and rate limiter. |

All API routes except `/healthz` require the stealth header and the Ed25519
signature. Request-body limits are per listener: relay uses
`max_body_bytes` (1 MiB default), files uses `max_file_bytes` (128 MiB
default); Caddy enforces the matching `LC_MAX_*` caps at the edge, so keep them
aligned with the TOML limits. Responses from the guarded API routes carry an
`X-Request-ID` header: a sane inbound value (1–64 characters of
`[A-Za-z0-9._-]`) is echoed, otherwise a 16-byte hex id is generated.

### Long-polling pulls

`GET /pull/{recipient}?wait=N`:

- no `wait`, `0` or an invalid value → immediate `204` on an empty queue;
- `1..pull_timeout_sec` waits for a push, then returns it; larger values are
  clamped;
- only requests that find an empty queue and have `wait > 0` acquire a slot;
  at most `relay_pull_max_concurrent` requests hold a long poll, and additional
  waiters get `503` with `Retry-After: 1`;
- the handler subscribes before checking the queue, so a push racing the check
  is not lost;
- client disconnect is observed through `r.Context()`, releases the semaphore
  immediately and returns the non-standard `499` status.

## Authentication

Canonical envelope (must match the Rust client):

```text
METHOD \n PATH \n CANONICAL_QUERY \n TIMESTAMP \n NONCE \n SHA256(body)
```

`METHOD` is uppercased, `PATH` gets a leading `/` and loses trailing slashes,
and `CANONICAL_QUERY` sorts pairs by key then value, joins them with `&` and
preserves percent-encoding. The body hash is lowercase hex SHA-256.

Headers:

- `X-Identity-Key` — `hex(ed25519_public_key)`; the server recomputes
  `hex(SHA256(public_key))` and requires it to match `X-Auth-Identity`;
- `X-Auth-Identity` — `hex(SHA256(public_key))`;
- `X-Auth-Timestamp` — decimal Unix seconds, accepted in
  `[now - 60, now + 30]`;
- `X-Auth-Nonce` — base64url without padding, 16..=32 decoded bytes;
- `X-Auth-Signature` — base64url without padding over the envelope.

This is self-authentication, not authorization: any generated key can push to
any recipient. `/pull` additionally requires the identity to equal the
recipient in the URL, so only the key owner can read that queue. Identity
comparisons are ASCII case-insensitive; the nonce and signature are byte-exact.

Every nonce is accepted once per identity and stored in bbolt for 150 seconds.
A nonce is inserted only after the signature and timestamp checks pass, so junk
requests cannot fill the store. The store is capped at 1024 live nonces per
identity and fails closed with `503` rather than evicting a live nonce.
Signature, body and nonce are never logged. All authentication failures return
`unauthorized`; a missing or wrong stealth header returns `forbidden`.

The shared `testdata/auth_vectors.json` pins the envelope and a real Ed25519
signature, so a client or server drift fails the test suite.

## Storage and retention

- bbolt buckets: `queues` (recipient plus a big-endian sequence number),
  `nonces` (identity plus nonce) and `files_meta` (`id`).
- The database is opened with mode `0600` and a 2-second lock timeout; a second
  process cannot open the same database concurrently.
- `Pull` and `Take` are single bbolt write transactions. A concurrent second
  download gets `404`.
- Queue values store their creation time; queues are capped at 100 messages per
  recipient and expire after `message_ttl_hours` (24 h default).
- File bodies live in `file_dir` with mode `0600`; metadata and bodies expire
  after `file_ttl_hours` (1 h default). Uploads stream through `.upload-*`
  temp files. Files are removed after delivery, and temp/orphaned files are
  cleaned at startup.
- A background worker runs once at startup and every 5 minutes. It purges
  expired messages, files and nonces, and drops idle rate-limiter buckets.

## Security notes

- **TLS 1.3 only** at Caddy. Backend traffic is plain HTTP on the internal
  Docker bridge; the relay and files ports are not published.
- **Stealth header** hides the service from casual scanning. It is not an
  access-control boundary against someone who learns the value; the real
  boundary is TLS plus the request signature.
- **Client IP**: the TCP peer is used by default. `X-Real-IP` is honoured only
  when the peer matches `TRUSTED_PROXY_CIDR`, or — when unset — is loopback /
  RFC1918 / ULA. Caddy overwrites `X-Real-IP` and `X-Forwarded-For` with
  `{remote_host}`. Invalid CIDR entries abort startup.
- **Rate limiting**: each listener has its own limiter at 5 requests/second
  with a burst of 10 per client IP, a bounded 4096-entry map, 10-minute idle
  eviction and a sweep at most once per minute. Replay protection uses the
  separate fail-closed nonce store.
- **Logging**: structured `slog` JSON on stderr; method, path, status,
  duration, peer address, request id and shortened identity only. Caddy access
  logging is disabled by default. Docker's `json-file` logs rotate at 10 MiB
  with three files retained.

## Tests

```bash
gofmt -l cmd internal e2e
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

Coverage includes config template/env/legacy aliases/validation, tilde
expansion and path precedence, bbolt push/pull/TTL/GC and concurrency, startup
orphan/temp cleanup, canonical auth vectors, skew/replay/tampering, nonce-store
capacity, per-port body limits, upload size/tampering checks, long-poll
wake/timeout/cancel/semaphore, guard, request IDs, rate limiting, health checks
and an end-to-end smoke test over both listeners. `TestCaddyfileValidates` runs
Caddy's parser against `env.example` when `caddy` is on `PATH`.

## Migration from the two-binary layout

The old `smg-relay/` and `file_api/` modules were replaced by this single
module and one persistent bbolt database. Old `/api-v1/*` and `/file-api/*`
prefixes are accepted by Caddy's `handle_path` and stripped before proxying;
clients must still sign the unprefixed path (`/push/...`, `/pull/...`,
`/upload`, `/download/...`). The legacy mapping covers those four routes only:
the old `/ping` and `/info` endpoints are not implemented, and `/healthz` is
the unauthenticated liveness endpoint.

The old SQLite queue used `:memory:` and had no persistent state to migrate.
Existing file-vault data is not imported automatically; the new file store
starts empty under `storage.file_dir`. Do not point `file_dir` at an old vault:
startup cleanup deletes valid-looking file bodies that have no metadata in the
new database.

## License

AGPL-3.0. See `LICENSE`.

## Support & Donation

| Asset | Address |
| :--- | :--- |
| **BTC** | 8Arc4tRdGAKcWNMLCb7mj2fnYqWgQGhTTgR7FEGaZpL2Pw6MNSwqsGMUGpeQGURgQbDoyxU1ASKMP7dKBJq8yJgCSwCgPYe |
| **XMR** | bc1qktffxm3579v6zs6mpms4yvwp6m067nkggd8ach |

## Contact & Feedback

- Session ID: `05f08d7242fe9cd621e98ef902cd1a21a8bf10d0c7c946e8c8e469d2396657a637`
- ProtonMail: `nabla.shell@proton.me`
- PGP public key: <https://github.com/NablaShell/LastChance/docs/public_key.asc>
- PGP fingerprint: `885F 3675 1D87 3F99 55ED 0ABC D1F6 A559 1458 507D`
