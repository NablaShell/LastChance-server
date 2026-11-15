# Last Chance Server 

A high-performance, privacy-focused dual-node relay system built with Go. Designed for secure, asynchronous data exchange with a zero-footprint architecture.

## Architecture Overview

The system consists of two specialized nodes orchestrated by a Caddy reverse proxy:
- **SMS Relay (Node):** Handles lightweight message queuing using an in-memory SQLite provider and Ed25519 cryptographic authorization.
- **File Relay (File API):** Manages temporary file storage with a hybrid RAM/Disk approach and secure deletion (shredding).
- **Caddy Proxy:** Acts as the "Stealth Layer," handling SSL (TLS 1.3), anti-scanning headers, and request filtering.

## Security Features

- **Asynchronous Stealth:** Uses custom header validation at the proxy level to drop unauthorized requests silently (403/404). The text and file relays re-check the same header, so reaching a backend container directly does not bypass the edge.
- **Crypto-Auth:** `/push`, `/pull`, `/upload`, `/download` and `/info` require an Ed25519 signature over the canonical request envelope `METHOD \n PATH \n QUERY \n TIMESTAMP \n NONCE \n SHA256(body)`. The headers are `X-Auth-Identity`, `X-Identity-Key`, `X-Auth-Timestamp`, `X-Auth-Nonce` and `X-Auth-Signature` (base64url, no padding).
- **Replay Protection:** Every nonce is accepted once per identity. Expired nonces are purged from the in-memory cache after `60 + 30 + 60` seconds, and a full cache fails closed with `503`.
- **Canonical Binding:** The signature covers the method, path, sorted query, timestamp and body hash, so an endpoint, query value or upload body cannot be swapped in transit.
- **Real client IP:** Rate limits are keyed by the peer address. `X-Real-IP` is honoured only when the peer is a trusted proxy (`TRUSTED_PROXY_CIDR` when set, otherwise loopback/RFC1918/ULA), and Caddy overwrites both `X-Real-IP` and `X-Forwarded-For` with `{remote_host}`; client-supplied forwarding headers are ignored.
- **Auto-Purge:** Files and messages have strict TTL (Time-To-Live). One-time download policy: data is shredded immediately after delivery.
- **Anti-Forensics:** Integrated `shred` utility support for overwriting disk sectors before file unlinking.
- **No content logging:** Signatures, nonces and bodies are never logged. Operational logs contain only the client IP, method, path, short identity and a rejection reason. See [Privacy and logging](#privacy-and-logging).

The server removes the Caddy prefix (`/api-v1` for the text node, `/file-api` for the file node) before verifying the canonical path, because the client signs the unprefixed API path (`/push/<hash>`, `/pull/<hash>`, `/upload`, `/download/<hash>`). The prefix is **transport routing, not part of the signature**:

- `/api-v1/push/...` + a signature over `/push/...` → accepted;
- `/push/...` + a signature over `/push/...` → accepted (also works if Caddy is switched to `handle_path`);
- `/api-v1/push/...` + a signature over `/api-v1/push/...` → `401`.

Changing the client to sign the external prefixed path is a **breaking protocol change**. Moving the prefix rewrite into Caddy (`handle_path`) is not breaking, because the path seen by the relay is then already unprefixed and the stripping becomes a no-op.

### Authentication contract

- `X-Identity-Key` is `hex(ed25519_public_key)`. It is necessary because the relay has no contact registry and therefore cannot look a key up by identity. The server recomputes `identity = hex(SHA256(public_key))` and requires it to equal `X-Auth-Identity`; this proves possession of the private key and binds the request to that key. It is **self-authentication, not authorization**: any generated key can push to any bucket. `/pull` additionally requires `X-Auth-Identity` to equal the bucket hash in the URL, so only the key owner can read that bucket.
- `X-Auth-Timestamp` is a decimal Unix timestamp in seconds (UTC, no leading zeros). The accepted window is `[now - 60, now + 30]`.
- `X-Auth-Nonce` is base64url without padding, decoding to 16..=32 bytes. It is checked only after the signature verifies, so invalid signatures cannot fill the replay cache. A nonce is accepted once per identity; the cache keeps entries for 150 seconds and fails closed with `503` when full.
- `X-Auth-Signature` is base64url without padding over the canonical envelope.
- `X-Auth-Identity` and the identity hash in `X-Identity-Key` are compared case-insensitively; the signature and nonce are byte-exact.
- `/ping` (and `/file-api/ping`) are unauthenticated health endpoints. `/file-api/info` is metadata, not a health check, and requires the same signature as `/upload` and `/download`.
- Uploads are hashed while streaming to a temporary file; the request body is not buffered in memory. The temp file is removed on every rejection path.
- The upload ceiling is **128 MiB** (`DiskLimit`), matching `FILE_MAX_ENVELOPE` in the Rust client. Caddy enforces the same cap with `request_body max_size 134217728`, so oversized bodies are rejected before the relay reads them. The text node caps request bodies at 1 MiB in Caddy; a text packet is at most 64 KiB.

### Rate limiting and client identity

Both relays allow 5 requests/second with a burst of 10 per client IP. Buckets are dropped after 10 minutes of inactivity and the map is capped at 4096 entries, so the limiter can neither be bypassed by waiting for a periodic `Cleanup` nor grow without bound. The cap evicts the least-recently-seen bucket. That is acceptable **only** for a rate limiter: losing a bucket gives one IP one extra burst, it cannot enable a replay. Replay protection uses a separate nonce cache that fails closed with `503` and never evicts an unexpired nonce; the two structures are intentionally not shared.

The client IP is resolved as follows:

1. take the TCP peer address (`RemoteAddr`) and strip the port;
2. if that peer is a trusted proxy, accept a syntactically valid `X-Real-IP`;
3. otherwise ignore all forwarding headers and use the peer address.

A peer is trusted when it matches `TRUSTED_PROXY_CIDR` (comma-separated CIDRs or bare IPs, see `env.example`). **When that variable is unset, every loopback / RFC1918 / ULA peer is trusted**, which matches the shipped single-host Docker deployment where Caddy is the only peer. That default is broad: any other machine on the same private network or VLAN could spoof `X-Real-IP`. To narrow it, pin Caddy's address (for example `TRUSTED_PROXY_CIDR=172.18.0.2/32`) or the bridge subnet; an invalid value aborts startup instead of silently widening trust.

Caddy sets both `header_up X-Real-IP {remote_host}` and `header_up X-Forwarded-For {remote_host}` on both routes. `{remote_host}` is the TCP peer, i.e. the real client. Both headers are **overwritten, not appended**, so `X-Forwarded-For` contains exactly one address rather than a chain. The relays read only `X-Real-IP`; `X-Forwarded-For` is set for completeness and is never parsed. A forged `X-Real-IP` from a direct client therefore changes neither the rate-limit bucket nor the logged IP.

> **Second proxy policy:** the single-hop XFF rewrite is correct only while Caddy is the first and only proxy. If another reverse proxy or CDN is placed in front of Caddy, the peer Caddy sees becomes that proxy, not the client. At that point this policy must change: enable Caddy's `trusted_proxies` for the front proxy, append to XFF instead of overwriting it, and decide which hop the relays should trust. Do not add a front proxy without revisiting `TRUSTED_PROXY_CIDR` and the Caddyfile together.

Other containers on the same Docker network are inside the trust boundary. If a deployment shares that network with unrelated workloads, add network segmentation or a Caddy-to-backend shared secret; the stealth header alone is not sufficient there.

### Trust boundary and TLS termination

TLS terminates at Caddy. The shipped Caddyfile pins the listener to **TLS 1.3 only** (`tls { protocols tls1.3 }`), so the "TLS 1.3 + Ed25519 signature" boundary described above is enforced by configuration, not merely by wording. Caddy still obtains and renews certificates automatically via ACME.

Caddy reaches both relays over **plain HTTP on the internal Docker bridge** (`sms-relay:8080`, `file-relay:8081`). This is acceptable only because the bridge is treated as trusted: neither relay publishes a host port (`expose`, not `ports`), and Caddy is the only legitimate peer. If Caddy is moved to another host, the bridge is no longer an isolation boundary — use a VPN/WireGuard tunnel or mTLS between Caddy and the relays, and never expose the relay ports publicly. The same applies if unrelated workloads share the network: segment it, or add a Caddy-to-backend shared secret.

### Privacy and logging

- Caddy access logging is **disabled by default**: a privacy relay should not persist every client IP and URI. Caddy runtime errors still go to stderr and are handled by the Docker logging driver. `Caddyfile` contains a commented, size- and age-bounded access-log block for operators who explicitly need one. Enabling it means storing every client IP, method, URI and status code for as long as the rotation keeps them — enable it only for a bounded debugging window.
- Application logs contain the client IP, HTTP method, request path, a shortened identity hash and an auth rejection reason. They never contain the request body, the signature, or the nonce.
- The Docker `json-file` driver's `max-size: 10m` / `max-file: 3` is **rotation, not "no logs"**: the services still write logs, and the files remain readable by anyone with Docker or root access. The bound is only on disk usage — roughly 30 MiB per container, with the oldest file deleted when a new one rotates in.
- That retention is **size-based, not time-based**. `json-file` does not delete entries by age, so `max-file × max-size` is an upper bound on volume and nothing guarantees that logs disappear after N days. If a time bound is required, add `max-age` (Docker 25+) to the driver options alongside `max-size`/`max-file`, switch to the `local` driver, or ship logs to an external driver with its own retention. With access logging enabled, also mount a volume for `/var/log/caddy` so Caddy's file rotation survives container restarts.

### Stealth header

`STEALTH_HEADER_NAME` / `STEALTH_HEADER_VALUE` live in `.env` (see `env.example`), are injected into Caddy and both relays, and are never committed. Rotate them by editing `.env` and running `docker compose up -d`; no rebuild is needed. Unset values fail closed (every request is rejected).

The stealth header is **not a security boundary** against someone who knows it — it only removes the relay from casual scanning. The real boundary is TLS 1.3 plus the Ed25519 request signature. If a deployment needs to restrict who may push, it needs a sender allowlist or recipient registration, which is not implemented here (see the identity model above).

### Client-side upload memory

The Rust client builds the encrypted envelope in memory and computes `SHA256(body)` over that same buffer; there is no separate hashing copy. A harness copy exists when the envelope is converted to the HTTP body, so peak client memory is roughly `2 × envelope`. The protocol ceiling is 128 MiB, which is acceptable on desktop but risky on low-memory mobile devices; a client-side cap of 64 MiB is a reasonable product choice if mobile is a target.

## Deployment

1. **Configure Environment:**
   Copy `env.example` to `.env` and fill in your domain, stealth headers, and secrets. All four variables are required: `docker compose up` aborts with an explicit error if `DOMAIN`, `ACME_EMAIL`, `STEALTH_HEADER_NAME` or `STEALTH_HEADER_VALUE` is empty, instead of starting Caddy with a Caddyfile that cannot be parsed.

2. **Run Infrastructure:**
   ```bash
   docker compose up -d --build
   ```

### Validating the Caddyfile

`Caddyfile` is fully env-driven (`{$DOMAIN}`, `{$ACME_EMAIL}`, `{$STEALTH_HEADER_NAME}`, `{$STEALTH_HEADER_VALUE}`). Caddy expands an unset variable to an **empty string**, so a bare `caddy validate` without those variables fails with a parse error, for example:

```
parsing caddyfile tokens for 'email': wrong argument count or unexpected line ending after 'email'
```

That message is about the missing `ACME_EMAIL`, not about the `email` directive itself. Always validate with an environment file:

```bash
# with your real deployment secrets
caddy validate --config Caddyfile --adapter caddyfile --envfile .env

# or, on a clean checkout, with the shipped template
caddy validate --config Caddyfile --adapter caddyfile --envfile env.example
```

`go test` in `node/` runs the same check automatically when a `caddy` binary is on `PATH` (`TestCaddyfileValidates`) and skips it otherwise.

The one warning that remains — `server is listening only on the HTTP port` — is expected: the `http://` block exists only to answer plaintext requests with `403`.

### Security Audit & Feedback

This is an open-source project dedicated to secure communications. We highly encourage community audits. If you find vulnerabilities or have suggestions regarding:

 - Ed25519 implementation logic.
 - Race conditions in the FileStore mutexes.
 - Proxy bypass techniques.

Please reach out via the secure channels below.

### Support & Donation

If this project helped you stay connected, consider supporting the maintenance:

    
| Asset | Address |
| :--- | :--- |
| **BTC** | 8Arc4tRdGAKcWNMLCb7mj2fnYqWgQGhTTgR7FEGaZpL2Pw6MNSwqsGMUGpeQGURgQbDoyxU1ASKMP7dKBJq8yJgCSwCgPYe |
| **XMR** | bc1qktffxm3579v6zs6mpms4yvwp6m067nkggd8ach |

*All donations go towards relay nodes and security audits.*

### Contact & Feedback

   Session ID: 05f08d7242fe9cd621e98ef902cd1a21a8bf10d0c7c946e8c8e469d2396657a637

   ProtonMail: nabla.shell@proton.me

   PGP Public Key: [here](https://github.com/NablaShell/LastChance/docs/public_key.asc) 
   
   *PGP Fingerprint: 885F 3675 1D87 3F99 55ED 0ABC D1F6 A559 1458 507D*


##  License
This project is licensed under the **AGPL-3.0 License** - see the LICENSE file for details.
