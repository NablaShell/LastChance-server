# Shared auth vectors

`auth_vectors.json` pins the wire contract between the Rust client
(`src/network/auth.rs`) and both Go services:

- canonical envelope: `METHOD \n PATH \n CANONICAL_QUERY \n TIMESTAMP \n NONCE \n SHA256(body)`;
- query pairs sorted by key, then value, with percent-encoding preserved;
- base64url without padding for nonce and signature;
- Ed25519 signature over the canonical bytes.

The signature vector uses the fixed seed `01` repeated 32 times, timestamp
`1700000000`, and a 24-byte nonce `00 01 02 … 17`. It was verified against the
actual Rust client with a temporary `cargo test`, so a divergence in the client
or either Go verifier fails
`TestCanonicalVectorsMatchSharedFixture`.
