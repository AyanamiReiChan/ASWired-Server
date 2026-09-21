# ASWired Agent channel v1

This is ASWired's own implementation, authorized on 2026-09-15. It does not claim compatibility with miaomiaowuX private protocols.

The master owns a persistent X25519 identity key. An agent pins `master_public_key`, generates a new ephemeral X25519 key for each connection and derives independent AES-256-GCM keys with HKDF-SHA256. The salt binds the protocol and both public keys. Nonces derive from strictly increasing per-direction sequence numbers. Reordered, replayed or unauthenticated frames fail closed. Never reuse an ephemeral key across sessions.

The first encrypted report contains `server_id`, the server token, version, mode, timestamp, actual observations and capabilities. WS `/api/agent/ws` receives a `Hello` first, then alternating report/reply encrypted packets. HTTP `/api/agent/pull` uses a fresh `Hello` per request and returns one encrypted reply. The master caches the ephemeral public keys for the timestamp validity window to reject replays of HTTP handshakes. TLS remains required on public deployments to protect metadata and endpoints.

`Report` and `Reply` types are maintained in `pkg/agentwire`. The Agent repository pins a byte-identical snapshot in `internal/wire`. Update both together and run cross-peer tests when changing the version.

Commands identify an operation and action. Result status `success` is permitted only after actual execution; unsupported operations return `unsupported`, failures `failed`. State saved by a controller is not proof of execution. Results of a repeated operation ID are not applied twice. Queued commands and completed results are separate from telemetry.

Direct HTTP first requests `/v1/hello?nonce=<32 random bytes, unpadded base64url>`. The response contains `protocol: aswired-direct-hello-v1`, `nonce`, `public_key`, `server_id`, `master_public_key`, Unix-second `timestamp`, and `proof`. The proof is unpadded base64url HMAC-SHA256 using the Agent API token over those first six fields in that order, separated by LF with no final LF. The controller checks the exact nonce and both expected identities, a timestamp within 90 seconds, and the complete proof before sending any credentials or configuration. Missing or invalid proofs are rejected; there is no unauthenticated fallback.

After that verification, the master derives the server role channel with its static private key and sends an encrypted `DirectRequest` to `/v1/rpc`; the request includes the Agent API token, command and timestamp. Agent retains each hello for at most 30 seconds and consumes it once. Its response is encrypted in the reverse direction. WS mode closes the direct listener. Both components must be upgraded together for this handshake.

User JWT, server token, Agent API token, subscription token, home endpoint identity and federation identity have different scopes and are never interchangeable.
