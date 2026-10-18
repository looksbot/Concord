# Concord

**Private, self-hosted, Discord-style chat with end-to-end encryption.**

No Discord code, names, logos, or assets. "Discord-style" refers to interaction patterns (guilds → channels → messages, realtime gateway, REST API) only.

Concord is an original implementation built after reverse-engineering Discord's client architecture (stable 1.0.162, Linux snap) to understand the protocol surface, then designing a new system where **the server cannot read any message content**.

---

## Architecture

```
 Browser (all crypto happens here)
 ├── concord-crypto.js   X25519 / Ed25519 / HKDF / AES-256-GCM (WebCrypto)
 ├── app.js              UI + gateway client + REST client
 └── localStorage        identity keys, ratchet states, wrapped channel keys
        │  HTTPS/WS (TLS at the reverse proxy for remote deployments)
        ▼
 Node server (zero npm dependencies)
 ├── index.js   HTTP + static + WS upgrade
 ├── ws.js      RFC 6455 WebSocket server implementation
 ├── api.js     REST /api/*
 ├── gateway.js Discord-style event gateway
 ├── store.js   JSON persistence (atomic tmp+rename, debounced flush)
 └── snowflake.js
 data/         users, guilds, channels, messages, invites, attachments
```

The server is a **ciphertext router**: it stores and fans out opaque encrypted envelopes, public keys, and metadata. It cannot read any message content.

---

## Encryption Design

All primitives use the browser/Node WebCrypto API (`X25519`, `Ed25519`, `HKDF-SHA256`, `AES-256-GCM`). No third-party crypto code.

### Identity (generated on first login, never leaves the device)
- **identity** — X25519 keypair (key agreement)
- **signing** — Ed25519 keypair (authenticity)

Public halves are uploaded to the server (`PUT /api/keys/@me`) along with a signed prekey (SPK) and a pool of signed one-time prekeys (OPKs).

### Direct Messages — X3DH-lite + Double Ratchet
Signal-style session setup (simplified X3DH). Alice fetches Bob's bundle (IK, SPK, OPK) and derives a root key from 4–5 DH outputs. From there a **double ratchet** runs:

- Root key ratchets on every remote DH public change;
- Per-direction chain keys ratchet per message;
- Each message key encrypts the JSON payload with AES-256-GCM (random 96-bit nonce in envelope);
- Skipped-message keys cached (bounded) for out-of-order delivery;
- Every envelope **Ed25519-signed** by the sender and verified by the receiver against the server-published signing key.

Result: forward secrecy and post-compromise recovery per DH turn. **Consequence**: DM history is only readable while the ratchet state exists in `localStorage`; a wiped profile cannot replay old DMs.

### Guild Channels — MLS-lite Envelope Encryption
Per channel a random 256-bit **channel key** `K` (rotated on member removal). `K` is stored server-side only *wrapped* for each member:

```
KEK_ij  = HKDF(X25519(identity_priv_i, identity_pub_j), "concord/kek")
wrapped_j = AES-256-GCM(KEK_ij, K)
```

Any member who holds `K` can wrap it for a new member (clients do this automatically on `GUILD_MEMBER_ADD`); the server merges wraps idempotently. Messages are `AES-256-GCM(K, payload)` + Ed25519 signature; `key_id` in the envelope identifies the generation after rotation.

This is Matrix-megolm/Signal-group-style: the server can add wrappings only for keys it was already given; it never sees `K`. Unlike the DM ratchet it has no per-message forward secrecy — documented tradeoff for history UX.

### What the Server Sees vs. Cannot See
| Sees | Cannot See |
|------|------------|
| Account names, public keys | Message content |
| Social graph (guilds, memberships) | DM plaintext |
| Message times, sizes, channels | Attachment bytes |
| Ciphertext envelopes | Channel keys |

**Safety numbers** (fingerprints of both DM identity keys) allow out-of-band verification.

---

## Protocol Surface

REST (Bearer token): `/api/auth/*`, `/api/users/*`, `/api/keys/*`, `/api/guilds/*`, `/api/channels/*`, `/api/invites/*`, `/api/attachments/*`

Gateway `WS /gateway`: `HELLO(10) → IDENTIFY(2) → READY(dispatch)`, heartbeat `1/11`, dispatch `0` with events `MESSAGE_CREATE/UPDATE/DELETE`, `TYPING_START`, `PRESENCE_UPDATE`, `GUILD_MEMBER_ADD/REMOVE`, `CHANNEL_CREATE/DELETE`, `CHANNEL_KEY_UPDATE`, `DM_CHANNEL_CREATE`.

IDs are Discord-style snowflakes (epoch 2026-01-01, BigInt → JSON string).

---

## Quick Start

```bash
# requirements: Node.js >= 22
cd concord
npm install   # only installs dev tooling; runtime has zero deps
npm start     # or: node server/index.js --port 3000 --host 127.0.0.1 --data ./data
```

Open `http://127.0.0.1:3000` in a browser. Register an account — your encryption keys are generated in the browser and never leave it.

For remote deployments, put a TLS-terminating reverse proxy (nginx, Caddy) in front and serve over HTTPS. The gateway upgrades to `wss://` automatically.

---

## Running Tests

```bash
npm test
# or
node --test
```

**Suite (8 tests):**
- 7 crypto unit tests: X3DH handshake, double ratchet (in-order, out-of-order), tamper detection, signatures, channel-key wrapping, safety numbers, bundle signature validation.
- 1 full-stack integration test: boots real server, registers two users, runs DM flow over live gateway, creates guild + invite, joins, verifies guild channel key distribution, edit/delete fan-out, kick rotation bookkeeping, and audits the data directory to prove **no plaintext or keys exist on disk**.

---

## Threat Model & Security Notes

**Protected against:**
- Passive server compromise (DB/files stolen) — all stored messages are ciphertext.
- Active server compromise (malicious admin) — cannot forge messages (Ed25519 signatures verified against published signing keys); cannot read past DMs (ratchet forward secrecy); cannot decrypt guild channels without a member's cooperation.
- Network eavesdropping — TLS at transport layer + AEAD at application layer.
- Replay / reordering — per-message nonces + double-ratchet sequencing + skipped-key cache.

**Not protected against (by design):**
- **Endpoint compromise** — if your device is malware-infected, keys and plaintext are exposed. This is a local-first app; hardware-backed keystore integration is future work.
- **Key compromise without rotation** — if an identity key is leaked, past DMs are safe (forward secrecy), but future DMs and all guild channels the member can access are vulnerable until the member is removed and keys rotated.
- **Metadata analysis** — the server sees who talks to whom, when, and how much.
- **Denial of service** — no rate limiting, no authz beyond guild membership in this MVP.

**Passwords** are only for authentication (scrypt); they never wrap key material. If you forget the password you can reset the account, but **cannot read old messages**.

---

## Legal

Concord contains no Discord code, names, logos, or assets. "Discord-style" refers to interaction patterns only. Reverse engineering was performed on a locally installed copy for interoperability-inspired, educational study.

---

## License

[MIT](LICENSE) — do whatever you want, but don't blame us if your secrets leak.