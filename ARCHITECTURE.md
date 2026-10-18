# Concord — Architecture

Concord is an original, self-hostable, Discord-style chat server + web client with
end-to-end encryption. No Discord code, assets, or trademarks are used; the UX
model (guilds → channels → messages, realtime gateway, REST API) follows the
category Discord popularized.

## 1. Reverse-engineering findings (what informed this design)

Target: Discord stable **1.0.162** (Linux snap), shipped artifacts only.
REA evidence: `analyze_javascript_application` on `discord_desktop_core`,
evidence id `ev_f19773c5f1fc2df8312c136278cf0c02775c0a239d20f56a06b812755fb8aee4`
(subject sha256 `183fcc8e…`). Facts below are split into **observations**
(read from shipped artifacts) vs **design choices** (not claimed to come from
the artifacts).

### Observations

| # | Finding | Evidence |
|---|---------|----------|
| O1 | Discord desktop is a modular Electron host: `app.asar` bootstrap + `standalone_modules/` (`discord_desktop_core`, `discord_erlpack`, `discord_voice`, `discord_krisp`, `discord_rpc`, `discord_utils`, …). `build_info.json`: `{"releaseChannel":"stable","version":"1.0.162","standaloneModules":true}` | snap tree `/snap/discord/current/usr/share/discord/resources/` |
| O2 | `discord_desktop_core` = `core.asar` (`bundle.js` host main, `mainScreenPreload.js`); REA: 1 contextBridge API surface, 5 IPC operations with dynamic channel names; the preload's semantic graph exceeded the result budget (retained as static facts). | REA evidence `ev_f19773c5…` limitations + summary |
| O3 | Gateway/REST protocol constants (gateway URL, opcodes, `/api/v*` paths) are **absent** from the shipped host bundles; extracted `bundle.js` contains only CDN/CDN-asset and acknowledgements URLs. They arrive with the runtime-downloaded webapp (no logged-in profile exists on this host, so that payload was not available). | strings/grep of extracted `core.asar` |
| O4 | `discord_erlpack` is a native `.node` ETF (Erlang Term Format) codec — the gateway's binary encoding path is shipped as a native module; the RPC layer uses JSON. | `standalone_modules/discord_erlpack/index.js`, `discord_rpc/*` |
| O5 | `discord_rpc` ships a readable local WebSocket server (`RPCWebSocket.js` uses the `ws` package) with framed messages carrying `cmd`/`args`/`evt`/`nonce` fields — a request/dispatch shape over WS. | `standalone_modules/discord_rpc/RPCWebSocket.js`, `RPCIPC.js` |
| O6 | The shipped host contains no message-content cryptography: crypto in artifacts is transport TLS (discord.com/CDN hosts) plus voice-engine modules. Desktop artifacts alone can't prove the webapp lacks message crypto, but no such layer exists in anything shipped here. | O1–O4 inventory; negative search is bounded to shipped artifacts |

### Design choices (homage, not artifact-derived)

* Gateway opcode semantics (HELLO 10 / IDENTIFY 2 / HEARTBEAT 1 / HEARTBEAT_ACK 11 / DISPATCH 0 with typed events like `MESSAGE_CREATE`, `READY`, `TYPING_START`) follow Discord's *publicly documented* gateway protocol. Chosen for familiar developer ergonomics; O3 means these constants were not lifted from the shipped bundles.
* Snowflake-style IDs (BigInt, stringified on the wire).
* JSON text frames everywhere instead of ETF (O4): auditability and zero-dependency clients over compactness.
* What O5/O6 motivate: Concord's entire differentiator — message bodies are **never** visible to the server (§3).

## 2. System shape

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

The server is a *ciphertext router*: it stores and fans out opaque encrypted
envelopes, public keys, and metadata. It cannot read any message content.

## 3. End-to-end encryption design

All primitives are WebCrypto (`X25519`, `Ed25519`, `HKDF-SHA256`,
`AES-256-GCM`, `PBKDF2` for optional key export — none leave the client.
The same module runs in browsers and in Node 22 (tests).

### 3.1 Identity

On registration the client generates and stores in `localStorage`:

* `identity` — X25519 keypair (key agreement)
* `signing` — Ed25519 keypair (authenticity)

Only public halves are uploaded (`PUT /api/keys/@me`) together with a signed
prekey (SPK) and a pool of signed one-time prekeys (OPKs). The password is
only for **authentication**; it never wraps key material in this MVP (see
README threat model).

### 3.2 Direct messages — X3DH-lite + double ratchet

Signal-style session setup (simplified X3DH). Alice fetches Bob's bundle
(identity key IK_B, signed prekey SPK_B, one OPK_B) and computes:

```
DH1 = X25519(IK_A_priv, IK_B_pub)
DH2 = X25519(IK_A_priv, SPK_B_pub)
DH3 = X25519(EK_A_priv, IK_B_pub)     EK_A = fresh ephemeral
DH4 = X25519(EK_A_priv, SPK_B_pub)
DH5 = X25519(EK_A_priv, OPK_B_pub)    (if an OPK was available)
SK   = HKDF(0, DH1‖DH2‖DH3‖DH4‖DH5, "concord/x3dh/dm")
```

Bob derives the same SK from the public keys carried in the first envelope's
`header`. From there a **double ratchet** runs:

* Root key ratchets on every change of the remote DH public (`KDF_RK`);
  per-direction chain keys ratchet per message (`KDF_CK` → next chain key ‖
  message key);
* message key encrypts the JSON payload with AES-256-GCM (random 96-bit
  nonce stored in the envelope);
* skipped-message keys are cached (bounded) for out-of-order delivery;
* every envelope is **Ed25519-signed** by the sender and verified by the
  receiver against the server-published signing key.

Result: forward secrecy and post-compromise recovery per DH turn, like
Signal. Consequence (intentional): DM history is only readable while the
ratchet state exists in `localStorage`; a wiped profile cannot replay old
DMs. Guild channels (below) keep full history decryptable.

### 3.3 Guild channels — MLS-lite envelope encryption

Per channel there is a random 256-bit **channel key** `K` (rotated on
member removal). `K` is stored server-side only *wrapped* for each member:

```
KEK_ij  = HKDF(X25519(identity_priv_i, identity_pub_j), "concord/kek")
wrapped_j = AES-256-GCM(KEK_ij, K)
```

Any member who holds `K` can wrap it for a new member (clients do this
automatically on `GUILD_MEMBER_ADD`); the server merges wraps idempotently.
Messages are `AES-256-GCM(K, payload)` + Ed25519 signature; `key_id` in the
envelope identifies the generation after rotation.

This is Matrix-megolm/Signal-group-style: the server can add wrappings only
for keys it was already given; it never sees `K`. Unlike the DM ratchet it
has no per-message forward secrecy — documented tradeoff for history UX.

### 3.4 What the server can and cannot see

Sees: account names, public keys, social graph (guilds/memberships), message
times/sizes/channel, ciphertext. Cannot see: any message content, DM
plaintext, attachment bytes, or channel keys. Safety numbers (fingerprints
of both DM identity keys) allow out-of-band verification.

## 4. Protocol surface

REST (Bearer token): auth, users, keys, guilds, channels, invites, messages
(ciphertext in/out), wrapped channel keys, attachments (opaque blobs).

Gateway `WS /gateway`: `HELLO(10) → IDENTIFY(2) → READY(dispatch)`,
heartbeat `1/11`, dispatch `0` with events `MESSAGE_CREATE/UPDATE/DELETE`,
`TYPING_START`, `PRESENCE_UPDATE`, `GUILD_MEMBER_ADD/REMOVE`,
`CHANNEL_CREATE/DELETE`, `CHANNEL_KEY_UPDATE`, `DM_CHANNEL_CREATE`.

IDs are Discord-style snowflakes (epoch 2026-01-01, BigInt → JSON string).

## 5. Legal notice

Concord contains no Discord code, names, logos, or assets. "Discord-style"
refers to interaction patterns only. Reverse engineering was performed on a
locally installed copy for interoperability-inspired, educational study.
