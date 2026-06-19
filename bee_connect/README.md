# bee_connect

Client-side helpers for AckiNacki wallet connect flows over `ackinacki-kit` `authservice`.

`bee_connect` is intended for the dApp/client side.
Wallet-side acceptance/deploy/send-first-message flow lives in `bee_wallet` (`connect` module).

## What It Does

`bee_connect` helps the dApp:

- create a connect session with ephemeral X25519 Diffie-Hellman key exchange
- derive deterministic `AuthProfile` address from `description`
- wait for the first wallet message (`wallet_hello`) and finalize DH key agreement
- send encrypted protocol requests (`set_mining_keys`, `client_disconnect`)
- query active sessions by multifactor wallet

## Protocol: `shared_key` (bidirectional, DH-authenticated)

Secure bidirectional channel over one `AuthProfile`. No secrets are transmitted
in URLs or deeplinks — only the client's X25519 public key.

### Handshake Flow

```
Client                     links.gosh.sh              Wallet
  │                              │                       │
  │ generate X25519 keypair      │                       │
  │                              │                       │
  │── URL: payload + dh_pub ───>│────> deeplink ────────>│
  │   (NO SECRETS IN URL!)       │                       │
  │                              │                       │ generate X25519 keypair
  │                              │                       │ shared_secret = DH(w_sec, c_pub)
  │                              │                       │ signing, encryption = HKDF(shared)
  │                              │                       │
  │                              │                       │ deploy AuthProfile(signing.pub)
  │                              │                       │ wallet_hello:
  │                              │                       │   dh_public: wallet_dh_pub
  │                              │                       │   body: encrypted(name, addr)
  │                              │                       │
  │<── poll AuthProfile ─────────────────────────────────│
  │ shared_secret = DH(c_sec, w_pub)                     │
  │ signing, encryption = HKDF(shared)                   │
  │ decrypt body ✓                                       │
  │                              │                       │
  │ rekey_outbound:              │                       │
  │   new DH, new root           │                       │
  │── set_mining_keys ──────────────────────────────────>│
  │   (encrypted with new_root,  │                       │ rekey_inbound:
  │    dh_public: new_pub)       │                       │   DH(my_sec, new_pub) → new root
  │                              │                       │
  │── disconnect ───────────────────────────────────────>│
  │   (re-keyed again)           │                       │ rekey_inbound again
```

### Step by Step

1. **Client** calls `create_shared_key_session(app_id, ttl_secs)`
   - Generates ephemeral X25519 keypair
   - Returns `client_dh_public` (in URL) and `client_dh_secret` (caller stores)
   - Deeplink URL: `?payload=<b64url>&client_dh_public=<hex>`

2. **Wallet** receives deeplink, calls `accept_shared_key_connect(payload, client_dh_public, ...)`
   - Generates wallet X25519 keypair
   - Computes `shared_secret = X25519(wallet_secret, client_dh_public)`
   - Derives session keys (`signing_keys` + `encryption_root`) via HKDF-SHA256
   - Returns `session_state: ConnectSessionState` (caller persists)
   - Deploys AuthProfile with derived signing public key
   - Sends `wallet_hello` with `dh_public` field (wallet's public key, cleartext)

3. **Client** calls `wait_wallet_hello(session_id, description, client_dh_secret)`
   - Polls AuthProfile for `wallet_hello`
   - Extracts `dh_public` from envelope
   - Computes same `shared_secret = X25519(client_secret, wallet_dh_public)`
   - Derives identical session keys
   - Decrypts and verifies wallet_hello body
   - Returns `session_state: ConnectSessionState` for subsequent operations

4. **Messaging** — each outbound message performs DH re-key (forward secrecy), encrypts with new root, includes `dh_public` in envelope. Caller persists `updated_session_state` after each send.

### Key Derivation

```
shared_secret = X25519(my_secret, their_public)

signing_seed    = HKDF-SHA256(ikm=shared_secret, salt=session_id, info="bee_connect.signing.v1")
encryption_root = HKDF-SHA256(ikm=shared_secret, salt=session_id, info="bee_connect.encryption.v1")

signing_key = Ed25519::SigningKey(signing_seed)
```

### Re-Key (Forward Secrecy)

Every outbound message performs a DH re-key before encryption:

```
new_dh         = X25519::generate()
shared         = X25519(new_dh.secret, peer_dh_public)
ikm            = old_encryption_root || shared    (64 bytes)
new_root       = HKDF-SHA256(ikm, salt=session_id, info="bee_connect.rekey.v1")
```

The `new_root` replaces `encryption_root` in the session state. The `new_dh.public` is included in the envelope's `dh_public` field. Old roots are discarded — forward secrecy.

### All HKDF Info Labels

| Purpose | Info | IKM |
|---------|------|-----|
| Signing key | `bee_connect.signing.v1` | DH shared secret (32 bytes) |
| Encryption root | `bee_connect.encryption.v1` | DH shared secret (32 bytes) |
| Per-message re-key | `bee_connect.rekey.v1` | old_root \|\| new_DH_shared (64 bytes) |
| Per-message encryption key | `bee_connect.msg.key.v1` | current encryption_root |

All use HKDF-SHA256 with `salt = session_id` (except per-message key which uses `salt = random_32_bytes`).

### MITM Protection

- **Passive intercept**: URL contains only `client_dh_public` — useless without secret
- **Active MITM** (public key substitution): client and wallet derive different shared secrets → wallet_hello decryption fails → session not established (DoS, not silent interception)
- **Low-order point attack**: DH shared secret is checked for all-zero bytes — rejected before key derivation

## Message Envelope (`bee_connect.msg/1`)

All messages are encrypted. Unencrypted (`alg: "none"`) messages are rejected.

### Envelope shape

```json
{
  "v": "bee_connect.msg/1",
  "session_id": "base64url-random",
  "dir": "w2c",
  "seq": 1700000000000,
  "type": "wallet_hello",
  "ts": 1700000000,
  "dh_public": "<hex, present in wallet_hello and all c2w messages after re-key>",
  "enc": {
    "alg": "xchacha20poly1305-hkdf-sha256",
    "nonce": "<base64url>",
    "salt": "<base64url>"
  },
  "body": "<base64url ciphertext>"
}
```

Fields:
- `v` — protocol version (`bee_connect.msg/1`)
- `session_id` — session identifier
- `dir` — direction: `w2c` (wallet→client) or `c2w` (client→wallet)
- `seq` — monotonic sequence number (millisecond timestamp for replay protection)
- `type` — message type: `wallet_hello`, `set_mining_keys`, `client_disconnect`
- `ts` — timestamp (seconds)
- `dh_public` — ephemeral X25519 public key for DH re-key; present in `wallet_hello` and all c2w messages
- `enc` — encryption metadata
- `body` — encrypted message body (base64url)

### Per-Message Encryption

```
per_message_key = HKDF-SHA256(ikm=encryption_root, salt=random_salt, info="bee_connect.msg.key.v1")
ciphertext = XChaCha20-Poly1305(key=per_message_key, nonce=random, plaintext=body, aad=envelope_metadata)
```

AAD includes: `v`, `session_id`, `dir`, `seq`, `type`, `ts`.

## Deeplink Payload (`bee_connect.dl/1`)

```json
{
  "v": "bee_connect.dl/1",
  "session_id": "base64url-random",
  "description": "bee_connect:v1:<app_id>:<session_id>:<random>",
  "expires_at": 1730000600,
  "app_id": "0x0000000000000000000000000000000000000000000000000000000000000001"
}
```

Deeplink URL query parameters:
- `payload=<base64url>` — encoded ConnectPayload
- `client_dh_public=<hex>` — client X25519 public key (64 hex chars)

## Cryptographic Primitives

| Purpose | Primitive | Key Size |
|---------|-----------|----------|
| DH key exchange | X25519 | 32 bytes |
| Key derivation | HKDF-SHA256 | — |
| On-chain signing | Ed25519 (verify_strict) | 32 bytes |
| Message encryption | XChaCha20-Poly1305 | 32 bytes |
| Replay protection | seq = now_millis() | u64 |

## Rust API

Core methods on `ConnectClient`:

- `create_shared_key_session(app_id, ttl_secs)` → session + DH keypair
- `decode_connect_payload_b64url(payload_b64url)` → parsed payload
- `get_profile_address(endpoints, description)` → profile address
- `is_session_profile_deployed(endpoints, description)` → bool
- `wait_wallet_hello(endpoints, session_id, description, client_dh_secret, ...)` → wallet info + session_state
- `request_set_mining_keys(endpoints, session_id, description, session_state, ...)` → message_id, updated_session_state
- `wait_set_mining_keys_request(endpoints, session_id, description, session_state, ...)` → app_id, owner_public, updated_session_state
- `disconnect_session(endpoints, session_id, description, session_state, ...)` → message_id, updated_session_state
- `query_active_sessions_by_multifactor(endpoints, multifactor_address, ...)` → sessions

DH helpers (`bee_connect::dh`):

- `generate_dh_keypair()` → DhKeyPair (public_hex, secret_hex)
- `compute_shared_secret(my_secret_hex, their_public_hex)` → shared_secret_hex
- `derive_session_keys(shared_secret_hex, session_id)` → DhSessionKeys (signing + encryption)
- `create_initial_state(session_keys, my_dh_secret, peer_dh_public)` → ConnectSessionState
- `rekey_outbound(state, session_id)` → RekeyResult (new root, new dh_public, updated state)
- `rekey_inbound(state, peer_new_dh_public, session_id)` → RekeyResult (new root, updated state)

## Data Contracts

### `ConnectSessionState`

Persisted by both client and wallet after every operation. JSON-serializable.

```rust
pub struct ConnectSessionState {
    pub encryption_root: Zeroizing<String>,  // hex, 32 bytes — rotated every message
    pub my_dh_secret: Zeroizing<String>,     // hex, 32 bytes — rotated on outbound
    pub peer_dh_public: String,              // hex, 32 bytes — updated on inbound
    pub signing_public: String,              // hex, 32 bytes — fixed for session
    pub signing_secret: Zeroizing<String>,   // hex, 32 bytes — fixed for session
    pub created_at: u64,                     // UNIX epoch seconds
    pub expires_at: u64,                     // UNIX epoch seconds (default: created_at + 24h)
}
```

- Secret fields are `Zeroizing<String>` — zeroed on drop.
- `created_at` / `expires_at` — set at handshake, carried through re-keys.
- `expires_at == 0` means legacy state (no expiration).
- `rekey_outbound` / `rekey_inbound` reject expired sessions.
- Default TTL: `DEFAULT_SESSION_TTL_SECS = 86400` (24 hours).

### `ResultOfWaitWalletHello`

Returned by `wait_wallet_hello` after successful DH finalization.

```rust
pub struct ResultOfWaitWalletHello {
    pub profile_address: String,            // on-chain AuthProfile address
    pub event_id: String,                   // wallet_hello event ID
    pub event_created_at: u64,              // event timestamp (seconds)
    pub wallet_name: String,                // from decrypted body
    pub wallet_address: String,             // from decrypted body
    pub raw_message_json: String,           // full envelope JSON for audit
    pub session_state: ConnectSessionState, // initial state for subsequent operations
}
```

### `ResultOfRequestSetMiningKeys`

```rust
pub struct ResultOfRequestSetMiningKeys {
    pub profile_address: String,
    pub message_id: Option<String>,
    pub updated_session_state: ConnectSessionState,
}
```

### `ResultOfWaitSetMiningKeysRequest`

```rust
pub struct ResultOfWaitSetMiningKeysRequest {
    pub profile_address: String,
    pub event_id: String,
    pub event_created_at: u64,
    pub app_id: String,
    pub owner_public: String,
    pub raw_message_json: String,
    pub updated_session_state: Option<ConnectSessionState>,
}
```

## Wallet-Side API (`bee_wallet`)

The wallet implements the other side of the protocol:

| Method | What it does |
|--------|-------------|
| `decode_connect_payload_b64url(payload)` | Parse deeplink payload |
| `accept_connect_shared_key(params)` | DH handshake + deploy AuthProfile + send wallet_hello |
| `query_connect_session_messages(params)` | Poll for c2w messages with automatic re-key |
| `destroy_connect_profile(params)` | Destroy AuthProfile on-chain |

See `bee_wallet` crate and `PROTOCOL.md` for full wallet-side documentation.

## TypeScript / WASM

Session state is passed as JSON string across the WASM boundary. Parse with:

```typescript
import type { TConnectSessionState } from "@teamgosh/bee-sdk";

const state: TConnectSessionState = JSON.parse(sessionStateJson);

// Check expiration in UI
if (state.expires_at > 0 && Date.now() / 1000 >= state.expires_at) {
  // Session expired — destroy profile and reconnect
}

// Pass back to WASM
const json = JSON.stringify(state);
```

The `TConnectSessionState` type is auto-generated by `wasm-bindgen` and exported from both `bee_connect` and `bee_wallet` WASM packages.

## Input Normalization

Hex inputs are normalized before use:

- **`app_id`**: Stripped of `0x`/`0X` prefix, left-padded to 64 chars, lowercased, prepended with `0x`.
  Example: `"0x1"` → `"0x0000000000000000000000000000000000000000000000000000000000000001"`
- **`owner_public`**: Stripped of `0x`/`0X` prefix, lowercased. Must be exactly 64 hex chars (32 bytes).
  Example: `"0xAABB...CC"` → `"aabb...cc"`

These normalizations are applied by both `bee_connect` and `bee_wallet` via shared functions in `bee_connect::message`.

## Polling Limits

Methods that poll on-chain state (`wait_wallet_hello`, `wait_set_mining_keys_request`, etc.) accept `max_attempts` as `u32`. Internally, `wait_account` (from `ackinacki-kit`) accepts `u8`, so values above **255** are clamped silently.

## Minimal Usage

```rust
use bee_connect::{ConnectClient, ParamsOfCreateSharedKeySession, ParamsOfWaitWalletHello, ParamsOfRequestSetMiningKeys};

let client = ConnectClient::new();

// Phase 1: Create session (generates X25519 DH keypair)
let session = client.create_shared_key_session(ParamsOfCreateSharedKeySession {
    app_id: "0x1".to_string(),
    ttl_secs: Some(300),
})?;

// session.deep_link — open in wallet app (contains only client_dh_public)
// session.client_dh_secret — store for phase 3

// Phase 3: Wait for wallet_hello + DH finalize
let hello = client.wait_wallet_hello(ParamsOfWaitWalletHello {
    endpoints: vec!["https://your-endpoint".to_string()],
    session_id: session.session_id.clone(),
    description: session.description.clone(),
    client_dh_secret: session.client_dh_secret.clone(),
    created_at_from: Some(session.created_at),
    max_attempts: Some(120),
    interval_ms: Some(1000),
}).await?;

// hello.session_state — persist this for all subsequent operations
// Contains signing keys, encryption root, DH keys for forward secrecy

// Phase 4: Send message (re-keys automatically for forward secrecy)
let result = client.request_set_mining_keys(ParamsOfRequestSetMiningKeys {
    endpoints: vec!["https://your-endpoint".to_string()],
    session_id: session.session_id.clone(),
    description: session.description.clone(),
    session_state: hello.session_state,  // ← pass current state
    app_id: "0x1".to_string(),
    owner_public: "your-mining-public-key-hex".to_string(),
    max_attempts: Some(30),
    interval_ms: Some(1000),
}).await?;

// MUST persist updated state — old state is no longer valid
let session_state = result.updated_session_state;
```

## Security Properties

- **Forward secrecy**: per-message DH re-key discards old roots — past messages are unrecoverable even if current state is compromised.
- **Mutual authentication**: successful `wallet_hello` decryption proves both sides share the same DH secret.
- **Replay protection**: `seq` (millisecond timestamp) is included in AEAD AAD.
- **Metadata integrity**: `session_id`, `dir`, `type`, `ts` are AEAD-authenticated.
- **Session timeout**: `ConnectSessionState` carries `expires_at` — operations reject expired sessions (default 24h TTL).
- **Memory safety**: secret fields use `Zeroizing<String>` — zeroed on drop.
- **Low-order point rejection**: all-zero DH shared secrets are rejected.

See `PROTOCOL.md` for full security analysis including signing key lifetime, wallet identity, and threat model.

## Build

Native:

```bash
cargo check -p bee-connect
cargo test -p bee-connect
```

WASM:

```bash
cargo check -p bee-connect --target wasm32-unknown-unknown --no-default-features --features single-wasm
```
