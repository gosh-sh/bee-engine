# bee_connect Protocol — DH Key Exchange Flow

## Overview

Connect protocol (`bee_connect.msg/1`) provides a secure channel between the client (dApp/miner) and wallet via an on-chain AuthProfile. All messages are encrypted. Secrets are **never transmitted** through URLs, QR codes, or other observable channels.

Instead of passing a session secret in the URL, ephemeral X25519 Diffie-Hellman key exchange is used. Both sides independently derive identical session keys.

---

## Participants

- **Client** — dApp or miner, initiates the session
- **Wallet** — mobile or desktop wallet, accepts the session
- **AuthProfile** — on-chain contract for exchanging encrypted messages
- **links.gosh.sh** — deeplink URL resolver (sees only the public DH key)

---

## Phase 1: Session Creation (Client)

```
Client: create_shared_key_session(app_id, ttl_secs)
```

1. Generates `session_id`, `description`, `expires_at`
2. Generates ephemeral **X25519 keypair** (`client_dh_public`, `client_dh_secret`)
3. Builds deeplink URL:
   ```
   https://links.gosh.sh/deeplinks/wallet/v1/connect
     ?payload=<base64url(ConnectPayload)>
     &client_dh_public=<64 hex chars>
   ```
4. Caller receives `ResultOfCreateSharedKeySession`:
   - `session_id`, `description`, `payload_b64url`
   - `client_dh_public` — public key (in URL)
   - `client_dh_secret` — secret key (**caller stores**, never transmitted)
   - `deep_link` — URL with no secrets

```
┌────────────────────────────────────────────────────┐
│ URL contains ONLY client_dh_public                  │
│ links.gosh.sh does NOT see any secrets              │
│ Intercepting the URL is useless without             │
│ client_dh_secret                                    │
└────────────────────────────────────────────────────┘
```

---

## Phase 2: Session Acceptance (Wallet)

```
Wallet: accept_shared_key_connect(payload, client_dh_public, wallet_name, wallet_address)
```

1. Wallet parses `payload` and `client_dh_public` from the deeplink URL
2. Generates wallet ephemeral **X25519 keypair** (`wallet_dh_public`, `wallet_dh_secret`)
3. **DH Key Agreement**:
   ```
   shared_secret = X25519(wallet_dh_secret, client_dh_public)  // 32 bytes
   ```
4. **Key Derivation** (HKDF-SHA256, salt = session_id):
   ```
   signing_seed     = HKDF(shared_secret, info="bee_connect.signing.v1")
   encryption_root  = HKDF(shared_secret, info="bee_connect.encryption.v1")

   signing_key = Ed25519::SigningKey(signing_seed)   // for on-chain transactions
   // encryption_root is used as input for per-message HKDF
   ```
5. **Deploy AuthProfile** on-chain with `signing_key.public`
6. **wallet_hello** — first encrypted message:
   ```json
   {
     "v": "bee_connect.msg/1",
     "session_id": "...",
     "dir": "w2c",
     "seq": 1700000000000,
     "type": "wallet_hello",
     "ts": 1700000000,
     "dh_public": "<wallet_dh_public hex>",
     "enc": {
       "alg": "xchacha20poly1305-hkdf-sha256",
       "nonce": "<base64url>",
       "salt": "<base64url>"
     },
     "body": "<encrypted base64url>"
   }
   ```
   - `dh_public` — **cleartext** top-level field so client can read it before decryption
   - `body` is encrypted with `encryption_root`
   - On-chain transaction signature uses `signing_key`

7. Wallet receives `ResultOfAcceptConnect`:
   - `session_state: ConnectSessionState` — **wallet stores** for all subsequent operations
     (contains signing keys, encryption root, DH keys for forward secrecy)

---

## Phase 3: DH Finalization (Client)

```
Client: wait_wallet_hello(session_id, description, client_dh_secret)
```

1. Client polls AuthProfile on-chain, waiting for `wallet_hello`
2. Extracts `dh_public` (wallet's public key) from the envelope
3. **DH Key Agreement** (mirrors wallet):
   ```
   shared_secret = X25519(client_dh_secret, wallet_dh_public)
   // Identical to shared_secret on the wallet side!
   ```
4. **Key Derivation** — identical HKDF:
   ```
   signing_seed     = HKDF(shared_secret, info="bee_connect.signing.v1")    // == wallet's
   encryption_root  = HKDF(shared_secret, info="bee_connect.encryption.v1") // == wallet's
   ```
5. Decrypts `body` using `encryption_root` — success verifies the DH exchange
6. Client receives `ResultOfWaitWalletHello`:
   - `wallet_name`, `wallet_address` — from decrypted body
   - `session_state: ConnectSessionState` — **client stores** for all subsequent operations
     (contains signing keys, encryption root, DH keys for forward secrecy)

---

## Phase 4: Message Exchange (Forward Secrecy)

After handshake both sides store a `ConnectSessionState`:

```rust
ConnectSessionState {
    encryption_root: Zeroizing<String>,  // rotated every message, zeroed on drop
    my_dh_secret: Zeroizing<String>,     // rotated on every outbound message, zeroed on drop
    peer_dh_public: String,              // updated on every inbound message
    signing_public: String,              // fixed for session lifetime
    signing_secret: Zeroizing<String>,   // fixed for session lifetime, zeroed on drop
    created_at: u64,                     // UNIX epoch seconds, set at handshake
    expires_at: u64,                     // UNIX epoch seconds, default = created_at + 24h
}
```

**Every outbound message performs a DH re-key for forward secrecy:**

1. Sender generates new ephemeral X25519 keypair
2. Computes `new_shared = X25519(new_secret, peer_dh_public)`
3. Derives `new_root = HKDF(old_root || new_shared, salt=session_id, info="bee_connect.rekey.v1")`
4. Encrypts message body with `new_root`
5. Includes `dh_public` (new public key) in the envelope
6. Updates local state: `encryption_root = new_root`, `my_dh_secret = new_secret`
7. Old root is discarded → forward secrecy

**Receiver mirrors the re-key:**

1. Reads `dh_public` from envelope
2. Computes `new_shared = X25519(my_dh_secret, peer_new_dh_public)`
3. Derives same `new_root = HKDF(old_root || new_shared, ...)`
4. Decrypts message body with `new_root`
5. Updates local state: `encryption_root = new_root`, `peer_dh_public = peer_new_dh_public`

### Client → Wallet: set_mining_keys

```
Client: request_set_mining_keys(session_state, app_id, owner_public) → updated_session_state
```

Caller MUST persist `updated_session_state` and discard old state.

Envelope example (after re-key):

```json
{
  "v": "bee_connect.msg/1",
  "session_id": "...",
  "dir": "c2w",
  "seq": 1700000001000,
  "type": "set_mining_keys",
  "ts": 1700000001,
  "dh_public": "<new ephemeral X25519 public key hex>",
  "enc": {
    "alg": "xchacha20poly1305-hkdf-sha256",
    "nonce": "<base64url>",
    "salt": "<base64url>"
  },
  "body": "<encrypted base64url>"
}
```

The `dh_public` field contains the sender's new ephemeral public key. The receiver uses it to perform `rekey_inbound` before decryption.

### Client → Wallet: sign_challenge (Backend Auth)

```
Client: request_sign_challenge(session_state, nonce) → updated_session_state
```

Proves wallet ownership to a backend. The flow:

1. **Backend** generates a random nonce (hex string) and gives it to the dApp client
2. **Client** sends `sign_challenge` (c2w) with the nonce through the connect session
3. **Wallet** receives the challenge, signs the nonce with its EPK key, and responds with `challenge_response` (w2c)
4. **Client** receives `challenge_response` containing `{ nonce, signature, wallet_address }`
5. **Client** forwards `signature` + `wallet_address` to the backend
6. **Backend** verifies the Ed25519 signature against the wallet's on-chain public key

Body (encrypted):
```json
{ "nonce": "<hex string from backend>" }
```

### Wallet → Client: challenge_response

```
Wallet: (responds to sign_challenge via query_session_messages)
```

The wallet signs the nonce from `sign_challenge` using its EPK key (`sign_detached_hex(nonce, epk_secret)`).

Body (encrypted):
```json
{
  "nonce": "<echoed nonce>",
  "signature": "<Ed25519 hex signature>",
  "wallet_address": "<multifactor address>",
  "epk_public": "<EPK public key hex, 64 chars>"
}
```

`epk_public` is the Ed25519 public key the wallet used to sign the nonce. The field is optional for backward compatibility with older wallets (`#[serde(default)]`).

**Backend verification (Python example):**
```python
from nacl.signing import VerifyKey  # pip install PyNaCl

# 1. Verify signature (offline, no chain access)
nonce_bytes = bytes.fromhex(nonce)
signature_bytes = bytes.fromhex(signature)
verify_key = VerifyKey(bytes.fromhex(epk_public))
verify_key.verify(nonce_bytes, signature_bytes)  # raises BadSignatureError

# 2. Confirm EPK is registered in multifactor contract (one RPC call, cacheable)
#    Call get_epk_expire_at(wallet_address, epk_public) on chain
#    If returns valid non-expired timestamp → EPK belongs to this wallet
```

**State persistence:** The dApp MUST NOT persist `updated_session_state` from `request_sign_challenge` until `wait_challenge_response` succeeds. If the wait times out, the wallet has already advanced its DH chain (inbound rekey for `sign_challenge` + outbound rekey for `challenge_response`), while the dApp only did one outbound rekey. Persisting early makes the desync permanent. By keeping the pre-challenge state on timeout, the dApp can re-establish the session cleanly.

### Client → Wallet: disconnect

```
Client: disconnect_session(session_state, reason) → updated_session_state
```

### Wallet → query

```
Wallet: query_session_messages(session_id, description, session_state) → messages, updated_session_state
```

The wallet re-keys for every c2w message with `dh_public` to maintain the chain.

---

## Per-Message Encryption

Each message is encrypted individually:

```
1. random salt (32 bytes) + random nonce (24 bytes)
2. per_message_key = HKDF-SHA256(ikm=encryption_root, salt=random_salt, info="bee_connect.msg.key.v1")
3. ciphertext = XChaCha20-Poly1305(key=per_message_key, nonce=random_nonce, plaintext=body, aad=envelope_metadata)
```

AAD (Associated Authenticated Data) includes: `v`, `session_id`, `dir`, `seq`, `type`, `ts` — protects against metadata substitution.

### Per-Message DH Re-Key (Forward Secrecy)

Before encrypting, the sender performs a DH re-key:

```
new_dh = X25519::generate()
shared = X25519(new_dh.secret, peer_dh_public)
ikm = old_encryption_root || shared   (64 bytes)
new_encryption_root = HKDF-SHA256(ikm, salt=session_id, info="bee_connect.rekey.v1")
```

The `new_encryption_root` replaces `encryption_root` in the per-message encryption step above.
The `new_dh.public` is included in the envelope's `dh_public` field.

This ensures:
- **Forward secrecy**: compromising the current state reveals nothing about past messages
- **Post-compromise security**: each message uses fresh DH material

---

## Cryptographic Primitives

| Purpose | Primitive | Key Size |
|---------|-----------|----------|
| DH key exchange | X25519 | 32 bytes |
| Key derivation | HKDF-SHA256 | — |
| On-chain signing | Ed25519 (verify_strict) | 32 bytes |
| Message encryption | XChaCha20-Poly1305 | 32 bytes |
| Replay protection | seq = now_millis() | u64 |

---

## MITM Analysis

| Attack | Result |
|--------|--------|
| Passive URL intercept | Sees `client_dh_public` — useless without `client_dh_secret` |
| Substitute `client_dh_public` in URL | Client and Wallet derive different shared_secret → wallet_hello decryption fails → session not established (DoS, not silent MITM) |
| Intercept wallet_hello | `dh_public` is public, body is encrypted → useless |
| Message replay | Different `seq` (millisecond timestamp) → AAD mismatch → AEAD rejects |

---

## Security Considerations

### Session Timeout

The bee_connect protocol uses two distinct TTL values:

**Connect session TTL** (`DEFAULT_CONNECT_TTL_SECS = 300`, 5 minutes)
Controls how long the deeplink / QR code is valid for wallet scanning.
Set via `ttl_secs` in `create_shared_key_session`. Callers SHOULD keep
this short — it is only the window for the wallet to scan and respond,
not the lifetime of the established session.
Maximum recommended value: **86400 seconds (24 hours)**. Values above
this are accepted by the API but strongly discouraged.

**Active session TTL** (`DEFAULT_SESSION_TTL_SECS = 86400`, 24 hours)
The lifetime of an established `ConnectSessionState` after the DH
handshake completes. Both `rekey_outbound` and `rekey_inbound` reject
operations on expired states.

Every `ConnectSessionState` carries `created_at` and `expires_at` timestamps (UNIX epoch seconds).

- `rekey_outbound` and `rekey_inbound` check `expires_at` before performing any crypto — expired sessions are rejected with an error.
- Legacy states (deserialized from JSON without these fields) have `expires_at = 0`, which is treated as **non-expiring** for backward compatibility.
- Callers can set a custom `expires_at` on the state after `create_initial_state` if a shorter or longer TTL is needed.

**Wallet app requirements:**

- On session accept: persist `created_at` and `expires_at` from the returned state.
- Before any operation with session state: check `state.is_expired()`. If expired, show "Session expired" to user and destroy the profile.
- On app foreground: check all stored session states, destroy expired ones.
- Display remaining session time in UI so user knows when to reconnect.

### State Persistence

`ConnectSessionState` contains secret key material. Callers are responsible for:

- Storing the JSON-serialized state in a secure location (OS keychain, encrypted storage)
- Overwriting or deleting old state after every re-key operation
- Never logging the state in plaintext

### Forward Secrecy Guarantees

After a re-key, old `encryption_root` and `my_dh_secret` are discarded. Even if the current state is compromised, past messages cannot be decrypted because the old DH secrets needed to reverse the HKDF chain are gone.

Forward secrecy holds only if:
1. The caller actually discards old state (does not keep backups of previous `ConnectSessionState`)
2. The runtime zeroes memory on drop (`ConnectSessionState` secret fields use `Zeroizing<String>` which handles this)

### Limitations

- `ConnectSessionState` secret fields (`encryption_root`, `my_dh_secret`, `signing_secret`) are wrapped in `Zeroizing<String>` — their memory is zeroed on drop. The `zeroize` crate's `serde` feature provides transparent JSON serialization.
- The protocol does not authenticate the initial DH exchange beyond decryption success. An active MITM at session creation causes a DoS (decryption failure), not silent interception.
- **Signing keys are fixed for the session lifetime** (see [Signing Key Lifetime](#signing-key-lifetime) below).
- The protocol uses symmetric authentication (AEAD). Both sides share the same keys, so non-repudiation (proving which side sent a specific message) is not provided.
- **Wallet identity is not cryptographically pinned.** The `wallet_address` in `wallet_hello` is self-reported by the wallet and authenticated only by AEAD decryption success — see [Wallet Identity](#wallet-identity) below.

### Signing Key Lifetime

The Ed25519 signing keypair (`signing_public`, `signing_secret`) is derived once during the DH handshake (Phase 2/3) and remains constant for the entire session. Unlike `encryption_root` and `my_dh_secret`, which rotate on every message via the DH re-key mechanism, signing keys are **never rotated**.

**Why this matters:**

- If `signing_secret` is leaked (memory dump, insecure state persistence, etc.), an attacker can forge on-chain AuthProfile transactions (e.g. `set_mining_keys`, `client_disconnect`) for the remainder of the session.
- Forward secrecy does **not** cover signing keys — compromising the current `ConnectSessionState` reveals the signing key for all past and future on-chain signatures within that session.

**Why this is acceptable for the current design:**

1. **Narrow scope.** Signing keys are only used to authorize AuthProfile context additions on-chain. They do not protect message confidentiality (that is handled by the AEAD encryption layer with per-message re-keying).
2. **Session-scoped impact.** A compromised signing key cannot be used outside the session's AuthProfile contract. Destroying the profile (`destroy_connect_profile`) invalidates the key on-chain.
3. **Rotation cost.** Rotating signing keys would require an on-chain transaction to update the AuthProfile's public key, adding latency and gas cost to every message — disproportionate for the threat model.

**Mitigations for callers:**

- Keep sessions short-lived. Do not reuse a `ConnectSessionState` across app restarts if avoidable.
- Destroy the AuthProfile (`destroy_connect_profile`) as soon as the session is no longer needed, to invalidate the signing key on-chain.
- Store `ConnectSessionState` in OS keychain or encrypted storage, not in plaintext files.

### Wallet Identity

The `wallet_address` field in the `wallet_hello` message body is **self-reported** by the wallet. The protocol does not perform independent on-chain verification that the wallet actually controls this address.

**Why additional pinning is not needed:**

1. **DH authentication is sufficient.** An attacker who does not possess the `client_dh_secret` (never transmitted — kept by the dApp) cannot compute the shared secret, and therefore cannot produce a `wallet_hello` that the client can decrypt. A successful decryption proves the wallet participated in the same DH exchange.

2. **MITM requires URL interception AND replacement.** To impersonate a different wallet, an attacker would need to intercept the deeplink URL, replace `client_dh_public` with their own, and forward it to a target wallet. But then the real client holds `client_dh_secret` for the original keypair — the attacker's `wallet_hello` (encrypted with the attacker's shared secret) will fail decryption on the client. This is a **DoS** (session fails to establish), not a silent impersonation.

3. **No secret exfiltration path.** Even if an attacker deploys their own AuthProfile and writes a `wallet_hello` with a fake `wallet_address`, the client will reject it because the DH shared secrets won't match.

**Recommendation for wallet apps:**

- After `wait_wallet_hello` succeeds, display the received `wallet_name` and `wallet_address` to the user for visual confirmation.
- If the dApp expects a specific wallet, compare `wallet_address` from the decrypted `wallet_hello` against the expected value at the application layer.

---

## Diagram

```
Client                     links.gosh.sh              Wallet
  │                              │                       │
  │ generate X25519              │                       │
  │ (client_dh_pub, _sec)        │                       │
  │                              │                       │
  │── URL: payload + pub ──────>│────> deeplink ────────>│
  │   (NO SECRETS!)              │                       │
  │                              │                       │ generate X25519
  │                              │                       │ (wallet_dh_pub, _sec)
  │                              │                       │
  │                              │                       │ shared = DH(w_sec, c_pub)
  │                              │                       │ signing, encryption = HKDF(shared)
  │                              │                       │
  │                              │                       │ deploy AuthProfile(signing.pub)
  │                              │                       │ wallet_hello:
  │                              │                       │   dh_public: wallet_dh_pub
  │                              │                       │   body: encrypted(name, addr)
  │                              │                       │
  │<── poll AuthProfile ─────────────────────────────────│
  │                              │                       │
  │ extract wallet_dh_pub        │                       │
  │ shared = DH(c_sec, w_pub)    │                       │
  │ signing, encryption = HKDF   │                       │
  │ decrypt body ✓               │                       │
  │                              │                       │
  │                              │                       │
  │ rekey_outbound:              │                       │
  │   new DH, new root           │                       │
  │── set_mining_keys ──────────────────────────────────>│
  │   (encrypted with new_root,  │                       │ rekey_inbound:
  │    dh_public: new_pub)       │                       │   DH(my_sec, new_pub) → new root
  │                              │                       │
  │ rekey_outbound again         │                       │
  │── disconnect ───────────────────────────────────────>│
  │   (encrypted with newer_root,│                       │ rekey_inbound again
  │    dh_public: newer_pub)     │                       │
  │                              │                       │
```

---

## API Reference

### Client-side (bee_connect)

| Method | Input | Output |
|--------|-------|--------|
| `create_shared_key_session` | `app_id`, `ttl_secs` | `session_id`, `client_dh_public`, `client_dh_secret`, `deep_link` |
| `decode_connect_payload_b64url` | `payload_b64url` | `ConnectPayload` |
| `get_profile_address` | `endpoints`, `description` | `profile_address` |
| `is_session_profile_deployed` | `endpoints`, `description` | `bool` |
| `wait_wallet_hello` | `session_id`, `description`, `client_dh_secret` | `wallet_name`, `wallet_address`, `session_state` |
| `request_set_mining_keys` | `session_state`, `app_id`, `owner_public` | `message_id`, `updated_session_state` |
| `wait_set_mining_keys_request` | `session_state` | `app_id`, `owner_public`, `updated_session_state` |
| `request_sign_challenge` | `session_state`, `nonce` | `message_id`, `updated_session_state` |
| `wait_challenge_response` | `session_state` | `nonce`, `signature`, `wallet_address`, `updated_session_state` |
| `disconnect_session` | `session_state`, `reason` | `message_id`, `updated_session_state` |
| `query_active_sessions_by_multifactor` | `multifactor_address`, `app_id?`, `before?` | `sessions[]`, `next_before` |

### Wallet-side (bee_wallet)

| Method | Input | Output |
|--------|-------|--------|
| `decode_connect_payload_b64url` | `payload_b64url` | `ConnectPayload` |
| `accept_shared_key_connect` | `payload`, `client_dh_public`, `wallet_name`, `wallet_address` | `profile_address`, `session_state` |
| `query_session_messages` | `session_id`, `description`, `session_state` | `messages[]`, `updated_session_state` |
| `destroy_connect_profile` | `profile_address`, `multifactor_address`, `signer_keys` | — |
