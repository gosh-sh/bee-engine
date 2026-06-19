//! Ephemeral X25519 Diffie-Hellman key exchange, session key derivation,
//! and per-message re-keying for bee_connect protocol.
//!
//! ## Handshake
//! 1. Client calls `generate_dh_keypair()` → puts `dh_public` (hex) in URL
//! 2. Wallet calls `generate_dh_keypair()` → computes shared secret with
//!    client's public
//! 3. Both sides call `derive_session_keys(shared_secret, session_id)` →
//!    identical signing + encryption keys
//! 4. Both sides call `create_initial_state(session_keys, my_dh_secret,
//!    peer_dh_public)` → `ConnectSessionState`
//!
//! ## Per-message re-keying (forward secrecy)
//! - Sender: `rekey_outbound(state, session_id)` → new DH, new root, updated
//!   state
//! - Receiver: `rekey_inbound(state, peer_new_dh_public, session_id)` → new
//!   root, updated state
//! - Each message rotates the encryption root. Old roots are discarded (forward
//!   secrecy).

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;
use zeroize::Zeroizing;

const SIGNING_KEY_INFO: &[u8] = b"bee_connect.signing.v1";
const ENCRYPTION_KEY_INFO: &[u8] = b"bee_connect.encryption.v1";
const REKEY_INFO: &[u8] = b"bee_connect.rekey.v1";

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
fn now_secs() -> u64 {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms < 0.0 {
        return 0;
    }
    (ms / 1000.0).floor() as u64
}

#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
fn now_millis() -> Result<u64, String> {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms < 0.0 {
        return Err("js_sys::Date::now() returned invalid value".to_string());
    }
    Ok(ms.floor() as u64)
}

#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
fn now_millis() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|e| format!("SystemTime error: {e}"))
}

/// X25519 ephemeral keypair for DH exchange.
pub struct DhKeyPair {
    /// Hex-encoded X25519 public key (32 bytes = 64 hex chars).
    /// Safe to transmit in URLs and on-chain.
    pub public_hex: String,
    /// Hex-encoded X25519 secret key (32 bytes = 64 hex chars).
    /// MUST be kept private. Caller stores this for phase 2 (shared secret
    /// computation).
    pub secret_hex: Zeroizing<String>,
}

/// Session keys derived from DH shared secret.
/// Both sides derive identical keys from the same shared secret + session_id.
pub struct DhSessionKeys {
    /// Ed25519 signing keypair derived from shared secret.
    /// Used for signing on-chain AuthProfile transactions.
    pub signing_public_hex: String,
    pub signing_secret_hex: Zeroizing<String>,
    /// Hex-encoded 32-byte encryption root.
    /// Used as `encryption_secret` in `derive_connect_message_key` for
    /// per-message HKDF.
    pub encryption_root_hex: Zeroizing<String>,
}

/// Generates a random X25519 ephemeral keypair.
pub fn generate_dh_keypair() -> Result<DhKeyPair, String> {
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes)
        .map_err(|e| format!("Failed to generate random bytes: {e}"))?;
    let secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let public = PublicKey::from(&secret);

    Ok(DhKeyPair {
        public_hex: hex::encode(public.as_bytes()),
        secret_hex: Zeroizing::new(hex::encode(secret.to_bytes())),
    })
}

/// Computes X25519 shared secret from own secret key and peer's public key.
/// Returns 32-byte shared secret as hex string (zeroized on drop).
pub fn compute_shared_secret(
    my_secret_hex: &str,
    their_public_hex: &str,
) -> Result<Zeroizing<String>, String> {
    let my_secret_bytes: [u8; 32] = hex::decode(my_secret_hex)
        .map_err(|e| format!("Decode DH secret hex ({e})"))?
        .try_into()
        .map_err(|_| "DH secret must be 32 bytes".to_string())?;

    let their_public_bytes: [u8; 32] = hex::decode(their_public_hex)
        .map_err(|e| format!("Decode DH public hex ({e})"))?
        .try_into()
        .map_err(|_| "DH public key must be 32 bytes".to_string())?;

    let my_secret = StaticSecret::from(my_secret_bytes);
    let their_public = PublicKey::from(their_public_bytes);

    let shared = my_secret.diffie_hellman(&their_public);
    let shared_bytes = shared.as_bytes();

    // Reject all-zero shared secret (low-order point attack)
    if shared_bytes.iter().all(|&b| b == 0) {
        return Err("DH shared secret is zero (invalid peer public key)".to_string());
    }

    Ok(Zeroizing::new(hex::encode(shared_bytes)))
}

/// Derives session signing keys and encryption root from shared secret.
///
/// `shared_secret_hex` — 32-byte shared secret from `compute_shared_secret`.
/// `session_id` — unique session identifier, used as HKDF salt for domain
/// separation.
///
/// Both sides call this with the same inputs and get identical output.
pub fn derive_session_keys(
    shared_secret_hex: &str,
    session_id: &str,
) -> Result<DhSessionKeys, String> {
    let shared_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Decode shared secret hex ({e})"))?;
    if shared_bytes.len() != 32 {
        return Err(format!("Shared secret must be 32 bytes, got {}", shared_bytes.len()));
    }

    let salt = session_id.as_bytes();

    // Single extraction — one PRK, two independent expand calls
    let hk = Hkdf::<Sha256>::new(Some(salt), &shared_bytes);

    // 1. Signing seed → Ed25519 keypair
    let mut signing_seed = Zeroizing::new([0u8; 32]);
    hk.expand(SIGNING_KEY_INFO, &mut *signing_seed)
        .map_err(|e| format!("HKDF expand signing key ({e})"))?;

    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = signing_key.verifying_key();

    // 2. Encryption root
    let mut encryption_root = Zeroizing::new([0u8; 32]);
    hk.expand(ENCRYPTION_KEY_INFO, &mut *encryption_root)
        .map_err(|e| format!("HKDF expand encryption root ({e})"))?;

    Ok(DhSessionKeys {
        signing_public_hex: hex::encode(verifying_key.to_bytes()),
        signing_secret_hex: Zeroizing::new(hex::encode(signing_key.to_bytes())),
        encryption_root_hex: Zeroizing::new(hex::encode(*encryption_root)),
    })
}

/// Complete session state for the bee_connect DH protocol.
///
/// Both client and wallet maintain one instance. Every send/receive operation
/// takes the current state, performs a DH re-key, and returns the updated
/// state. The caller MUST persist the updated state and discard the old one.
///
/// Signing keys are fixed for the session lifetime (tied to the on-chain
/// AuthProfile). Encryption root and DH keys rotate on every message
/// to provide forward secrecy.
///
/// Default session TTL: 24 hours in seconds.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

/// # Security note
///
/// Secret fields (`encryption_root`, `my_dh_secret`, `signing_secret`) are
/// wrapped in `Zeroizing<String>` — their memory is zeroed on drop.
/// Callers SHOULD drop the old state promptly after re-key.
/// The `Debug` impl redacts all secret fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConnectSessionState {
    /// Current encryption root key (hex, 32 bytes).
    /// Rotated on every sent or received message.
    pub encryption_root: Zeroizing<String>,
    /// My current X25519 secret key (hex, 32 bytes).
    /// Rotated on every outbound message.
    pub my_dh_secret: Zeroizing<String>,
    /// Peer's last known X25519 public key (hex, 32 bytes).
    /// Updated on every inbound message.
    pub peer_dh_public: String,
    /// Ed25519 signing public key (hex, 32 bytes). Fixed for session lifetime.
    pub signing_public: String,
    /// Ed25519 signing secret key (hex, 32 bytes). Fixed for session lifetime.
    pub signing_secret: Zeroizing<String>,
    /// Session creation timestamp (seconds since UNIX epoch).
    /// Set once during handshake, carried through all re-keys.
    #[serde(default)]
    pub created_at: u64,
    /// Session expiration timestamp (seconds since UNIX epoch).
    /// Operations MUST reject expired sessions.
    /// Default: `created_at + DEFAULT_SESSION_TTL_SECS` (24h).
    #[serde(default)]
    pub expires_at: u64,
    /// Highest `seq` successfully decrypted from an inbound message.
    /// Zero means no inbound message has been processed yet.
    /// `rekey_inbound` rejects any envelope with seq <= this value.
    #[serde(default)]
    pub last_seen_seq: u64,
    /// Highest `seq` used in an outbound message.
    /// Zero means no outbound message has been sent yet.
    /// `rekey_outbound` ensures the next seq is strictly greater than this.
    #[serde(default)]
    pub last_sent_seq: u64,
}

impl ConnectSessionState {
    /// Returns `true` if the session has expired.
    /// A session with `expires_at == 0` (legacy/unset) is considered
    /// non-expiring.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        now_secs() >= self.expires_at
    }

    /// Checks that the session is still valid. Returns `Err` if expired.
    pub fn ensure_not_expired(&self) -> Result<(), String> {
        if self.is_expired() {
            Err(format!(
                "Connect session expired at {} (created_at={})",
                self.expires_at, self.created_at
            ))
        } else {
            Ok(())
        }
    }

    /// Returns the next seq value for an outbound message.
    /// Guarantees strict monotonicity: result > last_sent_seq.
    pub fn next_outbound_seq(&self) -> Result<u64, String> {
        let now = now_millis()?;
        Ok(now.max(self.last_sent_seq + 1))
    }
}

impl std::fmt::Debug for ConnectSessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectSessionState")
            .field("encryption_root", &"[REDACTED]")
            .field("my_dh_secret", &"[REDACTED]")
            .field("peer_dh_public", &self.peer_dh_public)
            .field("signing_public", &self.signing_public)
            .field("signing_secret", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_seen_seq", &self.last_seen_seq)
            .field("last_sent_seq", &self.last_sent_seq)
            .finish()
    }
}

/// Result of a re-key operation.
pub struct RekeyResult {
    /// Encryption root to use for this specific message (hex).
    /// This is the new root AFTER re-keying — use it for encrypt/decrypt.
    pub message_encryption_root: Zeroizing<String>,
    /// New ephemeral DH public key (hex). Include in the message envelope.
    /// `None` for inbound re-key (receiver does not generate new DH).
    pub new_dh_public: Option<String>,
    /// Updated session state. Caller MUST persist this and discard the old
    /// state.
    pub updated_state: ConnectSessionState,
    /// The seq value to use in the outbound message envelope.
    /// Only set for outbound re-key; `0` for inbound.
    pub outbound_seq: u64,
}

impl std::fmt::Debug for RekeyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekeyResult")
            .field("message_encryption_root", &"[REDACTED]")
            .field("new_dh_public", &self.new_dh_public)
            .field("updated_state", &self.updated_state)
            .finish()
    }
}

/// Creates the initial session state from handshake results.
///
/// Called once after the DH handshake completes (after `derive_session_keys`).
/// - `session_keys` — derived signing + encryption keys
/// - `my_dh_secret_hex` — my X25519 secret used in the handshake
/// - `peer_dh_public_hex` — peer's X25519 public from the handshake
///
/// Sets `created_at` to now and `expires_at` to now +
/// `DEFAULT_SESSION_TTL_SECS` (24h).
pub fn create_initial_state(
    session_keys: &DhSessionKeys,
    my_dh_secret_hex: &str,
    peer_dh_public_hex: &str,
) -> ConnectSessionState {
    let now = now_secs();
    ConnectSessionState {
        encryption_root: Zeroizing::new(session_keys.encryption_root_hex.to_string()),
        my_dh_secret: Zeroizing::new(my_dh_secret_hex.to_string()),
        peer_dh_public: peer_dh_public_hex.to_string(),
        signing_public: session_keys.signing_public_hex.clone(),
        signing_secret: Zeroizing::new(session_keys.signing_secret_hex.to_string()),
        created_at: now,
        expires_at: now + DEFAULT_SESSION_TTL_SECS,
        last_seen_seq: 0,
        last_sent_seq: 0,
    }
}

/// Performs DH re-key for an outbound (sending) message.
///
/// 1. Generates a new ephemeral X25519 keypair
/// 2. Computes DH shared secret with peer's current public key
/// 3. Derives new encryption root from `old_root || shared_secret`
/// 4. Returns the new root (for encrypting this message), new DH public (for
///    the envelope), and the updated state
///
/// The caller MUST:
/// - Use `message_encryption_root` to encrypt the message body
/// - Include `new_dh_public` in the message envelope
/// - Persist `updated_state` and discard the old state
pub fn rekey_outbound(
    state: &ConnectSessionState,
    session_id: &str,
    outbound_seq: u64,
) -> Result<RekeyResult, String> {
    state.ensure_not_expired()?;

    if outbound_seq == 0 {
        return Err("rekey_outbound: outbound_seq must be > 0".to_string());
    }
    if outbound_seq <= state.last_sent_seq {
        return Err(format!(
            "rekey_outbound: seq {} is not monotonically increasing (last_sent={})",
            outbound_seq, state.last_sent_seq
        ));
    }

    // 1. Generate new ephemeral DH keypair
    let new_dh = generate_dh_keypair()?;

    // 2. Compute shared secret: DH(new_secret, peer_public)
    let shared = compute_shared_secret(&new_dh.secret_hex, &state.peer_dh_public)?;

    // 3. Derive new root from old_root || shared
    let new_root = derive_rekey_root(&state.encryption_root, &shared, session_id)?;

    // 4. Build updated state
    let updated_state = ConnectSessionState {
        encryption_root: Zeroizing::new(new_root.to_string()),
        my_dh_secret: Zeroizing::new(new_dh.secret_hex.to_string()),
        peer_dh_public: state.peer_dh_public.clone(),
        signing_public: state.signing_public.clone(),
        signing_secret: state.signing_secret.clone(),
        created_at: state.created_at,
        expires_at: state.expires_at,
        last_seen_seq: state.last_seen_seq,
        last_sent_seq: outbound_seq,
    };

    Ok(RekeyResult {
        message_encryption_root: new_root,
        new_dh_public: Some(new_dh.public_hex),
        updated_state,
        outbound_seq,
    })
}

/// Performs DH re-key for an inbound (receiving) message.
///
/// 1. Computes DH shared secret with peer's new public key from the envelope
/// 2. Derives new encryption root from `old_root || shared_secret`
/// 3. Returns the new root (for decrypting this message) and updated state
///
/// The caller MUST:
/// - Use `message_encryption_root` to decrypt the message body
/// - Persist `updated_state` and discard the old state
pub fn rekey_inbound(
    state: &ConnectSessionState,
    peer_new_dh_public: &str,
    session_id: &str,
    incoming_seq: u64,
) -> Result<RekeyResult, String> {
    state.ensure_not_expired()?;

    if incoming_seq == 0 {
        return Err("rekey_inbound: incoming seq must be > 0".to_string());
    }
    if incoming_seq <= state.last_seen_seq {
        return Err(format!(
            "rekey_inbound: replay detected — incoming seq {} <= last_seen_seq {}",
            incoming_seq, state.last_seen_seq
        ));
    }

    // 1. Compute shared secret: DH(my_secret, peer_new_public)
    let shared = compute_shared_secret(&state.my_dh_secret, peer_new_dh_public)?;

    // 2. Derive new root from old_root || shared
    let new_root = derive_rekey_root(&state.encryption_root, &shared, session_id)?;

    // 3. Build updated state
    let updated_state = ConnectSessionState {
        encryption_root: Zeroizing::new(new_root.to_string()),
        my_dh_secret: state.my_dh_secret.clone(),
        peer_dh_public: peer_new_dh_public.to_string(),
        signing_public: state.signing_public.clone(),
        signing_secret: state.signing_secret.clone(),
        created_at: state.created_at,
        expires_at: state.expires_at,
        last_seen_seq: incoming_seq,
        last_sent_seq: state.last_sent_seq,
    };

    Ok(RekeyResult {
        message_encryption_root: new_root,
        new_dh_public: None,
        updated_state,
        outbound_seq: 0,
    })
}

/// Derives a new encryption root by mixing the current root with a fresh DH
/// shared secret.
///
/// `ikm = old_root_bytes || shared_secret_bytes` ensures both must be known
/// to derive the new root (defense in depth).
fn derive_rekey_root(
    current_root_hex: &str,
    shared_secret_hex: &str,
    session_id: &str,
) -> Result<Zeroizing<String>, String> {
    let root_bytes =
        hex::decode(current_root_hex).map_err(|e| format!("Decode current root hex ({e})"))?;
    if root_bytes.len() != 32 {
        return Err(format!("Encryption root must be 32 bytes, got {}", root_bytes.len()));
    }

    let shared_bytes =
        hex::decode(shared_secret_hex).map_err(|e| format!("Decode shared secret hex ({e})"))?;
    if shared_bytes.len() != 32 {
        return Err(format!("Shared secret must be 32 bytes, got {}", shared_bytes.len()));
    }

    // Concatenate: old_root || shared_secret (64 bytes total)
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&root_bytes);
    ikm.extend_from_slice(&shared_bytes);

    let salt = session_id.as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut new_root = Zeroizing::new([0u8; 32]);
    hk.expand(REKEY_INFO, &mut *new_root).map_err(|e| format!("HKDF expand rekey root ({e})"))?;

    // Zeroize intermediate material
    ikm.zeroize();

    Ok(Zeroizing::new(hex::encode(*new_root)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dh_keypair_produces_valid_keys() {
        let kp = generate_dh_keypair().unwrap();
        assert_eq!(hex::decode(&kp.public_hex).unwrap().len(), 32);
        assert_eq!(hex::decode(&*kp.secret_hex).unwrap().len(), 32);
        // Public and secret must differ
        assert_ne!(kp.public_hex, *kp.secret_hex);
    }

    #[test]
    fn dh_shared_secret_symmetric() {
        // Both sides compute the same shared secret
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();

        let secret_a = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();
        let secret_b = compute_shared_secret(&wallet.secret_hex, &client.public_hex).unwrap();

        assert_eq!(*secret_a, *secret_b, "DH must be symmetric");
    }

    #[test]
    fn derive_session_keys_deterministic() {
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();

        let shared = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();

        let keys_1 = derive_session_keys(&shared, "test_session_1").unwrap();
        let keys_2 = derive_session_keys(&shared, "test_session_1").unwrap();

        assert_eq!(keys_1.signing_public_hex, keys_2.signing_public_hex);
        assert_eq!(*keys_1.signing_secret_hex, *keys_2.signing_secret_hex);
        assert_eq!(*keys_1.encryption_root_hex, *keys_2.encryption_root_hex);
    }

    #[test]
    fn derive_session_keys_different_sessions_differ() {
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();

        let shared = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();

        let keys_1 = derive_session_keys(&shared, "session_A").unwrap();
        let keys_2 = derive_session_keys(&shared, "session_B").unwrap();

        assert_ne!(keys_1.signing_public_hex, keys_2.signing_public_hex);
        assert_ne!(*keys_1.encryption_root_hex, *keys_2.encryption_root_hex);
    }

    #[test]
    fn both_sides_derive_identical_session_keys() {
        // Full flow: client and wallet independently derive the same keys
        let client_dh = generate_dh_keypair().unwrap();
        let wallet_dh = generate_dh_keypair().unwrap();
        let session_id = "test_session_123";

        // Client side
        let client_shared =
            compute_shared_secret(&client_dh.secret_hex, &wallet_dh.public_hex).unwrap();
        let client_keys = derive_session_keys(&client_shared, session_id).unwrap();

        // Wallet side
        let wallet_shared =
            compute_shared_secret(&wallet_dh.secret_hex, &client_dh.public_hex).unwrap();
        let wallet_keys = derive_session_keys(&wallet_shared, session_id).unwrap();

        assert_eq!(client_keys.signing_public_hex, wallet_keys.signing_public_hex);
        assert_eq!(*client_keys.signing_secret_hex, *wallet_keys.signing_secret_hex);
        assert_eq!(*client_keys.encryption_root_hex, *wallet_keys.encryption_root_hex);
    }

    #[test]
    fn different_keypairs_different_shared_secrets() {
        let client = generate_dh_keypair().unwrap();
        let wallet_1 = generate_dh_keypair().unwrap();
        let wallet_2 = generate_dh_keypair().unwrap();

        let shared_1 = compute_shared_secret(&client.secret_hex, &wallet_1.public_hex).unwrap();
        let shared_2 = compute_shared_secret(&client.secret_hex, &wallet_2.public_hex).unwrap();

        assert_ne!(*shared_1, *shared_2);
    }

    #[test]
    fn derived_signing_key_is_valid_ed25519() {
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();

        let shared = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();

        // Verify signing key produces valid signatures
        use ed25519_dalek::Signer;
        let secret_bytes: [u8; 32] =
            hex::decode(&*keys.signing_secret_hex).unwrap().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let signature = signing_key.sign(b"test message");

        use ed25519_dalek::Verifier;
        let pub_bytes: [u8; 32] =
            hex::decode(&keys.signing_public_hex).unwrap().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).unwrap();
        verifying_key.verify(b"test message", &signature).unwrap();
    }

    #[test]
    fn reject_zero_shared_secret() {
        // All-zero public key leads to all-zero shared secret (low-order point)
        let kp = generate_dh_keypair().unwrap();
        let zero_pub = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = compute_shared_secret(&kp.secret_hex, zero_pub);
        assert!(result.is_err(), "Zero shared secret must be rejected");
    }

    #[test]
    fn invalid_hex_rejected() {
        assert!(compute_shared_secret(
            "not_hex",
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        .is_err());
        assert!(compute_shared_secret(
            "aa",
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        .is_err());
    }

    #[test]
    fn create_initial_state_preserves_keys() {
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();

        let state = create_initial_state(&keys, &client.secret_hex, &wallet.public_hex);

        assert_eq!(*state.encryption_root, *keys.encryption_root_hex);
        assert_eq!(state.signing_public, keys.signing_public_hex);
        assert_eq!(*state.signing_secret, *keys.signing_secret_hex);
        assert_eq!(*state.my_dh_secret, *client.secret_hex);
        assert_eq!(state.peer_dh_public, wallet.public_hex);
    }

    #[test]
    fn rekey_outbound_rotates_root_and_dh() {
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &client.secret_hex, &wallet.public_hex);

        let result = rekey_outbound(&state, "session", 1000).unwrap();

        // Root rotated
        assert_ne!(result.updated_state.encryption_root, state.encryption_root);
        // DH secret rotated
        assert_ne!(result.updated_state.my_dh_secret, state.my_dh_secret);
        // Peer public unchanged
        assert_eq!(result.updated_state.peer_dh_public, state.peer_dh_public);
        // Signing keys unchanged
        assert_eq!(result.updated_state.signing_public, state.signing_public);
        assert_eq!(result.updated_state.signing_secret, state.signing_secret);
        // New DH public returned for envelope
        assert!(result.new_dh_public.is_some());
        let new_pub = result.new_dh_public.unwrap();
        assert_eq!(hex::decode(&new_pub).unwrap().len(), 32);
        // message_encryption_root == updated root
        assert_eq!(*result.message_encryption_root, *result.updated_state.encryption_root);
    }

    #[test]
    fn rekey_inbound_rotates_root_and_peer_public() {
        let client = generate_dh_keypair().unwrap();
        let wallet = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&client.secret_hex, &wallet.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &client.secret_hex, &wallet.public_hex);

        // Simulate peer sending with new DH
        let peer_new = generate_dh_keypair().unwrap();
        let result = rekey_inbound(&state, &peer_new.public_hex, "session", 1000).unwrap();

        // Root rotated
        assert_ne!(result.updated_state.encryption_root, state.encryption_root);
        // My DH secret unchanged
        assert_eq!(result.updated_state.my_dh_secret, state.my_dh_secret);
        // Peer public updated
        assert_eq!(result.updated_state.peer_dh_public, peer_new.public_hex);
        // No new DH public (inbound)
        assert!(result.new_dh_public.is_none());
    }

    #[test]
    fn rekey_symmetric_outbound_inbound() {
        // Full flow: Alice sends to Bob, both derive same root
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();

        let alice_state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);
        let bob_state = create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);

        // Alice sends message (rekey outbound)
        let alice_result = rekey_outbound(&alice_state, "session", 1000).unwrap();
        let alice_new_pub = alice_result.new_dh_public.as_ref().unwrap();

        // Bob receives message (rekey inbound with Alice's new DH public)
        let bob_result = rekey_inbound(&bob_state, alice_new_pub, "session", 1000).unwrap();

        // Both derive the same message encryption root
        assert_eq!(
            *alice_result.message_encryption_root, *bob_result.message_encryption_root,
            "Sender and receiver must derive the same encryption root"
        );

        // Both have the same updated encryption root in state
        assert_eq!(
            alice_result.updated_state.encryption_root,
            bob_result.updated_state.encryption_root,
        );
    }

    #[test]
    fn rekey_chain_forward_secrecy() {
        // After multiple re-keys, old roots cannot be derived from current state
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();

        let mut alice_state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);
        let mut bob_state = create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);

        let mut roots = vec![alice_state.encryption_root.clone()];
        let mut seq: u64 = 1000;

        // Simulate 5 message exchanges
        for _ in 0..5 {
            // Alice → Bob
            seq += 1;
            let a_result = rekey_outbound(&alice_state, "session", seq).unwrap();
            let a_pub = a_result.new_dh_public.clone().unwrap();
            alice_state = a_result.updated_state;

            let b_result = rekey_inbound(&bob_state, &a_pub, "session", seq).unwrap();
            bob_state = b_result.updated_state;

            roots.push(alice_state.encryption_root.clone());

            // Bob → Alice
            seq += 1;
            let b_result = rekey_outbound(&bob_state, "session", seq).unwrap();
            let b_pub = b_result.new_dh_public.clone().unwrap();
            bob_state = b_result.updated_state;

            let a_result = rekey_inbound(&alice_state, &b_pub, "session", seq).unwrap();
            alice_state = a_result.updated_state;

            roots.push(alice_state.encryption_root.clone());
        }

        // All roots must be unique
        let unique: std::collections::HashSet<&String> = roots.iter().map(|r| &**r).collect();
        assert_eq!(unique.len(), roots.len(), "Every re-key must produce a unique root");

        // Final states must match
        assert_eq!(alice_state.encryption_root, bob_state.encryption_root);
    }

    #[test]
    fn rekey_different_sessions_different_roots() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session_A").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        let result_a = rekey_outbound(&state, "session_A", 1000).unwrap();

        // Same state but different session_id
        let keys_b = derive_session_keys(&shared, "session_B").unwrap();
        let state_b = create_initial_state(&keys_b, &alice.secret_hex, &bob.public_hex);
        let result_b = rekey_outbound(&state_b, "session_B", 1000).unwrap();

        assert_ne!(*result_a.message_encryption_root, *result_b.message_encryption_root,);
    }

    #[test]
    fn connect_session_state_serializable() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        let json = serde_json::to_string(&state).expect("serialize");
        let restored: ConnectSessionState = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(state.encryption_root, restored.encryption_root);
        assert_eq!(state.my_dh_secret, restored.my_dh_secret);
        assert_eq!(state.peer_dh_public, restored.peer_dh_public);
        assert_eq!(state.signing_public, restored.signing_public);
        assert_eq!(state.signing_secret, restored.signing_secret);
    }

    #[test]
    fn rekey_inbound_rejects_replay() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        let peer_new = generate_dh_keypair().unwrap();
        let result = rekey_inbound(&state, &peer_new.public_hex, "session", 1000).unwrap();
        let advanced = result.updated_state;
        assert_eq!(advanced.last_seen_seq, 1000);

        // Same seq → replay
        let peer2 = generate_dh_keypair().unwrap();
        let err = rekey_inbound(&advanced, &peer2.public_hex, "session", 1000).unwrap_err();
        assert!(err.contains("replay"), "expected replay error, got: {err}");

        // Lower seq → replay
        let err = rekey_inbound(&advanced, &peer2.public_hex, "session", 999).unwrap_err();
        assert!(err.contains("replay"), "expected replay error, got: {err}");

        // Higher seq → ok
        assert!(rekey_inbound(&advanced, &peer2.public_hex, "session", 1001).is_ok());
    }

    #[test]
    fn rekey_inbound_rejects_seq_zero() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        let peer = generate_dh_keypair().unwrap();
        let err = rekey_inbound(&state, &peer.public_hex, "session", 0).unwrap_err();
        assert!(err.contains("must be > 0"), "expected seq>0 error, got: {err}");
    }

    #[test]
    fn last_seen_seq_carried_through_outbound_rekey() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        // Simulate inbound at seq=5000
        let peer = generate_dh_keypair().unwrap();
        let inbound = rekey_inbound(&state, &peer.public_hex, "session", 5000).unwrap();
        assert_eq!(inbound.updated_state.last_seen_seq, 5000);

        // Outbound must preserve last_seen_seq
        let outbound = rekey_outbound(&inbound.updated_state, "session", 6000).unwrap();
        assert_eq!(outbound.updated_state.last_seen_seq, 5000);
    }

    #[test]
    fn last_seen_seq_zero_in_legacy_deserialized_state() {
        // JSON without last_seen_seq → deserializes to 0
        let json = r#"{
            "encryption_root": "aa",
            "my_dh_secret": "bb",
            "peer_dh_public": "cc",
            "signing_public": "dd",
            "signing_secret": "ee",
            "created_at": 1000,
            "expires_at": 2000
        }"#;
        let state: ConnectSessionState = serde_json::from_str(json).unwrap();
        assert_eq!(state.last_seen_seq, 0);
        assert_eq!(state.last_sent_seq, 0);
    }

    #[test]
    fn rekey_outbound_rejects_non_monotonic_seq() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        let result = rekey_outbound(&state, "session", 1000).unwrap();
        let advanced = result.updated_state;
        assert_eq!(advanced.last_sent_seq, 1000);

        // Same seq → error
        let err = rekey_outbound(&advanced, "session", 1000).unwrap_err();
        assert!(err.contains("not monotonically"), "expected monotonic error, got: {err}");

        // Lower seq → error
        let err = rekey_outbound(&advanced, "session", 999).unwrap_err();
        assert!(err.contains("not monotonically"), "expected monotonic error, got: {err}");

        // Higher seq → ok
        assert!(rekey_outbound(&advanced, "session", 1001).is_ok());
    }

    #[test]
    fn rekey_outbound_rejects_seq_zero() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        let err = rekey_outbound(&state, "session", 0).unwrap_err();
        assert!(err.contains("must be > 0"), "expected seq>0 error, got: {err}");
    }

    #[test]
    fn last_sent_seq_carried_through_inbound_rekey() {
        let alice = generate_dh_keypair().unwrap();
        let bob = generate_dh_keypair().unwrap();
        let shared = compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = derive_session_keys(&shared, "session").unwrap();
        let state = create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);

        // Outbound at seq=3000
        let outbound = rekey_outbound(&state, "session", 3000).unwrap();
        assert_eq!(outbound.updated_state.last_sent_seq, 3000);

        // Inbound must preserve last_sent_seq
        let peer = generate_dh_keypair().unwrap();
        let inbound =
            rekey_inbound(&outbound.updated_state, &peer.public_hex, "session", 4000).unwrap();
        assert_eq!(inbound.updated_state.last_sent_seq, 3000);
    }
}
