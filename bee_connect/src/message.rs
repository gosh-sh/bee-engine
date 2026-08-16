//! Shared connect protocol message utilities.
//!
//! These functions are used by both `bee_connect` (client-side) and
//! `bee_wallet` (wallet-side) for message encryption, decryption, AAD
//! construction, and input normalization. Having a single implementation
//! prevents divergence.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use hkdf::Hkdf;
use sha2::Sha256;

// --- Protocol constants ---

pub const CONNECT_DEEPLINK_VERSION: &str = "bee_connect.dl/1";
/// Same session, same `description`, same rendezvous — without the `session_id` and `app_id`
/// copies that `dl/1` sends beside a description that already holds both.
///
/// The link is shown as a QR code on any desktop client, because the wallet is a phone
/// application, so its length decides the symbol version and whether the code fits a window.
/// Dropping the two copies takes a 672-character link to 449 and the symbol from version 18 to
/// version 15.
pub const CONNECT_DEEPLINK_VERSION_COMPACT: &str = "bee_connect.dl/2";
pub const CONNECT_MESSAGE_VERSION: &str = "bee_connect.msg/1";
pub const CONNECT_MESSAGE_TYPE_WALLET_HELLO: &str = "wallet_hello";
pub const CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT: &str = "client_disconnect";
pub const CONNECT_MESSAGE_TYPE_SET_MINING_KEYS: &str = "set_mining_keys";
pub const CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE: &str = "sign_challenge";
pub const CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE: &str = "challenge_response";

// DEX operations over bee_connect (dex_connect_protocol v1)
pub const CONNECT_MESSAGE_TYPE_DEX_DEPLOY_PMP_REQUEST: &str = "dex_deploy_pmp_request";
pub const CONNECT_MESSAGE_TYPE_DEX_DEPLOY_PMP_RESPONSE: &str = "dex_deploy_pmp_response";
pub const CONNECT_MESSAGE_TYPE_DEX_SET_STAKE_REQUEST: &str = "dex_set_stake_request";
pub const CONNECT_MESSAGE_TYPE_DEX_SET_STAKE_RESPONSE: &str = "dex_set_stake_response";
pub const CONNECT_MESSAGE_TYPE_DEX_CLAIM_REQUEST: &str = "dex_claim_request";
pub const CONNECT_MESSAGE_TYPE_DEX_CLAIM_RESPONSE: &str = "dex_claim_response";
pub const CONNECT_MESSAGE_TYPE_DEX_CANCEL_STAKE_REQUEST: &str = "dex_cancel_stake_request";
pub const CONNECT_MESSAGE_TYPE_DEX_CANCEL_STAKE_RESPONSE: &str = "dex_cancel_stake_response";
pub const CONNECT_MESSAGE_TYPE_DEX_REQUEST_RECEIVED: &str = "dex_request_received";

pub const CONNECT_MESSAGE_ENC_NONE: &str = "none";
pub const CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256: &str = "xchacha20poly1305-hkdf-sha256";
pub const CONNECT_MESSAGE_KEY_INFO: &[u8] = b"bee_connect.msg.key.v1";

// --- Encrypted body ---

/// Result of encrypting a connect message body.
#[derive(Debug, Clone)]
pub struct EncryptedConnectBody {
    pub ciphertext_b64url: String,
    pub nonce_b64url: String,
    pub salt_b64url: String,
}

/// Encrypts a JSON body with XChaCha20-Poly1305 using a per-message key derived
/// from `encryption_secret` via HKDF.
pub fn encrypt_connect_body(
    body: &serde_json::Value,
    encryption_secret: &str,
    aad: &[u8],
) -> Result<EncryptedConnectBody, String> {
    let plaintext = serde_json::to_vec(body)
        .map_err(|e| format!("Serialize connect body for encryption ({e})"))?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| format!("Generate connect nonce ({e})"))?;
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| format!("Generate connect salt ({e})"))?;
    let key = derive_connect_message_key(encryption_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad })
        .map_err(|e| format!("Encrypt connect body ({e})"))?;

    Ok(EncryptedConnectBody {
        ciphertext_b64url: URL_SAFE_NO_PAD.encode(ciphertext),
        nonce_b64url: URL_SAFE_NO_PAD.encode(nonce),
        salt_b64url: URL_SAFE_NO_PAD.encode(salt),
    })
}

/// Decrypts a connect message body from base64url-encoded components.
pub fn decrypt_connect_body(
    ciphertext_b64url: &str,
    nonce_b64url: &str,
    salt_b64url: &str,
    encryption_secret: &str,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext_b64url)
        .map_err(|e| format!("Decode encrypted connect ciphertext ({e})"))?;
    let nonce = URL_SAFE_NO_PAD
        .decode(nonce_b64url)
        .map_err(|e| format!("Decode encrypted connect nonce ({e})"))?;
    if nonce.len() != 24 {
        return Err(format!("Invalid encrypted connect nonce length: {}", nonce.len()));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(salt_b64url)
        .map_err(|e| format!("Decode encrypted connect salt ({e})"))?;
    if salt.len() != 32 {
        return Err(format!("Invalid encrypted connect salt length: {}", salt.len()));
    }
    let key = derive_connect_message_key(encryption_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad })
        .map_err(|e| format!("Decrypt connect body ({e})"))
}

/// Derives a per-message 32-byte encryption key via HKDF-SHA256.
///
/// `encryption_secret` is hex-encoded (with optional `0x` prefix).
/// `salt` is random 32 bytes (unique per message).
pub fn derive_connect_message_key(
    encryption_secret: &str,
    salt: &[u8],
) -> Result<[u8; 32], String> {
    let secret_hex =
        encryption_secret.strip_prefix("0x").or_else(|| encryption_secret.strip_prefix("0X"));
    let secret_hex = secret_hex.unwrap_or(encryption_secret);
    if secret_hex.is_empty() || !secret_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("encryption secret must be valid hex".to_string());
    }
    let secret =
        hex::decode(secret_hex).map_err(|e| format!("Decode encryption secret hex ({e})"))?;
    if secret.is_empty() {
        return Err("encryption secret must not be empty".to_string());
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), &secret);
    let mut key = [0u8; 32];
    hk.expand(CONNECT_MESSAGE_KEY_INFO, &mut key)
        .map_err(|e| format!("HKDF expand connect key ({e})"))?;
    Ok(key)
}

// --- AAD ---

/// Builds the AAD (Associated Authenticated Data) bytes for a connect message.
///
/// AAD includes: `v`, `session_id`, `dir`, `seq`, `type`, `ts`.
pub fn connect_message_aad(
    session_id: &str,
    dir: &str,
    seq: u64,
    msg_type: &str,
    ts: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "v": CONNECT_MESSAGE_VERSION,
        "session_id": session_id,
        "dir": dir,
        "seq": seq,
        "type": msg_type,
        "ts": ts,
    }))
    .map_err(|e| format!("Serialize connect message AAD ({e})"))
}

// --- Input normalization ---

/// Normalizes a uint256 hex value: strips `0x` prefix, left-pads to 64 chars,
/// lowercases, and prepends `0x`.
///
/// # Examples
/// - `"0x1"` → `"0x0000...0001"`
/// - `"FF"` → `"0x0000...00ff"`
pub fn normalize_uint256_hex(value: &str) -> Result<String, String> {
    let stripped = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if stripped.is_empty() {
        return Err("app_id must be a non-empty uint256 hex string".to_string());
    }
    if stripped.len() > 64 {
        return Err(format!("app_id hex is too long for uint256 ({} > 64)", stripped.len()));
    }
    if !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("app_id is not valid hex: {value}"));
    }
    Ok(format!("0x{:0>64}", stripped.to_ascii_lowercase()))
}

/// Normalizes an owner public key hex: strips `0x` prefix, lowercases,
/// validates exactly 64 hex chars (32 bytes).
///
/// # Examples
/// - `"0xAABB...CC"` → `"aabb...cc"` (64 chars)
pub fn normalize_owner_public_hex(value: &str) -> Result<String, String> {
    let stripped = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if stripped.is_empty() {
        return Err("owner_public must be non-empty hex string".to_string());
    }
    if stripped.len() != 64 {
        return Err(format!("owner_public must be 64 hex chars (got {})", stripped.len()));
    }
    if !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("owner_public is not valid hex: {value}"));
    }
    Ok(stripped.to_ascii_lowercase())
}
