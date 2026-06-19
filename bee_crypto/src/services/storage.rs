//! App-level storage encryption with a pre-derived key.
//!
//! Unlike `chacha.rs` (password-based, PBKDF2 per call), these functions
//! accept a raw 32-byte key. The caller derives the key once via
//! `derive_storage_key` and caches it for the session.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::errors::AppResult;

const STORAGE_ENVELOPE_VERSION: &str = "enc1";

/// Derives a 32-byte storage encryption key from a password and salt
/// using PBKDF2-HMAC-SHA256 with `PBKDF2_ITERATIONS` rounds.
///
/// Returns a `Zeroizing` wrapper that zeroes the key bytes on drop.
///
/// # Arguments
/// * `password` — user password bytes
/// * `salt` — random 32-byte salt (stored in plaintext WalletMeta)
pub fn derive_storage_key(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, super::key::PBKDF2_ITERATIONS, &mut key);
    Zeroizing::new(key)
}

/// Encrypts plaintext with a pre-derived 32-byte key.
///
/// Returns an envelope string: `enc1:{nonce_hex}:{ciphertext_hex}`
///
/// Uses XChaCha20-Poly1305 AEAD with a random 24-byte nonce.
/// Ciphertext includes a 16-byte Poly1305 authentication tag.
///
/// # Arguments
/// * `plaintext` — data to encrypt (UTF-8 bytes)
/// * `key` — 32-byte encryption key from `derive_storage_key`
pub fn storage_encrypt(plaintext: &[u8], key: &[u8; 32]) -> AppResult<String> {
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| AppError::new(format!("Failed to generate nonce: {e}")))?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| AppError::new(format!("AEAD encryption failed: {e}")))?;

    Ok(format!(
        "{}:{}:{}",
        STORAGE_ENVELOPE_VERSION,
        hex::encode(nonce_bytes),
        hex::encode(ciphertext),
    ))
}

/// Decrypts an `enc1:` envelope with a pre-derived 32-byte key.
///
/// # Arguments
/// * `envelope` — encrypted string in format
///   `enc1:{nonce_hex}:{ciphertext_hex}`
/// * `key` — 32-byte encryption key from `derive_storage_key`
///
/// # Errors
/// Returns error if envelope format is invalid, version is unknown,
/// or AEAD authentication fails (wrong key or tampered data).
pub fn storage_decrypt(envelope: &str, key: &[u8; 32]) -> AppResult<String> {
    let rest = envelope
        .strip_prefix("enc1:")
        .ok_or_else(|| AppError::new("Unknown storage envelope version"))?;

    let mut parts = rest.splitn(2, ':');
    let nonce_hex =
        parts.next().ok_or_else(|| AppError::new("Missing nonce in storage envelope"))?;
    let ct_hex =
        parts.next().ok_or_else(|| AppError::new("Missing ciphertext in storage envelope"))?;

    let nonce_bytes =
        hex::decode(nonce_hex).map_err(|e| AppError::from(e).with_context("Invalid nonce hex"))?;
    if nonce_bytes.len() != 24 {
        return Err(AppError::new(format!(
            "Invalid nonce length: expected 24, got {}",
            nonce_bytes.len()
        )));
    }

    let ciphertext = hex::decode(ct_hex)
        .map_err(|e| AppError::from(e).with_context("Invalid ciphertext hex"))?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| AppError::new("Storage decryption failed: wrong key or tampered data"))?;

    String::from_utf8(plaintext)
        .map_err(|e| AppError::from(e).with_context("Decrypted data is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Zeroizing<[u8; 32]> {
        derive_storage_key(b"test-password", b"test-salt-32-bytes-long-padding!")
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let encrypted = storage_encrypt(b"hello world", &key).unwrap();
        assert!(encrypted.starts_with("enc1:"));
        let decrypted = storage_decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "hello world");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_storage_key(b"password1", b"test-salt-32-bytes-long-padding!");
        let key2 = derive_storage_key(b"password2", b"test-salt-32-bytes-long-padding!");
        let encrypted = storage_encrypt(b"secret", &key1).unwrap();
        let result = storage_decrypt(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let key = test_key();
        let encrypted = storage_encrypt(b"secret", &key).unwrap();
        let parts: Vec<&str> = encrypted.splitn(3, ':').collect();
        let mut ct_bytes = hex::decode(parts[2]).unwrap();
        ct_bytes[0] ^= 0x01;
        let tampered = format!("enc1:{}:{}", parts[1], hex::encode(&ct_bytes));
        assert!(storage_decrypt(&tampered, &key).is_err());
    }

    #[test]
    fn tampered_nonce_detected() {
        let key = test_key();
        let encrypted = storage_encrypt(b"secret", &key).unwrap();
        let parts: Vec<&str> = encrypted.splitn(3, ':').collect();
        let mut nonce_bytes = hex::decode(parts[1]).unwrap();
        nonce_bytes[0] ^= 0x01;
        let tampered = format!("enc1:{}:{}", hex::encode(&nonce_bytes), parts[2]);
        assert!(storage_decrypt(&tampered, &key).is_err());
    }

    #[test]
    fn envelope_format() {
        let key = test_key();
        let encrypted = storage_encrypt(b"data", &key).unwrap();
        let parts: Vec<&str> = encrypted.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "enc1");
        assert_eq!(hex::decode(parts[1]).unwrap().len(), 24); // nonce
        let ct_bytes = hex::decode(parts[2]).unwrap();
        assert_eq!(ct_bytes.len(), 4 + 16); // plaintext + poly1305 tag
    }

    #[test]
    fn empty_plaintext() {
        let key = test_key();
        let encrypted = storage_encrypt(b"", &key).unwrap();
        let decrypted = storage_decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn unicode_plaintext() {
        let key = test_key();
        let text = "Привет мир 🌍 日本語";
        let encrypted = storage_encrypt(text.as_bytes(), &key).unwrap();
        let decrypted = storage_decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn large_plaintext() {
        let key = test_key();
        let text = "x".repeat(100_000);
        let encrypted = storage_encrypt(text.as_bytes(), &key).unwrap();
        let decrypted = storage_decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn unknown_version_rejected() {
        let key = test_key();
        assert!(storage_decrypt("enc2:aabb:ccdd", &key).is_err());
    }

    #[test]
    fn malformed_envelope_rejected() {
        let key = test_key();
        assert!(storage_decrypt("enc1:", &key).is_err());
        assert!(storage_decrypt("enc1:aabb", &key).is_err());
        assert!(storage_decrypt("not-an-envelope", &key).is_err());
    }

    #[test]
    fn derive_storage_key_deterministic() {
        let k1 = derive_storage_key(b"pwd", b"salt");
        let k2 = derive_storage_key(b"pwd", b"salt");
        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn derive_storage_key_different_salt() {
        let k1 = derive_storage_key(b"pwd", b"salt1");
        let k2 = derive_storage_key(b"pwd", b"salt2");
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn derive_storage_key_different_password() {
        let k1 = derive_storage_key(b"pwd1", b"salt");
        let k2 = derive_storage_key(b"pwd2", b"salt");
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn two_encryptions_produce_different_ciphertext() {
        let key = test_key();
        let e1 = storage_encrypt(b"same", &key).unwrap();
        let e2 = storage_encrypt(b"same", &key).unwrap();
        assert_ne!(e1, e2); // different random nonces
        assert_eq!(storage_decrypt(&e1, &key).unwrap(), "same");
        assert_eq!(storage_decrypt(&e2, &key).unwrap(), "same");
    }
}
