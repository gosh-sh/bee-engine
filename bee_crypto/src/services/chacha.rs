use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::chacha20;
use ackinacki_kit::tvm_client::crypto::ParamsOfChaCha20;
use ackinacki_kit::tvm_client::ClientContext;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use serde::Deserialize;
use zeroize::Zeroize;

use crate::errors::AppError;
use crate::errors::AppResult;

const LEGACY_PBKDF2_ITERATIONS: u32 = 100_000;

// ── AEAD helpers (sync, platform-independent) ──────────────────────

fn aead_encrypt(
    plaintext: &[u8],
    key_hex: &str,
    salt: &[u8],
    nonce: &[u8],
    version_tag: &str,
) -> AppResult<String> {
    let mut key_vec = hex::decode(key_hex)
        .map_err(|e| AppError::from(e).with_context("Failed to decode derived key"))?;
    let mut key_bytes: [u8; 32] =
        key_vec.as_slice().try_into().map_err(|_| AppError::new("Derived key must be 32 bytes"))?;
    key_vec.zeroize();

    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    key_bytes.zeroize();
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|e| AppError::new(format!("AEAD encryption failed: {e}")))?;

    Ok(format!(
        "{}:{}:{}:{}",
        version_tag,
        hex::encode(salt),
        hex::encode(nonce),
        hex::encode(ciphertext)
    ))
}

fn aead_decrypt(key_hex: &str, nonce: &[u8], ciphertext: &[u8]) -> AppResult<String> {
    let mut key_vec = hex::decode(key_hex)
        .map_err(|e| AppError::from(e).with_context("Failed to decode derived key"))?;
    let mut key_bytes: [u8; 32] =
        key_vec.as_slice().try_into().map_err(|_| AppError::new("Derived key must be 32 bytes"))?;
    key_vec.zeroize();

    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    key_bytes.zeroize();
    let plaintext = cipher.decrypt(XNonce::from_slice(nonce), ciphertext).map_err(|_| {
        AppError::new("Decryption failed: authentication tag mismatch (data may be tampered)")
    })?;

    String::from_utf8(plaintext)
        .map_err(|e| AppError::from(e).with_context("result decryption failure"))
}

// ── Envelope parsing helpers ───────────────────────────────────────

fn parse_aead_envelope(rest: &str) -> AppResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut parts = rest.splitn(3, ':');

    let salt_hex = parts.next().ok_or_else(|| AppError::new("Invalid envelope format"))?;
    let nonce_hex = parts.next().ok_or_else(|| AppError::new("Invalid envelope format"))?;
    let ciphertext_hex = parts.next().ok_or_else(|| AppError::new("Invalid envelope format"))?;

    let salt = hex::decode(salt_hex)
        .map_err(|e| AppError::from(e).with_context("Failed to decode salt"))?;
    if salt.len() != 32 {
        return Err(AppError::new(format!("Invalid salt length: expected 32, got {}", salt.len())));
    }

    let nonce = hex::decode(nonce_hex)
        .map_err(|e| AppError::from(e).with_context("Failed to decode nonce"))?;
    if nonce.len() != 24 {
        return Err(AppError::new(format!(
            "Invalid nonce length: expected 24, got {}",
            nonce.len()
        )));
    }

    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| AppError::from(e).with_context("Failed to decode ciphertext"))?;

    Ok((salt, nonce, ciphertext))
}

fn parse_v1_envelope(rest: &str) -> AppResult<(Vec<u8>, &str, &str)> {
    let mut parts = rest.splitn(3, ':');

    let salt_hex = parts.next().ok_or_else(|| AppError::new("Invalid envelope format"))?;
    let nonce_hex = parts.next().ok_or_else(|| AppError::new("Invalid envelope format"))?;
    let ciphertext = parts.next().ok_or_else(|| AppError::new("Invalid envelope format"))?;

    if nonce_hex.len() != 24 {
        // v1 nonce is 12 bytes = 24 hex characters
        return Err(AppError::new(format!(
            "Invalid v1 nonce length: expected 24 hex chars, got {}",
            nonce_hex.len()
        )));
    }

    let salt_bytes = hex::decode(salt_hex)
        .map_err(|e| AppError::from(e).with_context("Failed to decode salt hex"))?;

    if salt_bytes.len() != 16 {
        return Err(AppError::new(format!(
            "Invalid v1 salt length: expected 16, got {}",
            salt_bytes.len()
        )));
    }

    Ok((salt_bytes, nonce_hex, ciphertext))
}

// ── Public API: encrypt ────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
pub fn encrypt(
    _tvm_client: Arc<ClientContext>,
    plaintext: String,
    password: String,
) -> AppResult<String> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|e| AppError::new(format!("Failed to generate salt: {e}")))?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|e| AppError::new(format!("Failed to generate nonce: {e}")))?;
    let key_hex = super::key::derive_key_pbkdf2(password.as_bytes(), &salt)?;
    aead_encrypt(plaintext.as_bytes(), &key_hex, &salt, &nonce, "v3")
}

#[cfg(target_arch = "wasm32")]
pub async fn encrypt(
    _tvm_client: Arc<ClientContext>,
    plaintext: String,
    password: String,
) -> AppResult<String> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|e| AppError::new(format!("Failed to generate salt: {e}")))?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|e| AppError::new(format!("Failed to generate nonce: {e}")))?;
    let key_hex = super::key::derive_key_pbkdf2(password.as_bytes(), &salt).await?;
    aead_encrypt(plaintext.as_bytes(), &key_hex, &salt, &nonce, "v3")
}

// ── Public API: decrypt ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ParamsOfDecrypt {
    /// Encrypted envelope (e.g. "v3:...", "v2:..." or legacy "v1:...")
    pub encrypted: String,
    pub password: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt(tvm_client: Arc<ClientContext>, params: ParamsOfDecrypt) -> AppResult<String> {
    if let Some(rest) = params.encrypted.strip_prefix("v3:") {
        let (salt, nonce, ciphertext) = parse_aead_envelope(rest)?;
        let key_hex = super::key::derive_key_pbkdf2(params.password.as_bytes(), &salt)?;
        return aead_decrypt(&key_hex, &nonce, &ciphertext);
    }

    if let Some(rest) = params.encrypted.strip_prefix("v2:") {
        let (salt, nonce, ciphertext) = parse_aead_envelope(rest)?;
        let key_hex = super::key::derive_key_pbkdf2_with_rounds(
            params.password.as_bytes(),
            &salt,
            LEGACY_PBKDF2_ITERATIONS,
        )?;
        return aead_decrypt(&key_hex, &nonce, &ciphertext);
    }

    if let Some(rest) = params.encrypted.strip_prefix("v1:") {
        // TODO: Replace with log::warn! when logging dependency is added to bee_crypto
        eprintln!(
            "[DEPRECATION] Decrypting v1 envelope (unauthenticated ChaCha20). Re-encrypt with v3 format."
        );
        return decrypt_v1_legacy(tvm_client, rest, &params.password);
    }

    Err(AppError::new("Unknown encryption envelope version"))
}

#[cfg(target_arch = "wasm32")]
pub async fn decrypt(tvm_client: Arc<ClientContext>, params: ParamsOfDecrypt) -> AppResult<String> {
    if let Some(rest) = params.encrypted.strip_prefix("v3:") {
        let (salt, nonce, ciphertext) = parse_aead_envelope(rest)?;
        let key_hex = super::key::derive_key_pbkdf2(params.password.as_bytes(), &salt).await?;
        return aead_decrypt(&key_hex, &nonce, &ciphertext);
    }

    if let Some(rest) = params.encrypted.strip_prefix("v2:") {
        let (salt, nonce, ciphertext) = parse_aead_envelope(rest)?;
        let key_hex = super::key::derive_key_pbkdf2_with_rounds(
            params.password.as_bytes(),
            &salt,
            LEGACY_PBKDF2_ITERATIONS,
        )
        .await?;
        return aead_decrypt(&key_hex, &nonce, &ciphertext);
    }

    if let Some(rest) = params.encrypted.strip_prefix("v1:") {
        // TODO: Replace with log::warn! when logging dependency is added to bee_crypto
        eprintln!(
            "[DEPRECATION] Decrypting v1 envelope (unauthenticated ChaCha20). Re-encrypt with v3 format."
        );
        return decrypt_v1_legacy(tvm_client, rest, &params.password).await;
    }

    Err(AppError::new("Unknown encryption envelope version"))
}

// ── v1 legacy decrypt ──────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn decrypt_v1_legacy(
    tvm_client: Arc<ClientContext>,
    rest: &str,
    password: &str,
) -> AppResult<String> {
    let (salt_bytes, nonce_hex, ciphertext) = parse_v1_envelope(rest)?;
    let key_hex = super::key::derive_key_pbkdf2_with_rounds(
        password.as_bytes(),
        &salt_bytes,
        LEGACY_PBKDF2_ITERATIONS,
    )?;

    let res = chacha20(
        tvm_client.clone(),
        ParamsOfChaCha20 {
            data: ciphertext.to_string(),
            key: key_hex.to_string(),
            nonce: nonce_hex.to_string(),
        },
    )
    .map_err(|e| AppError::from(e).with_context("ChaCha20 decryption failed"))?;

    let decrypted_bytes = super::encoding::b64_std_decode(&res.data)
        .map_err(|e| AppError::from(e).with_context("Base64 decode error"))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| AppError::from(e).with_context("result decryption failure"))
}

#[cfg(target_arch = "wasm32")]
async fn decrypt_v1_legacy(
    tvm_client: Arc<ClientContext>,
    rest: &str,
    password: &str,
) -> AppResult<String> {
    let (salt_bytes, nonce_hex, ciphertext) = parse_v1_envelope(rest)?;
    let key_hex = super::key::derive_key_pbkdf2_with_rounds(
        password.as_bytes(),
        &salt_bytes,
        LEGACY_PBKDF2_ITERATIONS,
    )
    .await?;

    let res = chacha20(
        tvm_client.clone(),
        ParamsOfChaCha20 {
            data: ciphertext.to_string(),
            key: key_hex.to_string(),
            nonce: nonce_hex.to_string(),
        },
    )
    .map_err(|e| AppError::from(e).with_context("ChaCha20 decryption failed"))?;

    let decrypted_bytes = super::encoding::b64_std_decode(&res.data)
        .map_err(|e| AppError::from(e).with_context("Base64 decode error"))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| AppError::from(e).with_context("result decryption failure"))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ackinacki_kit::tvm_client::ClientContext;

    use super::decrypt;
    use super::encrypt;
    use super::ParamsOfDecrypt;

    fn tvm() -> Arc<ClientContext> {
        Arc::new(ClientContext::new(Default::default()).unwrap())
    }

    #[test]
    fn test_v3_encrypt_decrypt_round_trip() {
        let tc = tvm();
        let encrypted = encrypt(tc.clone(), "secret data".into(), "password".into()).unwrap();
        assert!(encrypted.starts_with("v3:"), "Must produce v3 envelope");
        let decrypted =
            decrypt(tc, ParamsOfDecrypt { encrypted, password: "password".into() }).unwrap();
        assert_eq!(decrypted, "secret data");
    }

    #[test]
    fn test_v3_wrong_password_fails() {
        let tc = tvm();
        let encrypted = encrypt(tc.clone(), "secret".into(), "correct".into()).unwrap();
        let result = decrypt(tc, ParamsOfDecrypt { encrypted, password: "wrong".into() });
        assert!(result.is_err(), "Wrong password must fail AEAD auth");
    }

    #[test]
    fn test_v3_tampered_ciphertext_detected() {
        let tc = tvm();
        let encrypted = encrypt(tc.clone(), "secret".into(), "pass".into()).unwrap();
        let parts: Vec<&str> = encrypted.splitn(4, ':').collect();
        let mut ct_bytes = hex::decode(parts[3]).unwrap();
        ct_bytes[0] ^= 0x01;
        let tampered = format!("v3:{}:{}:{}", parts[1], parts[2], hex::encode(&ct_bytes));
        let result = decrypt(tc, ParamsOfDecrypt { encrypted: tampered, password: "pass".into() });
        assert!(result.is_err(), "Tampered ciphertext MUST be rejected by AEAD");
    }

    #[test]
    fn test_v3_envelope_format() {
        let tc = tvm();
        let encrypted = encrypt(tc, "data".into(), "pw".into()).unwrap();
        let parts: Vec<&str> = encrypted.splitn(4, ':').collect();
        assert_eq!(parts[0], "v3");
        assert_eq!(hex::decode(parts[1]).unwrap().len(), 32, "salt must be 32 bytes");
        assert_eq!(hex::decode(parts[2]).unwrap().len(), 24, "nonce must be 24 bytes");
        let ct_bytes = hex::decode(parts[3]).unwrap();
        // "data" = 4 bytes plaintext + 16 bytes Poly1305 authentication tag
        assert_eq!(ct_bytes.len(), 4 + 16, "ciphertext must include 16-byte Poly1305 auth tag");
    }

    #[test]
    fn test_v3_tampered_salt_detected() {
        let tc = tvm();
        let encrypted = encrypt(tc.clone(), "secret".into(), "pass".into()).unwrap();
        let parts: Vec<&str> = encrypted.splitn(4, ':').collect();
        let mut salt_bytes = hex::decode(parts[1]).unwrap();
        salt_bytes[0] ^= 0x01;
        let tampered = format!("v3:{}:{}:{}", hex::encode(&salt_bytes), parts[2], parts[3]);
        let result = decrypt(tc, ParamsOfDecrypt { encrypted: tampered, password: "pass".into() });
        assert!(result.is_err(), "Tampered salt must cause AEAD auth failure");
    }

    #[test]
    fn test_v3_tampered_nonce_detected() {
        let tc = tvm();
        let encrypted = encrypt(tc.clone(), "secret".into(), "pass".into()).unwrap();
        let parts: Vec<&str> = encrypted.splitn(4, ':').collect();
        let mut nonce_bytes = hex::decode(parts[2]).unwrap();
        nonce_bytes[0] ^= 0x01;
        let tampered = format!("v3:{}:{}:{}", parts[1], hex::encode(&nonce_bytes), parts[3]);
        let result = decrypt(tc, ParamsOfDecrypt { encrypted: tampered, password: "pass".into() });
        assert!(result.is_err(), "Tampered nonce must cause AEAD auth failure");
    }

    #[test]
    fn test_v2_backward_compat() {
        let tc = tvm();
        // Create a v2 envelope the way SEC1-F01 did (AEAD, 100k iterations)
        let password = "testpass";
        let plaintext = "v2 aead data";

        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).unwrap();
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).unwrap();

        // Derive key with legacy 100k iterations
        let key_hex =
            super::super::key::derive_key_pbkdf2_with_rounds(password.as_bytes(), &salt, 100_000)
                .unwrap();

        // Encrypt with AEAD
        let key_vec: Vec<u8> = hex::decode(&key_hex).unwrap();
        let key_bytes: [u8; 32] = key_vec.try_into().unwrap();
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::aead::KeyInit;
        use chacha20poly1305::XChaCha20Poly1305;
        use chacha20poly1305::XNonce;
        let cipher = XChaCha20Poly1305::new((&key_bytes).into());
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), plaintext.as_bytes()).unwrap();

        let v2_envelope =
            format!("v2:{}:{}:{}", hex::encode(salt), hex::encode(nonce), hex::encode(ciphertext));

        let decrypted =
            decrypt(tc, ParamsOfDecrypt { encrypted: v2_envelope, password: password.into() })
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_v1_backward_compat() {
        let tc = tvm();
        use ackinacki_kit::tvm_client::crypto::chacha20;
        use ackinacki_kit::tvm_client::crypto::generate_random_bytes;
        use ackinacki_kit::tvm_client::crypto::ParamsOfChaCha20;
        use ackinacki_kit::tvm_client::crypto::ParamsOfGenerateRandomBytes;

        let password = "testpass";
        let plaintext = "v1 legacy data";

        let nonce_random =
            generate_random_bytes(tc.clone(), ParamsOfGenerateRandomBytes { length: 12 }).unwrap();
        let nonce_bytes = super::super::encoding::b64_std_decode(&nonce_random.bytes).unwrap();
        let nonce_hex = hex::encode(&nonce_bytes);

        let salt_random =
            generate_random_bytes(tc.clone(), ParamsOfGenerateRandomBytes { length: 16 }).unwrap();
        let salt_bytes = super::super::encoding::b64_std_decode(&salt_random.bytes).unwrap();
        let salt_hex = hex::encode(&salt_bytes);

        let data_base64 = super::super::encoding::b64_std_encode(plaintext.as_bytes());
        // Use legacy 100k iterations to match real v1 envelopes
        let key_hex = super::super::key::derive_key_pbkdf2_with_rounds(
            password.as_bytes(),
            &salt_bytes,
            100_000,
        )
        .unwrap();

        let res = chacha20(
            tc.clone(),
            ParamsOfChaCha20 {
                data: data_base64,
                key: key_hex.to_string(),
                nonce: nonce_hex.clone(),
            },
        )
        .unwrap();

        let v1_envelope = format!("v1:{salt_hex}:{nonce_hex}:{}", res.data);

        let decrypted =
            decrypt(tc, ParamsOfDecrypt { encrypted: v1_envelope, password: password.into() })
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_v3_empty_plaintext() {
        let tc = tvm();
        let encrypted = encrypt(tc.clone(), "".into(), "pass".into()).unwrap();
        assert!(encrypted.starts_with("v3:"));
        let decrypted =
            decrypt(tc, ParamsOfDecrypt { encrypted, password: "pass".into() }).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_v3_unicode_plaintext() {
        let tc = tvm();
        let text = "Привет мир 🌍 日本語";
        let encrypted = encrypt(tc.clone(), text.into(), "pass".into()).unwrap();
        let decrypted =
            decrypt(tc, ParamsOfDecrypt { encrypted, password: "pass".into() }).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_unknown_version_rejected() {
        let tc = tvm();
        let result = decrypt(
            tc,
            ParamsOfDecrypt { encrypted: "v99:aabb:ccdd:eeff".into(), password: "pass".into() },
        );
        assert!(result.is_err(), "Unknown envelope version must be rejected");
    }

    #[test]
    fn test_pbkdf2_iterations() {
        assert_eq!(
            super::super::key::PBKDF2_ITERATIONS,
            100_000,
            "PBKDF2 iterations = 100k (mobile UX tradeoff, AEAD integrity preserved)"
        );
    }
}
