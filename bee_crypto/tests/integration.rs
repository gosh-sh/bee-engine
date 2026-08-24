use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::ParamsOfHash;
use ackinacki_kit::tvm_client::crypto::ParamsOfSign;
use ackinacki_kit::tvm_client::crypto::ParamsOfVerifySignature;
use ackinacki_kit::tvm_client::ClientContext;
use base64::Engine;
use bee_crypto::Crypto;

const EXPLICIT_AGENT_PATH: &str = "m/44'/1331'/0'/1/0";
const KNOWN_24_WORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const KNOWN_24_WORD_DEFAULT_PUBLIC_KEY: &str =
    "a735f5004a58b190eaad81a090c4ebdcdce2ad58fb13352fbf5a6dec2c9a5c4f";
const KNOWN_24_WORD_EXPLICIT_PATH_PUBLIC_KEY: &str =
    "ae088fe12f111563ef288e51a87f0b877ee4c89384c4487e1b2db6b09ae4e92e";

fn create_crypto() -> Crypto {
    let endpoints = vec!["mainnet.ackinacki.org".to_string()];
    Crypto::new(endpoints).expect("Failed to create Crypto")
}

#[test]
fn test_hash_password_format() {
    let crypto = create_crypto();
    let hash = crypto.hash_password("password123".to_string()).unwrap();
    assert!(hash.starts_with("v3:"));
    let parts: Vec<&str> = hash.split(':').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1].len(), 64);
    assert_eq!(parts[2].len(), 64);
}

#[test]
fn test_verify_password_hash_round_trip() {
    let crypto = create_crypto();
    let password = "password123".to_string();
    let hash = crypto.hash_password(password.clone()).unwrap();

    let ok = crypto.verify_password_hash(password, hash.clone()).unwrap();
    assert!(ok, "correct password should verify");

    let bad = crypto.verify_password_hash("wrongpass".to_string(), hash).unwrap();
    assert!(!bad, "wrong password should not verify");
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let crypto = create_crypto();
    let plaintext = "hello world secret data";
    let password = "strongpassword";

    let encrypted = crypto.encrypt(plaintext.to_string(), password.to_string()).unwrap();
    assert!(encrypted.encrypted.starts_with("v3:"), "Must produce v3 envelope");
    assert_ne!(encrypted.encrypted, plaintext);

    let decrypted = crypto.decrypt(encrypted.encrypted, password.to_string()).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_wrong_password_fails() {
    let crypto = create_crypto();
    let encrypted = crypto.encrypt("secret".to_string(), "correct_password".to_string()).unwrap();

    let result = crypto.decrypt(encrypted.encrypted, "wrong_password".to_string());
    assert!(result.is_err());
}

#[test]
fn test_gen_mnemonic_and_derive_keys() {
    let crypto = create_crypto();
    let result = crypto.gen_mnemonic_and_derive_keys(24).unwrap();
    let words: Vec<&str> = result.phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    assert!(!result.keys.public.is_empty());
    assert!(!result.keys.secret.is_empty());
}

#[test]
fn test_get_keys_from_mnemonic_matches_gen() {
    let crypto = create_crypto();
    let generated = crypto.gen_mnemonic_and_derive_keys(24).unwrap();

    let derived = crypto.get_keys_from_mnemonic(generated.phrase.clone(), 24).unwrap();
    assert_eq!(derived.public, generated.keys.public);
    assert_eq!(derived.secret, generated.keys.secret);
}

#[test]
fn test_verify_mnemonic_valid() {
    let crypto = create_crypto();
    let generated = crypto.gen_mnemonic_and_derive_keys(24).unwrap();
    let is_valid = crypto.verify_mnemonic(generated.phrase, 24).unwrap();
    assert!(is_valid);
}

#[test]
fn test_verify_mnemonic_invalid() {
    let crypto = create_crypto();
    let is_valid = crypto
        .verify_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon".to_string(),
            24,
        )
        .unwrap();
    assert!(!is_valid);
}

#[test]
fn test_sign_deterministic() {
    let crypto = create_crypto();
    let keys = crypto.gen_mnemonic_and_derive_keys(24).unwrap();

    let params = ParamsOfSign {
        unsigned: base64::engine::general_purpose::STANDARD.encode(b"test message"),
        keys: KeyPair { public: keys.keys.public.clone(), secret: keys.keys.secret.clone() },
    };

    let result1 = crypto.sign(params).unwrap();
    assert!(!result1.signature.is_empty());
    assert!(!result1.signed.is_empty());

    let params2 = ParamsOfSign {
        unsigned: base64::engine::general_purpose::STANDARD.encode(b"test message"),
        keys: KeyPair { public: keys.keys.public.clone(), secret: keys.keys.secret.clone() },
    };
    let result2 = crypto.sign(params2).unwrap();
    assert_eq!(result1.signature, result2.signature);
}

#[test]
fn test_verify_signature_roundtrip() {
    let crypto = create_crypto();
    let keys = crypto.gen_mnemonic_and_derive_keys(24).unwrap();

    let sign_result = crypto
        .sign(ParamsOfSign {
            unsigned: base64::engine::general_purpose::STANDARD.encode(b"verify me"),
            keys: KeyPair { public: keys.keys.public.clone(), secret: keys.keys.secret.clone() },
        })
        .unwrap();

    let verify_result = crypto
        .verify_signature(ParamsOfVerifySignature {
            signed: sign_result.signed,
            public: keys.keys.public,
        })
        .unwrap();

    assert_eq!(
        verify_result.unsigned,
        base64::engine::general_purpose::STANDARD.encode(b"verify me")
    );
}

#[test]
fn test_gen_mining_keys() {
    let crypto = create_crypto();
    let keys = crypto.gen_mining_keys().unwrap();
    assert!(!keys.public.is_empty());
    assert!(!keys.secret.is_empty());
    assert_eq!(keys.public.len(), 64);
    assert_eq!(keys.secret.len(), 64);
}

#[test]
fn test_mnemonic_words() {
    let crypto = create_crypto();
    let words = crypto.mnemonic_words().unwrap();
    let word_list: Vec<&str> = words.split(' ').collect();
    assert!(word_list.len() > 2000); // BIP39 english = 2048
}

#[test]
fn test_sha_256() {
    let crypto = create_crypto();
    let result = crypto.sha_256(ParamsOfHash { data: "hello world".to_string() }).unwrap();
    assert_eq!(result.hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

#[test]
fn test_get_boc_hash() {
    let crypto = create_crypto();
    let hash = crypto.get_boc_hash("deadbeef".to_string()).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn test_from_client_context() {
    let tvm_client = Arc::new(ClientContext::new(Default::default()).unwrap());
    let crypto = Crypto::from_client_context(tvm_client);
    let words = crypto.mnemonic_words().unwrap();
    let word_list: Vec<&str> = words.split(' ').collect();
    assert!(word_list.len() > 2000);
}

#[test]
fn test_sign_detached_hex() {
    let crypto = create_crypto();
    let generated = crypto.gen_mnemonic_and_derive_keys(24).unwrap();
    let secret = generated.keys.secret;

    let hex_data = hex::encode(b"test payload");
    let sig = crypto.sign_detached_hex(hex_data.clone(), secret.clone()).unwrap();

    assert_eq!(sig.len(), 128, "detached signature must be 128 hex chars");
    assert!(sig.chars().all(|ch| ch.is_ascii_hexdigit()));

    // Deterministic: same input produces same signature
    let sig2 = crypto.sign_detached_hex(hex_data.clone(), secret.clone()).unwrap();
    assert_eq!(sig, sig2);

    // Different data produces different signature
    let other_data = hex::encode(b"other payload");
    let sig3 = crypto.sign_detached_hex(other_data, secret).unwrap();
    assert_ne!(sig, sig3);
}

#[test]
fn test_random_salted_hash() {
    let crypto = create_crypto();
    let input = "same_password".to_string();

    let hash1 = crypto.hash_password(input.clone()).unwrap();
    let hash2 = crypto.hash_password(input).unwrap();

    // Verify v3 format: "v3:{salt_hex}:{hash_hex}"
    assert!(hash1.starts_with("v3:"));
    let parts: Vec<&str> = hash1.split(':').collect();
    assert_eq!(parts.len(), 3);

    // Two calls with same input must produce different hashes (random salt)
    assert_ne!(hash1, hash2);
}

#[test]
fn test_verify_salted_hash() {
    let crypto = create_crypto();
    let password = "my_secret_value".to_string();

    let hash = crypto.hash_password(password.clone()).unwrap();

    // Correct password verifies
    let ok = crypto.verify_password_hash(password, hash.clone()).unwrap();
    assert!(ok, "correct password should verify");

    // Wrong password does not verify
    let bad = crypto.verify_password_hash("wrong_value".to_string(), hash.clone()).unwrap();
    assert!(!bad, "wrong password should not verify");

    // Corrupted hash fails
    let corrupted = "v3:0000:ffff".to_string();
    let result = crypto.verify_password_hash("my_secret_value".to_string(), corrupted);
    assert!(result.is_err() || !result.unwrap());
}

#[test]
fn test_12_word_mnemonic_round_trip() {
    let crypto = create_crypto();
    let generated = crypto.gen_mnemonic_and_derive_keys(12).unwrap();

    assert_eq!(generated.phrase.split_whitespace().count(), 12);
    assert!(crypto.verify_mnemonic(generated.phrase.clone(), 12).unwrap());

    let derived = crypto
        .get_keys_from_mnemonic_with_path(generated.phrase, EXPLICIT_AGENT_PATH.to_string(), 12)
        .unwrap();
    assert!(!derived.public.is_empty());
    assert!(!derived.secret.is_empty());
}

#[test]
fn test_24_word_mnemonic_regression_vectors() {
    let crypto = create_crypto();

    let default_keys = crypto.get_keys_from_mnemonic(KNOWN_24_WORD_PHRASE.to_string(), 24).unwrap();
    assert_eq!(default_keys.public, KNOWN_24_WORD_DEFAULT_PUBLIC_KEY);

    let explicit_keys = crypto
        .get_keys_from_mnemonic_with_path(
            KNOWN_24_WORD_PHRASE.to_string(),
            EXPLICIT_AGENT_PATH.to_string(),
            24,
        )
        .unwrap();
    assert_eq!(explicit_keys.public, KNOWN_24_WORD_EXPLICIT_PATH_PUBLIC_KEY);
}

#[test]
fn test_mnemonic_word_count_mismatch_fails_before_derivation() {
    let crypto = create_crypto();
    let generated = crypto.gen_mnemonic_and_derive_keys(12).unwrap();

    let default_path_error =
        crypto.get_keys_from_mnemonic(generated.phrase.clone(), 24).unwrap_err();
    assert!(default_path_error.message.contains("expected 24, got 12"));

    let explicit_path_error = crypto
        .get_keys_from_mnemonic_with_path(
            generated.phrase.clone(),
            EXPLICIT_AGENT_PATH.to_string(),
            24,
        )
        .unwrap_err();
    assert!(explicit_path_error.message.contains("expected 24, got 12"));

    let verify_error = crypto.verify_mnemonic(generated.phrase, 24).unwrap_err();
    assert!(verify_error.message.contains("expected 24, got 12"));
}
