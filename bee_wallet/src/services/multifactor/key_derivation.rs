use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::{self as tvm_crypto};
use ackinacki_kit::tvm_client::ClientContext;
use base64::Engine;
use bee_crypto::Crypto as BeeCrypto;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Params;
use pbkdf2::Pbkdf2;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

/// Current tvm-sdk default HD derivation path (v3.0.0.an, commit 4841c29).
///
/// Pinned explicitly: every multifactor key we *write* on-chain is derived
/// here, so a future change to the SDK's default path can never again silently
/// re-derive (and brick) freshly created wallets. This equals today's SDK
/// default, so pinning is a no-op for current wallets — guarded by the
/// `current_path_matches_sdk_default` test.
pub const CURRENT_DERIVATION_PATH: &str = "m/44'/1331'/0'/0/0";

/// Legacy HD path of wallets created on tvm-sdk v2 (coin type 396).
///
/// Their multifactor keys (owner / jwk-update / recovery) live here. We never
/// write new keys on this path; we only *resolve* against it so a pre-v3 wallet
/// can still sign with the key it actually holds on-chain (match-and-sign).
/// Drop once telemetry shows the 396 population has fully migrated.
pub const LEGACY_DERIVATION_PATH: &str = "m/44'/396'/0'/0/0";

/// HD paths tried, in order, when resolving which key a wallet holds on-chain.
/// Current first so post-v3 wallets match on the first attempt.
const CANDIDATE_PATHS: [&str; 2] = [CURRENT_DERIVATION_PATH, LEGACY_DERIVATION_PATH];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParamsOfBuildRecoveryKeys {
    pub password: String,
    pub multifactor_address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParamsOfBuildUpdateJwkKeys {
    pub password: String,
    pub sub: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecoveryKeys {
    pub pub_recovery_key: String,
    pub pub_recovery_key_sig: String,
    pub keys: KeyPair,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwkUpdateKeys {
    pub pub_jwk_update_key: String,
    pub pub_jwk_update_sig: String,
    pub keys: KeyPair,
}

/// Derive an ed25519 signing keypair from a 24-word `phrase` on an explicit HD
/// `path`. Unlike `path: None`, this never depends on the SDK's mutable
/// default.
fn derive_sign_keys(
    tvm_context: Arc<ClientContext>,
    phrase: String,
    path: &str,
) -> crate::errors::AppResult<KeyPair> {
    tvm_crypto::mnemonic_derive_sign_keys(
        tvm_context,
        tvm_crypto::ParamsOfMnemonicDeriveSignKeys {
            phrase,
            path: Some(path.to_string()),
            dictionary: None,
            word_count: Some(24),
        },
    )
    .map_err(|e| crate::errors::AppError::from(e).with_context("failed to derive sign keys"))
}

/// True if `derived_public` (bare hex, as returned by the SDK) is the same key
/// as `on_chain_pubkey` (which the contract stores `0x`-prefixed).
fn pubkey_matches(derived_public: &str, on_chain_pubkey: &str) -> bool {
    let on_chain = on_chain_pubkey.strip_prefix("0x").unwrap_or(on_chain_pubkey);
    derived_public.eq_ignore_ascii_case(on_chain)
}

/// Match-and-sign: derive the keypair for `phrase` on whichever known HD path
/// produces the public key the contract currently stores in `on_chain_pubkey`.
///
/// A wallet created on tvm-sdk v2 holds its multifactor keys on
/// [`LEGACY_DERIVATION_PATH`]; v3 wallets use [`CURRENT_DERIVATION_PATH`]. We
/// try each, compare against the on-chain pubkey, and return the one that
/// matches — so legacy wallets keep signing with the key they really have
/// instead of one re-derived on the wrong path (the ERR_NOT_OWNER / 402 bug).
///
/// Returns the matching keypair and the path it was found on (for telemetry).
/// Errors only if *no* known path matches, which indicates a genuine
/// password/seed mismatch rather than a path-generation gap.
pub fn resolve_sign_keys(
    tvm_context: Arc<ClientContext>,
    phrase: String,
    on_chain_pubkey: &str,
) -> crate::errors::AppResult<(KeyPair, &'static str)> {
    for path in CANDIDATE_PATHS {
        let keys = derive_sign_keys(Arc::clone(&tvm_context), phrase.clone(), path)?;
        if pubkey_matches(&keys.public, on_chain_pubkey) {
            return Ok((keys, path));
        }
    }

    Err(crate::errors::AppError::new(
        "no known HD derivation path matches the on-chain key (wrong password or social account?)",
    )
    .with_kind("key_path_resolution"))
}

/// Build the recovery keypair that is *written* on-chain (new state). Always
/// derived on [`CURRENT_DERIVATION_PATH`]; used by the seed-change /
/// zkid-update flows that establish fresh recovery material.
pub async fn build_recovery_keys(
    tvm_context: Arc<ClientContext>,
    params: ParamsOfBuildRecoveryKeys,
) -> crate::errors::AppResult<RecoveryKeys> {
    let password_sha256 = sha256(tvm_context.clone(), params.password)?;
    let crypto = BeeCrypto::from_client_context(tvm_context.clone());

    let recovery_mnemonic = build_recovery_password(
        Arc::clone(&tvm_context),
        password_sha256,
        params.multifactor_address,
    )?;
    let recovery_keys =
        derive_sign_keys(Arc::clone(&tvm_context), recovery_mnemonic, CURRENT_DERIVATION_PATH)
            .map_err(|e| e.with_context("failed to create recovery keys"))?;
    let pub_recovery_key_sig =
        crypto.sign_detached_hex(recovery_keys.public.clone(), recovery_keys.secret.clone())?;

    Ok(RecoveryKeys {
        pub_recovery_key: format!("0x{}", recovery_keys.public.clone()),
        pub_recovery_key_sig,
        keys: recovery_keys,
    })
}

/// Build the jwk-update keypair that is *written* on-chain (new state). Always
/// derived on [`CURRENT_DERIVATION_PATH`].
pub async fn build_update_jwk_keys(
    tvm_context: Arc<ClientContext>,
    params: ParamsOfBuildUpdateJwkKeys,
) -> crate::errors::AppResult<JwkUpdateKeys> {
    let password_sha256 = sha256(tvm_context.clone(), params.password)?;
    let crypto = BeeCrypto::from_client_context(tvm_context.clone());

    let password_secret_mnemonic =
        build_update_jwk(Arc::clone(&tvm_context), password_sha256, params.sub)?;
    let keys = derive_sign_keys(
        Arc::clone(&tvm_context),
        password_secret_mnemonic,
        CURRENT_DERIVATION_PATH,
    )
    .map_err(|e| e.with_context("failed to create jwk update keys"))?;
    let pub_jwk_update_sig = crypto.sign_detached_hex(keys.public.clone(), keys.secret.clone())?;

    Ok(JwkUpdateKeys {
        pub_jwk_update_key: format!("0x{}", keys.public.clone()),
        pub_jwk_update_sig,
        keys,
    })
}

/// Resolve the jwk-update keypair that matches the wallet's on-chain
/// `jwk_update_key`, trying current then legacy HD paths (match-and-sign).
///
/// Used to *sign* `addJwkModulus`, which the contract gates with
/// `onlyOwnerPubkey(_jwk_update_key)` — so a pre-v3 wallet must sign with its
/// legacy (396) jwk key, not one re-derived on the current path.
pub fn resolve_jwk_update_signer(
    tvm_context: Arc<ClientContext>,
    params: ParamsOfBuildUpdateJwkKeys,
    on_chain_jwk_update_key: &str,
) -> crate::errors::AppResult<(KeyPair, &'static str)> {
    let password_sha256 = sha256(tvm_context.clone(), params.password)?;
    let phrase = build_update_jwk(Arc::clone(&tvm_context), password_sha256, params.sub)?;
    resolve_sign_keys(tvm_context, phrase, on_chain_jwk_update_key)
}

/// Resolve the recovery keypair that matches the wallet's on-chain
/// `pub_recovery_key`, trying current then legacy HD paths (match-and-sign).
///
/// Used to *sign* owner-rotation acceptance (`acceptCandidateSeedPhrase`),
/// which the contract requires be signed by the recovery key — so a pre-v3
/// wallet must sign with its legacy (396) recovery key.
pub fn resolve_recovery_signer(
    tvm_context: Arc<ClientContext>,
    params: ParamsOfBuildRecoveryKeys,
    on_chain_pub_recovery_key: &str,
) -> crate::errors::AppResult<(KeyPair, &'static str)> {
    let password_sha256 = sha256(tvm_context.clone(), params.password)?;
    let phrase = build_recovery_password(
        Arc::clone(&tvm_context),
        password_sha256,
        params.multifactor_address,
    )?;
    resolve_sign_keys(tvm_context, phrase, on_chain_pub_recovery_key)
}

fn sha256(tvm_context: Arc<ClientContext>, data: String) -> crate::errors::AppResult<String> {
    let result = tvm_crypto::sha256(
        tvm_context,
        tvm_crypto::ParamsOfHash { data: base64::engine::general_purpose::STANDARD.encode(data) },
    )
    .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to hash data"))?;

    Ok(result.hash)
}

fn build_update_jwk(
    tvm_context: Arc<ClientContext>,
    password_sha256: String,
    address: String,
) -> crate::errors::AppResult<String> {
    let entropy = create_salted_hash(address, password_sha256)?;
    let password_secret_mnemonic = tvm_crypto::mnemonic_from_entropy(
        Arc::clone(&tvm_context),
        tvm_crypto::ParamsOfMnemonicFromEntropy { dictionary: None, word_count: Some(24), entropy },
    )
    .map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to create password secret")
    })?;

    Ok(password_secret_mnemonic.phrase)
}

fn build_recovery_password(
    tvm_context: Arc<ClientContext>,
    password_sha256: String,
    address: String,
) -> crate::errors::AppResult<String> {
    let entropy = create_salted_hash(password_sha256, address)?;
    let recovery_mnemonic = tvm_crypto::mnemonic_from_entropy(
        Arc::clone(&tvm_context),
        tvm_crypto::ParamsOfMnemonicFromEntropy { dictionary: None, word_count: Some(24), entropy },
    )
    .map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to create recovery password")
    })?;

    Ok(recovery_mnemonic.phrase)
}

fn create_salted_hash(password: String, salt_str: String) -> crate::errors::AppResult<String> {
    let salt_bytes = Sha256::digest(salt_str.as_bytes());
    let salt = SaltString::encode_b64(&salt_bytes[..16])
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to create salt"))?;
    // SEC1-F02 won't fix: 100k rounds — mobile UX tradeoff, AEAD integrity
    // preserved. Cannot change without on-chain migration of recovery keys.
    let params = Params { rounds: 100_000, output_length: 32 };
    let hash = Pbkdf2
        .hash_password_customized(password.as_bytes(), None, None, params, &salt)
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to hash"))?;
    let res = hash.hash.ok_or_else(|| "hash missing".to_string())?;

    Ok(hex::encode(res.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicFromRandom;
    use ackinacki_kit::tvm_client::ClientContext;

    use super::*;

    fn ctx() -> Arc<ClientContext> {
        Arc::new(ClientContext::new(Default::default()).unwrap())
    }

    fn random_phrase(ctx: &Arc<ClientContext>) -> String {
        tvm_crypto::mnemonic_from_random(
            ctx.clone(),
            ParamsOfMnemonicFromRandom { dictionary: None, word_count: Some(24) },
        )
        .unwrap()
        .phrase
    }

    /// Pinning the write path is only safe while [`CURRENT_DERIVATION_PATH`]
    /// equals the SDK's default. If a future SDK bump moves the default, this
    /// fails loudly here instead of silently re-deriving keys in production.
    #[test]
    fn current_path_matches_sdk_default() {
        let ctx = ctx();
        let phrase = random_phrase(&ctx);

        let via_default = tvm_crypto::mnemonic_derive_sign_keys(
            ctx.clone(),
            tvm_crypto::ParamsOfMnemonicDeriveSignKeys {
                phrase: phrase.clone(),
                path: None,
                dictionary: None,
                word_count: Some(24),
            },
        )
        .unwrap();
        let via_pinned = derive_sign_keys(ctx, phrase, CURRENT_DERIVATION_PATH).unwrap();

        assert_eq!(
            via_default.public, via_pinned.public,
            "CURRENT_DERIVATION_PATH drifted from the tvm-sdk default — update the constant \
             and plan a key migration before shipping"
        );
    }

    #[test]
    fn legacy_and_current_paths_differ() {
        let ctx = ctx();
        let phrase = random_phrase(&ctx);

        let current =
            derive_sign_keys(ctx.clone(), phrase.clone(), CURRENT_DERIVATION_PATH).unwrap();
        let legacy = derive_sign_keys(ctx, phrase, LEGACY_DERIVATION_PATH).unwrap();

        assert_ne!(current.public, legacy.public);
    }

    #[test]
    fn resolve_picks_legacy_when_onchain_is_legacy() {
        let ctx = ctx();
        let phrase = random_phrase(&ctx);

        let legacy = derive_sign_keys(ctx.clone(), phrase.clone(), LEGACY_DERIVATION_PATH).unwrap();
        let on_chain = format!("0x{}", legacy.public); // contract stores 0x-prefixed

        let (resolved, path) = resolve_sign_keys(ctx, phrase, &on_chain).unwrap();

        assert_eq!(path, LEGACY_DERIVATION_PATH);
        assert_eq!(resolved.public, legacy.public);
        assert_eq!(resolved.secret, legacy.secret);
    }

    #[test]
    fn resolve_picks_current_first() {
        let ctx = ctx();
        let phrase = random_phrase(&ctx);

        let current =
            derive_sign_keys(ctx.clone(), phrase.clone(), CURRENT_DERIVATION_PATH).unwrap();
        let on_chain = format!("0x{}", current.public);

        let (resolved, path) = resolve_sign_keys(ctx, phrase, &on_chain).unwrap();

        assert_eq!(path, CURRENT_DERIVATION_PATH);
        assert_eq!(resolved.public, current.public);
    }

    #[test]
    fn resolve_errors_when_no_path_matches() {
        let ctx = ctx();
        let phrase = random_phrase(&ctx);
        let bogus = format!("0x{}", "ab".repeat(32));

        assert!(resolve_sign_keys(ctx, phrase, &bogus).is_err());
    }

    #[test]
    fn pubkey_matches_normalizes_prefix_and_case() {
        assert!(pubkey_matches("ABCD", "0xabcd"));
        assert!(pubkey_matches("abcd", "ABCD"));
        assert!(pubkey_matches("abcd", "0xABCD"));
        assert!(!pubkey_matches("abcd", "0xabce"));
    }

    // Fixed inputs for the synthetic-key tests below. The multifactor address
    // doubles as the recovery salt; `sub` is the OAuth subject for jwk keys.
    const KAT_PASSWORD: &str = "Hello!23";
    const KAT_SUB: &str = "104824947798240050903";
    const KAT_ADDRESS: &str = "0:cfa74aad2b19d5f8721dc5ec0bd05c6ca7d03d6666493293a1310d8289d6fb81";

    /// `add_jwk_modulus` (the login fix) signs via `resolve_jwk_update_signer`.
    /// A pre-v3 wallet holds `jwk_update_key` on the legacy path; resolving
    /// against that on-chain value must return the legacy keypair, not a
    /// current-path one. Exercises the full password → synthetic mnemonic →
    /// resolve wiring, not just the low-level primitive.
    #[test]
    fn resolve_jwk_update_signer_matches_legacy_onchain() {
        let ctx = ctx();
        let params =
            ParamsOfBuildUpdateJwkKeys { password: KAT_PASSWORD.into(), sub: KAT_SUB.into() };

        // Simulate a pre-v3 wallet: its jwk_update_key was derived on 396.
        let pw = sha256(ctx.clone(), params.password.clone()).unwrap();
        let phrase = build_update_jwk(ctx.clone(), pw, params.sub.clone()).unwrap();
        let legacy = derive_sign_keys(ctx.clone(), phrase, LEGACY_DERIVATION_PATH).unwrap();
        let on_chain = format!("0x{}", legacy.public);

        let (signer, path) = resolve_jwk_update_signer(ctx, params, &on_chain).unwrap();
        assert_eq!(path, LEGACY_DERIVATION_PATH);
        assert_eq!(signer.public, legacy.public);
        assert_eq!(signer.secret, legacy.secret);
    }

    /// `change_seed_phrase` accept signs via `resolve_recovery_signer`. Same
    /// guarantee for the recovery key of a pre-v3 wallet.
    #[test]
    fn resolve_recovery_signer_matches_legacy_onchain() {
        let ctx = ctx();
        let params = ParamsOfBuildRecoveryKeys {
            password: KAT_PASSWORD.into(),
            multifactor_address: KAT_ADDRESS.into(),
        };

        let pw = sha256(ctx.clone(), params.password.clone()).unwrap();
        let phrase =
            build_recovery_password(ctx.clone(), pw, params.multifactor_address.clone()).unwrap();
        let legacy = derive_sign_keys(ctx.clone(), phrase, LEGACY_DERIVATION_PATH).unwrap();
        let on_chain = format!("0x{}", legacy.public);

        let (signer, path) = resolve_recovery_signer(ctx, params, &on_chain).unwrap();
        assert_eq!(path, LEGACY_DERIVATION_PATH);
        assert_eq!(signer.public, legacy.public);
        assert_eq!(signer.secret, legacy.secret);
    }

    /// A current-path wallet must resolve on the current path (first
    /// candidate).
    #[test]
    fn resolve_jwk_update_signer_matches_current_onchain() {
        let ctx = ctx();
        let params =
            ParamsOfBuildUpdateJwkKeys { password: KAT_PASSWORD.into(), sub: KAT_SUB.into() };

        let pw = sha256(ctx.clone(), params.password.clone()).unwrap();
        let phrase = build_update_jwk(ctx.clone(), pw, params.sub.clone()).unwrap();
        let current = derive_sign_keys(ctx.clone(), phrase, CURRENT_DERIVATION_PATH).unwrap();
        let on_chain = format!("0x{}", current.public);

        let (signer, path) = resolve_jwk_update_signer(ctx, params, &on_chain).unwrap();
        assert_eq!(path, CURRENT_DERIVATION_PATH);
        assert_eq!(signer.public, current.public);
    }

    /// Known-answer vector: freezes the entire synthetic-key derivation
    /// (pbkdf2 rounds + salt construction + mnemonic-from-entropy + HD path)
    /// for a fixed (password, sub/address). The on-chain keys of every existing
    /// wallet depend on these bytes being stable — any change here would brick
    /// them, so this test must fail loudly if the derivation ever drifts.
    #[test]
    fn synthetic_key_derivation_is_frozen() {
        let ctx = ctx();

        let jwk_pw = sha256(ctx.clone(), KAT_PASSWORD.into()).unwrap();
        let jwk_phrase = build_update_jwk(ctx.clone(), jwk_pw, KAT_SUB.into()).unwrap();
        let jwk_396 =
            derive_sign_keys(ctx.clone(), jwk_phrase.clone(), LEGACY_DERIVATION_PATH).unwrap();
        let jwk_1331 = derive_sign_keys(ctx.clone(), jwk_phrase, CURRENT_DERIVATION_PATH).unwrap();

        let rec_pw = sha256(ctx.clone(), KAT_PASSWORD.into()).unwrap();
        let rec_phrase = build_recovery_password(ctx.clone(), rec_pw, KAT_ADDRESS.into()).unwrap();
        let rec_396 =
            derive_sign_keys(ctx.clone(), rec_phrase.clone(), LEGACY_DERIVATION_PATH).unwrap();
        let rec_1331 = derive_sign_keys(ctx, rec_phrase, CURRENT_DERIVATION_PATH).unwrap();

        // Pinned vectors for KAT_PASSWORD / KAT_SUB / KAT_ADDRESS. If any of
        // these change, the synthetic derivation drifted — do NOT just update
        // the constants: existing wallets' on-chain keys would no longer match.
        assert_eq!(
            jwk_396.public,
            "59ced9e475646fe323493066b31a1459975b2d021ef1466535376696da71dece"
        );
        assert_eq!(
            jwk_1331.public,
            "b215cd32f87666d39152064df5462aec7996c26428bd948ccb15b37a1827f1c0"
        );
        assert_eq!(
            rec_396.public,
            "93a3adede9765b05e1cdb57dbfea1dedeb5771eaa77ca8ec13c755c512021c46"
        );
        assert_eq!(
            rec_1331.public,
            "2818aecc050af7613a5deb2753adae1b938f2e361d2d72ee3c1a878f35dd2749"
        );
    }
}
