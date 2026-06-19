use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::ParamsOfHash;
use ackinacki_kit::tvm_client::crypto::ParamsOfSign;
use ackinacki_kit::tvm_client::crypto::ParamsOfVerifySignature;
use ackinacki_kit::tvm_client::crypto::ResultOfHash;
use ackinacki_kit::tvm_client::ClientContext;

use crate::client::CryptoClient;
use crate::errors::AppResult;

pub mod dto;

/// High-level native API for local crypto operations.
pub struct Crypto {
    inner: CryptoClient,
}

impl Crypto {
    /// Creates a crypto client bound to the provided network endpoints.
    pub fn new(endpoints: Vec<String>) -> AppResult<Self> {
        Ok(Self { inner: CryptoClient::new(endpoints)? })
    }

    /// Creates a crypto client from an existing TVM client context.
    pub fn from_client_context(tvm_client: Arc<ClientContext>) -> Self {
        Self { inner: CryptoClient::from_tvm_client(tvm_client) }
    }

    /// Computes a password hash with random salt and version prefix.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn hash_password(&self, data: String) -> AppResult<String> {
        self.inner.hash_password(data)
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn hash_password(&self, data: String) -> AppResult<String> {
        self.inner.hash_password(data).await
    }

    /// Verifies a plain password against a `v2` or `v3` hash string.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify_password_hash(&self, password: String, expected: String) -> AppResult<bool> {
        self.inner.verify_password_hash(&password, &expected)
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn verify_password_hash(
        &self,
        password: String,
        expected: String,
    ) -> AppResult<bool> {
        self.inner.verify_password_hash(&password, &expected).await
    }

    /// Encrypts plaintext with a password and returns envelope metadata.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn encrypt(
        &self,
        plaintext: String,
        password: String,
    ) -> AppResult<dto::crypto::ResultOfEncrypt> {
        let res = self.inner.encrypt(plaintext, password)?;
        Ok(dto::crypto::ResultOfEncrypt::from(res))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn encrypt(
        &self,
        plaintext: String,
        password: String,
    ) -> AppResult<dto::crypto::ResultOfEncrypt> {
        let res = self.inner.encrypt(plaintext, password).await?;
        Ok(dto::crypto::ResultOfEncrypt::from(res))
    }

    /// Decrypts previously encrypted data with a password.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn decrypt(&self, encrypted: String, password: String) -> AppResult<String> {
        self.inner.decrypt(encrypted, password)
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn decrypt(&self, encrypted: String, password: String) -> AppResult<String> {
        self.inner.decrypt(encrypted, password).await
    }

    /// Signs base64-encoded input with an Ed25519 key pair.
    pub fn sign(&self, params: ParamsOfSign) -> AppResult<dto::crypto::ResultOfSign> {
        let res = self.inner.sign(params)?;
        Ok(dto::crypto::ResultOfSign::from(res))
    }

    /// Verifies signed data and returns base64-encoded unsigned payload.
    pub fn verify_signature(
        &self,
        params: ParamsOfVerifySignature,
    ) -> AppResult<dto::crypto::ResultOfVerifySignature> {
        let res = self.inner.verify_signature(params)?;
        Ok(dto::crypto::ResultOfVerifySignature::from(res))
    }

    /// Produces detached Ed25519 signature (`hex`) for hex-encoded input bytes.
    pub fn sign_detached_hex(&self, data: String, secret_key: String) -> AppResult<String> {
        self.inner.sign_detached_hex(data, secret_key)
    }

    /// Generates a short-lived mining key pair.
    pub fn gen_mining_keys(&self) -> AppResult<dto::crypto::ResultOfGetKeys> {
        let key_pair = self.inner.gen_mining_keys()?;
        Ok(dto::crypto::ResultOfGetKeys::from(key_pair))
    }

    /// Generates a 24-word mnemonic phrase and derives owner keys from it.
    pub fn gen_mnemonic_and_derive_keys(&self) -> AppResult<dto::crypto::ResultOfGenSeedAndKeys> {
        let res = self.inner.gen_mnemonic_and_derive_keys()?;
        Ok(dto::crypto::ResultOfGenSeedAndKeys::from(res))
    }

    /// Derives owner keys from a mnemonic phrase.
    pub fn get_keys_from_mnemonic(
        &self,
        phrase: String,
    ) -> AppResult<dto::crypto::ResultOfGetKeys> {
        let res = self.inner.get_keys_from_mnemonic(phrase)?;
        Ok(dto::crypto::ResultOfGetKeys::from(res))
    }

    /// Derives keys from a mnemonic phrase using a specific HD derivation path.
    ///
    /// Use incrementing paths to generate multiple key pairs from one seed,
    /// e.g. `"m/44'/396'/0'/0/0"`, `"m/44'/396'/0'/0/1"`, etc.
    pub fn get_keys_from_mnemonic_with_path(
        &self,
        phrase: String,
        path: String,
    ) -> AppResult<dto::crypto::ResultOfGetKeys> {
        let res = self.inner.get_keys_from_mnemonic_with_path(phrase, path)?;
        Ok(dto::crypto::ResultOfGetKeys::from(res))
    }

    /// Verifies mnemonic phrase checksum and format.
    pub fn verify_mnemonic(&self, phrase: String) -> AppResult<bool> {
        self.inner.verify_mnemonic(phrase)
    }

    /// Returns the full BIP39 dictionary used by mnemonic utilities.
    pub fn mnemonic_words(&self) -> AppResult<String> {
        self.inner.mnemonic_words()
    }

    /// Computes SHA-256 hash for input payload.
    pub fn sha_256(&self, params: ParamsOfHash) -> AppResult<ResultOfHash> {
        self.inner.sha_256(params)
    }

    /// Computes BOC hash for hex-encoded data.
    pub fn get_boc_hash(&self, data: String) -> AppResult<String> {
        self.inner.get_boc_hash(data)
    }

    /// Derives a 32-byte storage encryption key from password and salt.
    /// PBKDF2-HMAC-SHA256, `PBKDF2_ITERATIONS` rounds.
    ///
    /// The returned key is wrapped in `Zeroizing` — it will be zeroed on drop.
    /// Caller should cache the key for the session and drop it on lock/logout.
    pub fn derive_storage_key(password: &[u8], salt: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
        crate::services::storage::derive_storage_key(password, salt)
    }

    /// Encrypts plaintext with a pre-derived 32-byte key.
    /// Returns envelope: `enc1:{nonce_hex}:{ciphertext_hex}`
    pub fn storage_encrypt(plaintext: &[u8], key: &[u8; 32]) -> AppResult<String> {
        crate::services::storage::storage_encrypt(plaintext, key)
    }

    /// Decrypts an `enc1:` envelope with a pre-derived 32-byte key.
    pub fn storage_decrypt(envelope: &str, key: &[u8; 32]) -> AppResult<String> {
        crate::services::storage::storage_decrypt(envelope, key)
    }
}
