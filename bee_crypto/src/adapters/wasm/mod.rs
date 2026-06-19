use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::ParamsOfSign;
use ackinacki_kit::tvm_client::ClientContext;
use serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::client::CryptoClient;

mod dto;

/// High-level wasm API for crypto operations.
#[wasm_bindgen]
pub struct Crypto {
    inner: CryptoClient,
}

impl Crypto {
    /// Creates a crypto client from an existing TVM client context.
    ///
    /// This helper is primarily for internal Rust-side composition.
    pub fn from_client_context(tvm_client: Arc<ClientContext>) -> Self {
        Self { inner: CryptoClient::from_tvm_client(tvm_client) }
    }

    /// Produces detached Ed25519 signature (`hex`) for hex-encoded input bytes.
    ///
    /// Rust-only compatibility helper used by `bee_wallet` internals.
    pub fn sign_detached_hex(&self, data: String, secret_key: String) -> Result<String, JsError> {
        self.inner
            .sign_detached_hex(data, secret_key)
            .map_err(|e| JsError::new(&format!("failed to sign detached hex: {e:?}")))
    }

    /// Computes BOC hash for hex-encoded data.
    ///
    /// Rust-only compatibility helper used by `bee_wallet` internals.
    pub fn get_boc_hash(&self, data: String) -> Result<String, JsError> {
        self.inner
            .get_boc_hash(data)
            .map_err(|e| JsError::new(&format!("failed to get boc hash: {e:?}")))
    }
}

#[wasm_bindgen]
impl Crypto {
    /// Creates a crypto client bound to network endpoints.
    #[wasm_bindgen(constructor)]
    pub fn new(endpoints: Vec<String>) -> Result<Self, JsError> {
        let inner = CryptoClient::new(endpoints).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Computes a salted password hash in `v3:<salt_hex>:<dk_hex>` format.
    #[wasm_bindgen(js_name = hash_password)]
    pub async fn hash_password(&self, data: String) -> Result<String, JsError> {
        Ok(self
            .inner
            .hash_password(data)
            .await
            .map_err(|e| JsError::new(&format!("Failed to hash password: {e:?}")))?)
    }

    /// Verifies a plain password against a `v2` or `v3` hash.
    #[wasm_bindgen(js_name = verify_password_hash)]
    pub async fn verify_password_hash(
        &self,
        password: String,
        expected: String,
    ) -> Result<bool, JsError> {
        Ok(self
            .inner
            .verify_password_hash(&password, &expected)
            .await
            .map_err(|e| JsError::new(&format!("Failed to verify pwd hash: {e:?}")))?)
    }

    /// Encrypts plaintext with a password.
    #[wasm_bindgen(js_name = encrypt)]
    pub async fn encrypt(
        &self,
        plaintext: String,
        password: String,
    ) -> Result<dto::crypto::CryptoResultOfEncrypt, JsError> {
        let res = self
            .inner
            .encrypt(plaintext, password)
            .await
            .map_err(|e| JsError::new(&format!("Failed to encrypt data: {e:?}")))?;

        Ok(dto::crypto::CryptoResultOfEncrypt::from(res))
    }

    /// Decrypts data previously encrypted with `encrypt`.
    #[wasm_bindgen(js_name = decrypt)]
    pub async fn decrypt(&self, encrypted: String, password: String) -> Result<String, JsError> {
        Ok(self
            .inner
            .decrypt(encrypted, password)
            .await
            .map_err(|e| JsError::new(&format!("Failed to decrypt data: {e:?}")))?)
    }

    /// Signs base64-encoded payload with an Ed25519 keypair.
    #[wasm_bindgen(js_name = sign)]
    pub async fn sign(
        &self,
        params_js: dto::TParamsOfSign,
    ) -> Result<dto::crypto::CryptoResultOfSign, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfSign = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfSign: {e:?}")))?;
        let res = self
            .inner
            .sign(params)
            .map_err(|e| JsError::new(&format!("failed to sign data: {e:?}")))?;

        Ok(dto::crypto::CryptoResultOfSign::from(res))
    }

    /// Generates a short-lived mining keypair.
    #[wasm_bindgen(js_name = gen_mining_keys)]
    pub async fn gen_mining_keys(&self) -> Result<dto::crypto::CryptoResultOfGetKeys, JsError> {
        let key_pair = self
            .inner
            .gen_mining_keys()
            .map_err(|e| JsError::new(&format!("failed to gen mining keys: {e:?}")))?;

        Ok(dto::crypto::CryptoResultOfGetKeys::from(key_pair))
    }

    /// Generates 24-word mnemonic and derives keys from it.
    #[wasm_bindgen(js_name = gen_mnemonic_and_derive_keys)]
    pub async fn gen_mnemonic_and_derive_keys(
        &self,
    ) -> Result<dto::crypto::CryptoResultOfGenSeedAndKeys, JsError> {
        let res = self
            .inner
            .gen_mnemonic_and_derive_keys()
            .map_err(|e| JsError::new(&format!("failed to gen mnemonic and derive keys: {e:?}")))?;

        Ok(dto::crypto::CryptoResultOfGenSeedAndKeys::from(res))
    }

    /// Derives keys from a mnemonic phrase.
    #[wasm_bindgen(js_name = get_keys_from_mnemonic)]
    pub async fn get_keys_from_mnemonic(
        &self,
        phrase: String,
    ) -> Result<dto::crypto::CryptoResultOfGetKeys, JsError> {
        let res = self
            .inner
            .get_keys_from_mnemonic(phrase)
            .map_err(|e| JsError::new(&format!("failed to derive keys from mnemonic: {e:?}")))?;

        Ok(dto::crypto::CryptoResultOfGetKeys::from(res))
    }

    /// Derives keys from a mnemonic phrase using a specific HD derivation path.
    #[wasm_bindgen(js_name = get_keys_from_mnemonic_with_path)]
    pub async fn get_keys_from_mnemonic_with_path(
        &self,
        phrase: String,
        path: String,
    ) -> Result<dto::crypto::CryptoResultOfGetKeys, JsError> {
        let res = self
            .inner
            .get_keys_from_mnemonic_with_path(phrase, path)
            .map_err(|e| JsError::new(&format!("failed to derive keys with path: {e:?}")))?;

        Ok(dto::crypto::CryptoResultOfGetKeys::from(res))
    }

    /// Verifies mnemonic checksum and format.
    #[wasm_bindgen(js_name = verify_mnemonic)]
    pub async fn verify_mnemonic(&self, phrase: String) -> Result<bool, JsError> {
        Ok(self
            .inner
            .verify_mnemonic(phrase)
            .map_err(|e| JsError::new(&format!("failed to verify mnemonic: {e:?}")))?)
    }
}
