use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::ParamsOfHash;
use ackinacki_kit::tvm_client::crypto::ParamsOfSign;
use ackinacki_kit::tvm_client::crypto::ParamsOfVerifySignature;
use ackinacki_kit::tvm_client::crypto::ResultOfHash;
use ackinacki_kit::tvm_client::crypto::ResultOfSign;
use ackinacki_kit::tvm_client::crypto::ResultOfVerifySignature;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;

use crate::errors::AppError;
use crate::errors::AppResult;
use crate::services;
use crate::services::ParamsOfDecrypt;

pub(crate) struct CryptoContext {
    pub(crate) tvm_client: Arc<ClientContext>,
}

impl CryptoContext {
    pub(crate) fn new(endpoints: Vec<String>) -> AppResult<Self> {
        #[cfg(feature = "wasm")]
        console_error_panic_hook::set_once();

        let mut config = ClientConfig::default();
        config.network.endpoints = Some(endpoints);
        let client = ClientContext::new(config)
            .map_err(|e| AppError::from(e).with_context("failed to create tvm client"))?;

        Ok(Self { tvm_client: Arc::new(client) })
    }

    pub(crate) fn from_tvm_client(tvm_client: Arc<ClientContext>) -> Self {
        #[cfg(feature = "wasm")]
        console_error_panic_hook::set_once();

        Self { tvm_client }
    }
}

pub(crate) struct CryptoClient {
    ctx: CryptoContext,
}

impl CryptoClient {
    pub(crate) fn new(endpoints: Vec<String>) -> AppResult<Self> {
        Ok(Self { ctx: CryptoContext::new(endpoints)? })
    }

    pub(crate) fn from_tvm_client(tvm_client: Arc<ClientContext>) -> Self {
        Self { ctx: CryptoContext::from_tvm_client(tvm_client) }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn hash_password(&self, data: String) -> AppResult<String> {
        services::random_salted_hash(self.ctx.tvm_client.clone(), data)
            .map(|result_of_hash| result_of_hash.hash)
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn hash_password(&self, data: String) -> AppResult<String> {
        services::random_salted_hash(self.ctx.tvm_client.clone(), data)
            .await
            .map(|result_of_hash| result_of_hash.hash)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn verify_password_hash(&self, password: &str, expected: &str) -> AppResult<bool> {
        services::verify_salted_hash(password, expected)
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn verify_password_hash(
        &self,
        password: &str,
        expected: &str,
    ) -> AppResult<bool> {
        services::verify_salted_hash(password, expected).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn encrypt(&self, plaintext: String, password: String) -> AppResult<String> {
        services::encrypt(self.ctx.tvm_client.clone(), plaintext, password)
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn encrypt(&self, plaintext: String, password: String) -> AppResult<String> {
        services::encrypt(self.ctx.tvm_client.clone(), plaintext, password).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn decrypt(&self, encrypted: String, password: String) -> AppResult<String> {
        services::decrypt(self.ctx.tvm_client.clone(), ParamsOfDecrypt { encrypted, password })
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn decrypt(&self, encrypted: String, password: String) -> AppResult<String> {
        services::decrypt(self.ctx.tvm_client.clone(), ParamsOfDecrypt { encrypted, password })
            .await
    }

    pub(crate) fn sign(&self, params: ParamsOfSign) -> AppResult<ResultOfSign> {
        services::sign(self.ctx.tvm_client.clone(), params)
    }

    pub(crate) fn verify_signature(
        &self,
        params: ParamsOfVerifySignature,
    ) -> AppResult<ResultOfVerifySignature> {
        services::verify_signature(self.ctx.tvm_client.clone(), params)
    }

    pub(crate) fn sign_detached_hex(&self, data: String, secret_key: String) -> AppResult<String> {
        services::sign_detached_hex(data, secret_key)
    }

    pub(crate) fn gen_mining_keys(&self) -> AppResult<KeyPair> {
        let res = self.gen_mnemonic_and_derive_keys(12)?;
        Ok(res.1)
    }

    pub(crate) fn gen_mnemonic_and_derive_keys(
        &self,
        word_count: u8,
    ) -> AppResult<(String, KeyPair)> {
        services::gen_mnemonic_and_derive_keys(self.ctx.tvm_client.clone(), word_count)
    }

    pub(crate) fn get_keys_from_mnemonic(
        &self,
        phrase: String,
        word_count: u8,
    ) -> AppResult<KeyPair> {
        services::derive_keys_from_mnemonic(self.ctx.tvm_client.clone(), phrase, word_count)
    }

    pub(crate) fn get_keys_from_mnemonic_with_path(
        &self,
        phrase: String,
        path: String,
        word_count: u8,
    ) -> AppResult<KeyPair> {
        services::derive_keys_from_mnemonic_with_path(
            self.ctx.tvm_client.clone(),
            phrase,
            path,
            word_count,
        )
    }

    pub(crate) fn verify_mnemonic(&self, phrase: String, word_count: u8) -> AppResult<bool> {
        services::validate_phrase_word_count(&phrase, word_count)?;
        services::verify_mnemonic(self.ctx.tvm_client.clone(), phrase, word_count)
    }

    pub(crate) fn mnemonic_words(&self) -> AppResult<String> {
        services::mnemonic_words(self.ctx.tvm_client.clone())
    }

    pub(crate) fn sha_256(&self, params: ParamsOfHash) -> AppResult<ResultOfHash> {
        services::sha256(self.ctx.tvm_client.clone(), params.data)
            .map_err(|e| e.with_context("failed to hash data"))
    }

    pub(crate) fn get_boc_hash(&self, data: String) -> AppResult<String> {
        services::get_boc_hash(self.ctx.tvm_client.clone(), data)
    }
}
