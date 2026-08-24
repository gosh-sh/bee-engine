use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicDeriveSignKeys;
use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicFromRandom;
use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicVerify;
use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicWords;
use ackinacki_kit::tvm_client::ClientContext;

pub fn gen_mnemonic_and_derive_keys(
    tvm_client: Arc<ClientContext>,
    word_count: u8,
) -> crate::errors::AppResult<(String, KeyPair)> {
    let result_of_mnemonic_from_random = ackinacki_kit::tvm_client::crypto::mnemonic_from_random(
        tvm_client.clone(),
        ParamsOfMnemonicFromRandom { dictionary: None, word_count: Some(word_count) },
    )
    .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to gen seed"))?;

    let phrase = result_of_mnemonic_from_random.phrase;
    let result_of_mnemonic_derive_sign_keys =
        ackinacki_kit::tvm_client::crypto::mnemonic_derive_sign_keys(
            tvm_client.clone(),
            ParamsOfMnemonicDeriveSignKeys {
                phrase: phrase.clone(),
                path: None,
                dictionary: None,
                word_count: Some(word_count),
            },
        )
        .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to gen seed"))?;

    Ok((phrase, result_of_mnemonic_derive_sign_keys))
}

pub fn derive_keys_from_mnemonic(
    tvm_client: Arc<ClientContext>,
    phrase: String,
    word_count: u8,
) -> crate::errors::AppResult<KeyPair> {
    validate_phrase_word_count(&phrase, word_count)?;

    let result_of_mnemonic_derive_sign_keys =
        ackinacki_kit::tvm_client::crypto::mnemonic_derive_sign_keys(
            tvm_client.clone(),
            ParamsOfMnemonicDeriveSignKeys {
                phrase: phrase.clone(),
                path: None,
                dictionary: None,
                word_count: Some(word_count),
            },
        )
        .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to derive keys"))?;

    Ok(result_of_mnemonic_derive_sign_keys)
}

pub fn derive_keys_from_mnemonic_with_path(
    tvm_client: Arc<ClientContext>,
    phrase: String,
    path: String,
    word_count: u8,
) -> crate::errors::AppResult<KeyPair> {
    validate_phrase_word_count(&phrase, word_count)?;

    let result = ackinacki_kit::tvm_client::crypto::mnemonic_derive_sign_keys(
        tvm_client,
        ParamsOfMnemonicDeriveSignKeys {
            phrase,
            path: Some(path),
            dictionary: None,
            word_count: Some(word_count),
        },
    )
    .map_err(|e| {
        crate::errors::AppError::from(e).with_context("Failed to derive keys with path")
    })?;

    Ok(result)
}

pub fn verify_mnemonic(
    tvm_client: Arc<ClientContext>,
    phrase: String,
    word_count: u8,
) -> crate::errors::AppResult<bool> {
    let result_of_mnemonic_verify = ackinacki_kit::tvm_client::crypto::mnemonic_verify(
        tvm_client.clone(),
        ParamsOfMnemonicVerify {
            phrase: phrase.clone(),
            dictionary: None,
            word_count: Some(word_count),
        },
    )
    .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to derive keys"))?;

    Ok(result_of_mnemonic_verify.valid)
}

pub(crate) fn validate_phrase_word_count(
    phrase: &str,
    expected_word_count: u8,
) -> crate::errors::AppResult<()> {
    let actual_word_count = phrase.split_whitespace().count();
    if actual_word_count != usize::from(expected_word_count) {
        return Err(crate::errors::AppError::new(format!(
            "Mnemonic word count mismatch: expected {expected_word_count}, got {actual_word_count}"
        ))
        .with_kind("mnemonic"));
    }

    Ok(())
}

pub fn mnemonic_words(tvm_client: Arc<ClientContext>) -> crate::errors::AppResult<String> {
    let result = ackinacki_kit::tvm_client::crypto::mnemonic_words(
        tvm_client.clone(),
        ParamsOfMnemonicWords { dictionary: None },
    )
    .map_err(|e| {
        crate::errors::AppError::new(format!("Get mnemonic words failed: ({})", e))
            .with_details(e.message().to_string())
    })?;

    Ok(result.words)
}
