use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::ParamsOfSign;
use ackinacki_kit::tvm_client::crypto::ParamsOfVerifySignature;
use ackinacki_kit::tvm_client::crypto::ResultOfSign;
use ackinacki_kit::tvm_client::crypto::ResultOfVerifySignature;
use ackinacki_kit::tvm_client::ClientContext;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH;
use ed25519_dalek::SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH;
use zeroize::Zeroize;

pub fn sign(
    blockchain_context: Arc<ClientContext>,
    params: ParamsOfSign,
) -> crate::errors::AppResult<ResultOfSign> {
    ackinacki_kit::tvm_client::crypto::sign(blockchain_context, params)
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to sign data"))
}

pub fn verify_signature(
    _blockchain_context: Arc<ClientContext>,
    params: ParamsOfVerifySignature,
) -> crate::errors::AppResult<ResultOfVerifySignature> {
    use ed25519_dalek::Signature;
    use ed25519_dalek::VerifyingKey;

    // 1. Decode signed payload: base64(signature_64 || message)
    let signed_bytes = super::encoding::b64_std_decode(&params.signed).map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to decode signed base64")
    })?;

    if signed_bytes.len() < ED25519_SIGNATURE_LENGTH {
        return Err(crate::errors::AppError::new(
            "Signed data too short: must contain at least 64-byte signature",
        ));
    }

    let (sig_bytes, message) = signed_bytes.split_at(ED25519_SIGNATURE_LENGTH);

    // 2. Parse signature
    let signature = Signature::from_slice(sig_bytes)
        .map_err(|e| crate::errors::AppError::new(format!("Invalid signature encoding: {e}")))?;

    // 3. Decode public key from hex
    let pub_bytes = hex::decode(&params.public).map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to decode public key hex")
    })?;
    let pub_arr: [u8; ED25519_PUBLIC_KEY_LENGTH] = pub_bytes
        .try_into()
        .map_err(|_| crate::errors::AppError::new("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|e| crate::errors::AppError::new(format!("Invalid public key: {e}")))?;

    // 4. Strict verification — rejects non-canonical signatures
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|e| crate::errors::AppError::new(format!("Signature verification failed: {e}")))?;

    // 5. Return unsigned message as base64
    Ok(ResultOfVerifySignature { unsigned: super::encoding::b64_std_encode(message) })
}

pub fn sign_detached_hex(data: String, secret_key: String) -> crate::errors::AppResult<String> {
    let data_bytes = hex::decode(data.as_str())
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to decode hex data"))?;
    let mut secret_key_bytes = hex::decode(secret_key.as_str()).map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to decode hex secret")
    })?;
    let mut secret_key_arr: [u8; ED25519_PUBLIC_KEY_LENGTH] =
        secret_key_bytes.as_slice().try_into().map_err(|e| {
            crate::errors::AppError::new(format!("{e:?}"))
                .with_context("failed to convert secret bytes")
        })?;
    secret_key_bytes.zeroize();
    let signing_key = SigningKey::from_bytes(&secret_key_arr);
    secret_key_arr.zeroize();
    let signature: [u8; ED25519_SIGNATURE_LENGTH] = signing_key.sign(&data_bytes).to_bytes();

    Ok(hex::encode(signature))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicDeriveSignKeys;
    use ackinacki_kit::tvm_client::crypto::ParamsOfMnemonicFromRandom;
    use ackinacki_kit::tvm_client::crypto::ParamsOfSign;
    use ackinacki_kit::tvm_client::crypto::ParamsOfVerifySignature;
    use ackinacki_kit::tvm_client::ClientContext;
    use base64::Engine;

    #[test]
    fn sign_and_verify_signature_roundtrip() {
        let blockchain_context = Arc::new(ClientContext::new(Default::default()).unwrap());
        let unsigned =
            base64::engine::general_purpose::STANDARD.encode(b"bee_crypto_signature_test");

        let phrase = ackinacki_kit::tvm_client::crypto::mnemonic_from_random(
            blockchain_context.clone(),
            ParamsOfMnemonicFromRandom { dictionary: None, word_count: Some(24) },
        )
        .unwrap();

        let keys = ackinacki_kit::tvm_client::crypto::mnemonic_derive_sign_keys(
            blockchain_context.clone(),
            ParamsOfMnemonicDeriveSignKeys {
                phrase: phrase.phrase,
                path: None,
                dictionary: None,
                word_count: Some(24),
            },
        )
        .unwrap();
        let public = keys.public.clone();

        let sign_result = super::sign(
            blockchain_context.clone(),
            ParamsOfSign { unsigned: unsigned.clone(), keys },
        )
        .unwrap();

        let verify_result = super::verify_signature(
            blockchain_context,
            ParamsOfVerifySignature { signed: sign_result.signed, public },
        )
        .unwrap();
        assert_eq!(verify_result.unsigned, unsigned);
    }

    #[test]
    fn verify_strict_rejects_non_canonical_signature() {
        let blockchain_context = Arc::new(ClientContext::new(Default::default()).unwrap());

        let result = super::verify_signature(
            blockchain_context,
            ParamsOfVerifySignature {
                signed: base64::engine::general_purpose::STANDARD.encode(vec![0u8; 65]),
                public: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            },
        );
        assert!(result.is_err(), "Invalid signature must be rejected");
    }
}
