use std::sync::Arc;

use ackinacki_kit::tvm_client::crypto::ParamsOfHash;
use ackinacki_kit::tvm_client::crypto::ResultOfHash;
use ackinacki_kit::tvm_client::ClientContext;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroizing;

pub fn sha256(
    tvm_client: Arc<ClientContext>,
    data: String,
) -> crate::errors::AppResult<ResultOfHash> {
    let data_base64 = super::encoding::b64_std_encode(data);

    let res = ackinacki_kit::tvm_client::crypto::sha256(
        tvm_client.clone(),
        ParamsOfHash { data: data_base64 },
    )
    .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to hash data"))?;

    Ok(res)
}

const PBKDF2_ROUNDS_V3: u32 = super::key::PBKDF2_ITERATIONS;
const PBKDF2_ROUNDS_V2_LEGACY: u32 = 100_000;
const DK_LEN: usize = 32;
const SALT_LEN: usize = 32;

#[cfg(not(target_arch = "wasm32"))]
pub fn random_salted_hash(
    _tvm_client: Arc<ClientContext>,
    data: String,
) -> crate::errors::AppResult<ResultOfHash> {
    let mut salt_bytes = [0u8; SALT_LEN];
    getrandom::fill(&mut salt_bytes)
        .map_err(|e| crate::errors::AppError::new(format!("Failed to generate salt: {e}")))?;

    let mut dk = [0u8; DK_LEN];
    pbkdf2_hmac::<Sha256>(data.as_bytes(), &salt_bytes, PBKDF2_ROUNDS_V3, &mut dk);

    let envelope = format!("v3:{}:{}", hex::encode(salt_bytes), hex::encode(dk));
    dk.zeroize();
    Ok(ResultOfHash { hash: envelope })
}

#[cfg(target_arch = "wasm32")]
pub async fn random_salted_hash(
    _tvm_client: Arc<ClientContext>,
    data: String,
) -> crate::errors::AppResult<ResultOfHash> {
    let mut salt_bytes = [0u8; SALT_LEN];
    getrandom::fill(&mut salt_bytes)
        .map_err(|e| crate::errors::AppError::new(format!("Failed to generate salt: {e}")))?;

    let dk_hex: Zeroizing<String> =
        super::key::derive_key_pbkdf2(data.as_bytes(), &salt_bytes).await?;

    let envelope = format!("v3:{}:{}", hex::encode(salt_bytes), &*dk_hex);
    Ok(ResultOfHash { hash: envelope })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_salted_hash(password: &str, envelope: &str) -> crate::errors::AppResult<bool> {
    let parts: Vec<&str> = envelope.split(':').collect();
    if parts.len() != 3 {
        return Err("Bad format".into());
    }

    let iterations = match parts[0] {
        "v3" => PBKDF2_ROUNDS_V3,
        "v2" => PBKDF2_ROUNDS_V2_LEGACY,
        _ => return Err(format!("Unknown hash version: {}", parts[0]).into()),
    };

    let salt_bytes = hex::decode(parts[1]).map_err(|_| "Bad salt hex")?;
    if salt_bytes.len() != SALT_LEN {
        return Err("Bad salt length".into());
    }

    let expected = hex::decode(parts[2]).map_err(|_| "Bad dk hex")?;
    if expected.len() != DK_LEN {
        return Err("Bad dk length".into());
    }

    let mut dk = [0u8; DK_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, iterations, &mut dk);

    let result = dk.as_slice().ct_eq(expected.as_slice()).into();
    dk.zeroize();
    Ok(result)
}

#[cfg(target_arch = "wasm32")]
pub async fn verify_salted_hash(password: &str, envelope: &str) -> crate::errors::AppResult<bool> {
    let parts: Vec<&str> = envelope.split(':').collect();
    if parts.len() != 3 {
        return Err("Bad format".into());
    }

    let salt_bytes = hex::decode(parts[1]).map_err(|_| "Bad salt hex")?;
    if salt_bytes.len() != SALT_LEN {
        return Err("Bad salt length".into());
    }

    let expected = hex::decode(parts[2]).map_err(|_| "Bad dk hex")?;
    if expected.len() != DK_LEN {
        return Err("Bad dk length".into());
    }

    let dk_hex: Zeroizing<String> = match parts[0] {
        "v3" => {
            // 100k iterations — use SubtleCrypto
            super::key::derive_key_pbkdf2(password.as_bytes(), &salt_bytes).await?
        }
        "v2" => {
            // 100k iterations — Rust crate is fast enough
            let mut dk = [0u8; DK_LEN];
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                &salt_bytes,
                PBKDF2_ROUNDS_V2_LEGACY,
                &mut dk,
            );
            let hex_str = Zeroizing::new(hex::encode(dk));
            dk.zeroize();
            hex_str
        }
        _ => return Err(format!("Unknown hash version: {}", parts[0]).into()),
    };

    let mut dk_bytes = hex::decode(&*dk_hex).map_err(|_| "Bad computed dk hex")?;
    let result = dk_bytes.as_slice().ct_eq(expected.as_slice()).into();
    dk_bytes.zeroize();
    Ok(result)
}
