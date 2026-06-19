use zeroize::Zeroize;
use zeroize::Zeroizing;

pub(crate) const PBKDF2_ITERATIONS: u32 = 100_000;
pub(crate) const DERIVED_KEY_LEN: usize = 32;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
) -> crate::errors::AppResult<Zeroizing<String>> {
    derive_key_pbkdf2_with_rounds(password, salt, PBKDF2_ITERATIONS)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
) -> crate::errors::AppResult<Zeroizing<String>> {
    derive_key_pbkdf2_with_rounds(password, salt, PBKDF2_ITERATIONS).await
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn derive_key_pbkdf2_with_rounds(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
) -> crate::errors::AppResult<Zeroizing<String>> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut key = [0u8; DERIVED_KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut key);
    let result = Zeroizing::new(hex::encode(key));
    key.zeroize();
    Ok(result)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn derive_key_pbkdf2_with_rounds(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
) -> crate::errors::AppResult<Zeroizing<String>> {
    use js_sys::Array;
    use js_sys::ArrayBuffer;
    use js_sys::Object;
    use js_sys::Reflect;
    use js_sys::Uint8Array;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let global = js_sys::global();
    let crypto: web_sys::Crypto = Reflect::get(&global, &"crypto".into())
        .map_err(|_| crate::errors::AppError::new("Web Crypto API not available"))?
        .unchecked_into();
    let subtle = crypto.subtle();

    let password_buf = Uint8Array::from(password);
    let usages = Array::of1(&"deriveBits".into());

    let key_material: web_sys::CryptoKey = JsFuture::from(
        subtle
            .import_key_with_str("raw", &password_buf.buffer().into(), "PBKDF2", false, &usages)
            .map_err(|e| {
                crate::errors::AppError::new(format!("SubtleCrypto.importKey failed: {e:?}"))
            })?,
    )
    .await
    .map_err(|e| crate::errors::AppError::new(format!("SubtleCrypto.importKey rejected: {e:?}")))?
    .unchecked_into();

    let salt_buf = Uint8Array::from(salt);
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"PBKDF2".into())
        .map_err(|_| crate::errors::AppError::new("Failed to set algorithm.name"))?;
    Reflect::set(&algorithm, &"hash".into(), &"SHA-256".into())
        .map_err(|_| crate::errors::AppError::new("Failed to set algorithm.hash"))?;
    Reflect::set(&algorithm, &"salt".into(), &salt_buf.into())
        .map_err(|_| crate::errors::AppError::new("Failed to set algorithm.salt"))?;
    Reflect::set(&algorithm, &"iterations".into(), &wasm_bindgen::JsValue::from_f64(rounds as f64))
        .map_err(|_| crate::errors::AppError::new("Failed to set algorithm.iterations"))?;

    let derived: ArrayBuffer = JsFuture::from(
        subtle
            .derive_bits_with_object(&algorithm, &key_material, (DERIVED_KEY_LEN * 8) as u32)
            .map_err(|e| {
                crate::errors::AppError::new(format!("SubtleCrypto.deriveBits failed: {e:?}"))
            })?,
    )
    .await
    .map_err(|e| crate::errors::AppError::new(format!("SubtleCrypto.deriveBits rejected: {e:?}")))?
    .unchecked_into();

    let result = Uint8Array::new(&derived);
    let mut key = [0u8; DERIVED_KEY_LEN];
    result.copy_to(&mut key);
    let hex_key = Zeroizing::new(hex::encode(key));
    key.zeroize();

    Ok(hex_key)
}
