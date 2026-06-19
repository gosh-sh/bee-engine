use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::ResultOfSign as TvmResultOfSign;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct CryptoResultOfSign {
    /// Signed data combined with signature encoded in `base64`.
    signed: String,
    /// Signature encoded in `hex`.
    signature: String,
}

#[wasm_bindgen]
impl CryptoResultOfSign {
    #[wasm_bindgen(getter)]
    pub fn signed(&self) -> String {
        self.signed.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> String {
        self.signature.clone()
    }
}

impl From<TvmResultOfSign> for CryptoResultOfSign {
    fn from(value: TvmResultOfSign) -> Self {
        Self { signed: value.signed, signature: value.signature }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CryptoResultOfEncrypt {
    encrypted: String,
}

impl From<String> for CryptoResultOfEncrypt {
    fn from(value: String) -> Self {
        Self { encrypted: value }
    }
}

#[wasm_bindgen]
impl CryptoResultOfEncrypt {
    #[wasm_bindgen(getter)]
    pub fn encrypted(&self) -> String {
        self.encrypted.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CryptoResultOfGetKeys {
    public: String,
    secret: String,
}

impl From<KeyPair> for CryptoResultOfGetKeys {
    fn from(value: KeyPair) -> Self {
        Self { public: value.public.clone(), secret: value.secret.clone() }
    }
}

#[wasm_bindgen]
impl CryptoResultOfGetKeys {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CryptoResultOfGenSeedAndKeys {
    phrase: String,
    keys: CryptoResultOfGetKeys,
}

impl From<(String, KeyPair)> for CryptoResultOfGenSeedAndKeys {
    fn from(params: (String, KeyPair)) -> Self {
        Self { phrase: params.0, keys: CryptoResultOfGetKeys::from(params.1) }
    }
}

#[wasm_bindgen]
impl CryptoResultOfGenSeedAndKeys {
    #[wasm_bindgen(getter)]
    pub fn phrase(&self) -> String {
        self.phrase.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn keys(&self) -> CryptoResultOfGetKeys {
        self.keys.clone()
    }
}
