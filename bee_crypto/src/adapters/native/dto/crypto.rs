use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::crypto::ResultOfSign as TvmResultOfSign;
use ackinacki_kit::tvm_client::crypto::ResultOfVerifySignature as TvmResultOfVerifySignature;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfSign {
    pub signed: String,
    pub signature: String,
}

impl From<TvmResultOfSign> for ResultOfSign {
    fn from(value: TvmResultOfSign) -> Self {
        Self { signed: value.signed, signature: value.signature }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfVerifySignature {
    pub unsigned: String,
}

impl From<TvmResultOfVerifySignature> for ResultOfVerifySignature {
    fn from(value: TvmResultOfVerifySignature) -> Self {
        Self { unsigned: value.unsigned }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfEncrypt {
    pub encrypted: String,
}

impl From<String> for ResultOfEncrypt {
    fn from(value: String) -> Self {
        Self { encrypted: value }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResultOfGetKeys {
    pub public: String,
    pub secret: String,
}

impl std::fmt::Debug for ResultOfGetKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResultOfGetKeys")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl From<KeyPair> for ResultOfGetKeys {
    fn from(value: KeyPair) -> Self {
        Self { public: value.public.clone(), secret: value.secret.clone() }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResultOfGenSeedAndKeys {
    pub phrase: String,
    pub keys: ResultOfGetKeys,
}

impl std::fmt::Debug for ResultOfGenSeedAndKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResultOfGenSeedAndKeys")
            .field("phrase", &"[REDACTED]")
            .field("keys", &self.keys)
            .finish()
    }
}

impl From<(String, KeyPair)> for ResultOfGenSeedAndKeys {
    fn from(params: (String, KeyPair)) -> Self {
        Self { phrase: params.0, keys: ResultOfGetKeys::from(params.1) }
    }
}
