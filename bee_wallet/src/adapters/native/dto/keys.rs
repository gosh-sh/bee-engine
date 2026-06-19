use ackinacki_kit::tvm_client::crypto::KeyPair;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfGetKeys {
    pub public: String,
    pub secret: String,
}

impl From<KeyPair> for ResultOfGetKeys {
    fn from(value: KeyPair) -> Self {
        Self { public: value.public.clone(), secret: value.secret.clone() }
    }
}
