use ackinacki_kit::tvm_client::crypto::KeyPair;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfGetKeys {
    public: String,
    secret: String,
}

impl From<KeyPair> for ResultOfGetKeys {
    fn from(value: KeyPair) -> Self {
        Self { public: value.public.clone(), secret: value.secret.clone() }
    }
}

#[wasm_bindgen]
impl ResultOfGetKeys {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }
}
