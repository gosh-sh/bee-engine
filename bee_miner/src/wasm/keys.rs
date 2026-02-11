use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

use crate::core::keys::ResultOfGenMiningKeys as CoreResultOfGenMiningKeys;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfGenMiningKeys {
    public: String,
    secret: String,
    deep_link: String,
}

impl From<CoreResultOfGenMiningKeys> for ResultOfGenMiningKeys {
    fn from(value: CoreResultOfGenMiningKeys) -> Self {
        Self {
            public: value.keys.public.clone(),
            secret: value.keys.secret.clone(),
            deep_link: value.deep_link,
        }
    }
}

#[wasm_bindgen]
impl ResultOfGenMiningKeys {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn deep_link(&self) -> String {
        self.deep_link.clone()
    }
}

#[wasm_bindgen(js_name = gen_mining_keys)]
pub async fn gen_mining_keys(app_id: String) -> Result<ResultOfGenMiningKeys, JsError> {
    let result = crate::core::keys::gen_mining_keys(app_id)
        .await
        .map_err(|e| JsError::new(&format!("Failed to gen mining keys: {e}")))?;

    Ok(result.into())
}
