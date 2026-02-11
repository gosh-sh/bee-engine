use ackinacki_kit::tvm_client::ClientConfig;
use serde::Deserialize;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;
use wasm_bindgen::JsValue;

use crate::core::keys::ParamsOfEnsureMiningKeysPropagated;
use crate::core::keys::ResultOfGenMiningKeys as CoreResultOfGenMiningKeys;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type TParamsOfEnsureMiningKeysPropagated = {
    client_config: Record<string, unknown>;
    miner_address: string;
    app_id: string;
    expected_owner_public: string;
    max_attempts?: number;
    interval_ms?: number;
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TParamsOfEnsureMiningKeysPropagated")]
    pub type TParamsOfEnsureMiningKeysPropagated;
}

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

#[derive(Debug, Deserialize)]
struct ParamsOfEnsureMiningKeysPropagatedWasm {
    client_config: ClientConfig,
    miner_address: String,
    app_id: String,
    expected_owner_public: String,
    max_attempts: Option<u32>,
    interval_ms: Option<u64>,
}

#[wasm_bindgen(js_name = gen_mining_keys)]
pub async fn gen_mining_keys(app_id: String) -> Result<ResultOfGenMiningKeys, JsError> {
    let result = crate::core::keys::gen_mining_keys(app_id)
        .await
        .map_err(|e| JsError::new(&format!("Failed to gen mining keys: {e}")))?;

    Ok(result.into())
}

#[wasm_bindgen(js_name = ensure_mining_keys_propagated)]
pub async fn ensure_mining_keys_propagated(
    params: TParamsOfEnsureMiningKeysPropagated,
) -> Result<(), JsError> {
    let params: ParamsOfEnsureMiningKeysPropagatedWasm =
        serde_wasm_bindgen::from_value(JsValue::from(params)).map_err(|e| {
            JsError::new(&format!(
                "Failed to deserialize ensure_mining_keys_propagated params: {e}"
            ))
        })?;

    crate::core::keys::ensure_mining_keys_propagated(ParamsOfEnsureMiningKeysPropagated {
        client_config: params.client_config,
        miner_address: params.miner_address,
        app_id: params.app_id,
        expected_owner_public: params.expected_owner_public,
        max_attempts: params.max_attempts,
        interval_ms: params.interval_ms,
    })
    .await
    .map_err(|e| JsError::new(&format!("Failed to ensure mining keys propagated: {e}")))
}
