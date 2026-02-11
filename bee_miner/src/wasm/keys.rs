use ackinacki_kit::tvm_client::ClientConfig;
use serde::Deserialize;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;
use wasm_bindgen::JsValue;

use crate::core::keys::ParamsOfEnsureMiningKeysPropagated;
use crate::core::keys::ParamsOfGetMinerAddressByWalletName;
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

export type TParamsOfGetMinerAddressByWalletName = {
    client_config: Record<string, unknown>;
    wallet_name: string;
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "TParamsOfEnsureMiningKeysPropagated")]
    pub type TParamsOfEnsureMiningKeysPropagated;

    #[wasm_bindgen(typescript_type = "TParamsOfGetMinerAddressByWalletName")]
    pub type TParamsOfGetMinerAddressByWalletName;
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

#[derive(Debug, Deserialize)]
struct ParamsOfGetMinerAddressByWalletNameWasm {
    client_config: ClientConfig,
    wallet_name: String,
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

#[wasm_bindgen(js_name = get_miner_address_by_wallet_name)]
pub async fn get_miner_address_by_wallet_name(
    params: TParamsOfGetMinerAddressByWalletName,
) -> Result<String, JsError> {
    let params: ParamsOfGetMinerAddressByWalletNameWasm =
        serde_wasm_bindgen::from_value(JsValue::from(params)).map_err(|e| {
            JsError::new(&format!(
                "Failed to deserialize get_miner_address_by_wallet_name params: {e}"
            ))
        })?;

    crate::core::keys::get_miner_address_by_wallet_name(ParamsOfGetMinerAddressByWalletName {
        client_config: params.client_config,
        wallet_name: params.wallet_name,
    })
    .await
    .map_err(|e| JsError::new(&format!("Failed to get miner address by wallet name: {e}")))
}
