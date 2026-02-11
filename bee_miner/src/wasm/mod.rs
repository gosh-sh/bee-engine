use ackinacki_kit::contracts::deserialize::deserialize_u128;
use ackinacki_kit::contracts::deserialize::deserialize_u64;
use ackinacki_kit::contracts::event::query_events;
use ackinacki_kit::contracts::mvsystem;
use ackinacki_kit::contracts::mvsystem::miner::events::DecodedMinerEvent;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::ContextAccessor;
use ackinacki_kit::contracts::traits::FromEvent;
use ackinacki_kit::tvm_client::net::OrderBy;
use ackinacki_kit::tvm_client::net::SortDirection;
use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

pub mod keys;
pub mod miner;
pub mod worker;

#[wasm_bindgen]
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct GraphqlBlockData {
    pub seq_no: u64,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize)]
pub struct MinerAccountData {
    #[serde(alias = "_epochBigStart", deserialize_with = "deserialize_u64")]
    pub epoch_start: u64,

    #[serde(alias = "_epochStart", deserialize_with = "deserialize_u64")]
    pub epoch_5m_start: u64,

    #[serde(alias = "_tapSum", deserialize_with = "deserialize_u128")]
    pub tap_sum: u128,

    #[serde(alias = "_tapSum5m", deserialize_with = "deserialize_u128")]
    pub tap_sum_5m: u128,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct DecodedSessionStatusData {
    worker_id: u64,
}

impl TryFrom<String> for DecodedSessionStatusData {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes =
            hex::decode(&value).map_err(|e| format!("Decode data from hex `{value}` ({e})"))?;
        borsh::from_slice::<Self>(&bytes)
            .map_err(|e| format!("Deserialize data from `{bytes:?}` ({e})"))
    }
}

impl TryFrom<DecodedSessionStatusData> for String {
    type Error = String;

    fn try_from(value: DecodedSessionStatusData) -> Result<Self, Self::Error> {
        let bytes =
            borsh::to_vec(&value).map_err(|e| format!("Serialize event data `{value:?}` ({e})"))?;
        Ok(hex::encode(bytes))
    }
}

async fn get_miner_events(
    contract: &mvsystem::miner::contract::Miner,
    after_dt: u64,
) -> Result<Vec<DecodedMinerEvent>, JsError> {
    query_events(
        contract.context().clone(),
        Some(json!({
            "src": {"eq": contract.address()},
            "created_at": {"gt": after_dt},
        })),
        Some(vec![OrderBy { path: "created_at".to_string(), direction: SortDirection::ASC }]),
        Some(100),
    )
    .await
    .map_err(|e| JsError::new(&format!("Query miner events ({e})")))?
    .iter()
    .map(|event| {
        DecodedMinerEvent::from_event(event, contract).map_err(|e| JsError::new(&e.to_string()))
    })
    .collect::<Result<Vec<DecodedMinerEvent>, JsError>>()
}
