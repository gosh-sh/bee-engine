use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::services::miner::query::ResultOfGetMinerDetails as InnerResultOfGetMinerDetails;
use crate::wasm::dto::TMinerOwnerPublicMap;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfGetMinerDetails {
    address: String,
    owner_address: String,
    owner_public: HashMap<String, String>,
}

impl From<InnerResultOfGetMinerDetails> for ResultOfGetMinerDetails {
    fn from(value: InnerResultOfGetMinerDetails) -> Self {
        Self {
            owner_public: value.details.owner_public,
            owner_address: value.details.owner_address,
            address: value.address,
        }
    }
}

#[wasm_bindgen]
impl ResultOfGetMinerDetails {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner_address(&self) -> String {
        self.owner_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner_public(&self) -> TMinerOwnerPublicMap {
        let v = self
            .owner_public
            .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
            .unwrap_or(JsValue::NULL);

        v.unchecked_into::<TMinerOwnerPublicMap>()
    }
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfGetMinerAddress {
    pub multifactor_address: String,
}
