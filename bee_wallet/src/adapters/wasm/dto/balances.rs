use std::collections::BTreeMap;

use num_bigint::BigInt;
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use serde_with::serde_as;
use serde_with::DisplayFromStr;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::services::balance::ResultOfGetNativeBalances as InnerResultOfGetNativeBalances;
use crate::services::balance::ResultOfGetTokensBalances as InnerResultOfGetTokensBalances;
use crate::wasm::dto::TNativeBalancesMap;
use crate::wasm::dto::TTokenBalancesMap;

#[wasm_bindgen]
#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResultOfGetTokensBalances {
    #[serde_as(as = "BTreeMap<_, DisplayFromStr>")]
    tokens: BTreeMap<String, BigInt>,
}

impl From<InnerResultOfGetTokensBalances> for ResultOfGetTokensBalances {
    fn from(value: InnerResultOfGetTokensBalances) -> Self {
        Self { tokens: value.tokens }
    }
}

#[wasm_bindgen]
impl ResultOfGetTokensBalances {
    #[wasm_bindgen(getter)]
    pub fn tokens(&self) -> TTokenBalancesMap {
        stringify_string_bigint_map(&self.tokens).unchecked_into::<TTokenBalancesMap>()
    }
}

fn stringify_string_bigint_map(map: &BTreeMap<String, BigInt>) -> JsValue {
    let obj_map: BTreeMap<String, String> =
        map.iter().map(|(k, v)| (k.clone(), v.to_string())).collect();

    obj_map.serialize(&Serializer::json_compatible()).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResultOfGetNativeBalances {
    #[serde_as(as = "BTreeMap<_, DisplayFromStr>")]
    popitgame: BTreeMap<u32, BigInt>,
    #[serde_as(as = "BTreeMap<_, DisplayFromStr>")]
    ecc: BTreeMap<u32, BigInt>,
}

impl From<InnerResultOfGetNativeBalances> for ResultOfGetNativeBalances {
    fn from(value: InnerResultOfGetNativeBalances) -> Self {
        Self { popitgame: value.popitgame, ecc: value.ecc }
    }
}

#[wasm_bindgen]
impl ResultOfGetNativeBalances {
    #[wasm_bindgen(getter)]
    pub fn popitgame(&self) -> TNativeBalancesMap {
        stringify_u32_bigint_map(&self.popitgame).unchecked_into::<TNativeBalancesMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn ecc(&self) -> TNativeBalancesMap {
        stringify_u32_bigint_map(&self.ecc).unchecked_into::<TNativeBalancesMap>()
    }
}

fn stringify_u32_bigint_map(map: &BTreeMap<u32, BigInt>) -> JsValue {
    let obj_map: BTreeMap<String, String> =
        map.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    obj_map.serialize(&Serializer::json_compatible()).unwrap_or(JsValue::NULL)
}
