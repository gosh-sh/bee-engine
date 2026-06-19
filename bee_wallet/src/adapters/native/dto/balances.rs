use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::services::balance::ResultOfGetNativeBalances as InnerResultOfGetNativeBalances;
use crate::services::balance::ResultOfGetTokensBalances as InnerResultOfGetTokensBalances;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfGetNativeBalances {
    pub popitgame: BTreeMap<String, String>,
    pub ecc: BTreeMap<String, String>,
}

impl From<InnerResultOfGetNativeBalances> for ResultOfGetNativeBalances {
    fn from(value: InnerResultOfGetNativeBalances) -> Self {
        Self {
            popitgame: value
                .popitgame
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ecc: value.ecc.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfGetTokensBalances {
    pub tokens: BTreeMap<String, String>,
}

impl From<InnerResultOfGetTokensBalances> for ResultOfGetTokensBalances {
    fn from(value: InnerResultOfGetTokensBalances) -> Self {
        Self { tokens: value.tokens.into_iter().map(|(k, v)| (k, v.to_string())).collect() }
    }
}
