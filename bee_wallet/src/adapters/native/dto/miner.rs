use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;

use crate::services::miner::query::ResultOfGetMinerDetails as InnerResultOfGetMinerDetails;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfGetMinerDetails {
    pub address: String,
    pub owner_address: String,
    pub owner_public: HashMap<String, String>,
}

impl From<InnerResultOfGetMinerDetails> for ResultOfGetMinerDetails {
    fn from(value: InnerResultOfGetMinerDetails) -> Self {
        Self {
            address: value.address,
            owner_address: value.details.owner_address,
            owner_public: value.details.owner_public,
        }
    }
}
