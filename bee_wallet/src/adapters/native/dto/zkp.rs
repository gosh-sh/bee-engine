use serde::Deserialize;
use serde::Serialize;

use super::keys::ResultOfGetKeys;
use crate::services::zkp::ResultOfAddZKPFactor as InnerResultOfAddZKPFactor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfAddZKPFactor {
    pub name: String,
    pub address: String,
    pub message_id: Option<String>,
    pub message_ids: Vec<String>,
    pub pubkey: String,
    pub password_hash: String,
    pub signing_keys: ResultOfGetKeys,
}

impl From<InnerResultOfAddZKPFactor> for ResultOfAddZKPFactor {
    fn from(value: InnerResultOfAddZKPFactor) -> Self {
        Self {
            name: value.name,
            address: value.address,
            message_id: value.message_id,
            message_ids: value.message_ids,
            pubkey: value.pubkey,
            password_hash: value.password_hash,
            signing_keys: ResultOfGetKeys::from(value.signing_keys),
        }
    }
}
