use serde::Deserialize;
use serde::Serialize;

use super::keys::ResultOfGetKeys;
use crate::services::deploy::ResultOfDeployMultifactor as InnerResultOfDeployMultifactor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfDeployMultifactor {
    pub name: String,
    pub address: String,
    pub message_id: Option<String>,
    pub message_ids: Vec<String>,
    pub pending_stage: Option<String>,
    pub pending_reason: Option<String>,
    pub password_hash: String,
    pub phrase: String,
    pub pubkey: String,
    pub signing_keys: ResultOfGetKeys,
}

impl From<InnerResultOfDeployMultifactor> for ResultOfDeployMultifactor {
    fn from(value: InnerResultOfDeployMultifactor) -> Self {
        Self {
            name: value.name,
            address: value.address,
            message_id: value.message_id,
            message_ids: value.message_ids,
            pending_stage: value.pending_stage,
            pending_reason: value.pending_reason,
            password_hash: value.password_hash,
            phrase: value.phrase,
            pubkey: value.pubkey,
            signing_keys: ResultOfGetKeys::from(value.signing_keys),
        }
    }
}
