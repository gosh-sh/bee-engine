pub mod cmd;
pub mod query;

use ackinacki_kit::tvm_client::crypto::KeyPair;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ParamsOfSetMiningKeys {
    pub multifactor_address: String,
    pub signer_keys: KeyPair,
    pub mining_pubkey: String,
    #[serde(default)]
    pub app_id: String,
    pub epk_expire_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfDelMiningKey {
    pub multifactor_address: String,
    pub signer_keys: KeyPair,
    #[serde(default)]
    pub app_id: String,
    pub epk_expire_at: Option<u64>,
    #[serde(default)]
    pub wait: bool,
}
