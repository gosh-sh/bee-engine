use ackinacki_kit::tvm_client::crypto::KeyPair;
use serde::Deserialize;
use serde::Serialize;

pub mod prepare_deploy_params;
pub use prepare_deploy_params::ParamsOfPrepareDeploy;

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsOfDeployMultifactor {
    pub wallet_name: String,
    pub zkid: String,
    pub password: String,
    pub proof: String,
    pub epk: String,
    pub esk: String,
    pub jwk_modulus: String,
    pub jwk_modulus_expire_at: u64,
    pub index_mod_4: u8,
    pub iss_base_64: String,
    pub header_base_64: String,
    pub epk_expire_at: u64,
    pub kid: String,
    pub sub: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub signing_keys: KeyPair,
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfDeployMiner {
    pub multifactor_address: String,
    pub signer_keys: KeyPair,
}
