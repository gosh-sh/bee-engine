use ackinacki_kit::tvm_client::crypto::KeyPair;
use serde::Deserialize;
use serde::Serialize;

pub(crate) mod auth;
pub(crate) mod client_login_complete;
pub(crate) mod client_login_prepare;
pub(crate) mod utils;

#[derive(Debug, Deserialize, Clone)]
pub struct ParamsOfAddZKPFactor {
    pub wallet_name: String,
    pub proof: String,
    pub epk: String,
    pub esk: String,
    pub header_base_64: String,
    pub epk_expire_at: u64,
    pub jwk_expires_at: u64,
    pub kid: String,
    pub sub: String,
    pub password: String,
    pub zkid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfAddZKPFactor {
    pub name: String,
    pub address: String,
    pub message_id: Option<String>,
    pub message_ids: Vec<String>,
    pub pubkey: String,
    pub password_hash: String,
    pub signing_keys: KeyPair,
}

pub use client_login_complete::ZkLoginCompleteWithProverParams;
pub use client_login_complete::ZkLoginCompleteWithProverResult;
pub use client_login_prepare::ZkLoginPrepareResult;
