use wasm_bindgen::prelude::wasm_bindgen;

use crate::services::zkp::client_login_complete::IssBase64Details as InnerIssBase64Details;
use crate::services::zkp::ResultOfAddZKPFactor as InnerResultOfAddZKPFactor;
use crate::services::zkp::ZkLoginCompleteWithProverResult as InnerZkLoginCompleteWithProverResult;
use crate::services::zkp::ZkLoginPrepareResult as InnerZkLoginPrepareResult;
use crate::wasm::dto::keys::ResultOfGetKeys;

// TODO: same as deploy -> phrase should be optional
#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfAddZKPFactor {
    name: String,
    address: String,
    message_id: Option<String>,
    message_ids: Vec<String>,
    pubkey: String,
    password_hash: String,
    signing_keys: ResultOfGetKeys,
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

#[wasm_bindgen]
impl ResultOfAddZKPFactor {
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message_id(&self) -> Option<String> {
        self.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message_ids(&self) -> Vec<String> {
        self.message_ids.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn password_hash(&self) -> String {
        self.password_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signing_keys(&self) -> ResultOfGetKeys {
        self.signing_keys.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct IssBase64Details {
    value: String,
    index_mod4: u8,
}

impl From<InnerIssBase64Details> for IssBase64Details {
    fn from(value: InnerIssBase64Details) -> Self {
        Self { value: value.value, index_mod4: value.index_mod4 }
    }
}

#[wasm_bindgen]
impl IssBase64Details {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> String {
        self.value.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn index_mod4(&self) -> u8 {
        self.index_mod4
    }
}

#[wasm_bindgen]
pub struct ZkLoginCompleteWithProverResult {
    zkid: String,
    max_epoch: u64,
    ephemeral_private_key: String,
    zk_proof_compressed: String,
    iss_base64_details: IssBase64Details,
    header_base64: String,
    ephemeral_public_key_in_hex: String,
    ephemeral_secret_key_in_hex: String,
}

impl From<InnerZkLoginCompleteWithProverResult> for ZkLoginCompleteWithProverResult {
    fn from(value: InnerZkLoginCompleteWithProverResult) -> Self {
        Self {
            zkid: value.zkid,
            max_epoch: value.max_epoch,
            ephemeral_private_key: value.ephemeral_private_key,
            zk_proof_compressed: value.zk_proof_compressed,
            iss_base64_details: IssBase64Details::from(value.iss_base64_details),
            header_base64: value.header_base64,
            ephemeral_public_key_in_hex: value.ephemeral_public_key_in_hex,
            ephemeral_secret_key_in_hex: value.ephemeral_secret_key_in_hex,
        }
    }
}

#[wasm_bindgen]
pub struct ZkLoginPrepareResult {
    nonce: String,
    max_epoch: u64,
    randomness: String,
    ephemeral_private_key: String,
}

impl From<InnerZkLoginPrepareResult> for ZkLoginPrepareResult {
    fn from(value: InnerZkLoginPrepareResult) -> Self {
        Self {
            nonce: value.nonce,
            max_epoch: value.max_epoch,
            randomness: value.randomness,
            ephemeral_private_key: value.ephemeral_private_key,
        }
    }
}

#[wasm_bindgen]
impl ZkLoginPrepareResult {
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> String {
        self.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn max_epoch(&self) -> u64 {
        self.max_epoch
    }

    #[wasm_bindgen(getter)]
    pub fn randomness(&self) -> String {
        self.randomness.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ephemeral_private_key(&self) -> String {
        self.ephemeral_private_key.clone()
    }
}

#[wasm_bindgen]
impl ZkLoginCompleteWithProverResult {
    #[wasm_bindgen(getter)]
    pub fn zkid(&self) -> String {
        self.zkid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn max_epoch(&self) -> u64 {
        self.max_epoch
    }

    #[wasm_bindgen(getter)]
    pub fn ephemeral_private_key(&self) -> String {
        self.ephemeral_private_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn zk_proof_compressed(&self) -> String {
        self.zk_proof_compressed.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn iss_base64_details(&self) -> IssBase64Details {
        self.iss_base64_details.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn header_base64(&self) -> String {
        self.header_base64.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ephemeral_public_key_in_hex(&self) -> String {
        self.ephemeral_public_key_in_hex.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ephemeral_secret_key_in_hex(&self) -> String {
        self.ephemeral_secret_key_in_hex.clone()
    }
}
