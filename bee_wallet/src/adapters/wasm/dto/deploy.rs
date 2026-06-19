use std::collections::HashMap;

use ackinacki_kit::contracts::mvsystem::mirror::ParamsOfDeployMultifactor as InnerPreparedDeployParams;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::services::deploy::ResultOfDeployMultifactor as InnerResultOfDeployMultifactor;
use crate::wasm::dto::keys::ResultOfGetKeys;
use crate::wasm::dto::TRootProviderCertificatesMap;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfDeployMultifactor {
    name: String,
    address: String,
    message_id: Option<String>,
    message_ids: Vec<String>,
    pending_stage: Option<String>,
    pending_reason: Option<String>,
    password_hash: String,
    phrase: String,
    pubkey: String,
    signing_keys: ResultOfGetKeys,
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

#[wasm_bindgen]
impl ResultOfDeployMultifactor {
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
    pub fn pending_stage(&self) -> Option<String> {
        self.pending_stage.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pending_reason(&self) -> Option<String> {
        self.pending_reason.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn password_hash(&self) -> String {
        self.password_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn phrase(&self) -> String {
        self.phrase.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signing_keys(&self) -> ResultOfGetKeys {
        self.signing_keys.clone()
    }
}

/// Signed deploy params produced by `prepare_multifactor_deploy_params`.
/// Mirrors `ackinacki_kit::contracts::mvsystem::mirror::ParamsOfDeployMultifactor`.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PreparedDeployParams {
    name: String,
    zkid: String,
    proof: String,
    epk: String,
    epk_sig: String,
    epk_expire_at: u64,
    jwk_modulus: String,
    kid: String,
    jwk_modulus_expire_at: u64,
    index_mod_4: u8,
    iss_base_64: String,
    provider: String,
    header_base_64: String,
    pub_recovery_key: String,
    pub_recovery_key_sig: String,
    jwk_update_key: String,
    jwk_update_key_sig: String,
    root_provider_certificates: HashMap<String, String>,
}

impl From<InnerPreparedDeployParams> for PreparedDeployParams {
    fn from(value: InnerPreparedDeployParams) -> Self {
        Self {
            name: value.name,
            zkid: value.zkid,
            proof: value.proof,
            epk: value.epk,
            epk_sig: value.epk_sig,
            epk_expire_at: value.epk_expire_at,
            jwk_modulus: value.jwk_modulus,
            kid: value.kid,
            jwk_modulus_expire_at: value.jwk_modulus_expire_at,
            index_mod_4: value.index_mod_4,
            iss_base_64: value.iss_base_64,
            provider: value.provider,
            header_base_64: value.header_base_64,
            pub_recovery_key: value.pub_recovery_key,
            pub_recovery_key_sig: value.pub_recovery_key_sig,
            jwk_update_key: value.jwk_update_key,
            jwk_update_key_sig: value.jwk_update_key_sig,
            root_provider_certificates: value.root_provider_certificates,
        }
    }
}

#[wasm_bindgen]
impl PreparedDeployParams {
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn zkid(&self) -> String {
        self.zkid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> String {
        self.proof.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epk(&self) -> String {
        self.epk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epk_sig(&self) -> String {
        self.epk_sig.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epk_expire_at(&self) -> u64 {
        self.epk_expire_at
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_modulus(&self) -> String {
        self.jwk_modulus.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> String {
        self.kid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_modulus_expire_at(&self) -> u64 {
        self.jwk_modulus_expire_at
    }

    #[wasm_bindgen(getter)]
    pub fn index_mod_4(&self) -> u8 {
        self.index_mod_4
    }

    #[wasm_bindgen(getter)]
    pub fn iss_base_64(&self) -> String {
        self.iss_base_64.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn provider(&self) -> String {
        self.provider.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn header_base_64(&self) -> String {
        self.header_base_64.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pub_recovery_key(&self) -> String {
        self.pub_recovery_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pub_recovery_key_sig(&self) -> String {
        self.pub_recovery_key_sig.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_update_key(&self) -> String {
        self.jwk_update_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_update_key_sig(&self) -> String {
        self.jwk_update_key_sig.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn root_provider_certificates(&self) -> TRootProviderCertificatesMap {
        to_value(&self.root_provider_certificates)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TRootProviderCertificatesMap>()
    }
}
