use std::collections::HashMap;

use ackinacki_kit::contracts::mvsystem::multifactor::AccountData as InnerMultifactorAccountData;
use ackinacki_kit::contracts::mvsystem::multifactor::JwkData;
use ackinacki_kit::contracts::mvsystem::root::ResultOfGetMvMultifactorAddress as InnerResultOfGetMvMultifactorAddress;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::services::multifactor::query::ResultOfCheckNameAvailability as InnerResultOfCheckNameAvailability;
use crate::services::multifactor::query::ResultOfGetMultifactorDetails as InnerResultOfGetMultifactorDetails;
use crate::wasm::dto::TCandidateOwnerPubkeyExpirationMap;
use crate::wasm::dto::TFactorsOrderedByTimestampMap;
use crate::wasm::dto::TJwkModulusDataMap;
use crate::wasm::dto::TWhiteListOfAddressMap;
use crate::GetEPKExpireRes as InnerGetEPKExpireRes;
use crate::ResultGetMirrorAddress as InnerResultGetMirrorAddress;
use crate::ResultOfGetMultifactorInfo as InnerResultOfGetMultifactorInfo;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfGetMultifactorDetails {
    address: String,
    candidate_new_owner_pubkey_and_expiration: Option<HashMap<String, String>>,
    factors_len: String,
    factors_ordered_by_timestamp: HashMap<String, String>,
    force_remove_oldest: bool,
    index_mod_4: String,
    iss_base_64: String,
    jwk_modulus_data: HashMap<String, JwkData>,
    jwk_modulus_data_len: String,
    m_security_cards_len: String,
    m_transactions_len: String,
    max_cleanup_txns: String,
    min_value: String,
    name: String,
    owner_pubkey: String,
    pub_recovery_key: String,
    root: String,
    use_security_card: bool,
    zkid: String,
    jwk_update_key: String,
    wasm_hash: String,
    white_list_of_address: HashMap<String, bool>,
}

impl From<InnerResultOfGetMultifactorDetails> for ResultOfGetMultifactorDetails {
    fn from(value: InnerResultOfGetMultifactorDetails) -> Self {
        Self {
            address: value.address,
            candidate_new_owner_pubkey_and_expiration: value
                .candidate_new_owner_pubkey_and_expiration,
            factors_len: value.factors_len,
            factors_ordered_by_timestamp: value.factors_ordered_by_timestamp,
            force_remove_oldest: value.force_remove_oldest,
            index_mod_4: value.index_mod_4,
            iss_base_64: value.iss_base_64,
            jwk_modulus_data: value.jwk_modulus_data,
            jwk_modulus_data_len: value.jwk_modulus_data_len,
            m_security_cards_len: value.m_security_cards_len,
            m_transactions_len: value.m_transactions_len,
            max_cleanup_txns: value.max_cleanup_txns,
            min_value: value.min_value,
            name: value.name,
            owner_pubkey: value.owner_pubkey,
            pub_recovery_key: value.pub_recovery_key,
            root: value.root,
            use_security_card: value.use_security_card,
            zkid: value.zkid,
            jwk_update_key: value.jwk_update_key,
            wasm_hash: value.wasm_hash,
            white_list_of_address: value.white_list_of_address,
        }
    }
}

#[wasm_bindgen]
impl ResultOfGetMultifactorDetails {
    #[wasm_bindgen(getter)]
    pub fn candidate_new_owner_pubkey_and_expiration(&self) -> TCandidateOwnerPubkeyExpirationMap {
        to_value(&self.candidate_new_owner_pubkey_and_expiration)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TCandidateOwnerPubkeyExpirationMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn factors_ordered_by_timestamp(&self) -> TFactorsOrderedByTimestampMap {
        to_value(&self.factors_ordered_by_timestamp)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TFactorsOrderedByTimestampMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_modulus_data(&self) -> TJwkModulusDataMap {
        to_value(&self.jwk_modulus_data)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TJwkModulusDataMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn white_list_of_address(&self) -> TWhiteListOfAddressMap {
        to_value(&self.white_list_of_address)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TWhiteListOfAddressMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn factors_len(&self) -> String {
        self.factors_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn force_remove_oldest(&self) -> bool {
        self.force_remove_oldest
    }

    #[wasm_bindgen(getter)]
    pub fn index_mod_4(&self) -> String {
        self.index_mod_4.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn iss_base_64(&self) -> String {
        self.iss_base_64.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_modulus_data_len(&self) -> String {
        self.jwk_modulus_data_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn m_security_cards_len(&self) -> String {
        self.m_security_cards_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn m_transactions_len(&self) -> String {
        self.m_transactions_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn max_cleanup_txns(&self) -> String {
        self.max_cleanup_txns.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn min_value(&self) -> String {
        self.min_value.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner_pubkey(&self) -> String {
        self.owner_pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pub_recovery_key(&self) -> String {
        self.pub_recovery_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        self.root.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn use_security_card(&self) -> bool {
        self.use_security_card
    }

    #[wasm_bindgen(getter)]
    pub fn zkid(&self) -> String {
        self.zkid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_update_key(&self) -> String {
        self.jwk_update_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wasm_hash(&self) -> String {
        self.wasm_hash.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfCheckNameAvailability {
    is_available: bool,
    multifactor_address: Option<String>,
}

impl From<InnerResultOfCheckNameAvailability> for ResultOfCheckNameAvailability {
    fn from(value: InnerResultOfCheckNameAvailability) -> Self {
        Self { is_available: value.is_available, multifactor_address: value.multifactor_address }
    }
}

#[wasm_bindgen]
impl ResultOfCheckNameAvailability {
    #[wasm_bindgen(getter)]
    pub fn is_available(&self) -> bool {
        self.is_available
    }

    #[wasm_bindgen(getter)]
    pub fn multifactor_address(&self) -> Option<String> {
        self.multifactor_address.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfGetMvMultifactorAddress {
    address: String,
}

impl From<InnerResultOfGetMvMultifactorAddress> for ResultOfGetMvMultifactorAddress {
    fn from(value: InnerResultOfGetMvMultifactorAddress) -> Self {
        Self { address: value.address }
    }
}

#[wasm_bindgen]
impl ResultOfGetMvMultifactorAddress {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultGetMirrorAddress {
    address: String,
}

impl From<InnerResultGetMirrorAddress> for ResultGetMirrorAddress {
    fn from(value: InnerResultGetMirrorAddress) -> Self {
        Self { address: value.address }
    }
}

#[wasm_bindgen]
impl ResultGetMirrorAddress {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfGetEPKExpireAt {
    epk_expire_at: u64,
}

impl From<InnerGetEPKExpireRes> for ResultOfGetEPKExpireAt {
    fn from(value: InnerGetEPKExpireRes) -> Self {
        Self { epk_expire_at: value.epk_expire_at }
    }
}

#[wasm_bindgen]
impl ResultOfGetEPKExpireAt {
    #[wasm_bindgen(getter)]
    pub fn epk_expire_at(&self) -> u64 {
        self.epk_expire_at
    }
}

/// Decoded `Multifactor` contract account state. Mirrors
/// `ackinacki_kit::contracts::mvsystem::multifactor::AccountData`.
#[wasm_bindgen]
#[derive(Clone)]
pub struct MultifactorAccountData {
    candidate_new_owner_pubkey_and_expiration: Option<HashMap<String, String>>,
    factors_len: String,
    factors_ordered_by_timestamp: HashMap<String, String>,
    force_remove_oldest: bool,
    index_mod_4: String,
    iss_base_64: String,
    jwk_modulus_data: HashMap<String, JwkData>,
    jwk_modulus_data_len: String,
    m_security_cards_len: String,
    m_transactions_len: String,
    max_cleanup_txns: String,
    min_value: String,
    name: String,
    owner_pubkey: String,
    pub_recovery_key: String,
    root: String,
    use_security_card: bool,
    zkid: String,
    jwk_update_key: String,
    wasm_hash: String,
    white_list_of_address: HashMap<String, bool>,
}

impl From<InnerMultifactorAccountData> for MultifactorAccountData {
    fn from(value: InnerMultifactorAccountData) -> Self {
        Self {
            candidate_new_owner_pubkey_and_expiration: value
                .candidate_new_owner_pubkey_and_expiration,
            factors_len: value.factors_len,
            factors_ordered_by_timestamp: value.factors_ordered_by_timestamp,
            force_remove_oldest: value.force_remove_oldest,
            index_mod_4: value.index_mod_4,
            iss_base_64: value.iss_base_64,
            jwk_modulus_data: value.jwk_modulus_data,
            jwk_modulus_data_len: value.jwk_modulus_data_len,
            m_security_cards_len: value.m_security_cards_len,
            m_transactions_len: value.m_transactions_len,
            max_cleanup_txns: value.max_cleanup_txns,
            min_value: value.min_value,
            name: value.name,
            owner_pubkey: value.owner_pubkey,
            pub_recovery_key: value.pub_recovery_key,
            root: value.root,
            use_security_card: value.use_security_card,
            zkid: value.zkid,
            jwk_update_key: value.jwk_update_key,
            wasm_hash: value.wasm_hash,
            white_list_of_address: value.white_list_of_address,
        }
    }
}

#[wasm_bindgen]
impl MultifactorAccountData {
    #[wasm_bindgen(getter)]
    pub fn candidate_new_owner_pubkey_and_expiration(&self) -> TCandidateOwnerPubkeyExpirationMap {
        to_value(&self.candidate_new_owner_pubkey_and_expiration)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TCandidateOwnerPubkeyExpirationMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn factors_ordered_by_timestamp(&self) -> TFactorsOrderedByTimestampMap {
        to_value(&self.factors_ordered_by_timestamp)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TFactorsOrderedByTimestampMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_modulus_data(&self) -> TJwkModulusDataMap {
        to_value(&self.jwk_modulus_data)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TJwkModulusDataMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn white_list_of_address(&self) -> TWhiteListOfAddressMap {
        to_value(&self.white_list_of_address)
            .unwrap_or(JsValue::NULL)
            .unchecked_into::<TWhiteListOfAddressMap>()
    }

    #[wasm_bindgen(getter)]
    pub fn factors_len(&self) -> String {
        self.factors_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn force_remove_oldest(&self) -> bool {
        self.force_remove_oldest
    }

    #[wasm_bindgen(getter)]
    pub fn index_mod_4(&self) -> String {
        self.index_mod_4.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn iss_base_64(&self) -> String {
        self.iss_base_64.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_modulus_data_len(&self) -> String {
        self.jwk_modulus_data_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn m_security_cards_len(&self) -> String {
        self.m_security_cards_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn m_transactions_len(&self) -> String {
        self.m_transactions_len.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn max_cleanup_txns(&self) -> String {
        self.max_cleanup_txns.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn min_value(&self) -> String {
        self.min_value.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner_pubkey(&self) -> String {
        self.owner_pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pub_recovery_key(&self) -> String {
        self.pub_recovery_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        self.root.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn use_security_card(&self) -> bool {
        self.use_security_card
    }

    #[wasm_bindgen(getter)]
    pub fn zkid(&self) -> String {
        self.zkid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn jwk_update_key(&self) -> String {
        self.jwk_update_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wasm_hash(&self) -> String {
        self.wasm_hash.clone()
    }
}

#[wasm_bindgen]
pub struct ResultOfGetMultifactorInfo {
    data: Option<MultifactorAccountData>,
}

impl From<InnerResultOfGetMultifactorInfo> for ResultOfGetMultifactorInfo {
    fn from(value: InnerResultOfGetMultifactorInfo) -> Self {
        Self { data: value.data.map(MultifactorAccountData::from) }
    }
}

#[wasm_bindgen]
impl ResultOfGetMultifactorInfo {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Option<MultifactorAccountData> {
        self.data.clone()
    }
}
