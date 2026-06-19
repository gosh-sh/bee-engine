use std::collections::HashMap;
use std::sync::Arc;

use ackinacki_kit::contracts::error::KitErrorCode;
use ackinacki_kit::contracts::mvsystem::multifactor::AccountData as MultifactorData;
use ackinacki_kit::contracts::mvsystem::multifactor::JwkData;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor as MvMultifactor;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetIndexer;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::DecodeAccountData;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use ackinacki_kit::tvm_client::ClientContext;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfGetMultifactorDetails {
    pub address: String,
    pub candidate_new_owner_pubkey_and_expiration: Option<HashMap<String, String>>,
    pub factors_len: String,
    pub factors_ordered_by_timestamp: HashMap<String, String>,
    pub force_remove_oldest: bool,
    pub index_mod_4: String,
    pub iss_base_64: String,
    pub jwk_modulus_data: HashMap<String, JwkData>,
    pub jwk_modulus_data_len: String,
    pub m_security_cards_len: String,
    pub m_transactions_len: String,
    pub max_cleanup_txns: String,
    pub min_value: String,
    pub name: String,
    pub owner_pubkey: String,
    pub pub_recovery_key: String,
    pub root: String,
    pub use_security_card: bool,
    pub zkid: String,
    pub jwk_update_key: String,
    pub wasm_hash: String,
    pub white_list_of_address: HashMap<String, bool>,
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfGetMultifactorDataByName {
    pub wallet_name: String,
}

pub async fn get_multifactor_decoded_data_by_name(
    tvm_client: Arc<ClientContext>,
    params: ParamsOfGetMultifactorDataByName,
) -> crate::errors::AppResult<Option<ResultOfGetMultifactorDetails>> {
    let root_contract = MobileVerifiersRoot::new_default(tvm_client.clone());
    let indexer =
        root_contract.get_indexer(ParamsOfGetIndexer { name: params.wallet_name }).await.map_err(
            |e| crate::errors::AppError::from(e).with_context("failed to get_indexer_address"),
        )?;

    let indexer_details = indexer.get_details().await.map_err(|e| {
        crate::errors::AppError::from(e).with_context("failed to get_indexer_details")
    })?;

    let multifactor_contract =
        MvMultifactor::new_default(tvm_client.clone(), indexer_details.multifactor_address.clone());
    let multifactor = Arc::new(multifactor_contract);

    let acc_data = get_multifactor_decoded_data(&multifactor)
        .await
        .map_err(|e| e.with_context("failed to get decoded data"))?;

    let res = ResultOfGetMultifactorDetails {
        address: indexer_details.multifactor_address,
        candidate_new_owner_pubkey_and_expiration: acc_data
            .candidate_new_owner_pubkey_and_expiration,
        factors_len: acc_data.factors_len,
        factors_ordered_by_timestamp: acc_data.factors_ordered_by_timestamp,
        force_remove_oldest: acc_data.force_remove_oldest,
        index_mod_4: acc_data.index_mod_4,
        iss_base_64: acc_data.iss_base_64,
        jwk_modulus_data: acc_data.jwk_modulus_data,
        jwk_modulus_data_len: acc_data.jwk_modulus_data_len,
        m_security_cards_len: acc_data.m_security_cards_len,
        m_transactions_len: acc_data.m_transactions_len,
        max_cleanup_txns: acc_data.max_cleanup_txns,
        min_value: acc_data.min_value,
        name: acc_data.name,
        owner_pubkey: acc_data.owner_pubkey,
        pub_recovery_key: acc_data.pub_recovery_key,
        root: acc_data.root,
        use_security_card: acc_data.use_security_card,
        zkid: acc_data.zkid,
        jwk_update_key: acc_data.jwk_update_key,
        wasm_hash: acc_data.wasm_hash,
        white_list_of_address: acc_data.white_list_of_address,
    };

    Ok(Some(res))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfCheckNameAvailability {
    pub is_available: bool,
    pub multifactor_address: Option<String>,
}

pub async fn check_name_availability(
    tvm_client: Arc<ClientContext>,
    wallet_name: String,
) -> crate::errors::AppResult<ResultOfCheckNameAvailability> {
    let root_contract = MobileVerifiersRoot::new_default(tvm_client.clone());
    let indexer =
        root_contract.get_indexer(ParamsOfGetIndexer { name: wallet_name }).await.map_err(|e| {
            crate::errors::AppError::from(e).with_context("failed to get_indexer_address")
        })?;

    let details = match indexer.get_details().await {
        Ok(details) => Ok(Some(details)),
        Err(e) => {
            if e.code == KitErrorCode::AccountIsNotActive {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
    .map_err(|e| crate::errors::AppError::from(e).with_context("failed to get_indexer_details"))?;

    Ok(ResultOfCheckNameAvailability {
        is_available: details.is_none(),
        multifactor_address: details.map(|d| d.multifactor_address),
    })
}

pub async fn get_multifactor_decoded_data(
    multifactor: &Arc<MvMultifactor>,
) -> crate::errors::AppResult<MultifactorData> {
    if !multifactor.is_deployed().await {
        return Err(crate::errors::AppError::new(format!(
            "account {} is not deployed",
            multifactor.address()
        )));
    }

    let Some(data) = multifactor.async_guarded(|acc| acc.data.clone()).await else {
        return Err(crate::errors::AppError::new(format!(
            "account data {} not found",
            multifactor.address()
        )));
    };

    multifactor.decode_account_data(data).map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context(format!("failed to decode account data for {}", multifactor.address()))
    })
}
