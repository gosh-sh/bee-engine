use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::AccountData as MultifactorData;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfCleanWhitelist;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfUpdateWhitelist;
use ackinacki_kit::contracts::mvsystem::ContractIndex;
use ackinacki_kit::tvm_client::abi::Signer;

use crate::infra::poll_until;

const EXPECTED_AFTER_CLEAN: usize = 1;
const WHITELIST_MAX: usize = 15;

#[derive(Debug)]
pub struct ParamsOfUpdateMultifactorWhiteList {
    pub epk_expire_at: u64,
    pub payload_destination: ContractIndex,
    pub target_address: String,
    pub mirror_index: u128,
    pub whitelisted_name: Option<String>,
}

#[derive(Debug)]
pub struct ResultOfUpdateMultifactorWhiteList {
    pub message_ids: Vec<String>,
}

async fn update_multifactor_whitelist(
    multifactor: &Arc<Multifactor>,
    params: ParamsOfUpdateMultifactorWhiteList,
    signer: &Signer,
) -> crate::errors::AppResult<Option<String>> {
    if matches!(params.payload_destination, ContractIndex::PopCoinWallet)
        && params.whitelisted_name.is_none()
    {
        return Err(crate::errors::AppError::new(
            "whitelisted_name should be set in case of destionation is popcoin wallet",
        ));
    }
    let update_white_list_result = multifactor
        .update_whitelist(
            ParamsOfUpdateWhitelist {
                epk_expire_at: params.epk_expire_at,
                payload_destination: params.payload_destination,
                name: params.whitelisted_name.unwrap_or("".to_string()),
                mirror_index: params.mirror_index,
            },
            signer.clone(),
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("Update mutifactor whitelist")
        })?;

    let update_white_list_result =
        crate::infra::ensure_tx_success(update_white_list_result, "update_whitelist")?;

    Ok(update_white_list_result.message_hash)
}

pub async fn update_multifactor_whitelist_and_wait(
    multifactor: &Arc<Multifactor>,
    params: ParamsOfUpdateMultifactorWhiteList,
    signer: &Signer,
) -> crate::errors::AppResult<ResultOfUpdateMultifactorWhiteList> {
    let data = super::query::get_multifactor_decoded_data(multifactor).await?;
    let mut message_ids = Vec::new();

    if data.white_list_of_address.contains_key(&params.target_address) {
        return Ok(ResultOfUpdateMultifactorWhiteList { message_ids });
    }
    let mf = Arc::clone(multifactor);
    if data.white_list_of_address.len() > WHITELIST_MAX {
        let result = multifactor
            .clean_whitelist(
                ParamsOfCleanWhitelist { epk_expire_at: params.epk_expire_at },
                signer.clone(),
            )
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("clean_whitelist"))?;
        let result = crate::infra::ensure_tx_success(result, "clean_whitelist")?;
        if let Some(message_id) = result.message_hash {
            message_ids.push(message_id);
        }
        let _ = poll_until(
            || {
                let mf = mf.clone();
                async move {
                    super::query::get_multifactor_decoded_data(&mf)
                        .await
                        .map_err(|e| e.with_context("Multifactor get details"))
                }
            },
            move |data: &MultifactorData| {
                let white_list = data.white_list_of_address.keys().cloned();
                white_list.len() == EXPECTED_AFTER_CLEAN
            },
            None,
            None,
        )
        .await?;
    }

    let target_address = params.target_address.clone();
    if let Some(message_id) = update_multifactor_whitelist(multifactor, params, signer).await? {
        message_ids.push(message_id);
    }

    let details = poll_until(
        || {
            let mf = mf.clone();
            async move {
                super::query::get_multifactor_decoded_data(&mf)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            }
        },
        move |data: &MultifactorData| {
            let multifactor_whitelist = data.white_list_of_address.keys().collect::<Vec<_>>();

            multifactor_whitelist.contains(&&target_address)
        },
        None,
        None,
    )
    .await?;

    let _ = details;
    Ok(ResultOfUpdateMultifactorWhiteList { message_ids })
}
