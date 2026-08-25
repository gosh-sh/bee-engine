use std::collections::HashMap;
use std::sync::Arc;

use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::delivery::ContractContext;
use ackinacki_kit::contracts::mvsystem::miner::contract::Miner;
use ackinacki_kit::contracts::mvsystem::miner::contract::ParamsOfEncodeRemoveOwnerPublic;
use ackinacki_kit::contracts::mvsystem::miner::contract::ParamsOfEncodeSetOwnerPublic;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSubmitTransaction;
use ackinacki_kit::contracts::mvsystem::ContractIndex;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::abi::Signer;

use crate::services;
use crate::services::multifactor::whitelist::ParamsOfUpdateMultifactorWhiteList;
use crate::services::resolvers::resolve_miner_for_multifactor;
use crate::services::resolvers::resolve_mirror;
use crate::services::resolvers::MirrorSelector;

const TX_VALUE: u128 = 100_000_000;

pub struct ResultOfDeployMiner {
    pub message_ids: Vec<String>,
    pub pending_stage: Option<String>,
    pub pending_reason: Option<String>,
}

pub async fn deploy_miner(
    context: ContractContext,
    multifactor: &Arc<Multifactor>,
    signer: &Signer,
    epk_expire_at: u64,
) -> crate::errors::AppResult<ResultOfDeployMiner> {
    let mirror =
        resolve_mirror(context.clone(), MirrorSelector::ForMultifactorAddr(multifactor.address()))?;

    let miner = resolve_miner_for_multifactor(context, multifactor.address()).await?;
    let miner = Arc::new(miner);

    let whitelist_result = services::multifactor::whitelist::update_multifactor_whitelist_and_wait(
        multifactor,
        ParamsOfUpdateMultifactorWhiteList {
            epk_expire_at,
            payload_destination: ContractIndex::Mirror,
            target_address: mirror.address().to_string(),
            whitelisted_name: None,
            mirror_index: mirror.index() - 1,
        },
        signer,
    )
    .await
    .map_err(|e| e.with_context("miner.deploy_miner: add mirror to whitelist"))?;
    let mut message_ids = whitelist_result.message_ids;
    let deploy_miner_message = mirror.deploy_miner_message().await.map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context("miner.deploy_miner: mirror.deploy_miner_message")
    })?;

    let res = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: mirror.address().to_string(),
                value: TX_VALUE,
                cc: HashMap::new(),
                bounce: true,
                all_balance: false,
                epk_expire_at,
                payload: deploy_miner_message,
            },
            signer.clone(),
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("miner.deploy_miner: multifactor.submit_transaction")
        })?;

    let res = crate::infra::ensure_tx_success(res, "deploy_miner")?;
    if let Some(message_id) = res.message_hash {
        message_ids.push(message_id);
    }
    let wait_miner_result = miner
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::Active,
            attempts: Some(100),
            attempts_timeout: Some(100),
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("miner.deploy_miner: miner.wait_account")
        });

    let (pending_stage, pending_reason) = match wait_miner_result {
        Ok(()) => (None, None),
        Err(err) if crate::infra::is_confirmation_pending_error(&err) => {
            (Some("miner_activation".to_string()), Some(err.message.clone()))
        }
        Err(err) => return Err(err),
    };

    Ok(ResultOfDeployMiner { message_ids, pending_stage, pending_reason })
}

pub async fn set_mining_keys(
    context: ContractContext,
    miner: &Arc<Miner>,
    multifactor: &Arc<Multifactor>,
    mining_pubkey: String,
    epk_expire_at: u64,
    app_id: String,
    signer: &Signer,
) -> crate::errors::AppResult<Vec<String>> {
    let mirror =
        resolve_mirror(context, MirrorSelector::ForMultifactorAddr(multifactor.address()))?;

    let whitelist_result = services::multifactor::whitelist::update_multifactor_whitelist_and_wait(
        multifactor,
        ParamsOfUpdateMultifactorWhiteList {
            epk_expire_at,
            payload_destination: ContractIndex::Miner,
            target_address: miner.address().to_string(),
            whitelisted_name: None,
            mirror_index: mirror.index() - 1,
        },
        signer,
    )
    .await
    .map_err(|e| e.with_context("miner.set_mining_keys: add miner to whitelist"))?;
    let mut message_ids = whitelist_result.message_ids;

    let expected_owner_public = format!("0x{}", mining_pubkey);

    let msg = miner
        .set_owner_public_message(ParamsOfEncodeSetOwnerPublic {
            public: expected_owner_public.clone(),
            app_id: app_id.clone(),
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("miner.set_mining_keys: miner.set_owner_public_message")
        })?;

    let res = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: miner.address().to_string(),
                value: TX_VALUE,
                cc: HashMap::new(),
                bounce: true,
                all_balance: false,
                epk_expire_at,
                payload: msg,
            },
            signer.clone(),
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("miner.set_mining_keys: multifactor.submit_transaction")
        })?;

    let res = crate::infra::ensure_tx_success(res, "set_mining_keys")?;
    if let Some(message_id) = res.message_hash {
        message_ids.push(message_id);
    }

    let miner = miner.clone();
    let app_id_for_wait = app_id.clone();
    let _ = crate::infra::poll_until(
        move || {
            let miner = miner.clone();
            async move {
                miner.get_details().await.map_err(|e| {
                    crate::errors::AppError::from(e)
                        .with_context("miner.set_mining_keys: miner.get_details")
                })
            }
        },
        move |details| {
            details
                .owner_public
                .get(app_id_for_wait.as_str())
                .map(|value| value == &expected_owner_public)
                .unwrap_or(false)
        },
        Some(200),
        Some(250),
    )
    .await
    .map_err(|e| e.with_context("miner.set_mining_keys: wait owner_public set"))?;

    Ok(message_ids)
}

pub async fn del_mining_key(
    context: ContractContext,
    miner: &Arc<Miner>,
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    app_id: String,
    wait: bool,
    signer: &Signer,
) -> crate::errors::AppResult<Vec<String>> {
    let mirror =
        resolve_mirror(context, MirrorSelector::ForMultifactorAddr(multifactor.address()))?;

    let whitelist_result = services::multifactor::whitelist::update_multifactor_whitelist_and_wait(
        multifactor,
        ParamsOfUpdateMultifactorWhiteList {
            epk_expire_at,
            payload_destination: ContractIndex::Miner,
            target_address: miner.address().to_string(),
            whitelisted_name: None,
            mirror_index: mirror.index() - 1,
        },
        signer,
    )
    .await
    .map_err(|e| e.with_context("miner.del_mining_key: add miner to whitelist"))?;
    let mut message_ids = whitelist_result.message_ids;

    let msg = miner
        .remove_owner_public_message(ParamsOfEncodeRemoveOwnerPublic { app_id: app_id.clone() })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("miner.del_mining_key: miner.remove_owner_public_message")
        })?;

    let res = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: miner.address().to_string(),
                value: TX_VALUE,
                cc: HashMap::new(),
                bounce: true,
                all_balance: false,
                epk_expire_at,
                payload: msg,
            },
            signer.clone(),
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("miner.del_mining_key: multifactor.submit_transaction")
        })?;

    let res = crate::infra::ensure_tx_success(res, "del_mining_key")?;
    if let Some(message_id) = res.message_hash {
        message_ids.push(message_id);
    }

    if wait {
        let miner = miner.clone();
        let app_id_for_wait = app_id.clone();
        let _ = crate::infra::poll_until(
            || {
                let miner = miner.clone();
                async move {
                    miner.get_details().await.map_err(|e| {
                        crate::errors::AppError::from(e)
                            .with_context("miner.del_mining_key: miner.get_details")
                    })
                }
            },
            move |details| {
                !details
                    .owner_public
                    .get(app_id_for_wait.as_str())
                    .map(|value| !value.is_empty())
                    .unwrap_or(false)
            },
            None,
            None,
        )
        .await
        .map_err(|e| e.with_context("miner.del_mining_key: wait owner_public removal"))?;
    }

    Ok(message_ids)
}
