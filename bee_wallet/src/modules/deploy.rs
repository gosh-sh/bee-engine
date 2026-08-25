use std::sync::Arc;

use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetMvMultifactor;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use bee_crypto::Crypto as BeeCrypto;

use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::infra::spawn_bg;
use crate::progress::ProgressEvent;
use crate::progress::ProgressSink;
use crate::services;
use crate::services::boost::ParamsOfUpdateBoost;
use crate::services::deploy::prepare_deploy_params;
pub use crate::services::deploy::ParamsOfDeployMiner;
pub use crate::services::deploy::ParamsOfDeployMultifactor;
pub use crate::services::deploy::ResultOfDeployMultifactor;
use crate::services::resolvers;
use crate::services::resolvers::MirrorSelector;
use crate::services::validate_name::WalletNameError;

pub(crate) struct DeployModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> DeployModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub async fn prepare_multifactor_deploy_params(
        &self,
        params: prepare_deploy_params::ParamsOfPrepareDeploy,
    ) -> AppResult<ackinacki_kit::contracts::mvsystem::mirror::ParamsOfDeployMultifactor> {
        self.ctx.acquire().await;
        let (deploy_params, _wasm_hash) =
            prepare_deploy_params::prepare_multifactor_deploy(self.ctx.tvm_client.clone(), params)
                .await?;
        Ok(deploy_params)
    }

    pub async fn deploy_multifactor(
        &self,
        params: ParamsOfDeployMultifactor,
        should_update_contract_flags: bool,
        progress: Option<ProgressSink>,
    ) -> AppResult<ResultOfDeployMultifactor> {
        self.ctx.acquire().await;
        crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy", "preparing"));

        let result = self
            .run_deploy_multifactor(params, should_update_contract_flags, progress.clone())
            .await;
        if let Ok(ref r) = result {
            emit_deploy_outcome(
                progress.as_ref(),
                "deploy",
                r.pending_stage.as_deref(),
                r.pending_reason.as_deref(),
            );
        }
        crate::progress::report_failure(progress.as_ref(), "deploy", &result, None);
        result
    }

    async fn run_deploy_multifactor(
        &self,
        mut params: ParamsOfDeployMultifactor,
        should_update_contract_flags: bool,
        progress: Option<ProgressSink>,
    ) -> AppResult<ResultOfDeployMultifactor> {
        params.wallet_name = params.wallet_name.trim().to_lowercase();
        services::validate_name::verify_wallet_name(&params.wallet_name).map_err(|err| {
            let details = match err {
                WalletNameError::InvalidCharacters => {
                    "name must contain only lowercase latin letters, digits, '_' or '-'"
                }
                WalletNameError::ConsecutiveHyphens => "name cannot contain consecutive hyphens",
                WalletNameError::ConsecutiveUnderscores => {
                    "name cannot contain consecutive underscores"
                }
                WalletNameError::StartsWithSymbol => "name cannot start with '-' or '_'",
                WalletNameError::TooLong => "name must be at most 39 characters",
                WalletNameError::TooShort => "name must be at least 4 characters",
            };

            crate::errors::AppError::new("Invalid wallet name")
                .with_code("INVALID_WALLET_NAME")
                .with_details(details)
        })?;

        let crypto = BeeCrypto::from_client_context(self.ctx.tvm_client.clone());
        let generated = crypto
            .gen_mnemonic_and_derive_keys(24)
            .map_err(|e| e.with_context("Failed to gen seed"))?;
        let phrase = generated.phrase;
        let owner_keys = KeyPair {
            public: generated.keys.public.clone(),
            secret: generated.keys.secret.clone(),
        };

        let root_contract = MobileVerifiersRoot::new_default(self.ctx.contract_context.clone());
        let multifactor = root_contract
            .get_mv_multifactor(ParamsOfGetMvMultifactor {
                public: format!("0x{}", owner_keys.public.clone()),
            })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("Failed to get multifactor address")
            })?;

        let multifactor_arc = Arc::new(multifactor);
        let (deploy_params, _wasm_hash) = prepare_deploy_params::prepare_multifactor_deploy(
            self.ctx.tvm_client.clone(),
            prepare_deploy_params::ParamsOfPrepareDeploy {
                zkid: params.zkid,
                password: params.password.clone(),
                proof: params.proof,
                epk: params.epk.clone(),
                esk: params.esk.clone(),
                jwk_modulus: params.jwk_modulus,
                jwk_modulus_expire_at: params.jwk_modulus_expire_at,
                index_mod_4: params.index_mod_4,
                iss_base_64: params.iss_base_64,
                header_base_64: params.header_base_64,
                epk_expire_at: params.epk_expire_at,
                keys: owner_keys.clone(),
                kid: params.kid,
                wallet_name: params.wallet_name,
                multifactor_address: multifactor_arc.address().to_string(),
                sub: params.sub,
            },
        )
        .await
        .map_err(|e| e.with_context("Failed to prepare params"))?;

        let deploy_multifactor_mirror = resolvers::resolve_mirror(
            self.ctx.contract_context.clone(),
            MirrorSelector::ForPubkey(&owner_keys.public),
        )
        .map_err(|e| e.with_context("Failed to get mirror"))?;

        crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy", "deploying"));
        let deploy_result = deploy_multifactor_mirror
            .deploy_multifactor(deploy_params.clone(), Signer::Keys { keys: owner_keys.clone() })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Failed to deploy"))?;

        let deploy_result = crate::infra::ensure_tx_success(deploy_result, "deploy multifactor")?;
        crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy", "submitted"));
        #[cfg(not(target_arch = "wasm32"))]
        let password_hash = crypto.hash_password(params.password)?;
        #[cfg(target_arch = "wasm32")]
        let password_hash = crypto.hash_password(params.password).await?;
        let mut pending_stage = None;
        let mut pending_reason = None;

        crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy", "activating"));
        let wait_multifactor_result = multifactor_arc
            .wait_account(ParamsOfWaitAccount {
                status: AccountStatus::Active,
                attempts: Some(255),
                attempts_timeout: Some(200),
            })
            .await;
        if let Err(e) = wait_multifactor_result {
            let err = crate::errors::AppError::from(e).with_context("Wait multifactor active");
            if crate::infra::is_confirmation_pending_error(&err) {
                pending_stage = Some("multifactor_activation".to_string());
                pending_reason = Some(err.message.clone());
            } else {
                return Err(err);
            }
        } else {
            crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy", "active"));
        }
        let mut message_ids = Vec::new();
        if let Some(message_id) = deploy_result.message_hash.clone() {
            message_ids.push(message_id);
        }
        if pending_stage.is_none() && should_update_contract_flags {
            crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy", "configuring"));
            let update_contract_message_ids = crate::modules::multifactor::update_contract_flags(
                multifactor_arc.clone(),
                owner_keys.clone(),
                true,
            )
            .await;
            match update_contract_message_ids {
                Ok(ids) => message_ids.extend(ids),
                Err(err) if crate::infra::is_confirmation_pending_error(&err) => {
                    pending_stage = Some("contract_flags".to_string());
                    pending_reason = Some(err.message.clone());
                }
                Err(err) => return Err(err),
            }
        }

        Ok(ResultOfDeployMultifactor {
            name: deploy_params.name.clone(),
            address: multifactor_arc.address().to_string(),
            message_id: deploy_result.message_hash.clone(),
            message_ids,
            pending_stage,
            pending_reason,
            password_hash,
            phrase,
            pubkey: owner_keys.public.clone(),
            signing_keys: KeyPair { public: params.epk, secret: params.esk },
        })
    }

    pub async fn deploy_miner(
        &self,
        params: ParamsOfDeployMiner,
        progress: Option<ProgressSink>,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.ctx.acquire().await;
        crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy_miner", "resolving"));
        let result = self.run_deploy_miner(params, progress.clone()).await;
        if let Ok(ref r) = result {
            emit_deploy_outcome(
                progress.as_ref(),
                "deploy_miner",
                r.pending_stage.as_deref(),
                r.pending_reason.as_deref(),
            );
        }
        crate::progress::report_failure(progress.as_ref(), "deploy_miner", &result, None);
        result
    }

    async fn run_deploy_miner(
        &self,
        params: ParamsOfDeployMiner,
        progress: Option<ProgressSink>,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        let miner = resolvers::resolve_miner_for_multifactor(
            self.ctx.contract_context.clone(),
            &params.multifactor_address,
        )
        .await
        .map_err(|e| e.with_context("Failed to resolve miner for multifactor"))?;

        if miner.is_deployed().await {
            return Ok(crate::ResultOfBlockchainWrite::default());
        }

        let ephemeral_signer = Signer::Keys { keys: params.signer_keys.clone() };
        let multifactor = Multifactor::new_default(
            self.ctx.contract_context.clone(),
            params.multifactor_address.clone(),
        );
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;
        let multifactor_arc = Arc::new(multifactor);

        crate::progress::emit(progress.as_ref(), ProgressEvent::new("deploy_miner", "deploying"));
        let deploy_miner_result = services::miner::cmd::deploy_miner(
            self.ctx.contract_context.clone(),
            &multifactor_arc,
            &ephemeral_signer,
            epk_expire_at,
        )
        .await
        .map_err(|e| e.with_context("Failed to deploy miner"))?;

        let api_url = self.ctx.api_url.clone();
        spawn_bg(async move {
            let _ = services::boost::update_boost_code(ParamsOfUpdateBoost {
                api_url,
                multifactor_address: multifactor_arc.address().to_string(),
            })
            .await;
        });

        Ok(crate::ResultOfBlockchainWrite {
            message_ids: deploy_miner_result.message_ids,
            pending_stage: deploy_miner_result.pending_stage,
            pending_reason: deploy_miner_result.pending_reason,
        })
    }
}

/// Map a deploy result's pending markers to a terminal progress event:
/// `<op>:pending` (carrying the reason, or the stage as a fallback) when the
/// chain didn't confirm within the allotted wait, otherwise `<op>:confirmed`.
fn emit_deploy_outcome(
    progress: Option<&ProgressSink>,
    op: &str,
    pending_stage: Option<&str>,
    pending_reason: Option<&str>,
) {
    match pending_stage {
        Some(stage) => crate::progress::emit(
            progress,
            ProgressEvent::new(op, "pending")
                .with_detail(pending_reason.unwrap_or(stage).to_string()),
        ),
        None => crate::progress::emit(progress, ProgressEvent::new(op, "confirmed")),
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::emit_deploy_outcome;
    use crate::progress::ProgressEvent;

    #[tokio::test]
    async fn outcome_confirmed_when_not_pending() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        emit_deploy_outcome(Some(&tx), "deploy", None, None);
        drop(tx);
        let events: Vec<ProgressEvent> = rx.collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].op, "deploy");
        assert_eq!(events[0].stage, "confirmed");
    }

    #[tokio::test]
    async fn outcome_pending_carries_reason() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        emit_deploy_outcome(
            Some(&tx),
            "deploy",
            Some("multifactor_activation"),
            Some("still waiting"),
        );
        drop(tx);
        let events: Vec<ProgressEvent> = rx.collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].stage, "pending");
        assert_eq!(events[0].detail.as_deref(), Some("still waiting"));
    }

    #[tokio::test]
    async fn outcome_pending_falls_back_to_stage_when_no_reason() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        emit_deploy_outcome(Some(&tx), "deploy_miner", Some("contract_flags"), None);
        drop(tx);
        let events: Vec<ProgressEvent> = rx.collect().await;
        assert_eq!(events[0].op, "deploy_miner");
        assert_eq!(events[0].stage, "pending");
        assert_eq!(events[0].detail.as_deref(), Some("contract_flags"));
    }
}
