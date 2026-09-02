use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor as MvMultifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfDeleteZKPFactorByItself;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetIndexer;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::DecodeAccountData;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;
use bee_crypto::Crypto as BeeCrypto;

use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::infra::now_secs;
use crate::infra::poll_until_rated;
use crate::progress::ProgressEvent;
use crate::progress::ProgressSink;
use crate::services;
use crate::services::multifactor::cmd::AddZkpFactorReq;
use crate::services::multifactor::jwk::AddJwkModulusReq;
use crate::services::multifactor::query::get_multifactor_decoded_data;
pub use crate::services::zkp::ParamsOfAddZKPFactor;
pub use crate::services::zkp::ResultOfAddZKPFactor;
pub use crate::services::zkp::ZkLoginCompleteWithProverParams;
pub use crate::services::zkp::ZkLoginCompleteWithProverResult;
pub use crate::services::zkp::ZkLoginPrepareResult;
use crate::DeleteZkpFactorByItselfReq;

pub(crate) struct ZkpModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> ZkpModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub fn prepare_zk_login_v1_with_now_ms(&self, now_ms: u64) -> AppResult<ZkLoginPrepareResult> {
        services::zkp::client_login_prepare::prepare_zk_login_with_now_ms(now_ms)
    }

    pub async fn complete_zk_login_with_prover_v1(
        &self,
        params: ZkLoginCompleteWithProverParams,
        progress: Option<ProgressSink>,
    ) -> AppResult<ZkLoginCompleteWithProverResult> {
        self.ctx.acquire().await;
        services::zkp::client_login_complete::zk_login_complete_with_prover(params, progress).await
    }

    pub async fn add_zkp_factor(
        &self,
        params: ParamsOfAddZKPFactor,
        progress: Option<ProgressSink>,
    ) -> AppResult<ResultOfAddZKPFactor> {
        self.ctx.acquire().await;
        // Several on-chain reads (indexer → details → account data) run before
        // the first write; mark the start so the UI isn't blank during them.
        crate::progress::emit(progress.as_ref(), ProgressEvent::new("add_factor", "resolving"));

        let result = self.run_add_zkp_factor(params, progress.clone()).await;
        // Report a terminal failure into the stream too (not just the rejected
        // promise). `timed_out` is already emitted by the confirm phase, so
        // suppress it here to avoid double-reporting.
        crate::progress::report_failure(
            progress.as_ref(),
            "add_factor",
            &result,
            Some("add_factor_timeout"),
        );
        result
    }

    async fn run_add_zkp_factor(
        &self,
        params: ParamsOfAddZKPFactor,
        progress: Option<ProgressSink>,
    ) -> AppResult<ResultOfAddZKPFactor> {
        let mut message_ids = Vec::new();
        let crypto = BeeCrypto::from_client_context(self.ctx.tvm_client.clone());
        let root_contract = MobileVerifiersRoot::new_default(self.ctx.contract_context.clone());
        let indexer = root_contract
            .get_indexer(ParamsOfGetIndexer { name: params.wallet_name.clone() })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("failed to get_indexer_address")
            })?;

        let indexer_details = indexer.get_details().await.map_err(|e| {
            crate::errors::AppError::from(e).with_context("failed to get_indexer_details")
        })?;

        let multifactor_contract = MvMultifactor::new_default(
            self.ctx.contract_context.clone(),
            indexer_details.multifactor_address.clone(),
        );
        let multifactor = Arc::new(multifactor_contract);

        if !multifactor.is_deployed().await {
            return Err(crate::errors::AppError::new("contract is not deployed"));
        }
        let Some(data) = multifactor.async_guarded(|acc| acc.data.clone()).await else {
            return Err(crate::errors::AppError::new("failed to multifactor data"));
        };

        let acc_data = multifactor.decode_account_data(data).map_err(|e| {
            crate::errors::AppError::from(e).with_context("failed to decode_account_data")
        })?;

        if params.zkid != acc_data.zkid {
            return Err(crate::errors::AppError::new("Bad password or social account provided"));
        }

        let hashed_kid = crypto
            .get_boc_hash(params.kid.clone())
            .map_err(|e| e.with_context("failed to hashed kid"))?;
        let existing_jwk_key = format!("0x{}", hashed_kid.clone());
        let existing_jwk = acc_data.jwk_modulus_data.get(&existing_jwk_key);

        let now = now_secs();
        let min_life = 300;
        let now_plus_life = now + min_life + 1;
        let new_ok = params.jwk_expires_at > now_plus_life;
        let should_add_jwk_modulus = match existing_jwk {
            Some(jwk) => {
                let old = jwk.modulus_expire_at.parse::<u64>().unwrap_or(0);
                let old_expires_soon = old < now_plus_life;
                new_ok && old_expires_soon && params.jwk_expires_at > old
            }
            None => new_ok,
        };

        if should_add_jwk_modulus {
            // Extra on-chain step before the factor itself — tell the UI so the
            // bar doesn't look frozen during the JWK modulus round-trip.
            crate::progress::emit(
                progress.as_ref(),
                ProgressEvent::new("add_factor", "jwk").with_detail("adding json web key modulus"),
            );
            let add_jwk_result = services::multifactor::jwk::add_jwk_modulus(
                self.ctx.tvm_client.clone(),
                &multifactor,
                &acc_data,
                AddJwkModulusReq {
                    kid: params.kid.clone(),
                    password: params.password.clone(),
                    sub: params.sub.clone(),
                    kid_boc_hash: hashed_kid,
                },
            )
            .await
            .map_err(|e| e.with_context("Failed to add jwk modulus"))?;
            if let Some(message_id) = add_jwk_result {
                message_ids.push(message_id);
            }
            crate::progress::emit(
                progress.as_ref(),
                ProgressEvent::new("add_factor", "jwk_confirmed"),
            );
        }

        let add_zkp_result = services::multifactor::cmd::add_zkp_factor(
            &multifactor,
            &acc_data,
            AddZkpFactorReq {
                kid: params.kid.clone(),
                header_base_64: params.header_base_64.clone(),
                proof: params.proof.clone(),
                epk_expire_at: params.epk_expire_at as i64,
                epk: params.epk.clone(),
                esk: params.esk.clone(),
            },
            progress,
        )
        .await
        .map_err(|e| e.with_context("Failed to add jwk modulus"))?;
        if let Some(message_id) = add_zkp_result.message_id.clone() {
            message_ids.push(message_id);
        }

        #[cfg(not(target_arch = "wasm32"))]
        let password_hash = crypto.hash_password(params.password)?;
        #[cfg(target_arch = "wasm32")]
        let password_hash = crypto.hash_password(params.password).await?;

        Ok(ResultOfAddZKPFactor {
            name: params.wallet_name.clone(),
            address: multifactor.address().to_string(),
            message_id: add_zkp_result.message_id,
            message_ids,
            password_hash,
            pubkey: acc_data.owner_pubkey.clone(),
            signing_keys: KeyPair { public: params.epk, secret: params.esk },
        })
    }

    pub async fn delete_zkp_factor_by_itself(
        &self,
        params: DeleteZkpFactorByItselfReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.ctx.acquire().await;
        let contract_raw = MvMultifactor::new_default(
            self.ctx.contract_context.clone(),
            params.multifactor_address.clone(),
        );
        let contract = Arc::new(contract_raw);
        let epk_expire_at = contract
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let multifactor_data = get_multifactor_decoded_data(&contract).await?;

        let current_factors_length = multifactor_data.factors_len.parse().unwrap_or(0);
        let result = contract
            .delete_zkp_factor_by_itself(
                ParamsOfDeleteZKPFactorByItself { epk_expire_at },
                Signer::Keys { keys: params.signer_keys.clone() },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("delete_zkp_factor_by_itself")
            })?;

        let result = crate::infra::ensure_tx_success(result, "delete_zkp_factor_by_itself")?;

        poll_until_rated(
            self.ctx.rate_limiter.as_ref(),
            || async {
                services::multifactor::query::get_multifactor_decoded_data(&contract)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            },
            move |data: &ackinacki_kit::contracts::mvsystem::multifactor::AccountData| {
                let new_factors_length = data.factors_len.parse().unwrap_or(0);
                new_factors_length == current_factors_length - 1
            },
            None,
            None,
        )
        .await?;

        Ok(result)
    }
}
