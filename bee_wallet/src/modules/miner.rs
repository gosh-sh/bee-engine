use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::abi::Signer;

use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::services;
use crate::services::miner::query::ParamsOfGetMinerDetails;
use crate::services::miner::query::ResultOfGetMinerDetails;

pub(crate) struct MinerModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> MinerModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub async fn get_details_by_multifactor_address(
        &self,
        multifactor_address: String,
    ) -> AppResult<ResultOfGetMinerDetails> {
        self.ctx.acquire().await;
        services::miner::query::get_details_by_multifactor_address(
            self.ctx.tvm_client.clone(),
            ParamsOfGetMinerDetails { multifactor_address },
        )
        .await
    }

    pub async fn get_miner_address(&self, multifactor_address: &str) -> AppResult<String> {
        self.ctx.acquire().await;
        let miner = services::resolvers::resolve_miner_for_multifactor(
            self.ctx.tvm_client.clone(),
            multifactor_address,
        )
        .await?;
        Ok(miner.address().to_string())
    }

    pub async fn set_mining_keys(
        &self,
        params: crate::services::miner::ParamsOfSetMiningKeys,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.ctx.acquire().await;
        let miner = services::resolvers::resolve_miner_for_multifactor(
            self.ctx.tvm_client.clone(),
            &params.multifactor_address,
        )
        .await
        .map_err(|e| e.with_context("Failed to resolve miner for multifactor"))?;

        if !miner.is_deployed().await {
            return Err(crate::errors::AppError::new("Miner is not deployed"));
        }

        let ephemeral_signer = Signer::Keys { keys: params.signer_keys.clone() };
        let multifactor = Multifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        );
        let miner_arc = Arc::new(miner);
        let multifactor_arc = Arc::new(multifactor);

        let epk_expire_at = match params.epk_expire_at {
            Some(v) => v,
            None => {
                multifactor_arc
                    .get_epk_expire_at(ParamsOfGetEpkExpire {
                        epk: format!("0x{}", params.signer_keys.public.clone()),
                    })
                    .await
                    .map_err(|e| {
                        crate::errors::AppError::from(e).with_context("Get EPK expire at")
                    })?
                    .epk_expire_at
            }
        };
        let app_id = if params.app_id.is_empty() { self.ctx.app_id.clone() } else { params.app_id };

        let message_ids = services::miner::cmd::set_mining_keys(
            self.ctx.tvm_client.clone(),
            &miner_arc,
            &multifactor_arc,
            params.mining_pubkey.clone(),
            epk_expire_at,
            app_id,
            &ephemeral_signer,
        )
        .await
        .map_err(|e| e.with_context("Failed to set miner owner pubkey"))?;

        Ok(crate::ResultOfBlockchainWrite { message_ids, ..Default::default() })
    }

    pub async fn del_mining_key(
        &self,
        params: crate::services::miner::ParamsOfDelMiningKey,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.ctx.acquire().await;
        let miner = services::resolvers::resolve_miner_for_multifactor(
            self.ctx.tvm_client.clone(),
            &params.multifactor_address,
        )
        .await
        .map_err(|e| e.with_context("Failed to resolve miner for multifactor"))?;

        if !miner.is_deployed().await {
            return Err(crate::errors::AppError::new("Miner is not deployed"));
        }

        let ephemeral_signer = Signer::Keys { keys: params.signer_keys.clone() };
        let multifactor = Multifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        );
        let miner_arc = Arc::new(miner);
        let multifactor_arc = Arc::new(multifactor);

        let epk_expire_at = match params.epk_expire_at {
            Some(v) => v,
            None => {
                multifactor_arc
                    .get_epk_expire_at(ParamsOfGetEpkExpire {
                        epk: format!("0x{}", params.signer_keys.public.clone()),
                    })
                    .await
                    .map_err(|e| {
                        crate::errors::AppError::from(e).with_context("Get EPK expire at")
                    })?
                    .epk_expire_at
            }
        };
        let app_id = if params.app_id.is_empty() { self.ctx.app_id.clone() } else { params.app_id };

        let message_ids = services::miner::cmd::del_mining_key(
            self.ctx.tvm_client.clone(),
            &miner_arc,
            &multifactor_arc,
            epk_expire_at,
            app_id,
            params.wait,
            &ephemeral_signer,
        )
        .await
        .map_err(|e| e.with_context("Failed to del mining key"))?;

        Ok(crate::ResultOfBlockchainWrite { message_ids, ..Default::default() })
    }
}
