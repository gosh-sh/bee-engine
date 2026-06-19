use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor as MvMultifactor;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetMvMultifactor;
use ackinacki_kit::contracts::mvsystem::root::ResultOfGetMvMultifactorAddress;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::DecodeAccountData;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use bee_crypto::Crypto as BeeCrypto;

use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::services;
use crate::services::multifactor::cmd::ParamsOfChangeSeedPhrase;
use crate::services::multifactor::query::ResultOfCheckNameAvailability;
use crate::services::multifactor::query::ResultOfGetMultifactorDetails;
use crate::services::resolvers::resolve_mirror;
use crate::services::resolvers::MirrorSelector;
use crate::types::ParamsGetMirrorAddress;
use crate::types::ParamsOfGetMultifactorAddress;
use crate::types::ParamsOfGetMultifactorInfo;
use crate::types::ResultGetMirrorAddress;
use crate::types::ResultOfGetMultifactorInfo;

pub(crate) struct MultifactorModule<'a> {
    ctx: &'a WalletContext,
}

fn is_retryable_check_name_availability_error(err: &crate::errors::AppError) -> bool {
    let is_account_get_error =
        err.module.as_deref() == Some("account") && err.error_code.as_deref() == Some("205");
    if !is_account_get_error {
        return false;
    }

    let has_transient_network_hint = |s: &str| {
        s.contains("connection reset by peer")
            || s.contains("dns error")
            || s.contains("failed to lookup address information")
            || s.contains("client error (SendRequest)")
            || s.contains("client error (Connect)")
            || s.contains("timed out")
            || s.contains("timeout")
    };

    has_transient_network_hint(&err.message)
        || err.details.as_deref().is_some_and(has_transient_network_hint)
}

impl<'a> MultifactorModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub async fn check_name_availability(
        &self,
        wallet_name: String,
    ) -> AppResult<ResultOfCheckNameAvailability> {
        self.ctx.acquire().await;
        let tvm_client = self.ctx.tvm_client.clone();
        crate::infra::with_retry(
            || {
                let tvm_client = tvm_client.clone();
                let wallet_name = wallet_name.clone();
                async move {
                    services::multifactor::query::check_name_availability(tvm_client, wallet_name)
                        .await
                }
            },
            3,
            1_000,
            Some(
                is_retryable_check_name_availability_error as fn(&crate::errors::AppError) -> bool,
            ),
        )
        .await
    }

    pub async fn get_multifactor_data_by_name(
        &self,
        wallet_name: String,
    ) -> AppResult<Option<ResultOfGetMultifactorDetails>> {
        self.ctx.acquire().await;
        services::multifactor::query::get_multifactor_decoded_data_by_name(
            self.ctx.tvm_client.clone(),
            services::multifactor::query::ParamsOfGetMultifactorDataByName { wallet_name },
        )
        .await
    }

    pub async fn change_seed_phrase(
        &self,
        params: ParamsOfChangeSeedPhrase,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.ctx.acquire().await;
        let multifactor_contract = MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        );
        let multifactor = Arc::new(multifactor_contract);
        let epk_expire_at = multifactor
            .get_epk_expire_at(
                ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire {
                    epk: format!("0x{}", params.signer_keys.public.clone()),
                },
            )
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;
        let result = services::multifactor::cmd::change_seed_phrase(
            self.ctx.tvm_client.clone(),
            &multifactor,
            epk_expire_at,
            params,
        )
        .await?;
        Ok(crate::ResultOfBlockchainWrite { message_ids: result.message_ids, ..Default::default() })
    }

    pub async fn get_multifactor_address(
        &self,
        params: ParamsOfGetMultifactorAddress,
    ) -> AppResult<ResultOfGetMvMultifactorAddress> {
        self.ctx.acquire().await;
        let contract = MobileVerifiersRoot::new_default(self.ctx.tvm_client.clone());
        let result = contract
            .get_mv_multifactor(ParamsOfGetMvMultifactor { public: params.pubkey })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("failed to get_multifactor_address")
            })?;

        Ok(ResultOfGetMvMultifactorAddress { address: result.address().to_string() })
    }

    pub fn get_mirror_address(
        &self,
        params: ParamsGetMirrorAddress,
    ) -> AppResult<ResultGetMirrorAddress> {
        let mirror =
            resolve_mirror(self.ctx.tvm_client.clone(), MirrorSelector::ForPubkey(&params.pubkey))
                .map_err(|e| e.with_context("Get mirror"))?;
        Ok(ResultGetMirrorAddress { address: mirror.address().to_string() })
    }

    pub async fn get_multifactor_info(
        &self,
        params: ParamsOfGetMultifactorInfo,
    ) -> AppResult<ResultOfGetMultifactorInfo> {
        self.ctx.acquire().await;
        let contract =
            MvMultifactor::new_default(self.ctx.tvm_client.clone(), params.address.clone());

        if !contract.is_deployed().await {
            return Ok(ResultOfGetMultifactorInfo { data: None });
        }
        let Some(data) = contract.async_guarded(|acc| acc.data.clone()).await else {
            return Ok(ResultOfGetMultifactorInfo { data: None });
        };
        let acc_data = contract.decode_account_data(data).map_err(|e| {
            crate::errors::AppError::from(e).with_context("failed to decode_account_data")
        })?;

        Ok(ResultOfGetMultifactorInfo { data: Some(acc_data) })
    }

    pub async fn get_epk_expire_at(
        &self,
        params: crate::types::GetEPKExpireReq,
    ) -> AppResult<crate::types::GetEPKExpireRes> {
        self.ctx.acquire().await;
        let multifactor = MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        );
        let epk_expire_at = multifactor
            .get_epk_expire_at(
                ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire {
                    epk: format!("0x{}", params.epk),
                },
            )
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;
        Ok(crate::types::GetEPKExpireRes { epk_expire_at })
    }

    pub async fn update_zk_id(
        &self,
        params: crate::UpdateMultifactorZkIdReq,
    ) -> AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
        self.ctx.acquire().await;
        use ackinacki_kit::contracts::mvsystem::multifactor::AccountData;
        use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfUpdateRecoveryPhrase;
        use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfUpdateZkId;
        use ackinacki_kit::tvm_client::abi::Signer;
        use ackinacki_kit::tvm_client::crypto::KeyPair;
        use gosh_tls_lib::tls_connect::get_root_certs_map;

        use crate::infra::poll_until_rated;
        use crate::services::multifactor::key_derivation::build_recovery_keys;
        use crate::services::multifactor::key_derivation::build_update_jwk_keys;
        use crate::services::multifactor::key_derivation::ParamsOfBuildRecoveryKeys;
        use crate::services::multifactor::key_derivation::ParamsOfBuildUpdateJwkKeys;
        use crate::services::zkp::auth::get_auth_provider;
        use crate::services::zkp::auth::get_domain_by_auth_provider;
        use crate::services::zkp::auth::Claim;

        let provider = get_auth_provider(Claim {
            value: params.iss_base_64.clone(),
            index_mod_4: params.index_mod_4 as u8,
        })?;
        let domain = get_domain_by_auth_provider(&provider)?;
        let root_provider_certificates = get_root_certs_map(&domain).map_err(|e| {
            crate::errors::AppError::from(e).with_context("failed to get root certificates")
        })?;

        let update_jwk_keys = build_update_jwk_keys(
            self.ctx.tvm_client.clone(),
            ParamsOfBuildUpdateJwkKeys {
                password: params.password.clone(),
                sub: params.sub.clone(),
            },
        )
        .await?;
        let crypto = BeeCrypto::from_client_context(self.ctx.tvm_client.clone());
        let epk_sig = crypto.sign_detached_hex(params.epk.clone(), params.esk)?;
        let update_params = ParamsOfUpdateZkId {
            zkid: params.zkid.clone(),
            proof: params.proof,
            epk: format!("0x{}", params.epk),
            epk_sig,
            epk_expire_at: params.epk_expire_at,
            jwk_modulus: params.jwk_modulus,
            kid: params.kid,
            jwk_modulus_expire_at: params.jwk_modulus_expire_at,
            index_mod_4: params.index_mod_4,
            iss_base_64: params.iss_base_64,
            header_base_64: params.header_base_64,
            owner_pubkey: format!("0x{}", params.pubkey),
            root_provider_certificates,
            provider: provider.to_string(),
            jwk_update_key: update_jwk_keys.pub_jwk_update_key.clone(),
            jwk_update_key_sig: update_jwk_keys.pub_jwk_update_sig.clone(),
        };
        let recovery_keys = build_recovery_keys(
            self.ctx.tvm_client.clone(),
            ParamsOfBuildRecoveryKeys {
                password: params.password.clone(),
                multifactor_address: params.address.clone(),
            },
        )
        .await?;

        let contract_raw =
            MvMultifactor::new_default(self.ctx.tvm_client.clone(), params.address.clone());
        let contract = Arc::new(contract_raw);

        let update_zk_id_result = contract
            .update_zk_id(
                update_params,
                Signer::Keys {
                    keys: KeyPair {
                        public: params.pubkey.clone(),
                        secret: params.secretkey.clone(),
                    },
                },
            )
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("update_zk_id failed"))?;

        let update_zk_id_result =
            crate::infra::ensure_tx_success(update_zk_id_result, "update_zk_id")?;

        poll_until_rated(
            self.ctx.rate_limiter.as_ref(),
            || async {
                services::multifactor::query::get_multifactor_decoded_data(&contract)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            },
            move |data: &AccountData| params.zkid == data.zkid,
            None,
            None,
        )
        .await?;

        let update_recovery_phrase_result = contract
            .update_recovery_phrase(
                ParamsOfUpdateRecoveryPhrase {
                    new_pub_recovery_key: recovery_keys.pub_recovery_key.clone(),
                    new_pub_recovery_key_sig: recovery_keys.pub_recovery_key_sig,
                },
                Signer::Keys {
                    keys: KeyPair {
                        public: params.pubkey.clone(),
                        secret: params.secretkey.clone(),
                    },
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("update_recovery_phrase failed")
            })?;

        let _update_recovery_phrase_result = crate::infra::ensure_tx_success(
            update_recovery_phrase_result,
            "update_recovery_phrase",
        )?;

        poll_until_rated(
            self.ctx.rate_limiter.as_ref(),
            || async {
                services::multifactor::query::get_multifactor_decoded_data(&contract)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            },
            move |data: &AccountData| recovery_keys.pub_recovery_key == data.pub_recovery_key,
            None,
            None,
        )
        .await?;

        Ok(update_zk_id_result)
    }

    pub async fn update_contract(
        &self,
        params: crate::ParamsOfUpdateContract,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.ctx.acquire().await;
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let message_ids = update_contract_flags(multifactor, params.keys, true).await?;
        Ok(crate::ResultOfBlockchainWrite { message_ids, ..Default::default() })
    }
}

/// Ensure multifactor contract flags (`force_remove_oldest`, `wasm_hash`) are
/// up to date.
///
/// When `wait == true`, polls until changes are confirmed on-chain.
/// When `wait == false`, sends messages and returns immediately
/// (fire-and-forget).
pub(crate) async fn update_contract_flags(
    multifactor: Arc<MvMultifactor>,
    keys: ackinacki_kit::tvm_client::crypto::KeyPair,
    wait: bool,
) -> AppResult<Vec<String>> {
    use crate::services::multifactor::cmd::set_remove_oldest;
    use crate::services::multifactor::cmd::set_wasm_hash;
    use crate::services::multifactor::query::get_multifactor_decoded_data;
    use crate::services::multifactor::WASM_HASH;

    let current_data = get_multifactor_decoded_data(&multifactor).await?;

    let need_remove_oldest = !current_data.force_remove_oldest;
    let need_wasm_hash = current_data.wasm_hash != WASM_HASH;

    if !need_remove_oldest && !need_wasm_hash {
        return Ok(Vec::new());
    }

    let mut message_ids = Vec::new();

    if need_remove_oldest {
        let mf = multifactor.clone();
        let k = keys.clone();
        let message_id = crate::infra::with_retry(
            move || {
                let mf = mf.clone();
                let k = k.clone();
                async move { set_remove_oldest(&mf, k, true).await }
            },
            3,
            3000,
            None::<fn(&crate::errors::AppError) -> bool>,
        )
        .await
        .map_err(|e| e.with_context("Set force to remove oldest failure"))?;
        if let Some(id) = message_id {
            message_ids.push(id);
        }
    }

    if need_wasm_hash {
        let mf = multifactor.clone();
        let k = keys.clone();
        let message_id = crate::infra::with_retry(
            move || {
                let mf = mf.clone();
                let k = k.clone();
                async move { set_wasm_hash(&mf, k, WASM_HASH).await }
            },
            3,
            3000,
            None::<fn(&crate::errors::AppError) -> bool>,
        )
        .await
        .map_err(|e| e.with_context("Set wasm hash failure"))?;
        if let Some(id) = message_id {
            message_ids.push(id);
        }
    }

    if wait {
        use crate::infra::poll_until;

        let expected_hash = WASM_HASH.to_string();
        poll_until(
            || async {
                get_multifactor_decoded_data(&multifactor)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            },
            move |data| {
                (!need_remove_oldest || data.force_remove_oldest)
                    && (!need_wasm_hash || data.wasm_hash == expected_hash)
            },
            None,
            None,
        )
        .await?;
    }

    Ok(message_ids)
}
