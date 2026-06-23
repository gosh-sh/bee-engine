use serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::client::WalletClient;
use crate::client::WalletConfig;
use crate::services::balance::ParamsOfGetNativeBalances;
use crate::services::balance::ParamsOfGetTokensBalances;
use crate::services::connect::ParamsOfQuerySessionMessages;
use crate::services::deploy::ParamsOfDeployMiner;
use crate::services::deploy::ParamsOfDeployMultifactor;
use crate::services::deploy::ParamsOfPrepareDeploy;
use crate::services::miner::ParamsOfDelMiningKey;
use crate::services::miner::ParamsOfSetMiningKeys;
use crate::services::multifactor::cmd::ParamsOfChangeSeedPhrase;
use crate::services::transaction::history::ParamsOfGetHistory;
use crate::services::zkp::ParamsOfAddZKPFactor;
use crate::services::zkp::ZkLoginCompleteWithProverParams;
use crate::DeleteZkpFactorByItselfReq;
use crate::GetEPKExpireReq;
use crate::ParamsGetMirrorAddress;
use crate::ParamsOfGetMultifactorAddress;
use crate::ParamsOfGetMultifactorInfo;
use crate::UpdateMultifactorZkIdReq;

mod dto;

/// Drains progress events on the wasm event loop and forwards each one to the
/// JS callback as a plain object (`{ op, stage, detail?, pct? }`). The loop
/// ends when the operation drops its sender, so it needs no explicit cleanup.
fn spawn_progress_forwarder(
    mut rx: futures::channel::mpsc::UnboundedReceiver<crate::ProgressEvent>,
    on_progress: js_sys::Function,
) {
    use futures::StreamExt;
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(event) = rx.next().await {
            if let Ok(js) = serde_wasm_bindgen::to_value(&event) {
                let _ = on_progress.call1(&JsValue::NULL, &js);
            }
        }
    });
}

#[wasm_bindgen]
pub struct Wallet {
    inner: WalletClient,
}

#[wasm_bindgen]
impl Wallet {
    #[wasm_bindgen(constructor)]
    pub fn new(
        endpoints: Vec<String>,
        archive_endpoints: Option<Vec<String>>,
        api_url: String,
        app_id: String,
        api_token: Option<String>,
        max_rps: Option<u32>,
    ) -> Result<Self, JsError> {
        let inner = WalletClient::new(WalletConfig {
            endpoints,
            archive_endpoints,
            api_url,
            app_id,
            api_token,
            max_rps,
        })
        .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = validate_name)]
    pub fn validate_name(
        &self,
        wallet_name: String,
    ) -> Result<dto::names::ResultOfValidateWalletName, JsError> {
        let x = self.inner.names().validate_name(wallet_name);
        Ok(dto::names::ResultOfValidateWalletName::from(x))
    }

    #[wasm_bindgen(js_name = check_name_availability)]
    pub async fn check_name_availability(
        &self,
        wallet_name: String,
    ) -> Result<dto::multifactor::ResultOfCheckNameAvailability, JsError> {
        let res = self
            .inner
            .multifactor()
            .check_name_availability(wallet_name)
            .await
            .map_err(|e| JsError::new(&format!("Failed to check name availability: {e:?}")))?;

        Ok(dto::multifactor::ResultOfCheckNameAvailability::from(res))
    }

    #[wasm_bindgen(js_name = get_multifactor_data_by_name)]
    pub async fn get_multifactor_data_by_name(
        &self,
        wallet_name: String,
    ) -> Result<Option<dto::multifactor::ResultOfGetMultifactorDetails>, JsError> {
        let res = self
            .inner
            .multifactor()
            .get_multifactor_data_by_name(wallet_name)
            .await
            .map_err(|e| JsError::new(&format!("Failed to get multifacotr data: {e:?}")))?;

        match res {
            Some(v) => Ok(Some(dto::multifactor::ResultOfGetMultifactorDetails::from(v))),
            None => Ok(None),
        }
    }

    #[wasm_bindgen(js_name = add_zkp_factor)]
    pub async fn add_zkp_factor(
        &self,
        params_js: dto::TParamsOfAddZKPFactor,
    ) -> Result<dto::zkp::ResultOfAddZKPFactor, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfAddZKPFactor = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfAddZKPFactor: {e:?}")))?;
        let res = self
            .inner
            .zkp()
            .add_zkp_factor(params, None)
            .await
            .map_err(|e| JsError::new(&format!("failed to add zk factor: {e:?}")))?;

        Ok(dto::zkp::ResultOfAddZKPFactor::from(res))
    }

    /// Like [`add_zkp_factor`], but invokes `on_progress(event)` for each
    /// `add_factor` milestone (`jwk?` → `submitted` → `confirming`… →
    /// `confirmed`), where `event` is a plain object `{ op, stage, detail?,
    /// pct? }`. On confirmation timeout the call rejects with a terminal error.
    #[wasm_bindgen(js_name = add_zkp_factor_with_progress)]
    pub async fn add_zkp_factor_with_progress(
        &self,
        params_js: dto::TParamsOfAddZKPFactor,
        on_progress: js_sys::Function,
    ) -> Result<dto::zkp::ResultOfAddZKPFactor, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfAddZKPFactor = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfAddZKPFactor: {e:?}")))?;

        let (tx, rx) = futures::channel::mpsc::unbounded::<crate::ProgressEvent>();
        spawn_progress_forwarder(rx, on_progress);

        let res = self
            .inner
            .zkp()
            .add_zkp_factor(params, Some(tx))
            .await
            .map_err(|e| JsError::new(&format!("failed to add zk factor: {e:?}")))?;

        Ok(dto::zkp::ResultOfAddZKPFactor::from(res))
    }

    #[wasm_bindgen(js_name = change_seed_phrase)]
    pub async fn change_seed_phrase(
        &self,
        params_js: dto::TParamsOfChangeSeedPhrase,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfChangeSeedPhrase = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfChangeSeedPhrase: {e:?}")))?;
        let res = self
            .inner
            .multifactor()
            .change_seed_phrase(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to change seed phrase: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(res))
    }

    #[wasm_bindgen(js_name = decode_connect_payload_b64url)]
    pub fn decode_connect_payload_b64url(&self, payload_b64: String) -> Result<JsValue, JsError> {
        let payload = self
            .inner
            .connect()
            .decode_connect_payload_b64url(payload_b64)
            .map_err(|e| JsError::new(&format!("failed to decode connect payload: {e:?}")))?;
        serde_wasm_bindgen::to_value(&payload)
            .map_err(|e| JsError::new(&format!("failed to serialize connect payload: {e:?}")))
    }

    #[wasm_bindgen(js_name = query_connect_session_messages)]
    pub async fn query_connect_session_messages(
        &self,
        params_js: dto::TParamsOfQueryConnectSessionMessages,
    ) -> Result<dto::connect::ResultOfQuerySessionMessages, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfQuerySessionMessages = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| {
                JsError::new(&format!("Bad TParamsOfQueryConnectSessionMessages: {e:?}"))
            })?;
        let result = self.inner.connect().query_session_messages(params).await.map_err(|e| {
            JsError::new(&format!("failed to query connect session messages: {e:?}"))
        })?;

        Ok(dto::connect::ResultOfQuerySessionMessages::from(result))
    }

    #[wasm_bindgen(js_name = get_miner_details_by_multifactor_address)]
    pub async fn get_miner_details_by_multifactor_address(
        &self,
        multifactor_address: String,
    ) -> Result<dto::miner::ResultOfGetMinerDetails, JsError> {
        let res = self
            .inner
            .miner()
            .get_details_by_multifactor_address(multifactor_address)
            .await
            .map_err(|e| JsError::new(&format!("failed to get minier details: {e:?}")))?;

        Ok(dto::miner::ResultOfGetMinerDetails::from(res))
    }

    /// Deploy multifactor wallet only (does not deploy miner).
    #[wasm_bindgen(js_name = deploy_wallet)]
    pub async fn deploy_wallet(
        &self,
        params_js: dto::TParamsOfDeployMultifactor,
    ) -> Result<dto::deploy::ResultOfDeployMultifactor, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfDeployMultifactor = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfDeployMultifactor: {e:?}")))?;

        let res = self
            .inner
            .deploy()
            .deploy_multifactor(params, true, None)
            .await
            .map_err(|e| JsError::new(&format!("failed to deploy multifactor: {e:?}")))?;
        Ok(dto::deploy::ResultOfDeployMultifactor::from(res))
    }

    /// Like [`deploy_wallet`], but invokes `on_progress(event)` for each
    /// `deploy` milestone (`preparing` → `deploying` → `submitted` →
    /// `activating` → `active` → `configuring` → `confirmed`/`pending`/
    /// `failed`), where `event` is `{ op, stage, detail?, pct? }`.
    #[wasm_bindgen(js_name = deploy_wallet_with_progress)]
    pub async fn deploy_wallet_with_progress(
        &self,
        params_js: dto::TParamsOfDeployMultifactor,
        on_progress: js_sys::Function,
    ) -> Result<dto::deploy::ResultOfDeployMultifactor, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfDeployMultifactor = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfDeployMultifactor: {e:?}")))?;

        let (tx, rx) = futures::channel::mpsc::unbounded::<crate::ProgressEvent>();
        spawn_progress_forwarder(rx, on_progress);

        let res = self
            .inner
            .deploy()
            .deploy_multifactor(params, true, Some(tx))
            .await
            .map_err(|e| JsError::new(&format!("failed to deploy multifactor: {e:?}")))?;
        Ok(dto::deploy::ResultOfDeployMultifactor::from(res))
    }

    /// Deploy miner as a separate use case.
    /// Skips deploy if miner is already deployed.
    #[wasm_bindgen(js_name = deploy_miner)]
    pub async fn deploy_miner(
        &self,
        params_js: dto::TParamsOfDeployMiner,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfDeployMiner = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfDeployMultifactor: {e:?}")))?;

        let res = self
            .inner
            .deploy()
            .deploy_miner(params, None)
            .await
            .map_err(|e| JsError::new(&format!("failed to deploy miner: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(res))
    }

    /// Like [`deploy_miner`], but invokes `on_progress(event)` for each
    /// `deploy_miner` milestone (`resolving` → `deploying` → `confirmed`/
    /// `pending`/`failed`), where `event` is `{ op, stage, detail?, pct? }`.
    #[wasm_bindgen(js_name = deploy_miner_with_progress)]
    pub async fn deploy_miner_with_progress(
        &self,
        params_js: dto::TParamsOfDeployMiner,
        on_progress: js_sys::Function,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfDeployMiner = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfDeployMiner: {e:?}")))?;

        let (tx, rx) = futures::channel::mpsc::unbounded::<crate::ProgressEvent>();
        spawn_progress_forwarder(rx, on_progress);

        let res = self
            .inner
            .deploy()
            .deploy_miner(params, Some(tx))
            .await
            .map_err(|e| JsError::new(&format!("failed to deploy miner: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(res))
    }

    /// set mining keys for the app_id specified in sdk init
    #[wasm_bindgen(js_name = set_mining_keys)]
    pub async fn set_mining_keys(
        &self,
        params_js: dto::TParamsOfSetMiningKeys,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfSetMiningKeys = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfSetMiningKeys: {e:?}")))?;

        let res = self
            .inner
            .miner()
            .set_mining_keys(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to set mining keys: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(res))
    }

    #[wasm_bindgen(js_name = del_mining_key)]
    pub async fn del_mining_key(
        &self,
        params_js: dto::TParamsOfDelMiningKey,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfDelMiningKey = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfDelMiningKey: {e:?}")))?;

        let res = self
            .inner
            .miner()
            .del_mining_key(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to del mining key: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(res))
    }

    pub async fn get_multifactor_balances(
        &self,
        params_js: dto::TParamsOfGetMultifactorBalances,
    ) -> Result<dto::balances::ResultOfGetNativeBalances, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfGetNativeBalances = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfGetNativeBalances: {e:?}")))?;
        let res = self
            .inner
            .balance()
            .get_native_balances(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to get native balances: {e:?}")))?;

        Ok(dto::balances::ResultOfGetNativeBalances::from(res))
    }

    pub async fn get_tokens_balances(
        &self,
        params_js: dto::TParamsOfGetTokensBalances,
    ) -> Result<dto::balances::ResultOfGetTokensBalances, JsError> {
        let params_val: JsValue = params_js.into();
        // TODO: try let params: ParamsOfGetTokensBalances =
        // wserde_wasm_bindgen::from_value(JsValue::from(params_val))
        let params: ParamsOfGetTokensBalances = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfGetTokensBalances: {e:?}")))?;

        let res = self
            .inner
            .balance()
            .get_tokens_balances(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to get tokens balances: {e:?}")))?;

        Ok(dto::balances::ResultOfGetTokensBalances::from(res))
    }

    #[wasm_bindgen(js_name = get_history)]
    pub async fn get_history(
        &self,
        params_js: dto::TParamsOfGetHistory,
    ) -> Result<dto::tx::ResultOfGetHistory, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfGetHistory = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad ParamsOfGetHistory: {e:?}")))?;

        let res = self
            .inner
            .history()
            .get_history(params)
            .await
            .map_err(|e| JsError::new(&format!("Failed to get history: {e:?}")))?;

        Ok(dto::tx::ResultOfGetHistory::from(res))
    }

    #[wasm_bindgen(js_name = migrate_tip3_usdc)]
    pub async fn migrate_tip3_usdc(
        &self,
        params_js: dto::TMigrateTip3UsdcReq,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::types::MigrateTip3UsdcReq =
            serde_wasm_bindgen::from_value(params_val)
                .map_err(|e| JsError::new(&format!("Bad TMigrateTip3UsdcReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .migrate_tip3_usdc(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to migrate TIP-3 USDC: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(crate::ResultOfBlockchainWrite {
            message_ids: res.message_hash.into_iter().collect(),
            pending_stage: None,
            pending_reason: None,
        }))
    }

    #[wasm_bindgen(js_name = redeem_nackl)]
    pub async fn redeem_nackl(
        &self,
        params_js: dto::TRedeemNacklReq,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::RedeemNacklReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TRedeemNacklReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .redeem_nackl(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to redeem nackl: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(crate::ResultOfBlockchainWrite {
            message_ids: res.message_hash.into_iter().collect(),
            pending_stage: None,
            pending_reason: None,
        }))
    }

    #[wasm_bindgen(js_name = get_nackl_redeem_rate)]
    pub async fn get_nackl_redeem_rate(&self) -> Result<JsValue, JsError> {
        let res = self
            .inner
            .tokens()
            .get_nackl_redeem_rate()
            .await
            .map_err(|e| JsError::new(&format!("failed to get nackl redeem rate: {e:?}")))?;
        serde_wasm_bindgen::to_value(&res)
            .map_err(|e| JsError::new(&format!("failed to serialize NacklRedeemRateResult: {e:?}")))
    }

    #[wasm_bindgen(js_name = claim_usdc)]
    pub async fn claim_usdc(&self, params_js: dto::TClaimUsdcReq) -> Result<JsValue, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::ClaimUsdcReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TClaimUsdcReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .claim_usdc(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to claim usdc: {e:?}")))?;
        serde_wasm_bindgen::to_value(&res)
            .map_err(|e| JsError::new(&format!("failed to serialize ClaimUsdcResult: {e:?}")))
    }

    #[wasm_bindgen(js_name = get_my_sell_orders)]
    pub async fn get_my_sell_orders(
        &self,
        params_js: dto::TGetMySellOrdersReq,
    ) -> Result<JsValue, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::GetMySellOrdersReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TGetMySellOrdersReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .get_my_sell_orders(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to get sell orders: {e:?}")))?;
        serde_wasm_bindgen::to_value(&res)
            .map_err(|e| JsError::new(&format!("failed to serialize sell orders: {e:?}")))
    }

    #[wasm_bindgen(js_name = sell_shells)]
    pub async fn sell_shells(&self, params_js: dto::TSellShellsReq) -> Result<JsValue, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::SellShellsReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TSellShellsReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .sell_shells(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to sell shells: {e:?}")))?;
        serde_wasm_bindgen::to_value(&res)
            .map_err(|e| JsError::new(&format!("failed to serialize SellShellsResult: {e:?}")))
    }

    #[wasm_bindgen(js_name = send_tokens_direct)]
    pub async fn send_tokens_direct(
        &self,
        params_js: dto::TSendTokensDirectReq,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::SendTokensDirectReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TSendTokensDirectReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .send_tokens_direct(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to send tokens direct: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(crate::ResultOfBlockchainWrite {
            message_ids: res.message_hash.into_iter().collect(),
            pending_stage: None,
            pending_reason: None,
        }))
    }

    #[wasm_bindgen(js_name = buy_shells)]
    pub async fn buy_shells(
        &self,
        params_js: dto::TBuyShellsReq,
    ) -> Result<dto::write::ResultOfBlockchainWrite, JsError> {
        let params_val: JsValue = params_js.into();
        let params: crate::BuyShellsReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TBuyShellsReq: {e:?}")))?;
        let res = self
            .inner
            .tokens()
            .buy_shells(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to buy shells: {e:?}")))?;

        Ok(dto::write::ResultOfBlockchainWrite::from(crate::ResultOfBlockchainWrite {
            message_ids: res.message_hash.into_iter().collect(),
            pending_stage: None,
            pending_reason: None,
        }))
    }

    #[wasm_bindgen(js_name = get_miner_address)]
    pub async fn get_miner_address(
        &self,
        params_js: dto::TParamsOfGetMinerAddress,
    ) -> Result<String, JsError> {
        let params_val: JsValue = params_js.into();
        let params: dto::miner::ParamsOfGetMinerAddress =
            serde_wasm_bindgen::from_value(params_val)
                .map_err(|e| JsError::new(&format!("Bad ParamsOfGetMinerAddress: {e:?}")))?;

        let address =
            self.inner.miner().get_miner_address(&params.multifactor_address).await.map_err(
                |e| JsError::new(&format!("Failed to get resolve miner for multifactor: {e:?}")),
            )?;

        Ok(address)
    }

    /// Stage 1 of zk-login: generates ephemeral ed25519 keypair and the
    /// Poseidon-based `nonce` to bind to the OAuth `nonce=` parameter.
    /// Uses `Date.now()` (via js_sys) as the time source.
    #[wasm_bindgen(js_name = prepare_zk_login_v1)]
    pub fn prepare_zk_login_v1(&self) -> Result<dto::zkp::ZkLoginPrepareResult, JsError> {
        let now_ms = crate::infra::now_ms()
            .map_err(|e| JsError::new(&format!("failed to read now_ms: {e:?}")))?;
        let res = self
            .inner
            .zkp()
            .prepare_zk_login_v1_with_now_ms(now_ms)
            .map_err(|e| JsError::new(&format!("failed to prepare zk-login: {e:?}")))?;
        Ok(dto::zkp::ZkLoginPrepareResult::from(res))
    }

    /// Stage 5b — builds signed `ParamsOfDeployMultifactor` (epk_sig,
    /// recovery key + sig, jwk-update key + sig, provider certificates).
    /// Does not send anything on-chain.
    #[wasm_bindgen(js_name = prepare_multifactor_deploy_params)]
    pub async fn prepare_multifactor_deploy_params(
        &self,
        params_js: dto::TParamsOfPrepareDeploy,
    ) -> Result<dto::deploy::PreparedDeployParams, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfPrepareDeploy = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfPrepareDeploy: {e:?}")))?;
        let res = self
            .inner
            .deploy()
            .prepare_multifactor_deploy_params(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to prepare deploy params: {e:?}")))?;
        Ok(dto::deploy::PreparedDeployParams::from(res))
    }

    /// Completes zk-login by preparing local payload, fetching prover proofs
    /// and finalizing proof compression.
    #[wasm_bindgen(js_name = complete_zk_login_with_prover_v1)]
    pub async fn complete_zk_login_with_prover_v1(
        &self,
        params_js: dto::TZkLoginCompleteWithProverParams,
    ) -> Result<dto::zkp::ZkLoginCompleteWithProverResult, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ZkLoginCompleteWithProverParams = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TZkLoginCompleteWithProverParams: {e:?}")))?;
        let res = self
            .inner
            .zkp()
            .complete_zk_login_with_prover_v1(params, None)
            .await
            .map_err(|e| JsError::new(&format!("failed to complete zk-login: {e:?}")))?;
        Ok(dto::zkp::ZkLoginCompleteWithProverResult::from(res))
    }

    /// Like [`complete_zk_login_with_prover_v1`], but invokes
    /// `on_progress(event)` for each `prove` milestone (`started` →
    /// `finished`), where `event` is `{ op, stage, detail?, pct? }`.
    #[wasm_bindgen(js_name = complete_zk_login_with_prover_v1_with_progress)]
    pub async fn complete_zk_login_with_prover_v1_with_progress(
        &self,
        params_js: dto::TZkLoginCompleteWithProverParams,
        on_progress: js_sys::Function,
    ) -> Result<dto::zkp::ZkLoginCompleteWithProverResult, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ZkLoginCompleteWithProverParams = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TZkLoginCompleteWithProverParams: {e:?}")))?;

        let (tx, rx) = futures::channel::mpsc::unbounded::<crate::ProgressEvent>();
        spawn_progress_forwarder(rx, on_progress);

        let res = self
            .inner
            .zkp()
            .complete_zk_login_with_prover_v1(params, Some(tx))
            .await
            .map_err(|e| JsError::new(&format!("failed to complete zk-login: {e:?}")))?;
        Ok(dto::zkp::ZkLoginCompleteWithProverResult::from(res))
    }

    /// Replaces wallet ZK identity payload (`zkid`, proof, factor, JWK data).
    #[wasm_bindgen(js_name = update_zk_id)]
    pub async fn update_zk_id(
        &self,
        params_js: dto::TUpdateMultifactorZkIdReq,
    ) -> Result<dto::write::ResultOfSendMessage, JsError> {
        let params_val: JsValue = params_js.into();
        let params: UpdateMultifactorZkIdReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TUpdateMultifactorZkIdReq: {e:?}")))?;
        let res = self
            .inner
            .multifactor()
            .update_zk_id(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to update zk id: {e:?}")))?;
        Ok(dto::write::ResultOfSendMessage::from(res))
    }

    /// Deletes currently used ZKP factor by its own signer key.
    #[wasm_bindgen(js_name = delete_zkp_factor_by_itself)]
    pub async fn delete_zkp_factor_by_itself(
        &self,
        params_js: dto::TDeleteZkpFactorByItselfReq,
    ) -> Result<dto::write::ResultOfSendMessage, JsError> {
        let params_val: JsValue = params_js.into();
        let params: DeleteZkpFactorByItselfReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TDeleteZkpFactorByItselfReq: {e:?}")))?;
        let res = self
            .inner
            .zkp()
            .delete_zkp_factor_by_itself(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to delete zkp factor: {e:?}")))?;
        Ok(dto::write::ResultOfSendMessage::from(res))
    }

    /// Returns decoded multifactor contract state by address. `data` is `null`
    /// when the contract is not deployed or has no decodable account data.
    #[wasm_bindgen(js_name = get_multifactor_info)]
    pub async fn get_multifactor_info(
        &self,
        params_js: dto::TParamsOfGetMultifactorInfo,
    ) -> Result<dto::multifactor::ResultOfGetMultifactorInfo, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfGetMultifactorInfo = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfGetMultifactorInfo: {e:?}")))?;
        let res = self
            .inner
            .multifactor()
            .get_multifactor_info(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to get multifactor info: {e:?}")))?;
        Ok(dto::multifactor::ResultOfGetMultifactorInfo::from(res))
    }

    /// Resolves multifactor address by owner pubkey.
    #[wasm_bindgen(js_name = get_multifactor_address)]
    pub async fn get_multifactor_address(
        &self,
        params_js: dto::TParamsOfGetMultifactorAddress,
    ) -> Result<dto::multifactor::ResultOfGetMvMultifactorAddress, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsOfGetMultifactorAddress = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfGetMultifactorAddress: {e:?}")))?;
        let res = self
            .inner
            .multifactor()
            .get_multifactor_address(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to get multifactor address: {e:?}")))?;
        Ok(dto::multifactor::ResultOfGetMvMultifactorAddress::from(res))
    }

    /// Resolves mirror address for an owner pubkey.
    #[wasm_bindgen(js_name = get_mirror_address)]
    pub fn get_mirror_address(
        &self,
        params_js: dto::TParamsGetMirrorAddress,
    ) -> Result<dto::multifactor::ResultGetMirrorAddress, JsError> {
        let params_val: JsValue = params_js.into();
        let params: ParamsGetMirrorAddress = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsGetMirrorAddress: {e:?}")))?;
        let res = self
            .inner
            .multifactor()
            .get_mirror_address(params)
            .map_err(|e| JsError::new(&format!("failed to get mirror address: {e:?}")))?;
        Ok(dto::multifactor::ResultGetMirrorAddress::from(res))
    }

    /// Returns expiration timestamp for a factor identified by EPK.
    #[wasm_bindgen(js_name = get_epk_expire_at)]
    pub async fn get_epk_expire_at(
        &self,
        params_js: dto::TGetEPKExpireReq,
    ) -> Result<dto::multifactor::ResultOfGetEPKExpireAt, JsError> {
        let params_val: JsValue = params_js.into();
        let params: GetEPKExpireReq = serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TGetEPKExpireReq: {e:?}")))?;
        let res = self
            .inner
            .multifactor()
            .get_epk_expire_at(params)
            .await
            .map_err(|e| JsError::new(&format!("failed to get epk expire at: {e:?}")))?;
        Ok(dto::multifactor::ResultOfGetEPKExpireAt::from(res))
    }
}

/// Free function (no `Wallet` instance, no api_url/app_id): deploy a flat
/// Multisig on shellnet, funding the future address from the default giver.
/// Always returns the owner keypair — the frontend MUST persist `secret`.
#[wasm_bindgen(js_name = deploy_multisig_via_giver)]
pub async fn deploy_multisig_via_giver(
    params: dto::multisig::TParamsOfDeployMultisigViaGiver,
) -> Result<dto::multisig::TResultOfDeployMultisigViaGiver, JsError> {
    use wasm_bindgen::JsCast;

    let params_val: JsValue = params.into();
    let params: crate::services::multisig::ParamsOfDeployMultisigViaGiver =
        serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfDeployMultisigViaGiver: {e:?}")))?;

    let result = crate::services::multisig::deploy_multisig_via_giver(params)
        .await
        .map_err(|e| JsError::new(&format!("deploy_multisig_via_giver failed: {e:?}")))?;

    let js = serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("serialize result failed: {e:?}")))?;
    Ok(js.unchecked_into::<dto::multisig::TResultOfDeployMultisigViaGiver>())
}

/// Free function: ECC balances of any account by address as
/// `{ currency_id: raw_amount_string }`. Generic — works on a flat multisig,
/// unlike the multifactor-specific balance reader.
#[wasm_bindgen(js_name = multisig_balances)]
pub async fn multisig_balances(
    params: dto::multisig::TParamsOfMultisigBalances,
) -> Result<dto::multisig::TMultisigBalances, JsError> {
    use serde::Serialize;
    use wasm_bindgen::JsCast;

    let params_val: JsValue = params.into();
    let params: crate::services::multisig::ParamsOfMultisigBalances =
        serde_wasm_bindgen::from_value(params_val)
            .map_err(|e| JsError::new(&format!("Bad TParamsOfMultisigBalances: {e:?}")))?;

    let balances =
        crate::services::multisig::multisig_balances(params.endpoints, params.address)
            .await
            .map_err(|e| JsError::new(&format!("multisig_balances failed: {e:?}")))?;

    // Serialize the map as a plain JS object: { "2": "10000000000", ... }.
    let js = balances
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&format!("serialize balances failed: {e:?}")))?;
    Ok(js.unchecked_into::<dto::multisig::TMultisigBalances>())
}

#[cfg(not(feature = "single-wasm"))]
#[wasm_bindgen(start)]
pub fn start() {}
