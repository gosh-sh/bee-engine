use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;

use crate::client::WalletClient;
use crate::client::WalletConfig;
use crate::errors::AppResult;
use crate::modules::names::ResultOfValidateWalletName;

pub mod dto;

/// High-level native API for interacting with a multifactor wallet.
///
/// The API combines network-backed on-chain operations (deploy, balances,
/// mining, ZK-factor operations, and history).
pub struct Wallet {
    inner: WalletClient,
}

impl Wallet {
    /// Creates a wallet client from the supplied `WalletConfig`.
    pub fn new(config: WalletConfig) -> AppResult<Self> {
        let inner = WalletClient::new(config)?;
        Ok(Self { inner })
    }

    /// Prepares zk-login ephemeral data (nonce/randomness/ephemeral key).
    pub fn prepare_zk_login_v1(&self) -> AppResult<crate::ZkLoginPrepareResult> {
        let now_ms = crate::infra::now_ms()?;
        self.inner.zkp().prepare_zk_login_v1_with_now_ms(now_ms)
    }

    /// Completes zk-login by preparing local payload, fetching prover proofs
    /// and finalizing proof compression.
    pub async fn complete_zk_login_with_prover_v1(
        &self,
        params: crate::ZkLoginCompleteWithProverParams,
    ) -> AppResult<crate::ZkLoginCompleteWithProverResult> {
        self.inner.zkp().complete_zk_login_with_prover_v1(params, None).await
    }

    /// Like [`complete_zk_login_with_prover_v1`], but emits `prove` progress
    /// milestones (`started` → `finished`) into `progress` as they happen.
    ///
    /// The caller owns the receiver end (`futures::channel::mpsc::unbounded`)
    /// and forwards events to the host (e.g. a Tauri command draining into
    /// `window.emit`). Dropping the receiver is safe — events are best-effort.
    ///
    /// [`complete_zk_login_with_prover_v1`]: Self::complete_zk_login_with_prover_v1
    pub async fn complete_zk_login_with_prover_v1_with_progress(
        &self,
        params: crate::ZkLoginCompleteWithProverParams,
        progress: crate::ProgressSink,
    ) -> AppResult<crate::ZkLoginCompleteWithProverResult> {
        self.inner.zkp().complete_zk_login_with_prover_v1(params, Some(progress)).await
    }

    /// Generic polling helper for native callers (Tauri workers/adapters).
    pub async fn poll_until<T, FetchFn, FetchFut, VerifyFn>(
        &self,
        fetch_data: FetchFn,
        predicate: VerifyFn,
        max_attempts: Option<u32>,
        interval_ms: Option<u64>,
    ) -> AppResult<T>
    where
        FetchFn: Fn() -> FetchFut,
        FetchFut: std::future::Future<Output = AppResult<T>>,
        VerifyFn: Fn(&T) -> bool,
    {
        crate::infra::poll_until(fetch_data, predicate, max_attempts, interval_ms).await
    }

    /// Parses a bee-connect payload from raw base64url query value
    /// (`payload=`).
    pub fn decode_connect_payload_b64url(
        &self,
        payload_b64: String,
    ) -> AppResult<crate::ConnectPayload> {
        self.inner.connect().decode_connect_payload_b64url(payload_b64)
    }

    /// Accepts a shared-key connect session (Protocol 2): deploys AuthProfile
    /// with the shared session owner key and sends the first `wallet_hello`.
    pub async fn accept_connect_shared_key(
        &self,
        params: crate::ParamsOfAcceptSharedKeyConnect,
    ) -> AppResult<crate::ResultOfAcceptConnect> {
        self.inner.connect().accept_shared_key_connect(params).await
    }

    /// Destroys a connect `AuthProfile` through multifactor internal transfer.
    pub async fn destroy_connect_profile(
        &self,
        params: crate::ParamsOfDestroyConnectProfile,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.connect().destroy_connect_profile(params).await
    }

    /// Queries connect session messages for one session (`session_id` +
    /// `description`).
    pub async fn query_connect_session_messages(
        &self,
        params: crate::ParamsOfQuerySessionMessages,
    ) -> AppResult<crate::ResultOfQuerySessionMessages> {
        self.inner.connect().query_session_messages(params).await
    }

    /// Validates a wallet name and returns a typed validation result.
    pub fn validate_name(&self, wallet_name: String) -> ResultOfValidateWalletName {
        self.inner.names().validate_name(wallet_name)
    }

    /// Checks whether a wallet name is available in the indexer.
    pub async fn check_name_availability(
        &self,
        wallet_name: String,
    ) -> AppResult<dto::multifactor::ResultOfCheckNameAvailability> {
        self.inner.multifactor().check_name_availability(wallet_name).await
    }

    /// Returns multifactor metadata for a wallet name.
    pub async fn get_multifactor_data_by_name(
        &self,
        wallet_name: String,
    ) -> AppResult<Option<dto::multifactor::ResultOfGetMultifactorDetails>> {
        self.inner.multifactor().get_multifactor_data_by_name(wallet_name).await
    }

    /// Adds a ZKP factor to an existing multifactor wallet.
    pub async fn add_zkp_factor(
        &self,
        params: crate::services::zkp::ParamsOfAddZKPFactor,
    ) -> AppResult<dto::zkp::ResultOfAddZKPFactor> {
        let res = self.inner.zkp().add_zkp_factor(params, None).await?;
        Ok(dto::zkp::ResultOfAddZKPFactor::from(res))
    }

    /// Like [`add_zkp_factor`], but emits `add_factor` progress milestones
    /// (`jwk?` → `submitted` → `confirming`… → `confirmed`) into `progress`.
    ///
    /// The caller owns the receiver end (`futures::channel::mpsc::unbounded`)
    /// and forwards events to the host. On confirmation timeout the call fails
    /// with a terminal `add_factor_timeout`-kind error.
    ///
    /// [`add_zkp_factor`]: Self::add_zkp_factor
    pub async fn add_zkp_factor_with_progress(
        &self,
        params: crate::services::zkp::ParamsOfAddZKPFactor,
        progress: crate::ProgressSink,
    ) -> AppResult<dto::zkp::ResultOfAddZKPFactor> {
        let res = self.inner.zkp().add_zkp_factor(params, Some(progress)).await?;
        Ok(dto::zkp::ResultOfAddZKPFactor::from(res))
    }

    /// Starts the seed-phrase change flow and updates recovery-related data.
    pub async fn change_seed_phrase(
        &self,
        params: crate::services::multifactor::cmd::ParamsOfChangeSeedPhrase,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.multifactor().change_seed_phrase(params).await
    }

    /// Prepares deploy params.
    pub async fn prepare_multifactor_deploy_params(
        &self,
        params: crate::ParamsOfPrepareDeploy,
    ) -> AppResult<ackinacki_kit::contracts::mvsystem::mirror::ParamsOfDeployMultifactor> {
        self.inner.deploy().prepare_multifactor_deploy_params(params).await
    }

    /// Deploys a new multifactor wallet and returns deployment artifacts.
    ///
    /// Does not deploy miner automatically; use `deploy_miner` separately.
    pub async fn deploy_wallet(
        &self,
        params: crate::services::deploy::ParamsOfDeployMultifactor,
    ) -> AppResult<dto::deploy::ResultOfDeployMultifactor> {
        let res = self.inner.deploy().deploy_multifactor(params, true, None).await?;
        Ok(dto::deploy::ResultOfDeployMultifactor::from(res))
    }

    /// Like [`deploy_wallet`], but emits `deploy` progress milestones
    /// (`preparing` → `deploying` → `submitted` → `activating` → `active` →
    /// `configuring` → `confirmed`/`pending`/`failed`) into `progress`.
    ///
    /// [`deploy_wallet`]: Self::deploy_wallet
    pub async fn deploy_wallet_with_progress(
        &self,
        params: crate::services::deploy::ParamsOfDeployMultifactor,
        progress: crate::ProgressSink,
    ) -> AppResult<dto::deploy::ResultOfDeployMultifactor> {
        let res = self.inner.deploy().deploy_multifactor(params, true, Some(progress)).await?;
        Ok(dto::deploy::ResultOfDeployMultifactor::from(res))
    }

    /// Deploys a wallet without updating contract flags (wasm_hash,
    /// force_remove_oldest). Useful for testing `update_contract`
    /// separately.
    pub async fn deploy_wallet_only(
        &self,
        params: crate::services::deploy::ParamsOfDeployMultifactor,
    ) -> AppResult<dto::deploy::ResultOfDeployMultifactor> {
        let res = self.inner.deploy().deploy_multifactor(params, false, None).await?;
        Ok(dto::deploy::ResultOfDeployMultifactor::from(res))
    }

    /// Deploys miner contract for a multifactor wallet (idempotent).
    ///
    /// This is a separate use case from `deploy_wallet`.
    pub async fn deploy_miner(
        &self,
        params: crate::services::deploy::ParamsOfDeployMiner,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.deploy().deploy_miner(params, None).await
    }

    /// Like [`deploy_miner`], but emits `deploy_miner` progress milestones
    /// (`resolving` → `deploying` → `confirmed`/`pending`/`failed`) into
    /// `progress`.
    ///
    /// [`deploy_miner`]: Self::deploy_miner
    pub async fn deploy_miner_with_progress(
        &self,
        params: crate::services::deploy::ParamsOfDeployMiner,
        progress: crate::ProgressSink,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.deploy().deploy_miner(params, Some(progress)).await
    }

    /// Sets mining owner key for a miner app namespace.
    ///
    /// This method returns only after the owner key update is observed
    /// on-chain.
    pub async fn set_mining_keys(
        &self,
        params: crate::services::miner::ParamsOfSetMiningKeys,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.miner().set_mining_keys(params).await
    }

    /// Returns miner address and current owner key mapping for a multifactor
    /// wallet.
    pub async fn get_miner_details_by_multifactor_address(
        &self,
        multifactor_address: String,
    ) -> AppResult<dto::miner::ResultOfGetMinerDetails> {
        let res =
            self.inner.miner().get_details_by_multifactor_address(multifactor_address).await?;
        Ok(dto::miner::ResultOfGetMinerDetails::from(res))
    }

    /// Resolves miner address for a multifactor wallet address.
    pub async fn get_miner_address(&self, multifactor_address: &str) -> AppResult<String> {
        self.inner.miner().get_miner_address(multifactor_address).await
    }

    /// Removes mining owner key for an app namespace.
    ///
    /// Use `wait = true` in request params to wait until the key disappears
    /// from miner details.
    pub async fn del_mining_key(
        &self,
        params: crate::services::miner::ParamsOfDelMiningKey,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.miner().del_mining_key(params).await
    }

    /// Returns native balances (NACKL/SHELL and Popitgame balances).
    pub async fn get_multifactor_balances(
        &self,
        params: crate::services::balance::ParamsOfGetNativeBalances,
    ) -> AppResult<dto::balances::ResultOfGetNativeBalances> {
        let res = self.inner.balance().get_native_balances(params).await?;
        Ok(dto::balances::ResultOfGetNativeBalances::from(res))
    }

    /// Returns balances for provided TIP-3 token roots.
    pub async fn get_tokens_balances(
        &self,
        params: crate::services::balance::ParamsOfGetTokensBalances,
    ) -> AppResult<dto::balances::ResultOfGetTokensBalances> {
        let res = self.inner.balance().get_tokens_balances(params).await?;
        Ok(dto::balances::ResultOfGetTokensBalances::from(res))
    }

    /// Replaces wallet ZK identity payload (`zkid`, proof, factor, JWK data).
    pub async fn update_zk_id(
        &self,
        params: crate::UpdateMultifactorZkIdReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.multifactor().update_zk_id(params).await
    }

    /// Resolves multifactor address by owner pubkey.
    pub async fn get_multifactor_address(
        &self,
        params: crate::ParamsOfGetMultifactorAddress,
    ) -> AppResult<ackinacki_kit::contracts::mvsystem::root::ResultOfGetMvMultifactorAddress> {
        self.inner.multifactor().get_multifactor_address(params).await
    }

    /// Resolves mirror address for an owner pubkey.
    pub fn get_mirror_address(
        &self,
        params: crate::ParamsGetMirrorAddress,
    ) -> AppResult<crate::ResultGetMirrorAddress> {
        self.inner.multifactor().get_mirror_address(params)
    }

    /// Returns decoded multifactor contract state by address.
    pub async fn get_multifactor_info(
        &self,
        params: crate::ParamsOfGetMultifactorInfo,
    ) -> AppResult<crate::ResultOfGetMultifactorInfo> {
        self.inner.multifactor().get_multifactor_info(params).await
    }

    /// Returns own and locked balance for a token root.
    pub async fn get_balance_by_token_root(
        &self,
        params: crate::GetBalanceByTokenRootReq,
    ) -> AppResult<crate::ResultOfGetBalanceByTokenRoot> {
        self.inner.balance().get_balance_by_token_root(params).await
    }

    /// Withdraws pending Popitgame rewards to wallet balances.
    pub async fn withdraw_popitgame_rewards(
        &self,
        params: crate::WithdrawPopitgameRewardsReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.tokens().withdraw_popitgame_rewards(params).await
    }

    /// Buys Shell for USDC via accumulator.
    /// Sends ECC[3] (USDC) to ShellAccumulatorRootUSDC. The accumulator
    /// automatically sends ECC[2] (Shell) back.
    /// `usdc_amount` — whole USDC (no decimals).
    pub async fn buy_shells(&self, params: crate::BuyShellsReq) -> AppResult<ResultOfSendMessage> {
        self.inner.tokens().buy_shells(params).await
    }

    /// Burns NACKL and receives USDC proportional to share of supply.
    /// Sends ECC[1] (NACKL) to ShellAccumulatorRootUSDC.
    pub async fn redeem_nackl(
        &self,
        params: crate::RedeemNacklReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.tokens().redeem_nackl(params).await
    }

    /// Migrates TIP-3 USDC to ECC[3] via Exchange contract.
    pub async fn migrate_tip3_usdc(
        &self,
        params: crate::types::MigrateTip3UsdcReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.tokens().migrate_tip3_usdc(params).await
    }

    /// Returns current NACKL → USDC redemption rate.
    /// Read-only, no signing required.
    pub async fn get_nackl_redeem_rate(&self) -> AppResult<crate::types::NacklRedeemRateResult> {
        self.inner.tokens().get_nackl_redeem_rate().await
    }

    /// Claims USDC payout for a sold sell order.
    /// The SellOrderLot must be sold (bought by a buyer).
    /// After claim, the SellOrderLot self-destructs.
    pub async fn claim_usdc(
        &self,
        params: crate::ClaimUsdcReq,
    ) -> AppResult<crate::types::ClaimUsdcResult> {
        self.inner.tokens().claim_usdc(params).await
    }

    /// Returns paginated sell orders for the wallet (seller).
    /// Read-only, no signing required.
    pub async fn get_my_sell_orders(
        &self,
        params: crate::GetMySellOrdersReq,
    ) -> AppResult<crate::types::GetMySellOrdersResult> {
        self.inner.tokens().get_my_sell_orders(params).await
    }

    /// Places Shell for sale via accumulator.
    /// Sends ECC[2] (Shell) to ShellAccumulatorRootUSDC.
    /// `denom` — denomination (1, 10, 100, 1000). SDK computes the amount.
    /// Returns order_id for tracking the order.
    pub async fn sell_shells(
        &self,
        params: crate::SellShellsReq,
    ) -> AppResult<crate::types::SellShellsResult> {
        self.inner.tokens().sell_shells(params).await
    }

    /// Sends token amount from a multifactor wallet to a destination address.
    pub async fn send_tokens(
        &self,
        params: crate::SendTokensReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.tokens().send_tokens(params).await
    }

    /// Direct transfer of native tokens with explicit flags (uses
    /// `sendTransaction`). Only works when security card is off.
    pub async fn send_tokens_direct(
        &self,
        params: crate::SendTokensDirectReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.tokens().send_tokens_direct(params).await
    }

    /// Returns expiration timestamp for a factor identified by EPK.
    pub async fn get_epk_expire_at(
        &self,
        params: crate::GetEPKExpireReq,
    ) -> AppResult<crate::GetEPKExpireRes> {
        self.inner.multifactor().get_epk_expire_at(params).await
    }

    /// Deletes currently used ZKP factor by its own signer key.
    pub async fn delete_zkp_factor_by_itself(
        &self,
        params: crate::DeleteZkpFactorByItselfReq,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.zkp().delete_zkp_factor_by_itself(params).await
    }

    /// Updates contract code/settings through owner-signed operation.
    pub async fn update_contract(
        &self,
        params: crate::ParamsOfUpdateContract,
    ) -> AppResult<crate::ResultOfBlockchainWrite> {
        self.inner.multifactor().update_contract(params).await
    }

    /// Returns paginated token transfer history for a wallet.
    pub async fn get_history(
        &self,
        params: crate::services::transaction::history::ParamsOfGetHistory,
    ) -> AppResult<dto::tx::ResultOfGetHistory> {
        let res = self.inner.history().get_history(params).await?;
        Ok(dto::tx::ResultOfGetHistory::from(res))
    }

    /// Generate a DEX voucher: adds RootPN to whitelist, then sends ECC tokens
    /// from the multifactor wallet to RootPN with `generatevoucher` payload.
    #[cfg(feature = "dex")]
    pub async fn generate_voucher(
        &self,
        params: crate::modules::dex::ParamsOfGenerateVoucher,
    ) -> AppResult<ResultOfSendMessage> {
        self.inner.dex().generate_voucher(params).await
    }
}
