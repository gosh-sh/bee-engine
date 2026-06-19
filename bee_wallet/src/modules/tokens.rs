use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor as MvMultifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfGetEpkExpire;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSubmitTransaction;
use ackinacki_kit::contracts::mvsystem::popitgame::ParamsOfEncodeWithdraw;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetPopitgame;
use ackinacki_kit::contracts::mvsystem::ContractIndex;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::EncodeMessage;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use ackinacki_kit::tvm_client::abi::CallSet;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;
use rand::random_range;
use serde_json::json;

use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::services;
use crate::types::ClaimUsdcReq;
use crate::types::ClaimUsdcResult;
use crate::types::GetMySellOrdersReq;
use crate::types::MigrateTip3UsdcReq;
use crate::types::SellShellsResult;
use crate::BuyShellsReq;
use crate::RedeemNacklReq;
use crate::SellShellsReq;
use crate::SendTokensDirectReq;
use crate::SendTokensReq;
use crate::WithdrawPopitgameRewardsReq;

/// Returns `true` if `token_root` is a numeric ECC currency_id (e.g. "1", "2",
/// "3"), `false` if it's a TIP-3 token root address (e.g. "0:ffff...").
fn is_native_ecc(token_root: &str) -> bool {
    token_root.parse::<u32>().is_ok()
}

pub(crate) struct TokensModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> TokensModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub async fn send_tokens(&self, params: SendTokensReq) -> AppResult<ResultOfSendMessage> {
        self.ctx.acquire().await;
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let signer = Signer::Keys { keys: params.signer_keys };

        let res = if is_native_ecc(&params.token_root) {
            services::tokens::send_native_tokens(
                &multifactor,
                epk_expire_at,
                params.destination_address,
                params.token_root,
                params.amount_raw,
                signer,
                params.bounce,
            )
            .await?
        } else {
            services::tokens::send_other_tokens(
                self.ctx.tvm_client.clone(),
                &multifactor,
                epk_expire_at,
                params.destination_address,
                params.token_root,
                params.token_dapp,
                params.amount_raw,
                signer,
                params.bounce,
            )
            .await?
        };

        Ok(res)
    }

    pub async fn send_tokens_direct(
        &self,
        params: SendTokensDirectReq,
    ) -> AppResult<ResultOfSendMessage> {
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let signer = Signer::Keys { keys: params.signer_keys };

        services::tokens::send_native_tokens_direct(
            &multifactor,
            epk_expire_at,
            params.destination_address,
            params.token_root,
            params.amount_raw,
            params.flags,
            params.value,
            params.payload,
            signer,
            params.bounce,
        )
        .await
    }

    pub async fn buy_shells(&self, params: BuyShellsReq) -> AppResult<ResultOfSendMessage> {
        self.ctx.acquire().await;
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let signer = Signer::Keys { keys: params.signer_keys };

        services::tokens::buy_shells(
            &multifactor,
            epk_expire_at,
            params.usdc_amount,
            signer,
            params.bounce,
        )
        .await
    }

    pub async fn sell_shells(&self, params: SellShellsReq) -> AppResult<SellShellsResult> {
        self.ctx.acquire().await;
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let signer = Signer::Keys { keys: params.signer_keys };

        services::tokens::sell_shells(
            self.ctx.tvm_client.clone(),
            &multifactor,
            epk_expire_at,
            params.denom,
            signer,
            params.bounce,
        )
        .await
    }

    pub async fn claim_usdc(&self, params: ClaimUsdcReq) -> AppResult<ClaimUsdcResult> {
        self.ctx.acquire().await;
        let signer = Signer::Keys { keys: params.signer_keys };

        services::tokens::claim_usdc(
            self.ctx.tvm_client.clone(),
            params.denom,
            params.order_id,
            signer,
        )
        .await
    }

    pub async fn get_my_sell_orders(
        &self,
        params: GetMySellOrdersReq,
    ) -> AppResult<crate::types::GetMySellOrdersResult> {
        services::tokens::get_my_sell_orders(
            self.ctx.tvm_client.clone(),
            self.ctx.archive_tvm_client.clone(),
            self.ctx.rate_limiter.clone(),
            &params.multifactor_address,
            params.page_size,
            params.cursor,
        )
        .await
    }

    pub async fn redeem_nackl(&self, params: RedeemNacklReq) -> AppResult<ResultOfSendMessage> {
        self.ctx.acquire().await;
        if params.nackl_amount == 0 {
            return Err(crate::errors::AppError::new("redeem_nackl: nackl_amount must be > 0"));
        }

        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let signer = Signer::Keys { keys: params.signer_keys };

        services::tokens::redeem_nackl(
            &multifactor,
            epk_expire_at,
            params.nackl_amount,
            signer,
            params.bounce,
        )
        .await
    }

    pub async fn migrate_tip3_usdc(
        &self,
        params: MigrateTip3UsdcReq,
    ) -> AppResult<ResultOfSendMessage> {
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));
        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        let signer = Signer::Keys { keys: params.signer_keys };

        services::tokens::migrate_tip3_usdc(
            self.ctx.tvm_client.clone(),
            &multifactor,
            epk_expire_at,
            params.token_root,
            params.token_dapp,
            params.amount_raw,
            signer,
            params.bounce,
        )
        .await
    }

    pub async fn get_nackl_redeem_rate(&self) -> AppResult<crate::types::NacklRedeemRateResult> {
        services::tokens::get_nackl_redeem_rate(self.ctx.tvm_client.clone()).await
    }

    pub async fn withdraw_popitgame_rewards(
        &self,
        params: WithdrawPopitgameRewardsReq,
    ) -> AppResult<ResultOfSendMessage> {
        let verifiers_root = MobileVerifiersRoot::new_default(self.ctx.tvm_client.clone());
        let multifactor = Arc::new(MvMultifactor::new_default(
            self.ctx.tvm_client.clone(),
            params.multifactor_address.clone(),
        ));

        let popitgame = verifiers_root
            .get_popitgame(ParamsOfGetPopitgame {
                multifactor_address: multifactor.address().to_string(),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get popitgame"))?;

        popitgame.fetch_account().await.map_err(|e| {
            crate::errors::AppError::from(e).with_context("fetch account popitgame")
        })?;
        let popitgame_ecc = popitgame.async_guarded(|acc| acc.ecc.clone()).await;

        // TODO: beautify
        let value: u128 = match popitgame_ecc.get(&1) {
            Some(v) => v.to_string().parse::<u128>().unwrap_or_default(),
            None => 0,
        };

        let message = popitgame
            .encode_message_body(
                CallSet {
                    function_name: "withdraw".to_string(),
                    header: None,
                    input: Some(json!(ParamsOfEncodeWithdraw {
                        recipient: params.multifactor_address,
                        amount: value
                    })),
                },
                true,
                Signer::None,
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("Encode `activate` message")
            })?;

        let epk_expire_at = multifactor
            .get_epk_expire_at(ParamsOfGetEpkExpire {
                epk: format!("0x{}", params.signer_keys.public.clone()),
            })
            .await
            .map_err(|e| crate::errors::AppError::from(e).with_context("Get EPK expire at"))?
            .epk_expire_at;

        services::multifactor::whitelist::update_multifactor_whitelist_and_wait(
            &multifactor,
            services::multifactor::whitelist::ParamsOfUpdateMultifactorWhiteList {
                epk_expire_at,
                payload_destination: ContractIndex::PopitGame,
                target_address: popitgame.address().to_string(),
                mirror_index: random_range(0..999),
                whitelisted_name: None,
            },
            &Signer::Keys { keys: params.signer_keys.clone() },
        )
        .await
        .map_err(|e| e.with_context("withdraw_popitgame_rewards: update whitelist"))?;

        let result = multifactor
            .submit_transaction(
                ParamsOfSubmitTransaction {
                    dest: popitgame.address().to_string(),
                    epk_expire_at,
                    payload: message.body,
                    bounce: params.bounce.unwrap_or(true),
                    all_balance: false,
                    ..Default::default()
                },
                Signer::Keys { keys: params.signer_keys },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context(format!(
                    "Submit multifactor `{}` transaction",
                    multifactor.address()
                ))
            })?;

        crate::infra::ensure_tx_success(result, "submit_transaction (withdraw popitgame)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_native_ecc_nackl() {
        assert!(is_native_ecc("1"));
    }

    #[test]
    fn is_native_ecc_shell() {
        assert!(is_native_ecc("2"));
    }

    #[test]
    fn is_native_ecc_usdc() {
        assert!(is_native_ecc("3"));
    }

    #[test]
    fn is_native_ecc_future_currency() {
        assert!(is_native_ecc("4"));
        assert!(is_native_ecc("100"));
    }

    #[test]
    fn is_not_native_ecc_tip3_address() {
        assert!(!is_native_ecc(
            "0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
    }

    #[test]
    fn is_not_native_ecc_hex_address() {
        assert!(!is_native_ecc(
            "0:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
        ));
    }

    #[test]
    fn is_not_native_ecc_empty() {
        assert!(!is_native_ecc(""));
    }

    #[test]
    fn is_not_native_ecc_text() {
        assert!(!is_native_ecc("nackl"));
    }

    #[test]
    fn is_not_native_ecc_negative() {
        assert!(!is_native_ecc("-1"));
    }
}
