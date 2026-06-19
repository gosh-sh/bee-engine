use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::services;
use crate::services::balance::ParamsOfGetNativeBalances;
use crate::services::balance::ParamsOfGetTokensBalances;
use crate::services::balance::ResultOfGetNativeBalances;
use crate::services::balance::ResultOfGetTokensBalances;
use crate::types::GetBalanceByTokenRootReq;
use crate::types::ResultOfGetBalanceByTokenRoot;

pub(crate) struct BalanceModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> BalanceModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    pub async fn get_native_balances(
        &self,
        params: ParamsOfGetNativeBalances,
    ) -> AppResult<ResultOfGetNativeBalances> {
        self.ctx.acquire().await;
        services::balance::get_native_balances(self.ctx.tvm_client.clone(), params).await
    }

    pub async fn get_tokens_balances(
        &self,
        params: ParamsOfGetTokensBalances,
    ) -> AppResult<ResultOfGetTokensBalances> {
        self.ctx.acquire().await;
        services::balance::get_tokens_balances(self.ctx.tvm_client.clone(), params).await
    }

    pub async fn get_balance_by_token_root(
        &self,
        params: GetBalanceByTokenRootReq,
    ) -> AppResult<ResultOfGetBalanceByTokenRoot> {
        self.ctx.acquire().await;
        match params.token_root.as_ref() {
            // NACKL
            "1" => {
                let (own_balance, locked_balance) = services::balance::get_nackl_balance(
                    self.ctx.tvm_client.clone(),
                    params.multifactor_address,
                )
                .await?;
                Ok(ResultOfGetBalanceByTokenRoot {
                    own_balance,
                    locked_balance: Some(locked_balance),
                })
            }
            // SHELL
            "2" => {
                let own_balance = services::balance::get_shell_balance(
                    self.ctx.tvm_client.clone(),
                    params.multifactor_address,
                )
                .await?;
                Ok(ResultOfGetBalanceByTokenRoot { own_balance, locked_balance: None })
            }
            token_root => {
                let balance = services::balance::get_token_balance(
                    self.ctx.tvm_client.clone(),
                    params.multifactor_address,
                    token_root.to_string(),
                    params.token_dapp,
                )
                .await?;
                Ok(ResultOfGetBalanceByTokenRoot { own_balance: balance, locked_balance: None })
            }
        }
    }
}
