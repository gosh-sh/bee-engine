use std::collections::BTreeMap;
use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetPopitgame;
use ackinacki_kit::contracts::token::root::ParamsOfGetWalletAddress;
use ackinacki_kit::contracts::token::root::TokenRoot;
use ackinacki_kit::contracts::token::wallet::TokenWallet;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use ackinacki_kit::tvm_client::ClientContext;
use num_bigint::BigInt;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::DisplayFromStr;

use crate::types::ResultOfGetBalance;

#[derive(Debug, Deserialize)]
pub struct ParamsOfGetNativeBalances {
    pub multifactor_address: String,
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResultOfGetNativeBalances {
    #[serde_as(as = "BTreeMap<_, DisplayFromStr>")]
    pub popitgame: BTreeMap<u32, BigInt>,
    #[serde_as(as = "BTreeMap<_, DisplayFromStr>")]
    pub ecc: BTreeMap<u32, BigInt>,
}

pub async fn get_native_balances(
    tvm_client: Arc<ClientContext>,
    params: ParamsOfGetNativeBalances,
) -> crate::errors::AppResult<ResultOfGetNativeBalances> {
    let multifactor_contract =
        Multifactor::new_default(tvm_client.clone(), params.multifactor_address.clone());
    let root_contract = MobileVerifiersRoot::new_default(tvm_client.clone());
    // multifactor own balance
    multifactor_contract
        .fetch_account()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Fetch multifactor account"))?;
    let multifactor_ecc = multifactor_contract.async_guarded(|acc| acc.ecc.clone()).await;

    // popitgame balance
    let popitgame_instance = root_contract
        .get_popitgame(ParamsOfGetPopitgame {
            multifactor_address: params.multifactor_address.clone(),
        })
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get popitgame"))?;
    popitgame_instance
        .fetch_account()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get popitgame account"))?;

    let popitgame_ecc = popitgame_instance.async_guarded(|acc| acc.ecc.clone()).await;

    Ok(ResultOfGetNativeBalances { popitgame: popitgame_ecc, ecc: multifactor_ecc })
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResultOfGetTokensBalances {
    #[serde_as(as = "BTreeMap<_, DisplayFromStr>")]
    pub tokens: BTreeMap<String, BigInt>,
}

/// A TIP-3 token to query, with its own dApp (per-token; from the caller).
#[derive(Debug, Deserialize)]
pub struct TokenRef {
    pub token_root: String,
    /// Bare 64-hex dApp ID of `token_root` (ignored on gql-server < 1.0.0).
    pub token_dapp: String,
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfGetTokensBalances {
    pub multifactor_address: String,
    pub token_roots: Vec<TokenRef>,
}

pub async fn get_tokens_balances(
    tvm_client: Arc<ClientContext>,
    params: ParamsOfGetTokensBalances,
) -> crate::errors::AppResult<ResultOfGetTokensBalances> {
    let mut tokens = BTreeMap::new();
    for token in params.token_roots {
        let token_root = TokenRoot::new(
            tvm_client.clone(),
            crate::dapp::token_contract_params(
                token.token_root.as_str(),
                token.token_dapp.as_str(),
            ),
        );
        let token_wallet_address_res = token_root
            .get_wallet_address(ParamsOfGetWalletAddress {
                owner_address: params.multifactor_address.clone(),
            })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("get_wallet_address failed")
            })?;

        let token_wallet = TokenWallet::new(
            tvm_client.clone(),
            crate::dapp::token_contract_params(
                token_wallet_address_res.wallet_address,
                token.token_dapp.as_str(),
            ),
        );
        let balance = match token_wallet.is_deployed().await {
            true => {
                let details = token_wallet.get_details().await.map_err(|e| {
                    crate::errors::AppError::from(e).with_context("token_wallet get_details failed")
                })?;

                BigInt::from(details.balance)
            }
            false => BigInt::ZERO,
        };

        tokens.insert(token.token_root, balance);
    }

    Ok(ResultOfGetTokensBalances { tokens })
}

pub async fn get_nackl_balance(
    tvm_client: Arc<ClientContext>,
    multifactor_address: String,
) -> crate::errors::AppResult<(ResultOfGetBalance, ResultOfGetBalance)> {
    let multifactor_contract =
        Multifactor::new_default(tvm_client.clone(), multifactor_address.clone());
    let verifiers_root = MobileVerifiersRoot::new_default(tvm_client.clone());
    multifactor_contract
        .fetch_account()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Fetch multifactor account"))?;
    let multifactor_ecc = multifactor_contract.async_guarded(|acc| acc.ecc.clone()).await;
    let zero = BigInt::ZERO;
    let own_balance = multifactor_ecc.get(&1).unwrap_or(&zero);
    let popitgame_instance = verifiers_root
        .get_popitgame(ParamsOfGetPopitgame { multifactor_address })
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get popitgame"))?;
    popitgame_instance
        .fetch_account()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get popitgame account"))?;
    let popitgame_ecc = popitgame_instance.async_guarded(|acc| acc.ecc.clone()).await;
    let locked_balance = popitgame_ecc.get(&1).unwrap_or(&zero);

    Ok((
        ResultOfGetBalance { decimals: BigInt::from(9), value: own_balance.clone() },
        ResultOfGetBalance { decimals: BigInt::from(9), value: locked_balance.clone() },
    ))
}

pub async fn get_shell_balance(
    tvm_client: Arc<ClientContext>,
    multifactor_address: String,
) -> crate::errors::AppResult<ResultOfGetBalance> {
    let multifactor_contract = Multifactor::new_default(tvm_client, multifactor_address);
    multifactor_contract
        .fetch_account()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Fetch multifactor account"))?;
    let multifactor_ecc = multifactor_contract.async_guarded(|acc| acc.ecc.clone()).await;
    let zero = BigInt::ZERO;
    let own_balance = multifactor_ecc.get(&2).unwrap_or(&zero);
    Ok(ResultOfGetBalance { decimals: BigInt::from(9), value: own_balance.clone() })
}

pub async fn get_token_balance(
    tvm_client: Arc<ClientContext>,
    multifactor_address: String,
    token_root: String,
    token_dapp: String,
) -> crate::errors::AppResult<ResultOfGetBalance> {
    let token_root = TokenRoot::new(
        tvm_client.clone(),
        crate::dapp::token_contract_params(token_root, token_dapp.as_str()),
    );
    let token_root_details = token_root
        .get_details()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get details"))?;
    let token_wallet_address_res = token_root
        .get_wallet_address(ParamsOfGetWalletAddress { owner_address: multifactor_address })
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get wallet address"))?;
    let token_wallet = TokenWallet::new(
        tvm_client,
        crate::dapp::token_contract_params(
            token_wallet_address_res.wallet_address,
            token_dapp.as_str(),
        ),
    );
    let details = token_wallet
        .get_details()
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Get wallet details"))?;
    Ok(ResultOfGetBalance {
        decimals: BigInt::from(token_root_details.decimals),
        value: BigInt::from(details.balance),
    })
}
