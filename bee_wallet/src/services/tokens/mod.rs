use std::collections::HashMap;
use std::sync::Arc;

mod sell_orders;

use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::delivery::ContractContext;
use ackinacki_kit::contracts::exchange::exchange_contract::Exchange;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSendTransaction;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSubmitTransaction;
use ackinacki_kit::contracts::token::root::ParamsOfGetWalletAddress;
use ackinacki_kit::contracts::token::root::TokenRoot;
use ackinacki_kit::contracts::token::transaction::TokenTransaction;
use ackinacki_kit::contracts::token::wallet::ParamsOfDeployTransaction;
use ackinacki_kit::contracts::token::wallet::ParamsOfGetTransactionAddress;
use ackinacki_kit::contracts::token::wallet::TokenWallet;
use ackinacki_kit::contracts::token::wallet::Transaction;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::ClientContext;

// Low-level token operation: send native tokens (NACKL, SHELL)
pub async fn send_native_tokens(
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    destination_address: String,
    token_root: String,
    amount_raw: u64,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    let token_root_u: u32 = token_root.parse().map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context(format!("Parse token root failure `{token_root}` transaction"))
    })?;
    let ecc_nano = HashMap::from([(token_root_u, amount_raw)]);

    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: destination_address,
                epk_expire_at,
                value: 0,
                cc: ecc_nano,
                bounce: bounce.unwrap_or(true),
                all_balance: false,
                ..Default::default()
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context(format!("Submit multifactor `{}` transaction", multifactor.address()))
        })?;

    crate::infra::ensure_tx_success(result, "submit_transaction (send native tokens)")
}

/// Direct transfer of native tokens with explicit flags (uses
/// `sendTransaction`). Only works when security card is off.
/// Default gas value for `sendTransaction`: 1 VMShell.
const SEND_TX_DEFAULT_VALUE: u128 = 1_000_000_000;

#[allow(clippy::too_many_arguments)]
pub async fn send_native_tokens_direct(
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    destination_address: String,
    token_root: String,
    amount_raw: u64,
    flags: u8,
    value: Option<u128>,
    payload: Option<String>,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    let token_root_u: u32 = token_root.parse().map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context(format!("Parse token root failure `{token_root}` transaction"))
    })?;
    let ecc_nano = HashMap::from([(token_root_u, amount_raw)]);

    let result = multifactor
        .send_transaction(
            ParamsOfSendTransaction {
                dest: destination_address,
                epk_expire_at,
                value: value.unwrap_or(SEND_TX_DEFAULT_VALUE),
                cc: ecc_nano,
                bounce: bounce.unwrap_or(true),
                flags,
                payload: payload.unwrap_or_default(),
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context(format!("Send multifactor `{}` transaction", multifactor.address()))
        })?;

    crate::infra::ensure_tx_success(result, "send_transaction (send native tokens direct)")
}

use ackinacki_kit::contracts::accumulator::is_valid_denom;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetQueueState;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetSellOrderAddress;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ShellAccumulatorRootUsdc;
use ackinacki_kit::contracts::accumulator::shell_amount_for_denom;
use ackinacki_kit::contracts::accumulator::NACKL_ECC_ID;
use ackinacki_kit::contracts::accumulator::SHELL_ECC_ID;
use ackinacki_kit::contracts::accumulator::USDC_DECIMALS_FACTOR;
use ackinacki_kit::contracts::accumulator::USDC_ECC_ID;

/// Sends ECC[3] (USDC) to ShellAccumulatorRootUSDC for buying Shell.
/// `usdc_whole` — whole USDC (no decimals). Internally multiplied by
/// USDC_DECIMALS_FACTOR.
pub async fn buy_shells(
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    usdc_whole: u64,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    if usdc_whole == 0 {
        return Err(crate::errors::AppError::new("buy_shells: usdc_amount must be > 0"));
    }

    let usdc_micro = usdc_whole * (USDC_DECIMALS_FACTOR as u64);
    let ecc = HashMap::from([(USDC_ECC_ID, usdc_micro)]);

    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: ShellAccumulatorRootUsdc::DEFAULT_ADDRESS.to_string(),
                epk_expire_at,
                value: 1_000_000_000,
                cc: ecc,
                bounce: bounce.unwrap_or(true),
                all_balance: false,
                ..Default::default()
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "Submit multifactor `{}` buy_shells transaction",
                multifactor.address()
            ))
        })?;

    crate::infra::ensure_tx_success(result, "submit_transaction (buy_shells)")
}

/// Places Shell for sale in the accumulator.
/// `denom` — denomination (1, 10, 100, 1000). SDK computes Shell amount.
/// Returns order_id assigned by the accumulator.
pub async fn sell_shells(
    tvm_client: Arc<ClientContext>,
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    denom: u16,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<crate::types::SellShellsResult> {
    let shell_amount = shell_amount_for_denom(denom).ok_or_else(|| {
        crate::errors::AppError::new(format!(
            "sell_shells: invalid denom `{denom}`. Expected one of: 1, 10, 100, 1000"
        ))
    })?;

    // Remember nextId BEFORE sending — this will be our order_id.
    let accumulator = ShellAccumulatorRootUsdc::new_default(tvm_client.clone());
    let queue_before =
        accumulator.get_queue_state(ParamsOfGetQueueState { d: denom }).await.map_err(|e| {
            crate::errors::AppError::from(e).with_context("sell_shells: getQueueState before send")
        })?;
    let order_id = queue_before.next_id;

    let ecc = HashMap::from([(SHELL_ECC_ID, shell_amount as u64)]);

    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: ShellAccumulatorRootUsdc::DEFAULT_ADDRESS.to_string(),
                epk_expire_at,
                value: 1_000_000_000,
                cc: ecc,
                bounce: bounce.unwrap_or(true),
                all_balance: false,
                ..Default::default()
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "Submit multifactor `{}` sell_shells transaction",
                multifactor.address()
            ))
        })?;

    let result = crate::infra::ensure_tx_success(result, "submit_transaction (sell_shells)")?;

    // Poll getQueueState until nextId grows (order accepted by accumulator).
    let queue_after = crate::infra::poll_until(
        || {
            let acc = ShellAccumulatorRootUsdc::new_default(tvm_client.clone());
            async move {
                acc.get_queue_state(ParamsOfGetQueueState { d: denom }).await.map_err(|e| {
                    crate::errors::AppError::from(e).with_context("sell_shells: poll getQueueState")
                })
            }
        },
        |state| state.next_id > order_id,
        Some(30),
        Some(500),
    )
    .await
    .map_err(|e| e.with_context("sell_shells: timed out waiting for order confirmation"))?;

    // Address is deterministic — does not depend on contract deployment.
    let sell_order_address = accumulator
        .get_sell_order_address(ParamsOfGetSellOrderAddress { d: denom, order_id })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("sell_shells: getSellOrderAddress")
        })?
        .sell_order_addr;

    let sold = order_id <= queue_after.sold_prefix;
    let position_in_queue = if sold { 0 } else { order_id - queue_after.sold_prefix };

    Ok(crate::types::SellShellsResult {
        message_hash: result.message_hash,
        order_id,
        denom,
        sell_order_address,
        sold,
        position_in_queue,
    })
}

/// Returns paginated sell orders for the given multifactor address (seller).
///
/// Implementation lives in `sell_orders.rs` — it splits event lookups
/// (hot→archive failover) from state getters (hot only), which avoids the
/// failure mode where a flaky archive getter call breaks the whole pipeline.
/// See module docs there for the full strategy.
pub async fn get_my_sell_orders(
    tvm_client: Arc<ClientContext>,
    archive_tvm_client: Option<Arc<ClientContext>>,
    rate_limiter: Option<bee_infra::RateLimiter>,
    multifactor_address: &str,
    page_size: u32,
    cursor: Option<String>,
) -> crate::errors::AppResult<crate::types::GetMySellOrdersResult> {
    sell_orders::get_my_sell_orders(
        tvm_client,
        archive_tvm_client,
        rate_limiter,
        multifactor_address,
        page_size,
        cursor,
    )
    .await
}

/// Claims USDC payout for a sold sell order.
/// Uses `claim_for_order` which calls `SellOrderLot.claim()` directly (external
/// msg). The lot internally calls `AccumulatorRoot.claimUSDC()` to transfer
/// USDC to seller.
pub async fn claim_usdc(
    context: ContractContext,
    denom: u16,
    order_id: u64,
    signer: Signer,
) -> crate::errors::AppResult<crate::types::ClaimUsdcResult> {
    if !is_valid_denom(denom) {
        return Err(crate::errors::AppError::new(format!(
            "claim_usdc: invalid denom `{denom}`. Expected one of: 1, 10, 100, 1000"
        )));
    }

    let accumulator = ShellAccumulatorRootUsdc::new_default(context);
    let result = accumulator.claim_for_order(denom, order_id, signer).await.map_err(|e| {
        crate::errors::AppError::from(e).with_context("claim_usdc: claim_for_order")
    })?;

    let usdc_payout = (denom as u64) * (USDC_DECIMALS_FACTOR as u64);

    Ok(crate::types::ClaimUsdcResult { message_hash: result.message_hash, usdc_payout })
}

/// Returns current NACKL → USDC redemption rate from accumulator state.
pub async fn get_nackl_redeem_rate(
    tvm_client: Arc<ClientContext>,
) -> crate::errors::AppResult<crate::types::NacklRedeemRateResult> {
    let accumulator = ShellAccumulatorRootUsdc::new_default(tvm_client);

    let details = accumulator.get_details().await.map_err(|e| {
        crate::errors::AppError::from(e).with_context("get_nackl_redeem_rate: getDetails")
    })?;

    let nackl_info = accumulator.get_nackl_info().await.map_err(|e| {
        crate::errors::AppError::from(e).with_context("get_nackl_redeem_rate: getNacklInfo")
    })?;

    let redeemable_usdc = details.usdc_balance.saturating_sub(details.owed_total);
    let current_nackl_supply = nackl_info.supply.saturating_sub(nackl_info.burned);

    let usdc_per_nackl = if current_nackl_supply == 0 || redeemable_usdc == 0 {
        0
    } else {
        // Scale by 1e18 to preserve precision at low ratios.
        // Client divides by 1e18 to get micro-USDC per 1 nanoNACKL,
        // or by 1e9 to get micro-USDC per 1 whole NACKL.
        redeemable_usdc * 1_000_000_000_000_000_000 / current_nackl_supply
    };

    Ok(crate::types::NacklRedeemRateResult {
        redeemable_usdc,
        current_nackl_supply,
        usdc_per_nackl,
    })
}

/// Burns NACKL by sending ECC[1] to accumulator. Returns USDC proportional to
/// share of supply.
pub async fn redeem_nackl(
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    nackl_amount: u64,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    if nackl_amount == 0 {
        return Err(crate::errors::AppError::new("redeem_nackl: nackl_amount must be > 0"));
    }

    let ecc = HashMap::from([(NACKL_ECC_ID, nackl_amount)]);

    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: ShellAccumulatorRootUsdc::DEFAULT_ADDRESS.to_string(),
                epk_expire_at,
                value: 1_000_000_000,
                cc: ecc,
                bounce: bounce.unwrap_or(true),
                all_balance: false,
                ..Default::default()
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "Submit multifactor `{}` redeem_nackl transaction",
                multifactor.address()
            ))
        })?;

    crate::infra::ensure_tx_success(result, "submit_transaction (redeem_nackl)")
}

// Low-level token operation: send other tokens (non-native)
#[allow(clippy::too_many_arguments)]
pub async fn send_other_tokens(
    context: ContractContext,
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    destination_address: String,
    token_root: String,
    token_dapp: String,
    amount_raw: u64,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    let token_root = TokenRoot::new(
        context.clone(),
        crate::dapp::token_contract_params(token_root, token_dapp.as_str()),
    );
    let token_wallet_address_res = token_root
        .get_wallet_address(ParamsOfGetWalletAddress {
            owner_address: multifactor.address().to_string(),
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context(format!("get_wallet_address `{}`", multifactor.address()))
        })?;

    let token_wallet = TokenWallet::new(
        context.clone(),
        crate::dapp::token_contract_params(
            token_wallet_address_res.wallet_address,
            token_dapp.as_str(),
        ),
    );
    let result = token_wallet
        .deploy_transaction(
            ParamsOfDeployTransaction::from(Transaction::Transfer {
                value: amount_raw as u128,
                destination_owner: destination_address.clone(),
            }),
            signer.clone(),
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "deploy_transaction, token_wallet `{}`",
                token_wallet.address()
            ))
        })?;

    crate::infra::ensure_tx_success(result, "deploy_transaction (token wallet)")?;

    let res_of_tx_addr = token_wallet
        .get_transaction_address(ParamsOfGetTransactionAddress::from(Transaction::Transfer {
            value: amount_raw as u128,
            destination_owner: destination_address,
        }))
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "get_transaction_address, token_wallet `{}`",
                token_wallet.address()
            ))
        })?;

    let tx = TokenTransaction::new(
        context,
        crate::dapp::token_contract_params(res_of_tx_addr.transaction_address, token_dapp.as_str()),
    );
    tx.wait_account(ParamsOfWaitAccount::default()).await.map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context(format!("Wait for transaction `{}` active status", tx.address()))
    })?;

    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: tx.address().to_string(),
                epk_expire_at,
                value: 1_000_000_000,
                bounce: bounce.unwrap_or(true),
                all_balance: false,
                ..Default::default()
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context(format!("Submit multifactor `{}` transaction", multifactor.address()))
        })?;

    crate::infra::ensure_tx_success(result, "submit_transaction (send other tokens)")
}

/// Gas for Exchange callback chain (onTransferReceived → mint ECC[3] → send).
const EXCHANGE_CALLBACK_VALUE: u128 = 5_000_000_000;

/// Migrates TIP-3 USDC to ECC[3] via Exchange contract.
///
/// Sends TIP-3 USDC to Exchange (`0:1a1a...`), which triggers
/// `onTransferReceived` → mints ECC[3] → sends to sender.
#[allow(clippy::too_many_arguments)]
pub async fn migrate_tip3_usdc(
    context: ContractContext,
    multifactor: &Arc<Multifactor>,
    epk_expire_at: u64,
    token_root: String,
    token_dapp: String,
    amount_raw: u64,
    signer: Signer,
    bounce: Option<bool>,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    if amount_raw == 0 {
        return Err(crate::errors::AppError::new("migrate_tip3_usdc: amount_raw must be > 0"));
    }

    let exchange_address = Exchange::DEFAULT_ADDRESS;

    let token_root_contract = TokenRoot::new(
        context.clone(),
        crate::dapp::token_contract_params(token_root, token_dapp.as_str()),
    );
    let token_wallet_address_res = token_root_contract
        .get_wallet_address(ParamsOfGetWalletAddress {
            owner_address: multifactor.address().to_string(),
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context(format!("get_wallet_address `{}`", multifactor.address()))
        })?;

    let token_wallet = TokenWallet::new(
        context.clone(),
        crate::dapp::token_contract_params(
            token_wallet_address_res.wallet_address,
            token_dapp.as_str(),
        ),
    );

    let result = token_wallet
        .deploy_transaction(
            ParamsOfDeployTransaction::from(Transaction::Transfer {
                value: amount_raw as u128,
                destination_owner: exchange_address.to_string(),
            }),
            signer.clone(),
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "deploy_transaction, token_wallet `{}`",
                token_wallet.address()
            ))
        })?;

    crate::infra::ensure_tx_success(result, "deploy_transaction (migrate_tip3_usdc)")?;

    let res_of_tx_addr = token_wallet
        .get_transaction_address(ParamsOfGetTransactionAddress::from(Transaction::Transfer {
            value: amount_raw as u128,
            destination_owner: exchange_address.to_string(),
        }))
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "get_transaction_address, token_wallet `{}`",
                token_wallet.address()
            ))
        })?;

    let tx = TokenTransaction::new(
        context,
        crate::dapp::token_contract_params(res_of_tx_addr.transaction_address, token_dapp.as_str()),
    );
    tx.wait_account(ParamsOfWaitAccount::default()).await.map_err(|e| {
        crate::errors::AppError::from(e)
            .with_context(format!("Wait for transaction `{}` active status", tx.address()))
    })?;

    let result = multifactor
        .submit_transaction(
            ParamsOfSubmitTransaction {
                dest: tx.address().to_string(),
                epk_expire_at,
                value: EXCHANGE_CALLBACK_VALUE,
                bounce: bounce.unwrap_or(true),
                all_balance: false,
                ..Default::default()
            },
            signer,
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context(format!(
                "Submit multifactor `{}` migrate_tip3_usdc transaction",
                multifactor.address()
            ))
        })?;

    crate::infra::ensure_tx_success(result, "submit_transaction (migrate_tip3_usdc)")
}
