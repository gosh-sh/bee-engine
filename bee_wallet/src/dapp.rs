//! Single source of truth for dApp IDs we must pass to the v3 kit, plus helpers
//! for our OWN raw GraphQL queries that address an account.
//!
//! On gql-server `< 1.0.0` (current shellnet/mainnet) `dapp_id` is ignored, so
//! a wrong value is harmless *today* — but it travels into the GraphQL query on
//! `>= 1.0.0` servers, where a wrong/placeholder dApp makes account-bearing
//! calls fail (`518 DappIdRequired` / query miss). Keep the real values here so
//! flipping them later is a one-line change, not a repo-wide hunt.

use std::sync::Arc;

use ackinacki_kit::contracts::account::ParamsOfNewContract;
use ackinacki_kit::contracts::dapp::supports_dapp_id;
use ackinacki_kit::contracts::dapp::SystemDapp;
use ackinacki_kit::contracts::error::KitModule;
use ackinacki_kit::tvm_client::ClientContext;

use crate::errors::AppError;
use crate::errors::AppResult;

/// Build `ParamsOfNewContract` for a TIP-3 token-family contract
/// (`TokenRoot` / `TokenWallet` / `TokenTransaction`) at `address`.
///
/// Each token has its OWN dApp, so there is no single correct constant — the
/// caller supplies `dapp_id` (it arrives from the API request next to the token
/// root). Ignored on `< 1.0.0` servers; must be the token's real dApp on
/// `>= 1.0.0`.
pub fn token_contract_params(
    address: impl Into<String>,
    dapp_id: impl Into<String>,
) -> ParamsOfNewContract {
    ParamsOfNewContract::new(address, dapp_id)
}

/// dApp for DEX contracts (`RootPn` / `RootOracle` / `Oracle` / `PrivateNote` /
/// `Pmp` / ...).
///
/// TODO(dapp): DEX dApp is **UNCONFIRMED**. The kit dropped its `System`
/// placeholder for DEX (`new_default` removed — "Skip dex defaults"), so we
/// pass it explicitly. Same deal as [`TOKEN_DAPP`]: harmless on `< 1.0.0`, must
/// be the real value before any `>= 1.0.0` server.
pub const DEX_DAPP: SystemDapp = SystemDapp::System;

/// Build `ParamsOfNewContract` for a DEX-family contract at `address`.
pub fn dex_contract_params(address: impl Into<String>) -> ParamsOfNewContract {
    ParamsOfNewContract::new(address, DEX_DAPP)
}

/// Whether the server reached via `ctx` speaks the v3 (`>= 1.0.0`) GraphQL that
/// addresses accounts by `account_id` + `dapp_id` instead of legacy
/// `account(address:)`.
///
/// Use this to pick the query form for our OWN raw `net::query` calls — the
/// kit's own contract methods switch internally and need no help. The SDK
/// caches the parsed server version on the endpoint, so call it ONCE and hoist
/// the result out of paging loops.
pub async fn server_uses_dapp_id(ctx: &Arc<ClientContext>) -> AppResult<bool> {
    supports_dapp_id(ctx, KitModule::Event)
        .await
        .map_err(|e| AppError::from(e).with_context("detect GraphQL server version"))
}

/// Bare account-id for the v3 `account_id` GraphQL arg: drops the `"0:"`
/// workchain prefix (`"0:hex"` -> `"hex"`). Mirrors the kit's private
/// `account_id_from_address`.
pub fn account_id(address: &str) -> &str {
    address.rsplit_once(':').map(|(_, id)| id).unwrap_or(address)
}
