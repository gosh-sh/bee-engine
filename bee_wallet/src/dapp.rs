//! Single source of truth for dApp IDs we must pass to the kit, plus helpers
//! for our OWN raw GraphQL queries that address an account.
//!
//! Since kit v4 the kit speaks only the `>= 1.0.0` GraphQL, which addresses
//! accounts by `account_id` + `dapp_id` — the server-generation probe
//! (`supports_dapp_id`) is gone and there is no legacy `account(address:)`
//! fallback left. A wrong dApp therefore fails the call outright
//! (`518 DappIdRequired` / query miss), so the real values live here.

use ackinacki_kit::contracts::account::ParamsOfNewContract;
use ackinacki_kit::contracts::dapp::SystemDapp;

/// Build `ParamsOfNewContract` for a TIP-3 token-family contract
/// (`TokenRoot` / `TokenWallet` / `TokenTransaction`) at `address`.
///
/// Each token has its OWN dApp, so there is no single correct constant — the
/// caller supplies `dapp_id` (it arrives from the API request next to the token
/// root).
pub fn token_contract_params(
    address: impl Into<String>,
    dapp_id: impl Into<String>,
) -> ParamsOfNewContract {
    ParamsOfNewContract::new(address, dapp_id)
}

/// dApp for DEX contracts (`RootPn` / `RootOracle` / `Oracle` / `PrivateNote` /
/// `Pmp` / ...).
///
/// Was a `System` placeholder while the kit had no DEX variant; kit v4 added
/// [`SystemDapp::Dex`] (`…0004`), which is the real value.
pub const DEX_DAPP: SystemDapp = SystemDapp::Dex;

/// Build `ParamsOfNewContract` for a DEX-family contract at `address`.
pub fn dex_contract_params(address: impl Into<String>) -> ParamsOfNewContract {
    ParamsOfNewContract::new(address, DEX_DAPP)
}

/// Bare account-id for the `account_id` GraphQL arg: drops the `"0:"`
/// workchain prefix (`"0:hex"` -> `"hex"`). Mirrors the kit's private
/// `account_id_from_address`.
pub fn account_id(address: &str) -> &str {
    address.rsplit_once(':').map(|(_, id)| id).unwrap_or(address)
}
