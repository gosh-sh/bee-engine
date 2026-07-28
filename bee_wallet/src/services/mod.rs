//! Thin service/helper layer.
//!
//! Responsibilities:
//! - encapsulate reusable domain helpers and contract call helpers;
//! - keep logic focused and composable for modules.
//!
//! Non-responsibilities:
//! - cross-domain orchestration of full user flows (belongs to `modules`);
//! - transport/API shape ownership (belongs to adapters/types).

pub mod balance;
pub mod boost;
pub mod connect;
pub mod deploy;
// DEX wrappers live in `dodex-contracts` (native-only dep); voucher generation
// isn't exposed on wasm. Behind the `dex` feature while dodex is a kit major
// behind us — see the feature's comment in Cargo.toml.
#[cfg(all(not(target_arch = "wasm32"), feature = "dex"))]
pub mod dex;
pub mod miner;
pub mod multifactor;
pub mod multisig;
pub mod resolvers;
pub mod tokens;
pub mod transaction;
pub mod validate_name;
pub mod zkp;
