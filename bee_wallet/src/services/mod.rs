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
// isn't exposed on wasm.
#[cfg(not(target_arch = "wasm32"))]
pub mod dex;
pub mod miner;
pub mod multifactor;
pub mod resolvers;
pub mod tokens;
pub mod transaction;
pub mod validate_name;
pub mod zkp;
