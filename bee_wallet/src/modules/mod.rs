//! Domain orchestration layer.
//!
//! Responsibilities:
//! - compose multi-step wallet scenarios;
//! - call service helpers and infra primitives;
//! - define operation boundaries visible to adapters/API.
//!
//! Non-responsibilities:
//! - low-level crypto/math utils;
//! - direct data-shape conversion for transport DTOs.

pub(crate) mod balance;
pub(crate) mod connect;
pub(crate) mod deploy;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod dex;
pub(crate) mod history;
pub(crate) mod miner;
pub(crate) mod multifactor;
pub mod names; /* pub because ResultOfValidateWalletName and WalletNameErrorCode are
                * re-exported from lib.rs */
pub(crate) mod tokens;
pub(crate) mod zkp;
