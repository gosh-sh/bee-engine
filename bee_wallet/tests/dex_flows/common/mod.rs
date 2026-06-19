//! Shared helpers for the wallet-coupled DEX flow tests. Each sub-module
//! owns one responsibility:
//!
//! - `context` — endpoint constants + `ClientContext` / `Dex` builders.
//! - `keys` — random keypair generation.
//! - `misc` — small utilities (time, account-active wait, balance read).
//! - `voucher` — `mint_voucher_via_multifactor` driving the live halo2 pipeline
//!   off a multifactor-wallet-emitted voucher event.
//! - `pn` — PrivateNote deploy / gas-funding helpers + `ensure_root_pn_funded`.
//! - `wallet` — multifactor-wallet helpers.
//!
//! Each test module imports the items it actually uses via
//! `use crate::common::<sub>::<item>;`.

pub mod context;
pub mod keys;
pub mod misc;
pub mod pn;
pub mod voucher;
pub mod wallet;
