#![doc = include_str!("../README.md")]

mod adapters;
mod client;
mod services;

/// Error and result types used by `bee_crypto`.
pub mod errors;

/// Native crypto client API.
pub use adapters::native::Crypto;
/// Wasm adapter namespace (available with `wasm` feature).
#[cfg(feature = "wasm")]
pub use adapters::wasm;
