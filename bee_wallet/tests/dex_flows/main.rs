//! Wallet-coupled full-flow DEX integration tests against shellnet.
//!
//! These are the two multifactor flows that exercise **bee-wallet together
//! with the DEX façade** — a real multifactor wallet drives the voucher
//! cycle, halo2 proves against the wallet-emitted event, and the DEX
//! (`dodex-sdk`, imported as a git dev-dependency) consumes the proof. They
//! live here because they straddle the wallet↔DEX seam and so can't move out
//! to `dodex-backend` (which has no bee-wallet). The rest of the DEX
//! integration suite lives in `dodex-backend/sdk/tests`.
//!
//! - `common/` — shared helpers (network context, key generation, voucher
//!   pipeline, PN deploy/gas, multifactor wallet).
//! - `flows` — the two multifactor end-to-end flows.
//!
//! Run (needs SSH access to the halo2 kit + local halo2 params; see
//! `PARAMS_DIR` / `HALO2_PK_CACHE` defaults in `Halo2Paths::from_env`):
//!   cargo test -p bee-wallet --test dex_flows -- --nocapture --test-threads=1

// `common/` is a shared helper module: each test uses a subset, so some
// helpers are unused from any single flow's point of view.
#![allow(dead_code)]
// Native-only (heavy halo2 + dodex-sdk graph). Empty crate on wasm32 so
// `wasm-pack test --tests` doesn't try to build it.
#![cfg(not(target_arch = "wasm32"))]

mod common;
mod flows;
