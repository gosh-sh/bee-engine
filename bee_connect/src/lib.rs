//! Client-side helpers for AckiNacki wallet connect flows over `authservice`.
//!
//! The crate currently provides:
//! - `shared_key` (both sides write to a shared-session profile)
//! - protocol helpers for `wallet_hello`, `set_mining_keys`,
//!   `client_disconnect`, `sign_challenge`, `challenge_response`

mod client;
pub mod dex_protocol;
pub mod dh;
pub mod errors;
pub mod message;

pub use client::decode_connect_payload_b64url;
pub use client::ActiveConnectSession;
pub use client::ChallengeResponseBody;
pub use client::ConnectClient;
pub use client::ConnectPayload;
pub use client::ParamsOfCreateSharedKeySession;
pub use client::ParamsOfDisconnectSession;
pub use client::ParamsOfQueryActiveSessionsByMultifactor;
pub use client::ParamsOfRequestSetMiningKeys;
pub use client::ParamsOfRequestSignChallenge;
pub use client::ParamsOfResolveProfileAddress;
pub use client::ParamsOfWaitChallengeResponse;
pub use client::ParamsOfWaitSetMiningKeysRequest;
pub use client::ParamsOfWaitWalletHello;
pub use client::ResultOfCreateSharedKeySession;
pub use client::ResultOfDisconnectSession;
pub use client::ResultOfQueryActiveSessionsByMultifactor;
pub use client::ResultOfRequestSetMiningKeys;
pub use client::ResultOfRequestSignChallenge;
pub use client::ResultOfWaitChallengeResponse;
pub use client::ResultOfWaitSetMiningKeysRequest;
pub use client::ResultOfWaitWalletHello;
pub use client::SignChallengeBody;
pub use client::WalletHelloMetadata;
pub use dh::ConnectSessionState;
pub use dh::DhKeyPair;
pub use dh::DhSessionKeys;
pub use dh::RekeyResult;
pub use dh::DEFAULT_SESSION_TTL_SECS;

#[cfg(feature = "wasm")]
pub mod wasm;
