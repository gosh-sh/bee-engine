use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
use std::time::SystemTime;
#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
use std::time::UNIX_EPOCH;

use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::authservice::profile::AuthProfile;
use ackinacki_kit::contracts::authservice::profile::ParamsOfQueryProfileEvents;
use ackinacki_kit::contracts::authservice::root::AuthServiceRoot;
use ackinacki_kit::contracts::authservice::root::ParamsOfQueryProfilesByMultifactor;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::ContextAccessor;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde::Serialize;

use crate::message::connect_message_aad;
use crate::message::decrypt_connect_body;
use crate::message::encrypt_connect_body;
use crate::message::normalize_owner_public_hex;
use crate::message::normalize_uint256_hex;
use crate::message::CONNECT_DEEPLINK_VERSION;
use crate::message::CONNECT_MESSAGE_ENC_NONE;
use crate::message::CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256;
use crate::message::CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE;
use crate::message::CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT;
use crate::message::CONNECT_MESSAGE_TYPE_SET_MINING_KEYS;
use crate::message::CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE;
use crate::message::CONNECT_MESSAGE_TYPE_WALLET_HELLO;
use crate::message::CONNECT_MESSAGE_VERSION;

const CONNECT_DEEPLINK_RESOLVER_URL: &str = "https://links.gosh.sh";
const CONNECT_DEEPLINK_PATH: &str = "/deeplinks/wallet/v1/connect";
const DEFAULT_CONNECT_TTL_SECS: u64 = 300;
const ACTIVE_SESSIONS_CHUNK_SIZE: u32 = 10;
const CONNECT_DESCRIPTION_PREFIX: &str = "bee_connect:";
const CONNECT_DESCRIPTION_VERSION: &str = "v1";

#[derive(Debug, Clone, Default)]
pub struct ConnectClient {
    rate_limiter: Option<bee_infra::RateLimiter>,
    /// Optional BM API token, threaded into every `ClientContext` this client
    /// builds (see `root_with_endpoints`). `None` → anonymous requests, which
    /// is the intended default for the wasm/browser path (token is optional
    /// there). Native callers set it via [`ConnectClient::with_api_token`].
    api_token: Option<String>,
}

/// Parameters for creating a bidirectional `shared_key` connect session.
///
/// The client generates an ephemeral X25519 DH keypair. Only the public key
/// is included in the deeplink URL. The wallet will generate its own DH keypair
/// and both sides derive shared session keys via Diffie-Hellman key agreement.
#[derive(Debug, Clone)]
pub struct ParamsOfCreateSharedKeySession {
    /// dApp identifier as `uint256` hex string (`0x...` or raw hex).
    pub app_id: String,
    /// Session TTL in seconds. Defaults to a short connect timeout.
    pub ttl_secs: Option<u64>,
    /// Optional challenge nonce (hex). When present, it is embedded in the
    /// deeplink payload so the wallet can sign it and include the signature
    /// in `wallet_hello`. This eliminates the separate `sign_challenge` /
    /// `challenge_response` roundtrip.
    pub nonce: Option<String>,
}

/// Result of creating a `shared_key` connect session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfCreateSharedKeySession {
    /// Connect session identifier used in all protocol messages.
    pub session_id: String,
    /// Random profile description used to deterministically derive profile
    /// address.
    pub description: String,
    /// Session creation timestamp (unix seconds).
    pub created_at: u64,
    /// Session expiration timestamp (unix seconds).
    pub expires_at: u64,
    /// Normalized `app_id` (`0x` + 64 lowercase hex chars).
    pub app_id: String,
    /// Payload JSON before base64url encoding.
    pub payload_json: String,
    /// Deeplink URL for opening the wallet app. Contains only
    /// `client_dh_public` — no secrets.
    pub deep_link: String,
    /// Base64url-encoded payload for QR transfer / app bridge.
    pub payload_b64url: String,
    /// Client X25519 DH public key (hex). Transmitted in the deeplink URL.
    pub client_dh_public: String,
    /// Client X25519 DH secret key (hex). Caller MUST store this for DH
    /// finalization in `wait_wallet_hello`. NEVER transmitted.
    pub client_dh_secret: String,
}

/// Parameters for resolving a deterministic `AuthProfile` address by
/// `description`.
#[derive(Debug, Clone)]
pub struct ParamsOfResolveProfileAddress {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Connect profile description (rendezvous id).
    pub description: String,
}

/// Parameters for waiting for the first wallet message (`wallet_hello`).
#[derive(Debug, Clone)]
pub struct ParamsOfWaitWalletHello {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Session id that must match the received message envelope.
    pub session_id: String,
    /// Connect profile description used to resolve the profile address.
    pub description: String,
    /// Client X25519 DH secret key (hex) from `create_shared_key_session`.
    /// Used to compute shared secret with wallet's DH public key from
    /// wallet_hello.
    pub client_dh_secret: String,
    /// Optional lower bound for event timestamps (unix seconds).
    pub created_at_from: Option<u64>,
    /// Polling attempts for profile activation and event lookup.
    pub max_attempts: Option<u32>,
    /// Polling interval in milliseconds.
    pub interval_ms: Option<u64>,
}

/// Parameters for sending a client-side disconnect request.
#[derive(Debug, Clone)]
pub struct ParamsOfDisconnectSession {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Session id that must be included in the message envelope.
    pub session_id: String,
    /// Connect profile description used to resolve the profile address.
    pub description: String,
    /// Current session state (signing keys, encryption root, DH keys).
    pub session_state: crate::dh::ConnectSessionState,
    /// Optional disconnect reason.
    pub reason: Option<String>,
    /// Polling attempts for profile activation.
    pub max_attempts: Option<u32>,
    /// Polling interval in milliseconds.
    pub interval_ms: Option<u64>,
}

/// Parameters for sending `set_mining_keys` request from client to wallet.
#[derive(Debug, Clone)]
pub struct ParamsOfRequestSetMiningKeys {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Session id that must be included in the message envelope.
    pub session_id: String,
    /// Connect profile description used to resolve the profile address.
    pub description: String,
    /// Current session state (signing keys, encryption root, DH keys).
    pub session_state: crate::dh::ConnectSessionState,
    /// Miner app id (`uint256` hex string).
    pub app_id: String,
    /// Mining owner public key (hex).
    pub owner_public: String,
    /// Polling attempts for profile activation.
    pub max_attempts: Option<u32>,
    /// Polling interval in milliseconds.
    pub interval_ms: Option<u64>,
}

/// Parameters for querying active connect sessions by multifactor wallet.
#[derive(Debug, Clone)]
pub struct ParamsOfQueryActiveSessionsByMultifactor {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Multifactor wallet address.
    pub multifactor_address: String,
    /// Optional `app_id` filter (`uint256` hex string).
    ///
    /// If set, only sessions with successfully parsed matching `app_id` are
    /// returned. Malformed descriptions (`app_id = None`) are skipped.
    pub app_id: Option<String>,
    /// Optional lower bound for deploy event timestamps (unix seconds).
    pub created_at_from: Option<u64>,
    /// Reverse-pagination cursor for next chunk.
    pub before: Option<String>,
}

/// One active connect session resolved from `AuthProfileDeployed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnectSession {
    /// AuthProfile address.
    pub profile_address: String,
    /// Connect description (`bee_connect:v1:<app_id>:<session_id>:...`).
    pub description: String,
    /// Parsed `app_id` from description (`bee_connect:v1:<app_id>:...`).
    ///
    /// `None` means description doesn't match current protocol format.
    pub app_id: Option<String>,
    /// Parsed `session_id` from description (if parseable).
    pub session_id: Option<String>,
    /// GraphQL event id of `AuthProfileDeployed`.
    pub deployed_event_id: String,
    /// Deploy event timestamp (unix seconds).
    pub deployed_at: u64,
}

/// Result page for active connect sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfQueryActiveSessionsByMultifactor {
    /// Active sessions (at most 10 per call).
    pub sessions: Vec<ActiveConnectSession>,
    /// Cursor for the next page request.
    pub next_before: Option<String>,
    /// `true` means there are no more active connect sessions in older pages.
    pub exhausted_active: bool,
}

/// Wallet metadata received in the first `wallet_hello` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletHelloMetadata {
    /// Human-readable wallet name.
    pub wallet_name: String,
    /// Wallet account address shown to the dApp.
    pub wallet_address: String,
}

/// Result returned when the dApp receives the first `wallet_hello`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfWaitWalletHello {
    /// Resolved `AuthProfile` address.
    pub profile_address: String,
    /// GraphQL event id of the matched `ContextAdded` event.
    pub event_id: String,
    /// Event timestamp (unix seconds).
    pub event_created_at: u64,
    /// Wallet name from the `wallet_hello` body.
    pub wallet_name: String,
    /// Wallet address from the `wallet_hello` body.
    pub wallet_address: String,
    /// Raw JSON envelope received from the chain.
    pub raw_message_json: String,
    /// Initial session state after DH key exchange.
    /// Contains signing keys, encryption root, and DH keys.
    /// Caller MUST persist this for subsequent operations.
    pub session_state: crate::dh::ConnectSessionState,
    /// Inline challenge nonce (present when the wallet responded to a nonce in
    /// the deeplink).
    pub nonce: Option<String>,
    /// Inline challenge signature (present when the wallet signed the nonce).
    pub signature: Option<String>,
    /// EPK public key used to sign the nonce (hex).
    pub epk_public: Option<String>,
}

/// Result of sending `client_disconnect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfDisconnectSession {
    /// Resolved `AuthProfile` address.
    pub profile_address: String,
    /// Outbound message hash returned by TVM processing (if available).
    pub message_id: Option<String>,
    /// Raw JSON envelope sent to the chain.
    pub raw_message_json: String,
    /// Updated session state after DH re-key. Caller MUST persist this.
    pub updated_session_state: crate::dh::ConnectSessionState,
}

/// Result of sending `set_mining_keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfRequestSetMiningKeys {
    /// Resolved `AuthProfile` address.
    pub profile_address: String,
    /// Outbound message hash returned by TVM processing (if available).
    pub message_id: Option<String>,
    /// Normalized `app_id`.
    pub app_id: String,
    /// Normalized mining owner public key (lowercase hex without `0x`).
    pub owner_public: String,
    /// Raw JSON envelope sent to the chain.
    pub raw_message_json: String,
    /// Updated session state after DH re-key. Caller MUST persist this.
    pub updated_session_state: crate::dh::ConnectSessionState,
}

/// Parameters for waiting `set_mining_keys` request (wallet-side poll helper).
#[derive(Debug, Clone)]
pub struct ParamsOfWaitSetMiningKeysRequest {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Session id that must match the received message envelope.
    pub session_id: String,
    /// Connect profile description used to resolve the profile address.
    pub description: String,
    /// Session state for decrypting and re-keying incoming messages.
    pub session_state: Option<crate::dh::ConnectSessionState>,
    /// Optional lower bound for event timestamps (unix seconds).
    pub created_at_from: Option<u64>,
    /// Polling attempts for profile activation and event lookup.
    pub max_attempts: Option<u32>,
    /// Polling interval in milliseconds.
    pub interval_ms: Option<u64>,
}

/// Result of waiting `set_mining_keys` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfWaitSetMiningKeysRequest {
    /// Resolved `AuthProfile` address.
    pub profile_address: String,
    /// GraphQL event id of the matched `ContextAdded` event.
    pub event_id: String,
    /// Event timestamp (unix seconds).
    pub event_created_at: u64,
    /// Normalized `app_id`.
    pub app_id: String,
    /// Normalized mining owner public key.
    pub owner_public: String,
    /// Raw JSON envelope received from the chain.
    pub raw_message_json: String,
    /// Updated session state after re-keying. Caller SHOULD persist this.
    /// `None` if no `session_state` was provided in params.
    pub updated_session_state: Option<crate::dh::ConnectSessionState>,
}

/// Parameters for sending `sign_challenge` request from client to wallet.
///
/// The client (dApp backend) generates a random nonce and asks the wallet to
/// sign it with the multifactor's EPK key. The resulting signature proves
/// wallet ownership to the backend.
#[derive(Debug, Clone)]
pub struct ParamsOfRequestSignChallenge {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Session id that must be included in the message envelope.
    pub session_id: String,
    /// Connect profile description used to resolve the profile address.
    pub description: String,
    /// Current session state (signing keys, encryption root, DH keys).
    pub session_state: crate::dh::ConnectSessionState,
    /// Random nonce generated by the backend (hex string).
    pub nonce: String,
    /// Polling attempts for profile activation.
    pub max_attempts: Option<u32>,
    /// Polling interval in milliseconds.
    pub interval_ms: Option<u64>,
}

/// Result of sending `sign_challenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfRequestSignChallenge {
    /// Resolved `AuthProfile` address.
    pub profile_address: String,
    /// Outbound message hash returned by TVM processing (if available).
    pub message_id: Option<String>,
    /// Nonce that was sent (echoed back for convenience).
    pub nonce: String,
    /// Raw JSON envelope sent to the chain.
    pub raw_message_json: String,
    /// Updated session state after DH re-key. Caller MUST persist this.
    pub updated_session_state: crate::dh::ConnectSessionState,
    /// Timestamp (unix seconds) when the challenge was sent.
    /// Use as `created_at_from` in `wait_challenge_response` for precise event
    /// filtering.
    pub sent_at: u64,
}

/// Parameters for waiting `challenge_response` from wallet (client-side poll).
#[derive(Debug, Clone)]
pub struct ParamsOfWaitChallengeResponse {
    /// TVM RPC endpoints used to create a client context.
    pub endpoints: Vec<String>,
    /// Session id that must match the received message envelope.
    pub session_id: String,
    /// Connect profile description used to resolve the profile address.
    pub description: String,
    /// Session state for decrypting and re-keying incoming messages.
    pub session_state: Option<crate::dh::ConnectSessionState>,
    /// Optional lower bound for event timestamps (unix seconds).
    pub created_at_from: Option<u64>,
    /// Polling attempts for profile activation and event lookup.
    pub max_attempts: Option<u32>,
    /// Polling interval in milliseconds.
    pub interval_ms: Option<u64>,
}

/// Result of waiting `challenge_response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfWaitChallengeResponse {
    /// Resolved `AuthProfile` address.
    pub profile_address: String,
    /// GraphQL event id of the matched `ContextAdded` event.
    pub event_id: String,
    /// Event timestamp (unix seconds).
    pub event_created_at: u64,
    /// The nonce that was signed.
    pub nonce: String,
    /// Ed25519 signature of the nonce (hex).
    pub signature: String,
    /// Wallet address that signed the challenge.
    pub wallet_address: String,
    /// EPK public key used to sign the nonce (hex).
    /// `None` if the wallet uses an older protocol version without this field.
    pub epk_public: Option<String>,
    /// Raw JSON envelope received from the chain.
    pub raw_message_json: String,
    /// Updated session state after re-keying. Caller SHOULD persist this.
    /// `None` if no `session_state` was provided in params.
    pub updated_session_state: Option<crate::dh::ConnectSessionState>,
}

/// Body of `sign_challenge` message (c2w).
/// Sent by the dApp to ask the wallet to sign a nonce for backend auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignChallengeBody {
    /// Random hex nonce generated by the backend.
    pub nonce: String,
}

/// Body of `challenge_response` message (w2c).
/// Sent by the wallet in response to `sign_challenge`.
/// Backend verifies the signature to confirm wallet ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponseBody {
    /// Echoed nonce from the challenge.
    pub nonce: String,
    /// Ed25519 detached signature of the nonce (hex).
    pub signature: String,
    /// Multifactor address of the signing wallet.
    pub wallet_address: String,
    /// EPK public key used to sign the nonce (hex, 64 chars).
    /// Backend uses this to verify the signature and then confirms
    /// the key is registered in the multifactor contract via
    /// `get_epk_expire_at(wallet_address, epk_public)`.
    #[serde(default)]
    pub epk_public: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPayload {
    pub v: String,
    pub session_id: String,
    pub description: String,
    pub expires_at: u64,
    pub app_id: String,
    /// Optional challenge nonce for inline wallet ownership verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectMessageEnvelope {
    v: String,
    session_id: String,
    dir: String,
    seq: u64,
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    ts: Option<u64>,
    #[serde(default)]
    dh_public: Option<String>,
    #[serde(default)]
    enc: Option<ConnectMessageEnc>,
    #[serde(default)]
    body: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectMessageEnc {
    alg: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    salt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletHelloBody {
    wallet_name: String,
    wallet_address: String,
    /// Signed nonce (inline challenge response).
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    epk_public: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetMiningKeysBody {
    app_id: String,
    owner_public: String,
}

impl ConnectClient {
    /// Creates a new client-side helper for `bee_connect`.
    pub fn new() -> Self {
        Self { rate_limiter: None, api_token: None }
    }

    /// Creates a client with rate limiting (max requests per second).
    pub fn with_rate_limit(max_rps: u32) -> Self {
        Self { rate_limiter: Some(bee_infra::RateLimiter::new(max_rps)), api_token: None }
    }

    /// Sets the BM API token used for all requests this client makes.
    /// Chainable with [`Self::new`] / [`Self::with_rate_limit`], e.g.
    /// `ConnectClient::with_rate_limit(rps).with_api_token(token)`. Native
    /// apps pass `Some(BM_API_TOKEN)`; the wasm/browser path leaves it unset.
    pub fn with_api_token(mut self, api_token: Option<String>) -> Self {
        self.api_token = api_token;
        self
    }

    async fn acquire(&self) {
        bee_infra::maybe_acquire(self.rate_limiter.as_ref()).await;
    }

    /// Small health-check helper for integration smoke tests.
    pub fn ping(&self) -> &'static str {
        "bee_connect:stub"
    }

    /// Decodes and validates base64url connect payload (`payload` query
    /// value).
    pub fn decode_connect_payload_b64url(
        &self,
        payload_b64url: impl AsRef<str>,
    ) -> Result<ConnectPayload, crate::errors::AppError> {
        decode_connect_payload_b64url(payload_b64url)
    }

    /// Creates a `shared_key` session and generates an ephemeral X25519 DH
    /// keypair.
    ///
    /// The returned `client_dh_public` is included in the deeplink URL.
    /// The returned `client_dh_secret` MUST be stored by the caller and passed
    /// to `wait_wallet_hello` for DH key agreement.
    ///
    /// **No secrets are transmitted in the URL.**
    pub fn create_shared_key_session(
        &self,
        params: ParamsOfCreateSharedKeySession,
    ) -> Result<ResultOfCreateSharedKeySession, crate::errors::AppError> {
        let common = self.create_session_common(params.app_id, params.ttl_secs, params.nonce)?;
        let dh_keypair = crate::dh::generate_dh_keypair()?;
        let deep_link = format!(
            "{CONNECT_DEEPLINK_RESOLVER_URL}{CONNECT_DEEPLINK_PATH}?payload={}&client_dh_public={}",
            common.payload_b64url, dh_keypair.public_hex
        );

        Ok(ResultOfCreateSharedKeySession {
            session_id: common.session_id,
            description: common.description,
            created_at: common.created_at,
            expires_at: common.expires_at,
            app_id: common.app_id,
            payload_json: common.payload_json,
            deep_link,
            payload_b64url: common.payload_b64url,
            client_dh_public: dh_keypair.public_hex,
            client_dh_secret: dh_keypair.secret_hex.to_string(),
        })
    }

    /// Resolves deterministic `AuthProfile` address from a connect
    /// `description`.
    pub async fn get_profile_address(
        &self,
        params: ParamsOfResolveProfileAddress,
    ) -> Result<String, crate::errors::AppError> {
        self.acquire().await;
        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let result = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description,
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?;
        Ok(result.profile)
    }

    /// Checks whether session profile resolved from `description` is currently
    /// deployed on chain.
    pub async fn is_session_profile_deployed(
        &self,
        params: ParamsOfResolveProfileAddress,
    ) -> Result<bool, crate::errors::AppError> {
        self.acquire().await;
        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description,
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        Ok(profile.is_deployed().await)
    }

    /// Waits until the wallet deploys the profile and sends the first
    /// `wallet_hello`.
    ///
    /// Validates message envelope fields:
    /// - `v = bee_connect.msg/1`
    /// - `dir = w2c`
    /// - `seq > 0`
    /// - `type = wallet_hello`
    /// - `dh_public` present (wallet X25519 public key)
    /// - `session_id` matches the requested session
    ///
    /// Performs DH key agreement using `client_dh_secret` and wallet's
    /// `dh_public` from the envelope, derives session signing and encryption
    /// keys, and decrypts the `wallet_hello` body.
    pub async fn wait_wallet_hello(
        &self,
        params: ParamsOfWaitWalletHello,
    ) -> Result<ResultOfWaitWalletHello, crate::errors::AppError> {
        self.acquire().await;
        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description.clone(),
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        wait_profile_active(&profile, params.max_attempts, params.interval_ms).await?;

        let created_at_from = params
            .created_at_from
            .unwrap_or_else(|| now_secs().unwrap_or_default().saturating_sub(300));

        let client_dh_secret = params.client_dh_secret.clone();
        let rl = self.rate_limiter.clone();
        let found = bee_infra::poll_until(
            || {
                let profile = profile.clone();
                let session_id = params.session_id.clone();
                let client_dh_secret = client_dh_secret.clone();
                let rl = rl.clone();
                async move {
                    bee_infra::maybe_acquire(rl.as_ref()).await;
                    find_wallet_hello_event(
                        &profile,
                        &session_id,
                        &client_dh_secret,
                        created_at_from,
                    )
                    .await
                    .map_err(|e| e.with_context("Query wallet_hello"))
                }
            },
            |found| found.is_some(),
            params.max_attempts,
            params.interval_ms,
        )
        .await?
        .ok_or_else(|| "wait_wallet_hello: no wallet_hello event found".to_string())?;

        Ok(ResultOfWaitWalletHello {
            profile_address,
            event_id: found.event_id,
            event_created_at: found.event_created_at,
            wallet_name: found.wallet_name,
            wallet_address: found.wallet_address,
            raw_message_json: found.raw_message_json,
            session_state: found.session_state,
            nonce: found.nonce,
            signature: found.signature,
            epk_public: found.epk_public,
        })
    }

    /// Waits until client->wallet `set_mining_keys` request is written to
    /// profile context.
    pub async fn wait_set_mining_keys_request(
        &self,
        params: ParamsOfWaitSetMiningKeysRequest,
    ) -> Result<ResultOfWaitSetMiningKeysRequest, crate::errors::AppError> {
        self.acquire().await;
        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description.clone(),
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        wait_profile_active(&profile, params.max_attempts, params.interval_ms).await?;

        let created_at_from = params
            .created_at_from
            .unwrap_or_else(|| now_secs().unwrap_or_default().saturating_sub(300));

        let rl = self.rate_limiter.clone();
        let found = bee_infra::poll_until(
            || {
                let profile = profile.clone();
                let session_id = params.session_id.clone();
                let session_state = params.session_state.clone();
                let rl = rl.clone();
                async move {
                    bee_infra::maybe_acquire(rl.as_ref()).await;
                    find_set_mining_keys_event(
                        &profile,
                        &session_id,
                        session_state.as_ref(),
                        created_at_from,
                    )
                    .await
                    .map_err(|e| e.with_context("Query set_mining_keys"))
                }
            },
            |found| found.is_some(),
            params.max_attempts,
            params.interval_ms,
        )
        .await?
        .ok_or_else(|| {
            "wait_set_mining_keys_request: no set_mining_keys event found".to_string()
        })?;

        Ok(ResultOfWaitSetMiningKeysRequest {
            profile_address,
            event_id: found.event_id,
            event_created_at: found.event_created_at,
            app_id: found.app_id,
            owner_public: found.owner_public,
            raw_message_json: found.raw_message_json,
            updated_session_state: found.updated_session_state,
        })
    }

    /// Sends `client_disconnect` (`dir = c2w`, `type = client_disconnect`) to
    /// the connected profile using shared session owner keys.
    pub async fn disconnect_session(
        &self,
        params: ParamsOfDisconnectSession,
    ) -> Result<ResultOfDisconnectSession, crate::errors::AppError> {
        self.acquire().await;
        if params.session_id.trim().is_empty() {
            return Err("disconnect_session session_id is empty".to_string().into());
        }

        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description,
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        wait_profile_active(&profile, params.max_attempts, params.interval_ms).await?;

        let body = params
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|reason| serde_json::json!({ "reason": reason }))
            .unwrap_or_else(|| serde_json::json!({}));

        // DH re-key for forward secrecy
        let seq = params.session_state.next_outbound_seq().map_err(|e| {
            crate::errors::AppError::from(e).with_context("disconnect_session next_outbound_seq")
        })?;
        let rekey = crate::dh::rekey_outbound(&params.session_state, &params.session_id, seq)
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("disconnect_session rekey_outbound")
            })?;

        let signing_keys = KeyPair {
            public: params.session_state.signing_public.clone(),
            secret: params.session_state.signing_secret.to_string(),
        };

        let raw_message_json = encode_connect_message(
            &params.session_id,
            "c2w",
            rekey.outbound_seq,
            CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT,
            body,
            Some(&rekey.message_encryption_root),
            rekey.new_dh_public.as_deref(),
        )?;
        let send_result = profile
            .add_context_text(&raw_message_json, Signer::Keys { keys: signing_keys })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthProfile::add_context_text client_disconnect")
            })?;
        let send_result = ensure_tx_success(send_result, "client_disconnect add_context")?;

        Ok(ResultOfDisconnectSession {
            profile_address,
            message_id: send_result.message_hash,
            raw_message_json,
            updated_session_state: rekey.updated_state,
        })
    }

    /// Sends `set_mining_keys` (`dir = c2w`) to the connected profile.
    ///
    /// Wallet app can read this request and execute
    /// `bee_wallet.set_mining_keys`.
    pub async fn request_set_mining_keys(
        &self,
        params: ParamsOfRequestSetMiningKeys,
    ) -> Result<ResultOfRequestSetMiningKeys, crate::errors::AppError> {
        self.acquire().await;
        if params.session_id.trim().is_empty() {
            return Err("request_set_mining_keys session_id is empty".to_string().into());
        }

        let app_id = normalize_uint256_hex(&params.app_id)?;
        let owner_public = normalize_owner_public_hex(&params.owner_public)?;

        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description,
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        wait_profile_active(&profile, params.max_attempts, params.interval_ms).await?;

        let body = serde_json::to_value(SetMiningKeysBody {
            app_id: app_id.clone(),
            owner_public: owner_public.clone(),
        })
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("Serialize set_mining_keys body")
        })?;
        // DH re-key for forward secrecy
        let seq = params.session_state.next_outbound_seq().map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("request_set_mining_keys next_outbound_seq")
        })?;
        let rekey = crate::dh::rekey_outbound(&params.session_state, &params.session_id, seq)
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("request_set_mining_keys rekey_outbound")
            })?;

        let signing_keys = KeyPair {
            public: params.session_state.signing_public.clone(),
            secret: params.session_state.signing_secret.to_string(),
        };

        let raw_message_json = encode_connect_message(
            &params.session_id,
            "c2w",
            rekey.outbound_seq,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            body,
            Some(&rekey.message_encryption_root),
            rekey.new_dh_public.as_deref(),
        )?;
        let send_result = profile
            .add_context_text(&raw_message_json, Signer::Keys { keys: signing_keys })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthProfile::add_context_text set_mining_keys")
            })?;
        let send_result = ensure_tx_success(send_result, "set_mining_keys add_context")?;

        Ok(ResultOfRequestSetMiningKeys {
            profile_address,
            message_id: send_result.message_hash,
            app_id,
            owner_public,
            raw_message_json,
            updated_session_state: rekey.updated_state,
        })
    }

    /// Sends `sign_challenge` (`dir = c2w`) to the connected wallet.
    ///
    /// The wallet should sign the nonce with its EPK keys and respond
    /// with a `challenge_response` message. The backend can then verify
    /// the signature to confirm wallet ownership.
    pub async fn request_sign_challenge(
        &self,
        params: ParamsOfRequestSignChallenge,
    ) -> Result<ResultOfRequestSignChallenge, crate::errors::AppError> {
        self.acquire().await;
        if params.session_id.trim().is_empty() {
            return Err("request_sign_challenge session_id is empty".to_string().into());
        }
        if params.nonce.trim().is_empty() {
            return Err("request_sign_challenge nonce is empty".to_string().into());
        }

        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description,
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        wait_profile_active(&profile, params.max_attempts, params.interval_ms).await?;

        let body = serde_json::to_value(SignChallengeBody { nonce: params.nonce.clone() })
            .map_err(|e| {
                crate::errors::AppError::from(e).with_context("Serialize sign_challenge body")
            })?;

        let seq = params.session_state.next_outbound_seq().map_err(|e| {
            crate::errors::AppError::from(e)
                .with_context("request_sign_challenge next_outbound_seq")
        })?;
        let rekey = crate::dh::rekey_outbound(&params.session_state, &params.session_id, seq)
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("request_sign_challenge rekey_outbound")
            })?;

        let signing_keys = KeyPair {
            public: params.session_state.signing_public.clone(),
            secret: params.session_state.signing_secret.to_string(),
        };

        let raw_message_json = encode_connect_message(
            &params.session_id,
            "c2w",
            rekey.outbound_seq,
            CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE,
            body,
            Some(&rekey.message_encryption_root),
            rekey.new_dh_public.as_deref(),
        )?;
        let send_result = profile
            .add_context_text(&raw_message_json, Signer::Keys { keys: signing_keys })
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthProfile::add_context_text sign_challenge")
            })?;
        let send_result = ensure_tx_success(send_result, "sign_challenge add_context")?;

        Ok(ResultOfRequestSignChallenge {
            profile_address,
            message_id: send_result.message_hash,
            nonce: params.nonce,
            raw_message_json,
            updated_session_state: rekey.updated_state,
            sent_at: now_secs()?,
        })
    }

    /// Waits for `challenge_response` (`dir = w2c`) from the wallet.
    ///
    /// Polls the AuthProfile until a `challenge_response` message appears,
    /// then returns the nonce, signature, and wallet address for backend
    /// verification.
    pub async fn wait_challenge_response(
        &self,
        params: ParamsOfWaitChallengeResponse,
    ) -> Result<ResultOfWaitChallengeResponse, crate::errors::AppError> {
        self.acquire().await;
        if params.session_id.trim().is_empty() {
            return Err("wait_challenge_response session_id is empty".to_string().into());
        }

        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let profile_address = root
            .get_profile_address(
                ackinacki_kit::contracts::authservice::root::ParamsOfGetProfileAddress {
                    description: params.description.clone(),
                },
            )
            .await
            .map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context("AuthServiceRoot::get_profile_address")
            })?
            .profile;

        let profile = AuthProfile::new_default(root.context().clone(), &profile_address);
        wait_profile_active(&profile, params.max_attempts, params.interval_ms).await?;

        let created_at_from = params
            .created_at_from
            .unwrap_or_else(|| now_secs().unwrap_or_default().saturating_sub(300));

        let rl = self.rate_limiter.clone();
        let found = bee_infra::poll_until(
            || {
                let profile = profile.clone();
                let session_id = params.session_id.clone();
                let session_state = params.session_state.clone();
                let rl = rl.clone();
                async move {
                    bee_infra::maybe_acquire(rl.as_ref()).await;
                    find_challenge_response_event(
                        &profile,
                        &session_id,
                        session_state.as_ref(),
                        created_at_from,
                    )
                    .await
                    .map_err(|e| e.with_context("Query challenge_response"))
                }
            },
            |found| found.is_some(),
            params.max_attempts,
            params.interval_ms,
        )
        .await?
        .ok_or_else(|| "wait_challenge_response: no challenge_response event found".to_string())?;

        Ok(ResultOfWaitChallengeResponse {
            profile_address,
            event_id: found.event_id,
            event_created_at: found.event_created_at,
            nonce: found.nonce,
            signature: found.signature,
            wallet_address: found.wallet_address,
            epk_public: found.epk_public,
            raw_message_json: found.raw_message_json,
            updated_session_state: found.updated_session_state,
        })
    }

    /// Queries active `bee_connect` sessions for a multifactor wallet.
    ///
    /// The method scans one root-event chunk (`10` records) and returns only
    /// profiles that are currently deployed (`is_deployed == true`).
    ///
    /// Stop condition for active-session scan:
    /// - when the scanned chunk contains no deployed connect profiles, or
    /// - when there are no more root events.
    pub async fn query_active_sessions_by_multifactor(
        &self,
        params: ParamsOfQueryActiveSessionsByMultifactor,
    ) -> Result<ResultOfQueryActiveSessionsByMultifactor, crate::errors::AppError> {
        self.acquire().await;
        let app_id_filter = normalize_optional_app_id(params.app_id)?;
        let root = root_with_endpoints(params.endpoints, self.api_token.clone())?;
        let mut sessions = Vec::new();
        let mut seen_session_keys = HashSet::new();
        let mut deployed_cache = HashMap::new();
        let mut has_deployed_connect_profile = false;
        let mut next_before = None;
        let mut before = params.before.clone();
        let mut cursor_stalled = false;

        while sessions.len() < ACTIVE_SESSIONS_CHUNK_SIZE as usize {
            let before_for_query = before.clone();
            let query_result = root
                .query_profiles_by_multifactor(ParamsOfQueryProfilesByMultifactor {
                    multifactor: params.multifactor_address.clone(),
                    created_at_from: params.created_at_from,
                    limit: Some(ACTIVE_SESSIONS_CHUNK_SIZE),
                    before: before_for_query.clone(),
                })
                .await
                .map_err(|e| {
                    crate::errors::AppError::from(e)
                        .with_context("AuthServiceRoot::query_profiles_by_multifactor")
                })?;
            let records = &query_result.records;

            if records.is_empty() {
                break;
            }

            for record in records {
                if !is_connect_description(&record.data.description) {
                    continue;
                }

                let parsed = parse_connect_description(&record.data.description);
                let is_deployed = match deployed_cache.get(&record.data.profile).copied() {
                    Some(cached) => cached,
                    None => {
                        let profile =
                            AuthProfile::new_default(root.context().clone(), &record.data.profile);
                        let value = profile.is_deployed().await;
                        deployed_cache.insert(record.data.profile.clone(), value);
                        value
                    }
                };
                if !is_deployed {
                    continue;
                }

                has_deployed_connect_profile = true;
                if let Some(filter) = app_id_filter.as_deref() {
                    if parsed.app_id.as_deref() != Some(filter) {
                        continue;
                    }
                }

                let session = ActiveConnectSession {
                    profile_address: record.data.profile.clone(),
                    description: record.data.description.clone(),
                    app_id: parsed.app_id,
                    session_id: parsed.session_id,
                    deployed_event_id: record.event.id.clone(),
                    deployed_at: record.event.created_at,
                };
                push_unique_active_session(&mut sessions, &mut seen_session_keys, session);

                if sessions.len() >= ACTIVE_SESSIONS_CHUNK_SIZE as usize {
                    break;
                }
            }

            let Some(cursor) = query_result.oldest_cursor else {
                break;
            };
            if before_for_query.as_deref() == Some(cursor.as_str()) {
                cursor_stalled = true;
                next_before = None;
                break;
            }

            next_before = Some(cursor.clone());
            before = Some(cursor);

            if records.len() < ACTIVE_SESSIONS_CHUNK_SIZE as usize {
                break;
            }
        }

        Ok(ResultOfQueryActiveSessionsByMultifactor {
            sessions,
            next_before,
            exhausted_active: cursor_stalled || !has_deployed_connect_profile,
        })
    }
}

/// Decodes and validates base64url connect payload (`payload` query value).
pub fn decode_connect_payload_b64url(
    payload_b64url: impl AsRef<str>,
) -> Result<ConnectPayload, crate::errors::AppError> {
    let payload_b64url = payload_b64url.as_ref().trim();
    if payload_b64url.is_empty() {
        return Err("connect payload is empty".to_string().into());
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64url).map_err(|e| {
        crate::errors::AppError::from(e.to_string())
            .with_context("Decode connect payload base64url")
    })?;
    let payload_json = String::from_utf8(payload_bytes).map_err(|e| {
        crate::errors::AppError::from(e.to_string()).with_context("Decode connect payload utf8")
    })?;
    let mut payload: ConnectPayload = serde_json::from_str(&payload_json).map_err(|e| {
        crate::errors::AppError::from(e).with_context("Deserialize connect payload")
    })?;

    validate_connect_payload_shape(&payload)?;
    payload.app_id = normalize_uint256_hex(&payload.app_id)?;

    let parsed_description = parse_connect_description(&payload.description);
    if parsed_description.app_id.as_deref() != Some(payload.app_id.as_str()) {
        return Err("connect payload description app_id mismatch".to_string().into());
    }
    if parsed_description.session_id.as_deref() != Some(payload.session_id.as_str()) {
        return Err("connect payload description session_id mismatch".to_string().into());
    }

    Ok(payload)
}

struct SessionCommon {
    session_id: String,
    description: String,
    created_at: u64,
    expires_at: u64,
    app_id: String,
    payload_json: String,
    payload_b64url: String,
}

impl ConnectClient {
    fn create_session_common(
        &self,
        app_id: String,
        ttl_secs: Option<u64>,
        nonce: Option<String>,
    ) -> Result<SessionCommon, crate::errors::AppError> {
        let now_secs = now_secs()?;
        let ttl_secs = ttl_secs.unwrap_or(DEFAULT_CONNECT_TTL_SECS).max(1);
        let expires_at = now_secs.saturating_add(ttl_secs);
        let app_id = normalize_uint256_hex(&app_id)?;
        let session_id = random_token_b64url(16)?;
        let description = format!(
            "{CONNECT_DESCRIPTION_PREFIX}{CONNECT_DESCRIPTION_VERSION}:{app_id}:{session_id}:{}",
            random_token_b64url(16)?,
        );

        let payload = ConnectPayload {
            v: CONNECT_DEEPLINK_VERSION.to_string(),
            session_id: session_id.clone(),
            description: description.clone(),
            expires_at,
            app_id: app_id.clone(),
            nonce,
        };
        let payload_json = serde_json::to_string(&payload).map_err(|e| {
            crate::errors::AppError::from(e).with_context("Serialize connect payload")
        })?;
        let payload_b64url = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        Ok(SessionCommon {
            session_id,
            description,
            created_at: now_secs,
            expires_at,
            app_id,
            payload_json,
            payload_b64url,
        })
    }
}

#[derive(Debug, Clone)]
struct WalletHelloFound {
    event_id: String,
    event_created_at: u64,
    wallet_name: String,
    wallet_address: String,
    raw_message_json: String,
    session_state: crate::dh::ConnectSessionState,
    nonce: Option<String>,
    signature: Option<String>,
    epk_public: Option<String>,
}

#[derive(Debug, Clone)]
struct SetMiningKeysFound {
    event_id: String,
    event_created_at: u64,
    app_id: String,
    owner_public: String,
    raw_message_json: String,
    updated_session_state: Option<crate::dh::ConnectSessionState>,
}

#[derive(Debug, Clone)]
struct ChallengeResponseFound {
    event_id: String,
    event_created_at: u64,
    nonce: String,
    signature: String,
    wallet_address: String,
    epk_public: Option<String>,
    raw_message_json: String,
    updated_session_state: Option<crate::dh::ConnectSessionState>,
}

async fn find_wallet_hello_event(
    profile: &AuthProfile,
    session_id: &str,
    client_dh_secret: &str,
    created_at_from: u64,
) -> Result<Option<WalletHelloFound>, crate::errors::AppError> {
    let result = profile
        .query_context_added_events(ParamsOfQueryProfileEvents {
            created_at_from: Some(created_at_from),
            limit: Some(50),
            before: None,
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("AuthProfile::query_context_added_events")
        })?;

    let total_events = result.events.len();
    let mut no_dh_public: u32 = 0;
    let mut dh_failures: u32 = 0;
    let mut decrypt_failures: u32 = 0;
    let mut body_parse_failures: u32 = 0;

    for record in result.events {
        let raw = record.data.text;
        let Ok(envelope) = serde_json::from_str::<ConnectMessageEnvelope>(&raw) else {
            continue;
        };

        if envelope.v != CONNECT_MESSAGE_VERSION
            || envelope.session_id != session_id
            || envelope.dir != "w2c"
            || envelope.seq == 0
            || envelope.msg_type != CONNECT_MESSAGE_TYPE_WALLET_HELLO
        {
            continue;
        }

        // From here on — envelope matched our session's wallet_hello.
        // Failures below are real diagnostic signals.

        // Extract wallet DH public key from envelope
        let Some(wallet_dh_public) = envelope.dh_public.as_deref() else {
            no_dh_public += 1;
            continue;
        };

        // Compute DH shared secret and derive session keys
        let Ok(shared_secret) =
            crate::dh::compute_shared_secret(client_dh_secret, wallet_dh_public)
        else {
            dh_failures += 1;
            continue;
        };
        let Ok(session_keys) = crate::dh::derive_session_keys(&shared_secret, session_id) else {
            dh_failures += 1;
            continue;
        };

        // Decrypt body using derived encryption root
        let Ok(body_value) =
            decode_connect_message_body(&envelope, Some(&session_keys.encryption_root_hex))
        else {
            decrypt_failures += 1;
            continue;
        };
        let Some(body_value) = body_value else {
            decrypt_failures += 1;
            continue;
        };
        let Ok(body) = serde_json::from_value::<WalletHelloBody>(body_value) else {
            body_parse_failures += 1;
            continue;
        };

        let mut session_state =
            crate::dh::create_initial_state(&session_keys, client_dh_secret, wallet_dh_public);
        session_state.last_seen_seq = envelope.seq;

        return Ok(Some(WalletHelloFound {
            event_id: record.event.id,
            event_created_at: record.event.created_at,
            wallet_name: body.wallet_name,
            wallet_address: body.wallet_address,
            raw_message_json: raw,
            session_state,
            nonce: body.nonce,
            signature: body.signature,
            epk_public: body.epk_public,
        }));
    }

    let failed_candidates = no_dh_public + dh_failures + decrypt_failures + body_parse_failures;
    if failed_candidates > 0 {
        return Err(format!(
            "wallet_hello: found {failed_candidates} matching event(s) but none succeeded \
             (total_events={total_events}, \
             no_dh={no_dh_public}, dh_fail={dh_failures}, decrypt_fail={decrypt_failures}, \
             body_parse_fail={body_parse_failures})"
        )
        .into());
    }

    Ok(None)
}

async fn find_set_mining_keys_event(
    profile: &AuthProfile,
    session_id: &str,
    session_state: Option<&crate::dh::ConnectSessionState>,
    created_at_from: u64,
) -> Result<Option<SetMiningKeysFound>, crate::errors::AppError> {
    if let Some(state) = session_state {
        state.ensure_not_expired().map_err(|e| {
            crate::errors::AppError::from(e).with_context("find_set_mining_keys_event")
        })?;
    }

    let result = profile
        .query_context_added_events(ParamsOfQueryProfileEvents {
            created_at_from: Some(created_at_from),
            limit: Some(50),
            before: None,
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("AuthProfile::query_context_added_events")
        })?;

    let total_events = result.events.len();
    let mut rekey_failures: u32 = 0;
    let mut decrypt_failures: u32 = 0;
    let mut body_parse_failures: u32 = 0;
    let current_state = session_state.cloned();

    for record in result.events {
        let raw = record.data.text;
        let Ok(envelope) = serde_json::from_str::<ConnectMessageEnvelope>(&raw) else {
            continue;
        };

        if envelope.v != CONNECT_MESSAGE_VERSION
            || envelope.session_id != session_id
            || envelope.dir != "c2w"
        {
            continue;
        }

        if envelope.msg_type != CONNECT_MESSAGE_TYPE_SET_MINING_KEYS {
            continue;
        }

        // Re-key + decrypt atomically: only advance DH state if decryption succeeds.
        // This prevents stale c2w events (from prior attempts or other message types)
        // from corrupting the DH chain for the current set_mining_keys.
        if let (Some(state), Some(peer_dh_pub)) = (&current_state, envelope.dh_public.as_deref()) {
            let rekey = match crate::dh::rekey_inbound(state, peer_dh_pub, session_id, envelope.seq)
            {
                Ok(r) => r,
                Err(_) => {
                    rekey_failures += 1;
                    continue;
                }
            };
            let root = rekey.message_encryption_root.as_str();
            let body_value = match decode_connect_message_body(&envelope, Some(root)) {
                Ok(Some(v)) => v,
                _ => {
                    decrypt_failures += 1;
                    continue;
                }
            };
            match serde_json::from_value::<SetMiningKeysBody>(body_value) {
                Ok(body) => {
                    let app_id = match normalize_uint256_hex(&body.app_id) {
                        Ok(v) => v,
                        Err(_) => {
                            body_parse_failures += 1;
                            continue;
                        }
                    };
                    let owner_public = match normalize_owner_public_hex(&body.owner_public) {
                        Ok(v) => v,
                        Err(_) => {
                            body_parse_failures += 1;
                            continue;
                        }
                    };
                    return Ok(Some(SetMiningKeysFound {
                        event_id: record.event.id,
                        event_created_at: record.event.created_at,
                        app_id,
                        owner_public,
                        raw_message_json: raw,
                        updated_session_state: Some(rekey.updated_state),
                    }));
                }
                Err(_) => {
                    body_parse_failures += 1;
                    continue;
                }
            }
        }
    }

    let failed_candidates = rekey_failures + decrypt_failures + body_parse_failures;
    if failed_candidates > 0 {
        return Err(format!(
            "set_mining_keys: found {failed_candidates} matching event(s) but none succeeded \
             (total_events={total_events}, \
             rekey_fail={rekey_failures}, decrypt_fail={decrypt_failures}, \
             body_parse_fail={body_parse_failures})"
        )
        .into());
    }

    Ok(None)
}

/// Scans profile events for a `challenge_response` (w2c) message, maintaining
/// the DH re-key chain for all w2c messages encountered along the way.
async fn find_challenge_response_event(
    profile: &AuthProfile,
    session_id: &str,
    session_state: Option<&crate::dh::ConnectSessionState>,
    created_at_from: u64,
) -> Result<Option<ChallengeResponseFound>, crate::errors::AppError> {
    if let Some(state) = session_state {
        state.ensure_not_expired().map_err(|e| {
            crate::errors::AppError::from(e).with_context("find_challenge_response_event")
        })?;
    }

    let result = profile
        .query_context_added_events(ParamsOfQueryProfileEvents {
            created_at_from: Some(created_at_from),
            limit: Some(50),
            before: None,
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("AuthProfile::query_context_added_events")
        })?;

    let total_events = result.events.len();
    let mut parse_failures: u32 = 0;
    let mut filtered_out: u32 = 0;
    let mut rekey_failures: u32 = 0;
    let mut decrypt_failures: u32 = 0;
    let mut body_parse_failures: u32 = 0;
    let current_state = session_state.cloned();

    for record in result.events {
        let raw = record.data.text;
        let Ok(envelope) = serde_json::from_str::<ConnectMessageEnvelope>(&raw) else {
            parse_failures += 1;
            continue;
        };

        if envelope.v != CONNECT_MESSAGE_VERSION
            || envelope.session_id != session_id
            || envelope.dir != "w2c"
        {
            filtered_out += 1;
            continue;
        }

        // Skip wallet_hello — dApp state from wait_wallet_hello already accounts for
        // it.
        if envelope.msg_type == CONNECT_MESSAGE_TYPE_WALLET_HELLO {
            filtered_out += 1;
            continue;
        }

        if envelope.msg_type != CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE {
            filtered_out += 1;
            continue;
        }

        // Re-key + decrypt: only advance DH state if decryption succeeds.
        // This prevents stale challenge_response events (from prior attempts)
        // from corrupting the DH chain for the current response.
        if let (Some(state), Some(peer_dh_pub)) = (&current_state, envelope.dh_public.as_deref()) {
            let rekey = match crate::dh::rekey_inbound(state, peer_dh_pub, session_id, envelope.seq)
            {
                Ok(r) => r,
                Err(_) => {
                    rekey_failures += 1;
                    continue;
                }
            };
            let root = rekey.message_encryption_root.as_str();
            let body_value = match decode_connect_message_body(&envelope, Some(root)) {
                Ok(Some(v)) => v,
                _ => {
                    decrypt_failures += 1;
                    continue;
                }
            };
            match serde_json::from_value::<ChallengeResponseBody>(body_value) {
                Ok(body) => {
                    return Ok(Some(ChallengeResponseFound {
                        event_id: record.event.id,
                        event_created_at: record.event.created_at,
                        nonce: body.nonce,
                        signature: body.signature,
                        wallet_address: body.wallet_address,
                        epk_public: body.epk_public,
                        raw_message_json: raw,
                        updated_session_state: Some(rekey.updated_state),
                    }));
                }
                Err(_) => {
                    body_parse_failures += 1;
                    continue;
                }
            }
        }
    }

    let had_candidates =
        parse_failures + rekey_failures + decrypt_failures + body_parse_failures > 0;
    if had_candidates {
        let detail = format!(
            "(total_events={total_events}, parse_fail={parse_failures}, filtered={filtered_out}, \
             rekey_fail={rekey_failures}, decrypt_fail={decrypt_failures}, \
             body_parse_fail={body_parse_failures})"
        );
        // Undecryptable challenge_response events on-chain mean the DH chains
        // diverged (e.g. dApp retried from stale state).  Flag this as
        // session_desync so callers can drop the session immediately instead
        // of polling until timeout.
        let prefix = if decrypt_failures > 0 { "session_desync: " } else { "" };
        return Err(format!(
            "{prefix}challenge_response: found candidates but none succeeded {detail}"
        )
        .into());
    }

    Ok(None)
}

async fn wait_profile_active(
    profile: &AuthProfile,
    max_attempts: Option<u32>,
    interval_ms: Option<u64>,
) -> Result<(), crate::errors::AppError> {
    let attempts = max_attempts.unwrap_or(100).min(u8::MAX as u32) as u8;
    let attempts_timeout = interval_ms.unwrap_or(500);

    profile
        .wait_account(ParamsOfWaitAccount {
            status: AccountStatus::Active,
            attempts: Some(attempts),
            attempts_timeout: Some(attempts_timeout),
        })
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("AuthProfile::wait_account Active")
        })?;

    Ok(())
}

fn root_with_endpoints(
    endpoints: Vec<String>,
    api_token: Option<String>,
) -> Result<AuthServiceRoot, crate::errors::AppError> {
    let mut cfg = ClientConfig::default();
    cfg.network.endpoints = Some(endpoints);
    // Disable tvm_client's internal `query_graphql` re-connect loop —
    // it spins without sleep on multi-endpoint setups and turns a
    // single 502 into a sustained ~60 rps storm against the same BM.
    // We do bounded, classified retries one layer up via
    // `bee_infra::retry::with_retry_policy`.
    cfg.network.max_reconnect_timeout = 0;
    // Authenticate against BM when the caller supplied a token. `None` keeps
    // the request anonymous (wasm/browser default). Every ConnectClient method
    // funnels through here, so this is the single point that gates auth.
    cfg.network.api_token = api_token;
    let context = ClientContext::new(cfg)
        .map_err(|e| crate::errors::AppError::from(e).with_context("Create tvm client context"))?;
    let context = Arc::new(context);
    Ok(AuthServiceRoot::new_default(context))
}

fn encode_connect_message(
    session_id: &str,
    dir: &str,
    seq: u64,
    msg_type: &str,
    body: serde_json::Value,
    encryption_secret: Option<&str>,
    dh_public: Option<&str>,
) -> Result<String, crate::errors::AppError> {
    if session_id.trim().is_empty() {
        return Err("connect message session_id is empty".to_string().into());
    }
    if dir.trim().is_empty() {
        return Err("connect message dir is empty".to_string().into());
    }
    if msg_type.trim().is_empty() {
        return Err("connect message type is empty".to_string().into());
    }

    let ts = now_secs()?;
    let aad = connect_message_aad(session_id, dir, seq, msg_type, ts)?;

    let encryption_secret = encryption_secret.ok_or_else(|| {
        format!("connect message `{msg_type}` requires session owner secret for encryption")
    })?;
    let encrypted = encrypt_connect_body(&body, encryption_secret, &aad)?;
    let mut envelope = serde_json::json!({
        "v": CONNECT_MESSAGE_VERSION,
        "session_id": session_id,
        "dir": dir,
        "seq": seq,
        "type": msg_type,
        "ts": ts,
        "enc": {
            "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
            "nonce": encrypted.nonce_b64url,
            "salt": encrypted.salt_b64url,
        },
        "body": encrypted.ciphertext_b64url,
    });
    if let Some(dh_pub) = dh_public {
        envelope["dh_public"] = serde_json::Value::String(dh_pub.to_string());
    }

    serde_json::to_string(&envelope)
        .map_err(|e| crate::errors::AppError::from(e).with_context("Serialize connect message"))
}

fn decode_connect_message_body(
    envelope: &ConnectMessageEnvelope,
    encryption_secret: Option<&str>,
) -> Result<Option<serde_json::Value>, crate::errors::AppError> {
    let alg = envelope.enc.as_ref().map(|v| v.alg.as_str()).unwrap_or(CONNECT_MESSAGE_ENC_NONE);
    if alg == CONNECT_MESSAGE_ENC_NONE {
        return Err("Unencrypted connect messages are no longer accepted".to_string().into());
    }
    if alg != CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256 {
        return Ok(None);
    }

    let secret = encryption_secret.map(str::trim).filter(|v| !v.is_empty());
    let Some(secret) = secret else {
        return Ok(None);
    };

    let enc = envelope
        .enc
        .as_ref()
        .ok_or_else(|| "Encrypted connect message misses `enc`".to_string())?;
    let nonce_b64url =
        enc.nonce.as_deref().ok_or_else(|| "Encrypted connect message misses nonce".to_string())?;
    let salt_b64url =
        enc.salt.as_deref().ok_or_else(|| "Encrypted connect message misses salt".to_string())?;
    let ciphertext_b64url = envelope
        .body
        .as_str()
        .ok_or_else(|| "Encrypted connect message body must be base64url string".to_string())?;
    let ts = envelope.ts.ok_or_else(|| "Encrypted connect message misses ts".to_string())?;
    let aad = connect_message_aad(
        &envelope.session_id,
        &envelope.dir,
        envelope.seq,
        &envelope.msg_type,
        ts,
    )?;
    let plaintext =
        decrypt_connect_body(ciphertext_b64url, nonce_b64url, salt_b64url, secret, &aad)?;
    let body = serde_json::from_slice::<serde_json::Value>(&plaintext).map_err(|e| {
        crate::errors::AppError::from(e).with_context("Deserialize decrypted connect body")
    })?;
    Ok(Some(body))
}

fn ensure_tx_success(
    result: ResultOfSendMessage,
    context: &str,
) -> Result<ResultOfSendMessage, crate::errors::AppError> {
    let aborted = result.aborted.unwrap_or(false);
    let exit_code = result.exit_code.unwrap_or(0);
    if aborted || exit_code > 0 {
        return Err(format!("{context}: tx aborted={aborted}, exit_code={exit_code}").into());
    }
    Ok(result)
}

fn validate_connect_payload_shape(payload: &ConnectPayload) -> Result<(), crate::errors::AppError> {
    if payload.v != CONNECT_DEEPLINK_VERSION {
        return Err(format!(
            "Unsupported connect deeplink version `{}` (expected `{}`)",
            payload.v, CONNECT_DEEPLINK_VERSION
        )
        .into());
    }
    if payload.session_id.trim().is_empty() {
        return Err("connect payload session_id is empty".to_string().into());
    }
    if payload.description.trim().is_empty() {
        return Err("connect payload description is empty".to_string().into());
    }
    if payload.expires_at == 0 {
        return Err("connect payload expires_at must be > 0".to_string().into());
    }
    normalize_uint256_hex(&payload.app_id)?;
    Ok(())
}

fn normalize_optional_app_id(
    value: Option<String>,
) -> Result<Option<String>, crate::errors::AppError> {
    let Some(value) = value else {
        return Ok(None);
    };

    if value.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(normalize_uint256_hex(&value)?))
}

fn is_connect_description(value: &str) -> bool {
    value.starts_with(CONNECT_DESCRIPTION_PREFIX)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedConnectDescription {
    app_id: Option<String>,
    session_id: Option<String>,
}

fn parse_connect_description(value: &str) -> ParsedConnectDescription {
    let Some(tail) = value.strip_prefix(CONNECT_DESCRIPTION_PREFIX) else {
        return ParsedConnectDescription::default();
    };

    let mut parts = tail.split(':');
    let Some(version) = parts.next() else {
        return ParsedConnectDescription::default();
    };
    if version != CONNECT_DESCRIPTION_VERSION {
        return ParsedConnectDescription::default();
    }

    let Some(raw_app_id) = parts.next() else {
        return ParsedConnectDescription::default();
    };
    let app_id = normalize_uint256_hex(raw_app_id).ok();
    if app_id.is_none() {
        return ParsedConnectDescription::default();
    }

    let Some(raw_session_id) = parts.next() else {
        return ParsedConnectDescription::default();
    };
    if raw_session_id.is_empty() {
        return ParsedConnectDescription::default();
    }

    ParsedConnectDescription { app_id, session_id: Some(raw_session_id.to_string()) }
}

fn active_session_uniqueness_key(value: &ActiveConnectSession) -> String {
    let session_part = value
        .session_id
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(value.description.as_str());
    format!("{}::{session_part}", value.profile_address.to_ascii_lowercase())
}

fn push_unique_active_session(
    sessions: &mut Vec<ActiveConnectSession>,
    seen_keys: &mut HashSet<String>,
    session: ActiveConnectSession,
) {
    let key = active_session_uniqueness_key(&session);
    if seen_keys.insert(key) {
        sessions.push(session);
    }
}

fn random_token_b64url(num_bytes: usize) -> Result<String, crate::errors::AppError> {
    let mut bytes = vec![0u8; num_bytes];
    getrandom::fill(&mut bytes).map_err(|e| {
        crate::errors::AppError::from(e.to_string()).with_context("Generate random bytes")
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
fn now_secs() -> Result<u64, crate::errors::AppError> {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms < 0.0 {
        return Err(format!("Invalid JS timestamp: {ms}").into());
    }
    Ok((ms / 1000.0).floor() as u64)
}

#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
fn now_secs() -> Result<u64, crate::errors::AppError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            crate::errors::AppError::from(e.to_string())
                .with_context("SystemTime before UNIX_EPOCH")
        })?
        .as_secs())
}

#[allow(dead_code)]
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
fn now_millis() -> Result<u64, crate::errors::AppError> {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms < 0.0 {
        return Err(format!("Invalid JS timestamp: {ms}").into());
    }
    Ok(ms.floor() as u64)
}

#[allow(dead_code)]
#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
fn now_millis() -> Result<u64, crate::errors::AppError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            crate::errors::AppError::from(e.to_string())
                .with_context("SystemTime before UNIX_EPOCH")
        })?
        .as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_uint256_hex_pads_and_lowercases() {
        let got = normalize_uint256_hex("0xAbC").expect("normalize");
        assert_eq!(got.len(), 66);
        assert!(got.starts_with("0x"));
        assert!(got.ends_with("abc"));
    }

    #[test]
    fn create_shared_key_session_uses_dh() {
        let client = ConnectClient::new();
        let result = client
            .create_shared_key_session(ParamsOfCreateSharedKeySession {
                app_id: "0x1".to_string(),
                ttl_secs: Some(300),
                nonce: None,
            })
            .expect("create session");

        // DH public key in result
        assert_eq!(hex::decode(&result.client_dh_public).unwrap().len(), 32);
        assert_eq!(hex::decode(&result.client_dh_secret).unwrap().len(), 32);

        // URL contains only public key, no secret
        assert!(result.deep_link.contains("client_dh_public="));
        assert!(!result.deep_link.contains("session_owner_secret="));
        assert!(!result.deep_link.contains("session_owner_public="));
        assert!(!result.deep_link.contains(&result.client_dh_secret));

        // Public key in URL matches result
        assert!(result.deep_link.contains(&result.client_dh_public));
    }

    #[test]
    fn decode_connect_payload_b64url_roundtrip() {
        let client = ConnectClient::new();
        let session = client
            .create_shared_key_session(ParamsOfCreateSharedKeySession {
                app_id: "0x2".to_string(),
                ttl_secs: Some(60),
                nonce: None,
            })
            .expect("session");

        let parsed =
            decode_connect_payload_b64url(&session.payload_b64url).expect("decode connect payload");
        assert_eq!(parsed.session_id, session.session_id);
        assert_eq!(parsed.description, session.description);
        assert_eq!(parsed.app_id, session.app_id);
        assert_eq!(parsed.expires_at, session.expires_at);
    }

    #[test]
    fn decode_connect_payload_b64url_rejects_invalid_version() {
        let json = serde_json::json!({
            "v": "bee_connect.dl/999",
            "session_id": "sess",
            "description": "bee_connect:v1:0x0000000000000000000000000000000000000000000000000000000000000001:sess:r",
            "expires_at": 1u64,
            "app_id": "0x1"
        })
        .to_string();
        let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());

        let err = decode_connect_payload_b64url(b64).expect_err("must fail");
        assert!(err.message.contains("Unsupported connect deeplink version"));
    }

    #[test]
    fn push_unique_active_session_dedupes_same_profile_and_session() {
        let mut sessions = Vec::new();
        let mut seen = HashSet::new();

        let first = ActiveConnectSession {
            profile_address: "0:abc".to_string(),
            description: "bee_connect:v1:0x1:sess_1:r1".to_string(),
            app_id: Some("0x1".to_string()),
            session_id: Some("sess_1".to_string()),
            deployed_event_id: "evt_1".to_string(),
            deployed_at: 1,
        };
        let duplicate = ActiveConnectSession {
            profile_address: "0:AbC".to_string(),
            description: "bee_connect:v1:0x1:sess_1:r1".to_string(),
            app_id: Some("0x1".to_string()),
            session_id: Some("sess_1".to_string()),
            deployed_event_id: "evt_2".to_string(),
            deployed_at: 2,
        };

        push_unique_active_session(&mut sessions, &mut seen, first);
        push_unique_active_session(&mut sessions, &mut seen, duplicate);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn push_unique_active_session_keeps_distinct_sessions_same_profile() {
        let mut sessions = Vec::new();
        let mut seen = HashSet::new();

        let first = ActiveConnectSession {
            profile_address: "0:abc".to_string(),
            description: "bee_connect:v1:0x1:sess_1:r1".to_string(),
            app_id: Some("0x1".to_string()),
            session_id: Some("sess_1".to_string()),
            deployed_event_id: "evt_1".to_string(),
            deployed_at: 1,
        };
        let second = ActiveConnectSession {
            profile_address: "0:abc".to_string(),
            description: "bee_connect:v1:0x1:sess_2:r2".to_string(),
            app_id: Some("0x1".to_string()),
            session_id: Some("sess_2".to_string()),
            deployed_event_id: "evt_2".to_string(),
            deployed_at: 2,
        };

        push_unique_active_session(&mut sessions, &mut seen, first);
        push_unique_active_session(&mut sessions, &mut seen, second);
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn parse_connect_description_v1() {
        let parsed = parse_connect_description(
            "bee_connect:v1:0x00000000000000000000000000000000000000000000000000000000000000ab:sess_abc:rand_x",
        );
        assert_eq!(
            parsed.app_id.as_deref(),
            Some("0x00000000000000000000000000000000000000000000000000000000000000ab")
        );
        assert_eq!(parsed.session_id.as_deref(), Some("sess_abc"));
    }

    #[test]
    fn parse_connect_description_returns_unknown_for_invalid_input() {
        assert_eq!(
            parse_connect_description("bee_connect:v1:bad_hex:sess_abc:rand_x"),
            ParsedConnectDescription::default()
        );
        assert_eq!(
            parse_connect_description("bee_connect:sess_abc:rand_x"),
            ParsedConnectDescription::default()
        );
    }

    #[test]
    fn normalize_optional_app_id_empty_is_none() {
        assert_eq!(normalize_optional_app_id(None).unwrap(), None);
        assert_eq!(normalize_optional_app_id(Some("".to_string())).unwrap(), None);
    }

    #[test]
    fn normalize_owner_public_hex_strips_prefix_and_lowercases() {
        let got = normalize_owner_public_hex(
            "0xAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("normalize");
        assert_eq!(got.len(), 64);
        assert_eq!(got, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn encode_connect_message_builds_client_disconnect() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT,
            serde_json::json!({ "reason": "user_action" }),
            Some(secret),
            None,
        )
        .expect("encode");
        assert!(raw.contains("\"type\":\"client_disconnect\""));
        assert!(raw.contains("\"dir\":\"c2w\""));
        assert!(raw.contains("\"alg\":\"xchacha20poly1305-hkdf-sha256\""));
        assert!(!raw.contains("\"reason\":\"user_action\"")); // body is encrypted
    }

    #[test]
    fn encrypted_client_disconnect_roundtrip() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT,
            serde_json::json!({ "reason": "user_left" }),
            Some(secret),
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        let decoded =
            decode_connect_message_body(&envelope, Some(secret)).expect("decode").expect("body");
        assert_eq!(decoded["reason"], "user_left");
    }

    #[test]
    fn encode_connect_message_builds_set_mining_keys() {
        let body = serde_json::to_value(SetMiningKeysBody {
            app_id: "0x1".to_string(),
            owner_public: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        })
        .expect("body");
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            body,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            None,
        )
        .expect("encode");
        assert!(raw.contains("\"type\":\"set_mining_keys\""));
        assert!(raw.contains("\"alg\":\"xchacha20poly1305-hkdf-sha256\""));
        assert!(!raw.contains("\"app_id\":\"0x1\""));
    }

    #[test]
    fn encrypted_set_mining_keys_roundtrip() {
        let body = serde_json::to_value(SetMiningKeysBody {
            app_id: "0x1".to_string(),
            owner_public: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        })
        .expect("body");
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            body,
            Some(secret),
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        let decoded =
            decode_connect_message_body(&envelope, Some(secret)).expect("decode").expect("body");
        let parsed: SetMiningKeysBody = serde_json::from_value(decoded).expect("parsed");
        assert_eq!(parsed.app_id, "0x1");
        assert_eq!(
            parsed.owner_public,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn encrypted_set_mining_keys_without_secret_is_not_decodable() {
        let body = serde_json::to_value(SetMiningKeysBody {
            app_id: "0x1".to_string(),
            owner_public: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        })
        .expect("body");
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            body,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        assert_eq!(decode_connect_message_body(&envelope, None).expect("decode"), None);
    }

    #[test]
    fn encode_connect_message_includes_dh_public() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let dh_pub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT,
            serde_json::json!({ "reason": "test" }),
            Some(secret),
            Some(dh_pub),
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        assert_eq!(envelope.dh_public.as_deref(), Some(dh_pub));
    }

    #[test]
    fn encode_connect_message_omits_dh_public_when_none() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT,
            serde_json::json!({}),
            Some(secret),
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        assert!(envelope.dh_public.is_none());
    }

    #[test]
    fn encrypted_message_with_dh_public_roundtrip() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let dh_pub = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            serde_json::json!({ "app_id": "0x1", "owner_public": "aa".repeat(32) }),
            Some(secret),
            Some(dh_pub),
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        assert_eq!(envelope.dh_public.as_deref(), Some(dh_pub));
        let decoded =
            decode_connect_message_body(&envelope, Some(secret)).expect("decode").expect("body");
        assert_eq!(decoded["app_id"], "0x1");
    }

    #[test]
    fn rekey_inbound_decrypts_rekeyed_message() {
        // Setup: Alice (client) and Bob (wallet) establish session
        let alice = crate::dh::generate_dh_keypair().unwrap();
        let bob = crate::dh::generate_dh_keypair().unwrap();
        let shared = crate::dh::compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = crate::dh::derive_session_keys(&shared, "sess_1").unwrap();

        let alice_state =
            crate::dh::create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);
        let bob_state = crate::dh::create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);

        // Alice sends set_mining_keys with rekey_outbound
        let rekey = crate::dh::rekey_outbound(&alice_state, "sess_1", 1_700_000_000_000).unwrap();
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            rekey.outbound_seq,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            serde_json::json!({ "app_id": "0x1", "owner_public": "aa".repeat(32) }),
            Some(&rekey.message_encryption_root),
            rekey.new_dh_public.as_deref(),
        )
        .unwrap();

        // Bob receives: rekey_inbound with Alice's new dh_public
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).unwrap();
        let peer_dh_pub = envelope.dh_public.as_deref().unwrap();
        let bob_rekey =
            crate::dh::rekey_inbound(&bob_state, peer_dh_pub, "sess_1", envelope.seq).unwrap();

        // Bob decrypts with re-keyed root
        let decoded =
            decode_connect_message_body(&envelope, Some(&bob_rekey.message_encryption_root))
                .unwrap()
                .unwrap();
        assert_eq!(decoded["app_id"], "0x1");
    }

    #[test]
    fn rekey_chain_two_messages_decrypt_second() {
        let alice = crate::dh::generate_dh_keypair().unwrap();
        let bob = crate::dh::generate_dh_keypair().unwrap();
        let shared = crate::dh::compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = crate::dh::derive_session_keys(&shared, "sess_1").unwrap();

        let mut alice_state =
            crate::dh::create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);
        let mut bob_state =
            crate::dh::create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);

        // Message 1: Alice sends client_disconnect
        let rekey1 = crate::dh::rekey_outbound(&alice_state, "sess_1", 1_700_000_000_000).unwrap();
        let raw1 = encode_connect_message(
            "sess_1",
            "c2w",
            rekey1.outbound_seq,
            CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT,
            serde_json::json!({ "reason": "test" }),
            Some(&rekey1.message_encryption_root),
            rekey1.new_dh_public.as_deref(),
        )
        .unwrap();
        alice_state = rekey1.updated_state;

        // Message 2: Alice sends set_mining_keys
        let rekey2 = crate::dh::rekey_outbound(&alice_state, "sess_1", 1_700_000_000_001).unwrap();
        let raw2 = encode_connect_message(
            "sess_1",
            "c2w",
            rekey2.outbound_seq,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            serde_json::json!({ "app_id": "0x2", "owner_public": "bb".repeat(32) }),
            Some(&rekey2.message_encryption_root),
            rekey2.new_dh_public.as_deref(),
        )
        .unwrap();

        // Bob processes both messages in order (simulates find_set_mining_keys_event)
        let env1: ConnectMessageEnvelope = serde_json::from_str(&raw1).unwrap();
        let bob_rekey1 = crate::dh::rekey_inbound(
            &bob_state,
            env1.dh_public.as_deref().unwrap(),
            "sess_1",
            env1.seq,
        )
        .unwrap();
        bob_state = bob_rekey1.updated_state;

        let env2: ConnectMessageEnvelope = serde_json::from_str(&raw2).unwrap();
        let bob_rekey2 = crate::dh::rekey_inbound(
            &bob_state,
            env2.dh_public.as_deref().unwrap(),
            "sess_1",
            env2.seq,
        )
        .unwrap();

        // Bob decrypts message 2 with re-keyed root
        let decoded = decode_connect_message_body(&env2, Some(&bob_rekey2.message_encryption_root))
            .unwrap()
            .unwrap();
        assert_eq!(decoded["app_id"], "0x2");

        // Without re-key chain, decryption with initial root fails
        let initial_bob =
            crate::dh::create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);
        let result = decode_connect_message_body(&env2, Some(&initial_bob.encryption_root));
        assert!(result.is_err() || result.unwrap().is_none());
    }

    // ── Tests: sign_challenge / challenge_response ──────────────────

    #[test]
    fn encode_sign_challenge_message() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let body =
            serde_json::to_value(SignChallengeBody { nonce: "deadbeef".to_string() }).unwrap();
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE,
            body,
            Some(secret),
            None,
        )
        .expect("encode");
        assert!(raw.contains("\"type\":\"sign_challenge\""));
        assert!(raw.contains("\"dir\":\"c2w\""));
        // nonce is encrypted, not visible in envelope
        assert!(!raw.contains("\"deadbeef\""));
    }

    #[test]
    fn encrypted_sign_challenge_roundtrip() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let body =
            serde_json::to_value(SignChallengeBody { nonce: "cafebabe".to_string() }).unwrap();
        let raw = encode_connect_message(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE,
            body,
            Some(secret),
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        let decoded =
            decode_connect_message_body(&envelope, Some(secret)).expect("decode").expect("body");
        let parsed: SignChallengeBody = serde_json::from_value(decoded).expect("parsed");
        assert_eq!(parsed.nonce, "cafebabe");
    }

    #[test]
    fn encode_challenge_response_message() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let body = serde_json::to_value(ChallengeResponseBody {
            nonce: "cafebabe".to_string(),
            signature: "aabb".repeat(32),
            wallet_address: "0:1234".to_string(),
            epk_public: None,
        })
        .unwrap();
        let raw = encode_connect_message(
            "sess_1",
            "w2c",
            1_700_000_000_001u64,
            CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
            body,
            Some(secret),
            None,
        )
        .expect("encode");
        assert!(raw.contains("\"type\":\"challenge_response\""));
        assert!(raw.contains("\"dir\":\"w2c\""));
    }

    #[test]
    fn encrypted_challenge_response_roundtrip() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sig = "cc".repeat(64);
        let body = serde_json::to_value(ChallengeResponseBody {
            nonce: "deadbeef".to_string(),
            signature: sig.clone(),
            wallet_address: "0:abcd".to_string(),
            epk_public: None,
        })
        .unwrap();
        let raw = encode_connect_message(
            "sess_1",
            "w2c",
            1_700_000_000_001u64,
            CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
            body,
            Some(secret),
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&raw).expect("envelope");
        let decoded =
            decode_connect_message_body(&envelope, Some(secret)).expect("decode").expect("body");
        let parsed: ChallengeResponseBody = serde_json::from_value(decoded).expect("parsed");
        assert_eq!(parsed.nonce, "deadbeef");
        assert_eq!(parsed.signature, sig);
        assert_eq!(parsed.wallet_address, "0:abcd");
    }

    // ── Regression: stale challenge_response must not corrupt DH chain ──

    /// Verifies that a `challenge_response` encrypted with a wrong DH key does
    /// not prevent decryption of the correct one that follows it.
    ///
    /// This tests the core invariant of the atomic rekey+decrypt pattern:
    /// if rekey_inbound succeeds but decryption fails (wrong key), the DH state
    /// must NOT be advanced, so the next event is tried from the original
    /// state.
    #[test]
    fn wrong_key_challenge_response_does_not_corrupt_dh_chain() {
        let session_id = "sess_stale_test";

        // ── Setup: initial DH handshake ──
        let alice = crate::dh::generate_dh_keypair().unwrap();
        let bob = crate::dh::generate_dh_keypair().unwrap();
        let shared = crate::dh::compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = crate::dh::derive_session_keys(&shared, session_id).unwrap();
        let dapp_state = crate::dh::create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);
        let wallet_state =
            crate::dh::create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);

        // ── dApp sends sign_challenge, wallet responds correctly ──
        let dapp_rekey =
            crate::dh::rekey_outbound(&dapp_state, session_id, 1_700_000_000_000).unwrap();
        let dapp_after = dapp_rekey.updated_state;

        let wallet_inbound = crate::dh::rekey_inbound(
            &wallet_state,
            dapp_rekey.new_dh_public.as_deref().unwrap(),
            session_id,
            dapp_rekey.outbound_seq,
        )
        .unwrap();
        let wallet_outbound =
            crate::dh::rekey_outbound(&wallet_inbound.updated_state, session_id, 1_700_000_000_001)
                .unwrap();

        let correct_sig = "aa".repeat(64);
        let correct_body = serde_json::to_value(ChallengeResponseBody {
            nonce: "correct_nonce".to_string(),
            signature: correct_sig.clone(),
            wallet_address: "0:good".to_string(),
            epk_public: Some("dd".repeat(32)),
        })
        .unwrap();
        let correct_response = encode_connect_message(
            session_id,
            "w2c",
            1_700_000_000_001u64,
            CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
            correct_body,
            Some(&wallet_outbound.message_encryption_root),
            wallet_outbound.new_dh_public.as_deref(),
        )
        .unwrap();

        // ── Craft a bogus challenge_response encrypted with a random key ──
        let rogue = crate::dh::generate_dh_keypair().unwrap();
        let bogus_root = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let bogus_body = serde_json::to_value(ChallengeResponseBody {
            nonce: "bogus".to_string(),
            signature: "bb".repeat(64),
            wallet_address: "0:evil".to_string(),
            epk_public: None,
        })
        .unwrap();
        let bogus_response = encode_connect_message(
            session_id,
            "w2c",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
            bogus_body,
            Some(bogus_root),
            Some(&rogue.public_hex),
        )
        .unwrap();

        // ── Simulate event scanning: bogus first, then correct ──
        let events = [&bogus_response, &correct_response];
        let state_for_scan = dapp_after;

        let mut found = None;
        for raw in &events {
            let envelope: ConnectMessageEnvelope = serde_json::from_str(raw).unwrap();
            if envelope.msg_type != CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE {
                continue;
            }
            let Some(peer_dh_pub) = envelope.dh_public.as_deref() else {
                continue;
            };
            // Atomic rekey+decrypt — do NOT update state_for_scan on failure
            let Ok(rekey) =
                crate::dh::rekey_inbound(&state_for_scan, peer_dh_pub, session_id, envelope.seq)
            else {
                continue;
            };
            let root = rekey.message_encryption_root.as_str();
            let Ok(Some(body_value)) = decode_connect_message_body(&envelope, Some(root)) else {
                continue;
            };
            let Ok(body) = serde_json::from_value::<ChallengeResponseBody>(body_value) else {
                continue;
            };
            found = Some(body);
            break;
        }

        let body = found
            .expect("Must find the correct challenge_response even when a bogus one precedes it");
        assert_eq!(body.nonce, "correct_nonce");
        assert_eq!(body.signature, correct_sig);
        assert_eq!(body.wallet_address, "0:good");
    }

    /// Verifies that wallet_hello w2c events preceding challenge_response are
    /// correctly skipped and do not interfere with DH re-key.
    #[test]
    fn wallet_hello_does_not_break_challenge_response_rekey() {
        let session_id = "sess_wh_skip";

        let alice = crate::dh::generate_dh_keypair().unwrap();
        let bob = crate::dh::generate_dh_keypair().unwrap();
        let shared = crate::dh::compute_shared_secret(&alice.secret_hex, &bob.public_hex).unwrap();
        let keys = crate::dh::derive_session_keys(&shared, session_id).unwrap();
        let dapp_state = crate::dh::create_initial_state(&keys, &alice.secret_hex, &bob.public_hex);
        let wallet_state =
            crate::dh::create_initial_state(&keys, &bob.secret_hex, &alice.public_hex);

        // Wallet sends wallet_hello (w2c) — uses initial encryption root, includes
        // dh_public
        let wallet_hello_json = encode_connect_message(
            session_id,
            "w2c",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_WALLET_HELLO,
            serde_json::json!({ "wallet_name": "test", "wallet_address": "0:abc" }),
            Some(&keys.encryption_root_hex),
            Some(&bob.public_hex),
        )
        .unwrap();

        // dApp sends sign_challenge (c2w) with rekey_outbound
        let dapp_rekey =
            crate::dh::rekey_outbound(&dapp_state, session_id, 1_700_000_000_001).unwrap();
        let dapp_after = dapp_rekey.updated_state;

        // Wallet receives sign_challenge, rekeys inbound, then sends challenge_response
        let wallet_inbound = crate::dh::rekey_inbound(
            &wallet_state,
            dapp_rekey.new_dh_public.as_deref().unwrap(),
            session_id,
            dapp_rekey.outbound_seq,
        )
        .unwrap();
        let wallet_outbound =
            crate::dh::rekey_outbound(&wallet_inbound.updated_state, session_id, 1_700_000_000_002)
                .unwrap();

        let response_body = serde_json::to_value(ChallengeResponseBody {
            nonce: "test_nonce".to_string(),
            signature: "bb".repeat(64),
            wallet_address: "0:abc".to_string(),
            epk_public: Some("ee".repeat(32)),
        })
        .unwrap();
        let challenge_response_json = encode_connect_message(
            session_id,
            "w2c",
            1_700_000_000_001u64,
            CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
            response_body,
            Some(&wallet_outbound.message_encryption_root),
            wallet_outbound.new_dh_public.as_deref(),
        )
        .unwrap();

        // Simulate event scanning: wallet_hello first, then challenge_response
        let events_json = [&wallet_hello_json, &challenge_response_json];
        let state_for_scan = dapp_after;

        let mut found = None;
        for raw in &events_json {
            let envelope: ConnectMessageEnvelope = serde_json::from_str(raw).unwrap();
            if envelope.msg_type == CONNECT_MESSAGE_TYPE_WALLET_HELLO {
                continue; // Must skip wallet_hello
            }
            if envelope.msg_type != CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE {
                continue;
            }
            let peer_dh_pub = envelope.dh_public.as_deref().unwrap();
            let Ok(rekey) =
                crate::dh::rekey_inbound(&state_for_scan, peer_dh_pub, session_id, envelope.seq)
            else {
                continue;
            };
            let root = rekey.message_encryption_root.as_str();
            let Ok(Some(body_value)) = decode_connect_message_body(&envelope, Some(root)) else {
                continue;
            };
            if let Ok(body) = serde_json::from_value::<ChallengeResponseBody>(body_value) {
                found = Some(body);
                break;
            }
        }

        let body =
            found.expect("challenge_response must decrypt correctly when wallet_hello is skipped");
        assert_eq!(body.nonce, "test_nonce");

        // Also verify: if wallet_hello is NOT skipped and we naively rekey for it,
        // decryption of challenge_response FAILS — proving the skip is necessary.
        let mut corrupted_state = state_for_scan.clone();
        let wh_envelope: ConnectMessageEnvelope = serde_json::from_str(&wallet_hello_json).unwrap();
        if let Some(wh_dh_pub) = wh_envelope.dh_public.as_deref() {
            if let Ok(bad_rekey) =
                crate::dh::rekey_inbound(&corrupted_state, wh_dh_pub, session_id, wh_envelope.seq)
            {
                corrupted_state = bad_rekey.updated_state;
            }
        }
        // Now try to decrypt challenge_response with corrupted state
        let cr_envelope: ConnectMessageEnvelope =
            serde_json::from_str(&challenge_response_json).unwrap();
        let cr_dh_pub = cr_envelope.dh_public.as_deref().unwrap();
        let rekey_result =
            crate::dh::rekey_inbound(&corrupted_state, cr_dh_pub, session_id, cr_envelope.seq);
        if let Ok(rekey) = rekey_result {
            let decrypt_result =
                decode_connect_message_body(&cr_envelope, Some(&rekey.message_encryption_root));
            assert!(
                decrypt_result.is_err() || decrypt_result.unwrap().is_none(),
                "Decryption must FAIL when wallet_hello rekey corrupts the DH chain"
            );
        }
        // If rekey itself failed, that's also acceptable — the chain is broken
    }

    // ── Inline challenge (nonce in deeplink) tests ──

    #[test]
    fn create_session_with_nonce_includes_nonce_in_payload() {
        let client = ConnectClient::new();
        let nonce = "aabbccdd11223344";
        let result = client
            .create_shared_key_session(ParamsOfCreateSharedKeySession {
                app_id: "0x1".to_string(),
                ttl_secs: Some(300),
                nonce: Some(nonce.to_string()),
            })
            .expect("create session");

        // Nonce must appear in payload JSON
        assert!(result.payload_json.contains(nonce), "payload_json should contain nonce");

        // Roundtrip through base64url
        let parsed = decode_connect_payload_b64url(&result.payload_b64url).expect("decode payload");
        assert_eq!(parsed.nonce.as_deref(), Some(nonce));
    }

    #[test]
    fn create_session_without_nonce_omits_nonce_from_payload() {
        let client = ConnectClient::new();
        let result = client
            .create_shared_key_session(ParamsOfCreateSharedKeySession {
                app_id: "0x1".to_string(),
                ttl_secs: Some(300),
                nonce: None,
            })
            .expect("create session");

        // Nonce field should be absent (skip_serializing_if)
        assert!(
            !result.payload_json.contains("nonce"),
            "payload_json should not contain nonce key"
        );

        let parsed = decode_connect_payload_b64url(&result.payload_b64url).expect("decode payload");
        assert_eq!(parsed.nonce, None);
    }

    #[test]
    fn decode_old_payload_without_nonce_returns_none() {
        // Simulates a payload from old SDK (no nonce field)
        let json = serde_json::json!({
            "v": CONNECT_DEEPLINK_VERSION,
            "session_id": "sess_old",
            "description": "bee_connect:v1:0x0000000000000000000000000000000000000000000000000000000000000001:sess_old:r",
            "expires_at": 9999999999u64,
            "app_id": "0x0000000000000000000000000000000000000000000000000000000000000001"
        })
        .to_string();
        let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let parsed = decode_connect_payload_b64url(b64).expect("decode");
        assert_eq!(parsed.nonce, None, "old payload without nonce should parse as None");
    }

    #[test]
    fn wallet_hello_body_with_challenge_deserializes() {
        let body = serde_json::json!({
            "wallet_name": "TestWallet",
            "wallet_address": "0:abc",
            "nonce": "deadbeef",
            "signature": "cafebabe",
            "epk_public": "1234abcd"
        });
        let parsed: WalletHelloBody = serde_json::from_value(body).expect("deserialize");
        assert_eq!(parsed.wallet_name, "TestWallet");
        assert_eq!(parsed.nonce.as_deref(), Some("deadbeef"));
        assert_eq!(parsed.signature.as_deref(), Some("cafebabe"));
        assert_eq!(parsed.epk_public.as_deref(), Some("1234abcd"));
    }

    #[test]
    fn wallet_hello_body_without_challenge_deserializes() {
        let body = serde_json::json!({
            "wallet_name": "OldWallet",
            "wallet_address": "0:def"
        });
        let parsed: WalletHelloBody = serde_json::from_value(body).expect("deserialize");
        assert_eq!(parsed.wallet_name, "OldWallet");
        assert_eq!(parsed.nonce, None);
        assert_eq!(parsed.signature, None);
        assert_eq!(parsed.epk_public, None);
    }
}
