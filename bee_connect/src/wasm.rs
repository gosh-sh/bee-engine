use js_sys::Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;
use wasm_bindgen::JsValue;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
/**
 * Connect session state — opaque JSON blob passed between WASM calls.
 *
 * Secret fields (encryption_root, my_dh_secret, signing_secret) are sensitive.
 * Store in secure storage (OS keychain), never log in plaintext.
 * Parse with: `JSON.parse(sessionStateJson) as TConnectSessionState`
 * Pass back as: `JSON.stringify(state)`
 */
export type TConnectSessionState = {
    encryption_root: string;   // hex, 32 bytes — DO NOT log
    my_dh_secret: string;      // hex, 32 bytes — DO NOT log
    peer_dh_public: string;    // hex, 32 bytes
    signing_public: string;    // hex, 32 bytes
    signing_secret: string;    // hex, 32 bytes — DO NOT log
    created_at: number;        // UNIX epoch seconds, set at handshake
    expires_at: number;        // UNIX epoch seconds (0 = no expiration, default = created_at + 24h)
};
"#;

use crate::ActiveConnectSession as CoreActiveConnectSession;
use crate::ConnectClient;
use crate::ConnectPayload as CoreConnectPayload;
use crate::ParamsOfCreateSharedKeySession;
use crate::ParamsOfDisconnectSession;
use crate::ParamsOfQueryActiveSessionsByMultifactor;
use crate::ParamsOfRequestSetMiningKeys;
use crate::ParamsOfRequestSignChallenge;
use crate::ParamsOfResolveProfileAddress;
use crate::ParamsOfWaitChallengeResponse;
use crate::ParamsOfWaitSetMiningKeysRequest;
use crate::ParamsOfWaitWalletHello;
use crate::ResultOfCreateSharedKeySession as CoreResultOfCreateSharedKeySession;
use crate::ResultOfDisconnectSession as CoreResultOfDisconnectSession;
use crate::ResultOfQueryActiveSessionsByMultifactor as CoreResultOfQueryActiveSessionsByMultifactor;
use crate::ResultOfRequestSetMiningKeys as CoreResultOfRequestSetMiningKeys;
use crate::ResultOfRequestSignChallenge as CoreResultOfRequestSignChallenge;
use crate::ResultOfWaitChallengeResponse as CoreResultOfWaitChallengeResponse;
use crate::ResultOfWaitSetMiningKeysRequest as CoreResultOfWaitSetMiningKeysRequest;
use crate::ResultOfWaitWalletHello as CoreResultOfWaitWalletHello;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfCreateSharedKeySession {
    session_id: String,
    description: String,
    created_at: u64,
    expires_at: u64,
    app_id: String,
    payload_json: String,
    deep_link: String,
    payload_b64url: String,
    client_dh_public: String,
    client_dh_secret: String,
}

impl From<CoreResultOfCreateSharedKeySession> for ResultOfCreateSharedKeySession {
    fn from(value: CoreResultOfCreateSharedKeySession) -> Self {
        Self {
            session_id: value.session_id,
            description: value.description,
            created_at: value.created_at,
            expires_at: value.expires_at,
            app_id: value.app_id,
            payload_json: value.payload_json,
            deep_link: value.deep_link,
            payload_b64url: value.payload_b64url,
            client_dh_public: value.client_dh_public,
            client_dh_secret: value.client_dh_secret,
        }
    }
}

#[wasm_bindgen]
impl ResultOfCreateSharedKeySession {
    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    #[wasm_bindgen(getter)]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[wasm_bindgen(getter)]
    pub fn app_id(&self) -> String {
        self.app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payload_json(&self) -> String {
        self.payload_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn deep_link(&self) -> String {
        self.deep_link.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payload_b64url(&self) -> String {
        self.payload_b64url.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn client_dh_public(&self) -> String {
        self.client_dh_public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn client_dh_secret(&self) -> String {
        self.client_dh_secret.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ParsedConnectPayload {
    v: String,
    session_id: String,
    description: String,
    expires_at: u64,
    app_id: String,
    nonce: Option<String>,
}

impl From<CoreConnectPayload> for ParsedConnectPayload {
    fn from(value: CoreConnectPayload) -> Self {
        Self {
            v: value.v,
            session_id: value.session_id,
            description: value.description,
            expires_at: value.expires_at,
            app_id: value.app_id,
            nonce: value.nonce,
        }
    }
}

#[wasm_bindgen]
impl ParsedConnectPayload {
    #[wasm_bindgen(getter)]
    pub fn v(&self) -> String {
        self.v.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[wasm_bindgen(getter)]
    pub fn app_id(&self) -> String {
        self.app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Option<String> {
        self.nonce.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfWaitWalletHello {
    profile_address: String,
    event_id: String,
    event_created_at: u64,
    wallet_name: String,
    wallet_address: String,
    raw_message_json: String,
    session_state_json: String,
    nonce: Option<String>,
    signature: Option<String>,
    epk_public: Option<String>,
}

impl From<CoreResultOfWaitWalletHello> for ResultOfWaitWalletHello {
    fn from(value: CoreResultOfWaitWalletHello) -> Self {
        Self {
            profile_address: value.profile_address,
            event_id: value.event_id,
            event_created_at: value.event_created_at,
            wallet_name: value.wallet_name,
            wallet_address: value.wallet_address,
            raw_message_json: value.raw_message_json,
            session_state_json: serde_json::to_string(&value.session_state).unwrap_or_default(),
            nonce: value.nonce,
            signature: value.signature,
            epk_public: value.epk_public,
        }
    }
}

#[wasm_bindgen]
impl ResultOfWaitWalletHello {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_id(&self) -> String {
        self.event_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_created_at(&self) -> u64 {
        self.event_created_at
    }

    #[wasm_bindgen(getter)]
    pub fn wallet_name(&self) -> String {
        self.wallet_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wallet_address(&self) -> String {
        self.wallet_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn session_state_json(&self) -> String {
        self.session_state_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Option<String> {
        self.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epk_public(&self) -> Option<String> {
        self.epk_public.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfDisconnectSession {
    profile_address: String,
    message_id: Option<String>,
    raw_message_json: String,
    updated_session_state_json: String,
}

impl From<CoreResultOfDisconnectSession> for ResultOfDisconnectSession {
    fn from(value: CoreResultOfDisconnectSession) -> Self {
        Self {
            profile_address: value.profile_address,
            message_id: value.message_id,
            raw_message_json: value.raw_message_json,
            updated_session_state_json: serde_json::to_string(&value.updated_session_state)
                .unwrap_or_default(),
        }
    }
}

#[wasm_bindgen]
impl ResultOfDisconnectSession {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message_id(&self) -> Option<String> {
        self.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn updated_session_state_json(&self) -> String {
        self.updated_session_state_json.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfRequestSetMiningKeys {
    profile_address: String,
    message_id: Option<String>,
    app_id: String,
    owner_public: String,
    raw_message_json: String,
    updated_session_state_json: String,
}

impl From<CoreResultOfRequestSetMiningKeys> for ResultOfRequestSetMiningKeys {
    fn from(value: CoreResultOfRequestSetMiningKeys) -> Self {
        Self {
            profile_address: value.profile_address,
            message_id: value.message_id,
            app_id: value.app_id,
            owner_public: value.owner_public,
            raw_message_json: value.raw_message_json,
            updated_session_state_json: serde_json::to_string(&value.updated_session_state)
                .unwrap_or_default(),
        }
    }
}

#[wasm_bindgen]
impl ResultOfRequestSetMiningKeys {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message_id(&self) -> Option<String> {
        self.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn app_id(&self) -> String {
        self.app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner_public(&self) -> String {
        self.owner_public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn updated_session_state_json(&self) -> String {
        self.updated_session_state_json.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfWaitSetMiningKeysRequest {
    profile_address: String,
    event_id: String,
    event_created_at: u64,
    app_id: String,
    owner_public: String,
    raw_message_json: String,
    updated_session_state_json: Option<String>,
}

impl From<CoreResultOfWaitSetMiningKeysRequest> for ResultOfWaitSetMiningKeysRequest {
    fn from(value: CoreResultOfWaitSetMiningKeysRequest) -> Self {
        Self {
            profile_address: value.profile_address,
            event_id: value.event_id,
            event_created_at: value.event_created_at,
            app_id: value.app_id,
            owner_public: value.owner_public,
            raw_message_json: value.raw_message_json,
            updated_session_state_json: value
                .updated_session_state
                .map(|s| serde_json::to_string(&s).unwrap_or_default()),
        }
    }
}

#[wasm_bindgen]
impl ResultOfWaitSetMiningKeysRequest {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_id(&self) -> String {
        self.event_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_created_at(&self) -> u64 {
        self.event_created_at
    }

    #[wasm_bindgen(getter)]
    pub fn app_id(&self) -> String {
        self.app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner_public(&self) -> String {
        self.owner_public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn updated_session_state_json(&self) -> Option<String> {
        self.updated_session_state_json.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ActiveConnectSession {
    profile_address: String,
    description: String,
    app_id: Option<String>,
    session_id: Option<String>,
    deployed_event_id: String,
    deployed_at: u64,
}

impl From<CoreActiveConnectSession> for ActiveConnectSession {
    fn from(value: CoreActiveConnectSession) -> Self {
        Self {
            profile_address: value.profile_address,
            description: value.description,
            app_id: value.app_id,
            session_id: value.session_id,
            deployed_event_id: value.deployed_event_id,
            deployed_at: value.deployed_at,
        }
    }
}

#[wasm_bindgen]
impl ActiveConnectSession {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn app_id(&self) -> Option<String> {
        self.app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> Option<String> {
        self.session_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn deployed_event_id(&self) -> String {
        self.deployed_event_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn deployed_at(&self) -> u64 {
        self.deployed_at
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfQueryActiveSessionsByMultifactor {
    sessions: Vec<ActiveConnectSession>,
    next_before: Option<String>,
    exhausted_active: bool,
}

impl From<CoreResultOfQueryActiveSessionsByMultifactor>
    for ResultOfQueryActiveSessionsByMultifactor
{
    fn from(value: CoreResultOfQueryActiveSessionsByMultifactor) -> Self {
        Self {
            sessions: value.sessions.into_iter().map(ActiveConnectSession::from).collect(),
            next_before: value.next_before,
            exhausted_active: value.exhausted_active,
        }
    }
}

#[wasm_bindgen]
impl ResultOfQueryActiveSessionsByMultifactor {
    #[wasm_bindgen(getter)]
    pub fn sessions(&self) -> Array {
        self.sessions.iter().cloned().map(JsValue::from).collect()
    }

    #[wasm_bindgen(getter)]
    pub fn next_before(&self) -> Option<String> {
        self.next_before.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn exhausted_active(&self) -> bool {
        self.exhausted_active
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfRequestSignChallenge {
    profile_address: String,
    message_id: Option<String>,
    nonce: String,
    raw_message_json: String,
    updated_session_state_json: String,
    sent_at: u64,
}

impl From<CoreResultOfRequestSignChallenge> for ResultOfRequestSignChallenge {
    fn from(value: CoreResultOfRequestSignChallenge) -> Self {
        Self {
            profile_address: value.profile_address,
            message_id: value.message_id,
            nonce: value.nonce,
            raw_message_json: value.raw_message_json,
            updated_session_state_json: serde_json::to_string(&value.updated_session_state)
                .unwrap_or_default(),
            sent_at: value.sent_at,
        }
    }
}

#[wasm_bindgen]
impl ResultOfRequestSignChallenge {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message_id(&self) -> Option<String> {
        self.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> String {
        self.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn updated_session_state_json(&self) -> String {
        self.updated_session_state_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn sent_at(&self) -> u64 {
        self.sent_at
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfWaitChallengeResponse {
    profile_address: String,
    event_id: String,
    event_created_at: u64,
    nonce: String,
    signature: String,
    wallet_address: String,
    epk_public: Option<String>,
    raw_message_json: String,
    updated_session_state_json: Option<String>,
}

impl From<CoreResultOfWaitChallengeResponse> for ResultOfWaitChallengeResponse {
    fn from(value: CoreResultOfWaitChallengeResponse) -> Self {
        Self {
            profile_address: value.profile_address,
            event_id: value.event_id,
            event_created_at: value.event_created_at,
            nonce: value.nonce,
            signature: value.signature,
            wallet_address: value.wallet_address,
            epk_public: value.epk_public,
            raw_message_json: value.raw_message_json,
            updated_session_state_json: value
                .updated_session_state
                .map(|s| serde_json::to_string(&s).unwrap_or_default()),
        }
    }
}

#[wasm_bindgen]
impl ResultOfWaitChallengeResponse {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_id(&self) -> String {
        self.event_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_created_at(&self) -> u64 {
        self.event_created_at
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> String {
        self.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> String {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wallet_address(&self) -> String {
        self.wallet_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn epk_public(&self) -> Option<String> {
        self.epk_public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn updated_session_state_json(&self) -> Option<String> {
        self.updated_session_state_json.clone()
    }
}

#[wasm_bindgen]
pub struct BeeConnect {
    inner: ConnectClient,
}

#[wasm_bindgen]
impl BeeConnect {
    /// Creates a new wasm-facing `bee_connect` client wrapper.
    #[wasm_bindgen(constructor)]
    pub fn new(max_rps: Option<u32>) -> Self {
        let inner = match max_rps {
            Some(rps) => ConnectClient::with_rate_limit(rps),
            None => ConnectClient::new(),
        };
        Self { inner }
    }

    /// Small health-check helper for smoke tests.
    #[wasm_bindgen(js_name = ping)]
    pub fn ping(&self) -> String {
        self.inner.ping().to_string()
    }

    /// Creates a `shared_key` session and returns payload + temporary owner
    /// keys.
    #[wasm_bindgen(js_name = create_shared_key_session)]
    pub fn create_shared_key_session(
        &self,
        app_id: String,
        ttl_secs: Option<u32>,
        nonce: Option<String>,
    ) -> Result<ResultOfCreateSharedKeySession, JsError> {
        let result = self
            .inner
            .create_shared_key_session(ParamsOfCreateSharedKeySession {
                app_id,
                ttl_secs: ttl_secs.map(u64::from),
                nonce,
            })
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfCreateSharedKeySession::from(result))
    }

    /// Decodes and validates base64url connect payload (`payload` query
    /// value).
    #[wasm_bindgen(js_name = decode_connect_payload_b64url)]
    pub fn decode_connect_payload_b64url(
        &self,
        payload_b64url: String,
    ) -> Result<ParsedConnectPayload, JsError> {
        let payload = self
            .inner
            .decode_connect_payload_b64url(payload_b64url)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ParsedConnectPayload::from(payload))
    }

    /// Resolves deterministic `AuthProfile` address by `description`.
    #[wasm_bindgen(js_name = resolve_profile_address)]
    pub async fn resolve_profile_address(
        &self,
        endpoints: Vec<String>,
        description: String,
    ) -> Result<String, JsError> {
        self.inner
            .get_profile_address(ParamsOfResolveProfileAddress { endpoints, description })
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Returns `true` if session profile is currently deployed.
    #[wasm_bindgen(js_name = is_session_profile_deployed)]
    pub async fn is_session_profile_deployed(
        &self,
        endpoints: Vec<String>,
        description: String,
    ) -> Result<bool, JsError> {
        self.inner
            .is_session_profile_deployed(ParamsOfResolveProfileAddress { endpoints, description })
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Waits for the wallet's first `wallet_hello` message on the profile.
    #[wasm_bindgen(js_name = wait_wallet_hello)]
    pub async fn wait_wallet_hello(
        &self,
        endpoints: Vec<String>,
        session_id: String,
        description: String,
        client_dh_secret: String,
        created_at_from: Option<u64>,
        max_attempts: Option<u32>,
        interval_ms: Option<u32>,
    ) -> Result<ResultOfWaitWalletHello, JsError> {
        let result = self
            .inner
            .wait_wallet_hello(ParamsOfWaitWalletHello {
                endpoints,
                session_id,
                description,
                client_dh_secret,
                created_at_from,
                max_attempts,
                interval_ms: interval_ms.map(u64::from),
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfWaitWalletHello::from(result))
    }

    /// Waits for `set_mining_keys` request (`dir = c2w`) in session profile.
    #[wasm_bindgen(js_name = wait_set_mining_keys_request)]
    pub async fn wait_set_mining_keys_request(
        &self,
        endpoints: Vec<String>,
        session_id: String,
        description: String,
        created_at_from: Option<u64>,
        max_attempts: Option<u32>,
        interval_ms: Option<u32>,
        session_state_json: Option<String>,
    ) -> Result<ResultOfWaitSetMiningKeysRequest, JsError> {
        let session_state = session_state_json
            .map(|json| {
                serde_json::from_str::<crate::dh::ConnectSessionState>(&json)
                    .map_err(|e| JsError::new(&format!("Bad ConnectSessionState JSON: {e}")))
            })
            .transpose()?;

        let result = self
            .inner
            .wait_set_mining_keys_request(ParamsOfWaitSetMiningKeysRequest {
                endpoints,
                session_id,
                description,
                session_state,
                created_at_from,
                max_attempts,
                interval_ms: interval_ms.map(u64::from),
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfWaitSetMiningKeysRequest::from(result))
    }

    /// Sends a `client_disconnect` message (`dir = c2w`) to the connected
    /// profile. Performs DH re-key for forward secrecy.
    #[wasm_bindgen(js_name = disconnect_session)]
    pub async fn disconnect_session(
        &self,
        endpoints: Vec<String>,
        session_id: String,
        description: String,
        session_state_json: String,
        reason: Option<String>,
        max_attempts: Option<u32>,
        interval_ms: Option<u32>,
    ) -> Result<ResultOfDisconnectSession, JsError> {
        let session_state: crate::dh::ConnectSessionState =
            serde_json::from_str(&session_state_json)
                .map_err(|e| JsError::new(&format!("Bad ConnectSessionState JSON: {e}")))?;

        let result = self
            .inner
            .disconnect_session(ParamsOfDisconnectSession {
                endpoints,
                session_id,
                description,
                session_state,
                reason,
                max_attempts,
                interval_ms: interval_ms.map(u64::from),
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfDisconnectSession::from(result))
    }

    /// Sends `set_mining_keys` request (`dir = c2w`) to wallet over connect
    /// profile. Performs DH re-key for forward secrecy.
    #[wasm_bindgen(js_name = request_set_mining_keys)]
    pub async fn request_set_mining_keys(
        &self,
        endpoints: Vec<String>,
        session_id: String,
        description: String,
        session_state_json: String,
        app_id: String,
        owner_public: String,
        max_attempts: Option<u32>,
        interval_ms: Option<u32>,
    ) -> Result<ResultOfRequestSetMiningKeys, JsError> {
        let session_state: crate::dh::ConnectSessionState =
            serde_json::from_str(&session_state_json)
                .map_err(|e| JsError::new(&format!("Bad ConnectSessionState JSON: {e}")))?;

        let result = self
            .inner
            .request_set_mining_keys(ParamsOfRequestSetMiningKeys {
                endpoints,
                session_id,
                description,
                session_state,
                app_id,
                owner_public,
                max_attempts,
                interval_ms: interval_ms.map(u64::from),
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfRequestSetMiningKeys::from(result))
    }

    /// Sends `sign_challenge` (`dir = c2w`) to the wallet. The wallet should
    /// sign the nonce and respond with `challenge_response`.
    #[wasm_bindgen(js_name = request_sign_challenge)]
    pub async fn request_sign_challenge(
        &self,
        endpoints: Vec<String>,
        session_id: String,
        description: String,
        session_state_json: String,
        nonce: String,
        max_attempts: Option<u32>,
        interval_ms: Option<u32>,
    ) -> Result<ResultOfRequestSignChallenge, JsError> {
        let session_state: crate::dh::ConnectSessionState =
            serde_json::from_str(&session_state_json)
                .map_err(|e| JsError::new(&format!("Bad ConnectSessionState JSON: {e}")))?;

        let result = self
            .inner
            .request_sign_challenge(ParamsOfRequestSignChallenge {
                endpoints,
                session_id,
                description,
                session_state,
                nonce,
                max_attempts,
                interval_ms: interval_ms.map(u64::from),
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfRequestSignChallenge::from(result))
    }

    /// Waits for `challenge_response` (`dir = w2c`) from the wallet.
    #[wasm_bindgen(js_name = wait_challenge_response)]
    pub async fn wait_challenge_response(
        &self,
        endpoints: Vec<String>,
        session_id: String,
        description: String,
        session_state_json: Option<String>,
        created_at_from: Option<u64>,
        max_attempts: Option<u32>,
        interval_ms: Option<u32>,
    ) -> Result<ResultOfWaitChallengeResponse, JsError> {
        let session_state = session_state_json
            .map(|json| {
                serde_json::from_str::<crate::dh::ConnectSessionState>(&json)
                    .map_err(|e| JsError::new(&format!("Bad ConnectSessionState JSON: {e}")))
            })
            .transpose()?;

        let result = self
            .inner
            .wait_challenge_response(ParamsOfWaitChallengeResponse {
                endpoints,
                session_id,
                description,
                session_state,
                created_at_from,
                max_attempts,
                interval_ms: interval_ms.map(u64::from),
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfWaitChallengeResponse::from(result))
    }

    /// Queries one chunk of active connect sessions by multifactor.
    ///
    /// Returns at most 10 deployed `bee_connect` sessions and a cursor for the
    /// next chunk. Optional `app_id` filters to one application.
    #[wasm_bindgen(js_name = query_active_sessions_by_multifactor)]
    pub async fn query_active_sessions_by_multifactor(
        &self,
        endpoints: Vec<String>,
        multifactor_address: String,
        app_id: Option<String>,
        created_at_from: Option<u64>,
        before: Option<String>,
    ) -> Result<ResultOfQueryActiveSessionsByMultifactor, JsError> {
        let result = self
            .inner
            .query_active_sessions_by_multifactor(ParamsOfQueryActiveSessionsByMultifactor {
                endpoints,
                multifactor_address,
                app_id,
                created_at_from,
                before,
            })
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(ResultOfQueryActiveSessionsByMultifactor::from(result))
    }
}
