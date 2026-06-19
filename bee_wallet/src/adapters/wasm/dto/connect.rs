use js_sys::Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::services::connect::ClientDisconnectMessageBody as InnerClientDisconnectMessageBody;
use crate::services::connect::ConnectSessionMessage as InnerConnectSessionMessage;
use crate::services::connect::ResultOfQuerySessionMessages as InnerResultOfQuerySessionMessages;
use crate::services::connect::SetMiningKeysMessageBody as InnerSetMiningKeysMessageBody;
use crate::services::connect::WalletHelloMetadata as InnerWalletHelloMetadata;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ConnectSessionMessage {
    event_id: String,
    event_created_at: u64,
    dir: String,
    seq: u64,
    msg_type: String,
    ts: Option<u64>,
    raw_message_json: String,
    body_json: String,
    wallet_name: Option<String>,
    wallet_address: Option<String>,
    challenge_nonce: Option<String>,
    challenge_signature: Option<String>,
    challenge_epk_public: Option<String>,
    mining_app_id: Option<String>,
    mining_owner_public: Option<String>,
    disconnect_reason: Option<String>,
    session_state_after_json: Option<String>,
}

impl From<InnerConnectSessionMessage> for ConnectSessionMessage {
    fn from(value: InnerConnectSessionMessage) -> Self {
        let (
            wallet_name,
            wallet_address,
            challenge_nonce,
            challenge_signature,
            challenge_epk_public,
        ) = value
            .wallet_hello
            .map(|v: InnerWalletHelloMetadata| {
                (
                    Some(v.wallet_name),
                    Some(v.wallet_address),
                    v.challenge_nonce,
                    v.challenge_signature,
                    v.challenge_epk_public,
                )
            })
            .unwrap_or((None, None, None, None, None));
        let (mining_app_id, mining_owner_public) = value
            .set_mining_keys
            .map(|v: InnerSetMiningKeysMessageBody| (Some(v.app_id), Some(v.owner_public)))
            .unwrap_or((None, None));
        let disconnect_reason =
            value.client_disconnect.and_then(|v: InnerClientDisconnectMessageBody| v.reason);

        Self {
            event_id: value.event_id,
            event_created_at: value.event_created_at,
            dir: value.dir,
            seq: value.seq,
            msg_type: value.msg_type,
            ts: value.ts,
            raw_message_json: value.raw_message_json,
            body_json: value.body_json,
            wallet_name,
            wallet_address,
            challenge_nonce,
            challenge_signature,
            challenge_epk_public,
            mining_app_id,
            mining_owner_public,
            disconnect_reason,
            session_state_after_json: value
                .session_state_after
                .and_then(|s| serde_json::to_string(&s).ok()),
        }
    }
}

#[wasm_bindgen]
impl ConnectSessionMessage {
    #[wasm_bindgen(getter)]
    pub fn event_id(&self) -> String {
        self.event_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_created_at(&self) -> u64 {
        self.event_created_at
    }

    #[wasm_bindgen(getter)]
    pub fn dir(&self) -> String {
        self.dir.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    #[wasm_bindgen(getter)]
    pub fn msg_type(&self) -> String {
        self.msg_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ts(&self) -> Option<u64> {
        self.ts
    }

    #[wasm_bindgen(getter)]
    pub fn raw_message_json(&self) -> String {
        self.raw_message_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn body_json(&self) -> String {
        self.body_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wallet_name(&self) -> Option<String> {
        self.wallet_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wallet_address(&self) -> Option<String> {
        self.wallet_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn challenge_nonce(&self) -> Option<String> {
        self.challenge_nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn challenge_signature(&self) -> Option<String> {
        self.challenge_signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn challenge_epk_public(&self) -> Option<String> {
        self.challenge_epk_public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn mining_app_id(&self) -> Option<String> {
        self.mining_app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn mining_owner_public(&self) -> Option<String> {
        self.mining_owner_public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn disconnect_reason(&self) -> Option<String> {
        self.disconnect_reason.clone()
    }

    /// Session state snapshot taken immediately after `rekey_inbound` for this
    /// message. Present only for c2w messages that triggered a successful DH
    /// re-key. Use this when responding to the message (e.g. sending
    /// `challenge_response` after receiving `sign_challenge`).
    #[wasm_bindgen(getter)]
    pub fn session_state_after_json(&self) -> Option<String> {
        self.session_state_after_json.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfQuerySessionMessages {
    profile_address: String,
    messages: Vec<ConnectSessionMessage>,
    next_before: Option<String>,
    updated_session_state_json: Option<String>,
}

impl From<InnerResultOfQuerySessionMessages> for ResultOfQuerySessionMessages {
    fn from(value: InnerResultOfQuerySessionMessages) -> Self {
        Self {
            profile_address: value.profile_address,
            messages: value.messages.into_iter().map(ConnectSessionMessage::from).collect(),
            next_before: value.next_before,
            updated_session_state_json: value
                .updated_session_state
                .map(|s| serde_json::to_string(&s).unwrap_or_default()),
        }
    }
}

#[wasm_bindgen]
impl ResultOfQuerySessionMessages {
    #[wasm_bindgen(getter)]
    pub fn profile_address(&self) -> String {
        self.profile_address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn messages(&self) -> Array {
        self.messages.iter().cloned().map(JsValue::from).collect()
    }

    #[wasm_bindgen(getter)]
    pub fn next_before(&self) -> Option<String> {
        self.next_before.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn updated_session_state_json(&self) -> Option<String> {
        self.updated_session_state_json.clone()
    }
}
