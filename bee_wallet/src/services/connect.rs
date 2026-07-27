use ackinacki_kit::tvm_client::crypto::KeyPair;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bee_connect::message::connect_message_aad;
use bee_connect::message::decrypt_connect_body;
use bee_connect::message::encrypt_connect_body;
use bee_connect::message::normalize_owner_public_hex;
use bee_connect::message::normalize_uint256_hex;
pub use bee_connect::message::CONNECT_DEEPLINK_VERSION;
use bee_connect::message::CONNECT_MESSAGE_ENC_NONE;
use bee_connect::message::CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256;
pub use bee_connect::message::CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE;
pub use bee_connect::message::CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT;
pub use bee_connect::message::CONNECT_MESSAGE_TYPE_SET_MINING_KEYS;
pub use bee_connect::message::CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE;
pub use bee_connect::message::CONNECT_MESSAGE_TYPE_WALLET_HELLO;
use bee_connect::message::CONNECT_MESSAGE_VERSION;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::errors::AppError;
use crate::errors::AppResult;
const DEFAULT_QUERY_SESSION_MESSAGES_LIMIT: u32 = 50;
const MAX_QUERY_SESSION_MESSAGES_LIMIT: u32 = 200;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamsOfAcceptSharedKeyConnect {
    pub payload: ConnectPayload,
    pub wallet_name: String,
    pub wallet_address: String,
    /// Client's X25519 DH public key (hex), received from the deeplink URL.
    pub client_dh_public: String,
    pub max_attempts: Option<u32>,
    pub interval_ms: Option<u64>,
    /// Pre-computed signature of `payload.nonce` (hex). When present, included
    /// in the `wallet_hello` body for inline challenge verification.
    #[serde(default)]
    pub challenge_signature: Option<String>,
    /// EPK public key (hex) used to produce `challenge_signature`.
    #[serde(default)]
    pub challenge_epk_public: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfAcceptConnect {
    pub profile_address: String,
    pub deploy_message_id: Option<String>,
    pub wallet_hello_message_id: Option<String>,
    pub wallet_hello_json: String,
    /// Initial session state after DH key exchange.
    /// Contains signing keys, encryption root, and DH keys.
    /// Caller MUST persist this for `query_session_messages`.
    pub session_state: bee_connect::dh::ConnectSessionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamsOfDestroyConnectProfile {
    pub profile_address: String,
    pub multifactor_address: String,
    pub signer_keys: KeyPair,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamsOfQuerySessionMessages {
    pub session_id: String,
    pub description: String,
    /// Session state for decrypting and re-keying incoming c2w messages.
    pub session_state: Option<bee_connect::dh::ConnectSessionState>,
    pub created_at_from: Option<u64>,
    pub before: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletHelloMetadata {
    pub wallet_name: String,
    pub wallet_address: String,
    /// Inline challenge nonce (present when wallet responded to nonce in
    /// deeplink).
    #[serde(default, rename = "nonce", skip_serializing_if = "Option::is_none")]
    pub challenge_nonce: Option<String>,
    /// Inline challenge signature.
    #[serde(default, rename = "signature", skip_serializing_if = "Option::is_none")]
    pub challenge_signature: Option<String>,
    /// EPK public key used to sign the nonce.
    #[serde(default, rename = "epk_public", skip_serializing_if = "Option::is_none")]
    pub challenge_epk_public: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMiningKeysMessageBody {
    pub app_id: String,
    pub owner_public: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientDisconnectMessageBody {
    #[serde(default)]
    pub reason: Option<String>,
}

pub use bee_connect::ChallengeResponseBody;
pub use bee_connect::SignChallengeBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectSessionMessage {
    pub event_id: String,
    pub event_created_at: u64,
    pub dir: String,
    pub seq: u64,
    pub msg_type: String,
    pub ts: Option<u64>,
    pub raw_message_json: String,
    pub body_json: String,
    /// `true` when the encrypted body was decrypted and parsed as JSON with the
    /// secret supplied to the parse call. Note that `body_json` is NOT a usable
    /// substitute for this flag: on decrypt failure it falls back to the raw
    /// envelope body, so it is never empty. Callers deciding whether a message
    /// was really readable (e.g. whether to advance DH re-key state) must look
    /// at this field, not at the typed `*_body` fields — those stay `None` for
    /// any application-level `msg_type` this crate does not know.
    #[serde(default)]
    pub body_decrypted: bool,
    pub wallet_hello: Option<WalletHelloMetadata>,
    pub set_mining_keys: Option<SetMiningKeysMessageBody>,
    pub client_disconnect: Option<ClientDisconnectMessageBody>,
    pub sign_challenge: Option<SignChallengeBody>,
    pub challenge_response: Option<ChallengeResponseBody>,
    /// Session state snapshot taken immediately after `rekey_inbound` was
    /// applied for this specific message. Present only for c2w messages
    /// that triggered a successful DH re-key. Callers that need to respond
    /// to a message (e.g. `challenge_response` after `sign_challenge`)
    /// should use this state rather than the batch-level
    /// `ResultOfQuerySessionMessages::updated_session_state`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state_after: Option<bee_connect::dh::ConnectSessionState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfQuerySessionMessages {
    pub profile_address: String,
    pub messages: Vec<ConnectSessionMessage>,
    pub next_before: Option<String>,
    /// Updated session state after re-keying all c2w messages.
    /// `None` if no `session_state` was provided in params.
    /// Caller SHOULD persist this for the next `query_session_messages` call.
    pub updated_session_state: Option<bee_connect::dh::ConnectSessionState>,
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
    #[allow(dead_code)] // Read via serde_json::Value pre-parse in query_session_messages
    dh_public: Option<String>,
    #[serde(default)]
    enc: Option<ConnectMessageEnc>,
    #[serde(default)]
    body: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectMessageEnc {
    alg: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    salt: Option<String>,
}

pub fn decode_connect_payload_b64url(payload_b64: impl AsRef<str>) -> AppResult<ConnectPayload> {
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64.as_ref()).map_err(|e| {
        AppError::new(format!("Decode connect payload base64url ({e})")).with_kind("connect")
    })?;
    let payload_json = String::from_utf8(payload_bytes).map_err(|e| {
        AppError::new(format!("Decode connect payload utf8 ({e})")).with_kind("connect")
    })?;
    let payload: ConnectPayload = serde_json::from_str(&payload_json).map_err(|e| {
        AppError::new(format!("Deserialize connect payload json ({e})")).with_kind("connect")
    })?;
    validate_connect_payload_shape(&payload)?;
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_wallet_hello_message(
    session_id: impl AsRef<str>,
    wallet_name: impl AsRef<str>,
    wallet_address: impl AsRef<str>,
    encryption_root: &str,
    wallet_dh_public: &str,
    seq: u64,
    challenge_nonce: Option<&str>,
    challenge_signature: Option<&str>,
    challenge_epk_public: Option<&str>,
) -> AppResult<String> {
    let session_id = session_id.as_ref();
    if session_id.is_empty() {
        return Err(AppError::new("wallet_hello session_id is empty").with_kind("connect"));
    }
    if seq == 0 {
        return Err(AppError::new("wallet_hello seq must be > 0").with_kind("connect"));
    }

    let ts = crate::infra::now_secs();

    let mut body = serde_json::json!({
        "wallet_name": wallet_name.as_ref(),
        "wallet_address": wallet_address.as_ref(),
    });
    if let Some(nonce) = challenge_nonce {
        body["nonce"] = serde_json::Value::String(nonce.to_string());
    }
    if let Some(sig) = challenge_signature {
        body["signature"] = serde_json::Value::String(sig.to_string());
    }
    if let Some(epk) = challenge_epk_public {
        body["epk_public"] = serde_json::Value::String(epk.to_string());
    }

    let aad = connect_message_aad(session_id, "w2c", seq, "wallet_hello", ts)
        .map_err(|e| AppError::new(e).with_kind("connect"))?;
    let encrypted = encrypt_connect_body(&body, encryption_root, &aad)
        .map_err(|e| AppError::new(e).with_kind("connect"))?;

    let envelope = serde_json::json!({
        "v": CONNECT_MESSAGE_VERSION,
        "session_id": session_id,
        "dir": "w2c",
        "seq": seq,
        "type": "wallet_hello",
        "ts": ts,
        "dh_public": wallet_dh_public,
        "enc": {
            "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
            "nonce": encrypted.nonce_b64url,
            "salt": encrypted.salt_b64url,
        },
        "body": encrypted.ciphertext_b64url,
    });

    serde_json::to_string(&envelope).map_err(|e| {
        AppError::new(format!("Serialize wallet_hello message ({e})")).with_kind("connect")
    })
}

/// Encodes an encrypted `challenge_response` (w2c) message.
/// Called by the wallet after signing the nonce from `sign_challenge`.
///
/// `epk_public` — optional EPK public key (hex) used to sign the nonce.
/// When provided, the backend can verify the signature without fetching
/// the key from the chain first, then confirm the key is registered via
/// `get_epk_expire_at(wallet_address, epk_public)`.
#[allow(clippy::too_many_arguments)]
pub fn encode_challenge_response_message(
    session_id: impl AsRef<str>,
    nonce: impl AsRef<str>,
    signature: impl AsRef<str>,
    wallet_address: impl AsRef<str>,
    epk_public: Option<&str>,
    encryption_root: &str,
    wallet_dh_public: &str,
    seq: u64,
) -> AppResult<String> {
    let session_id = session_id.as_ref();
    if session_id.is_empty() {
        return Err(AppError::new("challenge_response session_id is empty").with_kind("connect"));
    }
    if seq == 0 {
        return Err(AppError::new("challenge_response seq must be > 0").with_kind("connect"));
    }

    let ts = crate::infra::now_secs();

    let mut body = serde_json::json!({
        "nonce": nonce.as_ref(),
        "signature": signature.as_ref(),
        "wallet_address": wallet_address.as_ref(),
    });
    if let Some(epk) = epk_public {
        body["epk_public"] = serde_json::Value::String(epk.to_string());
    }

    let aad =
        connect_message_aad(session_id, "w2c", seq, CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE, ts)
            .map_err(|e| AppError::new(e).with_kind("connect"))?;
    let encrypted = encrypt_connect_body(&body, encryption_root, &aad)
        .map_err(|e| AppError::new(e).with_kind("connect"))?;

    let envelope = serde_json::json!({
        "v": CONNECT_MESSAGE_VERSION,
        "session_id": session_id,
        "dir": "w2c",
        "seq": seq,
        "type": CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
        "ts": ts,
        "dh_public": wallet_dh_public,
        "enc": {
            "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
            "nonce": encrypted.nonce_b64url,
            "salt": encrypted.salt_b64url,
        },
        "body": encrypted.ciphertext_b64url,
    });

    serde_json::to_string(&envelope).map_err(|e| {
        AppError::new(format!("Serialize challenge_response message ({e})")).with_kind("connect")
    })
}

pub fn validate_shared_key_connect_payload(
    payload: &ConnectPayload,
    now_secs: u64,
) -> AppResult<()> {
    validate_connect_payload(payload, now_secs)?;
    Ok(())
}

fn validate_connect_payload(payload: &ConnectPayload, now_secs: u64) -> AppResult<()> {
    validate_connect_payload_shape(payload)?;
    if payload.expires_at <= now_secs {
        return Err(AppError::new(format!(
            "Connect payload expired at {}, now {}",
            payload.expires_at, now_secs
        ))
        .with_kind("connect"));
    }
    Ok(())
}

fn validate_connect_payload_shape(payload: &ConnectPayload) -> AppResult<()> {
    if payload.v != CONNECT_DEEPLINK_VERSION {
        return Err(AppError::new(format!(
            "Unsupported connect deeplink version `{}` (expected `{}`)",
            payload.v, CONNECT_DEEPLINK_VERSION
        ))
        .with_kind("connect"));
    }
    if payload.session_id.trim().is_empty() {
        return Err(AppError::new("Connect payload session_id is empty").with_kind("connect"));
    }
    if payload.description.trim().is_empty() {
        return Err(AppError::new("Connect payload description is empty").with_kind("connect"));
    }
    let _ = normalize_uint256_hex(&payload.app_id)
        .map_err(|e| AppError::new(e).with_kind("connect"))?;
    Ok(())
}

pub fn validate_session_message_params(
    session_id: impl AsRef<str>,
    description: impl AsRef<str>,
) -> AppResult<()> {
    if session_id.as_ref().trim().is_empty() {
        return Err(AppError::new("connect session_id is empty").with_kind("connect"));
    }
    if description.as_ref().trim().is_empty() {
        return Err(AppError::new("connect description is empty").with_kind("connect"));
    }
    Ok(())
}

pub fn normalize_query_session_messages_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(DEFAULT_QUERY_SESSION_MESSAGES_LIMIT).clamp(1, MAX_QUERY_SESSION_MESSAGES_LIMIT)
}

pub fn parse_connect_session_message(
    raw_message_json: impl AsRef<str>,
    expected_session_id: impl AsRef<str>,
    event_id: String,
    event_created_at: u64,
) -> Option<ConnectSessionMessage> {
    parse_connect_session_message_with_secret(
        raw_message_json,
        expected_session_id,
        None,
        event_id,
        event_created_at,
    )
}

pub fn parse_connect_session_message_with_secret(
    raw_message_json: impl AsRef<str>,
    expected_session_id: impl AsRef<str>,
    encryption_secret: Option<&str>,
    event_id: String,
    event_created_at: u64,
) -> Option<ConnectSessionMessage> {
    let expected_session_id = expected_session_id.as_ref().trim();
    if expected_session_id.is_empty() {
        return None;
    }

    let raw_message_json = raw_message_json.as_ref();
    let envelope: ConnectMessageEnvelope = serde_json::from_str(raw_message_json).ok()?;
    if envelope.v != CONNECT_MESSAGE_VERSION {
        return None;
    }
    if envelope.session_id != expected_session_id {
        return None;
    }
    if envelope.dir.trim().is_empty() {
        return None;
    }

    let decoded_body =
        decode_connect_message_body(&envelope, encryption_secret, expected_session_id).ok();
    let body_json =
        decoded_body.as_ref().and_then(|value| serde_json::to_string(value).ok()).unwrap_or_else(
            || serde_json::to_string(&envelope.body).unwrap_or_else(|_| "null".to_string()),
        );
    let mut message = ConnectSessionMessage {
        event_id,
        event_created_at,
        dir: envelope.dir,
        seq: envelope.seq,
        msg_type: envelope.msg_type.clone(),
        ts: envelope.ts,
        raw_message_json: raw_message_json.to_string(),
        body_json,
        body_decrypted: decoded_body.is_some(),
        wallet_hello: None,
        set_mining_keys: None,
        client_disconnect: None,
        sign_challenge: None,
        challenge_response: None,
        session_state_after: None,
    };

    match envelope.msg_type.as_str() {
        CONNECT_MESSAGE_TYPE_WALLET_HELLO => {
            if let Some(body) = decoded_body
                .as_ref()
                .and_then(|v| serde_json::from_value::<WalletHelloMetadata>(v.clone()).ok())
            {
                message.wallet_hello = Some(body);
            }
        }
        CONNECT_MESSAGE_TYPE_SET_MINING_KEYS => {
            if let Some(body) = decoded_body
                .as_ref()
                .and_then(|v| serde_json::from_value::<SetMiningKeysMessageBody>(v.clone()).ok())
            {
                let Some(app_id) = normalize_uint256_hex(&body.app_id).ok() else {
                    return Some(message);
                };
                let Some(owner_public) = normalize_owner_public_hex(&body.owner_public).ok() else {
                    return Some(message);
                };
                message.set_mining_keys = Some(SetMiningKeysMessageBody { app_id, owner_public });
            }
        }
        CONNECT_MESSAGE_TYPE_CLIENT_DISCONNECT => {
            if let Ok(mut body) = serde_json::from_value::<ClientDisconnectMessageBody>(
                decoded_body.as_ref().cloned().unwrap_or_else(|| envelope.body.clone()),
            ) {
                body.reason =
                    body.reason.and_then(|v| (!v.trim().is_empty()).then(|| v.trim().to_string()));
                message.client_disconnect = Some(body);
            }
        }
        CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE => {
            if let Some(body) = decoded_body
                .as_ref()
                .and_then(|v| serde_json::from_value::<SignChallengeBody>(v.clone()).ok())
            {
                message.sign_challenge = Some(body);
            }
        }
        CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE => {
            if let Some(body) = decoded_body
                .as_ref()
                .and_then(|v| serde_json::from_value::<ChallengeResponseBody>(v.clone()).ok())
            {
                message.challenge_response = Some(body);
            }
        }
        _ => {}
    }

    Some(message)
}

fn decode_connect_message_body(
    envelope: &ConnectMessageEnvelope,
    encryption_secret: Option<&str>,
    expected_session_id: &str,
) -> AppResult<Value> {
    let alg = envelope.enc.as_ref().map(|v| v.alg.as_str()).unwrap_or(CONNECT_MESSAGE_ENC_NONE);
    if alg == CONNECT_MESSAGE_ENC_NONE {
        return Err(AppError::new("Unencrypted connect messages are no longer accepted")
            .with_kind("connect"));
    }
    if alg != CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256 {
        return Err(AppError::new(format!("Unsupported connect message enc alg `{alg}`"))
            .with_kind("connect"));
    }

    let secret = encryption_secret.map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| {
        AppError::new("Encrypted connect message requires encryption secret").with_kind("connect")
    })?;

    let enc = envelope.enc.as_ref().ok_or_else(|| {
        AppError::new("Encrypted connect message misses `enc`").with_kind("connect")
    })?;
    let nonce_b64url = enc.nonce.as_deref().ok_or_else(|| {
        AppError::new("Encrypted connect message misses nonce").with_kind("connect")
    })?;
    let salt_b64url = enc.salt.as_deref().ok_or_else(|| {
        AppError::new("Encrypted connect message misses salt").with_kind("connect")
    })?;
    let ciphertext_b64url = envelope.body.as_str().ok_or_else(|| {
        AppError::new("Encrypted connect message body must be base64url string")
            .with_kind("connect")
    })?;
    let ts = envelope
        .ts
        .ok_or_else(|| AppError::new("Encrypted connect message misses ts").with_kind("connect"))?;
    let aad = connect_message_aad(
        expected_session_id,
        &envelope.dir,
        envelope.seq,
        &envelope.msg_type,
        ts,
    )
    .map_err(|e| AppError::new(e).with_kind("connect"))?;
    let plaintext =
        decrypt_connect_body(ciphertext_b64url, nonce_b64url, salt_b64url, secret, &aad)
            .map_err(|e| AppError::new(e).with_kind("connect"))?;
    serde_json::from_slice::<Value>(&plaintext).map_err(|e| {
        AppError::new(format!("Deserialize decrypted connect body ({e})")).with_kind("connect")
    })
}

#[cfg(test)]
mod tests {
    use bee_connect::message::derive_connect_message_key;
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::aead::Payload;
    use chacha20poly1305::XChaCha20Poly1305;
    use chacha20poly1305::XNonce;

    use super::*;

    #[test]
    fn parse_set_mining_keys_message() {
        let encryption_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ts = 100u64;
        let seq = 1_700_000_000_000u64;
        let nonce = [5u8; 24];
        let salt = [6u8; 32];
        let body = serde_json::json!({
            "app_id": "0x1",
            "owner_public": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        let aad =
            connect_message_aad("sess_1", "c2w", seq, CONNECT_MESSAGE_TYPE_SET_MINING_KEYS, ts)
                .expect("aad");
        let key = derive_connect_message_key(encryption_secret, &salt).expect("key");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let body_bytes = serde_json::to_vec(&body).expect("body");
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &body_bytes, aad: &aad })
            .expect("encrypt");
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "c2w",
            "seq": seq,
            "type": CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            "ts": ts,
            "enc": {
                "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
                "nonce": URL_SAFE_NO_PAD.encode(nonce),
                "salt": URL_SAFE_NO_PAD.encode(salt),
            },
            "body": URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .to_string();

        let parsed = parse_connect_session_message_with_secret(
            raw,
            "sess_1",
            Some(encryption_secret),
            "evt_1".to_string(),
            123,
        )
        .expect("parse");
        let set = parsed.set_mining_keys.expect("set_mining_keys body");
        assert_eq!(
            set.app_id,
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            set.owner_public,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn parse_unknown_message_keeps_envelope() {
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "c2w",
            "seq": 1_700_000_007_000u64,
            "type": "custom_event",
            "body": { "k": "v" }
        })
        .to_string();

        let parsed =
            parse_connect_session_message(raw, "sess_1", "evt_7".to_string(), 700).expect("parse");
        assert_eq!(parsed.msg_type, "custom_event");
        assert_eq!(parsed.seq, 1_700_000_007_000);
        assert!(parsed.wallet_hello.is_none());
        assert!(parsed.set_mining_keys.is_none());
        assert!(parsed.client_disconnect.is_none());
    }

    /// An application-level `msg_type` this crate knows nothing about still has
    /// to report `body_decrypted`, otherwise the re-key branch in
    /// `modules::connect::query_session_messages` treats it as corrupted and
    /// drops it without advancing the DH state.
    #[test]
    fn parse_unknown_encrypted_message_reports_body_decrypted() {
        let encryption_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ts = 100u64;
        let seq = 1_700_000_011_000u64;
        let nonce = [11u8; 24];
        let salt = [12u8; 32];
        let msg_type = "agent_onboard_request";
        let body = serde_json::json!({ "agent_id": "agent_1" });
        let aad = connect_message_aad("sess_1", "c2w", seq, msg_type, ts).expect("aad");
        let key = derive_connect_message_key(encryption_secret, &salt).expect("key");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let body_bytes = serde_json::to_vec(&body).expect("body");
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &body_bytes, aad: &aad })
            .expect("encrypt");
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "c2w",
            "seq": seq,
            "type": msg_type,
            "ts": ts,
            "enc": {
                "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
                "nonce": URL_SAFE_NO_PAD.encode(nonce),
                "salt": URL_SAFE_NO_PAD.encode(salt),
            },
            "body": URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .to_string();

        let parsed = parse_connect_session_message_with_secret(
            &raw,
            "sess_1",
            Some(encryption_secret),
            "evt_11".to_string(),
            1100,
        )
        .expect("parse");
        assert!(parsed.body_decrypted, "unknown msg_type must still report a decrypted body");
        assert_eq!(parsed.body_json, serde_json::to_string(&body).expect("body json"));
        assert!(parsed.wallet_hello.is_none());
        assert!(parsed.set_mining_keys.is_none());
        assert!(parsed.client_disconnect.is_none());
        assert!(parsed.sign_challenge.is_none());
        assert!(parsed.challenge_response.is_none());

        // Wrong secret: body stays undecrypted, yet body_json falls back to the
        // raw ciphertext envelope body — which is why body_json can never be
        // used as the "did it decrypt" signal.
        let wrong_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let undecrypted = parse_connect_session_message_with_secret(
            &raw,
            "sess_1",
            Some(wrong_secret),
            "evt_11".to_string(),
            1100,
        )
        .expect("parse");
        assert!(!undecrypted.body_decrypted);
        assert!(!undecrypted.body_json.is_empty());
        assert_ne!(undecrypted.body_json, "null");
    }

    #[test]
    fn parse_encrypted_set_mining_keys_message_with_secret() {
        let encryption_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ts = 100u64;
        let nonce = [7u8; 24];
        let salt = [9u8; 32];
        let body = serde_json::json!({
            "app_id": "0x1",
            "owner_public": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        let aad = connect_message_aad(
            "sess_1",
            "c2w",
            1_700_000_000_000u64,
            CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            ts,
        )
        .expect("aad");
        let key = derive_connect_message_key(encryption_secret, &salt).expect("key");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let body_bytes = serde_json::to_vec(&body).expect("body");
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &body_bytes, aad: &aad })
            .expect("encrypt");
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "c2w",
            "seq": 1_700_000_000_000u64,
            "type": CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            "ts": ts,
            "enc": {
                "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
                "nonce": URL_SAFE_NO_PAD.encode(nonce),
                "salt": URL_SAFE_NO_PAD.encode(salt),
            },
            "body": URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .to_string();

        let parsed = parse_connect_session_message_with_secret(
            raw,
            "sess_1",
            Some(encryption_secret),
            "evt_9".to_string(),
            900,
        )
        .expect("parse");
        let set = parsed.set_mining_keys.expect("set_mining_keys body");
        assert_eq!(
            set.app_id,
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            set.owner_public,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn parse_encrypted_set_mining_keys_without_secret_keeps_message_untyped() {
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "c2w",
            "seq": 1_700_000_000_000u64,
            "type": CONNECT_MESSAGE_TYPE_SET_MINING_KEYS,
            "ts": 100u64,
            "enc": {
                "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
                "nonce": URL_SAFE_NO_PAD.encode([1u8; 24]),
                "salt": URL_SAFE_NO_PAD.encode([2u8; 32]),
            },
            "body": URL_SAFE_NO_PAD.encode([3u8; 48]),
        })
        .to_string();

        let parsed = parse_connect_session_message(raw, "sess_1", "evt_10".to_string(), 1000)
            .expect("parse");
        assert_eq!(parsed.msg_type, CONNECT_MESSAGE_TYPE_SET_MINING_KEYS);
        assert!(parsed.set_mining_keys.is_none());
    }

    #[test]
    fn encode_wallet_hello_with_dh_public() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let wallet_dh_pub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let json = encode_wallet_hello_message(
            "sess_1",
            "TestWallet",
            "0:addr123",
            secret,
            wallet_dh_pub,
            1_700_000_000_000,
            None,
            None,
            None,
        )
        .expect("encode");
        let envelope: ConnectMessageEnvelope = serde_json::from_str(&json).expect("envelope");
        assert_eq!(envelope.msg_type, "wallet_hello");
        assert_eq!(envelope.dh_public.as_deref(), Some(wallet_dh_pub));
        let enc = envelope.enc.as_ref().expect("enc");
        assert_eq!(enc.alg, CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256);
        let body = decode_connect_message_body(&envelope, Some(secret), "sess_1").expect("decode");
        let hello: WalletHelloMetadata = serde_json::from_value(body).expect("parse");
        assert_eq!(hello.wallet_name, "TestWallet");
        assert_eq!(hello.wallet_address, "0:addr123");
        assert_eq!(hello.challenge_nonce, None);
        assert_eq!(hello.challenge_signature, None);
        assert_eq!(hello.challenge_epk_public, None);
    }

    #[test]
    fn encode_wallet_hello_with_challenge_includes_fields() {
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let wallet_dh_pub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let json = encode_wallet_hello_message(
            "sess_1",
            "ChallengeWallet",
            "0:chal",
            secret,
            wallet_dh_pub,
            1_700_000_000_000,
            Some("deadbeef"),
            Some("sig123"),
            Some("epk456"),
        )
        .expect("encode");

        let envelope: ConnectMessageEnvelope = serde_json::from_str(&json).expect("envelope");
        let body = decode_connect_message_body(&envelope, Some(secret), "sess_1").expect("decode");
        let hello: WalletHelloMetadata = serde_json::from_value(body).expect("parse");
        assert_eq!(hello.wallet_name, "ChallengeWallet");
        assert_eq!(hello.wallet_address, "0:chal");
        assert_eq!(hello.challenge_nonce.as_deref(), Some("deadbeef"));
        assert_eq!(hello.challenge_signature.as_deref(), Some("sig123"));
        assert_eq!(hello.challenge_epk_public.as_deref(), Some("epk456"));
    }

    #[test]
    fn normalize_query_limit_clamps() {
        assert_eq!(normalize_query_session_messages_limit(None), 50);
        assert_eq!(normalize_query_session_messages_limit(Some(0)), 1);
        assert_eq!(normalize_query_session_messages_limit(Some(500)), 200);
    }

    // ── Tests: sign_challenge / challenge_response parsing ──────────

    #[test]
    fn parse_sign_challenge_message() {
        let encryption_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ts = 200u64;
        let seq = 1_700_000_002_000u64;
        let nonce = [11u8; 24];
        let salt = [12u8; 32];
        let body = serde_json::json!({ "nonce": "deadbeef42" });
        let aad =
            connect_message_aad("sess_1", "c2w", seq, CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE, ts)
                .expect("aad");
        let key = derive_connect_message_key(encryption_secret, &salt).expect("key");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let body_bytes = serde_json::to_vec(&body).expect("body");
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &body_bytes, aad: &aad })
            .expect("encrypt");
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "c2w",
            "seq": seq,
            "type": CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE,
            "ts": ts,
            "enc": {
                "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
                "nonce": URL_SAFE_NO_PAD.encode(nonce),
                "salt": URL_SAFE_NO_PAD.encode(salt),
            },
            "body": URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .to_string();

        let parsed = parse_connect_session_message_with_secret(
            raw,
            "sess_1",
            Some(encryption_secret),
            "evt_sc".to_string(),
            200,
        )
        .expect("parse");
        assert_eq!(parsed.msg_type, CONNECT_MESSAGE_TYPE_SIGN_CHALLENGE);
        let sc = parsed.sign_challenge.expect("sign_challenge body");
        assert_eq!(sc.nonce, "deadbeef42");
        assert!(parsed.challenge_response.is_none());
    }

    #[test]
    fn parse_challenge_response_message() {
        let encryption_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ts = 201u64;
        let seq = 1_700_000_003_000u64;
        let nonce = [13u8; 24];
        let salt = [14u8; 32];
        let sig = "cc".repeat(64);
        let body = serde_json::json!({
            "nonce": "deadbeef42",
            "signature": sig,
            "wallet_address": "0:abcdef",
        });
        let aad =
            connect_message_aad("sess_1", "w2c", seq, CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE, ts)
                .expect("aad");
        let key = derive_connect_message_key(encryption_secret, &salt).expect("key");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let body_bytes = serde_json::to_vec(&body).expect("body");
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &body_bytes, aad: &aad })
            .expect("encrypt");
        let raw = serde_json::json!({
            "v": CONNECT_MESSAGE_VERSION,
            "session_id": "sess_1",
            "dir": "w2c",
            "seq": seq,
            "type": CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE,
            "ts": ts,
            "enc": {
                "alg": CONNECT_MESSAGE_ENC_XCHACHA20POLY1305_HKDF_SHA256,
                "nonce": URL_SAFE_NO_PAD.encode(nonce),
                "salt": URL_SAFE_NO_PAD.encode(salt),
            },
            "body": URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .to_string();

        let parsed = parse_connect_session_message_with_secret(
            raw,
            "sess_1",
            Some(encryption_secret),
            "evt_cr".to_string(),
            201,
        )
        .expect("parse");
        assert_eq!(parsed.msg_type, CONNECT_MESSAGE_TYPE_CHALLENGE_RESPONSE);
        let cr = parsed.challenge_response.expect("challenge_response body");
        assert_eq!(cr.nonce, "deadbeef42");
        assert_eq!(cr.signature, sig);
        assert_eq!(cr.wallet_address, "0:abcdef");
        assert!(parsed.sign_challenge.is_none());
    }

    #[test]
    fn encode_wallet_hello_rejects_seq_zero() {
        let secret = "aa".repeat(32);
        let dh_pub = "bb".repeat(32);
        let err = encode_wallet_hello_message(
            "sess_1", "W", "0:addr", &secret, &dh_pub, 0, None, None, None,
        )
        .unwrap_err();
        assert!(err.message.contains("seq must be > 0"), "got: {}", err.message);
    }

    #[test]
    fn encode_challenge_response_rejects_seq_zero() {
        let secret = "aa".repeat(32);
        let dh_pub = "bb".repeat(32);
        let err = encode_challenge_response_message(
            "sess_1", "deadbeef", "sigHex", "0:addr", None, &secret, &dh_pub, 0,
        )
        .unwrap_err();
        assert!(err.message.contains("seq must be > 0"), "got: {}", err.message);
    }
}
