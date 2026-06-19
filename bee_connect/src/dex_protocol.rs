//! DEX operations over bee_connect — typed request/response structs.
//!
//! Implements the message protocol from `dex_connect_protocol.md v1`.
//! All u128/u64 values are serialized as decimal strings per §6.3.

use serde::Deserialize;
use serde::Serialize;

// ── Common envelope ──────────────────────────────────────────────

pub const PROTOCOL_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexRequestEnvelope {
    pub protocol_version: String,
    pub chain_id: String,
    pub kind: String,
    pub request_id: String,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub valid_until: Option<u64>,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexResponseEnvelope {
    pub protocol_version: String,
    pub kind: String,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DexErrorPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexRequestAck {
    pub protocol_version: String,
    pub kind: String, // "dex_request_received"
    pub request_id: String,
    pub ack: bool,
}

// ── Labels (informational, from site) ────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DexLabels {
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub outcomes: Option<Vec<String>>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub site_description: Option<String>,
}

// ── deploy_pmp ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPmpParams {
    pub event_id: String,
    pub oracle_list_hash: String,
    pub oracle_fee: Vec<String>, // u128 as decimal strings
    pub token_type: u32,
    pub names: Vec<String>,
    pub index: Vec<u64>,
    pub initial_stakes: Vec<String>, // u128 as decimal strings
    #[serde(default)]
    pub outcome_count: Option<u32>,
    #[serde(default)]
    pub gas_to_fund: Option<String>, // u128 as decimal string
    #[serde(default)]
    pub labels: Option<DexLabels>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPmpResult {
    pub pmp_address: String,
    pub source_note_dih: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_funded: Option<String>,
}

// ── set_stake ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetStakeParams {
    pub pmp_address: String,
    pub event_id: String,
    pub oracle_list_hash: String,
    pub token_type: u32,
    pub outcome: u32,
    pub amount: String, // u128 as decimal string
    #[serde(default)]
    pub use_coupon: bool,
    #[serde(default)]
    pub gas_to_fund: Option<String>,
    #[serde(default)]
    pub labels: Option<DexLabels>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetStakeResult {
    pub source_note_dih: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

// ── claim ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimParams {
    pub pmp_address: String,
    pub event_id: String,
    pub oracle_list_hash: String,
    pub token_type: u32,
    #[serde(default)]
    pub gas_to_fund: Option<String>,
    #[serde(default)]
    pub labels: Option<DexLabels>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResult {
    pub source_note_dih: String,
}

// ── cancel_stake ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelStakeParams {
    pub pmp_address: String,
    pub event_id: String,
    pub oracle_list_hash: String,
    pub token_type: u32,
    #[serde(default)]
    pub gas_to_fund: Option<String>,
    #[serde(default)]
    pub labels: Option<DexLabels>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelStakeResult {
    pub source_note_dih: String,
}

// ── Error codes ──────────────────────────────────────────────────

pub mod error_code {
    pub const USER_REJECTED: &str = "user_rejected";
    pub const EXPIRED: &str = "expired";
    pub const CHAIN_MISMATCH: &str = "chain_mismatch";
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const INVALID_PARAMS: &str = "invalid_params";
    pub const INVALID_U128_FORMAT: &str = "invalid_u128_format";
    pub const TOKEN_TYPE_UNSUPPORTED: &str = "token_type_unsupported";
    pub const OUTCOME_COUNT_MISMATCH: &str = "outcome_count_mismatch";
    pub const NO_MATCHING_NOTE: &str = "no_matching_note";
    pub const INSUFFICIENT_BALANCE: &str = "insufficient_balance";
    pub const PMP_ADDRESS_MISMATCH: &str = "pmp_address_mismatch";
    pub const GAS_FUND_FAILED: &str = "gas_fund_failed";
    pub const DEPLOY_FAILED: &str = "deploy_failed";
    pub const SET_STAKE_FAILED: &str = "set_stake_failed";
    pub const CLAIM_FAILED: &str = "claim_failed";
    pub const CANCEL_STAKE_FAILED: &str = "cancel_stake_failed";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const IN_PROGRESS: &str = "in_progress";
    pub const INTERNAL_ERROR: &str = "internal_error";
}

// ── Helpers ──────────────────────────────────────────────────────

impl DexRequestEnvelope {
    /// Parse typed params from the envelope based on `kind`.
    pub fn parse_params(&self) -> Result<DexTypedParams, String> {
        match self.kind.as_str() {
            super::message::CONNECT_MESSAGE_TYPE_DEX_DEPLOY_PMP_REQUEST => {
                let p: DeployPmpParams = serde_json::from_value(self.params.clone())
                    .map_err(|e| format!("parse deploy_pmp params: {e}"))?;
                Ok(DexTypedParams::DeployPmp(p))
            }
            super::message::CONNECT_MESSAGE_TYPE_DEX_SET_STAKE_REQUEST => {
                let p: SetStakeParams = serde_json::from_value(self.params.clone())
                    .map_err(|e| format!("parse set_stake params: {e}"))?;
                Ok(DexTypedParams::SetStake(p))
            }
            super::message::CONNECT_MESSAGE_TYPE_DEX_CLAIM_REQUEST => {
                let p: ClaimParams = serde_json::from_value(self.params.clone())
                    .map_err(|e| format!("parse claim params: {e}"))?;
                Ok(DexTypedParams::Claim(p))
            }
            super::message::CONNECT_MESSAGE_TYPE_DEX_CANCEL_STAKE_REQUEST => {
                let p: CancelStakeParams = serde_json::from_value(self.params.clone())
                    .map_err(|e| format!("parse cancel_stake params: {e}"))?;
                Ok(DexTypedParams::CancelStake(p))
            }
            _ => Err(format!("unknown dex request kind: {}", self.kind)),
        }
    }

    /// Check if this request has expired.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.valid_until.is_some_and(|t| now_unix > t)
    }

    /// Validate protocol_version.
    pub fn validate_version(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!("unsupported protocol_version: {}", self.protocol_version));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DexTypedParams {
    DeployPmp(DeployPmpParams),
    SetStake(SetStakeParams),
    Claim(ClaimParams),
    CancelStake(CancelStakeParams),
}

impl DexResponseEnvelope {
    pub fn success(request_kind: &str, request_id: &str, result: serde_json::Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            kind: format!("{}_response", request_kind.trim_end_matches("_request")),
            request_id: request_id.to_string(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(request_kind: &str, request_id: &str, code: &str, message: &str) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            kind: format!("{}_response", request_kind.trim_end_matches("_request")),
            request_id: request_id.to_string(),
            ok: false,
            result: None,
            error: Some(DexErrorPayload {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
            }),
        }
    }
}

impl DexRequestAck {
    pub fn new(request_id: &str) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            kind: super::message::CONNECT_MESSAGE_TYPE_DEX_REQUEST_RECEIVED.to_string(),
            request_id: request_id.to_string(),
            ack: true,
        }
    }
}

/// Parse a decimal string as u128, rejecting hex/scientific/number-typed
/// values.
pub fn parse_u128_decimal(s: &str) -> Result<u128, String> {
    s.parse::<u128>().map_err(|e| format!("invalid u128 decimal '{s}': {e}"))
}

/// Validate all u128 string fields in DeployPmpParams.
pub fn validate_deploy_pmp_params(p: &DeployPmpParams) -> Result<(), (String, String)> {
    for (i, fee) in p.oracle_fee.iter().enumerate() {
        parse_u128_decimal(fee).map_err(|e| (format!("oracle_fee[{i}]"), e))?;
    }
    for (i, stake) in p.initial_stakes.iter().enumerate() {
        parse_u128_decimal(stake).map_err(|e| (format!("initial_stakes[{i}]"), e))?;
    }
    if let Some(ref gas) = p.gas_to_fund {
        parse_u128_decimal(gas).map_err(|e| ("gas_to_fund".to_string(), e))?;
    }
    if let Some(oc) = p.outcome_count {
        if p.initial_stakes.len() != oc as usize {
            return Err((
                "outcome_count".to_string(),
                format!("initial_stakes.len()={} != outcome_count={oc}", p.initial_stakes.len()),
            ));
        }
    }
    Ok(())
}

/// Validate u128 fields in SetStakeParams.
pub fn validate_set_stake_params(p: &SetStakeParams) -> Result<(), (String, String)> {
    parse_u128_decimal(&p.amount).map_err(|e| ("amount".to_string(), e))?;
    if let Some(ref gas) = p.gas_to_fund {
        parse_u128_decimal(gas).map_err(|e| ("gas_to_fund".to_string(), e))?;
    }
    Ok(())
}
