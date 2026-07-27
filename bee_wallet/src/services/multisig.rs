//! Flat `Multisig` deploy helpers (kit `contracts/abi/multisig/`).
//!
//! Three composable, network-agnostic bricks plus one shellnet-only
//! convenience composition:
//!
//! 1. [`compute_multisig_address`] — derive the deterministic address of a
//!    not-yet-deployed Multisig. Pure crypto, usable by anyone.
//! 2. giver top-up — fund the future address from the default shellnet giver.
//!    **Shellnet only** (the giver account `0:1111…` exists nowhere else); kept
//!    private, reachable solely through [`deploy_multisig_via_giver`].
//! 3. [`deploy_multisig`] — deploy a Multisig whose address is *already
//!    funded*. Network-agnostic: works on any network as long as the address
//!    has a balance to pay for the deploy. Idempotent (returns early if
//!    Active).
//!
//! [`deploy_multisig_via_giver`] wires 1 → 2 → 3 for a fully client-side
//! shellnet deploy. The ABI/TVC are vendored from the kit (`assets/multisig/`)
//! because the kit's `multisig` binding intentionally leaves deploy out of
//! scope.
//!
//! That pair is the *default*, not a hard wiring: every brick takes its build
//! from the spec ([`MultisigDeploySpec::code`]), so three things are deployable
//! — the default build, a second build vendored here
//! (`UpdateCustodianMultisigWallet` v2, `code: "update_custodian_v2"`), or a
//! caller's own (`code: { tvc_b64, abi }`). Handy while v2 rolls out: shellnet
//! on v2, mainnet still on the default. A different build means a different
//! derived address, which is why the override feeds brick 1 too, and why code
//! and ABI travel together (see [`MultisigCode`]).

use std::collections::HashMap;
use std::sync::Arc;

use ackinacki_kit::contracts::account::Account;
use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver;
use ackinacki_kit::tvm_client::abi::encode_message;
use ackinacki_kit::tvm_client::abi::Abi;
use ackinacki_kit::tvm_client::abi::CallSet;
use ackinacki_kit::tvm_client::abi::DeploySet;
use ackinacki_kit::tvm_client::abi::ParamsOfEncodeMessage;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::generate_random_sign_keys;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::processing::process_message;
use ackinacki_kit::tvm_client::processing::ParamsOfProcessMessage;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use base64::Engine;
use bee_infra::with_retry_policy;
use bee_infra::RateLimiter;
use bee_infra::RetryPolicy;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

use crate::errors::AppError;
use crate::errors::AppResult;

/// Canonical flat Multisig ABI/TVC, vendored at build time so the deploy is
/// fully self-contained (the kit doesn't expose them publicly). This is the
/// *default* build only — [`MultisigDeploySpec::code`] overrides it per deploy,
/// so a caller can put a different build (e.g. `UpdateCustodianMultisigWallet`
/// v2) on one network while the default stays put. See
/// `assets/multisig/PROVENANCE.md`.
const MULTISIG_ABI: &str = include_str!("../../assets/multisig/Multisig.abi.json");
const MULTISIG_TVC: &[u8] = include_bytes!("../../assets/multisig/Multisig.tvc");

/// `UpdateCustodianMultisigWallet` v2.1.0, the second vendored build — selected
/// by name (`code: "update_custodian_v2"`) instead of shipping the `.tvc` from
/// the frontend. Vendored verbatim from `gosh-sh/acki-nacki` `dev`
/// (`contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/`, the merged
/// form of #2413); code hash `09f596d5…`, `sold 0.81.0`. Its ABI is a strict
/// superset of the default's (adds `submitUpdateCode`/`confirmUpdateCode`) but
/// its `fields` add two storage slots, so it must be deployed with its OWN ABI
/// — see [`MultisigCode`].
const UPDATE_CUSTODIAN_V2_ABI: &str =
    include_str!("../../assets/multisig/v2/UpdateCustodianMultisigWallet.abi.json");
const UPDATE_CUSTODIAN_V2_TVC: &[u8] =
    include_bytes!("../../assets/multisig/v2/UpdateCustodianMultisigWallet.tvc");

/// Wire name of the [`UPDATE_CUSTODIAN_V2_TVC`] build.
const UPDATE_CUSTODIAN_V2_NAME: &str = "update_custodian_v2";
/// sha256 of [`UPDATE_CUSTODIAN_V2_TVC`], pinned so a swapped asset is caught
/// by a unit test rather than on-chain. Corresponds to code hash
/// `09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded`.
/// Test-only: the fixture it guards is the only consumer, and CI lints the lib
/// without `--tests`, where an ungated const reads as dead code.
#[cfg(test)]
const UPDATE_CUSTODIAN_V2_TVC_SHA256: &str =
    "535e180e85ee019c23631c6046449fa2a5536d88f55b26d64e026d671e82d520";

/// Constructor parameters [`MultisigDeploySpec::encode_params`] hardcodes. An
/// `abi` override must declare exactly these, in this order — otherwise the
/// input JSON below cannot be encoded against it. Overrides that only *add*
/// functions (v2's `submitUpdateCode` / `confirmUpdateCode`) are fine.
const CONSTRUCTOR_INPUTS: [&str; 5] =
    ["owners_pubkey", "owners_address", "reqConfirms", "reqConfirmsData", "value"];

/// ECC currency id of SHELL. Sent via the flag-16 creation transfer it
/// collapses into the account's native balance — which is fine for the cheap
/// gas top-up that brings the address into existence. The real HELD SHELL is
/// sent AFTER deploy via flag-1 (where it stays ECC[2]).
const SHELL_CURRENCY_ID: u32 = 2;
/// SHELL (as ECC) carried by the flag-16 creation transfer. Funding MUST go as
/// ECC, not native `value`: native value doesn't cross a dapp_id boundary and a
/// fresh account is the root of its own dapp, so giver-native would never
/// arrive. Flag 16 collapses this ECC SHELL into the new account's native
/// balance (its gas). A "human" 1,000,000 SHELL (× 10^9 nano = `ECC_TOPUP_GAS`
/// is 1 SHELL).
const DEFAULT_GIVER_VALUE: u64 = 1_000_000 * ECC_TOPUP_GAS;
/// Native VMSHELL `value` accompanying the post-deploy flag-1 ECC top-up — gas
/// for the live account to process it. Mirrors `bin/faucet.rs`.
const ECC_TOPUP_GAS: u64 = 1_000_000_000;
/// `sendCurrencyWithFlag` flag that brings a *not-yet-existing* address into
/// existence (Uninit). A plain flag-1 transfer does NOT create the account.
const GIVER_FLAG: u8 = 16;
/// Max external-message sends per second for the giver/deploy path. The node
/// throttles on-chain sends at ~3/s → 429; 2/s leaves a ≥500 ms gap (over the
/// 350 ms floor the consumer asked for, under the node's ceiling). Reads are
/// NOT gated — only the sends in [`deploy_multisig_via_giver`] go through this.
const MAX_SEND_RPS: u32 = 2;

/// A multisig build to deploy: compiled code plus the ABI it was compiled from.
///
/// The two are **one unit, not two independent knobs**. On ABI ≥ 2.3 (both
/// builds here are 2.4) the state-init *data* cell is rebuilt from the ABI's
/// `fields` list and then hashed into the address — see
/// `tvm_sdk::ContractImage::update_data`, which routes non-data-map ABIs
/// through `encode_storage_fields(abi_json, …)` and re-derives
/// `state_init.hash()`. So an ABI carries storage layout, not just a calling
/// convention: pairing v1's ABI with v2's code yields a *different* address
/// whose data cell the code does not agree with (measured against
/// `UpdateCustodianMultisigWallet` v2.1.0, whose `fields` add
/// `m_requestsMaskCode` and `m_code`). Hence one struct.
#[derive(Debug, Clone)]
pub struct MultisigCode {
    /// Raw `.tvc` bytes of the build.
    pub tvc: Vec<u8>,
    /// Contents of that build's `.abi.json`.
    pub abi: String,
}

impl MultisigCode {
    /// `UpdateCustodianMultisigWallet` v2.1.0, vendored in this SDK — code hash
    /// `09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded`. Over
    /// the wasm boundary the same build is `code: "update_custodian_v2"`.
    pub fn update_custodian_v2() -> Self {
        Self { tvc: UPDATE_CUSTODIAN_V2_TVC.to_vec(), abi: UPDATE_CUSTODIAN_V2_ABI.to_string() }
    }

    /// Resolves a vendored build by its wire name.
    fn by_name(name: &str) -> AppResult<Self> {
        match name {
            UPDATE_CUSTODIAN_V2_NAME => Ok(Self::update_custodian_v2()),
            other => Err(AppError::new(format!(
                "unknown multisig build `{other}` — vendored builds are \
                 [{UPDATE_CUSTODIAN_V2_NAME}]; omit `code` for the default build, or pass \
                 `{{ tvc_b64, abi }}` for your own",
            ))),
        }
    }
}

/// Everything needed to deterministically encode a flat Multisig deploy. The
/// owner `keys` sign their own deploy; `owners_pubkey` are the custodians
/// (`uint256[]`, each a `0x`-prefixed hex), defaulting to the owner alone.
///
/// `code` is the contract-build escape hatch: `None` deploys the vendored
/// build, `Some` deploys whatever you hand it (e.g.
/// `UpdateCustodianMultisigWallet` v2 on one network while another stays on the
/// vendored one). It feeds address derivation too, so
/// [`compute_multisig_address`] and [`deploy_multisig`] always agree on the
/// build the spec carries.
#[derive(Debug, Clone)]
pub struct MultisigDeploySpec {
    pub keys: KeyPair,
    pub owners_pubkey: Vec<String>,
    pub req_confirms: u8,
    pub req_confirms_data: u8,
    /// Constructor `value` arg (`uint64`), passed through as a decimal string.
    pub constructor_value: String,
    /// Build override. `None` = the vendored build.
    pub code: Option<MultisigCode>,
}

impl MultisigDeploySpec {
    /// Code this spec deploys: the caller's override, else the vendored build.
    fn code_bytes(&self) -> &[u8] {
        self.code.as_ref().map_or(MULTISIG_TVC, |code| code.tvc.as_slice())
    }

    /// ABI this spec encodes against: the caller's override, else the vendored
    /// one.
    fn abi_json(&self) -> &str {
        self.code.as_ref().map_or(MULTISIG_ABI, |code| code.abi.as_str())
    }

    /// Rejects an override that tvm_client would only reject much later, deep
    /// inside BOC/ABI parsing — or, worse, that would encode cleanly and fail
    /// on-chain. Cheap and local: non-empty code, parseable ABI, and a
    /// `constructor` matching [`CONSTRUCTOR_INPUTS`]. A `None` override is
    /// always valid (the vendored pair is known good, and the test below pins
    /// it against this same check).
    fn validate(&self) -> AppResult<()> {
        let Some(code) = self.code.as_ref() else { return Ok(()) };
        if code.tvc.is_empty() {
            return Err(AppError::new("multisig code override has an empty `tvc`"));
        }

        let parsed: serde_json::Value = serde_json::from_str(&code.abi).map_err(|e| {
            AppError::new(format!("multisig `abi` override is not valid JSON: {e}"))
        })?;
        let constructor = parsed
            .get("functions")
            .and_then(|f| f.as_array())
            .and_then(|fns| {
                fns.iter().find(|f| f.get("name").and_then(|n| n.as_str()) == Some("constructor"))
            })
            .ok_or_else(|| AppError::new("multisig `abi` override declares no `constructor`"))?;
        let inputs: Vec<&str> = constructor
            .get("inputs")
            .and_then(|i| i.as_array())
            .map(|inputs| {
                inputs.iter().filter_map(|i| i.get("name").and_then(|n| n.as_str())).collect()
            })
            .unwrap_or_default();
        if inputs != CONSTRUCTOR_INPUTS {
            return Err(AppError::new(format!(
                "multisig `abi` override has an incompatible constructor: got [{}], expected [{}]",
                inputs.join(", "),
                CONSTRUCTOR_INPUTS.join(", "),
            )));
        }
        Ok(())
    }

    /// Builds the `ParamsOfEncodeMessage` shared by address computation and the
    /// actual deploy, so both derive from one source of truth.
    fn encode_params(&self) -> ParamsOfEncodeMessage {
        let tvc_b64 = base64::engine::general_purpose::STANDARD.encode(self.code_bytes());
        ParamsOfEncodeMessage {
            abi: Abi::Json(self.abi_json().to_string()),
            address: None,
            deploy_set: Some(DeploySet {
                tvc: Some(tvc_b64),
                code: None,
                state_init: None,
                workchain_id: Some(0),
                initial_data: Some(json!({ "_pubkey": format!("0x{}", self.keys.public) })),
                initial_pubkey: None,
            }),
            call_set: Some(CallSet {
                function_name: "constructor".to_string(),
                header: None,
                input: Some(json!({
                    "owners_pubkey": self.owners_pubkey,
                    "owners_address": [],
                    "reqConfirms": self.req_confirms,
                    "reqConfirmsData": self.req_confirms_data,
                    "value": self.constructor_value,
                })),
            }),
            signer: Signer::Keys { keys: self.keys.clone() },
            processing_try_index: None,
            signature_id: None,
        }
    }
}

/// A fresh account is the root of its own dApp, so its `dapp_id` equals its
/// bare account-id (lookups are dApp-scoped on `>= 1.0.0` servers).
fn dapp_id_of(address: &str) -> String {
    address.trim_start_matches("0:").to_string()
}

/// Canonical dApp-scoped address for a self-rooted account (dapp_id ==
/// account): `<id>::<id>`. Only for values returned to callers; on-chain ops
/// use raw `0:<hex>`.
fn canonical_address(raw: &str) -> String {
    let id = raw.trim_start_matches("0:");
    format!("{id}::{id}")
}

/// **Brick 1.** Derive the deterministic address of a not-yet-deployed flat
/// Multisig. Pure local crypto — no network round-trip beyond `ctx` setup.
/// Derives from `spec.code` when set, so a build override yields the address
/// that build will actually occupy.
pub async fn compute_multisig_address(
    ctx: Arc<ClientContext>,
    spec: &MultisigDeploySpec,
) -> AppResult<String> {
    spec.validate()?;
    let encoded = encode_message(ctx, spec.encode_params()).await?;
    Ok(encoded.address)
}

/// Outcome of [`deploy_multisig`].
pub struct DeployOutcome {
    pub address: String,
    pub already_deployed: bool,
    /// Deploy transaction id; `None` when the account was already Active.
    pub deploy_tx: Option<String>,
}

/// **Brick 3.** Deploy a flat Multisig whose address is *already funded*.
/// Network-agnostic — anyone can call this once the computed address holds a
/// balance. Idempotent: if the account is already Active, returns immediately
/// without sending a deploy message.
pub async fn deploy_multisig(
    ctx: Arc<ClientContext>,
    spec: &MultisigDeploySpec,
    wait_for_active: bool,
) -> AppResult<DeployOutcome> {
    spec.validate()?;
    let encode_params = spec.encode_params();
    let address = encode_message(ctx.clone(), encode_params.clone()).await?.address;
    let dapp_id = dapp_id_of(&address);

    // Idempotency: already deployed -> nothing to do.
    let mut account = Account::new(ctx.clone(), &address, dapp_id.clone());
    account.fetch().await?;
    if account.acc_type == AccountStatus::Active {
        return Ok(DeployOutcome {
            address: canonical_address(&address),
            already_deployed: true,
            deploy_tx: None,
        });
    }

    let processed = process_message(
        ctx.clone(),
        ParamsOfProcessMessage {
            message_encode_params: encode_params,
            send_events: false,
            dapp_id,
        },
        // No progress events requested; an empty Send future satisfies the bound.
        |_| async {},
    )
    .await;

    let deploy_tx = match processed {
        Ok(result) => result.transaction.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()),
        // A failed *read-back* is not a failed deploy. `process_message` sends the
        // message and then fetches the resulting transaction
        // (`blockchain{transaction(hash){boc out_messages{boc}}}`); when that query
        // fails, the deploy it just performed is reported as an error. Measured on
        // shellnet with the `UpdateCustodianMultisigWallet` v2 build: the deploy
        // lands (account Active, `exit_code: 0`, expected code hash) while the
        // gateway answers that transaction query with HTTP 502 — reproducible with
        // plain curl on the tx hash, because v2's ~7 KB of code makes for a much
        // larger transaction BOC than the vendored build's.
        //
        // So before believing the error, ask the chain (bounded: 10 × 1 s, error
        // path only, even when `wait_for_active` is false — a wrong failure is
        // worse than a short wait). Only the matching build + owner key can make
        // *this* address Active (it's a state-init hash), so Active here can only
        // be our own deploy. The tx id is unknowable at that point -> `None`.
        Err(err) => {
            let landed = account
                .wait(ParamsOfWaitAccount { status: AccountStatus::Active, ..Default::default() })
                .await
                .is_ok();
            if !landed {
                return Err(AppError::from(err));
            }
            None
        }
    };

    if wait_for_active {
        account
            .wait(ParamsOfWaitAccount { status: AccountStatus::Active, ..Default::default() })
            .await?;
    }

    Ok(DeployOutcome { address: canonical_address(&address), already_deployed: false, deploy_tx })
}

/// Parameters for [`deploy_multisig_via_giver`]. All amounts are strings: u64 /
/// ECC values exceed `2^53` and would lose precision as a JS `number`.
#[derive(Debug, Clone, Deserialize)]
pub struct ParamsOfDeployMultisigViaGiver {
    /// GQL endpoints of the (shellnet) network.
    pub endpoints: Vec<String>,
    /// Owner keypair. Generated when absent — always returned to the caller.
    #[serde(default)]
    pub keys: Option<KeyPair>,
    /// Custodian pubkeys (`uint256[]`, each `0x`-hex). Defaults to `[owner]`.
    #[serde(default)]
    pub owners_pubkey: Option<Vec<String>>,
    #[serde(default)]
    pub req_confirms: Option<u8>,
    #[serde(default)]
    pub req_confirms_data: Option<u8>,
    /// Constructor `value` arg (`uint64` as string). Default `"0"`.
    #[serde(default)]
    pub constructor_value: Option<String>,
    /// SHELL-ECC funding of the future address via the flag-16 creation
    /// transfer (u64 as string; collapses into native balance). Default
    /// `"1000000000000000"` (1,000,000 SHELL). NB this rides on ECC, not native
    /// `value`, which can't cross dapp_id.
    #[serde(default)]
    pub giver_value: Option<String>,
    /// ECC top-up `{ currency_id: amount(u64-string) }`. Default `{}`.
    #[serde(default)]
    pub giver_ecc: Option<HashMap<u32, String>>,
    /// Wait for the deployed account to reach Active. Default `true`.
    #[serde(default)]
    pub wait_for_active: Option<bool>,
    /// Build override: a vendored build's name (`"update_custodian_v2"`) or
    /// your own `{ tvc_b64, abi }`. Absent → the default vendored build.
    #[serde(default)]
    pub code: Option<ParamsOfMultisigCode>,
}

/// Wire form of a build selection: either a build vendored in this SDK, picked
/// by name, or a caller-supplied pair. The pair is always both halves — see
/// [`MultisigCode`] for why they can't be supplied independently.
#[derive(Debug, Clone)]
pub enum ParamsOfMultisigCode {
    /// A build vendored here, e.g. `"update_custodian_v2"`.
    Named(String),
    /// Your own build: base64 `.tvc` (line wrapping tolerated) plus that
    /// build's `.abi.json`, either stringified or as the already-parsed object
    /// (JS callers usually hold the latter — `import abi from "…json"`).
    Custom { tvc_b64: String, abi: serde_json::Value },
}

/// Hand-written so the shape errors name the actual mistake. A derived
/// `#[serde(untagged)]` enum answers every malformed `code` with "data did not
/// match any variant", which is useless precisely where the caller needs help —
/// e.g. sending `{ tvc_b64 }` and forgetting the ABI, the one mistake that
/// would otherwise put a build at an address whose storage layout it disagrees
/// with.
impl<'de> Deserialize<'de> for ParamsOfMultisigCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(name) => Ok(Self::Named(name)),
            serde_json::Value::Object(mut map) => {
                let tvc_b64 = map.remove("tvc_b64");
                let abi = map.remove("abi");
                match (tvc_b64, abi) {
                    (Some(serde_json::Value::String(tvc_b64)), Some(abi)) => {
                        Ok(Self::Custom { tvc_b64, abi })
                    }
                    (Some(_), None) => Err(D::Error::custom(
                        "`code.abi` is missing — a build's code and ABI must be supplied \
                         together, from the same build",
                    )),
                    (None, Some(_)) => Err(D::Error::custom(
                        "`code.tvc_b64` is missing — a build's code and ABI must be supplied \
                         together, from the same build",
                    )),
                    (Some(_), Some(_)) => {
                        Err(D::Error::custom("`code.tvc_b64` must be a base64 string"))
                    }
                    (None, None) => Err(D::Error::custom(
                        "`code` object must be `{ tvc_b64, abi }`; omit `code` for the default \
                         build or pass a vendored build's name",
                    )),
                }
            }
            other => Err(D::Error::custom(format!(
                "`code` must be a vendored build's name or `{{ tvc_b64, abi }}`, got {other}"
            ))),
        }
    }
}

impl TryFrom<ParamsOfMultisigCode> for MultisigCode {
    type Error = AppError;

    fn try_from(params: ParamsOfMultisigCode) -> AppResult<Self> {
        match params {
            ParamsOfMultisigCode::Named(name) => MultisigCode::by_name(&name),
            ParamsOfMultisigCode::Custom { tvc_b64, abi } => {
                Ok(Self { tvc: decode_tvc_b64(&tvc_b64)?, abi: abi_to_json_string(abi)? })
            }
        }
    }
}

/// Result of [`deploy_multisig_via_giver`].
#[derive(Debug, Clone, Serialize)]
pub struct ResultOfDeployMultisigViaGiver {
    pub address: String,
    /// Owner pubkey (hex, no `0x`).
    pub public: String,
    /// Owner secret (hex) — the frontend MUST persist this.
    pub secret: String,
    /// `true` if the address was already Active (deploy skipped).
    pub already_deployed: bool,
    /// Deploy tx id, when a deploy was actually sent.
    pub deploy_tx: Option<String>,
}

/// Builds a `ClientContext` over the given endpoints, mirroring `WalletContext`
/// (disable tvm_client's internal reconnect storm; we retry one layer up).
fn make_context(endpoints: Vec<String>) -> AppResult<Arc<ClientContext>> {
    let mut config = ClientConfig::default();
    config.network.endpoints = Some(endpoints);
    config.network.max_reconnect_timeout = 0;
    let ctx = ClientContext::new(config)
        .map_err(|e| AppError::from(e).with_context("failed to create tvm client"))?;
    Ok(Arc::new(ctx))
}

/// Parses a u64-as-string amount, attributing the field name on failure.
fn parse_amount(field: &str, value: &str) -> AppResult<u64> {
    value
        .parse::<u64>()
        .map_err(|e| AppError::new(format!("invalid {field} amount `{value}`: {e}")))
}

/// Decodes a base64 `.tvc` override. Whitespace is stripped first: `.tvc.b64`
/// files (and anything that round-tripped through a terminal) are usually line
/// wrapped, and strict base64 would reject the newlines.
fn decode_tvc_b64(b64: &str) -> AppResult<Vec<u8>> {
    let compact: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .map_err(|e| AppError::new(format!("invalid `tvc_b64` (expected a base64 `.tvc`): {e}")))
}

/// Normalizes an `abi` override to the JSON text tvm_client wants, accepting
/// both the stringified ABI and the parsed object.
fn abi_to_json_string(abi: serde_json::Value) -> AppResult<String> {
    match abi {
        serde_json::Value::String(s) => Ok(s),
        object @ serde_json::Value::Object(_) => Ok(object.to_string()),
        other => Err(AppError::new(format!(
            "`abi` override must be a JSON object or a stringified ABI, got {}",
            match other {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "a boolean",
                serde_json::Value::Number(_) => "a number",
                _ => "an array",
            }
        ))),
    }
}

/// 429 / throttling signal. tvm_client strips HTTP headers before surfacing
/// errors, so the only things that survive are the numeric `server_code` (from
/// GraphQL extensions) and the message text — match on those. Used to tag the
/// terminal error as `rate_limited`.
fn is_rate_limited(err: &AppError) -> bool {
    let hit = |s: &str| {
        let s = s.to_ascii_lowercase();
        s.contains("server_code: 429") || s.contains("too many requests")
    };
    hit(&err.message) || err.details.as_deref().is_some_and(hit)
}

/// Retry predicate for on-chain sends: the HTTP-transient classes
/// (429 / 5xx / 408 / 425 / resets / timeouts) plus the explicit 429 signal.
fn send_should_retry(err: &AppError) -> bool {
    crate::infra::is_retryable_http_transient(err) || is_rate_limited(err)
}

/// Maps the error left after retries are exhausted. A throttled send becomes a
/// typed `rate_limited` error whose message starts with a stable `RateLimited:`
/// prefix, so the UI can show "busy, try later" instead of a generic transport
/// failure. Anything else just gets `context` prepended (legacy behavior).
fn tag_terminal_send_error(err: AppError, context: &str) -> AppError {
    if is_rate_limited(&err) {
        let mut tagged = AppError::new(format!("RateLimited: {context}: {}", err.message))
            .with_kind("rate_limited");
        if let Some(details) = err.details {
            tagged = tagged.with_details(details);
        }
        tagged
    } else {
        err.with_context(context)
    }
}

/// Runs one on-chain send under `policy` + the shared rate limiter (acquired
/// before every attempt, so retries count against the rps budget), retagging an
/// exhausted-retry failure via [`tag_terminal_send_error`].
async fn send_with_retry_policy<T, F, Fut>(
    policy: &RetryPolicy,
    rl: Option<&RateLimiter>,
    context: &str,
    op: F,
) -> AppResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = AppResult<T>>,
{
    with_retry_policy(policy, rl, send_should_retry, op)
        .await
        .map_err(|e| tag_terminal_send_error(e, context))
}

/// [`send_with_retry_policy`] with the default HTTP policy: 5 attempts, 60 s
/// total cap, 500 ms→30 s exponential backoff + jitter. `Retry-After` is
/// invisible at the tvm_client layer (headers stripped), so backoff substitutes
/// — the consumer's frontend is the only layer that can honor `Retry-After`.
async fn send_with_retry<T, F, Fut>(rl: Option<&RateLimiter>, context: &str, op: F) -> AppResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = AppResult<T>>,
{
    send_with_retry_policy(&RetryPolicy::http_default(), rl, context, op).await
}

/// Fully client-side flat-Multisig deploy on shellnet: compute the address
/// (brick 1), fund it from the default giver (brick 2, **shellnet only**), then
/// deploy (brick 3). Idempotent — an already-Active address skips funding and
/// deploy. Always returns the owner keypair (generated when not supplied).
///
/// The giver lives only on shellnet; on other networks the funding step errors
/// (no giver account). Callers are expected to gate this by network, but the
/// error is surfaced clearly regardless.
pub async fn deploy_multisig_via_giver(
    params: ParamsOfDeployMultisigViaGiver,
) -> AppResult<ResultOfDeployMultisigViaGiver> {
    let ctx = make_context(params.endpoints)?;

    let keys = match params.keys {
        Some(keys) => keys,
        None => generate_random_sign_keys(ctx.clone())?,
    };
    let owners_pubkey = params
        .owners_pubkey
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![format!("0x{}", keys.public)]);

    let spec = MultisigDeploySpec {
        keys: keys.clone(),
        owners_pubkey,
        req_confirms: params.req_confirms.unwrap_or(1),
        req_confirms_data: params.req_confirms_data.unwrap_or(1),
        constructor_value: params.constructor_value.unwrap_or_else(|| "0".to_string()),
        // Build override (absent = vendored build). Decoded and validated before
        // any giver money moves: `compute_multisig_address` below runs
        // `spec.validate()`, so a bad override fails without spending anything.
        code: params.code.map(MultisigCode::try_from).transpose()?,
    };

    let address = compute_multisig_address(ctx.clone(), &spec).await?;
    let dapp_id = dapp_id_of(&address);

    // Idempotency: never fund/redeploy an address that's already Active.
    let mut account = Account::new(ctx.clone(), &address, dapp_id);
    account.fetch().await?;
    if account.acc_type == AccountStatus::Active {
        return Ok(ResultOfDeployMultisigViaGiver {
            address: canonical_address(&address),
            public: keys.public.clone(),
            secret: keys.secret.clone(),
            already_deployed: true,
            deploy_tx: None,
        });
    }

    // Brick 2 — bring the future address into existence + fund it. Flag-16 is
    // REQUIRED to create a not-yet-existing account (a native-only / flag-1
    // transfer does NOT — proven: it times out on `Wait … Uninit`). Funding goes
    // as SHELL *ECC* (`giver_value`), NOT native `value`: native value doesn't
    // cross dapp_id and a fresh account is the root of its own dapp. Flag 16
    // collapses the ECC SHELL into the new account's native balance — that's its
    // gas. The real held ECC top-up happens AFTER deploy (Brick 4).
    let giver_value = match params.giver_value {
        Some(v) => parse_amount("giver_value", &v)?,
        None => DEFAULT_GIVER_VALUE,
    };

    // Shared limiter for ALL sends below (create → deploy → ECC top-up) plus
    // their retries: ≤2 sends/s globally, ≥500 ms apart. Keeps us under the
    // node's ~3-sends/s throttle so a multivalue funded deploy doesn't burst.
    let rl = Some(RateLimiter::new(MAX_SEND_RPS));

    let mut create_ecc = HashMap::new();
    create_ecc.insert(SHELL_CURRENCY_ID, giver_value);
    send_with_retry(
        rl.as_ref(),
        "giver account-creation failed (giver is available on shellnet only)",
        || {
            let ctx = ctx.clone();
            let create_ecc = create_ecc.clone();
            let address = address.clone();
            async move {
                send_currency_with_flag_from_default_giver(ctx, &address, 0, create_ecc, GIVER_FLAG)
                    .await
                    .map_err(AppError::from)
            }
        },
    )
    .await?;

    // Wait until the value message lands and the account exists (Uninit).
    account
        .wait(ParamsOfWaitAccount { status: AccountStatus::Uninit, ..Default::default() })
        .await?;

    // Brick 3 — deploy now that the address is funded. Retried as a unit: it's
    // idempotent (re-checks Active first), so a 429 mid-deploy just re-enters
    // and either resends or returns the already-Active outcome.
    let wait_for_active = params.wait_for_active.unwrap_or(true);
    let outcome = send_with_retry(rl.as_ref(), "multisig deploy failed", || {
        let ctx = ctx.clone();
        let spec = spec.clone();
        async move { deploy_multisig(ctx, &spec, wait_for_active).await }
    })
    .await?;

    // Brick 4 — held ECC top-up (NACKL/SHELL/USDC) AFTER the multisig is deployed
    // (Active), via flag-1 (NOT flag-16). To a live account flag-1 keeps every
    // currency held — SHELL (ECC[2]) included — instead of collapsing into native.
    let mut giver_ecc = HashMap::new();
    for (currency, amount) in params.giver_ecc.unwrap_or_default() {
        giver_ecc.insert(currency, parse_amount("giver_ecc", &amount)?);
    }
    if !giver_ecc.is_empty() {
        send_with_retry(
            rl.as_ref(),
            "giver ECC top-up failed (giver is available on shellnet only)",
            || {
                let ctx = ctx.clone();
                let giver_ecc = giver_ecc.clone();
                let address = address.clone();
                async move {
                    send_currency_with_flag_from_default_giver(
                        ctx,
                        &address,
                        ECC_TOPUP_GAS,
                        giver_ecc,
                        1,
                    )
                    .await
                    .map_err(AppError::from)
                }
            },
        )
        .await?;
    }

    Ok(ResultOfDeployMultisigViaGiver {
        address: outcome.address,
        public: keys.public.clone(),
        secret: keys.secret.clone(),
        already_deployed: outcome.already_deployed,
        deploy_tx: outcome.deploy_tx,
    })
}

/// Parameters for [`multisig_balances`] (wasm boundary).
#[derive(Debug, Clone, Deserialize)]
pub struct ParamsOfMultisigBalances {
    pub endpoints: Vec<String>,
    pub address: String,
}

/// ECC balances of any account by address. dApp id == account (self-rooted):
/// canonical `<dapp>::<account>` → part before `::`; else raw `0:<hex>`.
///
/// Generic (works on a flat multisig), unlike the multifactor-specific balance
/// reader. Returns raw integer amounts as strings keyed by ECC currency id
/// (1=NACKL, 2=SHELL, 3=USDC); the client applies per-token decimals.
pub async fn multisig_balances(
    endpoints: Vec<String>,
    address: String,
) -> AppResult<std::collections::BTreeMap<u32, String>> {
    let ctx = make_context(endpoints)?;
    let dapp_id = address
        .split_once("::")
        .map(|(d, _)| d.to_string())
        .unwrap_or_else(|| address.trim_start_matches("0:").to_string());
    let mut account = Account::new(ctx, &address, dapp_id);
    account.fetch().await?;
    Ok(account.ecc.iter().map(|(k, v)| (*k, v.to_string())).collect())
}

// Native-only: the send retry/throttle behavior is what the shellnet 429 storm
// hit. The on-chain sends themselves need a live giver, but the retry decision,
// the throttle classifier, and the typed-error tagging are pure and tested
// here.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::*;

    /// A 429 as tvm_client would surface it once stripped to text.
    fn err_429() -> AppError {
        AppError::new("GraphQL request failed: server_code: 429 Too Many Requests")
    }

    /// Spec with a fixed (bogus but well-formed) keypair — these tests never
    /// sign, they only exercise build resolution and validation.
    fn spec_with(code: Option<MultisigCode>) -> MultisigDeploySpec {
        MultisigDeploySpec {
            keys: KeyPair { public: "aa".repeat(32), secret: "bb".repeat(32) },
            owners_pubkey: vec![format!("0x{}", "aa".repeat(32))],
            req_confirms: 1,
            req_confirms_data: 1,
            constructor_value: "0".to_string(),
            code,
        }
    }

    /// Build override with placeholder code and the given ABI.
    fn code_with_abi(abi: impl Into<String>) -> Option<MultisigCode> {
        Some(MultisigCode { tvc: vec![1, 2, 3], abi: abi.into() })
    }

    /// Minimal ABI shaped like a *newer* multisig build: same constructor,
    /// extra functions (v2 adds `submitUpdateCode` / `confirmUpdateCode`).
    fn superset_abi() -> String {
        json!({
            "ABI version": 2,
            "version": "2.4",
            "header": ["pubkey", "time", "expire"],
            "functions": [
                { "name": "constructor", "inputs": CONSTRUCTOR_INPUTS
                    .iter()
                    .map(|name| json!({ "name": name, "type": "uint64" }))
                    .collect::<Vec<_>>(), "outputs": [] },
                { "name": "submitUpdateCode",
                  "inputs": [{ "name": "newcode", "type": "cell" }],
                  "outputs": [{ "name": "codeUpdateId", "type": "uint64" }] },
            ],
        })
        .to_string()
    }

    /// Fast policy for tests: real backoff math, 1 ms sleeps, no jitter.
    fn fast_policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            max_total: None,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter: false,
        }
    }

    #[test]
    fn default_giver_value_is_one_million_shell() {
        // Cross-dapp funding rides on ECC, so the multisig's native gas comes
        // from this flag-16 SHELL-ECC amount (collapsed to native). ECC_TOPUP_GAS
        // is exactly 1 SHELL (10^9 nano), so this pins the zero-count against a
        // typo in either constant.
        assert_eq!(DEFAULT_GIVER_VALUE, 1_000_000 * ECC_TOPUP_GAS);
        assert_eq!(DEFAULT_GIVER_VALUE, 1_000_000_000_000_000);
    }

    #[test]
    fn absent_override_resolves_to_the_vendored_build() {
        let spec = spec_with(None);
        assert_eq!(spec.code_bytes(), MULTISIG_TVC);
        assert_eq!(spec.abi_json(), MULTISIG_ABI);
        spec.validate().expect("the default spec must always be valid");
    }

    #[test]
    fn override_replaces_the_vendored_build() {
        let spec = spec_with(code_with_abi(superset_abi()));
        assert_eq!(spec.code_bytes(), &[1, 2, 3]);
        assert_eq!(spec.abi_json(), superset_abi());
        // Extra functions on top of an identical constructor is exactly the v2
        // case: accepted.
        spec.validate().expect("superset ABI must be accepted");
    }

    /// Pins [`CONSTRUCTOR_INPUTS`] against the vendored asset: if the two ever
    /// drift, every ABI override would be rejected (or a wrong one accepted).
    #[test]
    fn vendored_abi_satisfies_the_override_constructor_check() {
        spec_with(code_with_abi(MULTISIG_ABI))
            .validate()
            .expect("vendored ABI must pass the same check overrides face");
    }

    #[test]
    fn malformed_overrides_are_rejected_before_any_network_call() {
        let err = |spec: MultisigDeploySpec| spec.validate().unwrap_err().message;

        let empty_tvc = MultisigCode { tvc: Vec::new(), abi: MULTISIG_ABI.to_string() };
        assert!(err(spec_with(Some(empty_tvc))).contains("empty `tvc`"));
        assert!(err(spec_with(code_with_abi("not json"))).contains("not valid JSON"));
        assert!(err(spec_with(code_with_abi(json!({ "functions": [] }).to_string())))
            .contains("no `constructor`"));

        // Right shape, wrong constructor: our hardcoded input JSON couldn't be
        // encoded against it, so it must fail here rather than on-chain.
        let renamed = json!({
            "functions": [{
                "name": "constructor",
                "inputs": [{ "name": "owners", "type": "uint256[]" }],
                "outputs": [],
            }],
        });
        let message = err(spec_with(code_with_abi(renamed.to_string())));
        assert!(message.contains("incompatible constructor"), "got: {message}");
        assert!(message.contains("owners_pubkey"), "must name what was expected, got: {message}");
    }

    /// The wire form can only produce a *pair*: a caller who sends just one
    /// half gets an error naming the missing one, not a silently mismatched
    /// build. This is the invariant that keeps v2 code away from v1's ABI.
    #[test]
    fn wire_code_override_requires_both_halves() {
        let tvc_b64 = base64::engine::general_purpose::STANDARD.encode(MULTISIG_TVC);

        let complete: ParamsOfMultisigCode =
            serde_json::from_value(json!({ "tvc_b64": tvc_b64, "abi": MULTISIG_ABI })).unwrap();
        let code = MultisigCode::try_from(complete).expect("complete pair must convert");
        assert_eq!(code.tvc, MULTISIG_TVC);
        assert_eq!(code.abi, MULTISIG_ABI);

        let error = |value: serde_json::Value| {
            serde_json::from_value::<ParamsOfMultisigCode>(value)
                .expect_err("half a build must not deserialize")
                .to_string()
        };
        assert!(error(json!({ "tvc_b64": tvc_b64 })).contains("`code.abi` is missing"));
        assert!(error(json!({ "abi": MULTISIG_ABI })).contains("`code.tvc_b64` is missing"));
        assert!(error(json!(42)).contains("must be a vendored build's name"));
    }

    /// The vendored v2 asset must be the artifact from acki-nacki#2413 — pinned
    /// by content hash so a swapped or truncated file fails here instead of
    /// putting unknown code on-chain. (The matching *code* hash, which is what
    /// the node reports, is asserted in the integration tests.)
    #[test]
    fn vendored_v2_asset_is_pinned() {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(UPDATE_CUSTODIAN_V2_TVC);
        assert_eq!(hex::encode(digest), UPDATE_CUSTODIAN_V2_TVC_SHA256);

        // And it must satisfy the same override checks a caller's build faces.
        spec_with(Some(MultisigCode::update_custodian_v2()))
            .validate()
            .expect("vendored v2 build must be valid");
    }

    /// `code: "update_custodian_v2"` must resolve to the vendored v2 pair, and
    /// an unknown name must say what is available instead of failing later.
    #[test]
    fn named_builds_resolve_by_wire_name() {
        let named: ParamsOfMultisigCode =
            serde_json::from_value(json!(UPDATE_CUSTODIAN_V2_NAME)).unwrap();
        let code = MultisigCode::try_from(named).expect("named build must resolve");
        assert_eq!(code.tvc, UPDATE_CUSTODIAN_V2_TVC);
        assert_eq!(code.abi, UPDATE_CUSTODIAN_V2_ABI);
        // v2 is a genuinely different build from the default.
        assert_ne!(code.tvc, MULTISIG_TVC);
        assert_ne!(code.abi, MULTISIG_ABI);

        let unknown: ParamsOfMultisigCode = serde_json::from_value(json!("v3")).unwrap();
        let message = MultisigCode::try_from(unknown).unwrap_err().message;
        assert!(message.contains("unknown multisig build `v3`"), "got: {message}");
        assert!(message.contains(UPDATE_CUSTODIAN_V2_NAME), "must list what exists: {message}");
    }

    /// v2's ABI is a superset of the default's by function set — but its
    /// `fields` add storage slots, which is why the two travel together.
    /// Pins the fact behind [`MultisigCode`]'s pairing.
    #[test]
    fn vendored_v2_abi_adds_functions_and_storage_fields() {
        let names = |abi: &str| -> Vec<String> {
            let parsed: serde_json::Value = serde_json::from_str(abi).unwrap();
            parsed["functions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["name"].as_str().unwrap().to_string())
                .collect()
        };
        let fields = |abi: &str| -> Vec<String> {
            let parsed: serde_json::Value = serde_json::from_str(abi).unwrap();
            parsed["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["name"].as_str().unwrap().to_string())
                .collect()
        };

        let (default_fns, v2_fns) = (names(MULTISIG_ABI), names(UPDATE_CUSTODIAN_V2_ABI));
        for name in &default_fns {
            assert!(v2_fns.contains(name), "v2 must keep `{name}`");
        }
        for added in ["submitUpdateCode", "confirmUpdateCode"] {
            assert!(v2_fns.contains(&added.to_string()), "v2 must add `{added}`");
            assert!(!default_fns.contains(&added.to_string()));
        }

        let (default_fields, v2_fields) = (fields(MULTISIG_ABI), fields(UPDATE_CUSTODIAN_V2_ABI));
        for added in ["m_requestsMaskCode", "m_code"] {
            assert!(v2_fields.contains(&added.to_string()), "v2 must add field `{added}`");
            assert!(!default_fields.contains(&added.to_string()));
        }
        assert_ne!(default_fields, v2_fields, "differing `fields` ⇒ differing address");
    }

    #[test]
    fn tvc_b64_decodes_and_tolerates_line_wrapping() {
        let raw = MULTISIG_TVC;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(decode_tvc_b64(&b64).unwrap(), raw);

        // Line-wrapped (as `base64 < file` emits) must decode identically.
        let wrapped =
            b64.as_bytes().chunks(76).map(String::from_utf8_lossy).collect::<Vec<_>>().join("\n");
        assert_eq!(decode_tvc_b64(&wrapped).unwrap(), raw);

        let err = decode_tvc_b64("!!! not base64 !!!").unwrap_err().message;
        assert!(err.contains("invalid `tvc_b64`"), "got: {err}");
    }

    #[test]
    fn abi_override_accepts_both_string_and_object() {
        // Stringified: passed through verbatim.
        let as_string = json!("{\"functions\":[]}");
        assert_eq!(abi_to_json_string(as_string).unwrap(), "{\"functions\":[]}");

        // Parsed object (what a JS `import abi from "./x.abi.json"` yields):
        // re-serialized, and must survive the round-trip as the same JSON.
        let as_object: serde_json::Value = serde_json::from_str(MULTISIG_ABI).unwrap();
        let rendered = abi_to_json_string(as_object.clone()).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&rendered).unwrap(), as_object);

        let err = abi_to_json_string(json!([1, 2])).unwrap_err().message;
        assert!(err.contains("must be a JSON object or a stringified ABI"), "got: {err}");
    }

    #[test]
    fn is_rate_limited_recognizes_429_in_message_and_details() {
        assert!(is_rate_limited(&err_429()));
        assert!(is_rate_limited(
            &AppError::new("boom").with_details("nested: 429 too many requests")
        ));
        // Not a throttle:
        assert!(!is_rate_limited(&AppError::new("connection reset by peer")));
        assert!(!is_rate_limited(&AppError::new("server_code: 500 internal")));
    }

    #[test]
    fn send_should_retry_covers_429_and_5xx_but_not_hard_errors() {
        assert!(send_should_retry(&err_429()));
        assert!(send_should_retry(&AppError::new("server_code: 503 service unavailable")));
        assert!(!send_should_retry(&AppError::new("invalid giver_value amount `x`")));
    }

    #[test]
    fn tag_terminal_send_error_marks_throttle_with_prefix() {
        let tagged = tag_terminal_send_error(err_429(), "giver account-creation failed");
        assert_eq!(tagged.kind.as_deref(), Some("rate_limited"));
        assert!(tagged.message.starts_with("RateLimited:"), "got: {}", tagged.message);
    }

    #[test]
    fn tag_terminal_send_error_passes_through_non_throttle() {
        let tagged = tag_terminal_send_error(AppError::new("hard failure"), "ctx");
        assert_ne!(tagged.kind.as_deref(), Some("rate_limited"));
        assert!(tagged.message.starts_with("ctx:"), "got: {}", tagged.message);
    }

    #[tokio::test]
    async fn retries_throttled_send_then_succeeds() {
        let calls = AtomicU32::new(0);
        let res: AppResult<u32> = send_with_retry_policy(&fast_policy(5), None, "ctx", || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(err_429())
                } else {
                    Ok(7)
                }
            }
        })
        .await;
        assert_eq!(res.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "two 429s then success");
    }

    #[tokio::test]
    async fn exhausted_throttle_returns_typed_rate_limited() {
        let calls = AtomicU32::new(0);
        let res: AppResult<u32> =
            send_with_retry_policy(&fast_policy(3), None, "giver ECC top-up failed", || {
                calls.fetch_add(1, Ordering::SeqCst);
                async move { Err::<u32, _>(err_429()) }
            })
            .await;
        let err = res.unwrap_err();
        assert_eq!(err.kind.as_deref(), Some("rate_limited"));
        assert!(err.message.starts_with("RateLimited:"), "got: {}", err.message);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "all attempts spent");
    }

    #[tokio::test]
    async fn non_retryable_error_is_not_retried() {
        let calls = AtomicU32::new(0);
        let res: AppResult<u32> = send_with_retry_policy(&fast_policy(5), None, "ctx", || {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err::<u32, _>(AppError::new("hard failure")) }
        })
        .await;
        assert!(res.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hard error must not retry");
    }

    #[tokio::test]
    async fn rate_limiter_serializes_sends_to_the_configured_interval() {
        // 5 rps ⇒ ~200 ms min spacing; 3 acquisitions ⇒ ≥2 intervals elapsed.
        let rl = RateLimiter::new(5);
        let start = std::time::Instant::now();
        for _ in 0..3 {
            rl.acquire().await;
        }
        assert!(
            start.elapsed() >= Duration::from_millis(380),
            "3 sends at 5rps should span ≥2 intervals (~400ms), got {:?}",
            start.elapsed()
        );
    }
}
