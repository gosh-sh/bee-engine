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
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

use crate::errors::AppError;
use crate::errors::AppResult;

/// Canonical flat Multisig ABI/TVC, vendored from the kit at build time so the
/// deploy is fully self-contained (the kit doesn't expose them publicly).
const MULTISIG_ABI: &str = include_str!("../../assets/multisig/Multisig.abi.json");
const MULTISIG_TVC: &[u8] = include_bytes!("../../assets/multisig/Multisig.tvc");

/// ECC currency id of SHELL — the gas/value currency on Acki Nacki. Crediting
/// it shows up as the account's base `balance`.
const SHELL_CURRENCY_ID: u32 = 2;
/// Default SHELL top-up for the future address (10 SHELL, u64 raw).
const DEFAULT_GIVER_VALUE: u64 = 10_000_000_000;
/// `sendCurrencyWithFlag` flag used to fund a *not-yet-existing* address: it
/// creates the account (Uninit) and credits the carried ECC. A plain native
/// `value` transfer (flag 1) does not bring a fresh account into existence.
const GIVER_FLAG: u8 = 16;

/// Everything needed to deterministically encode a flat Multisig deploy. The
/// owner `keys` sign their own deploy; `owners_pubkey` are the custodians
/// (`uint256[]`, each a `0x`-prefixed hex), defaulting to the owner alone.
#[derive(Debug, Clone)]
pub struct MultisigDeploySpec {
    pub keys: KeyPair,
    pub owners_pubkey: Vec<String>,
    pub req_confirms: u8,
    pub req_confirms_data: u8,
    /// Constructor `value` arg (`uint64`), passed through as a decimal string.
    pub constructor_value: String,
}

impl MultisigDeploySpec {
    /// Builds the `ParamsOfEncodeMessage` shared by address computation and the
    /// actual deploy, so both derive from one source of truth.
    fn encode_params(&self) -> ParamsOfEncodeMessage {
        let tvc_b64 = base64::engine::general_purpose::STANDARD.encode(MULTISIG_TVC);
        ParamsOfEncodeMessage {
            abi: Abi::Json(MULTISIG_ABI.to_string()),
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
pub async fn compute_multisig_address(
    ctx: Arc<ClientContext>,
    spec: &MultisigDeploySpec,
) -> AppResult<String> {
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

    let result = process_message(
        ctx.clone(),
        ParamsOfProcessMessage {
            message_encode_params: encode_params,
            send_events: false,
            dapp_id,
        },
        // No progress events requested; an empty Send future satisfies the bound.
        |_| async {},
    )
    .await?;

    let deploy_tx = result.transaction.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());

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
    /// Native top-up of the future address (u64 as string). Default
    /// `"10000000000"`.
    #[serde(default)]
    pub giver_value: Option<String>,
    /// ECC top-up `{ currency_id: amount(u64-string) }`. Default `{}`.
    #[serde(default)]
    pub giver_ecc: Option<HashMap<u32, String>>,
    /// Wait for the deployed account to reach Active. Default `true`.
    #[serde(default)]
    pub wait_for_active: Option<bool>,
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

    // Brick 2 — fund the future address from the default (shellnet) giver.
    //
    // The address does not exist yet. On Acki Nacki a fresh account is brought
    // into existence by a flag-16 currency transfer carrying SHELL (ECC[2], the
    // gas currency); a plain native `value` transfer does not create it. So the
    // gas top-up goes into the ECC map under SHELL, alongside any extra ECC the
    // caller asked for. `giver_value` is that SHELL amount.
    let giver_value = match params.giver_value {
        Some(v) => parse_amount("giver_value", &v)?,
        None => DEFAULT_GIVER_VALUE,
    };
    let mut giver_ecc = HashMap::new();
    giver_ecc.insert(SHELL_CURRENCY_ID, giver_value);
    // Caller-specified ECC overrides/extends the default SHELL gas top-up.
    for (currency, amount) in params.giver_ecc.unwrap_or_default() {
        giver_ecc.insert(currency, parse_amount("giver_ecc", &amount)?);
    }

    send_currency_with_flag_from_default_giver(ctx.clone(), &address, 0, giver_ecc, GIVER_FLAG)
        .await
        .map_err(|e| {
            AppError::from(e)
                .with_context("giver top-up failed (giver is available on shellnet only)")
        })?;

    // Wait until the value message lands and the account exists (Uninit).
    account
        .wait(ParamsOfWaitAccount { status: AccountStatus::Uninit, ..Default::default() })
        .await?;

    // Brick 3 — deploy now that the address is funded.
    let outcome = deploy_multisig(ctx, &spec, params.wait_for_active.unwrap_or(true)).await?;

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
