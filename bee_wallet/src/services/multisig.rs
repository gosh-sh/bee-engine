//! Canonical `UpdateCustodianMultisigWallet` deploy helpers.
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
//! shellnet deploy. The single accepted ABI/TVC pair is vendored under
//! `assets/multisig/`; every brick uses that exact pair.

use std::collections::HashMap;
use std::sync::Arc;

use ackinacki_kit::contracts::account::Account;
use ackinacki_kit::contracts::account::AccountStatus;
use ackinacki_kit::contracts::account::ParamsOfWaitAccount;
use ackinacki_kit::contracts::giver::v3::send_currency_with_flag_from_default_giver;
use ackinacki_kit::contracts::multisig::Multisig;
use ackinacki_kit::contracts::traits::SendMessage;
use ackinacki_kit::tvm_client::abi::encode_message;
use ackinacki_kit::tvm_client::abi::Abi;
use ackinacki_kit::tvm_client::abi::CallSet;
use ackinacki_kit::tvm_client::abi::DeploySet;
use ackinacki_kit::tvm_client::abi::ParamsOfEncodeMessage;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::generate_random_sign_keys;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use base64::Engine;
use bee_infra::RateLimiter;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

use crate::errors::AppError;
use crate::errors::AppResult;

/// Canonical `UpdateCustodianMultisigWallet` v2.4.0 ABI/TVC, vendored at build
/// time so deploy and address derivation are fully self-contained. See
/// `assets/multisig/PROVENANCE.md` for immutable source and artifact hashes.
const MULTISIG_ABI: &str = include_str!("../../assets/multisig/Multisig.abi.json");
const MULTISIG_TVC: &[u8] = include_bytes!("../../assets/multisig/Multisig.tvc");

pub const MULTISIG_CODE_HASH: &str =
    "cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1";

#[cfg(all(test, not(target_arch = "wasm32")))]
const MULTISIG_ABI_SHA256: &str =
    "e7573b233667cf50d8edc9ab0ce235f8ac88674ae9610c77d426bec22070f581";
#[cfg(all(test, not(target_arch = "wasm32")))]
const MULTISIG_TVC_SHA256: &str =
    "b0d72acbbdc6af309823e74b96b0b3ffb0f871a5b98316b6e89affdfb56c5c9d";

#[cfg(all(test, not(target_arch = "wasm32")))]
const MULTISIG_CONSTRUCTOR_INPUTS: [&str; 7] = [
    "owners_pubkey",
    "owners_address",
    "reqConfirms",
    "reqConfirmsData",
    "value",
    "minBalance",
    "targetBalance",
];

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

/// Initial gas self-management configuration supported by
/// `UpdateCustodianMultisigWallet_v2` v2.4.0. Amounts are uint128 decimal
/// strings so JS callers cannot lose precision. `min_balance = 0` disables
/// automatic SHELL-to-vmshell conversion.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MultisigBalanceConfig {
    pub min_balance: String,
    pub target_balance: String,
}

impl Default for MultisigBalanceConfig {
    fn default() -> Self {
        Self { min_balance: "0".to_string(), target_balance: "0".to_string() }
    }
}

impl MultisigBalanceConfig {
    fn validate(&self) -> AppResult<()> {
        let min_balance = self.min_balance.parse::<u128>().map_err(|e| {
            AppError::new(format!(
                "invalid balance_config.min_balance amount `{}`: {e}",
                self.min_balance
            ))
        })?;
        let target_balance = self.target_balance.parse::<u128>().map_err(|e| {
            AppError::new(format!(
                "invalid balance_config.target_balance amount `{}`: {e}",
                self.target_balance
            ))
        })?;
        if target_balance < min_balance {
            return Err(AppError::new(format!(
                "balance_config.target_balance must be >= min_balance ({} < {})",
                self.target_balance, self.min_balance
            )));
        }
        Ok(())
    }
}

/// Everything needed to deterministically encode a canonical Multisig deploy.
/// The owner `keys` sign their own deploy; `owners_pubkey` are the custodians
/// (`uint256[]`, each a `0x`-prefixed hex), defaulting to the owner alone.
#[derive(Debug, Clone)]
pub struct MultisigDeploySpec {
    pub keys: KeyPair,
    pub owners_pubkey: Vec<String>,
    pub req_confirms: u8,
    pub req_confirms_data: u8,
    /// Constructor `value` arg (`uint64`), passed through as a decimal string.
    pub constructor_value: String,
    /// Gas self-management settings. Omit to pass `0/0` and disable automatic
    /// conversion.
    pub balance_config: Option<MultisigBalanceConfig>,
}

impl MultisigDeploySpec {
    fn validate(&self) -> AppResult<()> {
        if let Some(config) = &self.balance_config {
            config.validate()?;
        }
        Ok(())
    }

    fn constructor_input(&self) -> AppResult<serde_json::Value> {
        self.validate()?;
        let config = self.balance_config.clone().unwrap_or_default();
        Ok(json!({
            "owners_pubkey": self.owners_pubkey,
            "owners_address": [],
            "reqConfirms": self.req_confirms,
            "reqConfirmsData": self.req_confirms_data,
            "value": self.constructor_value,
            "minBalance": config.min_balance,
            "targetBalance": config.target_balance,
        }))
    }

    /// Builds the `ParamsOfEncodeMessage` shared by address computation and the
    /// actual deploy, so both derive from one source of truth.
    fn encode_params(&self) -> AppResult<ParamsOfEncodeMessage> {
        let tvc_b64 = base64::engine::general_purpose::STANDARD.encode(MULTISIG_TVC);
        Ok(ParamsOfEncodeMessage {
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
                input: Some(self.constructor_input()?),
            }),
            signer: Signer::Keys { keys: self.keys.clone() },
            processing_try_index: None,
            signature_id: None,
        })
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
    let encoded = encode_message(ctx, spec.encode_params()?).await?;
    Ok(encoded.address)
}

/// Outcome of [`deploy_multisig`].
pub struct DeployOutcome {
    pub address: String,
    pub already_deployed: bool,
    /// Deploy transaction id; `None` when the account was already Active.
    pub deploy_tx: Option<String>,
}

/// **Brick 3.** Deploy the canonical Multisig whose address is *already
/// funded*. Network-agnostic — anyone can call this once the computed address
/// holds a balance. Idempotent: if the account is already Active, returns
/// immediately without sending a deploy message.
pub async fn deploy_multisig(
    ctx: Arc<ClientContext>,
    spec: &MultisigDeploySpec,
    wait_for_active: bool,
) -> AppResult<DeployOutcome> {
    let encode_params = spec.encode_params()?;
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

    let multisig = Multisig::new(
        crate::wallet_contract_context(ctx.clone()),
        ackinacki_kit::contracts::account::ParamsOfNewContract::new(address.clone(), dapp_id),
    );
    let prepared = multisig
        .prepare_message(encode_params.call_set, encode_params.deploy_set, encode_params.signer)
        .await
        .map_err(AppError::from)?;
    let sent = multisig.send_prepared_message(&prepared).await.map_err(AppError::from)?;
    let deploy_tx = sent.tx_hash;

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
#[serde(deny_unknown_fields)]
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
    /// Gas self-management settings (`uint128` decimal strings). Omit to
    /// disable automatic conversion with `0/0`.
    #[serde(default)]
    pub balance_config: Option<MultisigBalanceConfig>,
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
/// and disabling tvm_client's internal reconnect storm. Contract writes use
/// the exact-message delivery context created from this client.
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

/// Fully client-side Multisig deploy on shellnet: compute the address
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
        balance_config: params.balance_config,
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

    // Shared limiter for ALL sends below (create → deploy → ECC top-up):
    // ≤2 sends/s globally, ≥500 ms apart. Keeps us under the
    // node's ~3-sends/s throttle so a multivalue funded deploy doesn't burst.
    let rate_limiter = RateLimiter::new(MAX_SEND_RPS);
    let delivery_context = crate::wallet_contract_context(ctx.clone());

    let mut create_ecc = HashMap::new();
    create_ecc.insert(SHELL_CURRENCY_ID, giver_value);
    rate_limiter.acquire().await;
    send_currency_with_flag_from_default_giver(
        delivery_context.clone(),
        &address,
        0,
        create_ecc,
        GIVER_FLAG,
    )
    .await
    .map_err(AppError::from)
    .map_err(|error| {
        error.with_context("giver account-creation failed (giver is available on shellnet only)")
    })?;

    // Wait until the value message lands and the account exists (Uninit).
    account
        .wait(ParamsOfWaitAccount { status: AccountStatus::Uninit, ..Default::default() })
        .await?;

    // Brick 3 — deploy now that the address is funded.
    let wait_for_active = params.wait_for_active.unwrap_or(true);
    rate_limiter.acquire().await;
    let outcome = deploy_multisig(ctx.clone(), &spec, wait_for_active)
        .await
        .map_err(|error| error.with_context("multisig deploy failed"))?;

    // Brick 4 — held ECC top-up (NACKL/SHELL/USDC) AFTER the multisig is deployed
    // (Active), via flag-1 (NOT flag-16). To a live account flag-1 keeps every
    // currency held — SHELL (ECC[2]) included — instead of collapsing into native.
    let mut giver_ecc = HashMap::new();
    for (currency, amount) in params.giver_ecc.unwrap_or_default() {
        giver_ecc.insert(currency, parse_amount("giver_ecc", &amount)?);
    }
    if !giver_ecc.is_empty() {
        rate_limiter.acquire().await;
        send_currency_with_flag_from_default_giver(
            delivery_context,
            &address,
            ECC_TOPUP_GAS,
            giver_ecc,
            1,
        )
        .await
        .map_err(AppError::from)
        .map_err(|error| {
            error.with_context("giver ECC top-up failed (giver is available on shellnet only)")
        })?;
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
/// Generic (works on the canonical Multisig), unlike the multifactor-specific
/// balance reader. Returns raw integer amounts as strings keyed by ECC currency
/// id (1=NACKL, 2=SHELL, 3=USDC); the client applies per-token decimals.
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Spec with a fixed (bogus but well-formed) keypair — these tests never
    /// sign, they only exercise constructor input and validation.
    fn spec() -> MultisigDeploySpec {
        MultisigDeploySpec {
            keys: KeyPair { public: "aa".repeat(32), secret: "bb".repeat(32) },
            owners_pubkey: vec![format!("0x{}", "aa".repeat(32))],
            req_confirms: 1,
            req_confirms_data: 1,
            constructor_value: "0".to_string(),
            balance_config: None,
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

    /// The canonical UpdateCustodian build is an immutable input to address
    /// derivation. Pin ABI, TVC, decoded code cell, and constructor shape
    /// before it can reach a network.
    #[test]
    fn canonical_multisig_assets_are_pinned() {
        use sha2::Digest;

        assert_eq!(
            MULTISIG_CODE_HASH,
            ackinacki_kit::contracts::multisig::CODE_HASH,
            "bee deploy artifact and kit operation binding must target the same build",
        );
        assert_eq!(hex::encode(sha2::Sha256::digest(MULTISIG_ABI.as_bytes())), MULTISIG_ABI_SHA256);
        assert_eq!(hex::encode(sha2::Sha256::digest(MULTISIG_TVC)), MULTISIG_TVC_SHA256);

        let ctx = Arc::new(ClientContext::new(ClientConfig::default()).expect("client context"));
        let decoded = ackinacki_kit::tvm_client::boc::decode_state_init(
            ctx,
            ackinacki_kit::tvm_client::boc::ParamsOfDecodeStateInit {
                state_init: base64::engine::general_purpose::STANDARD.encode(MULTISIG_TVC),
                boc_cache: None,
            },
        )
        .expect("decode canonical state init");
        assert_eq!(decoded.code_hash.as_deref(), Some(MULTISIG_CODE_HASH));
        assert_eq!(decoded.compiler_version.as_deref(), Some("sol 0.81.0"));

        let abi: serde_json::Value = serde_json::from_str(MULTISIG_ABI).expect("canonical ABI");
        let inputs = abi["functions"]
            .as_array()
            .and_then(|functions| functions.iter().find(|f| f["name"] == "constructor"))
            .and_then(|constructor| constructor["inputs"].as_array())
            .expect("canonical constructor")
            .iter()
            .map(|input| input["name"].as_str().expect("input name"))
            .collect::<Vec<_>>();
        assert_eq!(inputs, MULTISIG_CONSTRUCTOR_INPUTS);
    }

    #[test]
    fn constructor_carries_explicit_or_disabled_balance_config() {
        let mut explicit = spec();
        explicit.balance_config = Some(MultisigBalanceConfig {
            min_balance: "1000000000".to_string(),
            target_balance: "2000000000".to_string(),
        });
        let input = explicit.constructor_input().expect("constructor input");
        assert_eq!(input["minBalance"], "1000000000");
        assert_eq!(input["targetBalance"], "2000000000");

        let disabled = spec().constructor_input().expect("default-disabled constructor input");
        assert_eq!(disabled["minBalance"], "0");
        assert_eq!(disabled["targetBalance"], "0");
    }

    #[test]
    fn balance_config_is_validated() {
        let mut inverted = spec();
        inverted.balance_config = Some(MultisigBalanceConfig {
            min_balance: "2".to_string(),
            target_balance: "1".to_string(),
        });
        let message = inverted.validate().unwrap_err().message;
        assert!(message.contains("target_balance must be >= min_balance"), "got: {message}");

        let mut malformed = spec();
        malformed.balance_config = Some(MultisigBalanceConfig {
            min_balance: "one".to_string(),
            target_balance: "2".to_string(),
        });
        let message = malformed.validate().unwrap_err().message;
        assert!(message.contains("invalid balance_config.min_balance"), "got: {message}");
    }

    #[test]
    fn wire_balance_config_uses_precision_safe_decimal_strings() {
        let params: ParamsOfDeployMultisigViaGiver = serde_json::from_value(json!({
            "endpoints": ["https://example.invalid"],
            "balance_config": {
                "min_balance": "340282366920938463463374607431768211454",
                "target_balance": "340282366920938463463374607431768211455"
            }
        }))
        .expect("wire params must deserialize");

        let config = params.balance_config.expect("balance config");
        config.validate().expect("valid uint128 bounds");
        assert_eq!(config.target_balance, u128::MAX.to_string());
    }

    #[test]
    fn removed_code_selector_is_rejected_instead_of_ignored() {
        let error = serde_json::from_value::<ParamsOfDeployMultisigViaGiver>(json!({
            "endpoints": ["https://example.invalid"],
            "code": "update_custodian_v2_4"
        }))
        .expect_err("removed selector must not silently fall back")
        .to_string();
        assert!(error.contains("unknown field `code`"), "got: {error}");
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
