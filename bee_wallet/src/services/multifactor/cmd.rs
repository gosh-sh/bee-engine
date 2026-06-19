use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem::multifactor::AccountData as MultifactorData;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor as MvMultifactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfAcceptCandidateSeedPhrase;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfAddZkpFactor;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfChangeSeedPhrase as KitParamsOfChangeSeedPhrase;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfDeleteCandidateSeedPhrase;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSetForceRemoveOldest;
use ackinacki_kit::contracts::mvsystem::multifactor::ParamsOfSetWasmHash;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::ClientContext;
use bee_crypto::Crypto as BeeCrypto;
use serde::Deserialize;

use crate::infra::poll_until;
use crate::progress::ProgressEvent;
use crate::progress::ProgressSink;
use crate::services::multifactor::key_derivation::resolve_recovery_signer;
use crate::services::multifactor::key_derivation::ParamsOfBuildRecoveryKeys;

const MAX_NUM_OF_FACTORS: i32 = 10;

/// Bounded confirm-poll for `add_zkp_factor` (~30s = 60 × 500ms). On
/// exhaustion the caller gets a typed terminal `add_factor_timeout` error
/// instead of a UI stuck waiting on an increment that never comes.
const ADD_FACTOR_CONFIRM_MAX_ATTEMPTS: u32 = 60;
const ADD_FACTOR_CONFIRM_INTERVAL_MS: u64 = 500;

#[derive(Debug)]
pub struct AddZkpFactorReq {
    pub header_base_64: String,
    pub proof: String,
    pub epk_expire_at: i64,
    pub epk: String,
    pub esk: String,
    pub kid: String,
}

#[derive(Debug)]
pub struct ResultOfAddZkpFactor {
    pub message_id: Option<String>,
}

#[derive(Debug)]
pub struct ResultOfChangeSeedPhrase {
    pub message_ids: Vec<String>,
}

fn push_message_id(message_ids: &mut Vec<String>, message_id: Option<String>) {
    if let Some(message_id) = message_id {
        message_ids.push(message_id);
    }
}

fn has_candidate_seed_phrase(data: &MultifactorData) -> bool {
    data.candidate_new_owner_pubkey_and_expiration.as_ref().map(|m| !m.is_empty()).unwrap_or(false)
}

async fn get_multifactor_decoded_data(
    multifactor: &Arc<MvMultifactor>,
) -> crate::errors::AppResult<MultifactorData> {
    super::query::get_multifactor_decoded_data(multifactor).await
}

async fn wait_until_candidate_seed_phrase_absent(
    multifactor: &Arc<MvMultifactor>,
) -> crate::errors::AppResult<()> {
    let mf = Arc::clone(multifactor);
    let _ = poll_until(
        || {
            let mf = mf.clone();
            async move {
                super::query::get_multifactor_decoded_data(&mf)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            }
        },
        move |data: &MultifactorData| !has_candidate_seed_phrase(data),
        None,
        None,
    )
    .await?;

    Ok(())
}

async fn wait_until_candidate_seed_phrase_present(
    multifactor: &Arc<MvMultifactor>,
) -> crate::errors::AppResult<()> {
    let mf = Arc::clone(multifactor);
    let _ = poll_until(
        || {
            let mf = mf.clone();
            async move {
                super::query::get_multifactor_decoded_data(&mf)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            }
        },
        move |data: &MultifactorData| {
            // TODO: double check what exactly we have here -> should we look for new owner
            // pub key?
            has_candidate_seed_phrase(data)
        },
        None,
        None,
    )
    .await?;

    Ok(())
}

async fn wait_until_owner_pubkey(
    multifactor: &Arc<MvMultifactor>,
    expected_owner_pubkey: String,
) -> crate::errors::AppResult<()> {
    let mf = Arc::clone(multifactor);
    let _ = poll_until(
        || {
            let mf = mf.clone();
            async move {
                super::query::get_multifactor_decoded_data(&mf)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            }
        },
        move |data: &MultifactorData| data.owner_pubkey == expected_owner_pubkey,
        None,
        None,
    )
    .await?;

    Ok(())
}

async fn delete_candidate_seed_phrase_and_wait(
    multifactor: &Arc<MvMultifactor>,
    epk_expire_at: u64,
    signer_keys: KeyPair,
) -> crate::errors::AppResult<Option<String>> {
    let result = multifactor
        .delete_candidate_seed_phrase(
            ParamsOfDeleteCandidateSeedPhrase { epk_expire_at },
            Signer::Keys { keys: signer_keys },
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("[delete_candidate_seed_phrase]")
        })?;

    let result = crate::infra::ensure_tx_success(result, "delete_candidate_seed_phrase")?;
    wait_until_candidate_seed_phrase_absent(multifactor).await?;

    Ok(result.message_hash)
}

async fn submit_change_seed_phrase(
    multifactor: &Arc<MvMultifactor>,
    epk_expire_at: u64,
    new_owner_pubkey_sig: String,
    new_owner_pubkey: String,
    signer_keys: KeyPair,
) -> crate::errors::AppResult<Option<String>> {
    let result = multifactor
        .change_seed_phrase(
            KitParamsOfChangeSeedPhrase { epk_expire_at, new_owner_pubkey_sig, new_owner_pubkey },
            Signer::Keys { keys: signer_keys },
        )
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("[change_seed_phrase]"))?;

    let result = crate::infra::ensure_tx_success(result, "change_seed_phrase")?;
    wait_until_candidate_seed_phrase_present(multifactor).await?;

    Ok(result.message_hash)
}

async fn accept_candidate_seed_phrase_and_wait(
    multifactor: &Arc<MvMultifactor>,
    new_owner_pubkey: String,
    signer_keys: KeyPair,
) -> crate::errors::AppResult<Option<String>> {
    let result = multifactor
        .accept_candidate_seed_phrase(
            ParamsOfAcceptCandidateSeedPhrase { new_owner_pubkey: new_owner_pubkey.clone() },
            Signer::Keys { keys: signer_keys },
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("[accept_candidate_seed_phrase]")
        })?;

    let result = crate::infra::ensure_tx_success(result, "accept_candidate_seed_phrase")?;
    wait_until_owner_pubkey(multifactor, new_owner_pubkey).await?;

    Ok(result.message_hash)
}

/// Confirm phase shared by `add_zkp_factor`: polls `fetch` until `predicate`
/// holds, emitting an `add_factor:confirming` heartbeat on every attempt, a
/// final `add_factor:confirmed` on success, or `add_factor:timed_out` (plus a
/// terminal `add_factor_timeout` error) when attempts are exhausted. Generic
/// over the fetched data so it stays unit-testable without a live contract.
async fn confirm_factor_increment<T, FetchFn, FetchFut, VerifyFn>(
    fetch: FetchFn,
    predicate: VerifyFn,
    progress: Option<ProgressSink>,
    max_attempts: u32,
    interval_ms: u64,
) -> crate::errors::AppResult<T>
where
    FetchFn: Fn() -> FetchFut,
    FetchFut: std::future::Future<Output = crate::errors::AppResult<T>>,
    VerifyFn: Fn(&T) -> bool,
{
    let heartbeat = progress.clone();
    let polled = poll_until(
        || {
            let heartbeat = heartbeat.clone();
            let fut = fetch();
            async move {
                // One heartbeat per poll attempt = "still working" liveness.
                crate::progress::emit(
                    heartbeat.as_ref(),
                    ProgressEvent::new("add_factor", "confirming"),
                );
                fut.await
            }
        },
        predicate,
        Some(max_attempts),
        Some(interval_ms),
    )
    .await;

    let data = match polled {
        Ok(data) => data,
        Err(e) => {
            if crate::infra::is_confirmation_pending_error(&e) {
                crate::progress::emit(
                    progress.as_ref(),
                    ProgressEvent::new("add_factor", "timed_out"),
                );
                return Err(crate::errors::AppError::new(
                    "add_zkp_factor: on-chain confirmation did not arrive in time",
                )
                .with_kind("add_factor_timeout"));
            }
            return Err(e);
        }
    };

    crate::progress::emit(progress.as_ref(), ProgressEvent::new("add_factor", "confirmed"));
    Ok(data)
}

pub async fn add_zkp_factor(
    multifactor: &Arc<MvMultifactor>,
    multifactor_data: &MultifactorData,
    params: AddZkpFactorReq,
    progress: Option<ProgressSink>,
) -> crate::errors::AppResult<ResultOfAddZkpFactor> {
    let current_factors_length = multifactor_data.factors_len.parse().unwrap_or(0);
    let result = multifactor
        .add_zkp_factor(
            ParamsOfAddZkpFactor {
                proof: params.proof,
                epk: format!("0x{}", params.epk.clone()),
                kid: params.kid,
                header_base_64: params.header_base_64,
                epk_expire_at: params.epk_expire_at,
            },
            Signer::Keys { keys: KeyPair { public: params.epk, secret: params.esk } },
        )
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("failed to add zkp factor"))?;

    let result = crate::infra::ensure_tx_success(result, "add_zkp_factor")?;
    let message_id = result.message_hash.clone();

    // Message accepted by the network; now wait for the factor count to tick up.
    crate::progress::emit(progress.as_ref(), ProgressEvent::new("add_factor", "submitted"));

    let mf = Arc::clone(multifactor);
    let target_factors_len = (current_factors_length + 1).min(MAX_NUM_OF_FACTORS);
    confirm_factor_increment(
        move || {
            let mf = mf.clone();
            async move {
                super::query::get_multifactor_decoded_data(&mf)
                    .await
                    .map_err(|e| e.with_context("Multifactor get details"))
            }
        },
        move |data: &MultifactorData| data.factors_len.parse().unwrap_or(0) == target_factors_len,
        progress,
        ADD_FACTOR_CONFIRM_MAX_ATTEMPTS,
        ADD_FACTOR_CONFIRM_INTERVAL_MS,
    )
    .await?;

    Ok(ResultOfAddZkpFactor { message_id })
}

pub async fn set_remove_oldest(
    multifactor: &Arc<MvMultifactor>,
    owner_keys: KeyPair,
    flag: bool,
) -> crate::errors::AppResult<Option<String>> {
    let result = multifactor
        .set_force_remove_oldest(
            ParamsOfSetForceRemoveOldest { flag },
            Signer::Keys { keys: owner_keys },
        )
        .await
        .map_err(|e| {
            crate::errors::AppError::from(e).with_context("Set force to remove oldest failure")
        })?;

    let result = crate::infra::ensure_tx_success(result, "set_force_remove_oldest")?;

    Ok(result.message_hash)
}

pub async fn set_wasm_hash(
    multifactor: &Arc<MvMultifactor>,
    owner_keys: KeyPair,
    wasm_hash: impl AsRef<str>,
) -> crate::errors::AppResult<Option<String>> {
    let result = multifactor
        .set_wasm_hash(
            ParamsOfSetWasmHash { wasm_hash: wasm_hash.as_ref().to_string() },
            Signer::Keys { keys: owner_keys.clone() },
        )
        .await
        .map_err(|e| crate::errors::AppError::from(e).with_context("Set wasm hash failure"))?;

    let result = crate::infra::ensure_tx_success(result, "set_wasm_hash")?;

    Ok(result.message_hash)
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfChangeSeedPhrase {
    pub password: String,
    pub signer_keys: KeyPair,
    pub new_owner_keys: KeyPair,
    pub multifactor_address: String,
}

// TODO(refactor/change_seed_phrase): Keep this as one domain operation
// ("replace seed"), but split the internal orchestration into private step
// helpers to reduce function size.
pub async fn change_seed_phrase(
    tvm_ctx: Arc<ClientContext>,
    multifactor: &Arc<MvMultifactor>,
    epk_expire_at: u64,
    params: ParamsOfChangeSeedPhrase,
) -> crate::errors::AppResult<ResultOfChangeSeedPhrase> {
    let mut message_ids = Vec::new();
    let crypto = BeeCrypto::from_client_context(tvm_ctx.clone());

    let new_owner_pubkey_sig = crypto.sign_detached_hex(
        params.new_owner_keys.public.clone(),
        params.new_owner_keys.secret.clone(),
    )?;
    let new_owner_pubkey = format!("0x{}", params.new_owner_keys.public);

    let multifactor_data = get_multifactor_decoded_data(multifactor).await?;
    let has_candidate = has_candidate_seed_phrase(&multifactor_data);

    if has_candidate {
        let message_id = delete_candidate_seed_phrase_and_wait(
            multifactor,
            epk_expire_at,
            params.signer_keys.clone(),
        )
        .await?;
        push_message_id(&mut message_ids, message_id);
    }

    let message_id = {
        let mf = Arc::clone(multifactor);
        let sig = new_owner_pubkey_sig.clone();
        let pubkey = new_owner_pubkey.clone();
        let keys = params.signer_keys.clone();
        crate::infra::with_retry(
            move || {
                let mf = mf.clone();
                let sig = sig.clone();
                let pubkey = pubkey.clone();
                let keys = keys.clone();
                async move {
                    submit_change_seed_phrase(&mf, epk_expire_at, sig, pubkey, keys).await
                }
            },
            3,
            3000,
            None::<fn(&crate::errors::AppError) -> bool>,
        )
        .await
        .map_err(|e| e.with_context("change_seed_phrase step 2: submit"))?
    };
    push_message_id(&mut message_ids, message_id);

    // `acceptCandidateSeedPhrase` must be signed by the recovery key. Pre-v3
    // wallets hold it on the legacy (396) HD path, so resolve against the
    // on-chain `pub_recovery_key` instead of re-deriving on the current path
    // (which would fail with ERR_NOT_OWNER). `pub_recovery_key` is not mutated
    // by the delete/submit steps above, so the earlier read is still valid.
    let (recovery_signer, _resolved_path) = resolve_recovery_signer(
        tvm_ctx.clone(),
        ParamsOfBuildRecoveryKeys {
            password: params.password.clone(),
            multifactor_address: multifactor.address().to_string(),
        },
        &multifactor_data.pub_recovery_key,
    )?;

    let message_id = {
        let mf = Arc::clone(multifactor);
        let pubkey = format!("0x{}", params.new_owner_keys.public);
        let keys = recovery_signer;
        crate::infra::with_retry(
            move || {
                let mf = mf.clone();
                let pubkey = pubkey.clone();
                let keys = keys.clone();
                async move { accept_candidate_seed_phrase_and_wait(&mf, pubkey, keys).await }
            },
            3,
            3000,
            None::<fn(&crate::errors::AppError) -> bool>,
        )
        .await
        .map_err(|e| e.with_context("change_seed_phrase step 3: accept"))?
    };
    push_message_id(&mut message_ids, message_id);

    Ok(ResultOfChangeSeedPhrase { message_ids })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use futures::StreamExt;

    use super::confirm_factor_increment;
    use crate::errors::AppError;
    use crate::progress::ProgressEvent;

    #[tokio::test]
    async fn confirm_emits_heartbeat_per_attempt_then_confirmed() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_fetch = calls.clone();

        let res = confirm_factor_increment(
            move || {
                let calls_fetch = calls_fetch.clone();
                async move {
                    // satisfies the predicate on the 3rd attempt
                    let n = calls_fetch.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok::<u32, AppError>(n)
                }
            },
            |n: &u32| *n >= 3,
            Some(tx),
            10,
            1,
        )
        .await;

        assert!(res.is_ok());
        let events: Vec<ProgressEvent> = rx.collect().await;
        let stages: Vec<&str> = events.iter().map(|e| e.stage.as_str()).collect();
        assert_eq!(stages, ["confirming", "confirming", "confirming", "confirmed"]);
        assert!(events.iter().all(|e| e.op == "add_factor"));
    }

    #[tokio::test]
    async fn confirm_times_out_with_terminal_error_and_emits_timed_out() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();

        let res = confirm_factor_increment(
            || async { Ok::<u32, AppError>(0) },
            |n: &u32| *n == 99,
            Some(tx),
            3,
            1,
        )
        .await;

        let err = res.expect_err("should time out");
        assert_eq!(err.kind.as_deref(), Some("add_factor_timeout"));

        let events: Vec<ProgressEvent> = rx.collect().await;
        let stages: Vec<&str> = events.iter().map(|e| e.stage.as_str()).collect();
        assert_eq!(stages, ["confirming", "confirming", "confirming", "timed_out"]);
    }
}
