use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Display;
use std::rc::Rc;

use ackinacki_kit::contracts::mvsystem;
use ackinacki_kit::contracts::mvsystem::miner::contract::ParamsOfSubmitSession;
use ackinacki_kit::contracts::mvsystem::miner::contract::ParamsOfVerifySession;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use bee_shared::miner::SessionProof;
use bee_shared::miner::SessionSubmit;
use bee_shared::verifier;
use futures::channel::mpsc::UnboundedReceiver;
use futures::channel::mpsc::UnboundedSender;
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;
use wasm_bindgen::JsValue;

use crate::core::context::MiningCore;
use crate::core::context::ParamsOfCompute;
use crate::core::context::ResultOfGetMerkleSnapshot;
use crate::wasm::DecodedSessionStatusData;

#[derive(Clone)]
pub(crate) enum MinerCommand {
    Stop,
    QueueTap { x: u32, y: u32 },
    SendSessionInterval(mvsystem::miner::events::SessionIntervalData),
    ProcessSessionAccepted { wasm_result: String },
    ProcessSessionRejected { wasm_result: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MinerStatus {
    Queued,
    Computing,
    Submitting,
    Finished,
}

impl Display for MinerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MinerStatus::Queued => "queued",
            MinerStatus::Computing => "computing",
            MinerStatus::Submitting => "submitting",
            MinerStatus::Finished => "finished",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Serialize)]
struct CallbackData {
    action: String,
    data: Option<serde_json::Value>,
    error: Option<String>,
}

impl CallbackData {
    pub fn data(action: impl AsRef<str>, data: Option<serde_json::Value>) -> Self {
        Self { action: action.as_ref().to_string(), data, error: None }
    }

    pub fn error(
        action: impl AsRef<str>,
        error: impl AsRef<str>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self { action: action.as_ref().to_string(), data, error: Some(error.as_ref().to_string()) }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MinerWorker {
    pub id: u64,
    pub sender: UnboundedSender<MinerCommand>,
    pub status: MinerStatus,
    pub contract: mvsystem::miner::contract::Miner,
    pub app_id: String,
    pub keys: KeyPair,
    pub seed: String,
    pub duration_ms: u64,
    pub easy_complexity: u32,
    pub hard_complexity: u32,
}

pub(crate) async fn run(
    worker: MinerWorker,
    mut worker_receiver: UnboundedReceiver<MinerCommand>,
    seeds_ref: Rc<RefCell<VecDeque<String>>>,
    workers_ref: Rc<RefCell<Vec<MinerWorker>>>,
    callback: js_sys::Function,
) {
    // Set worker status and post callback
    update_worker_status(worker.id, &workers_ref, MinerStatus::Computing);
    send_callback(
        &callback,
        CallbackData::data(
            "status_updated",
            Some(json!({"worker_id": worker.id, "status": MinerStatus::Computing.to_string()})),
        ),
    );

    // Initialize miner cores
    let mut time_core =
        MiningCore::new(worker.seed.clone(), worker.duration_ms, worker.easy_complexity);
    let mut tap_core =
        MiningCore::new(worker.seed.clone(), worker.duration_ms, worker.hard_complexity);

    // Start computation loop
    let start_ms = js_sys::Date::now() as u64;
    loop {
        // Process incoming command and calculate hashes
        let now_ms = js_sys::Date::now() as u64;
        match worker_receiver.try_recv() {
            Ok(event) => match event {
                MinerCommand::QueueTap { x, y } => {
                    tap_core.compute(ParamsOfCompute { x, y, now_ms });
                    send_callback(
                        &callback,
                        CallbackData::data("tap_computed", Some(json!({"worker_id": worker.id}))),
                    );
                }
                MinerCommand::Stop => {
                    break;
                }
                _ => {}
            },
            Err(_) => {
                time_core.compute(ParamsOfCompute { x: 0, y: 0, now_ms });
            }
        }

        // If duration reached, send event and stop
        if now_ms >= start_ms + worker.duration_ms {
            break;
        }

        // Small delay to allow js event loop
        gloo_timers::future::TimeoutFuture::new(10).await;
    }

    // Start finalization.
    let time_tree = time_core.get_merkle();
    let tap_tree = tap_core.get_merkle();
    send_callback(
        &callback,
        CallbackData::data(
            "computation_completed",
            Some(json!({"worker_id": worker.id, "taps": tap_tree.leaves.len()})),
        ),
    );

    // Do nothing if any tree is empty and shutdown worker
    if time_tree.leaves.is_empty() || tap_tree.leaves.is_empty() {
        seeds_ref.borrow_mut().push_front(worker.seed.clone());
        shutdown_worker(&worker, &workers_ref, false, false, &callback);
        return;
    }

    // Wait if there is any worker with status `Submitting`
    loop {
        if workers_ref.borrow().iter().any(|w| w.status == MinerStatus::Submitting) {
            gloo_timers::future::TimeoutFuture::new(1000).await;
        } else {
            break;
        }
    }

    // Submit data to miner contract
    update_worker_status(worker.id, &workers_ref, MinerStatus::Submitting);
    send_callback(
        &callback,
        CallbackData::data(
            "status_updated",
            Some(json!({"worker_id": worker.id, "status": MinerStatus::Submitting.to_string()})),
        ),
    );

    let signer = Signer::Keys { keys: worker.keys.clone() };
    match submit_session_root(&worker, (&time_tree, &tap_tree), signer.clone()).await {
        Ok(_) => send_callback(
            &callback,
            CallbackData::data("submit_session_root", Some(json!({"worker_id": worker.id}))),
        ),
        Err(e) => {
            send_callback(
                &callback,
                CallbackData::error(
                    "submit_session_root",
                    "Submit session root failed",
                    Some(json!({"worker_id": worker.id, "message": e})),
                ),
            );

            shutdown_worker(&worker, &workers_ref, true, true, &callback);
            return;
        }
    }

    // Wait for session interval event
    while let Some(command) = worker_receiver.next().await {
        match command {
            MinerCommand::SendSessionInterval(data) => {
                let cores = (&mut time_core, &mut tap_core);
                let trees = (&time_tree, &tap_tree);
                match submit_session_proof(&worker, cores, trees, data, signer.clone()).await {
                    Ok(_) => {
                        send_callback(
                            &callback,
                            CallbackData::data(
                                "submit_session_proof",
                                Some(json!({"worker_id": worker.id})),
                            ),
                        );
                    }
                    Err(e) => {
                        send_callback(
                            &callback,
                            CallbackData::error(
                                "submit_session_proof",
                                "Submit session root failed",
                                Some(json!({"worker_id": worker.id, "message": e})),
                            ),
                        );
                        break;
                    }
                }
            }
            MinerCommand::ProcessSessionAccepted { wasm_result } => {
                send_callback(
                    &callback,
                    CallbackData::data(
                        "session_accepted",
                        Some(json!({"worker_id": worker.id, "result": wasm_result})),
                    ),
                );
                break;
            }
            MinerCommand::ProcessSessionRejected { wasm_result } => {
                send_callback(
                    &callback,
                    CallbackData::error(
                        "session_rejected",
                        "Session rejected",
                        Some(json!({"worker_id": worker.id, "result": wasm_result})),
                    ),
                );
                break;
            }
            _ => {}
        }
    }

    // Update worker status and remove from workers
    shutdown_worker(&worker, &workers_ref, true, false, &callback);
}

fn send_callback(callback: &js_sys::Function, arg: CallbackData) {
    let _ = callback.call1(&JsValue::NULL, &serde_json::to_string(&arg).unwrap().into());
}

fn update_worker_status(
    worker_id: u64,
    workers_ref: &Rc<RefCell<Vec<MinerWorker>>>,
    status: MinerStatus,
) {
    if let Some(worker) = workers_ref.borrow_mut().iter_mut().find(|w| w.id == worker_id) {
        worker.status = status
    }
}

fn shutdown_worker(
    worker: &MinerWorker,
    workers_ref: &Rc<RefCell<Vec<MinerWorker>>>,
    seed_used: bool,
    miner_state_corrupted: bool,
    callback: &js_sys::Function,
) {
    update_worker_status(worker.id, workers_ref, MinerStatus::Finished);
    send_callback(
        callback,
        CallbackData::data(
            "status_updated",
            Some(json!({"worker_id": worker.id, "status": MinerStatus::Finished.to_string()})),
        ),
    );

    workers_ref.borrow_mut().retain(|w| w.id != worker.id);
    send_callback(
        callback,
        CallbackData::data(
            "status_updated",
            Some(json!({
                "worker_id": worker.id,
                "status": "removed",
                "seed": if seed_used { Some(worker.seed.clone()) } else { None },
                "miner_state_corrupted": miner_state_corrupted
            })),
        ),
    );
}

async fn submit_session_root(
    worker: &MinerWorker,
    trees: (&ResultOfGetMerkleSnapshot, &ResultOfGetMerkleSnapshot),
    signer: Signer,
) -> Result<(), String> {
    let easy_params =
        SessionSubmit { root: trees.0.root.clone(), leaves_count: trees.0.leaves.len() as u64 };
    let hard_params =
        SessionSubmit { root: trees.1.root.clone(), leaves_count: trees.1.leaves.len() as u64 };

    let submit_session_params_bytes = verifier::combine_bytes(&[&easy_params, &hard_params])
        .map_err(|e| format!("Serialize submit session params to bytes ({e})"))?;

    // Send submit session params to miner
    worker
        .contract
        .submit_session(
            ParamsOfSubmitSession {
                app_id: worker.app_id.clone(),
                easy_count: easy_params.leaves_count,
                hard_count: hard_params.leaves_count,
                worker_id: worker.id,
                data: hex::encode(submit_session_params_bytes),
            },
            signer,
        )
        .await
        .map_err(|e| format!("Submit miner session ({e})"))?;

    Ok(())
}

async fn submit_session_proof(
    worker: &MinerWorker,
    cores: (&mut MiningCore, &mut MiningCore),
    trees: (&ResultOfGetMerkleSnapshot, &ResultOfGetMerkleSnapshot),
    interval: mvsystem::miner::events::SessionIntervalData,
    signer: Signer,
) -> Result<(), String> {
    let easy_core = cores.0;
    let hard_core = cores.1;
    let hard_tree = trees.1;

    let easy_proof_params = {
        let proof = easy_core
            .get_proof(interval.easy.start as usize, interval.easy.end as usize)
            .map_err(|e| format!("Get easy proof ({e})"))?;
        SessionProof {
            proof: proof.proof,
            leaves_tree: proof.selected_leaves,
            leaves_data: proof.selected_leaves_data.to_vec(),
        }
    };

    let hard_first_proof_params = {
        let proof = hard_core.get_proof(0, 1).map_err(|e| format!("Get hard first proof ({e})"))?;
        SessionProof {
            proof: proof.proof,
            leaves_tree: proof.selected_leaves,
            leaves_data: proof.selected_leaves_data.to_vec(),
        }
    };

    let hard_range_proof_params = {
        let proof = hard_core
            .get_proof(interval.hard.start as usize, interval.hard.end as usize)
            .map_err(|e| format!("Get hard range proof ({e})"))?;
        SessionProof {
            proof: proof.proof,
            leaves_tree: proof.selected_leaves,
            leaves_data: proof.selected_leaves_data.to_vec(),
        }
    };

    let hard_last_proof_params = {
        let proof = hard_core
            .get_proof(hard_tree.leaves.len() - 1, hard_tree.leaves.len())
            .map_err(|e| format!("Get hard last proof ({e})"))?;
        SessionProof {
            proof: proof.proof,
            leaves_tree: proof.selected_leaves,
            leaves_data: proof.selected_leaves_data.to_vec(),
        }
    };

    let verify_session_params_bytes = verifier::combine_bytes(&[
        &easy_proof_params,
        &hard_first_proof_params,
        &hard_range_proof_params,
        &hard_last_proof_params,
    ])
    .map_err(|e| format!("Serialize submit session params to bytes ({e})"))?;

    let event_data = String::try_from(DecodedSessionStatusData { worker_id: worker.id })
        .map_err(|e| format!("Serialize event data ({e})"))?;

    // Send verify session params to miner
    worker
        .contract
        .verify_session(
            ParamsOfVerifySession {
                app_id: worker.app_id.clone(),
                data: hex::encode(verify_session_params_bytes),
                success_event_address: vec![
                    mvsystem::miner::events::MinerEvent::SessionAccepted.to_address()
                ],
                success_event_data: vec![event_data.clone()],
                error_event_address: vec![
                    mvsystem::miner::events::MinerEvent::SessionRejected.to_address()
                ],
                error_event_data: vec![event_data.clone()],
            },
            signer.clone(),
        )
        .await
        .map_err(|e| format!("Verify miner session ({e})"))?;

    Ok(())
}
