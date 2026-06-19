#![cfg(feature = "wasm")]
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;

use ackinacki_kit::contracts::mvsystem;
use ackinacki_kit::contracts::mvsystem::miner::contract::ParamsOfCancelSession;
use ackinacki_kit::contracts::mvsystem::miner::contract::ParamsOfGetReward;
use ackinacki_kit::contracts::mvsystem::miner::events::DecodedMinerEvent;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::ContextAccessor;
use ackinacki_kit::contracts::traits::DecodeAccountData;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use ackinacki_kit::tvm_client::abi::Signer;
use ackinacki_kit::tvm_client::crypto::KeyPair;
use ackinacki_kit::tvm_client::net;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;
use futures::channel::mpsc::unbounded;
use wasm_bindgen::prelude::*;

use crate::graphql::block::BlocksBlockchain;
use crate::graphql::GqlResponse;
use crate::wasm::get_miner_events;
use crate::wasm::worker;
use crate::wasm::worker::MinerCommand;
use crate::wasm::worker::MinerStatus;
use crate::wasm::worker::MinerWorker;
use crate::wasm::DecodedSessionStatusData;
use crate::wasm::GraphqlBlockData;
use crate::wasm::MinerAccountData;

#[wasm_bindgen]
pub struct Miner {
    app_id: String,
    contract: mvsystem::miner::contract::Miner,
    keys: KeyPair,
    seeds: Rc<RefCell<VecDeque<String>>>,
    complexity: Rc<Cell<(u32, u32)>>,
    workers: Rc<RefCell<Vec<MinerWorker>>>,
    dropped: Rc<Cell<bool>>,
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}

#[wasm_bindgen]
impl Miner {
    #[wasm_bindgen(js_name = new)]
    pub async fn new(
        endpoints: Vec<String>,
        app_id: String,
        address: String,
        public_key: String,
        secret_key: String,
    ) -> Result<Miner, JsError> {
        // Create blockchain context
        let tvm_context = {
            let mut config = ClientConfig::default();
            config.network.endpoints = Some(endpoints);
            config.network.query_timeout = 10000;

            let context = ClientContext::new(config).map_err(|e| JsError::new(&e.to_string()))?;
            Arc::new(context)
        };

        // Read current complexity and seeds from contract
        let contract = mvsystem::miner::contract::Miner::new_default(tvm_context.clone(), &address);
        let keys = KeyPair { public: public_key, secret: secret_key };
        let details = match contract.get_details().await {
            Ok(data) => data,
            Err(e) => return Err(JsError::new(&format!("Get miner details ({e})"))),
        };

        // Check if any session data is not present, otherwise repair
        let events_after_dt = js_sys::Date::now() as u64 / 1000 - 1;
        let complexity = (details.easy_complexity, details.hard_complexity);
        let seeds = {
            if details.submit_session_data.is_some() {
                let cancel_session_result = contract
                    .cancel_session(
                        ParamsOfCancelSession { app_id: app_id.clone() },
                        Signer::Keys { keys: keys.clone() },
                    )
                    .await;
                if let Err(e) = cancel_session_result {
                    return Err(JsError::new(&format!("Cancel stale session data ({e})")));
                }
                VecDeque::from([details.next_seed])
            } else {
                VecDeque::from([details.seed, details.next_seed])
            }
        };

        // Create miner instance
        let miner = Miner {
            app_id: app_id.clone(),
            contract: contract.clone(),
            keys,
            seeds: Rc::new(RefCell::new(seeds)),
            complexity: Rc::new(Cell::new(complexity)),
            workers: Rc::new(RefCell::new(Vec::new())),
            dropped: Rc::new(Cell::new(false)),
        };

        // Start internal thread, which will catch miner contract events
        let seeds_ref = miner.seeds.clone();
        let complexity_ref = miner.complexity.clone();
        let workers_ref = miner.workers.clone();
        let contract_ref = contract.clone();
        let dropped_ref = miner.dropped.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let mut after_dt = events_after_dt;

            while !dropped_ref.get() {
                gloo_timers::future::TimeoutFuture::new(2500).await;
                web_sys::console::debug_1(&"Read miner events thread".to_string().into());

                let decoded_events = match get_miner_events(&contract_ref, after_dt).await {
                    Ok(items) => items,
                    Err(e) => {
                        web_sys::console::error_1(&e.into());
                        continue;
                    }
                };

                let mut created_at = Vec::new();
                for decoded_event in decoded_events {
                    match decoded_event {
                        DecodedMinerEvent::SessionInterval { event, data, .. } => {
                            created_at.push(event.created_at);

                            if let Some(worker) =
                                workers_ref.borrow().iter().find(|w| w.id == data.worker_id)
                            {
                                let _ = worker
                                    .sender
                                    .unbounded_send(MinerCommand::SendSessionInterval(data));
                            }
                        }
                        DecodedMinerEvent::SeedUpdated { event, data, .. } => {
                            created_at.push(event.created_at);
                            seeds_ref.borrow_mut().push_back(data.next_seed);
                        }
                        DecodedMinerEvent::ComplexityUpdated { event, data, .. } => {
                            created_at.push(event.created_at);
                            complexity_ref.set((data.easy, data.hard));
                        }
                        DecodedMinerEvent::SessionAccepted { event, data, .. } => {
                            created_at.push(event.created_at);

                            handle_session_result(
                                &workers_ref,
                                data.data,
                                MinerCommand::ProcessSessionAccepted {
                                    wasm_result: data.wasm_result,
                                },
                            );
                        }
                        DecodedMinerEvent::SessionRejected { event, data, .. } => {
                            created_at.push(event.created_at);

                            handle_session_result(
                                &workers_ref,
                                data.data,
                                MinerCommand::ProcessSessionRejected {
                                    wasm_result: data.wasm_result,
                                },
                            );
                        }
                    }
                }

                if let Some(created_at_max) = created_at.iter().max() {
                    after_dt = *created_at_max;
                }
            }
        });

        Ok(miner)
    }

    #[wasm_bindgen(js_name = can_start)]
    pub fn can_start(&self) -> bool {
        let is_active_worker =
            self.workers.borrow().iter().any(|w| w.status == MinerStatus::Computing);
        let is_seeds_empty = self.seeds.borrow().is_empty();

        !is_active_worker && !is_seeds_empty
    }

    #[wasm_bindgen(js_name = start)]
    pub fn start(&self, duration_ms: u32, callback: js_sys::Function) -> Result<(), JsError> {
        // Create worker
        if self.workers.borrow().iter().any(|w| w.status == MinerStatus::Computing) {
            return Err(JsError::new("There is already running worker"));
        }

        let Some(seed) = self.seeds.borrow_mut().pop_front() else {
            return Err(JsError::new("No seeds available"));
        };

        // Spawn worker
        let (worker_sender, worker_receiver) = unbounded::<MinerCommand>();
        let (easy_complexity, hard_complexity) = self.complexity.get();
        let worker = MinerWorker {
            id: (js_sys::Math::random() * u64::MAX as f64) as u64,
            sender: worker_sender,
            status: MinerStatus::Queued,
            contract: self.contract.clone(),
            app_id: self.app_id.clone(),
            keys: self.keys.clone(),
            seed: seed.clone(),
            duration_ms: duration_ms as u64,
            easy_complexity,
            hard_complexity,
        };

        let seeds_ref = self.seeds.clone();
        let workers_ref = self.workers.clone();
        workers_ref.borrow_mut().push(worker.clone());

        wasm_bindgen_futures::spawn_local(worker::run(
            worker,
            worker_receiver,
            seeds_ref,
            workers_ref,
            callback,
        ));

        Ok(())
    }

    #[wasm_bindgen(js_name = stop)]
    pub fn stop(&self) {
        // Remove queued workers
        self.workers.borrow_mut().retain(|w| w.status != MinerStatus::Queued);

        // Send stop cmd to running workers
        for worker in self.workers.borrow().iter().filter(|w| w.status == MinerStatus::Computing) {
            let _ = worker.sender.unbounded_send(MinerCommand::Stop);
        }
    }

    #[wasm_bindgen(js_name = add_tap)]
    pub fn add_tap(&self, x: u32, y: u32) -> Result<(), JsError> {
        // Send cmd to running workers
        match self.workers.borrow().iter().find(|w| w.status == MinerStatus::Computing) {
            Some(worker) => {
                let _ = worker.sender.unbounded_send(MinerCommand::QueueTap { x, y });
            }
            None => return Err(JsError::new("No running workers to add tap to")),
        }
        Ok(())
    }

    #[wasm_bindgen(js_name = remove_seed)]
    pub fn remove_seed(&self, seed: String) {
        self.seeds.borrow_mut().retain(|v| v != &seed);
    }

    #[wasm_bindgen(js_name = get_reward)]
    pub async fn get_reward(&self) -> Result<(), JsError> {
        let _ = self
            .contract
            .get_reward(
                ParamsOfGetReward { app_id: self.app_id.clone() },
                Signer::Keys { keys: self.keys.clone() },
            )
            .await
            .map_err(|e| JsError::new(&format!("Send `get reward` message ({e})")))?;
        Ok(())
    }

    #[wasm_bindgen(js_name = get_miner_data)]
    pub async fn get_miner_data(&self) -> Result<MinerAccountData, JsError> {
        self.contract
            .fetch_account()
            .await
            .map_err(|e| JsError::new(&format!("Fetch miner account data ({e})")))?;

        let Some(data) = self.contract.async_guarded(|account| account.data.clone()).await else {
            return Err(JsError::new("Miner account has no data"));
        };

        let value = self
            .contract
            .decode_account_data(data)
            .map_err(|e| JsError::new(&format!("Get miner account data ({e})")))?;

        serde_json::from_value::<MinerAccountData>(value)
            .map_err(|e| JsError::new(&format!("Deserialize miner accounr data ({e})")))
    }

    #[wasm_bindgen(js_name = get_current_block)]
    pub async fn get_current_block(&self) -> Result<GraphqlBlockData, JsError> {
        let raw = net::query(
            self.contract.context().clone(),
            net::ParamsOfQuery {
                query: r#"
                  query {
                    blockchain {
                      blocks(last: 1) {
                        edges {
                          node { seq_no }
                        }
                      }
                    }
                  }
                "#
                .to_string(),
                variables: None,
            },
        )
        .await
        .map_err(|e| JsError::new(&format!("Query block seq_no ({e})")))?;

        let parsed = serde_json::from_value::<GqlResponse<BlocksBlockchain>>(raw.result)
            .map_err(|e| JsError::new(&format!("Deserialize blocks response ({e})")))?;

        parsed
            .data
            .blockchain
            .blocks
            .edges
            .first()
            .map(|edge| GraphqlBlockData { seq_no: edge.node.seq_no })
            .ok_or_else(|| JsError::new("No blocks returned"))
    }
}

#[cfg(not(feature = "single-wasm"))]
#[wasm_bindgen(start)]
pub fn start() {}

fn handle_session_result(
    workers_ref: &Rc<RefCell<Vec<MinerWorker>>>,
    session_status_data: impl AsRef<str>,
    cmd: MinerCommand,
) {
    let status = match DecodedSessionStatusData::try_from(session_status_data.as_ref().to_string())
    {
        Ok(s) => s,
        Err(e) => {
            web_sys::console::error_1(&e.into());
            return;
        }
    };

    if let Some(worker) = workers_ref.borrow().iter().find(|w| w.id == status.worker_id) {
        let _ = worker.sender.unbounded_send(cmd);
    }
}
