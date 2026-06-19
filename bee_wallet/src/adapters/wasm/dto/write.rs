use wasm_bindgen::prelude::wasm_bindgen;

use crate::ResultOfBlockchainWrite as InnerResultOfBlockchainWrite;
use crate::ResultOfSendMessage as InnerResultOfSendMessage;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ResultOfBlockchainWrite {
    message_ids: Vec<String>,
    pending_stage: Option<String>,
    pending_reason: Option<String>,
}

impl From<InnerResultOfBlockchainWrite> for ResultOfBlockchainWrite {
    fn from(value: InnerResultOfBlockchainWrite) -> Self {
        Self {
            message_ids: value.message_ids,
            pending_stage: value.pending_stage,
            pending_reason: value.pending_reason,
        }
    }
}

#[wasm_bindgen]
impl ResultOfBlockchainWrite {
    #[wasm_bindgen(getter)]
    pub fn message_ids(&self) -> Vec<String> {
        self.message_ids.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pending_stage(&self) -> Option<String> {
        self.pending_stage.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pending_reason(&self) -> Option<String> {
        self.pending_reason.clone()
    }
}

/// Wraps `ackinacki_kit::tvm_client::processing::ResultOfSendMessage`.
/// Numeric `exit_code` is signed (i32) and survives the boundary as-is.
#[wasm_bindgen]
pub struct ResultOfSendMessage {
    message_hash: Option<String>,
    block_hash: Option<String>,
    tx_hash: Option<String>,
    aborted: Option<bool>,
    exit_code: Option<i32>,
    thread_id: Option<String>,
    producers: Vec<String>,
    current_time: Option<String>,
}

impl From<InnerResultOfSendMessage> for ResultOfSendMessage {
    fn from(value: InnerResultOfSendMessage) -> Self {
        Self {
            message_hash: value.message_hash,
            block_hash: value.block_hash,
            tx_hash: value.tx_hash,
            aborted: value.aborted,
            exit_code: value.exit_code,
            thread_id: value.thread_id,
            producers: value.producers,
            current_time: value.current_time,
        }
    }
}

#[wasm_bindgen]
impl ResultOfSendMessage {
    #[wasm_bindgen(getter)]
    pub fn message_hash(&self) -> Option<String> {
        self.message_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn block_hash(&self) -> Option<String> {
        self.block_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn tx_hash(&self) -> Option<String> {
        self.tx_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn aborted(&self) -> Option<bool> {
        self.aborted
    }

    #[wasm_bindgen(getter)]
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    #[wasm_bindgen(getter)]
    pub fn thread_id(&self) -> Option<String> {
        self.thread_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn producers(&self) -> Vec<String> {
        self.producers.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn current_time(&self) -> Option<String> {
        self.current_time.clone()
    }
}
