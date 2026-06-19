use wasm_bindgen::prelude::wasm_bindgen;

use crate::services::transaction::history::ResultOfGetHistory as InnerResultOfGetHistory;
use crate::services::transaction::history::TxData as InnerTxData;
use crate::services::transaction::history::TxType as InnerTxType;

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TxData {
    id: String,
    tx_type: String,
    created_at: String,
    value: String,
    src_name: Option<String>,
}

fn tx_type_to_string(tx_type: &InnerTxType) -> String {
    match tx_type {
        InnerTxType::Mining => "Mining".to_string(),
        InnerTxType::Incoming => "Incoming".to_string(),
        InnerTxType::Outgoing => "Outgoing".to_string(),
    }
}

impl From<InnerTxData> for TxData {
    fn from(tx: InnerTxData) -> Self {
        Self {
            id: tx.id,
            tx_type: tx_type_to_string(&tx.tx_type),
            created_at: tx.created_at.to_string(),
            value: tx.value.to_string(),
            src_name: tx.src_name,
        }
    }
}

#[wasm_bindgen]
impl TxData {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn tx_type(&self) -> String {
        self.tx_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn value(&self) -> String {
        self.value.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn created_at(&self) -> String {
        self.created_at.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn src_name(&self) -> Option<String> {
        self.src_name.clone()
    }
}

#[wasm_bindgen]
pub struct ResultOfGetHistory {
    data: Vec<TxData>,
    next_cursor: Option<String>,
    next_mining_cursor: Option<String>,
    has_next_page: bool,
}

impl From<InnerResultOfGetHistory> for ResultOfGetHistory {
    fn from(value: InnerResultOfGetHistory) -> Self {
        Self {
            data: value.data.into_iter().map(TxData::from).collect(),
            next_cursor: value.next_cursor,
            next_mining_cursor: value.next_mining_cursor,
            has_next_page: value.has_next_page,
        }
    }
}

#[wasm_bindgen]
impl ResultOfGetHistory {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<TxData> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn next_cursor(&self) -> Option<String> {
        self.next_cursor.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn next_mining_cursor(&self) -> Option<String> {
        self.next_mining_cursor.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn has_next_page(&self) -> bool {
        self.has_next_page
    }
}
