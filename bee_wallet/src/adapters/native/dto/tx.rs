use serde::Deserialize;
use serde::Serialize;

use crate::services::transaction::history::ResultOfGetHistory as InnerResultOfGetHistory;
use crate::services::transaction::history::TxData as InnerTxData;
use crate::services::transaction::history::TxType as InnerTxType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    pub id: String,
    pub tx_type: String,
    pub created_at: String,
    pub value: String,
    pub src_name: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultOfGetHistory {
    pub data: Vec<TxData>,
    pub next_cursor: Option<String>,
    pub next_mining_cursor: Option<String>,
    pub has_next_page: bool,
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
