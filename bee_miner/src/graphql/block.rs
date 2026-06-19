use serde::Deserialize;

use super::GqlEdge;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct BlocksBlockchain {
    pub blocks: BlocksConnection,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct BlocksConnection {
    pub edges: Vec<GqlEdge<BlockNode>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct BlockNode {
    pub seq_no: u64,
}
