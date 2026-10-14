use borsh::BorshDeserialize;
use borsh::BorshSerialize;

use crate::miner::leaf::ComputedLeaf;

pub mod chain;
pub mod leaf;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SessionSubmit {
    pub root: Vec<u8>,
    pub leaves_count: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SessionProof {
    pub proof: Vec<u8>,
    pub leaves_tree: Vec<Vec<u8>>,
    pub leaves_data: Vec<ComputedLeaf>,
}
