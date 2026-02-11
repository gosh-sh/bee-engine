use bee_shared::miner::leaf::ComputedLeaf;
use bee_shared::miner::leaf::Leaf;

use crate::core::merkle::MerkleProcessor;

#[derive(Clone)]
pub struct MiningProcessor {
    merkle: MerkleProcessor,
}

#[derive(Debug)]
pub(crate) struct ParamsOfCalcHash<'a> {
    pub seed: &'a str,
    pub idx: u128,
    pub x: u32,
    pub y: u32,
    pub timestamp: u64,
    pub complexity: u32,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ResultOfGetProof {
    pub proof: Vec<u8>,
    pub selected_leaves: Vec<Vec<u8>>,
}

impl MiningProcessor {
    pub fn new() -> Self {
        Self { merkle: MerkleProcessor::new() }
    }

    pub fn calc_hash_blake(&mut self, params: ParamsOfCalcHash) -> ComputedLeaf {
        let mut nonce = 0u64;
        let threshold = u128::MAX >> params.complexity;

        loop {
            let leaf = Leaf {
                index: params.idx,
                nonce,
                seed: params.seed.to_string(),
                x: params.x,
                y: params.y,
                timestamp: params.timestamp,
                complexity: params.complexity,
            };

            let computed_leaf = leaf.compute();
            if computed_leaf.hash_num() < threshold {
                self.merkle.add_leaf(&computed_leaf);
                return computed_leaf;
            }

            nonce = nonce.wrapping_add(1);
        }
    }

    pub fn get_merkle_root(&self) -> Vec<u8> {
        self.merkle.get_merkle_root()
    }

    pub fn get_merkle_leaves(&self) -> Vec<Vec<u8>> {
        self.merkle.get_merkle_leaves()
    }

    pub fn get_proof_in_window(
        &self,
        start_index: usize,
        end_index: usize,
    ) -> Result<ResultOfGetProof, String> {
        let (proof, selected_leaves) =
            self.merkle.get_proof_in_window(start_index, end_index).map_err(|e| e.to_string())?;

        Ok(ResultOfGetProof { proof, selected_leaves })
    }

    pub fn clear_merkle(&mut self) {
        self.merkle.clear();
    }

    pub fn commit(&mut self) {
        self.merkle.commit();
    }
}
