use bee_shared::miner::leaf::ComputedLeaf;

use crate::core::processor::MiningProcessor;
use crate::core::processor::ParamsOfCalcHash;

#[derive(Debug, Clone)]
pub struct ParamsOfCompute {
    pub x: u32,
    pub y: u32,
    pub now_ms: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResultOfGetMerkleSnapshot {
    pub root: Vec<u8>,
    pub leaves: Vec<Vec<u8>>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ResultOfGetProof {
    pub proof: Vec<u8>,
    pub selected_leaves: Vec<Vec<u8>>,
    pub selected_leaves_data: Vec<ComputedLeaf>,
}

#[derive(Clone)]
pub struct MiningCore {
    hash_processor: MiningProcessor,
    target_bits: u32,
    seed: String,
    committed: bool,
    completed: Vec<ComputedLeaf>,
    ends_at_ms: Option<u64>,
    duration_ms: u64,
    last_now_ms: Option<u64>,
}

impl MiningCore {
    pub fn new(seed: String, duration_ms: u64, target_bits: u32) -> Self {
        let hash_processor = MiningProcessor::new();

        Self {
            hash_processor,
            target_bits,
            seed,
            duration_ms,
            committed: false,
            completed: Vec::new(),
            ends_at_ms: None,
            last_now_ms: None,
        }
    }

    pub fn compute(&mut self, params: ParamsOfCompute) -> Option<ComputedLeaf> {
        if self.ends_at_ms.is_none() {
            self.ends_at_ms = Some(params.now_ms.saturating_add(self.duration_ms));
        }

        if self.deadline_reached_ms(params.now_ms) {
            return None;
        }
        if self.committed {
            return None;
        }

        if let Some(prev) = self.last_now_ms {
            if params.now_ms < prev {
                return None;
            }
        }

        let job_index = self.completed.len() as u128;
        let computed_leaf = self.hash_processor.calc_hash_blake(ParamsOfCalcHash {
            seed: &self.seed,
            x: params.x,
            y: params.y,
            timestamp: params.now_ms,
            complexity: self.target_bits,
            idx: job_index,
        });
        self.completed.push(computed_leaf.clone());
        Some(computed_leaf)
    }

    pub fn get_merkle(&mut self) -> ResultOfGetMerkleSnapshot {
        if !self.committed {
            self.hash_processor.commit();
            self.committed = true;
        }
        ResultOfGetMerkleSnapshot {
            root: self.hash_processor.get_merkle_root(),
            leaves: self.hash_processor.get_merkle_leaves(),
        }
    }

    pub fn get_proof(
        &self,
        start_index: usize,
        end_index: usize,
    ) -> Result<ResultOfGetProof, String> {
        let proof = self.hash_processor.get_proof_in_window(start_index, end_index)?;
        Ok(ResultOfGetProof {
            proof: proof.proof,
            selected_leaves: proof.selected_leaves,
            selected_leaves_data: self.completed_in_window(start_index, end_index),
        })
    }

    pub fn completed_in_window(&self, start_index: usize, end_index: usize) -> Vec<ComputedLeaf> {
        self.completed[start_index..end_index].to_vec()
    }

    pub fn reset(&mut self) {
        self.hash_processor.clear_merkle();
        self.completed.clear();
        self.committed = false;
        self.ends_at_ms = None;
    }

    fn deadline_reached_ms(&self, now_ms: u64) -> bool {
        self.ends_at_ms.is_some_and(|end| now_ms >= end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_tap(core: &mut MiningCore, x: u32, y: u32, now_ms: u64) -> Option<ComputedLeaf> {
        core.compute(ParamsOfCompute { x, y, now_ms })
    }

    #[test]
    fn sets_deadline_on_first_job_and_honors_it() {
        let mut core = MiningCore::new("s".to_string(), 15_000, 12);

        assert!(core.ends_at_ms.is_none());

        let start = 1_000_000;
        let _ = add_tap(&mut core, 1, 1, start);
        let end = core.ends_at_ms.expect("deadline must be set");
        assert_eq!(end, start + 15_000);

        let mut core2 = MiningCore::new("s".to_string(), 15_000, 12);
        let _ = add_tap(&mut core2, 1, 1, start);
        let ok = add_tap(&mut core2, 1, 1, start + 14_999);
        assert!(ok.is_some());

        // forbidden at the end
        let out = add_tap(&mut core, 1, 1, end);
        assert!(out.is_none());
    }

    #[test]
    fn after_commit_no_more_jobs() {
        let mut core = MiningCore::new("seed".to_string(), 5_000, 12);
        let _ = add_tap(&mut core, 1, 1, 0);
        let _ = add_tap(&mut core, 1, 1, 100);

        let _snap = core.get_merkle();

        assert!(core.committed, "must be committed after get_merkle");

        let out = add_tap(&mut core, 1, 1, 200);
        assert!(out.is_none(), "no jobs after commit");
    }

    #[test]
    fn completed_slice_returns_elements_in_order() {
        let mut core = MiningCore::new("s".to_string(), 5_000, 12);
        let _ = add_tap(&mut core, 1, 1, 0);
        let _ = add_tap(&mut core, 1, 1, 100);
        let _ = add_tap(&mut core, 1, 1, 200);
        let _ = add_tap(&mut core, 1, 1, 300);
        let v = core.completed_in_window(1, 3);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].index, 1);
        assert_eq!(v[1].index, 2);
    }

    #[test]
    fn reset_clears_state_and_restarts_session() {
        let mut core = MiningCore::new("seed0".to_string(), 10_000, 12);

        let _ = add_tap(&mut core, 1, 1, 0);
        let _ = add_tap(&mut core, 1, 1, 100);
        assert!(!core.completed.is_empty());
        assert!(core.ends_at_ms.is_some());

        core.reset();
        assert!(core.completed.is_empty());
        assert!(!core.committed);
        assert!(core.ends_at_ms.is_none());

        let _ = add_tap(&mut core, 1, 1, 5_000);
        assert!(core.ends_at_ms.is_some());
    }

    #[test]
    fn accepts_last_ms_before_deadline_and_rejects_at_deadline() {
        let mut core = MiningCore::new("s".to_string(), 2_000, 12);
        let start = 10_000;
        let _ = add_tap(&mut core, 1, 1, start);
        let end = core.ends_at_ms.unwrap();

        // last ms before deadline
        assert!(add_tap(&mut core, 1, 1, end - 1).is_some());
        // at deadline
        assert!(add_tap(&mut core, 1, 1, end).is_none());
    }

    #[test]
    fn get_merkle_is_idempotent_and_returns_non_empty_root_after_work() {
        let mut core = MiningCore::new("seed".to_string(), 5_000, 12);
        let _ = add_tap(&mut core, 1, 1, 0);
        let _ = add_tap(&mut core, 1, 1, 100);

        let snap1 = core.get_merkle();
        let root1 = snap1.root.clone();
        let snap2 = core.get_merkle();
        assert_eq!(root1, snap2.root, "commit should be idempotent");
        assert!(!root1.is_empty(), "merkle root should not be empty after some work");
    }

    #[test]
    fn get_proof_bounds() {
        let mut core = MiningCore::new("s".to_string(), 5_000, 12);
        let _ = add_tap(&mut core, 1, 1, 0);
        let _ = add_tap(&mut core, 1, 1, 100);
        let _ = add_tap(&mut core, 1, 1, 200);
        let _ = core.get_merkle();

        let ok = core.get_proof(1, 2);
        assert!(ok.is_ok());

        let bad = core.get_proof(1, 100);
        assert!(bad.is_err());

        let bad = core.get_proof(100, 2);
        assert!(bad.is_err());

        let bad = core.get_proof(100, 200);
        assert!(bad.is_err());
    }

    #[test]
    fn merkle_before_any_work_is_empty_but_commits() {
        let mut core = MiningCore::new("s".to_string(), 5_000, 12);
        let _ = core.get_merkle();
        assert!(core.committed);
    }
}
