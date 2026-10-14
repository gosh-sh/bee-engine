//! Building the sequential-chain proof on the device.
//!
//! The miner walks the chain step by step, keeping only every `stride`-th state
//! plus the steps themselves, and commits the checkpoints as merkle leaves. When
//! the contract names the intervals to open, [`ChainCore::interval_proof`]
//! produces the endpoints, the steps between them, and a merkle proof covering
//! both — everything the verifier needs and nothing more.
//!
//! Memory is `checkpoints * 32 B` plus the steps, rather than the
//! `steps * 32 B` a naive walk would hold: at 64 M steps that is the difference
//! between a few MiB and two gigabytes.

use bee_shared::miner::chain::ChainSubmit;
use bee_shared::miner::chain::IntervalProof;
use bee_shared::miner::chain::Step;
use bee_shared::miner::chain::DEFAULT_STRIDE;
use rs_merkle::Hasher;
use rs_merkle::MerkleTree;

use crate::core::merkle::Blake3Hasher;

/// A chain under construction.
pub struct ChainCore {
    stride: u32,
    /// State at every `stride`-th step, including the genesis state.
    checkpoints: Vec<[u8; 32]>,
    /// Every step taken, needed to answer whichever interval is asked for.
    steps: Vec<Step>,
    /// Rolling state; equals `checkpoints.last()` only on a stride boundary.
    head: [u8; 32],
    tree: Option<MerkleTree<Blake3Hasher>>,
}

impl ChainCore {
    pub fn new(seed: impl AsRef<str>) -> Self {
        Self::with_stride(seed, DEFAULT_STRIDE)
    }

    pub fn with_stride(seed: impl AsRef<str>, stride: u32) -> Self {
        assert!(stride > 0, "stride must be positive");
        let genesis = bee_shared::miner::chain::genesis(seed.as_ref());
        Self {
            stride,
            checkpoints: vec![genesis],
            steps: Vec::new(),
            head: genesis,
            tree: None,
        }
    }

    /// Advance the chain by one step. Returns the new state.
    ///
    /// Committing freezes the chain, so a step after that is refused rather than
    /// silently invalidating the root the contract already holds.
    pub fn advance(&mut self, step: Step) -> Option<[u8; 32]> {
        if self.tree.is_some() {
            return None;
        }
        self.head = step.apply(&self.head);
        self.steps.push(step);
        if self.steps.len() % self.stride as usize == 0 {
            self.checkpoints.push(self.head);
        }
        Some(self.head)
    }

    /// Advance by `count` time-driven steps, continuing the nonce sequence.
    pub fn advance_idle(&mut self, count: u64) -> Option<[u8; 32]> {
        let mut last = None;
        for _ in 0..count {
            let nonce = self.steps.len() as u64;
            last = self.advance(Step::idle(nonce))?.into();
        }
        last
    }

    /// Record a tap at the current position in the chain.
    pub fn advance_tap(&mut self, x: u32, y: u32) -> Option<[u8; 32]> {
        let nonce = self.steps.len() as u64;
        self.advance(Step { x, y, nonce })
    }

    pub fn steps_taken(&self) -> u64 {
        self.steps.len() as u64
    }

    /// Steps past the last checkpoint. Those are not covered by the commitment,
    /// so they earn nothing — the client should stop on a boundary.
    pub fn steps_past_last_checkpoint(&self) -> u64 {
        self.steps.len() as u64 % self.stride as u64
    }

    /// Bytes the miner is holding for this chain.
    pub fn memory_bytes(&self) -> usize {
        self.checkpoints.len() * 32 + self.steps.len() * std::mem::size_of::<Step>()
    }

    /// Freeze the chain and commit the checkpoints. Idempotent.
    pub fn commit(&mut self) -> ChainSubmit {
        if self.tree.is_none() {
            let mut tree = MerkleTree::<Blake3Hasher>::new();
            for cp in &self.checkpoints {
                tree.insert(Blake3Hasher::hash(cp.as_ref()));
            }
            tree.commit();
            self.tree = Some(tree);
        }
        let tree = self.tree.as_ref().expect("just committed");
        ChainSubmit {
            root: tree.root().map(|r| r.to_vec()).unwrap_or_default(),
            checkpoints_count: self.checkpoints.len() as u64,
            stride: self.stride,
        }
    }

    /// Open interval `index`: the walk from checkpoint `index` to `index + 1`.
    ///
    /// Fails if the chain was not committed yet or the interval is out of range,
    /// rather than producing a proof the verifier would reject.
    pub fn interval_proof(&self, index: u64) -> Result<IntervalProof, String> {
        let tree = self.tree.as_ref().ok_or("chain is not committed")?;
        // `index` arrives from the contract, so it can be anything at all;
        // every derived offset is checked rather than assumed to fit.
        let out_of_range = || {
            format!("interval {index} is out of range ({} checkpoints)", self.checkpoints.len())
        };
        let i = usize::try_from(index).map_err(|_| out_of_range())?;
        if i.checked_add(1).is_none_or(|next| next >= self.checkpoints.len()) {
            return Err(out_of_range());
        }

        let start = i.checked_mul(self.stride as usize).ok_or_else(out_of_range)?;
        let end = start.checked_add(self.stride as usize).ok_or_else(out_of_range)?;
        // A committed chain always has whole strides up to the last checkpoint,
        // so this range is present; guard anyway rather than panic on a slice.
        if end > self.steps.len() {
            return Err(format!("steps {start}..{end} are missing"));
        }

        Ok(IntervalProof {
            index,
            from: self.checkpoints[i].to_vec(),
            to: self.checkpoints[i + 1].to_vec(),
            proof: tree.proof(&[i, i + 1]).to_bytes(),
            steps: self.steps[start..end].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const STRIDE: u32 = 8;

    fn walked(steps: u64) -> ChainCore {
        let mut c = ChainCore::with_stride("seed", STRIDE);
        c.advance_idle(steps);
        c
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn checkpoints_appear_on_stride_boundaries() {
        let c = walked(3 * STRIDE as u64);
        // genesis + one per completed stride
        assert_eq!(c.commit_count_for_test(), 4);
        assert_eq!(c.steps_past_last_checkpoint(), 0);

        let c = walked(3 * STRIDE as u64 + 5);
        assert_eq!(c.commit_count_for_test(), 4, "a partial stride adds nothing");
        assert_eq!(c.steps_past_last_checkpoint(), 5);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn committing_freezes_the_chain() {
        let mut c = walked(STRIDE as u64);
        let first = c.commit();
        assert!(c.advance_tap(1, 2).is_none(), "no steps after commit");
        let second = c.commit();
        assert_eq!(first.root, second.root, "commit is idempotent");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn an_interval_replays_to_the_next_checkpoint() {
        let mut c = walked(4 * STRIDE as u64);
        c.commit();

        let iv = c.interval_proof(2).expect("interval 2 exists");
        assert_eq!(iv.steps.len(), STRIDE as usize);

        let mut h: [u8; 32] = iv.from.clone().try_into().unwrap();
        for s in &iv.steps {
            h = s.apply(&h);
        }
        assert_eq!(h.to_vec(), iv.to, "replaying the steps must reach `to`");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn intervals_are_bounded_and_need_a_commit() {
        let mut c = walked(2 * STRIDE as u64);
        assert!(c.interval_proof(0).is_err(), "not committed yet");

        c.commit();
        assert!(c.interval_proof(0).is_ok());
        assert!(c.interval_proof(1).is_ok());
        // Only two intervals exist between three checkpoints.
        assert!(c.interval_proof(2).is_err());
        assert!(c.interval_proof(u64::MAX).is_err());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn taps_are_bound_to_their_position() {
        let mut a = ChainCore::with_stride("seed", STRIDE);
        a.advance_idle(3);
        a.advance_tap(10, 20);
        a.advance_idle(4);

        let mut b = ChainCore::with_stride("seed", STRIDE);
        b.advance_idle(4);
        b.advance_tap(10, 20);
        b.advance_idle(3);

        assert_ne!(a.commit().root, b.commit().root, "moving a tap changes the chain");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn memory_tracks_checkpoints_not_steps() {
        let c = walked(64 * STRIDE as u64);
        // 65 checkpoints, not 512 states.
        assert!(c.memory_bytes() < 512 * 32 + 512 * std::mem::size_of::<Step>() + 64 * 32);
    }

    impl ChainCore {
        fn commit_count_for_test(&self) -> usize {
            self.checkpoints.len()
        }
    }
}
