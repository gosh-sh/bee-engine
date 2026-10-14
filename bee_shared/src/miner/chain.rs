//! Sequential-chain proof: types shared by the miner and the verifier.
//!
//! In the v1 scheme every leaf is independent, so the work parallelises, a farm
//! amortises one CPU across every account it owns, and the claimed duration is
//! whatever the miner writes into the leaf. Here step `i` consumes the state of
//! step `i-1`:
//!
//! ```text
//! h_0     = H(seed)
//! h_{i+1} = H(h_i ‖ x_i ‖ y_i ‖ nonce_i)
//! ```
//!
//! The chain cannot be parallelised, so producing it costs wall-clock time that
//! no amount of hardware removes — only clock speed helps, and that is worth
//! well under 2x.
//!
//! Keeping every intermediate state would cost gigabytes at the lengths we care
//! about, so the miner keeps one state per [`Chain::stride`] steps — a
//! *checkpoint* — and commits those as merkle leaves. The spot-check window is
//! exactly one checkpoint interval: the verifier replays `stride` steps from
//! checkpoint `k` and must land on checkpoint `k+1`, with both endpoints proven
//! against the committed root. Verification therefore costs `stride` hashes plus
//! two merkle paths **regardless of how long the chain is**, which is what lets
//! the build cost be raised without touching the verifier.

use borsh::BorshDeserialize;
use borsh::BorshSerialize;

/// Number of steps between committed checkpoints, and hence the size of a
/// spot-checked interval. Chosen so that verifying two intervals costs about
/// what the v1 verifier already costs; see the measurements in
/// acki-nacki#2591.
pub const DEFAULT_STRIDE: u32 = 256;

/// Number of independent intervals the contract asks for. A miner that computed
/// only a fraction `f` of the chain passes only if *every* checked interval
/// falls inside the part it did compute, so the odds are `f^INTERVALS`.
pub const DEFAULT_INTERVALS: usize = 2;

/// One link of the chain.
///
/// `x`/`y` carry the user's tap (both zero when the step is time-driven rather
/// than tap-driven), which anchors a tap to a position in the chain: it cannot
/// be backdated or moved without redoing every step after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Step {
    pub x: u32,
    pub y: u32,
    pub nonce: u64,
}

impl Step {
    /// Time-driven step: no tap behind it.
    pub fn idle(nonce: u64) -> Self {
        Self { x: 0, y: 0, nonce }
    }

    /// Apply the step to a chain state.
    #[inline(always)]
    pub fn apply(&self, prev: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev);
        hasher.update(&self.x.to_be_bytes());
        hasher.update(&self.y.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Starting state of a chain, derived from the seed the contract handed out.
pub fn genesis(seed: &str) -> [u8; 32] {
    blake3::hash(seed.as_bytes()).into()
}

/// What the miner commits before learning which intervals will be checked.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ChainSubmit {
    /// Merkle root over the checkpoints.
    pub root: Vec<u8>,
    /// Number of committed checkpoints, i.e. `steps / stride + 1`.
    pub checkpoints_count: u64,
    /// Steps between checkpoints.
    pub stride: u32,
}

impl ChainSubmit {
    /// Total steps the submission claims to have walked.
    pub fn steps(&self) -> u64 {
        self.checkpoints_count.saturating_sub(1) * self.stride as u64
    }
}

/// One spot-checked interval: checkpoint `index` and the steps that lead from it
/// to checkpoint `index + 1`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IntervalProof {
    /// Index of the opening checkpoint.
    pub index: u64,
    /// State at `index` and at `index + 1`.
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    /// Merkle proof covering both endpoints against the committed root.
    pub proof: Vec<u8>,
    /// The steps to replay. Must contain exactly `stride` entries.
    pub steps: Vec<Step>,
}

/// The reveal: the intervals the contract asked for.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ChainProof {
    pub intervals: Vec<IntervalProof>,
}


/// Everything `verify` receives, as the contract lays it out.
///
/// The header is fixed-width so the contract can build it with plain byte
/// appends, exactly as the v1 scheme does; the variable-length part is borsh.
///
/// ```text
///  0..32   seed (raw bytes; the contract holds it as uint256)
/// 32..36   stride            (u32, big endian)
/// 36..40   interval count    (u32, big endian)
/// 40..40+8n  interval indices (u64 each, big endian)
/// then     borsh(ChainSubmit), borsh(ChainProof)
/// ```
#[derive(Debug)]
pub struct ParamsOfVerifyChain {
    pub seed: String,
    pub stride: u32,
    pub requested_intervals: Vec<u64>,
    pub submit: ChainSubmit,
    pub proof: ChainProof,
}

/// Fixed part of the header, before the interval indices.
const CHAIN_HEADER_LEN: usize = 40;

impl TryFrom<Vec<u8>> for ParamsOfVerifyChain {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() < CHAIN_HEADER_LEN {
            return Err(format!(
                "Input too short: expected at least {CHAIN_HEADER_LEN} bytes, got {}",
                bytes.len()
            ));
        }

        let seed = format!("0x{}", hex::encode(&bytes[0..32]));
        let stride = u32::from_be_bytes(
            bytes[32..36].try_into().map_err(|e| format!("Decode stride ({e})"))?,
        );
        let count = u32::from_be_bytes(
            bytes[36..40].try_into().map_err(|e| format!("Decode interval count ({e})"))?,
        ) as usize;

        // Reject a count the body cannot back before allocating for it.
        let indices_end = CHAIN_HEADER_LEN
            .checked_add(count.checked_mul(8).ok_or("Interval count overflows")?)
            .ok_or("Interval count overflows")?;
        if bytes.len() < indices_end {
            return Err(format!(
                "Input too short for {count} intervals: need {indices_end} bytes, got {}",
                bytes.len()
            ));
        }

        let mut requested_intervals = Vec::with_capacity(count);
        for i in 0..count {
            let at = CHAIN_HEADER_LEN + i * 8;
            requested_intervals.push(u64::from_be_bytes(
                bytes[at..at + 8].try_into().map_err(|e| format!("Decode interval {i} ({e})"))?,
            ));
        }

        let mut rest = &bytes[indices_end..];
        let submit = ChainSubmit::deserialize(&mut rest)
            .map_err(|e| format!("Decode chain submit ({e})"))?;
        let proof =
            ChainProof::deserialize(&mut rest).map_err(|e| format!("Decode chain proof ({e})"))?;

        Ok(ParamsOfVerifyChain { seed, stride, requested_intervals, submit, proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_step_depends_on_the_previous_state() {
        let a = genesis("seed");
        let s = Step::idle(0);
        let once = s.apply(&a);
        let twice = s.apply(&once);
        assert_ne!(once, a, "a step must move the state");
        assert_ne!(twice, once, "the same step from a different state differs");
    }

    #[test]
    fn taps_change_the_chain() {
        let a = genesis("seed");
        let idle = Step::idle(7).apply(&a);
        let tap = Step { x: 100, y: 200, nonce: 7 }.apply(&a);
        assert_ne!(idle, tap, "tap coordinates must be bound into the chain");
    }

    #[test]
    fn genesis_follows_the_seed() {
        assert_ne!(genesis("a"), genesis("b"));
        assert_eq!(genesis("a"), genesis("a"));
    }

    #[test]
    fn submit_reports_the_steps_it_covers() {
        let s = ChainSubmit { root: vec![], checkpoints_count: 5, stride: 256 };
        assert_eq!(s.steps(), 4 * 256);

        // A submission with no interval at all must not underflow.
        let empty = ChainSubmit { root: vec![], checkpoints_count: 0, stride: 256 };
        assert_eq!(empty.steps(), 0);
    }

    fn encode(seed: &[u8; 32], stride: u32, intervals: &[u64], submit: &ChainSubmit, proof: &ChainProof) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(seed);
        v.extend_from_slice(&stride.to_be_bytes());
        v.extend_from_slice(&(intervals.len() as u32).to_be_bytes());
        for i in intervals {
            v.extend_from_slice(&i.to_be_bytes());
        }
        v.extend(borsh::to_vec(submit).unwrap());
        v.extend(borsh::to_vec(proof).unwrap());
        v
    }

    #[test]
    fn params_round_trip() {
        let submit = ChainSubmit { root: vec![7u8; 32], checkpoints_count: 9, stride: 256 };
        let proof = ChainProof {
            intervals: vec![IntervalProof {
                index: 3,
                from: vec![1u8; 32],
                to: vec![2u8; 32],
                proof: vec![3u8; 64],
                steps: vec![Step::idle(0), Step { x: 5, y: 6, nonce: 1 }],
            }],
        };
        let bytes = encode(&[9u8; 32], 256, &[3, 5], &submit, &proof);

        let p = ParamsOfVerifyChain::try_from(bytes).expect("must parse");
        assert_eq!(p.stride, 256);
        assert_eq!(p.requested_intervals, vec![3, 5]);
        assert_eq!(p.submit.checkpoints_count, 9);
        assert_eq!(p.proof.intervals.len(), 1);
        assert_eq!(p.proof.intervals[0].steps.len(), 2);
        assert!(p.seed.starts_with("0x"));
    }

    #[test]
    fn params_reject_short_input_without_panic() {
        for len in [0usize, 1, 31, 32, 39] {
            assert!(
                ParamsOfVerifyChain::try_from(vec![0u8; len]).is_err(),
                "len={len} must be rejected"
            );
        }
    }

    #[test]
    fn params_reject_an_interval_count_the_body_cannot_back() {
        // Header claims a huge number of intervals; the body has none of them.
        let mut v = vec![0u8; 32];
        v.extend_from_slice(&256u32.to_be_bytes());
        v.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = ParamsOfVerifyChain::try_from(v).unwrap_err();
        assert!(err.contains("Input too short"), "got: {err}");
    }

    #[test]
    fn params_reject_a_truncated_body() {
        let submit = ChainSubmit { root: vec![0u8; 32], checkpoints_count: 2, stride: 8 };
        let proof = ChainProof { intervals: vec![] };
        let mut bytes = encode(&[0u8; 32], 8, &[0], &submit, &proof);
        bytes.truncate(bytes.len() - 1);
        assert!(ParamsOfVerifyChain::try_from(bytes).is_err());
    }
}
