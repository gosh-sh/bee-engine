//! Checking a sequential-chain proof.
//!
//! Cost is `intervals * stride` hash steps plus two merkle paths each — it does
//! not grow with the length of the chain. That is the property the whole scheme
//! rests on: the miner's work can be raised arbitrarily without the verifier,
//! which runs inside a block via `gosh.runwasm`, paying for it.

use bee_shared::miner::chain::ChainSubmit;
use bee_shared::miner::chain::IntervalProof;
use rs_merkle::Hasher;
use rs_merkle::MerkleProof;

use crate::error::LibError;
use crate::error::LibErrorCode;

#[derive(Clone)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        blake3::hash(data).into()
    }
}

/// Reject a submission that could not describe a real chain, before any of it
/// is used to size loops or index proofs.
pub(crate) fn check_submit(submit: &ChainSubmit, stride: u32) -> Result<(), LibError> {
    if stride == 0 {
        return Err(LibError::new(LibErrorCode::BadSubmit, Some("stride is zero".into())));
    }
    if submit.stride != stride {
        return Err(LibError::new(
            LibErrorCode::BadSubmit,
            Some(format!("stride mismatch: header {stride}, submit {}", submit.stride)),
        ));
    }
    // One checkpoint is just the genesis state: no interval exists, so there is
    // nothing that could be spot-checked and nothing was proven.
    if submit.checkpoints_count < 2 {
        return Err(LibError::new(
            LibErrorCode::BadSubmit,
            Some(format!("{} checkpoints leave no interval", submit.checkpoints_count)),
        ));
    }
    if submit.root.len() != 32 {
        return Err(LibError::new(
            LibErrorCode::CheckRoot,
            Some(format!("root is {} bytes", submit.root.len())),
        ));
    }
    Ok(())
}

/// Verify one interval: the endpoints are the committed checkpoints `index` and
/// `index + 1`, and replaying the steps from the first lands exactly on the
/// second.
///
/// Both halves matter. The merkle proof alone would let a miner open any pair of
/// checkpoints it likes; the replay alone would let it invent endpoints. Only
/// together do they say "this stretch of the committed chain was really walked".
pub(crate) fn verify_interval(
    interval: &IntervalProof,
    submit: &ChainSubmit,
    stride: u32,
) -> Result<bool, LibError> {
    if interval.steps.len() != stride as usize {
        return Err(LibError::new(
            LibErrorCode::BadStrideLength,
            Some(format!("interval {} carries {} steps", interval.index, interval.steps.len())),
        ));
    }

    let from: [u8; 32] = interval.from.as_slice().try_into().map_err(|_| {
        LibError::new(
            LibErrorCode::CheckCheckpoint,
            Some(format!("interval {} `from` is {} bytes", interval.index, interval.from.len())),
        )
    })?;
    let to: [u8; 32] = interval.to.as_slice().try_into().map_err(|_| {
        LibError::new(
            LibErrorCode::CheckCheckpoint,
            Some(format!("interval {} `to` is {} bytes", interval.index, interval.to.len())),
        )
    })?;

    let index = usize::try_from(interval.index).map_err(|_| {
        LibError::new(
            LibErrorCode::CheckCheckpoint,
            Some(format!("interval {} is out of range", interval.index)),
        )
    })?;
    let next = index.checked_add(1).ok_or_else(|| {
        LibError::new(
            LibErrorCode::CheckCheckpoint,
            Some(format!("interval {} is out of range", interval.index)),
        )
    })?;
    let count = usize::try_from(submit.checkpoints_count).map_err(|_| {
        LibError::new(LibErrorCode::BadSubmit, Some("checkpoint count is out of range".into()))
    })?;
    if next >= count {
        return Ok(false);
    }

    // Endpoints belong to the committed tree.
    let root: [u8; 32] = submit.root.as_slice().try_into().map_err(|_| {
        LibError::new(LibErrorCode::CheckRoot, Some("root is not 32 bytes".into()))
    })?;
    let proof = MerkleProof::<Blake3Hasher>::from_bytes(&interval.proof).map_err(|e| {
        LibError::new(LibErrorCode::BuildMerkleProof, Some(format!("Proof build failure ({e})")))
    })?;
    let leaves = [Blake3Hasher::hash(&from), Blake3Hasher::hash(&to)];
    if !proof.verify(root, &[index, next], &leaves, count) {
        return Ok(false);
    }

    // ...and the walk between them was actually performed.
    let mut head = from;
    for step in &interval.steps {
        head = step.apply(&head);
    }
    Ok(head == to)
}

#[cfg(test)]
mod tests {
    use bee_shared::miner::chain::genesis;
    use bee_shared::miner::chain::ChainSubmit;
    use bee_shared::miner::chain::IntervalProof;
    use bee_shared::miner::chain::Step;
    use rs_merkle::MerkleTree;

    use super::*;

    const STRIDE: u32 = 4;

    /// Walk a chain and commit it, the way the miner does.
    struct Built {
        submit: ChainSubmit,
        checkpoints: Vec<[u8; 32]>,
        steps: Vec<Step>,
        tree: MerkleTree<Blake3Hasher>,
    }

    fn build(intervals: usize) -> Built {
        let mut head = genesis("seed");
        let mut checkpoints = vec![head];
        let mut steps = Vec::new();
        for i in 0..(intervals * STRIDE as usize) {
            let s = Step::idle(i as u64);
            head = s.apply(&head);
            steps.push(s);
            if steps.len() % STRIDE as usize == 0 {
                checkpoints.push(head);
            }
        }
        let mut tree = MerkleTree::<Blake3Hasher>::new();
        for cp in &checkpoints {
            tree.insert(Blake3Hasher::hash(cp));
        }
        tree.commit();
        let submit = ChainSubmit {
            root: tree.root().unwrap().to_vec(),
            checkpoints_count: checkpoints.len() as u64,
            stride: STRIDE,
        };
        Built { submit, checkpoints, steps, tree }
    }

    fn interval_at(b: &Built, index: usize) -> IntervalProof {
        let start = index * STRIDE as usize;
        IntervalProof {
            index: index as u64,
            from: b.checkpoints[index].to_vec(),
            to: b.checkpoints[index + 1].to_vec(),
            proof: b.tree.proof(&[index, index + 1]).to_bytes(),
            steps: b.steps[start..start + STRIDE as usize].to_vec(),
        }
    }

    #[test]
    fn an_honest_interval_verifies() {
        let b = build(4);
        for i in 0..4 {
            assert!(
                verify_interval(&interval_at(&b, i), &b.submit, STRIDE).unwrap(),
                "interval {i} must verify"
            );
        }
    }

    #[test]
    fn tampering_with_a_step_is_caught() {
        let b = build(3);
        let mut iv = interval_at(&b, 1);
        iv.steps[2] = Step { x: 1, y: 1, nonce: 999 };
        assert!(!verify_interval(&iv, &b.submit, STRIDE).unwrap(), "replay must not reach `to`");
    }

    #[test]
    fn endpoints_outside_the_tree_are_caught() {
        let b = build(3);
        let mut iv = interval_at(&b, 1);
        // A self-consistent walk that was never committed.
        let mut head = [42u8; 32];
        iv.from = head.to_vec();
        for s in &iv.steps {
            head = s.apply(&head);
        }
        iv.to = head.to_vec();
        assert!(!verify_interval(&iv, &b.submit, STRIDE).unwrap(), "merkle proof must fail");
    }

    #[test]
    fn a_short_interval_is_rejected() {
        let b = build(2);
        let mut iv = interval_at(&b, 0);
        iv.steps.pop();
        let err = verify_interval(&iv, &b.submit, STRIDE).unwrap_err();
        assert!(matches!(err_code(&err), LibErrorCode::BadStrideLength));
    }

    #[test]
    fn an_out_of_range_interval_is_rejected_without_panic() {
        let b = build(2);
        let mut iv = interval_at(&b, 0);
        iv.index = u64::MAX;
        // Either a clean error or a plain false, but never a panic.
        let _ = verify_interval(&iv, &b.submit, STRIDE);

        iv.index = b.submit.checkpoints_count;
        assert!(!verify_interval(&iv, &b.submit, STRIDE).unwrap_or(false));
    }

    #[test]
    fn malformed_endpoints_are_rejected() {
        let b = build(2);
        for mangle in [0, 1] {
            let mut iv = interval_at(&b, 0);
            if mangle == 0 {
                iv.from = vec![0u8; 31];
            } else {
                iv.to = vec![0u8; 33];
            }
            assert!(verify_interval(&iv, &b.submit, STRIDE).is_err());
        }
    }

    #[test]
    fn submissions_that_prove_nothing_are_rejected() {
        let b = build(2);

        let mut s = b.submit.clone();
        s.checkpoints_count = 1;
        assert!(check_submit(&s, STRIDE).is_err(), "a lone genesis proves nothing");

        let mut s = b.submit.clone();
        s.stride = STRIDE + 1;
        assert!(check_submit(&s, STRIDE).is_err(), "stride must match the header");

        assert!(check_submit(&b.submit, 0).is_err(), "zero stride");

        let mut s = b.submit.clone();
        s.root = vec![0u8; 31];
        assert!(check_submit(&s, STRIDE).is_err(), "short root");

        assert!(check_submit(&b.submit, STRIDE).is_ok());
    }

    fn err_code(e: &LibError) -> LibErrorCode {
        // `LibError` keeps its fields private; round-tripping through the wire
        // form is enough to read the code back out.
        let bytes: Vec<u8> = e.clone().into();
        let raw = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        match raw {
            401 => LibErrorCode::BadStrideLength,
            402 => LibErrorCode::BadSubmit,
            400 => LibErrorCode::IntervalMismatch,
            302 => LibErrorCode::CheckCheckpoint,
            301 => LibErrorCode::BuildMerkleProof,
            200 => LibErrorCode::CheckRoot,
            _ => LibErrorCode::DeserializeRequest,
        }
    }
}
