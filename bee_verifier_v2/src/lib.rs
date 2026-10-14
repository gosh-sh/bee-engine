//! Sequential-chain proof verifier, run by `gosh.runwasm` inside a block.
//!
//! v1 (`bee_verifier`) stays as it is: its binary is already whitelisted on the
//! nodes and v1 miners keep calling it. This is a separate component with its
//! own hash, referenced by `Miner_V2`.
//!
//! The result layout is the one the miner contract already reads:
//!
//! ```text
//! byte 0    1 = the call itself succeeded, 0 = error (code follows)
//! byte 1    1 = every requested interval verified, 0 = it did not
//! bytes 2-5 u32 LE, work proven: the number of committed intervals
//! ```
//!
//! Byte 2-5 is *claimed* work. `Miner_V2` caps it by the blocks actually elapsed
//! since that miner's previous accepted session, so a proof has to be backed by
//! both the walk and the wall clock.

use bee_shared::miner::chain::ParamsOfVerifyChain;

use crate::bindings::exports::docs::bee_engine::verifier_interface::Guest as VerifierInterface;
use crate::error::LibError;
use crate::error::LibErrorCode;
use crate::verifier::check_submit;
use crate::verifier::verify_interval;

#[allow(warnings)]
mod bindings;

mod error;
mod verifier;

struct VerifierGuest {}

impl VerifierInterface for VerifierGuest {
    fn verify(req: Vec<u8>) -> Vec<u8> {
        let params = match ParamsOfVerifyChain::try_from(req) {
            Ok(value) => value,
            Err(e) => return LibError::new(LibErrorCode::DeserializeRequest, Some(e)).into(),
        };

        if let Err(e) = check_submit(&params.submit, params.stride) {
            return e.into();
        }

        // The reveal has to answer exactly the intervals that were asked for,
        // in the same order. Without this a miner could reply with whichever
        // interval it happens to have computed and ignore the challenge.
        if params.proof.intervals.len() != params.requested_intervals.len() {
            return LibError::new(
                LibErrorCode::IntervalMismatch,
                Some(format!(
                    "{} intervals requested, {} supplied",
                    params.requested_intervals.len(),
                    params.proof.intervals.len()
                )),
            )
            .into();
        }
        for (asked, given) in params.requested_intervals.iter().zip(params.proof.intervals.iter()) {
            if *asked != given.index {
                return LibError::new(
                    LibErrorCode::IntervalMismatch,
                    Some(format!("interval {asked} was requested, {} supplied", given.index)),
                )
                .into();
            }
        }
        // An empty challenge proves nothing, so treat it as a malformed request
        // rather than as a vacuously valid proof.
        if params.proof.intervals.is_empty() {
            return LibError::new(
                LibErrorCode::IntervalMismatch,
                Some("no intervals were requested".into()),
            )
            .into();
        }

        let mut all_valid = true;
        for interval in &params.proof.intervals {
            match verify_interval(interval, &params.submit, params.stride) {
                Ok(true) => {}
                Ok(false) => {
                    all_valid = false;
                    break;
                }
                Err(e) => return e.into(),
            }
        }

        // Work proven, in committed intervals. Saturating rather than wrapping:
        // a chain long enough to overflow a u32 of intervals is far past any
        // cap the contract applies anyway.
        let intervals_walked = params.submit.checkpoints_count.saturating_sub(1);
        let proven: u32 = intervals_walked.try_into().unwrap_or(u32::MAX);

        let mut result = vec![1];
        result.push(all_valid as u8);
        result.extend_from_slice(&proven.to_le_bytes());
        result
    }
}

bindings::export!(VerifierGuest with_types_in bindings);

#[cfg(test)]
mod tests {
    use bee_shared::miner::chain::genesis;
    use bee_shared::miner::chain::ChainProof;
    use bee_shared::miner::chain::ChainSubmit;
    use bee_shared::miner::chain::IntervalProof;
    use bee_shared::miner::chain::Step;
    use rs_merkle::Hasher;
    use rs_merkle::MerkleTree;

    use super::*;
    use crate::verifier::Blake3Hasher;

    const STRIDE: u32 = 4;

    fn session(intervals: usize) -> (ChainSubmit, Vec<IntervalProof>) {
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
        let proofs = (0..intervals)
            .map(|i| IntervalProof {
                index: i as u64,
                from: checkpoints[i].to_vec(),
                to: checkpoints[i + 1].to_vec(),
                proof: tree.proof(&[i, i + 1]).to_bytes(),
                steps: steps[i * STRIDE as usize..(i + 1) * STRIDE as usize].to_vec(),
            })
            .collect();
        (submit, proofs)
    }

    fn encode(requested: &[u64], submit: &ChainSubmit, proof: &ChainProof) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v.extend_from_slice(&STRIDE.to_be_bytes());
        v.extend_from_slice(&(requested.len() as u32).to_be_bytes());
        for i in requested {
            v.extend_from_slice(&i.to_be_bytes());
        }
        v.extend(borsh::to_vec(submit).unwrap());
        v.extend(borsh::to_vec(proof).unwrap());
        v
    }

    #[test]
    fn an_honest_session_is_accepted_and_reports_its_work() {
        let (submit, proofs) = session(6);
        let picked = vec![proofs[1].clone(), proofs[4].clone()];
        let bytes = encode(&[1, 4], &submit, &ChainProof { intervals: picked });

        let out = VerifierGuest::verify(bytes);
        assert_eq!(out[0], 1, "call succeeded");
        assert_eq!(out[1], 1, "proof valid");
        let proven = u32::from_le_bytes([out[2], out[3], out[4], out[5]]);
        assert_eq!(proven, 6, "six intervals were committed");
    }

    #[test]
    fn a_tampered_interval_is_rejected() {
        let (submit, proofs) = session(4);
        let mut bad = proofs[2].clone();
        bad.steps[0] = Step { x: 9, y: 9, nonce: 9 };
        let bytes = encode(&[2], &submit, &ChainProof { intervals: vec![bad] });

        let out = VerifierGuest::verify(bytes);
        assert_eq!(out[0], 1, "call still succeeds");
        assert_eq!(out[1], 0, "but the proof is not valid");
    }

    #[test]
    fn answering_a_different_interval_than_asked_is_refused() {
        let (submit, proofs) = session(4);
        // Interval 0 is genuinely valid, but 3 was the challenge.
        let bytes = encode(&[3], &submit, &ChainProof { intervals: vec![proofs[0].clone()] });

        let out = VerifierGuest::verify(bytes);
        assert_eq!(out[0], 0, "must be an error, not a pass");
    }

    #[test]
    fn a_short_reveal_is_refused() {
        let (submit, proofs) = session(4);
        let bytes = encode(&[0, 1], &submit, &ChainProof { intervals: vec![proofs[0].clone()] });
        assert_eq!(VerifierGuest::verify(bytes)[0], 0);
    }

    #[test]
    fn an_empty_challenge_is_refused() {
        let (submit, _) = session(4);
        let bytes = encode(&[], &submit, &ChainProof { intervals: vec![] });
        assert_eq!(VerifierGuest::verify(bytes)[0], 0, "nothing was proven");
    }

    #[test]
    fn garbage_input_does_not_panic() {
        for len in [0usize, 1, 39, 40, 64] {
            let out = VerifierGuest::verify(vec![0u8; len]);
            assert_eq!(out[0], 0, "len={len} must be a clean error");
        }
    }
}
