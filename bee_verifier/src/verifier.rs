use bee_shared::miner::leaf::ComputedLeaf;
use borsh::BorshDeserialize;
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

#[derive(Debug, BorshDeserialize)]
pub(crate) struct ParamsOfValidateProof {
    pub root: Vec<u8>,
    pub proof: Vec<u8>,
    pub leaves_count: usize,
    pub leaves_chunk: Vec<Vec<u8>>,
    pub leaves_indices: Vec<usize>,
}

pub(crate) fn validate_proof(req: ParamsOfValidateProof) -> Result<bool, LibError> {
    if req.proof.is_empty() {
        if req.leaves_chunk.len() == 1 {
            return Ok(req.leaves_chunk[0] == req.root);
        } else {
            return Ok(false);
        }
    }

    let proof = MerkleProof::<Blake3Hasher>::from_bytes(&req.proof).map_err(|e| {
        LibError::new(LibErrorCode::BuildMerkleProof, Some(format!("Proof build failure ({e})")))
    })?;

    let root: [u8; 32] = req.root.as_slice().try_into().map_err(|e| {
        LibError::new(LibErrorCode::CheckRoot, Some(format!("Root bytes to slice ({e})")))
    })?;

    let leaves = req
        .leaves_chunk
        .iter()
        .enumerate()
        .map(|(i, leaf)| {
            leaf.as_slice().try_into().map_err(|e| {
                LibError::new(
                    LibErrorCode::CheckLeaf,
                    Some(format!("Leaf `{i}` bytes to slice ({e})")),
                )
            })
        })
        .collect::<Result<Vec<[u8; 32]>, LibError>>()?;

    let is_proof_valid = proof.verify(root, &req.leaves_indices, &leaves, req.leaves_count);

    Ok(is_proof_valid)
}

pub(crate) struct ParamsOfValidateLeaves {
    pub seed: String,
    pub complexity: u32,
    pub leaves: Vec<ComputedLeaf>,
}

pub fn validate_leaves(params: ParamsOfValidateLeaves) -> bool {
    !params.leaves.is_empty()
        && params
            .leaves
            .iter()
            .all(|computed_leaf| computed_leaf.verify(&params.seed, params.complexity))
}
