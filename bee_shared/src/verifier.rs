use std::fmt::Debug;

use borsh::BorshDeserialize;
use borsh::BorshSerialize;

use crate::miner::SessionProof;
use crate::miner::SessionSubmit;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ParamsOfVerifySession {
    pub seed: String,
    pub easy_complexity: u32,
    pub easy_interval_start: u64,
    pub easy_interval_end: u64,
    pub hard_complexity: u32,
    pub hard_interval_start: u64,
    pub hard_interval_end: u64,
    pub easy_submit_params: SessionSubmit,
    pub hard_submit_params: SessionSubmit,
    pub easy_proof_params: SessionProof,
    pub hard_first_proof_params: SessionProof,
    pub hard_range_proof_params: SessionProof,
    pub hard_last_proof_params: SessionProof,
}

#[derive(Debug, BorshDeserialize)]
struct PartialVerifySession {
    easy_submit_params: SessionSubmit,
    hard_submit_params: SessionSubmit,
    easy_proof_params: SessionProof,
    hard_first_proof_params: SessionProof,
    hard_range_proof_params: SessionProof,
    hard_last_proof_params: SessionProof,
}

impl TryFrom<Vec<u8>> for ParamsOfVerifySession {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Seed
        let seed = {
            let slice = &bytes[0..32];
            hex::encode(slice)
        };

        // Easy complexity
        let easy_complexity = {
            let slice = &bytes[32..36];
            let sized: [u8; 4] =
                slice.try_into().map_err(|e| format!("Decode easy complexity ({e})"))?;
            u32::from_be_bytes(sized)
        };

        // Easy interval start
        let easy_interval_start = {
            let slice = &bytes[36..44];
            let sized: [u8; 8] =
                slice.try_into().map_err(|e| format!("Decode easy interval start ({e})"))?;
            u64::from_be_bytes(sized)
        };

        // Easy interval end
        let easy_interval_end = {
            let slice = &bytes[44..52];
            let sized: [u8; 8] =
                slice.try_into().map_err(|e| format!("Decode easy interval end ({e})"))?;
            u64::from_be_bytes(sized)
        };

        // Hard complexity
        let hard_complexity = {
            let slice = &bytes[52..56];
            let sized: [u8; 4] =
                slice.try_into().map_err(|e| format!("Decode hard complexity ({e})"))?;
            u32::from_be_bytes(sized)
        };

        // Hard interval start
        let hard_interval_start = {
            let slice = &bytes[56..64];
            let sized: [u8; 8] =
                slice.try_into().map_err(|e| format!("Decode hard interval start ({e})"))?;
            u64::from_be_bytes(sized)
        };

        // Hard interval end
        let hard_interval_end = {
            let slice = &bytes[64..72];
            let sized: [u8; 8] =
                slice.try_into().map_err(|e| format!("Decode hard interval end ({e})"))?;
            u64::from_be_bytes(sized)
        };

        // Rest bytes decode with borsh
        let bytes_rest = &bytes[72..];
        let rest = borsh::from_slice::<PartialVerifySession>(bytes_rest)
            .map_err(|e| format!("Decode rest bytes ({e})"))?;

        Ok(ParamsOfVerifySession {
            seed: format!("0x{seed}"),
            easy_complexity,
            easy_interval_start,
            easy_interval_end,
            hard_complexity,
            hard_interval_start,
            hard_interval_end,
            easy_submit_params: rest.easy_submit_params,
            hard_submit_params: rest.hard_submit_params,
            easy_proof_params: rest.easy_proof_params,
            hard_first_proof_params: rest.hard_first_proof_params,
            hard_range_proof_params: rest.hard_range_proof_params,
            hard_last_proof_params: rest.hard_last_proof_params,
        })
    }
}

pub fn combine_bytes(args: &[&(impl BorshSerialize + Debug)]) -> Result<Vec<u8>, String> {
    let mut combined = Vec::new();
    for arg in args {
        let bytes =
            borsh::to_vec(&arg).map_err(|e| format!("Serialize `{arg:?}` to bytes ({e})"))?;
        combined.extend(bytes);
    }

    Ok(combined)
}
