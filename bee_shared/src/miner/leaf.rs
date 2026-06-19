use borsh::BorshDeserialize;
use borsh::BorshSerialize;

#[derive(Debug, Clone)]
pub struct Leaf {
    pub index: u128,
    pub nonce: u64,
    pub seed: String,
    pub x: u32,
    pub y: u32,
    pub timestamp: u64,
    pub complexity: u32,
}

impl From<ComputedLeaf> for Leaf {
    fn from(value: ComputedLeaf) -> Self {
        Self {
            index: value.index,
            nonce: value.nonce,
            seed: value.seed,
            x: value.x,
            y: value.y,
            timestamp: value.timestamp,
            complexity: value.complexity,
        }
    }
}

impl Leaf {
    pub fn compute(&self) -> ComputedLeaf {
        let hash = {
            let mut hasher = blake3::Hasher::new();

            hasher.update(self.x.to_be_bytes().as_ref());
            hasher.update(self.y.to_be_bytes().as_ref());
            hasher.update(self.timestamp.to_be_bytes().as_ref());
            hasher.update(self.complexity.to_be_bytes().as_ref());
            hasher.update(self.seed.as_bytes());
            hasher.update(self.index.to_be_bytes().as_ref());
            hasher.update(self.nonce.to_be_bytes().as_ref());

            hasher.finalize()
        };

        ComputedLeaf {
            index: self.index,
            nonce: self.nonce,
            seed: self.seed.clone(),
            x: self.x,
            y: self.y,
            timestamp: self.timestamp,
            complexity: self.complexity,
            hash: hash.as_bytes().to_vec(),
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ComputedLeaf {
    pub index: u128,
    pub nonce: u64,
    pub seed: String,
    pub x: u32,
    pub y: u32,
    pub timestamp: u64,
    pub complexity: u32,
    pub hash: Vec<u8>,
}

impl ComputedLeaf {
    pub fn merkle_hash(&self) -> [u8; 32] {
        let data = format!(
            "index:{},nonce:{},seed:{},x:{},y:{},timestamp:{},complexity:{},hash:{}",
            self.index,
            self.nonce,
            self.seed,
            self.x,
            self.y,
            self.timestamp,
            self.complexity,
            hex::encode(self.hash.clone()),
        );

        let hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(data.as_bytes());
            hasher.finalize()
        };

        let mut h = [0u8; 32];
        h.copy_from_slice(hash.as_bytes());
        h
    }

    pub fn verify(&self, seed: impl AsRef<str>, complexity: u32) -> bool {
        if self.seed != seed.as_ref() || self.complexity != complexity {
            return false;
        }
        // A threshold for complexity >= 128 would shift u128 past its width
        // (panic in debug, masked-shift in release). No hash can satisfy such
        // a constraint, so reject up front.
        if self.complexity >= 128 {
            return false;
        }

        let hash_valid = {
            let leaf = Leaf::from(self.clone());
            let computed = leaf.compute();
            self.hash == computed.hash
        };

        let num_valid = {
            let threshold = u128::MAX >> self.complexity;
            self.hash_num() < threshold
        };

        hash_valid && num_valid
    }

    pub fn hash_num(&self) -> u128 {
        if self.hash.len() < 16 {
            // Malformed hash cannot satisfy any difficulty threshold; return the
            // sentinel that compares strictly above every valid threshold.
            return u128::MAX;
        }
        let mut hi16 = [0u8; 16];
        hi16.copy_from_slice(&self.hash[0..16]);
        u128::from_be_bytes(hi16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_with(complexity: u32, hash: Vec<u8>) -> ComputedLeaf {
        ComputedLeaf {
            index: 0,
            nonce: 0,
            seed: "seed".to_string(),
            x: 0,
            y: 0,
            timestamp: 0,
            complexity,
            hash,
        }
    }

    #[test]
    fn verify_rejects_complexity_at_or_above_128_without_panic() {
        // A complexity that would shift past u128 width must not panic.
        for c in [128u32, 129, 200, u32::MAX] {
            let leaf = leaf_with(c, vec![0u8; 32]);
            assert!(!leaf.verify("seed", c), "complexity={c} must be rejected");
        }
    }

    #[test]
    fn hash_num_safe_on_short_hash() {
        // Short hash must not panic and must not satisfy any real threshold.
        let leaf = leaf_with(10, vec![0u8; 5]);
        assert_eq!(leaf.hash_num(), u128::MAX);
        assert!(!leaf.verify("seed", 10));
    }

    #[test]
    fn hash_num_reads_first_16_bytes_big_endian() {
        let mut hash = vec![0u8; 32];
        hash[0] = 0x01;
        hash[15] = 0xFF;
        let leaf = leaf_with(10, hash);
        assert_eq!(leaf.hash_num(), (1u128 << 120) | 0xFF);
    }
}
