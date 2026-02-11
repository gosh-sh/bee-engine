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
        let mut hi16 = [0u8; 16];
        hi16.copy_from_slice(&self.hash[0..16]);
        u128::from_be_bytes(hi16)
    }
}
