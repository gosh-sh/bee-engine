use bee_shared::miner::leaf::ComputedLeaf;
use rs_merkle::Hasher;
use rs_merkle::MerkleTree;

#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        blake3::hash(data).into()
    }
}

#[derive(Clone)]
pub struct MerkleProcessor {
    tree: MerkleTree<Blake3Hasher>,
}

impl Default for MerkleProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleProcessor {
    pub fn new() -> MerkleProcessor {
        MerkleProcessor { tree: MerkleTree::new() }
    }

    pub fn add_leaf(&mut self, computed_leaf: &ComputedLeaf) {
        self.tree.insert(computed_leaf.merkle_hash());
    }

    pub fn get_merkle_root(&self) -> Vec<u8> {
        if let Some(root) = self.tree.root() {
            root.to_vec()
        } else {
            Vec::new()
        }
    }

    pub fn get_merkle_leaves(&self) -> Vec<Vec<u8>> {
        if let Some(leaves) = self.tree.leaves() {
            leaves.iter().map(|leaf| leaf.to_vec()).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_proof_in_window(
        &self,
        start_index: usize,
        end_index: usize,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
        let leaves = self.get_merkle_leaves();
        let total_leaves = leaves.len();

        if start_index >= end_index || end_index > total_leaves {
            return Err("invalid window range".to_string());
        }

        let indices_to_prove: Vec<usize> = (start_index..end_index).collect();
        let proof_bytes = self.tree.proof(&indices_to_prove).to_bytes();
        let selected_leaves = leaves[start_index..end_index].to_vec();

        Ok((proof_bytes, selected_leaves))
    }

    pub fn clear(&mut self) {
        self.tree = MerkleTree::new();
    }

    pub fn commit(&mut self) {
        self.tree.commit();
    }
}

#[cfg(test)]
mod tests {
    use bee_shared::miner::leaf::Leaf;
    use rs_merkle::MerkleProof;

    use super::*;

    fn create_computed_leaf(index: u128) -> ComputedLeaf {
        let leaf = Leaf {
            index,
            nonce: 1,
            seed: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            x: 0,
            y: 0,
            timestamp: 1765567702,
            complexity: 10,
        };
        leaf.compute()
    }

    #[test]
    fn empty_tree_has_empty_root_and_no_leaves() {
        let merkle = MerkleProcessor::new();
        assert!(merkle.get_merkle_root().is_empty());
        assert!(merkle.get_merkle_leaves().is_empty());
    }

    #[test]
    fn leaves_are_blake3_of_input_and_root_is_stable_after_commit() {
        let mut merkle = MerkleProcessor::new();
        merkle.add_leaf(&create_computed_leaf(0));
        merkle.add_leaf(&create_computed_leaf(1));

        merkle.commit();

        let leaves = merkle.get_merkle_leaves();
        assert_eq!(leaves.len(), 2);

        let root = merkle.get_merkle_root();
        assert!(!root.is_empty(), "root must not be empty after commit");
    }

    #[test]
    fn proof_verifies_for_window() {
        let mut m = MerkleProcessor::new();
        let total = 10usize;
        for i in 0..total {
            m.add_leaf(&create_computed_leaf(i as u128));
        }
        m.commit();

        let start_index = 4;
        let end_index = 6;
        let (proof_bytes, selected) = m.get_proof_in_window(start_index, end_index).unwrap();
        let proof = MerkleProof::<Blake3Hasher>::from_bytes(&proof_bytes).unwrap();

        let indices: Vec<usize> = (start_index..end_index).collect();
        let selected: Vec<[u8; 32]> = selected.into_iter().map(|h| h.try_into().unwrap()).collect();

        let root: [u8; 32] = m.get_merkle_root().try_into().unwrap();

        assert!(proof.verify(root, &indices, &selected, total));
    }

    #[test]
    fn clear_resets_tree_to_empty_state() {
        let mut merkle = MerkleProcessor::new();
        merkle.add_leaf(&create_computed_leaf(0));
        merkle.commit();
        assert!(!merkle.get_merkle_root().is_empty());

        merkle.clear();
        println!("{:?}", merkle.get_merkle_root());
        assert!(merkle.get_merkle_root().is_empty());
        assert!(merkle.get_merkle_leaves().is_empty());
    }

    #[test]
    fn order_of_leaves_affects_root() {
        let mut m1 = MerkleProcessor::new();
        m1.add_leaf(&create_computed_leaf(0));
        m1.add_leaf(&create_computed_leaf(1));
        m1.add_leaf(&create_computed_leaf(2));
        m1.commit();

        let mut m2 = MerkleProcessor::new();
        m2.add_leaf(&create_computed_leaf(2));
        m2.add_leaf(&create_computed_leaf(1));
        m2.add_leaf(&create_computed_leaf(0));
        m2.commit();

        let r1 = m1.get_merkle_root();
        let r2 = m2.get_merkle_root();
        assert_ne!(r1, r2, "different leaf order should produce different root");
    }
}
