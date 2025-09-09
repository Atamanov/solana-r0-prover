use alloc::vec::Vec;
use blake3::Hasher;
use twine_solana_r0_prover_lib::ZkValidatorSetEntry;

/// Calculate the ESR merkle root from validator set entries
pub fn calculate_esr_merkle_root(validators: &[ZkValidatorSetEntry]) -> [u8; 32] {
    if validators.is_empty() {
        return [0u8; 32];
    }

    // Create leaf hashes for each validator
    let mut leaf_hashes: Vec<[u8; 32]> =
        validators.iter().map(|v| hash_validator_entry(v)).collect();

    // Build merkle tree from bottom up
    while leaf_hashes.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..leaf_hashes.len()).step_by(2) {
            if i + 1 < leaf_hashes.len() {
                // Hash pair of nodes
                let combined = hash_pair(&leaf_hashes[i], &leaf_hashes[i + 1]);
                next_level.push(combined);
            } else {
                // Odd node, carry forward
                next_level.push(leaf_hashes[i]);
            }
        }

        leaf_hashes = next_level;
    }

    leaf_hashes[0]
}

/// Verify a merkle proof for a validator
pub fn verify_vote_merkle_proof(
    vote_account: &[u8; 32],
    active_stake: u64,
    proof: &[[u8; 32]],
    merkle_root: &[u8; 32],
    mut leaf_index: usize,
) -> bool {
    // Leaf hash: Blake3(vote_account || count(1) || vote_account || stake || total_stake)
    let mut h = Hasher::new();
    h.update(vote_account);
    h.update(&(1u32).to_le_bytes());
    h.update(vote_account);
    h.update(&active_stake.to_le_bytes());
    h.update(&active_stake.to_le_bytes());
    let mut current = *h.finalize().as_bytes();

    for sib in proof {
        let mut hh = Hasher::new();
        if leaf_index % 2 == 0 {
            hh.update(&current);
            hh.update(sib);
        } else {
            hh.update(sib);
            hh.update(&current);
        }
        current = *hh.finalize().as_bytes();
        leaf_index /= 2;
    }
    current == *merkle_root
}

/// Hash a validator entry for merkle tree - using simplified ESR leaf structure
fn hash_validator_entry(validator: &ZkValidatorSetEntry) -> [u8; 32] {
    // Match the simplified ESR leaf hash used in database
    // Blake3(vote_account || count(1) || vote_account || stake || total_stake)
    let mut hasher = Hasher::new();
    hasher.update(&validator.validator_vote_account);
    hasher.update(&(1u32).to_le_bytes());
    hasher.update(&validator.validator_vote_account);
    hasher.update(&validator.active_stake.to_le_bytes());
    hasher.update(&validator.active_stake.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Hash two nodes together for merkle tree
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}
