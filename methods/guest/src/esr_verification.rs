use alloc::vec::Vec;
use blake3::Hasher;
use twine_solana_r0_prover_lib::ZkValidatorSetEntry;

/// Calculate the ESR merkle root from validator set entries
pub fn calculate_esr_merkle_root(validators: &[ZkValidatorSetEntry]) -> [u8; 32] {
    if validators.is_empty() {
        return [0u8; 32];
    }

    // Sort validators by vote account for deterministic ordering (CRITICAL: must match SP1)
    let mut sorted_validators = validators.to_vec();
    sorted_validators.sort_by(|a, b| a.validator_vote_account.cmp(&b.validator_vote_account));

    // Create leaf hashes for each validator
    let mut leaf_hashes: Vec<[u8; 32]> = sorted_validators
        .iter()
        .map(|v| hash_validator_entry(v))
        .collect();

    // Build merkle tree from bottom up
    while leaf_hashes.len() > 1 {
        let mut next_level = Vec::new();

        for pair in leaf_hashes.chunks(2) {
            let mut hasher = Hasher::new();
            hasher.update(&pair[0]);
            if pair.len() > 1 {
                hasher.update(&pair[1]);
            } else {
                // Odd number of nodes - hash with itself (CRITICAL: must match SP1)
                // This duplication (hashing pair[0] + pair[0]) is required for compatibility with SP1's Merkle tree implementation,
                // which expects the last node to be concatenated with itself before hashing when the number of nodes is odd.
                // See SP1 documentation/specification for details.
                hasher.update(&pair[0]);
            }
            next_level.push(*hasher.finalize().as_bytes());
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
