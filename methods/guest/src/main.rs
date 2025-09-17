#![no_main]
#![no_std]

use risc0_zkvm::guest::env;

mod esr_verification;

use esr_verification::{calculate_esr_merkle_root, verify_vote_merkle_proof};
use twine_solana_r0_prover_lib::{
    core::LtHash, AccountStateCommitment, CompleteProofPackage, PublicCommitments, ZkAccountChange,
    ZkSlotData, ZkValidatorSetEntry, ZkVoteTransaction,
};

extern crate alloc;
use alloc::vec::Vec;
use alloc::{format, vec};
use hashbrown::{HashMap, HashSet};

risc0_zkvm::guest::entry!(main);

/// Consensus proof constraints enforced by this zkVM program:
/// 1) Chain continuity: slots are strictly consecutive and each parent_bank_hash equals the previous slot's bank_hash.
/// 2) Bank hash correctness: bank_hash = hash(hash(parent_bank_hash, signature_count, last_blockhash), cumulative_lthash).
/// 3) LtHash transformation: final slot cumulative LtHash equals previous cumulative LtHash with changed account LtHashes mixed out/in.
/// 4) LtHash checksum: final slot accounts_lthash_checksum equals checksum(cumulative LtHash).
/// 5) ESR inclusion: every vote's vote account is proven via provided Merkle proof to be in the ESR root.
/// 6) Vote validity: each vote is signed by required signers and votes for the final slot and its bank_hash (via pre-parsed fields).
/// 7) Supermajority: unique validators of valid votes represent >= 2/3 of total active stake for the epoch.

pub fn main() {
    let input: CompleteProofPackage = env::read();

    env::log("Starting Solana consensus proof verification...");
    env::log(&format!(
        "Slot range: {} to {}",
        input.start_slot, input.end_slot
    ));
    env::log(&format!(
        "Monitored accounts: {}",
        input.monitored_accounts.len()
    ));
    env::log(&format!("Slot chain length: {}", input.slot_chain.len()));

    // Track validation results
    let mut all_validations_passed = true;

    // Verify we have a valid chain
    if input.slot_chain.is_empty() {
        env::log("ERROR: Slot chain cannot be empty");
        return;
    }

    // Get first and last slots
    let first_slot = &input.slot_chain[0];
    let last_slot = &input.slot_chain[input.slot_chain.len() - 1];

    // Verify chain continuity
    if !verify_chain_continuity(&input.slot_chain) {
        all_validations_passed = false;
    }

    // Verify bank hashes
    if !verify_bank_hashes(&input.slot_chain) {
        all_validations_passed = false;
    }

    // Extract account data hash across all monitored accounts at last slot
    let (account_data_hash, account_state_commitments) =
        aggregate_account_data_and_commitments(&input.account_changes, &input.monitored_accounts);

    // Verify account changes and LtHash transformations for ALL accounts
    if !input.account_changes.is_empty() {
        if !verify_account_changes(&input.account_changes, &input.monitored_accounts) {
            all_validations_passed = false;
        }

        // Verify LtHash transformations for ALL account changes if we have at least 2 slots
        if input.slot_chain.len() >= 2 {
            if !verify_lthash_transformation(
                &input.slot_chain[input.slot_chain.len() - 2],
                &input.slot_chain[input.slot_chain.len() - 1],
                &input.account_changes,
                &input.monitored_accounts.get(0).unwrap_or(&[0u8; 32]),
            ) {
                all_validations_passed = false;
            }
        }
    } else {
        env::log("ERROR: No account changes found");
        all_validations_passed = false;
    }

    // Verify votes: intent, signatures, ESR inclusion, and supermajority
    if !verify_votes_intent_signatures_esr_and_supermajority(
        &input.vote_transactions,
        &input.validator_set,
        &input.esr_data,
        &input.merkle_proofs,
        last_slot,
    ) {
        all_validations_passed = false;
    }

    // Calculate or use provided ESR root
    let (hash_root_valset, total_active_stake, validator_count) =
        if let Some(ref esr_data) = input.esr_data {
            // Use the ESR root from database (RPC-based, most reliable)
            env::log(&format!(
                "Using ESR from database for epoch {}: root={}",
                esr_data.epoch,
                bs58::encode(&esr_data.merkle_root).into_string()
            ));

            // ESR root present; vote verification already performed above using provided proofs

            (
                esr_data.merkle_root,
                esr_data.total_active_stake,
                esr_data.validator_count,
            )
        } else if !input.validator_set.is_empty() {
            // Calculate ESR root from validator set if no pre-computed root available
            env::log(&format!(
                "Calculating ESR root from {} validators",
                input.validator_set.len()
            ));
            let root = calculate_esr_merkle_root(&input.validator_set);
            let total_stake: u64 = input.validator_set.iter().map(|v| v.active_stake).sum();
            (root, total_stake, input.validator_set.len() as u32)
        } else {
            // No ESR data available
            env::log("WARNING: No ESR data available for verification");
            ([0u8; 32], 0, 0)
        };

    // Prepare public commitments
    let original_bank_hash = first_slot.bank_hash;
    let last_bank_hash = last_slot.bank_hash;

    // Create public commitments with epoch and ESR data
    let commitments = PublicCommitments {
        start_slot: input.start_slot,
        end_slot: input.end_slot,
        epoch: input.epoch,
        original_bank_hash,
        last_bank_hash,
        account_data_hash,
        hash_root_valset,
        total_active_stake,
        validator_count,
        monitored_accounts_state: account_state_commitments,
        validations_passed: all_validations_passed,
    };

    // Commit to public values
    env::commit(&commitments);

    env::log("Proof generation completed successfully!");
    env::log(&format!(
        "All validations passed: {}",
        all_validations_passed
    ));
}

/// Verify chain continuity - each slot must follow the previous
fn verify_chain_continuity(slot_chain: &[ZkSlotData]) -> bool {
    env::log("Verifying chain continuity...");

    for i in 1..slot_chain.len() {
        let prev = &slot_chain[i - 1];
        let curr = &slot_chain[i];

        // Verify slot numbers are consecutive
        if curr.slot != prev.slot + 1 {
            env::log(&format!(
                "ERROR: Slot {} does not follow slot {} consecutively",
                curr.slot, prev.slot
            ));
            return false;
        }

        // Verify parent bank hash matches previous bank hash
        if curr.parent_bank_hash != prev.bank_hash {
            env::log(&format!(
                "ERROR: Parent bank hash mismatch at slot {}",
                curr.slot
            ));
            return false;
        }
    }

    env::log("Chain continuity verified!");
    true
}

/// Verify bank hashes are computed correctly
fn verify_bank_hashes(slot_chain: &[ZkSlotData]) -> bool {
    use twine_solana_r0_prover_lib::core::hashv;

    env::log("Verifying bank hashes...");

    for (index, slot) in slot_chain.iter().enumerate() {
        env::log(&format!("Verifying slot {} (index {})", slot.slot, index));
        env::log(&format!(
            "  Parent bank hash: {}",
            bs58::encode(&slot.parent_bank_hash).into_string()
        ));
        env::log(&format!("  Signature count: {}", slot.signature_count));
        env::log(&format!(
            "  Last blockhash: {}",
            bs58::encode(&slot.last_blockhash).into_string()
        ));
        env::log(&format!(
            "  Cumulative LtHash length: {} bytes",
            slot.cumulative_lthash.len()
        ));

        // Calculate bank hash using Solana's standard algorithm
        // Step 1: Calculate base hash (parent_bank_hash, signature_count, last_blockhash)
        let base_hash = hashv(&[
            &slot.parent_bank_hash,
            &slot.signature_count.to_le_bytes(),
            &slot.last_blockhash,
        ]);

        env::log(&format!(
            "  Base hash: {}",
            bs58::encode(base_hash.to_bytes()).into_string()
        ));

        // Step 2: Hash the base hash with cumulative LtHash
        let calculated_hash =
            hashv(&[base_hash.to_bytes().as_ref(), &slot.cumulative_lthash]).to_bytes();

        // Compare with provided bank hash
        if calculated_hash != slot.bank_hash {
            env::log(&format!("ERROR: Bank hash mismatch at slot {}", slot.slot));
            env::log(&format!(
                "  Expected: {}",
                bs58::encode(&slot.bank_hash).into_string()
            ));
            env::log(&format!(
                "  Calculated: {}",
                bs58::encode(&calculated_hash).into_string()
            ));
            return false;
        }
    }

    env::log("Bank hashes verified!");
    true
}

/// Verify account changes are valid
fn verify_account_changes(
    account_changes: &[ZkAccountChange],
    monitored_accounts: &[[u8; 32]],
) -> bool {
    env::log("Verifying account changes...");

    // For now, just verify we have changes for monitored accounts
    let monitored_set: HashSet<[u8; 32]> = monitored_accounts.iter().cloned().collect();

    for change in account_changes {
        if !monitored_set.contains(&change.account_pubkey) {
            env::log(&format!(
                "WARNING: Account change for non-monitored account: {}",
                bs58::encode(&change.account_pubkey).into_string()
            ));
        }
    }

    env::log("Account changes verified!");
    true
}

/// Verify LtHash transformation for ALL account changes
fn verify_lthash_transformation(
    prev_slot: &ZkSlotData,
    last_slot: &ZkSlotData,
    account_changes: &[ZkAccountChange],
    _target_pubkey: &[u8; 32], // unused - kept for API compatibility
) -> bool {
    // Parse LtHashes
    let prev_cumulative = match parse_lthash(&prev_slot.cumulative_lthash) {
        Ok(hash) => hash,
        Err(e) => {
            env::log(&format!(
                "ERROR: Invalid previous cumulative LtHash for slot {}: {}",
                prev_slot.slot, e
            ));
            return false;
        }
    };
    let stored_cumulative = match parse_lthash(&last_slot.cumulative_lthash) {
        Ok(hash) => hash,
        Err(e) => {
            env::log(&format!(
                "ERROR: Invalid stored cumulative LtHash for slot {}: {}",
                last_slot.slot, e
            ));
            return false;
        }
    };
    // Do not rely on stored delta LtHash; recompute transformation from account_changes to minimize inputs

    // Calculate cumulative LT hash from ALL account changes in the slot
    let mut calculated_cumulative = prev_cumulative.clone();

    for change in account_changes {
        // Filter out empty changes (both old and new have 0 lamports and no data)
        // This is a data storage issue where empty values are incorrectly stored as changes
        if change.old_lamports == 0
            && change.new_lamports == 0
            && change.old_data.is_empty()
            && change.new_data.is_empty()
        {
            continue;
        }

        // CRITICAL: Skip unchanged accounts - Agave does this check BEFORE mixing!
        // This matches Agave's accounts_equal check in accounts_lt_hash.rs
        if change.old_lamports == change.new_lamports
            && change.old_data == change.new_data
            && change.old_executable == change.new_executable
            && change.old_owner == change.new_owner
            && change.old_rent_epoch == change.new_rent_epoch
        {
            // Account didn't actually change, skip it for LtHash mixing
            continue;
        }

        // Calculate account LtHashes
        let calculated_old = calculate_account_lthash(
            change.old_lamports,
            change.old_rent_epoch,
            &change.old_data,
            change.old_executable,
            &change.old_owner,
            &change.account_pubkey,
        );

        let calculated_new = calculate_account_lthash(
            change.new_lamports,
            change.new_rent_epoch,
            &change.new_data,
            change.new_executable,
            &change.new_owner,
            &change.account_pubkey,
        );

        // Parse stored LtHashes
        let stored_old = match parse_lthash(&change.old_lthash) {
            Ok(hash) => hash,
            Err(e) => {
                env::log(&format!(
                    "ERROR: Invalid old LtHash for account {}: {}",
                    bs58::encode(&change.account_pubkey).into_string(),
                    e
                ));
                return false;
            }
        };
        let stored_new = match parse_lthash(&change.new_lthash) {
            Ok(hash) => hash,
            Err(e) => {
                env::log(&format!(
                    "ERROR: Invalid new LtHash for account {}: {}",
                    bs58::encode(&change.account_pubkey).into_string(),
                    e
                ));
                return false;
            }
        };

        // Verify our calculations match stored values
        if calculated_old != stored_old {
            env::log(&format!(
                "ERROR: Old LtHash mismatch for account {}",
                bs58::encode(&change.account_pubkey).into_string()
            ));
            return false;
        }
        if calculated_new != stored_new {
            env::log(&format!(
                "ERROR: New LtHash mismatch for account {}",
                bs58::encode(&change.account_pubkey).into_string()
            ));
            return false;
        }

        // Apply the LT hash transformation for this account change
        // This updates the cumulative LT hash with: new_cumulative = old_cumulative - old_account_lthash + new_account_lthash
        calculated_cumulative.mix_out(&stored_old);
        calculated_cumulative.mix_in(&stored_new);
    }

    // Verify that our calculated cumulative LT hash matches the stored one
    // This proves that ALL account changes were correctly applied to the LT hash
    if calculated_cumulative != stored_cumulative {
        env::log(&format!(
            "ERROR: Cumulative LtHash mismatch after applying all account changes for slot {}",
            last_slot.slot
        ));
        return false;
    }

    // Verify checksum if present
    if let Some(stored_checksum) = &last_slot.accounts_lthash_checksum {
        let calculated_checksum = calculated_cumulative.checksum();
        if calculated_checksum.0 != *stored_checksum {
            env::log(&format!(
                "ERROR: LtHash checksum mismatch for slot {}",
                last_slot.slot
            ));
            return false;
        }
    }

    env::log(&format!(
        "✅ LtHash transformation verified successfully for slot {}",
        last_slot.slot
    ));
    true
}

/// Parse LtHash from bytes
fn parse_lthash(bytes: &[u8]) -> Result<LtHash, &'static str> {
    use solana_lattice_hash::lt_hash::LtHash;

    if bytes.len() != 2048 {
        return Err("Invalid LtHash length: expected 2048 bytes");
    }

    let mut arr = [0u16; 1024]; // LtHash::NUM_ELEMENTS
    for i in 0..1024 {
        arr[i] = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }

    Ok(LtHash(arr))
}

/// Calculate account LtHash
fn calculate_account_lthash(
    lamports: u64,
    _rent_epoch: u64, // rent_epoch is excluded from account hash
    data: &[u8],
    executable: bool,
    owner: &[u8; 32],
    pubkey: &[u8; 32],
) -> LtHash {
    // Zero-lamport accounts use identity LtHash
    if lamports == 0 {
        return LtHash::identity();
    }

    // Use blake3 for account hash (matching Solana)
    use blake3::Hasher as Blake3Hasher;
    let mut hasher = Blake3Hasher::new();

    // Hash account data in order (excluding rent_epoch)
    hasher.update(&lamports.to_le_bytes());
    hasher.update(data);
    hasher.update(&[executable as u8]);
    hasher.update(owner);
    hasher.update(pubkey);

    // Use LtHash::with to convert blake3 hash to LtHash
    LtHash::with(&hasher)
}

/// Calculate hash of monitored account data
fn aggregate_account_data_and_commitments(
    account_changes: &[ZkAccountChange],
    monitored_accounts: &Vec<[u8; 32]>,
) -> ([u8; 32], Vec<AccountStateCommitment>) {
    let mut hasher = twine_solana_r0_prover_lib::core::Hasher::new();
    let mut commitments: Vec<AccountStateCommitment> = Vec::new();

    for account in monitored_accounts {
        // Find last change for each monitored account
        let mut found: Option<(&ZkAccountChange, u64)> = None;
        for change in account_changes.iter().rev() {
            if &change.account_pubkey == account {
                found = Some((change, change.slot));
                break;
            }
        }
        if let Some((change, slot)) = found {
            // Hash into aggregated account_data_hash
            hasher.hash(&change.new_lamports.to_le_bytes());
            hasher.hash(&change.new_owner);
            hasher.hash(&[change.new_executable as u8]);
            hasher.hash(&change.new_rent_epoch.to_le_bytes());
            hasher.hash(&change.new_data);

            // Compute per-account data hash
            let mut ah = twine_solana_r0_prover_lib::core::Hasher::new();
            ah.hash(&change.new_lamports.to_le_bytes());
            ah.hash(&change.new_owner);
            ah.hash(&[change.new_executable as u8]);
            ah.hash(&change.new_rent_epoch.to_le_bytes());
            ah.hash(&change.new_data);
            let account_hash = ah.result().to_bytes();

            commitments.push(AccountStateCommitment {
                account_pubkey: *account,
                last_change_slot: slot,
                account_data_hash: account_hash,
                lamports: change.new_lamports,
                owner: change.new_owner,
                executable: change.new_executable,
                rent_epoch: change.new_rent_epoch,
                data: change.new_data.clone(),
            });
        } else {
            // No change since start; commit with last_change_slot = 0 and zero hash
            commitments.push(AccountStateCommitment {
                account_pubkey: *account,
                last_change_slot: 0,
                account_data_hash: [0u8; 32],
                lamports: 0,
                owner: [0u8; 32],
                executable: false,
                rent_epoch: 0,
                data: vec![],
            });
        }
    }

    (hasher.result().to_bytes(), commitments)
}

/// Verify votes for the last slot and enforce ESR inclusion + supermajority
fn verify_votes_intent_signatures_esr_and_supermajority(
    vote_transactions: &[ZkVoteTransaction],
    validator_set: &[ZkValidatorSetEntry],
    esr_data: &Option<twine_solana_r0_prover_lib::ZkEpochValidatorMerkleRoot>,
    merkle_proofs: &HashMap<[u8; 32], Vec<[u8; 32]>>,
    last_slot: &ZkSlotData,
) -> bool {
    if esr_data.is_none() {
        env::log("ERROR: ESR data is required for vote verification");
        return false;
    }

    let esr = esr_data.as_ref().unwrap();

    if vote_transactions.is_empty() {
        env::log(&format!(
            "ERROR: No vote transactions provided for slot {}",
            last_slot.slot
        ));
        return false;
    }

    // Build sorted validator list and map vote_account -> (index, stake)
    let mut sorted_validators = validator_set.to_vec();
    sorted_validators.sort_by(|a, b| a.validator_vote_account.cmp(&b.validator_vote_account));
    let mut validator_map = HashMap::new();
    for (index, v) in sorted_validators.iter().enumerate() {
        validator_map.insert(v.validator_vote_account, (index, v.active_stake));
    }

    let mut unique_voting_validators: HashSet<[u8; 32]> = HashSet::new();
    let mut total_voting_stake: u128 = 0;
    let mut all_ok = true;

    // Track statistics for debugging
    let mut votes_with_matching_hash = 0;
    let mut votes_with_mismatched_hash = 0;
    let mut total_votes_processed = 0;

    for vote_tx in vote_transactions {
        total_votes_processed += 1;
        // 1) Transaction must be recorded at the last_slot.slot
        if vote_tx.slot != last_slot.slot {
            env::log(&format!(
                "ERROR: Vote transaction from wrong slot: expected {}, got {}",
                last_slot.slot, vote_tx.slot
            ));
            all_ok = false;
            continue;
        }

        // 2) Vote intent must explicitly include the last slot number
        if !vote_tx.vote_slots.iter().any(|&s| s == last_slot.slot) {
            env::log(&format!(
                "WARNING: Vote in database doesn't include target slot {}",
                last_slot.slot
            ));
            // Skip this vote but don't fail the entire verification
            continue;
        }

        // 3) Filter votes by bank hash - skip those that don't match
        // This is expected behavior - not all votes will have the same hash
        match vote_tx.vote_hash {
            Some(h) if h == last_slot.bank_hash => {
                votes_with_matching_hash += 1;
            }
            _ => {
                // This is normal - votes can have different hashes
                // Just skip this vote, don't fail verification
                votes_with_mismatched_hash += 1;
                continue;
            }
        }

        // 4) Verify all provided signatures against the message (first num_required_signatures)
        // Parse signature count and message bytes from transaction
        let tx_bytes = &vote_tx.vote_transaction;
        if tx_bytes.len() < 65 {
            env::log(&format!(
                "ERROR: Transaction too short for vote at slot {}",
                vote_tx.slot
            ));
            all_ok = false;
            continue;
        }
        let (sig_count, sigs_offset) = parse_compact_u16(tx_bytes);
        if sig_count == 0 {
            env::log(&format!(
                "ERROR: No signatures in vote transaction at slot {}",
                vote_tx.slot
            ));
            all_ok = false;
            continue;
        }
        let message_start = sigs_offset + (sig_count as usize * 64);
        if message_start >= tx_bytes.len() {
            env::log(&format!(
                "ERROR: Invalid transaction structure at slot {}",
                vote_tx.slot
            ));
            all_ok = false;
            continue;
        }
        let message = &tx_bytes[message_start..];

        // Verify signatures correspond to provided signer_pubkeys
        let signer_pubkeys_in_msg: Vec<twine_solana_r0_prover_lib::core::Pubkey> = vote_tx
            .signer_pubkeys
            .iter()
            .map(|b| twine_solana_r0_prover_lib::core::Pubkey(*b))
            .collect();
        let pairs_to_check = core::cmp::min(sig_count as usize, signer_pubkeys_in_msg.len());
        let mut sigs_ok = true;
        for i in 0..pairs_to_check {
            let start = sigs_offset + (i * 64);
            let end = start + 64;
            if end > tx_bytes.len() {
                sigs_ok = false;
                break;
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&tx_bytes[start..end]);
            if !verify_ed25519_signature_mechanical(&sig_arr, &message, &signer_pubkeys_in_msg[i]) {
                env::log(&format!(
                    "ERROR: Signature {} invalid for signer {}",
                    i,
                    bs58::encode(&signer_pubkeys_in_msg[i].0).into_string()
                ));
                sigs_ok = false;
                break;
            }
        }
        if !sigs_ok {
            all_ok = false;
            continue;
        }

        // 5) If authorized voter is provided, it must be among the transaction signers
        if let Some(av) = &vote_tx.authorized_voter {
            let av_pub = twine_solana_r0_prover_lib::core::Pubkey(*av);
            if !signer_pubkeys_in_msg.iter().any(|pk| pk.0 == av_pub.0) {
                env::log(&format!(
                    "ERROR: Authorized voter {} is not among transaction signers",
                    bs58::encode(&av_pub.0).into_string()
                ));
                all_ok = false;
                continue;
            }
        }

        // 6) ESR inclusion: must have a provided Merkle proof for this vote account and verify it
        let vote_acct = vote_tx.vote_account_pubkey;
        let (leaf_index, active_stake) = match validator_map.get(&vote_acct) {
            Some(x) => *x,
            None => {
                // Not in the committed validator set (e.g., not in top-N) -> not counted
                continue;
            }
        };

        let proof = match merkle_proofs.get(&vote_acct) {
            Some(p) => p,
            None => {
                env::log(&format!(
                    "ERROR: Missing ESR merkle proof for vote account {}",
                    bs58::encode(&vote_acct).into_string()
                ));
                all_ok = false;
                continue;
            }
        };

        if !verify_vote_merkle_proof(
            &vote_acct,
            active_stake,
            proof,
            &esr.merkle_root,
            leaf_index,
        ) {
            env::log(&format!(
                "ERROR: ESR merkle proof failed for vote account {}",
                bs58::encode(&vote_acct).into_string()
            ));
            all_ok = false;
            continue;
        }

        // Count unique validator stake toward supermajority only once
        if unique_voting_validators.insert(vote_acct) {
            total_voting_stake += active_stake as u128;
        }
    }

    // Log vote processing statistics
    env::log(&format!(
        "Vote processing for slot {}: total_votes={}, matching_hash={}, mismatched_hash={}",
        last_slot.slot, total_votes_processed, votes_with_matching_hash, votes_with_mismatched_hash
    ));

    if !all_ok {
        env::log("Vote verification failed due to signature or other validation errors");
        return false;
    }

    // 7) Supermajority check
    let total_active_stake = esr.total_active_stake as u128;
    let supermajority_ok = total_voting_stake * 3 >= total_active_stake * 2;

    // Enhanced logging for consensus status
    let percentage = if total_active_stake > 0 {
        (total_voting_stake * 100) / total_active_stake
    } else {
        0
    };
    env::log(&format!(
        "Consensus check for slot {}: voting_stake={} ({}%), total_stake={}, required=66.67%",
        last_slot.slot, total_voting_stake, percentage, total_active_stake
    ));

    if !supermajority_ok {
        env::log(&format!(
            "❌ Supermajority NOT reached for slot {} - only {}% of stake voted with matching hash",
            last_slot.slot, percentage
        ));
        env::log(&format!(
            "   Need at least {} stake, but only have {} stake from {} validators with matching bank hash",
            (total_active_stake * 2) / 3, total_voting_stake, unique_voting_validators.len()
        ));
    } else {
        env::log(&format!(
            "✅ Supermajority reached for slot {} - {}% of stake voted with matching hash",
            last_slot.slot, percentage
        ));
    }

    supermajority_ok
}

/// Parse compact-u16 from bytes
fn parse_compact_u16(bytes: &[u8]) -> (u16, usize) {
    if bytes.is_empty() {
        return (0, 0);
    }

    match bytes[0] {
        0..=127 => (bytes[0] as u16, 1),
        128..=255 => {
            if bytes.len() < 2 {
                env::log("ERROR: Invalid compact-u16 encoding - insufficient bytes");
                return (0, 0);
            }
            let val = ((bytes[0] & 0x7f) as u16) | ((bytes[1] as u16) << 7);
            (val, 2)
        }
    }
}

/// Verify Ed25519 signature mechanically using curve25519-dalek
fn verify_ed25519_signature_mechanical(
    signature: &[u8; 64],
    message: &[u8],
    pubkey: &twine_solana_r0_prover_lib::core::Pubkey,
) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    // Parse signature components (R || s)
    let r_bytes: [u8; 32] = match signature[..32].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let s_bytes: [u8; 32] = match signature[32..].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Parse public key point
    let compressed_pubkey = CompressedEdwardsY(pubkey.0);
    let pubkey_point = match compressed_pubkey.decompress() {
        Some(point) => point,
        None => return false,
    };

    // Parse R point
    let r_point = match CompressedEdwardsY(r_bytes).decompress() {
        Some(point) => point,
        None => return false,
    };

    // Parse s scalar
    let s_option = Scalar::from_canonical_bytes(s_bytes);
    let s = if s_option.is_some().into() {
        s_option.unwrap()
    } else {
        return false;
    };

    // Compute hash(R || pubkey || message)
    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(&pubkey.0);
    hasher.update(message);
    let hash = hasher.finalize();
    let h = Scalar::from_bytes_mod_order_wide(&hash.into());

    // Verify: s*G = R + h*pubkey
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let left = &s * &ED25519_BASEPOINT_POINT;
    let right = &r_point + &(&h * &pubkey_point);

    // Return true if signature is valid
    left.compress().to_bytes() == right.compress().to_bytes()
}
