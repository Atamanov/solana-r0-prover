#![cfg_attr(feature = "zkvm", no_std)]

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(not(feature = "zkvm"))]
use std::collections::HashMap;
#[cfg(feature = "zkvm")]
extern crate alloc;
#[cfg(feature = "zkvm")]
use alloc::vec::Vec;
#[cfg(feature = "zkvm")]
use hashbrown::HashMap;

pub mod core;

/// Account change data with full cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAccountChange {
    pub slot: u64,
    pub account_pubkey: [u8; 32],
    pub write_version: u64,
    // Old account state (required for LT hash mixing)
    pub old_lamports: u64,
    pub old_owner: [u8; 32],
    pub old_executable: bool,
    pub old_rent_epoch: u64,
    pub old_data: Vec<u8>,
    pub old_state_hash: Option<[u8; 32]>, // Account state hash for verification
    pub old_lt_hash_checksum: Option<[u8; 32]>, // LT hash checksum for verification
    pub old_lthash: Vec<u8>,              // 2048 bytes - CRITICAL for verification
    // New account state
    pub new_lamports: u64,
    pub new_owner: [u8; 32],
    pub new_executable: bool,
    pub new_rent_epoch: u64,
    pub new_data: Vec<u8>,
    pub new_state_hash: Option<[u8; 32]>, // Account state hash for verification
    pub new_lt_hash_checksum: Option<[u8; 32]>, // LT hash checksum for verification
    pub new_lthash: Vec<u8>,              // 2048 bytes - CRITICAL for verification
}

/// Validator set entry optimized for zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkValidatorSetEntry {
    pub validator_vote_account: [u8; 32], // Vote account pubkey
    pub active_stake: u64,                // Active stake amount
    pub commission_rate: u16,             // Commission rate (basis points)
    pub authorized_voter: [u8; 32],       // Authorized voter pubkey
}

/// Epoch validator merkle root for zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkEpochValidatorMerkleRoot {
    pub epoch: u64,
    pub merkle_root: [u8; 32],   // Merkle root of validator set
    pub total_active_stake: u64, // Total active stake in epoch
    pub validator_count: u32,    // Number of active validators
}

/// Merkle proof for a validator's inclusion in the set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkValidatorMerkleProof {
    pub validator_vote_account: [u8; 32], // Vote account being proven
    pub active_stake: u64,                // Stake amount for this validator
    pub merkle_proof: Vec<[u8; 32]>,      // Path from leaf to root
    pub leaf_index: u32,                  // Position in the merkle tree
}

/// Complete proof package with full cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteProofPackage {
    /// Start slot number
    pub start_slot: u64,
    /// End slot number (last rooted slot with account data)
    pub end_slot: u64,
    /// Epoch number for the end slot
    pub epoch: u64,
    /// Monitored account public keys (as bytes)
    pub monitored_accounts: Vec<[u8; 32]>,
    /// Complete slot chain data from start to end with ALL components
    pub slot_chain: Vec<ZkSlotData>,
    /// All account changes in the last slot with full LT hash data
    pub account_changes: Vec<ZkAccountChange>,
    /// Vote transactions for the last slot with full verification data
    pub vote_transactions: Vec<ZkVoteTransaction>,
    /// ESR (Epoch Staking Root) data for the epoch
    pub esr_data: Option<ZkEpochValidatorMerkleRoot>,
    /// Validator set entries (for merkle proof verification)
    pub validator_set: Vec<ZkValidatorSetEntry>,
    /// Pre-computed merkle proofs for vote accounts
    pub merkle_proofs: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

/// Complete slot data with all bank hash components for cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkSlotData {
    pub slot: u64,
    pub bank_hash: [u8; 32],
    pub parent_bank_hash: [u8; 32],
    pub signature_count: u64,
    pub last_blockhash: [u8; 32],
    pub cumulative_lthash: Vec<u8>, // 2048 bytes - CRITICAL for LT hash verification
    pub delta_lthash: Vec<u8>,      // 2048 bytes - CRITICAL for account change verification
    pub accounts_delta_hash: [u8; 32],
    pub accounts_lthash_checksum: Option<[u8; 32]>, // CRITICAL for checksum validation
    pub epoch_accounts_hash: Option<[u8; 32]>,
}

/// Complete vote transaction data for full Ed25519 verification
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVoteTransaction {
    pub slot: u64,
    // Vote account pubkey referenced in instruction (not necessarily signer)
    pub vote_account_pubkey: [u8; 32],
    #[serde_as(as = "[_; 64]")]
    pub vote_signature: [u8; 64], // Pre-decoded Ed25519 signature
    pub vote_transaction: Vec<u8>, // Raw transaction bytes - CRITICAL for signature verification
    pub transaction_meta: Option<Vec<u8>>,
    pub vote_type: u8,        // Encoded vote type
    pub vote_slots: Vec<u64>, // Pre-parsed vote slots from simple-geyser
    pub vote_hash: Option<[u8; 32]>,
    pub root_slot: Option<u64>,
    pub lockouts_count: Option<u64>,
    pub timestamp: Option<i64>,
    // Optional: authorized voter resolved at ingestion time
    pub authorized_voter: Option<[u8; 32]>,
    // The message header signer pubkeys (first num_required_signatures accounts)
    pub signer_pubkeys: Vec<[u8; 32]>,
}

/// The public values committed by the ZKVM program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCommitments {
    /// Start slot number of the proven chain
    pub start_slot: u64,
    /// End slot number of the proven chain
    pub end_slot: u64,
    /// Epoch number for the end slot
    pub epoch: u64,
    /// Original slot bank hash (first slot in the chain)
    pub original_bank_hash: [u8; 32],
    /// Last slot bank hash (end of the proven chain)
    pub last_bank_hash: [u8; 32],
    /// Hash of monitored account data at the last slot
    pub account_data_hash: [u8; 32],
    /// ESR root (validator set merkle root) for the epoch
    pub hash_root_valset: [u8; 32],
    /// Total active stake in the epoch
    pub total_active_stake: u64,
    /// Number of validators in the epoch
    pub validator_count: u32,
    /// Map of monitored account -> {last_change_slot, account_data_hash_at_that_slot}
    pub monitored_accounts_state: Vec<AccountStateCommitment>,
    /// Aggregated validation result (true if all validations passed)
    pub validations_passed: bool,
}

/// Public commitment per monitored account to disambiguate which slot carried its last change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStateCommitment {
    pub account_pubkey: [u8; 32],
    pub last_change_slot: u64,
    pub account_data_hash: [u8; 32],
    // Full account state at last_change_slot (new state)
    pub lamports: u64,
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}
