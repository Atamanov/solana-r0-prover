use blake3::Hasher as Blake3Hasher;
use deadpool_postgres::{Config, Pool, Runtime};
use log::info;
use solana_lattice_hash::lt_hash::LtHash as LatticeLtHash;
use std::error::Error;
use tokio_postgres::NoTls;
use twine_solana_r0_prover_lib::{
    CompleteProofPackage, ZkAccountChange, ZkEpochValidatorMerkleRoot, ZkSlotData,
    ZkValidatorSetEntry, ZkVoteTransaction,
};

pub struct DatabaseClient {
    pool: Pool,
}

impl DatabaseClient {
    pub async fn new(db_url: &str) -> Result<Self, Box<dyn Error>> {
        // Parse PostgreSQL connection string format: "host=... port=... user=... password=... dbname=..."
        let mut cfg = Config::new();

        // Parse key-value pairs from the connection string
        for part in db_url.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "host" => cfg.host = Some(value.to_string()),
                    "port" => {
                        if let Ok(port) = value.parse::<u16>() {
                            cfg.port = Some(port);
                        }
                    }
                    "user" => cfg.user = Some(value.to_string()),
                    "password" => cfg.password = Some(value.to_string()),
                    "dbname" => cfg.dbname = Some(value.to_string()),
                    _ => {} // Ignore unknown keys
                }
            }
        }

        // Enable compression and performance optimizations
        cfg.application_name = Some("twine-solana-r0-prover".to_string());

        // Create connection pool with performance optimizations
        let pool = cfg
            .builder(NoTls)?
            .max_size(16) // Maximum number of connections in the pool
            .wait_timeout(Some(std::time::Duration::from_secs(30)))
            .create_timeout(Some(std::time::Duration::from_secs(30)))
            .recycle_timeout(Some(std::time::Duration::from_secs(30)))
            .runtime(Runtime::Tokio1)
            .build()?;

        Ok(DatabaseClient { pool })
    }

    pub async fn fetch_proof_package(
        &self,
        start_slot: u64,
        monitored_accounts: Vec<[u8; 32]>,
    ) -> Result<CompleteProofPackage, Box<dyn Error>> {
        let client = self.pool.get().await?;

        // Optimize PostgreSQL session for large data transfers
        let _ = client.execute("SET work_mem = '256MB'", &[]).await;
        let _ = client.execute("SET enable_hashjoin = on", &[]).await;
        let _ = client.execute("SET enable_mergejoin = on", &[]).await;
        let _ = client.execute("SET random_page_cost = 1.1", &[]).await;

        // Pick the last slot in database with ANY account changes
        let end_slot = self.get_latest_slot_with_any_changes(&client).await?;
        println!("Found account changes at slot: {}", end_slot);

        // Get the epoch for the end slot
        let epoch = self.get_epoch_for_slot(&client, end_slot).await?;
        println!("End slot {} is in epoch {}", end_slot, epoch);

        // Build full slot chain from start_slot to end_slot
        let slot_chain = self.fetch_slot_chain(&client, start_slot, end_slot).await?;

        // Fetch ALL account changes for the end slot only (required for LtHash transformation)
        let account_changes = self
            .fetch_account_changes_for_slot(&client, end_slot)
            .await?;

        // Fetch vote transactions that vote FOR the end_slot
        // These are now stored directly under the target slot in the database
        let vote_transactions = self
            .fetch_vote_transactions_for_slot(&client, end_slot)
            .await?;

        // Fetch ESR data for the epoch (required)
        let esr_data = self
            .fetch_esr_for_epoch(epoch)
            .await
            .map_err(|e| format!("Failed to fetch ESR for epoch {}: {}", epoch, e))?;

        println!(
            "Fetched ESR for epoch {}: root={}, stake={}, validators={}",
            epoch,
            hex::encode(&esr_data.merkle_root),
            esr_data.total_active_stake,
            esr_data.validator_count
        );

        // Fetch validator set (required for merkle proof verification)
        let validator_set = self
            .fetch_validator_set_for_epoch(epoch, Some(1000))
            .await
            .map_err(|e| format!("Failed to fetch validator set for epoch {}: {}", epoch, e))?;

        println!(
            "Fetched {} validators for epoch {}",
            validator_set.len(),
            epoch
        );

        // Extract unique vote accounts from transactions
        let vote_accounts: Vec<[u8; 32]> = vote_transactions
            .iter()
            .map(|vt| vt.vote_account_pubkey)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Fetch pre-computed merkle proofs for these vote accounts
        let mut merkle_proofs = match self
            .fetch_validator_merkle_proofs(epoch, &vote_accounts)
            .await
        {
            Ok(proofs) => proofs,
            Err(e) => {
                return Err(format!("Failed to fetch merkle proofs: {}", e).into());
            }
        };

        // Prepare Merkle proofs for any missing vote accounts (generate deterministically)
        let mut sorted_validators = validator_set.clone();
        sorted_validators.sort_by(|a, b| a.validator_vote_account.cmp(&b.validator_vote_account));
        let leaf_hashes = Self::build_esr_leaf_hashes(&sorted_validators);
        let layers = Self::build_merkle_layers(leaf_hashes);
        let index_map = Self::build_vote_index_map(&sorted_validators);

        let topn_set: std::collections::HashSet<[u8; 32]> = validator_set
            .iter()
            .map(|v| v.validator_vote_account)
            .collect();
        for acct in vote_accounts {
            if !topn_set.contains(&acct) {
                continue;
            }
            if !merkle_proofs.contains_key(&acct) {
                if let Some(&idx) = index_map.get(&acct) {
                    let proof = Self::generate_merkle_proof_from_layers(&layers, idx);
                    merkle_proofs.insert(acct, proof);
                }
            }
        }

        Ok(CompleteProofPackage {
            start_slot,
            end_slot,
            epoch,
            monitored_accounts,
            slot_chain,
            account_changes,
            vote_transactions,
            esr_data: Some(esr_data),
            validator_set,
            merkle_proofs,
        })
    }

    async fn fetch_slot_chain(
        &self,
        client: &tokio_postgres::Client,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<Vec<ZkSlotData>, Box<dyn Error>> {
        let query = "
            WITH latest AS (
                SELECT h.slot, MAX(h.created_at) AS created_at
                FROM solana.bank_hash_components h
                WHERE h.slot >= $1 AND h.slot <= $2
                GROUP BY h.slot
            )
            SELECT 
                h.slot,
                h.bank_hash,
                h.parent_bank_hash,
                h.signature_count,
                h.last_blockhash,
                h.slot_lt_hash,
                h.accounts_lt_hash_checksum,
                h.epoch_accounts_hash
            FROM solana.bank_hash_components h
            JOIN latest l ON l.slot = h.slot AND l.created_at = h.created_at
            ORDER BY h.slot ASC
        ";

        info!(
            "Fetching bank hash components for slots {} to {}",
            start_slot, end_slot
        );

        let rows = client
            .query(query, &[&(start_slot as i64), &(end_slot as i64)])
            .await?;

        let mut slot_chain = Vec::new();
        info!("Processing {} bank hash components rows", rows.len());

        // Build a map of slot -> row to allow continuity trimming (rows are already unique latest per slot)
        use std::collections::BTreeMap;
        let mut by_slot: BTreeMap<
            u64,
            (
                Vec<u8>,
                [u8; 32],
                [u8; 32],
                u64,
                [u8; 32],
                Option<[u8; 32]>,
                Option<[u8; 32]>,
            ),
        > = BTreeMap::new();

        for (i, row) in rows.iter().enumerate() {
            let slot: i64 = row.get(0);
            let bank_hash_str: String = row.get(1);
            let parent_bank_hash_str: String = row.get(2);
            let signature_count: i64 = row.get(3);
            let last_blockhash_str: String = row.get(4);
            let slot_lt_hash: Vec<u8> = row.get(5);
            let accounts_lt_hash_checksum: Option<String> = row.get(6);
            let epoch_accounts_hash: Option<String> = row.get(7);

            // Decode base58 hashes
            let bank_hash = Self::decode_hash(&bank_hash_str)?;
            let parent_bank_hash = Self::decode_hash(&parent_bank_hash_str)?;
            let last_blockhash = Self::decode_hash(&last_blockhash_str)?;

            let accounts_lthash_checksum = if let Some(checksum) = accounts_lt_hash_checksum {
                Some(Self::decode_hash(&checksum)?)
            } else {
                None
            };

            let epoch_accounts_hash = if let Some(hash) = epoch_accounts_hash {
                Some(Self::decode_hash(&hash)?)
            } else {
                None
            };

            if i > 0 && i < 5 {
                // Log first few entries for debugging
                info!(
                    "Slot {}: bank_hash={}, parent_bank_hash={}",
                    slot,
                    bs58::encode(&bank_hash).into_string(),
                    bs58::encode(&parent_bank_hash).into_string()
                );
            }

            if slot_lt_hash.len() != 2048 {
                continue; // skip malformed rows
            }

            by_slot.insert(
                slot as u64,
                (
                    slot_lt_hash,
                    bank_hash,
                    parent_bank_hash,
                    signature_count as u64,
                    last_blockhash,
                    accounts_lthash_checksum,
                    epoch_accounts_hash,
                ),
            );
        }

        // Trim to the longest consecutive suffix ending at end_slot
        let mut expected = end_slot;
        let mut min_slot_in_suffix = end_slot;
        loop {
            if by_slot.contains_key(&expected) {
                min_slot_in_suffix = expected;
                if expected == start_slot {
                    break;
                }
                expected -= 1;
            } else {
                break;
            }
        }

        let available_count = by_slot.len();
        let suffix_len = (end_slot - min_slot_in_suffix + 1) as usize;
        info!(
            "Fetched {} unique slots; consecutive tail length {} from {} to {}",
            available_count, suffix_len, min_slot_in_suffix, end_slot
        );

        for (
            slot_num,
            (
                slot_lt_hash,
                bank_hash,
                parent_bank_hash,
                signature_count,
                last_blockhash,
                accounts_lthash_checksum,
                epoch_accounts_hash,
            ),
        ) in by_slot
            .into_iter()
            .filter(|(s, _)| *s >= min_slot_in_suffix && *s <= end_slot)
        {
            slot_chain.push(ZkSlotData {
                slot: slot_num,
                bank_hash,
                parent_bank_hash,
                signature_count,
                last_blockhash,
                cumulative_lthash: slot_lt_hash,
                delta_lthash: vec![0u8; 0],
                accounts_delta_hash: [0u8; 32],
                accounts_lthash_checksum,
                epoch_accounts_hash,
            });
        }

        info!("Fetched {} slots from database", slot_chain.len());

        Ok(slot_chain)
    }

    async fn fetch_account_changes_for_slot(
        &self,
        client: &tokio_postgres::Client,
        slot: u64,
    ) -> Result<Vec<ZkAccountChange>, Box<dyn Error>> {
        // When an account has multiple changes in a slot, we need:
        // - The FIRST old state (from the earliest change)
        // - The LAST new state (from the latest change)
        // This represents the actual transformation for the account in this slot
        let query = "
            WITH first_and_last AS (
                SELECT 
                    account_pubkey,
                    FIRST_VALUE(old_lamports) OVER (PARTITION BY account_pubkey ORDER BY id) as old_lamports,
                    FIRST_VALUE(old_owner) OVER (PARTITION BY account_pubkey ORDER BY id) as old_owner,
                    FIRST_VALUE(old_executable) OVER (PARTITION BY account_pubkey ORDER BY id) as old_executable,
                    FIRST_VALUE(old_rent_epoch) OVER (PARTITION BY account_pubkey ORDER BY id) as old_rent_epoch,
                    FIRST_VALUE(old_data) OVER (PARTITION BY account_pubkey ORDER BY id) as old_data,
                    FIRST_VALUE(old_state_hash) OVER (PARTITION BY account_pubkey ORDER BY id) as old_state_hash,
                    FIRST_VALUE(old_lt_hash_checksum) OVER (PARTITION BY account_pubkey ORDER BY id) as old_lt_hash_checksum,
                    FIRST_VALUE(old_lt_hash) OVER (PARTITION BY account_pubkey ORDER BY id) as old_lt_hash,
                    LAST_VALUE(new_lamports) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_lamports,
                    LAST_VALUE(new_owner) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_owner,
                    LAST_VALUE(new_executable) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_executable,
                    LAST_VALUE(new_rent_epoch) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_rent_epoch,
                    LAST_VALUE(new_data) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_data,
                    LAST_VALUE(new_state_hash) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_state_hash,
                    LAST_VALUE(new_lt_hash_checksum) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_lt_hash_checksum,
                    LAST_VALUE(new_lt_hash) OVER (PARTITION BY account_pubkey ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) as new_lt_hash,
                    $1::bigint as slot
                FROM solana.account_changes
                WHERE slot = $1
            )
            SELECT DISTINCT
                slot, account_pubkey,
                old_lamports, old_owner, old_executable, old_rent_epoch, old_data,
                old_state_hash, old_lt_hash_checksum, old_lt_hash,
                new_lamports, new_owner, new_executable, new_rent_epoch, new_data,
                new_state_hash, new_lt_hash_checksum, new_lt_hash
            FROM first_and_last
            ORDER BY account_pubkey
        ";
        let rows = client.query(query, &[&(slot as i64)]).await?;
        let mut account_changes = Vec::new();
        for row in rows {
            let account_pubkey_str: String = row.get(1);
            // Old account state
            let old_lamports: i64 = row.get(2);
            let old_owner_str: String = row.get(3);
            let old_executable: bool = row.get(4);
            let old_rent_epoch: i64 = row.get(5);
            let old_data: Vec<u8> = row.get(6);
            let old_state_hash: Option<String> = row.get(7);
            let old_lt_hash_checksum: Option<String> = row.get(8);
            let old_lt_hash: Option<Vec<u8>> = row.get(9);
            // New account state
            let new_lamports: i64 = row.get(10);
            let new_owner_str: String = row.get(11);
            let new_executable: bool = row.get(12);
            let new_rent_epoch: i64 = row.get(13);
            let new_data: Vec<u8> = row.get(14);
            let new_state_hash: Option<String> = row.get(15);
            let new_lt_hash_checksum: Option<String> = row.get(16);
            let new_lt_hash: Option<Vec<u8>> = row.get(17);

            let account_pubkey = Self::decode_pubkey(&account_pubkey_str)?;
            let new_owner = Self::decode_pubkey(&new_owner_str)?;
            let old_owner = Self::decode_pubkey(&old_owner_str)?;

            let old_lthash = match old_lt_hash {
                Some(hash) if hash.len() == 2048 => hash,
                _ => Self::calculate_account_lthash_bytes(
                    old_lamports as u64,
                    &old_owner,
                    old_executable,
                    &account_pubkey,
                    &old_data,
                ),
            };
            let new_lthash = match new_lt_hash {
                Some(hash) if hash.len() == 2048 => hash,
                _ => Self::calculate_account_lthash_bytes(
                    new_lamports as u64,
                    &new_owner,
                    new_executable,
                    &account_pubkey,
                    &new_data,
                ),
            };

            let old_state_hash_bytes = old_state_hash.as_ref().and_then(|h| {
                hex::decode(h).ok().and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                })
            });
            let old_lt_hash_checksum_bytes = old_lt_hash_checksum.as_ref().and_then(|h| {
                hex::decode(h).ok().and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                })
            });
            let new_state_hash_bytes = new_state_hash.as_ref().and_then(|h| {
                hex::decode(h).ok().and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                })
            });
            let new_lt_hash_checksum_bytes = new_lt_hash_checksum.as_ref().and_then(|h| {
                hex::decode(h).ok().and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                })
            });

            account_changes.push(ZkAccountChange {
                slot,
                account_pubkey,
                write_version: 0,
                old_lamports: old_lamports as u64,
                old_owner,
                old_executable,
                old_rent_epoch: old_rent_epoch as u64,
                old_data,
                old_state_hash: old_state_hash_bytes,
                old_lt_hash_checksum: old_lt_hash_checksum_bytes,
                old_lthash,
                new_lamports: new_lamports as u64,
                new_owner,
                new_executable,
                new_rent_epoch: new_rent_epoch as u64,
                new_data,
                new_state_hash: new_state_hash_bytes,
                new_lt_hash_checksum: new_lt_hash_checksum_bytes,
                new_lthash,
            });
        }
        Ok(account_changes)
    }

    async fn fetch_vote_transactions_for_slot(
        &self,
        client: &tokio_postgres::Client,
        target_slot: u64,
    ) -> Result<Vec<ZkVoteTransaction>, Box<dyn Error>> {
        // Fetch votes that are stored under the target slot (votes FOR this slot)
        let query = "
            SELECT 
                slot,
                vote_account_pubkey,
                vote_signature,
                vote_transaction,
                transaction_meta,
                vote_type,
                vote_slots,
                vote_hash,
                authorized_voter,
                signer_pubkeys,
                root_slot,
                lockouts_count,
                timestamp
            FROM solana.vote_transactions
            WHERE slot = $1
            ORDER BY id ASC
            LIMIT 5000
        ";

        let rows = client.query(query, &[&(target_slot as i64)]).await?;

        let mut vote_transactions = Vec::new();
        for row in rows {
            let slot: i64 = row.get(0);
            let vote_account_pubkey_str: String = row.get(1);
            let vote_signature_str: String = row.get(2);
            let vote_transaction: Vec<u8> = row.get(3);
            let transaction_meta: Option<Vec<u8>> = row.get(4);
            let vote_type_str: String = row.get(5);
            let vote_slots: Vec<i64> = row.get(6);
            let vote_hash: Option<String> = row.get(7);
            let authorized_voter_str: Option<String> = row.get(8);
            let signer_pubkeys_arr: Vec<String> = row.get(9);
            let root_slot: Option<i64> = row.get(10);
            let lockouts_count: Option<i64> = row.get(11);
            let timestamp: Option<i64> = row.get(12);

            let vote_account_pubkey = Self::decode_pubkey(&vote_account_pubkey_str)?;
            let vote_signature = Self::decode_signature(&vote_signature_str)?;

            let vote_type = match vote_type_str.as_str() {
                "vote" => 0,
                "vote_state_update" => 1,
                _ => 0,
            };

            let vote_slots: Vec<u64> = vote_slots.into_iter().map(|s| s as u64).collect();

            let vote_hash = if let Some(hash) = vote_hash {
                Some(Self::decode_hash(&hash)?)
            } else {
                None
            };

            let authorized_voter = if let Some(av) = authorized_voter_str {
                Some(Self::decode_pubkey(&av)?)
            } else {
                None
            };

            let signer_pubkeys: Vec<[u8; 32]> = signer_pubkeys_arr
                .iter()
                .filter_map(|s| Self::decode_pubkey(s).ok())
                .collect();

            vote_transactions.push(ZkVoteTransaction {
                slot: slot as u64,
                vote_account_pubkey,
                vote_signature,
                vote_transaction,
                transaction_meta,
                vote_type,
                vote_slots,
                vote_hash,
                root_slot: root_slot.map(|s| s as u64),
                lockouts_count: lockouts_count.map(|c| c as u64),
                timestamp,
                authorized_voter,
                signer_pubkeys,
            });
        }

        Ok(vote_transactions)
    }

    fn decode_hash(hash_str: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let bytes = bs58::decode(hash_str).into_vec()?;
        if bytes.len() != 32 {
            return Err(format!("Invalid hash length: {}", bytes.len()).into());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }

    fn decode_pubkey(pubkey_str: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let bytes = bs58::decode(pubkey_str).into_vec()?;
        if bytes.len() != 32 {
            return Err(format!("Invalid pubkey length: {}", bytes.len()).into());
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes);
        Ok(pubkey)
    }

    fn decode_signature(sig_str: &str) -> Result<[u8; 64], Box<dyn Error>> {
        let bytes = bs58::decode(sig_str).into_vec()?;
        if bytes.len() != 64 {
            return Err(format!("Invalid signature length: {}", bytes.len()).into());
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes);
        Ok(signature)
    }

    /// Calculate account LtHash bytes (2048) matching zkVM algorithm.
    fn calculate_account_lthash_bytes(
        lamports: u64,
        owner: &[u8; 32],
        executable: bool,
        pubkey: &[u8; 32],
        data: &[u8],
    ) -> Vec<u8> {
        if lamports == 0 {
            let id = LatticeLtHash::identity();
            let mut out = Vec::with_capacity(2048);
            for &el in &id.0 {
                out.extend_from_slice(&el.to_le_bytes());
            }
            return out;
        }
        let mut hasher = Blake3Hasher::new();
        hasher.update(&lamports.to_le_bytes());
        hasher.update(data);
        hasher.update(&[executable as u8]);
        hasher.update(owner);
        hasher.update(pubkey);
        let lt = LatticeLtHash::with(&hasher);
        let mut out = Vec::with_capacity(2048);
        for &el in &lt.0 {
            out.extend_from_slice(&el.to_le_bytes());
        }
        out
    }

    /// Build ESR leaf hash for a validator entry using simplified scheme
    fn esr_leaf_hash(vote_account: &[u8; 32], active_stake: u64) -> [u8; 32] {
        let mut h = Blake3Hasher::new();
        h.update(vote_account);
        h.update(&(1u32).to_le_bytes());
        h.update(vote_account);
        h.update(&active_stake.to_le_bytes());
        h.update(&active_stake.to_le_bytes());
        *h.finalize().as_bytes()
    }

    fn build_esr_leaf_hashes(validators: &[ZkValidatorSetEntry]) -> Vec<[u8; 32]> {
        validators
            .iter()
            .map(|v| Self::esr_leaf_hash(&v.validator_vote_account, v.active_stake))
            .collect()
    }

    /// Build Merkle tree layers bottom-up; layers[0] are leaves
    fn build_merkle_layers(mut current: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
        let mut layers = Vec::new();
        layers.push(current.clone());
        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
            for pair in current.chunks(2) {
                let mut h = Blake3Hasher::new();
                h.update(&pair[0]);
                if pair.len() > 1 {
                    h.update(&pair[1]);
                } else {
                    h.update(&pair[0]);
                }
                next.push(*h.finalize().as_bytes());
            }
            layers.push(next.clone());
            current = next;
        }
        layers
    }

    fn build_vote_index_map(
        validators: &[ZkValidatorSetEntry],
    ) -> std::collections::HashMap<[u8; 32], usize> {
        let mut map = std::collections::HashMap::new();
        for (i, v) in validators.iter().enumerate() {
            map.insert(v.validator_vote_account, i);
        }
        map
    }

    /// Generate Merkle proof for a leaf index using prebuilt layers
    fn generate_merkle_proof_from_layers(
        layers: &Vec<Vec<[u8; 32]>>,
        mut index: usize,
    ) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        for level in 0..(layers.len() - 1) {
            let layer = &layers[level];
            let sibling = if index % 2 == 0 {
                if index + 1 < layer.len() {
                    index + 1
                } else {
                    index
                }
            } else {
                index - 1
            };
            proof.push(layer[sibling]);
            index /= 2;
        }
        proof
    }

    /// Fetch ESR (Epoch Staking Root) data from RPC-based table for a specific epoch
    pub async fn fetch_esr_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<ZkEpochValidatorMerkleRoot, Box<dyn Error>> {
        let client = self.pool.get().await?;

        // Fetch from the RPC-based ESR table (most reliable source)
        let query = "
            SELECT 
                epoch,
                merkle_root,
                total_active_stake,
                validator_count,
                top_n
            FROM solana.esr_roots_rpc
            WHERE epoch = $1
            ORDER BY created_at DESC
            LIMIT 1
        ";

        let row_opt = client.query_opt(query, &[&(epoch as i64)]).await?;

        match row_opt {
            Some(row) => {
                let epoch_val: i64 = row.get(0);
                let merkle_root_bytes: Vec<u8> = row.get(1);
                let total_active_stake: i64 = row.get(2);
                let validator_count: i32 = row.get(3);

                // Convert merkle root bytes to [u8; 32]
                let mut merkle_root = [0u8; 32];
                if merkle_root_bytes.len() == 32 {
                    merkle_root.copy_from_slice(&merkle_root_bytes);
                } else {
                    return Err(
                        format!("Invalid merkle root length: {}", merkle_root_bytes.len()).into(),
                    );
                }

                Ok(ZkEpochValidatorMerkleRoot {
                    epoch: epoch_val as u64,
                    merkle_root,
                    total_active_stake: total_active_stake as u64,
                    validator_count: validator_count as u32,
                })
            }
            None => Err(format!("ESR data not found for epoch {}", epoch).into()),
        }
    }

    /// Fetch validator set entries with stake accounts for a specific epoch
    pub async fn fetch_validator_set_for_epoch(
        &self,
        epoch: u64,
        limit: Option<usize>,
    ) -> Result<Vec<ZkValidatorSetEntry>, Box<dyn Error>> {
        let client = self.pool.get().await?;

        // Fetch validator stakes from the RPC-based table with correct column names
        let query = if let Some(limit) = limit {
            format!(
                "SELECT 
                    vote_account_pubkey,
                    total_active_stake,
                    node_pubkey,
                    commission
                FROM solana.esr_validator_stakes_rpc
                WHERE epoch = $1
                ORDER BY total_active_stake DESC
                LIMIT {}",
                limit
            )
        } else {
            "SELECT 
                vote_account_pubkey,
                total_active_stake,
                node_pubkey,
                commission
            FROM solana.esr_validator_stakes_rpc
            WHERE epoch = $1
            ORDER BY total_active_stake DESC"
                .to_string()
        };

        let rows = client.query(&query, &[&(epoch as i64)]).await?;

        let mut validator_set = Vec::new();
        for row in rows {
            let vote_account_str: String = row.get(0);
            let active_stake: i64 = row.get(1);
            let node_pubkey_opt: Option<String> = row.get(2);
            let commission_opt: Option<i16> = row.get(3);

            // Decode vote account pubkey
            let vote_account_bytes = bs58::decode(&vote_account_str).into_vec()?;
            if vote_account_bytes.len() != 32 {
                continue; // Skip invalid pubkeys
            }
            let mut vote_account = [0u8; 32];
            vote_account.copy_from_slice(&vote_account_bytes);

            // Use node_pubkey as authorized_voter if available, otherwise use vote account
            let authorized_voter = if let Some(node_str) = node_pubkey_opt {
                let node_bytes = bs58::decode(&node_str)
                    .into_vec()
                    .unwrap_or_else(|_| vec![0u8; 32]);
                if node_bytes.len() == 32 {
                    let mut node = [0u8; 32];
                    node.copy_from_slice(&node_bytes);
                    node
                } else {
                    vote_account // Fallback to vote account
                }
            } else {
                vote_account // Use vote account as fallback
            };

            validator_set.push(ZkValidatorSetEntry {
                validator_vote_account: vote_account,
                active_stake: active_stake as u64,
                commission_rate: commission_opt.unwrap_or(0) as u16,
                authorized_voter,
            });
        }

        Ok(validator_set)
    }

    /// Fetch pre-computed merkle proofs for validators from the database
    pub async fn fetch_validator_merkle_proofs(
        &self,
        epoch: u64,
        vote_accounts: &[[u8; 32]],
    ) -> Result<std::collections::HashMap<[u8; 32], Vec<[u8; 32]>>, Box<dyn Error>> {
        let client = self.pool.get().await?;

        let vote_pubkeys: Vec<String> = vote_accounts
            .iter()
            .map(|pk| bs58::encode(pk).into_string())
            .collect();

        if vote_pubkeys.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let query = "
            SELECT 
                mp.vote_account_pubkey,
                mp.merkle_proof,
                mp.leaf_index
            FROM solana.esr_merkle_proofs mp
            WHERE mp.epoch = $1 
                AND mp.vote_account_pubkey = ANY($2)
        ";

        let rows = client
            .query(query, &[&(epoch as i64), &vote_pubkeys])
            .await?;

        let mut proof_map = std::collections::HashMap::new();

        for row in rows {
            let vote_account_str: String = row.get(0);
            let merkle_proof_json: serde_json::Value = row.get(1);
            let _leaf_index: i32 = row.get(2);

            // Parse vote account pubkey
            let vote_account_bytes = bs58::decode(&vote_account_str).into_vec()?;
            if vote_account_bytes.len() != 32 {
                continue;
            }
            let mut vote_account = [0u8; 32];
            vote_account.copy_from_slice(&vote_account_bytes);

            // Parse merkle proof from JSON
            if let Some(proof_array) = merkle_proof_json["proof"].as_array() {
                let mut merkle_proof = Vec::new();
                for hash_hex in proof_array {
                    if let Some(hash_str) = hash_hex.as_str() {
                        if let Ok(hash_bytes) = hex::decode(hash_str) {
                            if hash_bytes.len() == 32 {
                                let mut hash = [0u8; 32];
                                hash.copy_from_slice(&hash_bytes);
                                merkle_proof.push(hash);
                            }
                        }
                    }
                }
                proof_map.insert(vote_account, merkle_proof);
            }
        }

        println!(
            "Fetched {} merkle proofs from database for epoch {}",
            proof_map.len(),
            epoch
        );
        Ok(proof_map)
    }

    /// Get the epoch number for a given slot using standard Solana epoch schedule
    pub async fn get_epoch_for_slot(
        &self,
        _client: &tokio_postgres::Client,
        slot: u64,
    ) -> Result<u64, Box<dyn Error>> {
        // Using standard mainnet epoch schedule: 432,000 slots per epoch
        const SLOTS_PER_EPOCH: u64 = 432_000;
        Ok(slot / SLOTS_PER_EPOCH)
    }

    async fn get_latest_slot_with_any_changes(
        &self,
        client: &tokio_postgres::Client,
    ) -> Result<u64, Box<dyn Error>> {
        let query = "
            SELECT ac.slot
            FROM solana.account_changes ac
            JOIN solana.slot_latest_status s ON s.slot = ac.slot
            WHERE s.status IN ('confirmed','rooted')
            GROUP BY ac.slot
            ORDER BY ac.slot DESC
            LIMIT 1
        ";
        let row = client.query_one(query, &[]).await?;
        let slot: i64 = row.get(0);
        Ok(slot as u64)
    }
}
