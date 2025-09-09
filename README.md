## Twine Solana R0 Prover

A RISC Zero-based zero-knowledge prover for Solana consensus verification.

### Overview

This project implements a zero-knowledge proof system for verifying Solana consensus using RISC Zero's zkVM. It provides cryptographic proof of:

1. **Chain Continuity**: Slots are strictly consecutive and parent/child bank hashes are properly linked
2. **Bank Hash Correctness**: Each slot's bank hash is computed correctly from its components
3. **LtHash Transformation**: Account state changes are properly reflected in the lattice hash
4. **ESR Inclusion**: Vote accounts are proven to be in the Epoch Staking Root (ESR)
5. **Vote Validity**: Vote transactions are properly signed and vote for the correct slot/hash
6. **Supermajority**: Voting validators represent ≥2/3 of total active stake

### Architecture

- **Host Program** (`host/`): Fetches real data from PostgreSQL and coordinates proof generation
- **Guest Program** (`methods/guest/`): Runs inside the zkVM to verify consensus constraints
- **Library** (`lib/`): Shared data structures and utilities

### Key Features

- **Real Data Integration**: Fetches real data from PostgreSQL database (no mock/stub data)
- **Full Cryptographic Verification**: Complete Solana consensus verification
- **Ed25519 Signature Verification**: Mechanical verification using curve25519-dalek
- **Merkle Proof Verification**: ESR inclusion proofs for vote accounts
- **LtHash Verification**: Account state consistency using Solana's lattice hash
- **Database Integration**: Real-time data fetching from Solana database with connection pooling
- **Performance Optimized**: Connection pooling, TCP keepalive, and optimized query settings
- **RISC Zero Optimized**: Built for RISC Zero zkVM with proper no_std support

### Building
```bash
cargo build --release
```

### Running

The prover can be run in two modes:

1. **Validation Only** (fast, no proof generation):
```bash
cargo run --bin proof_generator -- \
    --start-slot 12345 \
    --pubkey ACCOUNT_PUBKEY_BASE58 \
    --db-url "host=localhost port=5432 user=username password=password dbname=solana"
```

2. **Full Proof Generation**:
```bash
cargo run --bin proof_generator -- \
    --start-slot 12345 \
    --pubkey ACCOUNT_PUBKEY_BASE58 \
    --db-url "host=localhost port=5432 user=username password=password dbname=solana" \
    --prove
```
3. **Example Data With Known Changes**:

```bash
 cargo run --release --bin proof_generator -- --start-slot 404118620 --pubkey 2GNuM5ksdfNxGNbwf2hrnND9FHgQsdju7vz8CyGd7Zjy --db-url "host=3.16.49.73 port=5432
  user=geyser_writer password=geyser_writer_password dbname=twine_solana_db" --prove
```

### Parameters

- `--start-slot`: Starting slot number for the proof
- `--pubkey`: Monitored account public keys (comma-separated, base58 encoded)
- `--db-url`: PostgreSQL database connection string
- `--output`: Output file for proof package (default: proof_package.json)
- `--prove`: Generate actual ZK proof (otherwise just validate)
- `--max-account-changes`: Maximum account changes to process (default: 10000)

### Database Requirements

The prover expects a PostgreSQL database with the following tables:
- `solana.bank_hash_components`: Bank hash data for each slot
- `solana.account_changes`: Account state changes with LtHash data
- `solana.vote_transactions`: Vote transaction data with full signatures
- `solana.esr_roots_rpc`: Epoch Staking Root data from RPC
- `solana.esr_validator_stakes_rpc`: Validator stake information
- `solana.esr_merkle_proofs`: Pre-computed merkle proofs for validators
- `solana.slot_latest_status`: Slot confirmation status

### Data Flow

1. **Database Connection**: Connect to PostgreSQL using provided credentials
2. **Data Fetching**: Fetch real slot data, account changes, vote transactions, ESR data
3. **Merkle Proof Generation**: Generate missing merkle proofs for vote accounts
4. **Validation**: Run preflight validation of all consensus constraints
5. **Proof Generation**: Generate RISC Zero proof if requested
6. **Verification**: Verify proof and extract public commitments

### Output

The prover generates:
1. **Debug Package** (JSON): Summary of processed data
2. **ZK Proof** (when `--prove` is used): Cryptographic proof of consensus validity
3. **Public Commitments**: Verified public outputs including slot range, bank hashes, and validation status

### Verification Constraints

The zkVM guest program enforces these consensus constraints:

1. **Chain Continuity**: `curr_slot.parent_bank_hash == prev_slot.bank_hash`
2. **Bank Hash**: `bank_hash = hash(hash(parent_bank_hash, sig_count, last_blockhash), cumulative_lthash)`
3. **LtHash Transform**: `new_cumulative_lthash = old_cumulative_lthash - old_account_lthashes + new_account_lthashes`
4. **ESR Inclusion**: Each vote account has a valid merkle proof to the ESR root
5. **Vote Validity**: Each vote is Ed25519 signed and votes for the target slot/hash
6. **Supermajority**: Voting stake ≥ 2/3 of total active stake

### Technical Implementation

This RISC Zero implementation includes:

- **RISC Zero APIs**: Uses `risc0_zkvm` for proof generation and verification
- **Ed25519 Verification**: Uses `curve25519-dalek` for cryptographic signature verification
- **No_std Support**: Proper `no_std` support with `alloc` for guest program
- **Database Integration**: PostgreSQL integration for real-time data fetching
- **Consensus Verification**: Complete implementation of Solana consensus constraints

### Example Usage

```bash
# Validate consensus for a specific account and slot range
cargo run --bin proof_generator -- \
    --start-slot 280000000 \
    --pubkey 11111111111111111111111111111112 \
    --db-url "host=db.example.com port=5432 user=readonly password=secret dbname=solana"

# Generate full ZK proof
cargo run --bin proof_generator -- \
    --start-slot 280000000 \
    --pubkey 11111111111111111111111111111112 \
    --db-url "host=db.example.com port=5432 user=readonly password=secret dbname=solana" \
    --prove \
    --output consensus_proof.json
```

### Development Mode

For faster iteration during development, use RISC Zero's dev mode:

```bash
RISC0_DEV_MODE=1 cargo run --bin proof_generator -- [arguments]
```

### License
Use only with written permision of Cedro Finance Limited