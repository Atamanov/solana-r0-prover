/// Core types that work in both std and no_std environments (ZKVM compatible)
use serde::{Deserialize, Serialize};

#[cfg(feature = "zkvm")]
use alloc::string::String;
#[cfg(feature = "zkvm")]
use alloc::vec::Vec;

/// Hash type (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("Invalid hash length");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Hash(arr))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_string(&self) -> String {
        hex::encode(self.0)
    }
}

/// Pubkey type (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("Invalid pubkey length");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Pubkey(arr))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// Re-export Solana's LtHash
pub use solana_lattice_hash::lt_hash::LtHash;

/// SHA256 hasher implementation for ZKVM
pub struct Hasher {
    data: Vec<u8>,
}

impl Hasher {
    pub fn new() -> Self {
        Hasher { data: Vec::new() }
    }

    pub fn hash(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub fn result(&self) -> Hash {
        #[cfg(feature = "zkvm")]
        {
            use sha2_risczero::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&self.data);
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash(bytes)
        }
        #[cfg(not(feature = "zkvm"))]
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&self.data);
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash(bytes)
        }
    }
}

/// Hash multiple byte arrays together (like Solana's hashv)
pub fn hashv(data: &[&[u8]]) -> Hash {
    #[cfg(feature = "zkvm")]
    {
        use sha2_risczero::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for bytes in data {
            hasher.update(bytes);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash(bytes)
    }
    #[cfg(not(feature = "zkvm"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for bytes in data {
            hasher.update(bytes);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash(bytes)
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}
