use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte BLAKE3 digest used throughout Aeon for block hashes, transaction
/// ids and merkle roots.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Interprets the hash as a big-endian unsigned integer, used to compare
    /// a block's PoW digest against the difficulty target.
    pub fn to_u256_be(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

/// Hashes arbitrary bytes with BLAKE3, Aeon's proof-of-work and general
/// purpose hash function (used in place of Kaspa's kHeavyHash).
pub fn blake3_hash(data: &[u8]) -> Hash {
    Hash(*blake3::hash(data).as_bytes())
}

/// Merkle root over a list of transaction ids. Uses a simple binary merkle
/// tree with BLAKE3; an odd node at any level is duplicated (Bitcoin-style).
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0].0);
                buf[32..].copy_from_slice(&pair[1].0);
                blake3_hash(&buf)
            })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_single_leaf_is_itself() {
        let h = blake3_hash(b"tx1");
        assert_eq!(merkle_root(&[h]), h);
    }

    #[test]
    fn merkle_root_is_order_sensitive() {
        let a = blake3_hash(b"tx1");
        let b = blake3_hash(b"tx2");
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }
}
