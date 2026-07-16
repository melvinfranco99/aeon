use aeon_core::{genesis_bits, Block, BlockHeader};
use aeon_crypto::Hash;

/// Fixed at a constant (rather than "now") so every Aeon node, anywhere,
/// independently derives the exact same genesis block hash and is
/// therefore on the same network. Roughly 2026-01-01T00:00:00Z.
pub const GENESIS_TIMESTAMP: u64 = 1_767_225_600;

/// Aeon's genesis block: no parents, no transactions (it mints nothing),
/// mined at the easiest possible difficulty.
pub fn genesis_block() -> Block {
    let header = BlockHeader {
        parents: vec![],
        merkle_root: Hash::ZERO,
        timestamp: GENESIS_TIMESTAMP,
        bits: genesis_bits(),
        nonce: 0,
    };
    Block {
        header,
        transactions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_is_deterministic() {
        assert_eq!(genesis_block().hash(), genesis_block().hash());
    }
}
