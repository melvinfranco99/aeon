use aeon_crypto::{blake3_hash, merkle_root, Hash, PublicKey, SchnorrSignature};
use serde::{Deserialize, Serialize};

/// A reference to a specific output of a previous transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Hash,
    pub index: u32,
}

/// A coin-spending input: which output it spends, and the proof of
/// ownership (public key + Schnorr signature over the transaction).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_out: OutPoint,
    pub pubkey: PublicKey,
    pub signature: SchnorrSignature,
}

/// A newly created coin, locked to whoever can prove ownership of
/// `pubkey_hash` (Aeon's simplified P2PKH-style locking condition).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    /// Amount in quarks (1 AEON = 100_000_000 quarks).
    pub amount: u64,
    pub pubkey_hash: [u8; 20],
}

/// An Aeon transaction. Coinbase transactions (which mint new coins) have
/// no inputs.
///
/// Coinbase transactions **must** set `lock_time` to the block's chain
/// height (`GhostdagData::blue_score`), analogous to Bitcoin's BIP34: since
/// a coinbase has no inputs to make it unique, two blocks paying the same
/// reward to the same address would otherwise produce byte-identical
/// coinbase transactions and thus colliding txids, silently overwriting one
/// block's reward with the other's in the UTXO set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u64,
}

impl Transaction {
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// The data that both the transaction id and each input's signature are
    /// computed over: input outpoints and output contents, but *not* the
    /// unlocking signatures/pubkeys themselves. This makes the txid stable
    /// under re-signing and immune to signature malleability, the same way
    /// SegWit excludes witness data from Bitcoin's txid.
    pub fn signing_data(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for input in &self.inputs {
            buf.extend_from_slice(input.prev_out.txid.as_bytes());
            buf.extend_from_slice(&input.prev_out.index.to_le_bytes());
        }
        for output in &self.outputs {
            buf.extend_from_slice(&output.amount.to_le_bytes());
            buf.extend_from_slice(&output.pubkey_hash);
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    pub fn txid(&self) -> Hash {
        blake3_hash(&self.signing_data())
    }

    pub fn total_output_amount(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }
}

/// A BlockDAG block header. Unlike a single-parent Bitcoin header, Aeon
/// headers may reference multiple `parents`, forming a DAG rather than a
/// chain. GHOSTDAG bookkeeping (blue score/work, selected parent) is
/// deterministically derived by every honest node from this structure and
/// is *not* itself part of the header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parents: Vec<Hash>,
    pub merkle_root: Hash,
    pub timestamp: u64,
    /// Compact difficulty target encoding (Bitcoin-style "nBits").
    pub bits: u32,
    pub nonce: u64,
}

impl BlockHeader {
    pub fn serialize_for_hashing(&self) -> Vec<u8> {
        bincode::serialize(self).expect("header serialization cannot fail")
    }

    /// The block's proof-of-work identity/hash: BLAKE3 of the header, which
    /// must be below the difficulty target derived from `bits`.
    pub fn hash(&self) -> Hash {
        blake3_hash(&self.serialize_for_hashing())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn compute_merkle_root(&self) -> Hash {
        let txids: Vec<Hash> = self.transactions.iter().map(|tx| tx.txid()).collect();
        merkle_root(&txids)
    }

    pub fn coinbase(&self) -> Option<&Transaction> {
        self.transactions.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_ignores_signature_and_pubkey_bytes() {
        let kp1 = aeon_crypto::KeyPair::generate();
        let kp2 = aeon_crypto::KeyPair::generate();
        let out = TxOutput {
            amount: 42,
            pubkey_hash: [1u8; 20],
        };
        let base_input = TxInput {
            prev_out: OutPoint {
                txid: Hash::ZERO,
                index: 0,
            },
            pubkey: kp1.public_key(),
            signature: kp1.sign(b"whatever"),
        };
        let mut tx_a = Transaction {
            inputs: vec![base_input.clone()],
            outputs: vec![out.clone()],
            lock_time: 0,
        };
        let mut tx_b = tx_a.clone();
        tx_b.inputs[0].pubkey = kp2.public_key();
        tx_b.inputs[0].signature = kp2.sign(b"different signature data");
        assert_eq!(tx_a.txid(), tx_b.txid());

        tx_a.outputs[0].amount = 43;
        assert_ne!(tx_a.txid(), tx_b.txid());
        let _ = &mut tx_b; // silence unused mut warning if any
    }
}
