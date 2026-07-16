use std::collections::{HashMap, HashSet};

use aeon_core::Transaction;
use aeon_crypto::Hash;

/// An in-memory pool of transactions that have been validated but not yet
/// included in a block. Not persisted: a restarted node starts with an
/// empty mempool, same as most simple node implementations.
#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Hash, Transaction>,
}

impl Mempool {
    pub fn insert(&mut self, tx: Transaction) -> Hash {
        let txid = tx.txid();
        self.txs.insert(txid, tx);
        txid
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &Hash) -> Option<&Transaction> {
        self.txs.get(txid)
    }

    pub fn values(&self) -> impl Iterator<Item = &Transaction> {
        self.txs.values()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Removes every mempool transaction that was itself just confirmed, or
    /// that conflicts with a transaction in `confirmed` — spending the same
    /// transparent output, or (for a shielded bundle) reusing a nullifier
    /// `confirmed` already spent. Without this, a purely shielded
    /// transaction (no transparent inputs at all) would never be pruned by
    /// the transparent-only conflict check and would stay in the mempool
    /// forever, causing every later block template to fail re-validating it
    /// (its nullifier is already spent) and silently drop the *entire*
    /// mempool batch — see `docs/PRIVACY.md`.
    pub fn remove_conflicting(&mut self, confirmed: &[Transaction]) {
        let confirmed_txids: HashSet<Hash> = confirmed.iter().map(|tx| tx.txid()).collect();
        let spent_outpoints: HashSet<_> = confirmed
            .iter()
            .flat_map(|tx| tx.inputs.iter().map(|i| i.prev_out))
            .collect();
        let spent_nullifiers: HashSet<[u8; 32]> = confirmed
            .iter()
            .filter_map(|tx| tx.shielded.as_ref())
            .flat_map(|bundle| bundle.nullifier_bytes())
            .collect();

        self.txs.retain(|txid, tx| {
            if confirmed_txids.contains(txid) {
                return false;
            }
            if tx
                .inputs
                .iter()
                .any(|i| spent_outpoints.contains(&i.prev_out))
            {
                return false;
            }
            if let Some(bundle) = &tx.shielded {
                if bundle
                    .nullifier_bytes()
                    .iter()
                    .any(|nf| spent_nullifiers.contains(nf))
                {
                    return false;
                }
            }
            true
        });
    }
}
