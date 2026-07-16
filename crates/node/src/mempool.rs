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

    /// Removes every mempool transaction that conflicts with (spends the
    /// same input as) any transaction in `confirmed`, e.g. because a new
    /// block just confirmed one version of that spend.
    pub fn remove_conflicting(&mut self, confirmed: &[Transaction]) {
        let spent: HashSet<_> = confirmed
            .iter()
            .flat_map(|tx| tx.inputs.iter().map(|i| i.prev_out))
            .collect();
        self.txs
            .retain(|_, tx| !tx.inputs.iter().any(|i| spent.contains(&i.prev_out)));
    }
}
