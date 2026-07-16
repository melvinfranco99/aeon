use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{OutPoint, Transaction, TxOutput};

/// An unspent transaction output plus the bookkeeping needed to validate
/// spends of it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub output: TxOutput,
    pub is_coinbase: bool,
}

/// Read-only lookup of unspent outputs. Implemented by [`UtxoSet`] (used in
/// tests and as a simple reference implementation) and by
/// `aeon_storage::Store` (the real, persistent ledger), so validation code
/// in this crate stays storage-agnostic.
pub trait UtxoView {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry>;
}

/// An in-memory view of the UTXO set. `aeon-storage` provides a persistent,
/// `sled`-backed implementation with the same semantics; both implement
/// [`UtxoView`] so validation code stays storage-agnostic.
#[derive(Clone, Debug, Default)]
pub struct UtxoSet {
    entries: HashMap<OutPoint, UtxoEntry>,
}

impl UtxoView for UtxoSet {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.get(outpoint).cloned()
    }
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        self.entries.get(outpoint)
    }

    pub fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) {
        self.entries.insert(outpoint, entry);
    }

    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.entries.remove(outpoint)
    }

    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.entries.contains_key(outpoint)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Applies a validated transaction: removes spent inputs, inserts new
    /// outputs. Caller must have already validated the transaction with
    /// [`crate::validation::verify_transaction`].
    pub fn apply_transaction(&mut self, tx: &Transaction, is_coinbase: bool) {
        if !is_coinbase {
            for input in &tx.inputs {
                self.remove(&input.prev_out);
            }
        }
        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            self.insert(
                OutPoint {
                    txid,
                    index: index as u32,
                },
                UtxoEntry {
                    output: output.clone(),
                    is_coinbase,
                },
            );
        }
    }
}
