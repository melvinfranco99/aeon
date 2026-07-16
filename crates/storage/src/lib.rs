//! Persistent storage for an Aeon node, backed by `sled` (a pure-Rust
//! embedded database, chosen so the project builds cleanly on Windows
//! without a C/C++ toolchain).
//!
//! Stores raw blocks, each block's derived GHOSTDAG data, and a UTXO ledger.
//!
//! **Scope note:** the ledger (UTXO set) is derived only from transactions
//! on the *selected-parent chain* (GHOSTDAG's analogue of Bitcoin's "best
//! chain"), the same way Bitcoin's UTXO set only reflects the best chain.
//! Kaspa's real design also incorporates merge-set (including red) blocks'
//! transactions into a single total order, specifically to resist
//! transaction censorship by whoever produces the selected chain. Skipping
//! that here is a deliberate scope reduction (documented in
//! `docs/CONSENSUS.md`): the BlockDAG/GHOSTDAG *security and tie-breaking*
//! machinery is fully real, but ledger bookkeeping follows the selected
//! chain only, which keeps reorg handling as simple and well-understood as
//! Bitcoin's.

use std::path::Path;

use aeon_core::{
    bits_to_target, compute_ghostdag_data, work_from_target, Block, DaaWindowEntry, GhostdagData,
    GhostdagParams, GhostdagStore, OutPoint, UtxoEntry,
};
use aeon_crypto::Hash;
use aeon_shielded::CommitmentFrontier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How many of the most recent per-block anchors (note commitment tree
/// roots) a shielded spend's proof may be built against. Tolerates a
/// prover being a little behind the chain tip without holding an unbounded
/// history; Aeon's own choice (documented in `docs/PRIVACY.md`), analogous
/// to Zcash's own anchor-recency allowance.
const RECENT_ANCHOR_WINDOW: usize = 100;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    #[error("block {0} already exists")]
    AlreadyExists(Hash),
    #[error("genesis has already been set")]
    GenesisAlreadySet,
    #[error("missing parent block {0}")]
    MissingParent(Hash),
    #[error("a non-genesis block must declare at least one parent")]
    MissingParents,
    #[error("store has no genesis block yet")]
    NoGenesis,
}

#[derive(Serialize, Deserialize, Default)]
struct UndoRecord {
    /// UTXOs consumed by this block's transactions, to be restored if the
    /// block is later undone by a reorg.
    removed: Vec<(OutPoint, UtxoEntry)>,
    /// UTXOs created by this block's transactions, to be deleted if the
    /// block is later undone by a reorg.
    added: Vec<OutPoint>,
    /// Nullifiers this block's shielded bundles added to the seen-set, to
    /// be removed if the block is later undone.
    shielded_nullifiers_added: Vec<[u8; 32]>,
    /// The note commitment frontier's serialized state *before* this block
    /// was applied, restored verbatim on undo (cheaper and much simpler
    /// than incrementally rewinding the tree).
    shielded_frontier_before: Vec<u8>,
    /// The recent-anchor history's state *before* this block, restored
    /// verbatim on undo for the same reason.
    shielded_anchor_history_before: Vec<u8>,
}

pub struct Store {
    blocks: sled::Tree,
    ghostdag: sled::Tree,
    undo: sled::Tree,
    utxo: sled::Tree,
    meta: sled::Tree,
    /// The set of current DAG tips (blocks with no known children), keyed
    /// by hash with an empty value. A block template should reference
    /// *all* of these as parents — that's what makes Aeon a BlockDAG
    /// rather than a hidden single chain.
    tips: sled::Tree,
    /// Nullifiers of every spent shielded note ever confirmed on the
    /// selected chain (see `docs/PRIVACY.md`), keyed by the 32-byte
    /// nullifier with an empty value — Aeon's shielded-pool analogue of
    /// double-spend prevention.
    shielded_nullifiers: sled::Tree,
    /// Small metadata tree holding the current note commitment frontier
    /// (key `"frontier"`) and the recent-anchor history (key `"anchors"`).
    shielded_meta: sled::Tree,
}

const META_TIP_KEY: &[u8] = b"tip";
const META_GENESIS_KEY: &[u8] = b"genesis";

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        Ok(Store {
            blocks: db.open_tree("blocks")?,
            ghostdag: db.open_tree("ghostdag")?,
            undo: db.open_tree("undo")?,
            utxo: db.open_tree("utxo")?,
            meta: db.open_tree("meta")?,
            tips: db.open_tree("tips")?,
            shielded_nullifiers: db.open_tree("shielded_nullifiers")?,
            shielded_meta: db.open_tree("shielded_meta")?,
        })
    }

    /// An in-memory store, useful for tests and short-lived tools.
    pub fn open_temporary() -> Result<Self, StoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Store {
            blocks: db.open_tree("blocks")?,
            ghostdag: db.open_tree("ghostdag")?,
            undo: db.open_tree("undo")?,
            utxo: db.open_tree("utxo")?,
            meta: db.open_tree("meta")?,
            tips: db.open_tree("tips")?,
            shielded_nullifiers: db.open_tree("shielded_nullifiers")?,
            shielded_meta: db.open_tree("shielded_meta")?,
        })
    }

    // ---- shielded pool -------------------------------------------------

    pub fn shielded_nullifier_seen(&self, nullifier: &[u8; 32]) -> bool {
        self.shielded_nullifiers
            .contains_key(nullifier)
            .unwrap_or(false)
    }

    fn current_frontier(&self) -> CommitmentFrontier {
        match self.shielded_meta.get(b"frontier").ok().flatten() {
            Some(bytes) => {
                CommitmentFrontier::from_bytes(&bytes).expect("stored frontier is well-formed")
            }
            None => CommitmentFrontier::empty(),
        }
    }

    fn recent_anchor_history(&self) -> Vec<[u8; 32]> {
        match self.shielded_meta.get(b"anchors").ok().flatten() {
            Some(bytes) => bincode::deserialize(&bytes).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// The current note commitment tree anchor — what a freshly-built
    /// shielded spend should prove against.
    pub fn shielded_anchor(&self) -> [u8; 32] {
        self.current_frontier().root_bytes()
    }

    /// Whether `anchor` is the current anchor or one of the last
    /// [`RECENT_ANCHOR_WINDOW`] anchors, i.e. recent enough for a shielded
    /// spend to be built against without the prover needing to be
    /// perfectly caught up to the chain tip.
    pub fn is_recent_shielded_anchor(&self, anchor: &[u8; 32]) -> bool {
        self.recent_anchor_history().iter().any(|a| a == anchor)
    }

    /// All current DAG tips (blocks with no known children yet).
    pub fn tips(&self) -> Vec<Hash> {
        self.tips
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .map(|k| hash_from_ivec(&k))
            .collect()
    }

    // ---- basic accessors -------------------------------------------------

    pub fn has_block(&self, hash: &Hash) -> bool {
        self.blocks.contains_key(hash.as_bytes()).unwrap_or(false)
    }

    pub fn get_block(&self, hash: &Hash) -> Option<Block> {
        let bytes = self.blocks.get(hash.as_bytes()).ok().flatten()?;
        bincode::deserialize(&bytes).ok()
    }

    pub fn get_ghostdag(&self, hash: &Hash) -> Option<GhostdagData> {
        let bytes = self.ghostdag.get(hash.as_bytes()).ok().flatten()?;
        bincode::deserialize(&bytes).ok()
    }

    pub fn tip(&self) -> Option<Hash> {
        let bytes = self.meta.get(META_TIP_KEY).ok().flatten()?;
        Some(hash_from_ivec(&bytes))
    }

    pub fn genesis_hash(&self) -> Option<Hash> {
        let bytes = self.meta.get(META_GENESIS_KEY).ok().flatten()?;
        Some(hash_from_ivec(&bytes))
    }

    pub fn get_tip_block(&self) -> Option<Block> {
        self.get_block(&self.tip()?)
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        let key = bincode::serialize(outpoint).ok()?;
        let bytes = self.utxo.get(key).ok().flatten()?;
        bincode::deserialize(&bytes).ok()
    }

    /// All UTXOs currently locked to a given pubkey hash. Scans the whole
    /// UTXO tree; adequate for a hobby/testnet-scale ledger.
    pub fn utxos_for_pubkey_hash(&self, pubkey_hash: &[u8; 20]) -> Vec<(OutPoint, UtxoEntry)> {
        self.utxo
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(k, v)| {
                let outpoint: OutPoint = bincode::deserialize(&k).ok()?;
                let entry: UtxoEntry = bincode::deserialize(&v).ok()?;
                if &entry.output.pubkey_hash == pubkey_hash {
                    Some((outpoint, entry))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn balance_for_pubkey_hash(&self, pubkey_hash: &[u8; 20]) -> u64 {
        self.utxos_for_pubkey_hash(pubkey_hash)
            .iter()
            .map(|(_, entry)| entry.output.amount)
            .sum()
    }

    /// Timestamps/bits of the most recent `size` blocks along the selected
    /// parent chain ending at `tip`, oldest first — the window the
    /// difficulty adjustment algorithm needs.
    pub fn daa_window(&self, tip: &Hash, size: usize) -> Vec<DaaWindowEntry> {
        let mut window = Vec::with_capacity(size);
        let mut current = *tip;
        for _ in 0..size {
            let Some(block) = self.get_block(&current) else {
                break;
            };
            window.push(DaaWindowEntry {
                timestamp: block.header.timestamp,
                bits: block.header.bits,
            });
            let Some(data) = self.get_ghostdag(&current) else {
                break;
            };
            match data.selected_parent {
                Some(sp) => current = sp,
                None => break,
            }
        }
        window.reverse();
        window
    }

    /// Every block on the selected parent chain with height (blue score)
    /// strictly greater than `since_height`, oldest first — what a wallet's
    /// `/shielded-actions` scan walks to discover its own notes and rebuild
    /// its local commitment tree (see `aeon_shielded::witness_for_position`).
    pub fn selected_chain_blocks_since(&self, since_height: u64) -> Vec<(u64, Block)> {
        let mut collected = Vec::new();
        let Some(mut current) = self.tip() else {
            return collected;
        };
        while let Some(data) = self.get_ghostdag(&current) {
            if data.blue_score <= since_height {
                break;
            }
            let Some(block) = self.get_block(&current) else {
                break;
            };
            collected.push((data.blue_score, block));
            match data.selected_parent {
                Some(sp) => current = sp,
                None => break,
            }
        }
        collected.reverse();
        collected
    }

    /// The difficulty ("bits") the next block extending `tip` should use.
    pub fn next_bits_for_new_block(&self, tip: &Hash) -> u32 {
        let window = self.daa_window(tip, aeon_core::difficulty::DAA_WINDOW_SIZE);
        aeon_core::next_bits(&window)
    }

    // ---- mutation ----------------------------------------------------

    pub fn insert_genesis(&self, block: Block) -> Result<GhostdagData, StoreError> {
        if self.tip().is_some() {
            return Err(StoreError::GenesisAlreadySet);
        }
        let hash = block.hash();
        let ghostdag_data = GhostdagData::genesis();
        self.put_block(&hash, &block)?;
        self.put_ghostdag(&hash, &ghostdag_data)?;
        let undo = self.apply_block_to_ledger(&block);
        self.put_undo(&hash, &undo)?;
        self.meta.insert(META_TIP_KEY, hash.as_bytes())?;
        self.meta.insert(META_GENESIS_KEY, hash.as_bytes())?;
        self.tips.insert(hash.as_bytes(), &[])?;
        Ok(ghostdag_data)
    }

    /// Computes what a candidate block's GHOSTDAG data *would* be, without
    /// persisting anything. Lets a caller (the node's block-acceptance
    /// logic) learn the block's `blue_score` — needed to validate its
    /// coinbase reward — before deciding whether to accept and store it.
    pub fn preview_ghostdag_data(
        &self,
        hash: &Hash,
        parents: &[Hash],
        bits: u32,
        params: &GhostdagParams,
    ) -> Result<GhostdagData, StoreError> {
        for p in parents {
            if !self.has_block(p) {
                return Err(StoreError::MissingParent(*p));
            }
        }
        let own_work = work_from_target(bits_to_target(bits));
        Ok(compute_ghostdag_data(
            &StoreGhostdagView(self),
            hash,
            parents,
            own_work,
            params,
        ))
    }

    /// Validates parent linkage, computes GHOSTDAG data, persists the block,
    /// and reorgs the ledger onto this block if it becomes the new selected
    /// tip. Assumes the caller has already validated the block's
    /// transactions (signatures, coinbase allowance) via
    /// `aeon_core::validation` — this method only performs GHOSTDAG
    /// coloring and UTXO bookkeeping, not consensus/script validation.
    pub fn insert_block(
        &self,
        block: Block,
        params: &GhostdagParams,
    ) -> Result<GhostdagData, StoreError> {
        let hash = block.hash();
        if self.has_block(&hash) {
            return Err(StoreError::AlreadyExists(hash));
        }
        let parents = block.header.parents.clone();
        if parents.is_empty() {
            return Err(StoreError::MissingParents);
        }
        for p in &parents {
            if !self.has_block(p) {
                return Err(StoreError::MissingParent(*p));
            }
        }

        let own_work = work_from_target(bits_to_target(block.header.bits));
        self.put_block(&hash, &block)?;
        let ghostdag_data =
            compute_ghostdag_data(&StoreGhostdagView(self), &hash, &parents, own_work, params);
        self.put_ghostdag(&hash, &ghostdag_data)?;

        for p in &parents {
            self.tips.remove(p.as_bytes())?;
        }
        self.tips.insert(hash.as_bytes(), &[])?;

        let current_tip = self.tip().ok_or(StoreError::NoGenesis)?;
        let tip_data = self
            .get_ghostdag(&current_tip)
            .expect("tip must have GHOSTDAG data");

        let becomes_tip = ghostdag_data.blue_work > tip_data.blue_work
            || (ghostdag_data.blue_work == tip_data.blue_work && hash < current_tip);

        if becomes_tip {
            self.reorg_to(&hash, current_tip)?;
            self.meta.insert(META_TIP_KEY, hash.as_bytes())?;
        }

        Ok(ghostdag_data)
    }

    fn reorg_to(&self, new_tip: &Hash, old_tip: Hash) -> Result<(), StoreError> {
        let fork_point = self.find_fork_point(old_tip, *new_tip);

        let undo_list = self.collect_chain_back_to(old_tip, fork_point); // newest-first
        for h in undo_list {
            if let Some(undo) = self.get_undo(&h)? {
                self.undo_block_from_ledger(&undo)?;
                self.undo.remove(h.as_bytes())?;
            }
        }

        let mut apply_list = self.collect_chain_back_to(*new_tip, fork_point); // newest-first
        apply_list.reverse(); // oldest-first
        for h in apply_list {
            let block = self
                .get_block(&h)
                .expect("block on selected chain must exist");
            let undo = self.apply_block_to_ledger(&block);
            self.put_undo(&h, &undo)?;
        }
        Ok(())
    }

    fn find_fork_point(&self, a: Hash, b: Hash) -> Hash {
        let mut a_cur = a;
        let mut b_cur = b;
        loop {
            if a_cur == b_cur {
                return a_cur;
            }
            let a_score = self.get_ghostdag(&a_cur).expect("must exist").blue_score;
            let b_score = self.get_ghostdag(&b_cur).expect("must exist").blue_score;
            if a_score >= b_score {
                a_cur = self
                    .get_ghostdag(&a_cur)
                    .unwrap()
                    .selected_parent
                    .expect("reached genesis without finding fork point");
            } else {
                b_cur = self
                    .get_ghostdag(&b_cur)
                    .unwrap()
                    .selected_parent
                    .expect("reached genesis without finding fork point");
            }
        }
    }

    /// Blocks from `from` back to (but excluding) `back_to`, newest-first.
    fn collect_chain_back_to(&self, from: Hash, back_to: Hash) -> Vec<Hash> {
        let mut chain = Vec::new();
        let mut current = from;
        while current != back_to {
            chain.push(current);
            current = self
                .get_ghostdag(&current)
                .expect("block on chain must exist")
                .selected_parent
                .expect("reached genesis before finding ancestor");
        }
        chain
    }

    fn apply_block_to_ledger(&self, block: &Block) -> UndoRecord {
        let mut removed = Vec::new();
        let mut added = Vec::new();

        let frontier_before = self.current_frontier();
        let anchor_history_before = self.recent_anchor_history();
        let shielded_frontier_before = frontier_before.to_bytes();
        let shielded_anchor_history_before =
            bincode::serialize(&anchor_history_before).expect("anchor history serializes");

        let mut frontier = frontier_before;
        let mut anchor_history = anchor_history_before;
        let mut shielded_nullifiers_added = Vec::new();

        for (i, tx) in block.transactions.iter().enumerate() {
            let is_coinbase = i == 0;
            if !is_coinbase {
                for input in &tx.inputs {
                    if let Some(entry) = self.get_utxo(&input.prev_out) {
                        removed.push((input.prev_out, entry));
                        self.delete_utxo(&input.prev_out);
                    }
                }
            }
            let txid = tx.txid();
            for (index, output) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    index: index as u32,
                };
                self.put_utxo(
                    &outpoint,
                    &UtxoEntry {
                        output: output.clone(),
                        is_coinbase,
                    },
                );
                added.push(outpoint);
            }

            if let Some(bundle) = &tx.shielded {
                for nf in bundle.nullifier_bytes() {
                    self.shielded_nullifiers
                        .insert(nf, &[])
                        .expect("sled insert");
                    shielded_nullifiers_added.push(nf);
                }
                for cmx in bundle.note_commitment_bytes() {
                    frontier
                        .append(cmx)
                        .expect("a proven bundle's own commitments are always valid");
                }
            }
        }

        // One anchor entry per block (even with no shielded activity, so
        // the window covers "the last N blocks", not "the last N blocks
        // that happened to contain shielded activity").
        anchor_history.push(frontier.root_bytes());
        if anchor_history.len() > RECENT_ANCHOR_WINDOW {
            let excess = anchor_history.len() - RECENT_ANCHOR_WINDOW;
            anchor_history.drain(0..excess);
        }

        self.shielded_meta
            .insert(b"frontier", frontier.to_bytes())
            .expect("sled insert");
        self.shielded_meta
            .insert(
                b"anchors",
                bincode::serialize(&anchor_history).expect("anchor history serializes"),
            )
            .expect("sled insert");

        UndoRecord {
            removed,
            added,
            shielded_nullifiers_added,
            shielded_frontier_before,
            shielded_anchor_history_before,
        }
    }

    fn undo_block_from_ledger(&self, undo: &UndoRecord) -> Result<(), StoreError> {
        for outpoint in &undo.added {
            self.delete_utxo(outpoint);
        }
        for (outpoint, entry) in &undo.removed {
            self.put_utxo(outpoint, entry);
        }
        for nf in &undo.shielded_nullifiers_added {
            self.shielded_nullifiers.remove(nf)?;
        }
        self.shielded_meta
            .insert(b"frontier", undo.shielded_frontier_before.clone())?;
        self.shielded_meta
            .insert(b"anchors", undo.shielded_anchor_history_before.clone())?;
        Ok(())
    }

    // ---- low-level tree helpers -------------------------------------

    fn put_block(&self, hash: &Hash, block: &Block) -> Result<(), StoreError> {
        let bytes = bincode::serialize(block)?;
        self.blocks.insert(hash.as_bytes(), bytes)?;
        Ok(())
    }

    fn put_ghostdag(&self, hash: &Hash, data: &GhostdagData) -> Result<(), StoreError> {
        let bytes = bincode::serialize(data)?;
        self.ghostdag.insert(hash.as_bytes(), bytes)?;
        Ok(())
    }

    fn put_undo(&self, hash: &Hash, undo: &UndoRecord) -> Result<(), StoreError> {
        let bytes = bincode::serialize(undo)?;
        self.undo.insert(hash.as_bytes(), bytes)?;
        Ok(())
    }

    fn get_undo(&self, hash: &Hash) -> Result<Option<UndoRecord>, StoreError> {
        match self.undo.get(hash.as_bytes())? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put_utxo(&self, outpoint: &OutPoint, entry: &UtxoEntry) {
        let key = bincode::serialize(outpoint).expect("outpoint serializes");
        let value = bincode::serialize(entry).expect("utxo entry serializes");
        self.utxo.insert(key, value).expect("sled insert");
    }

    fn delete_utxo(&self, outpoint: &OutPoint) {
        let key = bincode::serialize(outpoint).expect("outpoint serializes");
        self.utxo.remove(key).expect("sled remove");
    }
}

impl aeon_core::UtxoView for Store {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        Store::get_utxo(self, outpoint)
    }
}

impl aeon_core::ShieldedPoolView for Store {
    fn shielded_nullifier_seen(&self, nullifier: &[u8; 32]) -> bool {
        Store::shielded_nullifier_seen(self, nullifier)
    }
    fn is_recent_shielded_anchor(&self, anchor: &[u8; 32]) -> bool {
        Store::is_recent_shielded_anchor(self, anchor)
    }
}

fn hash_from_ivec(ivec: &sled::IVec) -> Hash {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(ivec.as_ref());
    Hash::from(bytes)
}

struct StoreGhostdagView<'a>(&'a Store);

impl<'a> GhostdagStore for StoreGhostdagView<'a> {
    fn parents(&self, block: &Hash) -> Vec<Hash> {
        self.0
            .get_block(block)
            .map(|b| b.header.parents)
            .unwrap_or_default()
    }

    fn ghostdag_data(&self, block: &Hash) -> Option<GhostdagData> {
        self.0.get_ghostdag(block)
    }

    fn header_work(&self, block: &Hash) -> u128 {
        self.0
            .get_block(block)
            .map(|b| work_from_target(bits_to_target(b.header.bits)))
            .unwrap_or(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeon_core::{genesis_bits, BlockHeader, Transaction, TxOutput};
    use aeon_crypto::KeyPair;

    fn make_block(parents: Vec<Hash>, transactions: Vec<Transaction>, nonce: u64) -> Block {
        let mut header = BlockHeader {
            parents,
            merkle_root: Hash::ZERO,
            timestamp: nonce, // distinct fake timestamps keep block hashes unique too
            bits: genesis_bits(),
            nonce,
        };
        let dummy = Block {
            header: header.clone(),
            transactions: transactions.clone(),
        };
        header.merkle_root = dummy.compute_merkle_root();
        Block {
            header,
            transactions,
        }
    }

    fn coinbase_tx(to: &KeyPair, amount: u64, height: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![TxOutput {
                amount,
                pubkey_hash: to.public_key().pubkey_hash(),
            }],
            // lock_time = chain height, so coinbases paying the same
            // amount to the same address at different heights don't
            // collide on txid (see the doc comment on `Transaction`).
            lock_time: height,
            shielded: None,
        }
    }

    #[test]
    fn genesis_then_linear_chain_updates_tip_and_balances() {
        let store = Store::open_temporary().unwrap();
        let miner = KeyPair::generate();

        let genesis = make_block(vec![], vec![], 0);
        let genesis_hash = genesis.hash();
        store.insert_genesis(genesis).unwrap();
        assert_eq!(store.tip(), Some(genesis_hash));

        let params = GhostdagParams::default();
        let block1 = make_block(vec![genesis_hash], vec![coinbase_tx(&miner, 1000, 1)], 1);
        let block1_hash = block1.hash();
        store.insert_block(block1, &params).unwrap();

        assert_eq!(store.tip(), Some(block1_hash));
        assert_eq!(
            store.balance_for_pubkey_hash(&miner.public_key().pubkey_hash()),
            1000
        );
    }

    #[test]
    fn tips_tracks_parallel_blocks_and_collapses_once_merged() {
        let store = Store::open_temporary().unwrap();
        let params = GhostdagParams::default();

        let genesis = make_block(vec![], vec![], 0);
        let genesis_hash = genesis.hash();
        store.insert_genesis(genesis).unwrap();
        assert_eq!(store.tips(), vec![genesis_hash]);

        let a = make_block(vec![genesis_hash], vec![], 1);
        let a_hash = a.hash();
        let b = make_block(vec![genesis_hash], vec![], 2);
        let b_hash = b.hash();
        store.insert_block(a, &params).unwrap();
        store.insert_block(b, &params).unwrap();

        let mut tips = store.tips();
        tips.sort();
        let mut expected = vec![a_hash, b_hash];
        expected.sort();
        assert_eq!(tips, expected, "both parallel blocks should be tips");

        // A block merging both parallel tips collapses the tip set to
        // just itself.
        let merger = make_block(vec![a_hash, b_hash], vec![], 3);
        let merger_hash = merger.hash();
        store.insert_block(merger, &params).unwrap();
        assert_eq!(store.tips(), vec![merger_hash]);
    }

    #[test]
    fn reorg_switches_ledger_to_the_heavier_branch() {
        let store = Store::open_temporary().unwrap();
        let params = GhostdagParams::default();
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let genesis = make_block(vec![], vec![], 0);
        let genesis_hash = genesis.hash();
        store.insert_genesis(genesis).unwrap();

        // Branch A: one block paying Alice.
        let branch_a = make_block(vec![genesis_hash], vec![coinbase_tx(&alice, 500, 1)], 1);
        let branch_a_hash = branch_a.hash();
        store.insert_block(branch_a, &params).unwrap();
        assert_eq!(store.tip(), Some(branch_a_hash));
        assert_eq!(
            store.balance_for_pubkey_hash(&alice.public_key().pubkey_hash()),
            500
        );

        // Branch B: two blocks off genesis paying Bob, giving it strictly
        // more accumulated work, so it should overtake branch A as tip.
        let branch_b1 = make_block(vec![genesis_hash], vec![coinbase_tx(&bob, 300, 1)], 2);
        let branch_b1_hash = branch_b1.hash();
        store.insert_block(branch_b1, &params).unwrap();
        let branch_b2 = make_block(vec![branch_b1_hash], vec![coinbase_tx(&bob, 300, 2)], 3);
        let branch_b2_hash = branch_b2.hash();
        store.insert_block(branch_b2, &params).unwrap();

        assert_eq!(store.tip(), Some(branch_b2_hash));
        // Ledger should have reorged: Alice's branch-A coins are gone,
        // Bob's branch-B coins are present.
        assert_eq!(
            store.balance_for_pubkey_hash(&alice.public_key().pubkey_hash()),
            0
        );
        assert_eq!(
            store.balance_for_pubkey_hash(&bob.public_key().pubkey_hash()),
            600
        );
    }

    /// Builds a real, proven shielding bundle (see `aeon-shielded`). Slow
    /// (real zk-SNARK proving), by nature of what's being tested.
    fn dummy_shielding_bundle(value_quarks: u64) -> aeon_shielded::ShieldedBundle {
        let mnemonic = aeon_crypto::generate_mnemonic();
        let sk = aeon_shielded::derive_spending_key(&mnemonic, "");
        let address = aeon_shielded::default_address(&sk);
        aeon_shielded::build_shielding_bundle(address, value_quarks)
            .expect("shielding bundle should build")
    }

    #[test]
    fn shielded_pool_advances_anchor_and_undoes_it_on_reorg() {
        let store = Store::open_temporary().unwrap();
        let params = GhostdagParams::default();

        let genesis = make_block(vec![], vec![], 0);
        let genesis_hash = genesis.hash();
        store.insert_genesis(genesis).unwrap();
        let empty_anchor = store.shielded_anchor();

        let shielding_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            shielded: Some(dummy_shielding_bundle(5000)),
        };
        let branch_a = make_block(vec![genesis_hash], vec![shielding_tx], 1);
        store.insert_block(branch_a, &params).unwrap();

        let anchor_after_shielding = store.shielded_anchor();
        assert_ne!(
            anchor_after_shielding, empty_anchor,
            "the anchor should change once a note commitment is added"
        );
        assert!(store.is_recent_shielded_anchor(&anchor_after_shielding));
        assert!(
            store.is_recent_shielded_anchor(&empty_anchor),
            "genesis's own anchor is still recent"
        );

        // A heavier competing branch with no shielded activity overtakes
        // branch A, so its shielded effects should be undone.
        let branch_b1 = make_block(vec![genesis_hash], vec![], 2);
        let branch_b1_hash = branch_b1.hash();
        store.insert_block(branch_b1, &params).unwrap();
        let branch_b2 = make_block(vec![branch_b1_hash], vec![], 3);
        store.insert_block(branch_b2, &params).unwrap();

        assert_eq!(
            store.shielded_anchor(),
            empty_anchor,
            "undoing branch A's shielded block should restore the pre-shielding anchor"
        );
    }
}
