//! Aeon consensus core: the GHOSTDAG BlockDAG engine, block/transaction
//! types, the UTXO ledger, the emission schedule (21,000,000 AEON cap) and
//! the per-block difficulty adjustment algorithm.

pub mod difficulty;
pub mod emission;
pub mod ghostdag;
pub mod types;
pub mod utxo;
pub mod validation;

pub use difficulty::{
    bits_to_target, genesis_bits, hash_meets_target, max_target, next_bits, target_to_bits,
    work_from_target, DaaWindowEntry,
};
pub use emission::{
    block_reward, halving_epoch, HALVING_INTERVAL_BLOCKS, MAX_SUPPLY_QUARKS, QUARKS_PER_AEON,
};
pub use ghostdag::{
    compute_ghostdag_data, is_ancestor, GhostdagData, GhostdagParams, GhostdagStore,
};
pub use types::{Block, BlockHeader, OutPoint, Transaction, TxInput, TxOutput};
pub use utxo::{UtxoEntry, UtxoSet, UtxoView};
pub use validation::{
    expected_pubkey_hash, sign_input, verify_block_transactions, verify_coinbase,
    verify_shielded_component, verify_transaction, verify_transaction_full, ShieldedPoolView,
    ValidationError,
};
