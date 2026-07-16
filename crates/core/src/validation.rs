use std::collections::{HashMap, HashSet};

use aeon_crypto::PublicKey;
use thiserror::Error;

use crate::emission::block_reward;
use crate::types::{OutPoint, Transaction};
use crate::utxo::{UtxoEntry, UtxoView};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("transaction has no inputs, outputs, or shielded bundle")]
    EmptyTransaction,
    #[error("input references an unknown or already-spent output")]
    MissingUtxo,
    #[error("input's public key does not match the locked pubkey hash")]
    PubkeyMismatch,
    #[error("input signature does not verify")]
    BadSignature,
    #[error("transaction outputs (transparent and/or shielded) exceed its inputs")]
    OutputsExceedInputs,
    #[error("duplicate input within the same transaction")]
    DuplicateInput,
    #[error("coinbase transaction must have exactly one input-less, unshielded mint output set")]
    InvalidCoinbaseShape,
    #[error("coinbase mints more than the block reward plus collected fees")]
    CoinbaseExceedsAllowance,
    #[error("shielded bundle failed verification: {0}")]
    ShieldedBundleInvalid(String),
    #[error("shielded bundle's anchor is not a known recent note commitment tree root")]
    UnknownShieldedAnchor,
    #[error("shielded bundle reuses a nullifier that has already been spent")]
    ShieldedNullifierReused,
}

/// Read-only access to the shielded pool's consensus state — recent note
/// commitment tree anchors and spent nullifiers — needed to validate a
/// transaction's shielded bundle. Implemented by `aeon_storage::Store`;
/// kept as a trait so this crate stays storage-agnostic, the same way
/// [`UtxoView`] does for the transparent ledger.
pub trait ShieldedPoolView {
    fn shielded_nullifier_seen(&self, nullifier: &[u8; 32]) -> bool;
    fn is_recent_shielded_anchor(&self, anchor: &[u8; 32]) -> bool;
}

/// Validates a transaction's transparent side against the current UTXO set
/// (every input references an existing, unspent output; the spender proves
/// ownership; a valid signature covers the transaction), and folds in its
/// shielded bundle's public `value_balance` if it has one. Returns the fee
/// (transparent inputs, plus value leaving the shielded pool, minus
/// transparent outputs and value entering the shielded pool) in quarks.
///
/// Does **not** verify the shielded bundle's zk-SNARK proof/signatures or
/// check nullifier-reuse/anchor validity — see [`verify_shielded_component`]
/// and [`verify_transaction_full`], which combine both. This split exists
/// because the transparent checks only need a [`UtxoView`], while the
/// shielded checks need chain-wide [`ShieldedPoolView`] state; most callers
/// want [`verify_transaction_full`].
///
/// Does not mutate `utxo`; the caller applies the transaction afterwards via
/// [`crate::utxo::UtxoSet::apply_transaction`] (or, for a whole block, via
/// [`verify_block_transactions`], which also catches double-spends
/// *within* a block by validating against a running overlay).
pub fn verify_transaction(tx: &Transaction, utxo: &impl UtxoView) -> Result<u64, ValidationError> {
    if tx.inputs.is_empty() && tx.outputs.is_empty() && tx.shielded.is_none() {
        return Err(ValidationError::EmptyTransaction);
    }

    let signing_data = tx.signing_data();
    let mut seen = std::collections::HashSet::new();
    let mut total_in: u128 = 0;

    for input in &tx.inputs {
        if !seen.insert(input.prev_out) {
            return Err(ValidationError::DuplicateInput);
        }
        let entry = utxo
            .get_utxo(&input.prev_out)
            .ok_or(ValidationError::MissingUtxo)?;

        let expected_hash = input.pubkey.pubkey_hash();
        if expected_hash != entry.output.pubkey_hash {
            return Err(ValidationError::PubkeyMismatch);
        }

        input
            .pubkey
            .verify(&signing_data, &input.signature)
            .map_err(|_| ValidationError::BadSignature)?;

        total_in += entry.output.amount as u128;
    }

    let total_out = tx.total_output_amount() as u128;
    // Positive value_balance means value is *leaving* the shielded pool
    // (funding transparent outputs); negative means value is *entering* it
    // (drawn from transparent inputs) — see docs/CONSENSUS.md.
    let shielded_value_balance: i128 = tx
        .shielded
        .as_ref()
        .map(|b| b.value_balance() as i128)
        .unwrap_or(0);

    let net = total_in as i128 - total_out as i128 + shielded_value_balance;
    if net < 0 {
        return Err(ValidationError::OutputsExceedInputs);
    }
    Ok(net as u64)
}

/// Verifies a transaction's shielded bundle, if it has one: the zk-SNARK
/// proof and signatures ([`aeon_shielded::ShieldedBundle::verify`]), that
/// its anchor is a recent, known note commitment tree root, and that none
/// of its nullifiers have already been spent — either on-chain
/// (`pool`) or earlier in the same block (`nullifiers_seen_in_block`, which
/// this function updates). A no-op for a purely transparent transaction.
pub fn verify_shielded_component(
    tx: &Transaction,
    pool: &impl ShieldedPoolView,
    nullifiers_seen_in_block: &mut HashSet<[u8; 32]>,
) -> Result<(), ValidationError> {
    let Some(bundle) = &tx.shielded else {
        return Ok(());
    };

    bundle
        .verify()
        .map_err(|e| ValidationError::ShieldedBundleInvalid(e.to_string()))?;

    if !pool.is_recent_shielded_anchor(&bundle.anchor_bytes()) {
        return Err(ValidationError::UnknownShieldedAnchor);
    }

    for nullifier in bundle.nullifier_bytes() {
        if pool.shielded_nullifier_seen(&nullifier) || !nullifiers_seen_in_block.insert(nullifier) {
            return Err(ValidationError::ShieldedNullifierReused);
        }
    }

    Ok(())
}

/// [`verify_transaction`] and [`verify_shielded_component`] combined — what
/// most callers (mempool acceptance, block validation) actually want.
pub fn verify_transaction_full(
    tx: &Transaction,
    utxo: &impl UtxoView,
    pool: &impl ShieldedPoolView,
    nullifiers_seen_in_block: &mut HashSet<[u8; 32]>,
) -> Result<u64, ValidationError> {
    verify_shielded_component(tx, pool, nullifiers_seen_in_block)?;
    verify_transaction(tx, utxo)
}

/// Validates a block's coinbase transaction: it must have no inputs and no
/// shielded bundle (mining rewards always start out transparent — see
/// `docs/PRIVACY.md`), and must not mint more than the height's block
/// subsidy plus the fees collected from the block's other transactions.
pub fn verify_coinbase(
    tx: &Transaction,
    chain_height: u64,
    total_fees: u64,
) -> Result<(), ValidationError> {
    if !tx.is_coinbase() || tx.outputs.is_empty() || tx.shielded.is_some() {
        return Err(ValidationError::InvalidCoinbaseShape);
    }
    let allowance = block_reward(chain_height).saturating_add(total_fees);
    if tx.total_output_amount() > allowance {
        return Err(ValidationError::CoinbaseExceedsAllowance);
    }
    Ok(())
}

/// A read-only [`UtxoView`] that layers a block-in-progress's spends and
/// newly created outputs on top of a base view, without mutating it. This
/// lets [`verify_block_transactions`] validate a block's transactions in
/// order — including ones that spend an output created earlier in the same
/// block — and reject the block outright if any input double-spends
/// another input already used earlier in it.
struct BlockOverlay<'a, V: UtxoView> {
    base: &'a V,
    spent: HashSet<OutPoint>,
    created: HashMap<OutPoint, UtxoEntry>,
}

impl<'a, V: UtxoView> UtxoView for BlockOverlay<'a, V> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        if self.spent.contains(outpoint) {
            return None;
        }
        self.created
            .get(outpoint)
            .cloned()
            .or_else(|| self.base.get_utxo(outpoint))
    }
}

/// Validates every transaction in a block (in order) against `base_utxo`,
/// a coinbase-aware overlay that also catches double-spends within the
/// block itself (both transparent, via the UTXO overlay, and shielded, via
/// a per-block nullifier set), and finally validates the coinbase against
/// the collected fees. Returns the total fees on success.
pub fn verify_block_transactions(
    transactions: &[Transaction],
    chain_height: u64,
    base_utxo: &impl UtxoView,
    shielded_pool: &impl ShieldedPoolView,
) -> Result<u64, ValidationError> {
    if transactions.is_empty() {
        return Err(ValidationError::InvalidCoinbaseShape);
    }

    let mut overlay = BlockOverlay {
        base: base_utxo,
        spent: HashSet::new(),
        created: HashMap::new(),
    };
    let mut nullifiers_seen_in_block = HashSet::new();
    let mut total_fees: u64 = 0;

    for tx in &transactions[1..] {
        let fee =
            verify_transaction_full(tx, &overlay, shielded_pool, &mut nullifiers_seen_in_block)?;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(ValidationError::CoinbaseExceedsAllowance)?;

        for input in &tx.inputs {
            overlay.spent.insert(input.prev_out);
        }
        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            overlay.created.insert(
                OutPoint {
                    txid,
                    index: index as u32,
                },
                UtxoEntry {
                    output: output.clone(),
                    is_coinbase: false,
                },
            );
        }
    }

    verify_coinbase(&transactions[0], chain_height, total_fees)?;
    Ok(total_fees)
}

/// Convenience used by wallets/miners to recompute the hash a signature
/// should be over, and to sign it, without depending on internal field
/// layout of [`Transaction`].
pub fn sign_input(
    tx: &Transaction,
    keypair: &aeon_crypto::KeyPair,
) -> aeon_crypto::SchnorrSignature {
    keypair.sign(&tx.signing_data())
}

pub fn expected_pubkey_hash(pubkey: &PublicKey) -> [u8; 20] {
    pubkey.pubkey_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`ShieldedPoolView`] for tests that never exercise the shielded
    /// pool: since [`verify_shielded_component`] never even calls into
    /// `pool` for a transaction with `shielded: None`, its answers here are
    /// never observed.
    struct NoShieldedActivity;
    impl ShieldedPoolView for NoShieldedActivity {
        fn shielded_nullifier_seen(&self, _nullifier: &[u8; 32]) -> bool {
            false
        }
        fn is_recent_shielded_anchor(&self, _anchor: &[u8; 32]) -> bool {
            false
        }
    }
    use crate::types::{OutPoint, TxInput, TxOutput};
    use crate::utxo::UtxoSet;
    use aeon_crypto::{Hash, KeyPair};

    fn funded_utxo(owner: &KeyPair, amount: u64) -> (UtxoSet, OutPoint) {
        let mut utxo = UtxoSet::new();
        let outpoint = OutPoint {
            txid: Hash::ZERO,
            index: 0,
        };
        utxo.insert(
            outpoint,
            crate::utxo::UtxoEntry {
                output: TxOutput {
                    amount,
                    pubkey_hash: owner.public_key().pubkey_hash(),
                },
                is_coinbase: false,
            },
        );
        (utxo, outpoint)
    }

    fn spend(
        owner: &KeyPair,
        outpoint: OutPoint,
        to: [u8; 20],
        amount: u64,
        change: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_out: outpoint,
                pubkey: owner.public_key(),
                signature: owner.sign(b"placeholder"),
            }],
            outputs: {
                let mut outs = vec![TxOutput {
                    amount,
                    pubkey_hash: to,
                }];
                if change > 0 {
                    outs.push(TxOutput {
                        amount: change,
                        pubkey_hash: owner.public_key().pubkey_hash(),
                    });
                }
                outs
            },
            lock_time: 0,
            shielded: None,
        };
        let sig = sign_input(&tx, owner);
        tx.inputs[0].signature = sig;
        tx
    }

    #[test]
    fn valid_transaction_is_accepted_and_fee_is_correct() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let (utxo, outpoint) = funded_utxo(&alice, 1000);
        let tx = spend(&alice, outpoint, bob.public_key().pubkey_hash(), 700, 250);
        let fee = verify_transaction(&tx, &utxo).unwrap();
        assert_eq!(fee, 50);
    }

    #[test]
    fn rejects_spending_someone_elses_output() {
        let alice = KeyPair::generate();
        let mallory = KeyPair::generate();
        let bob = KeyPair::generate();
        let (utxo, outpoint) = funded_utxo(&alice, 1000);
        // Mallory tries to spend Alice's output by attaching her own key.
        let tx = spend(&mallory, outpoint, bob.public_key().pubkey_hash(), 700, 250);
        assert_eq!(
            verify_transaction(&tx, &utxo),
            Err(ValidationError::PubkeyMismatch)
        );
    }

    #[test]
    fn rejects_outputs_exceeding_inputs() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let (utxo, outpoint) = funded_utxo(&alice, 1000);
        let tx = spend(&alice, outpoint, bob.public_key().pubkey_hash(), 900, 200);
        assert_eq!(
            verify_transaction(&tx, &utxo),
            Err(ValidationError::OutputsExceedInputs)
        );
    }

    #[test]
    fn rejects_double_spend_after_utxo_removed() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let (mut utxo, outpoint) = funded_utxo(&alice, 1000);
        let tx = spend(&alice, outpoint, bob.public_key().pubkey_hash(), 700, 250);
        verify_transaction(&tx, &utxo).unwrap();
        utxo.apply_transaction(&tx, false);
        // Re-broadcasting the same transaction should now fail: its input
        // no longer exists in the UTXO set.
        assert_eq!(
            verify_transaction(&tx, &utxo),
            Err(ValidationError::MissingUtxo)
        );
    }

    #[test]
    fn coinbase_cannot_exceed_reward_plus_fees() {
        let miner = KeyPair::generate();
        let coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: crate::emission::block_reward(0) + 100,
                pubkey_hash: miner.public_key().pubkey_hash(),
            }],
            lock_time: 0,
            shielded: None,
        };
        assert_eq!(
            verify_coinbase(&coinbase, 0, 50),
            Err(ValidationError::CoinbaseExceedsAllowance)
        );
        assert!(verify_coinbase(&coinbase, 0, 100).is_ok());
    }

    #[test]
    fn block_validation_allows_spending_an_output_created_earlier_in_the_same_block() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let carol = KeyPair::generate();
        let (utxo, outpoint) = funded_utxo(&alice, 1000);

        // tx1: Alice -> Bob (900 + 100 change to Alice, no change needed here)
        let tx1 = spend(&alice, outpoint, bob.public_key().pubkey_hash(), 1000, 0);
        let tx1_out0 = OutPoint {
            txid: tx1.txid(),
            index: 0,
        };
        // tx2: Bob spends the output tx1 just created, paying Carol.
        let tx2 = spend(&bob, tx1_out0, carol.public_key().pubkey_hash(), 900, 0);

        let coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: block_reward(0) + 100, // 100 = tx2's fee
                pubkey_hash: alice.public_key().pubkey_hash(),
            }],
            lock_time: 0,
            shielded: None,
        };

        let fees = verify_block_transactions(&[coinbase, tx1, tx2], 0, &utxo, &NoShieldedActivity)
            .unwrap();
        assert_eq!(fees, 100);
    }

    #[test]
    fn block_validation_rejects_the_same_input_spent_twice_in_one_block() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let (utxo, outpoint) = funded_utxo(&alice, 1000);

        let tx1 = spend(&alice, outpoint, bob.public_key().pubkey_hash(), 1000, 0);
        let tx2 = spend(&alice, outpoint, bob.public_key().pubkey_hash(), 1000, 0);

        let coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: block_reward(0),
                pubkey_hash: alice.public_key().pubkey_hash(),
            }],
            lock_time: 0,
            shielded: None,
        };

        assert_eq!(
            verify_block_transactions(&[coinbase, tx1, tx2], 0, &utxo, &NoShieldedActivity),
            Err(ValidationError::MissingUtxo)
        );
    }
}
