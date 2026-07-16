use std::collections::{HashMap, HashSet};

use aeon_crypto::PublicKey;
use thiserror::Error;

use crate::emission::block_reward;
use crate::types::{OutPoint, Transaction};
use crate::utxo::{UtxoEntry, UtxoView};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("non-coinbase transaction has no inputs")]
    NoInputs,
    #[error("input references an unknown or already-spent output")]
    MissingUtxo,
    #[error("input's public key does not match the locked pubkey hash")]
    PubkeyMismatch,
    #[error("input signature does not verify")]
    BadSignature,
    #[error("transaction outputs exceed transaction inputs")]
    OutputsExceedInputs,
    #[error("duplicate input within the same transaction")]
    DuplicateInput,
    #[error("coinbase transaction must have exactly one input-less mint output set")]
    InvalidCoinbaseShape,
    #[error("coinbase mints more than the block reward plus collected fees")]
    CoinbaseExceedsAllowance,
}

/// Validates a non-coinbase transaction against the current UTXO set:
/// every input must reference an existing, unspent output; the spender must
/// prove ownership of it (pubkey hashes to the locked hash, and the
/// signature verifies over the transaction's signing data); and outputs
/// must not exceed inputs. Returns the fee (inputs - outputs) in quarks.
///
/// Does not mutate `utxo`; the caller applies the transaction afterwards via
/// [`crate::utxo::UtxoSet::apply_transaction`] (or, for a whole block, via
/// [`verify_block_transactions`], which also catches double-spends
/// *within* a block by validating against a running overlay).
pub fn verify_transaction(tx: &Transaction, utxo: &impl UtxoView) -> Result<u64, ValidationError> {
    if tx.outputs.is_empty() {
        return Err(ValidationError::NoOutputs);
    }
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs);
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
    if total_out > total_in {
        return Err(ValidationError::OutputsExceedInputs);
    }

    Ok((total_in - total_out) as u64)
}

/// Validates a block's coinbase transaction: it must have no inputs, and
/// must not mint more than the height's block subsidy plus the fees
/// collected from the block's other transactions.
pub fn verify_coinbase(
    tx: &Transaction,
    chain_height: u64,
    total_fees: u64,
) -> Result<(), ValidationError> {
    if !tx.is_coinbase() || tx.outputs.is_empty() {
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
/// block itself, and finally validates the coinbase against the collected
/// fees. Returns the total fees on success.
pub fn verify_block_transactions(
    transactions: &[Transaction],
    chain_height: u64,
    base_utxo: &impl UtxoView,
) -> Result<u64, ValidationError> {
    if transactions.is_empty() {
        return Err(ValidationError::InvalidCoinbaseShape);
    }

    let mut overlay = BlockOverlay {
        base: base_utxo,
        spent: HashSet::new(),
        created: HashMap::new(),
    };
    let mut total_fees: u64 = 0;

    for tx in &transactions[1..] {
        let fee = verify_transaction(tx, &overlay)?;
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
        };

        let fees = verify_block_transactions(&[coinbase, tx1, tx2], 0, &utxo).unwrap();
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
        };

        assert_eq!(
            verify_block_transactions(&[coinbase, tx1, tx2], 0, &utxo),
            Err(ValidationError::MissingUtxo)
        );
    }
}
