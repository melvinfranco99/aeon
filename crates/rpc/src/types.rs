use aeon_core::{Block, Transaction};
use aeon_crypto::Hash;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TipInfo {
    pub tip: Hash,
    pub blue_score: u64,
    /// u128 doesn't round-trip losslessly through JSON numbers in every
    /// client, so it's carried as a decimal string.
    pub blue_work: String,
    pub bits: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockTemplate {
    /// An unmined block: correct parents/merkle root/bits/timestamp and a
    /// coinbase paying the requesting address, with `nonce = 0`. The miner
    /// searches for a nonce (and may bump `timestamp`) until the header
    /// hash meets the target implied by `bits`.
    pub block: Block,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubmitBlockRequest {
    pub block: Block,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubmitTxRequest {
    pub tx: Transaction,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubmitResult {
    pub accepted: bool,
    pub reason: Option<String>,
}

impl SubmitResult {
    pub fn ok() -> Self {
        SubmitResult {
            accepted: true,
            reason: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        SubmitResult {
            accepted: false,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BalanceInfo {
    pub address: String,
    pub balance_quarks: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UtxoInfo {
    pub txid: Hash,
    pub index: u32,
    pub amount_quarks: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AddressQuery {
    pub address: String,
}
