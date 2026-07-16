//! The node's single-threaded "actor": owns the `Store` and `Mempool`
//! exclusively and processes one command at a time (RPC requests, network
//! events), so block/UTXO bookkeeping never races against itself.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aeon_core::{
    bits_to_target, block_reward, genesis_bits, hash_meets_target, verify_block_transactions,
    verify_transaction_full, Block, BlockHeader, GhostdagParams, Transaction, TxOutput,
};
use aeon_crypto::Hash;
use aeon_network::{NetMessage, Network};
use aeon_rpc::{
    BlockTemplate, ShieldedAnchorInfo, ShieldedBundleInfo, SubmitResult, TipInfo, UtxoInfo,
};
use aeon_storage::Store;
use tokio::sync::{mpsc, oneshot};

use crate::mempool::Mempool;

pub enum NodeCommand {
    SubmitBlock {
        block: Box<Block>,
        respond_to: oneshot::Sender<SubmitResult>,
    },
    SubmitTransaction {
        tx: Box<Transaction>,
        respond_to: oneshot::Sender<SubmitResult>,
    },
    GetTipInfo {
        respond_to: oneshot::Sender<TipInfo>,
    },
    GetBlockTemplate {
        pubkey_hash: [u8; 20],
        respond_to: oneshot::Sender<Result<BlockTemplate, String>>,
    },
    GetBalance {
        pubkey_hash: [u8; 20],
        respond_to: oneshot::Sender<u64>,
    },
    GetUtxos {
        pubkey_hash: [u8; 20],
        respond_to: oneshot::Sender<Vec<UtxoInfo>>,
    },
    GetShieldedAnchor {
        respond_to: oneshot::Sender<ShieldedAnchorInfo>,
    },
    GetShieldedActionsSince {
        since_height: u64,
        respond_to: oneshot::Sender<Vec<ShieldedBundleInfo>>,
    },
    PeerConnected {
        addr: SocketAddr,
        best_tip: Hash,
        best_blue_work: u128,
    },
    PeerMessage {
        addr: SocketAddr,
        message: NetMessage,
    },
}

pub struct NodeActor {
    pub store: Store,
    pub params: GhostdagParams,
    pub network: Arc<Network>,
    pub mempool: Mempool,
    /// Blocks received whose parent(s) we don't have yet, keyed by the
    /// missing parent's hash. Reprocessed once that parent arrives.
    pub orphans: HashMap<Hash, Vec<Block>>,
}

impl NodeActor {
    pub async fn run(mut self, mut cmd_rx: mpsc::Receiver<NodeCommand>) {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                NodeCommand::SubmitBlock { block, respond_to } => {
                    let hash = block.hash();
                    self.try_accept_block(*block, None).await;
                    let result = if self.store.has_block(&hash) {
                        SubmitResult::ok()
                    } else {
                        SubmitResult::rejected(
                            "block was not accepted (invalid, unmet target, or orphaned)",
                        )
                    };
                    let _ = respond_to.send(result);
                }
                NodeCommand::SubmitTransaction { tx, respond_to } => {
                    let result = self.try_accept_transaction(*tx, true).await;
                    let _ = respond_to.send(result);
                }
                NodeCommand::GetTipInfo { respond_to } => {
                    let _ = respond_to.send(self.tip_info());
                }
                NodeCommand::GetBlockTemplate {
                    pubkey_hash,
                    respond_to,
                } => {
                    let result = self
                        .build_block_template(pubkey_hash)
                        .map(|block| BlockTemplate { block });
                    let _ = respond_to.send(result);
                }
                NodeCommand::GetBalance {
                    pubkey_hash,
                    respond_to,
                } => {
                    let _ = respond_to.send(self.store.balance_for_pubkey_hash(&pubkey_hash));
                }
                NodeCommand::GetUtxos {
                    pubkey_hash,
                    respond_to,
                } => {
                    let utxos = self
                        .store
                        .utxos_for_pubkey_hash(&pubkey_hash)
                        .into_iter()
                        .map(|(outpoint, entry)| UtxoInfo {
                            txid: outpoint.txid,
                            index: outpoint.index,
                            amount_quarks: entry.output.amount,
                        })
                        .collect();
                    let _ = respond_to.send(utxos);
                }
                NodeCommand::GetShieldedAnchor { respond_to } => {
                    let _ = respond_to.send(ShieldedAnchorInfo {
                        anchor: self.store.shielded_anchor(),
                    });
                }
                NodeCommand::GetShieldedActionsSince {
                    since_height,
                    respond_to,
                } => {
                    let bundles = self
                        .store
                        .selected_chain_blocks_since(since_height)
                        .into_iter()
                        .flat_map(|(height, block)| {
                            block.transactions.into_iter().filter_map(move |tx| {
                                tx.shielded
                                    .map(|bundle| ShieldedBundleInfo { height, bundle })
                            })
                        })
                        .collect();
                    let _ = respond_to.send(bundles);
                }
                NodeCommand::PeerConnected {
                    addr,
                    best_tip,
                    best_blue_work,
                } => {
                    self.handle_peer_connected(addr, best_tip, best_blue_work)
                        .await;
                }
                NodeCommand::PeerMessage { addr, message } => {
                    self.handle_peer_message(addr, message).await;
                }
            }
        }
    }

    fn tip_info(&self) -> TipInfo {
        let tip = self.store.tip().unwrap_or(Hash::ZERO);
        let data = self.store.get_ghostdag(&tip);
        let bits = self
            .store
            .get_block(&tip)
            .map(|b| b.header.bits)
            .unwrap_or_else(genesis_bits);
        TipInfo {
            tip,
            blue_score: data.as_ref().map(|d| d.blue_score).unwrap_or(0),
            blue_work: data.map(|d| d.blue_work).unwrap_or(0).to_string(),
            bits,
        }
    }

    async fn handle_peer_connected(
        &mut self,
        addr: SocketAddr,
        best_tip: Hash,
        best_blue_work: u128,
    ) {
        let our_blue_work = self
            .store
            .tip()
            .and_then(|t| self.store.get_ghostdag(&t))
            .map(|d| d.blue_work)
            .unwrap_or(0);
        if best_blue_work > our_blue_work && !self.store.has_block(&best_tip) {
            self.network
                .send_to(addr, NetMessage::GetBlock(best_tip))
                .await;
        }
    }

    async fn handle_peer_message(&mut self, addr: SocketAddr, message: NetMessage) {
        match message {
            NetMessage::InvBlock(hash) => {
                if !self.store.has_block(&hash) {
                    self.network.send_to(addr, NetMessage::GetBlock(hash)).await;
                }
            }
            NetMessage::GetBlock(hash) => {
                if let Some(block) = self.store.get_block(&hash) {
                    self.network
                        .send_to(addr, NetMessage::Block(Box::new(block)))
                        .await;
                }
            }
            NetMessage::Block(block) => {
                self.try_accept_block(*block, Some(addr)).await;
            }
            NetMessage::InvTx(txid) => {
                if !self.mempool.contains(&txid) {
                    self.network.send_to(addr, NetMessage::GetTx(txid)).await;
                }
            }
            NetMessage::GetTx(txid) => {
                if let Some(tx) = self.mempool.get(&txid) {
                    self.network
                        .send_to(addr, NetMessage::Tx(Box::new(tx.clone())))
                        .await;
                }
            }
            NetMessage::Tx(tx) => {
                self.try_accept_transaction(*tx, true).await;
            }
            NetMessage::Ping => self.network.send_to(addr, NetMessage::Pong).await,
            NetMessage::Pong | NetMessage::Handshake { .. } => {}
        }
    }

    async fn try_accept_transaction(&mut self, tx: Transaction, broadcast: bool) -> SubmitResult {
        let txid = tx.txid();
        if self.mempool.contains(&txid) {
            return SubmitResult::ok();
        }
        let mut no_conflicts_within_this_call = HashSet::new();
        match verify_transaction_full(
            &tx,
            &self.store,
            &self.store,
            &mut no_conflicts_within_this_call,
        ) {
            Ok(_fee) => {
                self.mempool.insert(tx);
                if broadcast {
                    self.network.broadcast(NetMessage::InvTx(txid)).await;
                }
                SubmitResult::ok()
            }
            Err(e) => SubmitResult::rejected(e.to_string()),
        }
    }

    /// Accepts `initial` and, transitively, any previously-orphaned blocks
    /// that were waiting on it. Uses an explicit queue rather than
    /// recursion (async fns can't recurse without heap-boxing the future).
    async fn try_accept_block(&mut self, initial: Block, from: Option<SocketAddr>) {
        let mut queue = VecDeque::new();
        queue.push_back((initial, from));

        while let Some((block, from)) = queue.pop_front() {
            let hash = block.hash();
            if self.store.has_block(&hash) {
                continue;
            }

            let target = bits_to_target(block.header.bits);
            if !hash_meets_target(&hash, target) {
                tracing::warn!(%hash, "rejecting block: proof-of-work does not meet the target");
                continue;
            }

            let parents = block.header.parents.clone();
            if parents.is_empty() {
                tracing::warn!(%hash, "rejecting non-genesis block with no parents");
                continue;
            }

            if let Some(missing) = parents.iter().find(|p| !self.store.has_block(p)).copied() {
                self.orphans.entry(missing).or_default().push(block);
                let request = NetMessage::GetBlock(missing);
                match from {
                    Some(addr) => self.network.send_to(addr, request).await,
                    None => self.network.broadcast(request).await,
                }
                continue;
            }

            let preview = match self.store.preview_ghostdag_data(
                &hash,
                &parents,
                block.header.bits,
                &self.params,
            ) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(%hash, "rejecting block: {e}");
                    continue;
                }
            };

            if let Err(e) = verify_block_transactions(
                &block.transactions,
                preview.blue_score,
                &self.store,
                &self.store,
            ) {
                tracing::warn!(%hash, "rejecting block: invalid transactions: {e}");
                continue;
            }

            match self.store.insert_block(block.clone(), &self.params) {
                Ok(_data) => {
                    self.mempool.remove_conflicting(&block.transactions);
                    if let Some(tip) = self.store.tip() {
                        if let Some(tip_data) = self.store.get_ghostdag(&tip) {
                            self.network.set_local_tip(tip, tip_data.blue_work).await;
                        }
                    }
                    self.network.broadcast(NetMessage::InvBlock(hash)).await;
                    if let Some(children) = self.orphans.remove(&hash) {
                        for child in children {
                            queue.push_back((child, None));
                        }
                    }
                }
                Err(e) => tracing::warn!(%hash, "failed to persist accepted block: {e}"),
            }
        }
    }

    fn build_block_template(&self, miner_pubkey_hash: [u8; 20]) -> Result<Block, String> {
        let parents = self.store.tips();
        if parents.is_empty() {
            return Err("store has no genesis block yet".to_string());
        }
        let best_parent = parents
            .iter()
            .max_by_key(|p| self.store.get_ghostdag(p).map(|d| d.blue_work).unwrap_or(0))
            .copied()
            .expect("parents is non-empty");
        let bits = self.store.next_bits_for_new_block(&best_parent);
        let timestamp = current_unix_timestamp();

        let preview = self
            .store
            .preview_ghostdag_data(&Hash::ZERO, &parents, bits, &self.params)
            .map_err(|e| e.to_string())?;
        let chain_height = preview.blue_score;

        let coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: block_reward(chain_height),
                pubkey_hash: miner_pubkey_hash,
            }],
            // See the doc comment on `Transaction`: lock_time = chain
            // height keeps coinbase txids unique across blocks.
            lock_time: chain_height,
            shielded: None,
        };

        let mut transactions = vec![coinbase];
        transactions.extend(self.mempool.values().cloned());

        let total_fees = match verify_block_transactions(
            &transactions,
            chain_height,
            &self.store,
            &self.store,
        ) {
            Ok(fees) => fees,
            Err(_) => {
                // Something in the mempool no longer validates together
                // (e.g. a just-confirmed conflicting spend); fall back to
                // a coinbase-only template rather than fail mining
                // entirely.
                transactions.truncate(1);
                0
            }
        };
        if total_fees > 0 {
            transactions[0].outputs[0].amount += total_fees;
        }

        let mut header = BlockHeader {
            parents,
            merkle_root: Hash::ZERO,
            timestamp,
            bits,
            nonce: 0,
        };
        header.merkle_root = Block {
            header: header.clone(),
            transactions: transactions.clone(),
        }
        .compute_merkle_root();

        Ok(Block {
            header,
            transactions,
        })
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
