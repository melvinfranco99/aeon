use aeon_core::{Block, Transaction};
use aeon_crypto::{Address, Hash};
use aeon_rpc::{BalanceInfo, BlockTemplate, RpcBackend, SubmitResult, TipInfo, UtxoInfo};
use tokio::sync::{mpsc, oneshot};

use crate::actor::NodeCommand;

/// A cheaply-cloneable handle to the running `NodeActor`, used to implement
/// `aeon_rpc::RpcBackend` by translating each call into a command sent over
/// a channel and awaiting the actor's response.
#[derive(Clone)]
pub struct NodeHandle {
    cmd_tx: mpsc::Sender<NodeCommand>,
}

impl NodeHandle {
    pub fn new(cmd_tx: mpsc::Sender<NodeCommand>) -> Self {
        NodeHandle { cmd_tx }
    }
}

const ACTOR_STOPPED: &str = "the node's internal actor task has stopped";

#[async_trait::async_trait]
impl RpcBackend for NodeHandle {
    async fn tip_info(&self) -> TipInfo {
        let (respond_to, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NodeCommand::GetTipInfo { respond_to })
            .await
            .is_err()
        {
            return TipInfo {
                tip: Hash::ZERO,
                blue_score: 0,
                blue_work: "0".to_string(),
                bits: 0,
            };
        }
        rx.await.unwrap_or(TipInfo {
            tip: Hash::ZERO,
            blue_score: 0,
            blue_work: "0".to_string(),
            bits: 0,
        })
    }

    async fn block_template(&self, miner_address: &str) -> Result<BlockTemplate, String> {
        let pubkey_hash = Address::decode(miner_address).map_err(|e| e.to_string())?;
        let (respond_to, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::GetBlockTemplate {
                pubkey_hash,
                respond_to,
            })
            .await
            .map_err(|_| ACTOR_STOPPED.to_string())?;
        rx.await.map_err(|_| ACTOR_STOPPED.to_string())?
    }

    async fn submit_block(&self, block: Block) -> SubmitResult {
        let (respond_to, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NodeCommand::SubmitBlock { block, respond_to })
            .await
            .is_err()
        {
            return SubmitResult::rejected(ACTOR_STOPPED);
        }
        rx.await
            .unwrap_or_else(|_| SubmitResult::rejected(ACTOR_STOPPED))
    }

    async fn balance(&self, address: &str) -> Result<BalanceInfo, String> {
        let pubkey_hash = Address::decode(address).map_err(|e| e.to_string())?;
        let (respond_to, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::GetBalance {
                pubkey_hash,
                respond_to,
            })
            .await
            .map_err(|_| ACTOR_STOPPED.to_string())?;
        let balance_quarks = rx.await.map_err(|_| ACTOR_STOPPED.to_string())?;
        Ok(BalanceInfo {
            address: address.to_string(),
            balance_quarks,
        })
    }

    async fn submit_transaction(&self, tx: Transaction) -> SubmitResult {
        let (respond_to, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NodeCommand::SubmitTransaction { tx, respond_to })
            .await
            .is_err()
        {
            return SubmitResult::rejected(ACTOR_STOPPED);
        }
        rx.await
            .unwrap_or_else(|_| SubmitResult::rejected(ACTOR_STOPPED))
    }

    async fn utxos(&self, address: &str) -> Result<Vec<UtxoInfo>, String> {
        let pubkey_hash = Address::decode(address).map_err(|e| e.to_string())?;
        let (respond_to, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::GetUtxos {
                pubkey_hash,
                respond_to,
            })
            .await
            .map_err(|_| ACTOR_STOPPED.to_string())?;
        rx.await.map_err(|_| ACTOR_STOPPED.to_string())
    }
}
