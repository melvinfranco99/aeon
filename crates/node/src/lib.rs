//! The Aeon node library: consensus glue between `aeon-storage`,
//! `aeon-network` and `aeon-rpc`. `aeon-node`'s `main.rs` is a thin CLI
//! wrapper around [`spawn_node`]; tests drive this library directly so
//! multi-node scenarios can run in-process.

pub mod actor;
pub mod backend;
pub mod genesis;
pub mod mempool;

pub use actor::{NodeActor, NodeCommand};
pub use backend::NodeHandle;
pub use genesis::genesis_block;

use std::sync::Arc;

use aeon_core::GhostdagParams;
use aeon_network::{NetEvent, Network};
use aeon_storage::Store;
use mempool::Mempool;
use tokio::sync::mpsc;

/// A running node: an [`NodeHandle`] for RPC/local use, plus the shared
/// network handle it was started with.
pub struct RunningNode {
    pub handle: NodeHandle,
    pub network: Arc<Network>,
}

/// Spawns the node's actor task and its network-event pump task. `store`
/// must already have a genesis block inserted.
pub fn spawn_node(store: Store, params: GhostdagParams, network: Arc<Network>) -> RunningNode {
    let (cmd_tx, cmd_rx) = mpsc::channel(256);

    let actor = NodeActor {
        store,
        params,
        network: network.clone(),
        mempool: Mempool::default(),
        orphans: Default::default(),
    };
    tokio::spawn(actor.run(cmd_rx));

    let handle = NodeHandle::new(cmd_tx.clone());

    {
        let network = network.clone();
        tokio::spawn(async move {
            while let Some(event) = network.next_event().await {
                let cmd = match event {
                    NetEvent::PeerConnected {
                        addr,
                        best_tip,
                        best_blue_work,
                    } => NodeCommand::PeerConnected {
                        addr,
                        best_tip,
                        best_blue_work,
                    },
                    NetEvent::PeerDisconnected { addr } => {
                        tracing::info!(%addr, "peer disconnected");
                        continue;
                    }
                    NetEvent::Message { addr, message } => {
                        NodeCommand::PeerMessage { addr, message }
                    }
                };
                if cmd_tx.send(cmd).await.is_err() {
                    break;
                }
            }
        });
    }

    RunningNode { handle, network }
}
