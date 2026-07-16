use aeon_core::{Block, Transaction};
use aeon_crypto::Hash;
use serde::{Deserialize, Serialize};

/// Aeon's wire-protocol version. Peers with a different version are
/// rejected during handshake.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetMessage {
    /// First message sent by both sides immediately after connecting.
    Handshake {
        version: u32,
        node_id: [u8; 16],
        best_tip: Hash,
        best_blue_work: u128,
    },
    /// "I have a block with this hash" (sent unsolicited when a peer learns
    /// of a new block, e.g. by mining or receiving it from another peer).
    InvBlock(Hash),
    GetBlock(Hash),
    Block(Box<Block>),
    InvTx(Hash),
    GetTx(Hash),
    Tx(Box<Transaction>),
    Ping,
    Pong,
}
