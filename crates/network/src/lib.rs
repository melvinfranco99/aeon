//! Aeon's peer-to-peer gossip network: plain TCP with length-prefixed
//! bincode framing (see `framing`), a handshake exchanging each side's best
//! known tip, and simple inv/getdata-style announcement of new blocks and
//! transactions.
//!
//! Peer discovery is intentionally simple (a static list of addresses
//! passed via `--addnode`), which is all a small/hobby network needs;
//! Aeon does not implement DNS seeds or peer exchange.

pub mod framing;
pub mod message;

pub use message::{NetMessage, PROTOCOL_VERSION};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use aeon_crypto::Hash;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

#[derive(Debug)]
pub enum NetEvent {
    PeerConnected {
        addr: SocketAddr,
        best_tip: Hash,
        best_blue_work: u128,
    },
    PeerDisconnected {
        addr: SocketAddr,
    },
    Message {
        addr: SocketAddr,
        message: NetMessage,
    },
}

struct PeerHandle {
    outbound: mpsc::UnboundedSender<NetMessage>,
}

type PeerMap = Arc<Mutex<HashMap<SocketAddr, PeerHandle>>>;
type LocalTip = Arc<Mutex<(Hash, u128)>>;

/// A running Aeon P2P endpoint: accepts inbound connections, makes outbound
/// connections, and exposes a single event stream plus broadcast/send
/// methods for the node layer to drive.
pub struct Network {
    peers: PeerMap,
    events_tx: mpsc::UnboundedSender<NetEvent>,
    // Wrapped in a `Mutex` (rather than requiring `&mut self`) so a single
    // `Arc<Network>` can be shared between the task pumping `next_event`
    // and whichever code calls `broadcast`/`send_to`/`connect`.
    events_rx: Mutex<mpsc::UnboundedReceiver<NetEvent>>,
    node_id: [u8; 16],
    local_tip: LocalTip,
}

impl Network {
    pub fn new(node_id: [u8; 16], local_tip: Hash, local_blue_work: u128) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Network {
            peers: Arc::new(Mutex::new(HashMap::new())),
            events_tx,
            events_rx: Mutex::new(events_rx),
            node_id,
            local_tip: Arc::new(Mutex::new((local_tip, local_blue_work))),
        }
    }

    /// Updates the tip advertised to newly-connecting peers (does not
    /// affect already-established connections' handshakes).
    pub async fn set_local_tip(&self, tip: Hash, blue_work: u128) {
        *self.local_tip.lock().await = (tip, blue_work);
    }

    pub async fn listen(&self, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let peers = self.peers.clone();
        let events_tx = self.events_tx.clone();
        let node_id = self.node_id;
        let local_tip = self.local_tip.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        spawn_peer(
                            stream,
                            addr,
                            peers.clone(),
                            events_tx.clone(),
                            node_id,
                            local_tip.clone(),
                        );
                    }
                    Err(e) => tracing::warn!("P2P accept error: {e}"),
                }
            }
        });
        Ok(())
    }

    pub async fn connect(&self, addr: SocketAddr) -> std::io::Result<()> {
        let stream = TcpStream::connect(addr).await?;
        spawn_peer(
            stream,
            addr,
            self.peers.clone(),
            self.events_tx.clone(),
            self.node_id,
            self.local_tip.clone(),
        );
        Ok(())
    }

    pub async fn next_event(&self) -> Option<NetEvent> {
        self.events_rx.lock().await.recv().await
    }

    pub async fn broadcast(&self, msg: NetMessage) {
        let peers = self.peers.lock().await;
        for handle in peers.values() {
            let _ = handle.outbound.send(msg.clone());
        }
    }

    pub async fn send_to(&self, addr: SocketAddr, msg: NetMessage) {
        let peers = self.peers.lock().await;
        if let Some(handle) = peers.get(&addr) {
            let _ = handle.outbound.send(msg);
        }
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }
}

fn spawn_peer(
    stream: TcpStream,
    addr: SocketAddr,
    peers: PeerMap,
    events_tx: mpsc::UnboundedSender<NetEvent>,
    node_id: [u8; 16],
    local_tip: LocalTip,
) {
    tokio::spawn(async move {
        let (mut read_half, mut write_half) = stream.into_split();

        let (tip, blue_work) = *local_tip.lock().await;
        let handshake = NetMessage::Handshake {
            version: PROTOCOL_VERSION,
            node_id,
            best_tip: tip,
            best_blue_work: blue_work,
        };
        if framing::write_message(&mut write_half, &handshake)
            .await
            .is_err()
        {
            return;
        }

        let (peer_tip, peer_blue_work) = match framing::read_message(&mut read_half).await {
            Ok(Some(NetMessage::Handshake {
                version,
                best_tip,
                best_blue_work,
                ..
            })) if version == PROTOCOL_VERSION => (best_tip, best_blue_work),
            _ => return, // protocol violation, version mismatch, or disconnect: drop silently
        };

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<NetMessage>();
        peers.lock().await.insert(
            addr,
            PeerHandle {
                outbound: outbound_tx,
            },
        );
        let _ = events_tx.send(NetEvent::PeerConnected {
            addr,
            best_tip: peer_tip,
            best_blue_work: peer_blue_work,
        });

        // Separate reader/writer tasks: simpler and more robust than
        // `tokio::select!`-ing both halves of the same connection, which
        // would risk dropping a partially-read frame if the read branch
        // were cancelled mid-message.
        tokio::spawn(run_writer(write_half, outbound_rx));
        run_reader(read_half, addr, peers, events_tx).await;
    });
}

async fn run_reader<R: AsyncRead + Unpin>(
    mut reader: R,
    addr: SocketAddr,
    peers: PeerMap,
    events_tx: mpsc::UnboundedSender<NetEvent>,
) {
    while let Ok(Some(message)) = framing::read_message(&mut reader).await {
        if events_tx.send(NetEvent::Message { addr, message }).is_err() {
            break;
        }
    }
    // Dropping the peer's entry drops its outbound sender, which ends the
    // writer task too.
    peers.lock().await.remove(&addr);
    let _ = events_tx.send(NetEvent::PeerDisconnected { addr });
}

async fn run_writer<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut outbound_rx: mpsc::UnboundedReceiver<NetMessage>,
) {
    while let Some(msg) = outbound_rx.recv().await {
        if framing::write_message(&mut writer, &msg).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn expect_event(net: &mut Network) -> NetEvent {
        tokio::time::timeout(Duration::from_secs(5), net.next_event())
            .await
            .expect("timed out waiting for a network event")
            .expect("event stream ended unexpectedly")
    }

    #[tokio::test]
    async fn two_nodes_handshake_and_exchange_a_block_announcement() {
        let mut node_a = Network::new([1u8; 16], Hash::ZERO, 0);
        let mut node_b = Network::new([2u8; 16], Hash::ZERO, 42);

        let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr_a).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        drop(listener); // just to pick a free port; `listen` binds it again below
        node_a.listen(bound_addr).await.unwrap();

        node_b.connect(bound_addr).await.unwrap();

        // Node A should see node B connect (as an inbound peer).
        let event_a = expect_event(&mut node_a).await;
        let peer_b_addr = match event_a {
            NetEvent::PeerConnected {
                addr,
                best_blue_work,
                ..
            } => {
                assert_eq!(best_blue_work, 42);
                addr
            }
            other => panic!("unexpected event: {other:?}"),
        };

        // Node B should see its outbound connection to node A complete.
        let event_b = expect_event(&mut node_b).await;
        assert!(matches!(
            event_b,
            NetEvent::PeerConnected {
                best_blue_work: 0,
                ..
            }
        ));

        // Node A announces a block hash to all peers; node B should
        // receive it as a `Message` event.
        let block_hash = Hash::from([9u8; 32]);
        node_a.broadcast(NetMessage::InvBlock(block_hash)).await;

        let event_b2 = expect_event(&mut node_b).await;
        match event_b2 {
            NetEvent::Message {
                message: NetMessage::InvBlock(h),
                ..
            } => assert_eq!(h, block_hash),
            other => panic!("unexpected event: {other:?}"),
        }

        assert_eq!(node_a.peer_count().await, 1);
        let _ = peer_b_addr;
    }
}
