use std::net::SocketAddr;
use std::sync::Arc;

use aeon_core::GhostdagParams;
use aeon_network::Network;
use aeon_storage::Store;
use clap::Parser;
use rand::RngCore;

/// The Aeon full node daemon.
#[derive(Parser, Debug)]
#[command(
    name = "aeon-node",
    about = "Aeon full node: GHOSTDAG consensus, P2P gossip, and JSON-RPC"
)]
struct Cli {
    /// Directory where the node stores its database.
    #[arg(long, default_value = "./aeon-data")]
    datadir: String,

    /// Address to listen on for peer-to-peer connections.
    #[arg(long, default_value = "127.0.0.1:16110")]
    p2p_listen: SocketAddr,

    /// Address to listen on for the JSON-RPC API (used by aeon-wallet and
    /// aeon-miner).
    #[arg(long, default_value = "127.0.0.1:16111")]
    rpc_listen: SocketAddr,

    /// Address of a peer to connect to on startup. May be passed multiple
    /// times.
    #[arg(long)]
    addnode: Vec<SocketAddr>,

    /// GHOSTDAG anticone-size security parameter `k`.
    #[arg(long, default_value_t = 18)]
    ghostdag_k: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let store = Store::open(&cli.datadir)?;
    if store.tip().is_none() {
        store.insert_genesis(aeon_node::genesis_block())?;
        tracing::info!(datadir = %cli.datadir, "initialized new datadir with the Aeon genesis block");
    }
    let params = GhostdagParams { k: cli.ghostdag_k };

    let tip = store.tip().expect("genesis was just ensured to exist");
    let tip_data = store
        .get_ghostdag(&tip)
        .expect("tip must have GHOSTDAG data");

    let mut node_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut node_id);
    let network = Arc::new(Network::new(node_id, tip, tip_data.blue_work));
    network.listen(cli.p2p_listen).await?;
    tracing::info!(addr = %cli.p2p_listen, "P2P listening");

    for addr in &cli.addnode {
        match network.connect(*addr).await {
            Ok(()) => tracing::info!(%addr, "connecting to peer"),
            Err(e) => tracing::warn!(%addr, "failed to connect to peer: {e}"),
        }
    }

    let running = aeon_node::spawn_node(store, params, network);

    let app = aeon_rpc::build_router(Arc::new(running.handle));
    let listener = tokio::net::TcpListener::bind(cli.rpc_listen).await?;
    tracing::info!(addr = %cli.rpc_listen, "RPC listening");
    axum::serve(listener, app).await?;

    Ok(())
}
