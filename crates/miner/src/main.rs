use std::time::{Duration, Instant};

use aeon_core::{bits_to_target, hash_meets_target, Block};
use aeon_rpc::RpcClient;
use clap::Parser;

/// Aeon CPU miner: repeatedly fetches a block template from a node over
/// RPC, searches for a nonce whose header hash meets the difficulty
/// target, and submits any block it solves.
#[derive(Parser, Debug)]
#[command(name = "aeon-miner")]
struct Cli {
    /// Base URL of the node's RPC API.
    #[arg(long, default_value = "http://127.0.0.1:16111")]
    node: String,

    /// Aeon address to receive the block reward.
    #[arg(long)]
    address: String,

    /// How long to search a single template before refreshing it (so the
    /// miner picks up a new tip or mempool transactions).
    #[arg(long, default_value_t = 5)]
    refresh_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let client = RpcClient::new(cli.node.clone());

    println!("Aeon miner starting");
    println!("  node:    {}", cli.node);
    println!("  address: {}", cli.address);

    loop {
        let template = match client.block_template(&cli.address).await {
            Ok(t) => t.block,
            Err(e) => {
                eprintln!("failed to fetch block template ({e}); retrying in 2s...");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        match mine_one_template(&client, template, Duration::from_secs(cli.refresh_secs)).await {
            Ok(()) => {}
            Err(e) => eprintln!("mining error: {e}"),
        }
    }
}

async fn mine_one_template(
    client: &RpcClient,
    template: Block,
    refresh_after: Duration,
) -> anyhow::Result<()> {
    let target = bits_to_target(template.header.bits);
    let mut header = template.header.clone();
    let start = Instant::now();
    let mut hashes: u64 = 0;

    loop {
        header.nonce = header.nonce.wrapping_add(1);
        hashes += 1;
        let hash = header.hash();

        if hash_meets_target(&hash, target) {
            let elapsed = start.elapsed().as_secs_f64().max(f64::EPSILON);
            println!(
                "Found a block! hash={hash} nonce={} ({:.2} kH/s over {} hashes)",
                header.nonce,
                (hashes as f64 / elapsed) / 1000.0,
                hashes
            );
            let block = Block {
                header,
                transactions: template.transactions,
            };
            let result = client.submit_block(block).await?;
            if result.accepted {
                println!("Block accepted by node.");
            } else {
                println!("Block rejected by node: {:?}", result.reason);
            }
            return Ok(());
        }

        if hashes.is_multiple_of(100_000) && start.elapsed() >= refresh_after {
            let elapsed = start.elapsed().as_secs_f64().max(f64::EPSILON);
            println!(
                "No solution yet ({:.2} kH/s); refreshing template...",
                (hashes as f64 / elapsed) / 1000.0
            );
            return Ok(());
        }
    }
}
