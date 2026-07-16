//! Shared JSON-RPC types, the axum HTTP server, and an HTTP client, used to
//! connect `aeon-node`, `aeon-miner` and `aeon-wallet`.

pub mod client;
pub mod server;
pub mod types;

pub use client::RpcClient;
pub use server::{build_router, RpcBackend};
pub use types::*;
