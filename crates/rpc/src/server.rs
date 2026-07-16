use std::sync::Arc;

use aeon_core::{Block, Transaction};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::types::{
    AddressQuery, BalanceInfo, BlockTemplate, ShieldedAnchorInfo, ShieldedBundleInfo,
    SinceHeightQuery, SubmitBlockRequest, SubmitResult, SubmitTxRequest, TipInfo, UtxoInfo,
};

/// Everything the RPC layer needs from a running node. Implemented by
/// `aeon-node`; kept as a trait so `aeon-rpc` doesn't need to depend on
/// node internals (storage, mempool, networking).
#[async_trait::async_trait]
pub trait RpcBackend: Send + Sync + 'static {
    async fn tip_info(&self) -> TipInfo;
    async fn block_template(&self, miner_address: &str) -> Result<BlockTemplate, String>;
    async fn submit_block(&self, block: Block) -> SubmitResult;
    async fn balance(&self, address: &str) -> Result<BalanceInfo, String>;
    async fn submit_transaction(&self, tx: Transaction) -> SubmitResult;
    async fn utxos(&self, address: &str) -> Result<Vec<UtxoInfo>, String>;
    /// The shielded pool's current note commitment tree anchor — what a
    /// freshly-built shielded spend should prove against.
    async fn shielded_anchor(&self) -> ShieldedAnchorInfo;
    /// Every shielded bundle confirmed since `since_height`, oldest first —
    /// a wallet scans these locally (trial-decryption with its own viewing
    /// key, and rebuilding its own commitment tree) to discover incoming
    /// payments and spendable notes. See `docs/PRIVACY.md`.
    async fn shielded_actions_since(&self, since_height: u64) -> Vec<ShieldedBundleInfo>;
}

pub fn build_router(backend: Arc<dyn RpcBackend>) -> Router {
    Router::new()
        .route("/tip", get(get_tip))
        .route("/block-template", get(get_block_template))
        .route("/submit-block", post(post_submit_block))
        .route("/balance", get(get_balance))
        .route("/submit-tx", post(post_submit_tx))
        .route("/utxos", get(get_utxos))
        .route("/shielded-anchor", get(get_shielded_anchor))
        .route("/shielded-actions", get(get_shielded_actions))
        .with_state(backend)
}

async fn get_tip(State(backend): State<Arc<dyn RpcBackend>>) -> Json<TipInfo> {
    Json(backend.tip_info().await)
}

async fn get_block_template(
    State(backend): State<Arc<dyn RpcBackend>>,
    Query(q): Query<AddressQuery>,
) -> Result<Json<BlockTemplate>, (StatusCode, String)> {
    backend
        .block_template(&q.address)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

async fn post_submit_block(
    State(backend): State<Arc<dyn RpcBackend>>,
    Json(payload): Json<SubmitBlockRequest>,
) -> Json<SubmitResult> {
    Json(backend.submit_block(payload.block).await)
}

async fn get_balance(
    State(backend): State<Arc<dyn RpcBackend>>,
    Query(q): Query<AddressQuery>,
) -> Result<Json<BalanceInfo>, (StatusCode, String)> {
    backend
        .balance(&q.address)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

async fn post_submit_tx(
    State(backend): State<Arc<dyn RpcBackend>>,
    Json(payload): Json<SubmitTxRequest>,
) -> Json<SubmitResult> {
    Json(backend.submit_transaction(payload.tx).await)
}

async fn get_utxos(
    State(backend): State<Arc<dyn RpcBackend>>,
    Query(q): Query<AddressQuery>,
) -> Result<Json<Vec<UtxoInfo>>, (StatusCode, String)> {
    backend
        .utxos(&q.address)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

async fn get_shielded_anchor(
    State(backend): State<Arc<dyn RpcBackend>>,
) -> Json<ShieldedAnchorInfo> {
    Json(backend.shielded_anchor().await)
}

async fn get_shielded_actions(
    State(backend): State<Arc<dyn RpcBackend>>,
    Query(q): Query<SinceHeightQuery>,
) -> Json<Vec<ShieldedBundleInfo>> {
    Json(backend.shielded_actions_since(q.since_height).await)
}
