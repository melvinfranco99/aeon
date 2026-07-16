use aeon_core::{Block, Transaction};

use crate::types::{
    BalanceInfo, BlockTemplate, ShieldedAnchorInfo, ShieldedBundleInfo, SubmitBlockRequest,
    SubmitResult, SubmitTxRequest, TipInfo, UtxoInfo,
};

/// Thin async HTTP client for Aeon's node RPC, used by `aeon-wallet` and
/// `aeon-miner` so neither needs to know about axum/routing details.
#[derive(Clone)]
pub struct RpcClient {
    base_url: String,
    http: reqwest::Client,
}

impl RpcClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        RpcClient {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn tip(&self) -> reqwest::Result<TipInfo> {
        self.http
            .get(format!("{}/tip", self.base_url))
            .send()
            .await?
            .json()
            .await
    }

    pub async fn block_template(&self, address: &str) -> reqwest::Result<BlockTemplate> {
        self.http
            .get(format!("{}/block-template", self.base_url))
            .query(&[("address", address)])
            .send()
            .await?
            .json()
            .await
    }

    pub async fn submit_block(&self, block: Block) -> reqwest::Result<SubmitResult> {
        self.http
            .post(format!("{}/submit-block", self.base_url))
            .json(&SubmitBlockRequest { block })
            .send()
            .await?
            .json()
            .await
    }

    pub async fn balance(&self, address: &str) -> reqwest::Result<BalanceInfo> {
        self.http
            .get(format!("{}/balance", self.base_url))
            .query(&[("address", address)])
            .send()
            .await?
            .json()
            .await
    }

    pub async fn submit_transaction(&self, tx: Transaction) -> reqwest::Result<SubmitResult> {
        self.http
            .post(format!("{}/submit-tx", self.base_url))
            .json(&SubmitTxRequest { tx })
            .send()
            .await?
            .json()
            .await
    }

    pub async fn utxos(&self, address: &str) -> reqwest::Result<Vec<UtxoInfo>> {
        self.http
            .get(format!("{}/utxos", self.base_url))
            .query(&[("address", address)])
            .send()
            .await?
            .json()
            .await
    }

    pub async fn shielded_anchor(&self) -> reqwest::Result<ShieldedAnchorInfo> {
        self.http
            .get(format!("{}/shielded-anchor", self.base_url))
            .send()
            .await?
            .json()
            .await
    }

    pub async fn shielded_actions_since(
        &self,
        since_height: u64,
    ) -> reqwest::Result<Vec<ShieldedBundleInfo>> {
        self.http
            .get(format!("{}/shielded-actions", self.base_url))
            .query(&[("since_height", since_height.to_string())])
            .send()
            .await?
            .json()
            .await
    }
}
