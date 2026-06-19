use crate::client::WalletContext;
use crate::errors::AppResult;
use crate::services;
use crate::services::transaction::history::ParamsOfGetHistory;
use crate::services::transaction::history::ResultOfGetHistory;

pub(crate) struct HistoryModule<'a> {
    ctx: &'a WalletContext,
}

impl<'a> HistoryModule<'a> {
    pub fn new(ctx: &'a WalletContext) -> Self {
        Self { ctx }
    }

    /// Unified history: routes to ECC or TIP-3 based on token_id
    pub async fn get_history(&self, params: ParamsOfGetHistory) -> AppResult<ResultOfGetHistory> {
        self.ctx.acquire().await;
        services::transaction::history::get_history(
            self.ctx.tvm_client.clone(),
            self.ctx.archive_tvm_client.clone(),
            params,
        )
        .await
        .map_err(|e| e.with_context("Failed to get history"))
    }
}
