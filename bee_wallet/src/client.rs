use std::sync::Arc;

use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;

use crate::errors::AppResult;
use crate::modules;

/// Configuration passed to `Wallet::new`. All fields have empty/`None`
/// defaults so embedding apps can use struct-update syntax and only set
/// what they need:
///
/// ```ignore
/// Wallet::new(WalletConfig {
///     endpoints: vec!["https://shellnet.ackinacki.org".into()],
///     api_token: Some(env!("BM_API_TOKEN").into()),
///     ..Default::default()
/// })?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct WalletConfig {
    /// TVM GraphQL endpoints for primary traffic.
    pub endpoints: Vec<String>,
    /// Optional archive endpoints used for historical queries that fall
    /// off the regular node's retention window.
    pub archive_endpoints: Option<Vec<String>>,
    /// bee-infra backend URL (DEX vouchers, name resolution, etc.).
    pub api_url: String,
    /// App identifier for bee-infra backend.
    pub app_id: String,
    /// Bearer token sent as `Authorization: Bearer <token>` on every
    /// TVM GraphQL request (primary + archive). `None` disables auth.
    pub api_token: Option<String>,
    /// Cap on outbound TVM requests per second. `None` disables
    /// rate-limiting.
    pub max_rps: Option<u32>,
}

pub(crate) struct WalletContext {
    pub(crate) tvm_client: Arc<ClientContext>,
    /// Optional TVM client pointing to the archive data endpoint.
    pub(crate) archive_tvm_client: Option<Arc<ClientContext>>,
    pub(crate) api_url: String,
    pub(crate) app_id: String,
    pub(crate) rate_limiter: Option<bee_infra::RateLimiter>,
}

impl WalletContext {
    pub(crate) fn new(config: WalletConfig) -> AppResult<Self> {
        #[cfg(feature = "wasm")]
        console_error_panic_hook::set_once();

        let WalletConfig { endpoints, archive_endpoints, api_url, app_id, api_token, max_rps } =
            config;

        let mut tvm_config = ClientConfig::default();
        tvm_config.network.endpoints = Some(endpoints);
        // Disable tvm_client's internal `query_graphql` re-connect loop —
        // it spins without sleep on multi-endpoint setups and turns a
        // single 502 into a sustained ~60 rps storm against the same BM.
        // We do bounded, classified retries one layer up via
        // `bee_infra::retry::with_retry_policy`.
        tvm_config.network.max_reconnect_timeout = 0;
        tvm_config.network.api_token = api_token.clone();
        let client = ClientContext::new(tvm_config).map_err(|e| {
            crate::errors::AppError::from(e).with_context("failed to create tvm client")
        })?;

        let archive_client = archive_endpoints
            .map(|eps| {
                let mut cfg = ClientConfig::default();
                cfg.network.endpoints = Some(eps);
                cfg.network.max_reconnect_timeout = 0;
                cfg.network.api_token = api_token.clone();
                ClientContext::new(cfg).map_err(|e| {
                    crate::errors::AppError::from(e)
                        .with_context("failed to create archive tvm client")
                })
            })
            .transpose()?;

        Ok(Self {
            tvm_client: Arc::new(client),
            archive_tvm_client: archive_client.map(Arc::new),
            api_url,
            app_id,
            rate_limiter: bee_infra::RateLimiter::optional(max_rps),
        })
    }

    pub(crate) async fn acquire(&self) {
        bee_infra::maybe_acquire(self.rate_limiter.as_ref()).await;
    }
}

pub(crate) struct WalletClient {
    ctx: WalletContext,
}

impl WalletClient {
    pub(crate) fn new(config: WalletConfig) -> AppResult<Self> {
        Ok(Self { ctx: WalletContext::new(config)? })
    }

    pub(crate) fn deploy(&self) -> modules::deploy::DeployModule<'_> {
        modules::deploy::DeployModule::new(&self.ctx)
    }

    pub(crate) fn multifactor(&self) -> modules::multifactor::MultifactorModule<'_> {
        modules::multifactor::MultifactorModule::new(&self.ctx)
    }

    pub(crate) fn miner(&self) -> modules::miner::MinerModule<'_> {
        modules::miner::MinerModule::new(&self.ctx)
    }

    pub(crate) fn balance(&self) -> modules::balance::BalanceModule<'_> {
        modules::balance::BalanceModule::new(&self.ctx)
    }

    pub(crate) fn tokens(&self) -> modules::tokens::TokensModule<'_> {
        modules::tokens::TokensModule::new(&self.ctx)
    }

    pub(crate) fn history(&self) -> modules::history::HistoryModule<'_> {
        modules::history::HistoryModule::new(&self.ctx)
    }

    pub(crate) fn zkp(&self) -> modules::zkp::ZkpModule<'_> {
        modules::zkp::ZkpModule::new(&self.ctx)
    }

    pub(crate) fn connect(&self) -> modules::connect::ConnectModule<'_> {
        modules::connect::ConnectModule::new(&self.ctx)
    }

    pub(crate) fn names(&self) -> modules::names::NamesModule<'_> {
        modules::names::NamesModule::new(&self.ctx)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn dex(&self) -> modules::dex::DexModule<'_> {
        modules::dex::DexModule::new(&self.ctx)
    }
}
