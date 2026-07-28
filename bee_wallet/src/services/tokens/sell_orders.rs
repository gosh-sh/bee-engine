//! Self-contained pipeline for `get_my_sell_orders`.
//!
//! kit's `get_orders_by_seller` is a black box that mixes GraphQL event lookups
//! (need archive for >24h history) with contract getters (need current state
//! from hot). When archive blips on a getter call, the whole kit call errors
//! out and we lose visibility into perfectly legitimate orders. This SDK
//! pipeline splits the two concerns:
//!
//! - **Event lookups** (`SellOrderCreated`, `UsdcClaimed`) — try hot first; if
//!   hot returns nothing (event older than retention window), fall back to
//!   archive. Same pattern as `services::transaction::history`.
//! - **Getter calls** (`get_queue_state`, `get_sell_order_address`,
//!   `lot.get_details`) — always on hot. They read current contract state, so
//!   hot is both correct and more reliable.
//!
//! All network calls retry up to 3 times with exponential backoff. After 3
//! failures the error bubbles up to the caller — the app decides what to do
//! (retry later, show stale cache, etc.).

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;

use ackinacki_kit::contracts::accumulator::events::AccumulatorRootEvent;
use ackinacki_kit::contracts::accumulator::events::DecodedAccumulatorRootEvent;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetQueueState;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetSellOrderAddress;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ResultOfGetQueueState;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ShellAccumulatorRootUsdc;
use ackinacki_kit::contracts::accumulator::shell_sell_order_lot::ShellSellOrderLot;
use ackinacki_kit::contracts::event::Event as KitEvent;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::FromEvent;
use ackinacki_kit::tvm_client::net::query as gql_query;
use ackinacki_kit::tvm_client::net::ParamsOfQuery as GqlParams;
use ackinacki_kit::tvm_client::ClientContext;
use bee_infra::RateLimiter;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use serde_json::json;

use crate::errors::AppError;
use crate::errors::AppResult;
use crate::types::GetMySellOrdersResult;
use crate::types::SellOrderInfo;

const VALID_DENOMS: [u16; 4] = [1, 10, 100, 1000];
const EVENT_PAGE_SIZE: i32 = 100;
const GETTER_CONCURRENCY: usize = 8;
const MAX_EVENT_PAGES: u32 = 50;

/// Bounded exponential-backoff retry policy for the read-only GraphQL
/// queries used by the sell-orders pipeline. Matches the legacy local
/// behaviour (3 attempts, 300ms / 600ms backoff) but goes through the
/// shared `bee_infra::retry` engine and adds jitter to de-correlate
/// retries across colliding clients. Retries on any error — the
/// underlying tvm_client transport is configured to fail fast, so
/// every error reaching this layer is already a real transport miss.
fn sell_orders_retry_policy() -> bee_infra::RetryPolicy {
    bee_infra::RetryPolicy {
        max_attempts: 3,
        max_total: None,
        base_delay: std::time::Duration::from_millis(300),
        max_delay: std::time::Duration::from_millis(600),
        jitter: true,
    }
}

/// Accumulator events by `dst`. Addresses the account by `account_id` +
/// `dapp_id` (gql-server `>= 1.0.0`; the only form the kit speaks since v4).
const GQL_EVENTS_BY_DST: &str = r#"
    query($account_id: String!, $dapp_id: String!, $dst: String!, $last: Int!, $before: String) {
      blockchain {
        account(account_id: $account_id, dapp_id: $dapp_id) {
          events(dst: $dst, last: $last, before: $before) {
            edges {
              cursor
              node { msg_id created_at dst body }
            }
            pageInfo { hasPreviousPage }
          }
        }
      }
    }
"#;

// kit's normalize_address / addresses_equal are private. The accumulator emits
// addresses as canonical "0:hex" — a simple case-insensitive trim is enough for
// equality against the seller we're given.
fn addresses_equal(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

// Internal "0:hex" → external ":hex" form used as dst filter for per-seller
// event channel.
fn internal_to_external_address(addr: &str) -> String {
    match addr.find(':') {
        Some(i) => format!(":{}", &addr[i + 1..]),
        None => format!(":{}", addr),
    }
}

/// One paginated GraphQL events-by-dst pull, lenient to a `null` events field
/// in the response (some archive nodes return that for empty results instead
/// of `{edges: []}`).
async fn fetch_events_one_endpoint(
    ctx: &Arc<ClientContext>,
    rate_limiter: Option<&RateLimiter>,
    accumulator_addr: &str,
    dst: &str,
) -> AppResult<Vec<KitEvent>> {
    // The accumulator lives under the Mobile Verifiers dApp.
    let dapp_id = ackinacki_kit::contracts::dapp::SystemDapp::MobileVerifiers.dapp_id();
    let mut all = Vec::new();
    let mut before: Option<String> = None;
    for _ in 0..MAX_EVENT_PAGES {
        let variables = json!({
            "account_id": crate::dapp::account_id(accumulator_addr),
            "dapp_id": dapp_id,
            "dst": dst,
            "last": EVENT_PAGE_SIZE,
            "before": before,
        });
        let ctx_clone = ctx.clone();
        let result_value = bee_infra::with_retry_policy(
            &sell_orders_retry_policy(),
            rate_limiter,
            |_: &AppError| true,
            || {
                let ctx_clone = ctx_clone.clone();
                let variables = variables.clone();
                async move {
                    gql_query(
                        ctx_clone,
                        GqlParams {
                            query: GQL_EVENTS_BY_DST.to_string(),
                            variables: Some(variables),
                        },
                    )
                    .await
                    .map(|r| r.result)
                    .map_err(|e| AppError::from(e).with_context("events GraphQL query"))
                }
            },
        )
        .await?;

        let events_field = result_value
            .get("data")
            .and_then(|v| v.get("blockchain"))
            .and_then(|v| v.get("account"))
            .and_then(|v| v.get("events"));
        let edges = match events_field {
            None | Some(serde_json::Value::Null) => break,
            Some(v) => v.get("edges").and_then(|e| e.as_array()).cloned().unwrap_or_default(),
        };
        if edges.is_empty() {
            break;
        }

        let mut next_before: Option<String> = None;
        for edge in &edges {
            if next_before.is_none() {
                next_before = edge.get("cursor").and_then(|c| c.as_str()).map(|s| s.to_string());
            }
            let Some(node) = edge.get("node") else { continue };
            let msg_id =
                node.get("msg_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let dst_v = node.get("dst").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let body = node.get("body").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let created_at = node.get("created_at").and_then(|v| v.as_u64()).unwrap_or_default();
            all.push(KitEvent { id: msg_id, dst: dst_v, created_at, body });
        }

        let has_prev = events_field
            .and_then(|v| v.get("pageInfo"))
            .and_then(|v| v.get("hasPreviousPage"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !has_prev {
            break;
        }
        match next_before {
            Some(c) => before = Some(c),
            None => break,
        }
    }
    Ok(all)
}

fn decode_and_filter<F>(
    events: &[KitEvent],
    accumulator: &ShellAccumulatorRootUsdc,
    seller: &str,
    mut pick: F,
) -> BTreeSet<(u16, u64)>
where
    F: FnMut(&DecodedAccumulatorRootEvent, &str) -> Option<(u16, u64)>,
{
    let mut out = BTreeSet::new();
    for ev in events {
        let Ok(decoded) = DecodedAccumulatorRootEvent::from_event(ev, accumulator) else {
            continue;
        };
        if let Some(pair) = pick(&decoded, seller) {
            out.insert(pair);
        }
    }
    out
}

/// On a single endpoint: try the per-seller dst first (server-side filtered
/// so result is small and authoritative). If it returns nothing for this
/// seller, fall back to the legacy global dst and filter the payload
/// client-side.
#[allow(clippy::too_many_arguments)]
async fn fetch_seller_pairs_on_endpoint<F>(
    ctx: &Arc<ClientContext>,
    rate_limiter: Option<&RateLimiter>,
    accumulator: &ShellAccumulatorRootUsdc,
    accumulator_addr: &str,
    seller: &str,
    primary_dst: &str,
    legacy_dst: &str,
    picker: F,
) -> AppResult<BTreeSet<(u16, u64)>>
where
    F: FnMut(&DecodedAccumulatorRootEvent, &str) -> Option<(u16, u64)> + Copy,
{
    if primary_dst != legacy_dst {
        let primary =
            fetch_events_one_endpoint(ctx, rate_limiter, accumulator_addr, primary_dst).await?;
        let pairs = decode_and_filter(&primary, accumulator, seller, picker);
        if !pairs.is_empty() {
            return Ok(pairs);
        }
    }
    let legacy = fetch_events_one_endpoint(ctx, rate_limiter, accumulator_addr, legacy_dst).await?;
    Ok(decode_and_filter(&legacy, accumulator, seller, picker))
}

/// Hot-first → archive-on-empty for a seller's (denom, order_id) pairs.
/// `archive` is consulted only if hot returned nothing for this seller — a
/// non-empty hot result means the seller's events are within retention.
#[allow(clippy::too_many_arguments)]
async fn fetch_seller_pairs_with_archive_fallback<F>(
    hot: &Arc<ClientContext>,
    archive: Option<&Arc<ClientContext>>,
    rate_limiter: Option<&RateLimiter>,
    accumulator_hot: &ShellAccumulatorRootUsdc,
    accumulator_archive: Option<&ShellAccumulatorRootUsdc>,
    accumulator_addr: &str,
    seller: &str,
    primary_dst: &str,
    legacy_dst: &str,
    picker: F,
) -> AppResult<BTreeSet<(u16, u64)>>
where
    F: FnMut(&DecodedAccumulatorRootEvent, &str) -> Option<(u16, u64)> + Copy,
{
    let hot_pairs = fetch_seller_pairs_on_endpoint(
        hot,
        rate_limiter,
        accumulator_hot,
        accumulator_addr,
        seller,
        primary_dst,
        legacy_dst,
        picker,
    )
    .await?;
    if !hot_pairs.is_empty() {
        return Ok(hot_pairs);
    }
    if let (Some(arc_ctx), Some(acc_arc)) = (archive, accumulator_archive) {
        return fetch_seller_pairs_on_endpoint(
            arc_ctx,
            rate_limiter,
            acc_arc,
            accumulator_addr,
            seller,
            primary_dst,
            legacy_dst,
            picker,
        )
        .await;
    }
    Ok(hot_pairs)
}

fn encode_cursor(denom: u16, order_id: u64) -> String {
    format!("{denom}:{order_id}")
}

fn parse_cursor(s: &str) -> Option<(u16, u64)> {
    let mut parts = s.splitn(2, ':');
    let d: u16 = parts.next()?.parse().ok()?;
    let o: u64 = parts.next()?.parse().ok()?;
    Some((d, o))
}

/// Returns paginated sell orders for `seller`. See module docs for strategy.
pub(crate) async fn get_my_sell_orders(
    hot: Arc<ClientContext>,
    archive: Option<Arc<ClientContext>>,
    rate_limiter: Option<RateLimiter>,
    seller: &str,
    page_size: u32,
    cursor: Option<String>,
) -> AppResult<GetMySellOrdersResult> {
    let accumulator_hot = ShellAccumulatorRootUsdc::new_default(hot.clone());
    let accumulator_addr = accumulator_hot.address().to_string();
    let accumulator_archive =
        archive.as_ref().map(|a| ShellAccumulatorRootUsdc::new_default(a.clone()));
    let rl = rate_limiter.as_ref();

    let seller_ext = internal_to_external_address(seller);
    let created_legacy_dst = AccumulatorRootEvent::SellOrderCreated.to_external_address();
    let claimed_legacy_dst = AccumulatorRootEvent::UsdcClaimed.to_external_address();

    // 1. SellOrderCreated for this seller: per-seller dst first (server-side
    //    scoped), legacy fallback (client-side filter). Hot first; if hot is empty
    //    for this seller, go to archive.
    let created_pairs = fetch_seller_pairs_with_archive_fallback(
        &hot,
        archive.as_ref(),
        rl,
        &accumulator_hot,
        accumulator_archive.as_ref(),
        &accumulator_addr,
        seller,
        &seller_ext,
        &created_legacy_dst,
        |ev, who| match ev {
            DecodedAccumulatorRootEvent::SellOrderCreated { data, .. } => {
                if addresses_equal(&data.seller, who) {
                    Some((data.denom, data.order_id))
                } else {
                    None
                }
            }
            _ => None,
        },
    )
    .await?;

    // 2. UsdcClaimed: no per-seller dst in the current contract, so legacy is both
    //    primary and fallback. Filter by seller in payload.
    let claimed_pairs = fetch_seller_pairs_with_archive_fallback(
        &hot,
        archive.as_ref(),
        rl,
        &accumulator_hot,
        accumulator_archive.as_ref(),
        &accumulator_addr,
        seller,
        &claimed_legacy_dst,
        &claimed_legacy_dst,
        |ev, who| match ev {
            DecodedAccumulatorRootEvent::UsdcClaimed { data, .. } => {
                if addresses_equal(&data.seller, who) {
                    Some((data.denom, data.order_id))
                } else {
                    None
                }
            }
            _ => None,
        },
    )
    .await?;

    // 3. Pull queue_state per denom on hot (current state). Sequential — only 4
    //    calls and they're cheap getters.
    let mut queue_states: HashMap<u16, ResultOfGetQueueState> = HashMap::with_capacity(4);
    for d in VALID_DENOMS {
        let acc = ShellAccumulatorRootUsdc::new_default(hot.clone());
        let qs = bee_infra::with_retry_policy(
            &sell_orders_retry_policy(),
            rl,
            |_: &ackinacki_kit::contracts::error::KitError| true,
            || {
                let acc = acc.clone();
                async move { acc.get_queue_state(ParamsOfGetQueueState { d }).await }
            },
        )
        .await
        .map_err(|e: ackinacki_kit::contracts::error::KitError| {
            AppError::from(e).with_context(format!("get_my_sell_orders: get_queue_state(d={d})"))
        })?;
        queue_states.insert(d, qs);
    }

    // 4. Filter candidates by kit's own rules: drop already-claimed, drop invalid
    //    order_id, drop order_id outside the live queue range.
    let mut candidates: Vec<(u16, u64)> = Vec::new();
    for (denom, order_id) in created_pairs {
        if claimed_pairs.contains(&(denom, order_id)) {
            continue;
        }
        let Some(qs) = queue_states.get(&denom) else {
            continue;
        };
        if order_id == 0 || order_id >= qs.next_id {
            continue;
        }
        candidates.push((denom, order_id));
    }
    candidates.sort();

    // 5. Apply cursor: take items strictly greater than the cursor's pair.
    let start = match cursor.as_deref() {
        Some(c) => {
            let pair = parse_cursor(c).ok_or_else(|| {
                AppError::new(format!("get_my_sell_orders: invalid cursor `{c}`"))
            })?;
            candidates.iter().position(|p| *p > pair).unwrap_or(candidates.len())
        }
        None => 0,
    };
    let limit = page_size.max(1) as usize;
    // Take limit+1 to detect next page.
    let take = candidates.len().saturating_sub(start).min(limit + 1);
    let page_pairs: Vec<(u16, u64)> = candidates[start..start + take].to_vec();

    // 6. For each pair on this page: derive lot address + fetch lot.get_details on
    //    hot. Driven concurrently with a semaphore cap (rate limiter still applies
    //    via with_retry). Not spawned: wasm32 is single-threaded and gloo_timers
    //    futures aren't Send, so we drive everything on the current task via
    //    FuturesUnordered.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(GETTER_CONCURRENCY));
    let mut tasks = FuturesUnordered::new();
    for (denom, order_id) in &page_pairs {
        let denom = *denom;
        let order_id = *order_id;
        let hot = hot.clone();
        let rl_clone = rate_limiter.clone();
        let seller_owned = seller.to_string();
        let qs = queue_states
            .get(&denom)
            .cloned()
            .expect("queue state pre-fetched for all valid denoms");
        let sem = semaphore.clone();
        tasks.push(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore never closed");
            let acc = ShellAccumulatorRootUsdc::new_default(hot.clone());
            let addr_result = bee_infra::with_retry_policy(
                &sell_orders_retry_policy(),
                rl_clone.as_ref(),
                |_: &ackinacki_kit::contracts::error::KitError| true,
                || {
                    let acc = acc.clone();
                    async move {
                        acc.get_sell_order_address(ParamsOfGetSellOrderAddress {
                            d: denom,
                            order_id,
                        })
                        .await
                    }
                },
            )
            .await
            .map_err(|e: ackinacki_kit::contracts::error::KitError| {
                AppError::from(e).with_context(format!(
                    "get_my_sell_orders: get_sell_order_address(d={denom}, order_id={order_id})"
                ))
            })?;
            let lot_addr = addr_result.sell_order_addr;
            let lot = ShellSellOrderLot::new_default(hot.clone(), &lot_addr);
            let details = bee_infra::with_retry_policy(
                &sell_orders_retry_policy(),
                rl_clone.as_ref(),
                |_: &ackinacki_kit::contracts::error::KitError| true,
                || {
                    let lot = lot.clone();
                    async move { lot.get_details().await }
                },
            )
            .await
            .map_err(|e: ackinacki_kit::contracts::error::KitError| {
                AppError::from(e).with_context(format!(
                    "get_my_sell_orders: lot.get_details(addr={lot_addr}, d={denom}, order_id={order_id})"
                ))
            })?;
            // Defensive: if owner doesn't match, this order isn't ours
            // (shouldn't happen — event already had us as seller — but kit
            // checks this too).
            if !addresses_equal(&details.owner, &seller_owned) {
                return Ok::<Option<SellOrderInfo>, AppError>(None);
            }
            let sold = order_id <= qs.sold_prefix;
            let position_in_queue = if sold {
                0
            } else {
                order_id.saturating_sub(qs.sold_prefix)
            };
            Ok(Some(SellOrderInfo {
                denom,
                order_id,
                sell_order_address: lot_addr,
                claimed: details.claimed,
                sold,
                position_in_queue,
            }))
        });
    }

    let mut results: Vec<SellOrderInfo> = Vec::with_capacity(tasks.len());
    while let Some(res) = tasks.next().await {
        match res {
            Ok(Some(info)) => results.push(info),
            Ok(None) => {}
            Err(e) => return Err(e),
        }
    }
    results.sort_by_key(|o| (o.denom, o.order_id));

    let has_next_page = page_pairs.len() > limit;
    if has_next_page && results.len() > limit {
        results.truncate(limit);
    }
    let next_cursor = if has_next_page {
        results.last().map(|o| encode_cursor(o.denom, o.order_id))
    } else {
        None
    };

    Ok(GetMySellOrdersResult { orders: results, next_cursor, has_next_page })
}
