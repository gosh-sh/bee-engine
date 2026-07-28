use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ackinacki_kit::contracts::mvsystem::multifactor::AccountData;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetPopitgame;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::tvm_client::ClientContext;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde_json::json;

use crate::services::multifactor::query::get_multifactor_decoded_data;

/// Address of the MobileVerifiersGameRoot contract that sends mining rewards.
const GAME_ROOT_ADDRESS: &str =
    "0:0505050505050505050505050505050505050505050505050505050505050505";

/// ECC currency id for NACKL. Mining rewards (`RewardedPopitGame` events
/// from `GAME_ROOT_ADDRESS`) are issued exclusively in NACKL — querying the
/// mining stream for any other currency is wasted round-trips and (worse)
/// surfaces NACKL rewards mis-stamped as the requested currency.
const NACKL_CURRENCY_ID: u32 = 1;

/// Well-known system contract addresses → human-readable names.
const KNOWN_ADDRESSES: &[(&str, &str)] = &[
    ("0:1111111111111111111111111111111111111111111111111111111111111111", "Giver"),
    ("0:1010101010101010101010101010101010101010101010101010101010101010", "DEX"),
    ("0:1515151515151515151515151515151515151515151515151515151515151515", "DEX Oracle"),
    ("0:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "Exchange"),
    ("0:3535353535353535353535353535353535353535353535353535353535353535", "Accumulator"),
];

fn known_name(address: &str) -> Option<String> {
    KNOWN_ADDRESSES.iter().find(|(addr, _)| *addr == address).map(|(_, name)| name.to_string())
}

/// Prefix used to mark cursors that belong to the archive data source.
const ARCHIVE_CURSOR_PREFIX: &str = "a:";

/// A decoded cursor that knows which data source it came from.
enum CursorSource {
    /// Cursor for the hot (recent) data endpoint.
    Hot(Option<String>),
    /// Cursor for the archive data endpoint.
    Archive(Option<String>),
}

fn decode_cursor(cursor: Option<String>) -> CursorSource {
    match cursor {
        None => CursorSource::Hot(None),
        Some(c) if c.starts_with(ARCHIVE_CURSOR_PREFIX) => {
            let inner = c[ARCHIVE_CURSOR_PREFIX.len()..].to_string();
            CursorSource::Archive(if inner.is_empty() { None } else { Some(inner) })
        }
        Some(c) => CursorSource::Hot(Some(c)),
    }
}

fn encode_archive_cursor(cursor: Option<String>) -> Option<String> {
    Some(format!("{}{}", ARCHIVE_CURSOR_PREFIX, cursor.unwrap_or_default()))
}

/// Maximum number of auto-fetch iterations when the current page has no
/// messages matching the requested `currency_id`.
const MAX_AUTO_FETCH_PAGES: u32 = 10;

/// Archive endpoint is a soft dependency: the user's history must surface
/// even if the archive node is slow, broken, or unreachable. These bounds
/// keep the SDK from blocking the UI on a misbehaving archive.
///
/// `ARCHIVE_FETCH_TIMEOUT` covers a real archive page fetch (continuation
/// or hot-empty fallback). `ARCHIVE_PROBE_TIMEOUT` is for the cheap
/// "is there anything in archive?" probe done on the final hot page —
/// shorter because we only need a yes/no, not actual data.
const ARCHIVE_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const ARCHIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const ARCHIVE_PROBE_PAGE_SIZE: u32 = 1;

fn default_page_size() -> u32 {
    20
}

#[derive(Debug, Deserialize)]
pub struct ParamsOfGetHistory {
    /// Multifactor account address
    pub multifactor_address: String,
    /// Token identifier:
    /// - ECC: "1" or "2" (currency_id)
    /// - TIP-3: "0:ffff..." (token_root address)
    pub token_id: String,
    /// Number of records per page (default 20)
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Cursor for main messages (`None` = first page)
    pub cursor: Option<String>,
    /// Cursor for popitgame/mining messages (`None` = first page).
    /// For TIP-3 history, leave this as `None`.
    pub mining_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum TxType {
    Mining,
    Incoming,
    Outgoing,
}

#[derive(Debug, Serialize)]
pub struct TxData {
    pub id: String,
    pub tx_type: TxType,
    pub created_at: u64,
    pub value: u128,
    pub src_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResultOfGetHistory {
    /// Transaction list for the current page
    pub data: Vec<TxData>,
    /// Cursor for the next multifactor page (`None` = last page)
    pub next_cursor: Option<String>,
    /// Cursor for the next popitgame/mining page (`None` = last page)
    pub next_mining_cursor: Option<String>,
    /// Whether there are more pages (from either stream)
    pub has_next_page: bool,
}

#[allow(dead_code)]
enum TokenKind {
    Ecc(u32),
    Tip3(String),
}

/// Determines if token_id is an ECC currency_id or a TIP-3 token_root address.
fn parse_token_id(token_id: &str) -> Result<TokenKind, String> {
    match token_id.parse::<u32>() {
        Ok(currency_id) => Ok(TokenKind::Ecc(currency_id)),
        Err(_) => Ok(TokenKind::Tip3(token_id.to_string())),
    }
}

fn de_u32_from_f64<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let v = f64::deserialize(deserializer)?;

    Ok(v as u32)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValueOther {
    #[serde(deserialize_with = "de_u32_from_f64")]
    pub currency: u32,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EccMsg {
    pub id: String,
    pub src: String,
    pub dst: String,
    pub created_at: u64,
    #[serde(default)]
    pub value_other: Vec<ValueOther>,
}

// ---------- GraphQL response types ----------

#[derive(Debug, Deserialize)]
struct GqlResponse {
    data: GqlData,
}

#[derive(Debug, Deserialize)]
struct GqlData {
    blockchain: GqlBlockchain,
}

#[derive(Debug, Deserialize)]
struct GqlBlockchain {
    account: GqlAccount,
}

#[derive(Debug, Deserialize)]
struct GqlAccount {
    messages: GqlMessages,
}

#[derive(Debug, Deserialize)]
struct GqlMessages {
    edges: Vec<GqlEdge>,
    #[serde(rename = "pageInfo")]
    page_info: GqlPageInfo,
}

#[derive(Debug, Deserialize)]
struct GqlEdge {
    node: EccMsg,
}

#[derive(Debug, Deserialize)]
struct GqlPageInfo {
    #[serde(rename = "startCursor")]
    start_cursor: Option<String>,
    #[serde(rename = "hasPreviousPage")]
    has_previous_page: bool,
}

// ---------- GraphQL queries ----------

/// ECC: all incoming and outgoing internal messages for multifactor account.
/// Addresses the account by `account_id` + `dapp_id` (gql-server `>= 1.0.0`;
/// the only form the kit speaks since v4). Uses `last`/`before` to get newest
/// messages first (reverse cursor pagination).
const GQL_ECC_QUERY: &str = r#"
    query($account_id: String!, $dapp_id: String!, $last: Int!, $before: String) {
      blockchain {
        account(account_id: $account_id, dapp_id: $dapp_id) {
          messages(msg_type: [IntIn, IntOut], last: $last, before: $before) {
            edges {
              node {
                id
                src
                dst
                created_at
                value_other {
                  currency
                  value(format: DEC)
                }
              }
            }
            pageInfo {
              startCursor
              hasPreviousPage
            }
          }
        }
      }
    }
"#;

/// Mining: RewardedPopitGame events emitted by GameRoot, filtered by dst =
/// popitgame external address. Each event body contains `reward: uint128`.
/// Addresses the account by `account_id` + `dapp_id`. Uses `last`/`before` for
/// reverse cursor pagination (newest first).
const GQL_MINING_EVENTS_QUERY: &str = r#"
    query($account_id: String!, $dapp_id: String!, $dst: String!, $last: Int!, $before: String) {
      blockchain {
        account(account_id: $account_id, dapp_id: $dapp_id) {
          events(dst: $dst, last: $last, before: $before) {
            edges {
              node {
                msg_id
                created_at
                dst
                body
              }
            }
            pageInfo {
              startCursor
              hasPreviousPage
            }
          }
        }
      }
    }
"#;

// ---------- Query execution ----------

async fn execute_gql_query(
    tvm_client: &Arc<ClientContext>,
    address: &str,
    page_size: u32,
    cursor: Option<&str>,
) -> crate::errors::AppResult<(Vec<EccMsg>, GqlPageInfo)> {
    // Multifactor account lives under the Mobile Verifiers dApp.
    let dapp_id = ackinacki_kit::contracts::dapp::SystemDapp::MobileVerifiers.dapp_id();
    let variables = json!({
        "account_id": crate::dapp::account_id(address),
        "dapp_id": dapp_id,
        "last": page_size,
        "before": cursor,
    });

    let result = ackinacki_kit::tvm_client::net::query(
        tvm_client.clone(),
        ackinacki_kit::tvm_client::net::ParamsOfQuery {
            query: GQL_ECC_QUERY.to_string(),
            variables: Some(variables),
        },
    )
    .await
    .map_err(|e| crate::errors::AppError::from(e).with_context("GraphQL query failed"))?;

    let resp: GqlResponse = serde_json::from_value(result.result)
        .map_err(|e| crate::errors::AppError::from(e).with_context("Parse GQL response"))?;

    let GqlMessages { edges, page_info } = resp.data.blockchain.account.messages;
    let msgs: Vec<EccMsg> = edges.into_iter().map(|e| e.node).collect();

    Ok((msgs, page_info))
}

// ---------- Mining events response types ----------

#[derive(Debug, Deserialize)]
struct GqlEventsResponse {
    data: GqlEventsData,
}

#[derive(Debug, Deserialize)]
struct GqlEventsData {
    blockchain: GqlEventsBlockchain,
}

#[derive(Debug, Deserialize)]
struct GqlEventsBlockchain {
    account: GqlEventsAccount,
}

#[derive(Debug, Deserialize)]
struct GqlEventsAccount {
    events: GqlEvents,
}

#[derive(Debug, Deserialize)]
struct GqlEvents {
    edges: Vec<GqlEventEdge>,
    #[serde(rename = "pageInfo")]
    page_info: GqlPageInfo,
}

#[derive(Debug, Deserialize)]
struct GqlEventEdge {
    node: GqlEventNode,
}

#[derive(Debug, Deserialize)]
struct GqlEventNode {
    msg_id: String,
    created_at: u64,
    #[allow(dead_code)]
    dst: String,
    body: String,
}

/// Queries RewardedPopitGame events from GameRoot, converts them to EccMsg
/// for compatibility with the existing history pipeline.
async fn execute_mining_events_query(
    tvm_client: &Arc<ClientContext>,
    popitgame_address: &str,
    currency_id: u32,
    page_size: u32,
    cursor: Option<&str>,
) -> crate::errors::AppResult<(Vec<EccMsg>, GqlPageInfo)> {
    use ackinacki_kit::contracts::event::Event;
    use ackinacki_kit::contracts::mvsystem::game_root::contract::MobileVerifiersGameRoot;
    use ackinacki_kit::contracts::mvsystem::game_root::events::RewardedPopitGameData;

    // Convert popitgame address "0:abc..." → ":abc..." for dst filter
    let popitgame_ext_dst = popitgame_address.replacen("0:", ":", 1);

    // GameRoot lives under the Mobile Verifiers dApp.
    let dapp_id = ackinacki_kit::contracts::dapp::SystemDapp::MobileVerifiers.dapp_id();
    let variables = json!({
        "account_id": crate::dapp::account_id(GAME_ROOT_ADDRESS),
        "dapp_id": dapp_id,
        "dst": popitgame_ext_dst,
        "last": page_size,
        "before": cursor,
    });

    let result = ackinacki_kit::tvm_client::net::query(
        tvm_client.clone(),
        ackinacki_kit::tvm_client::net::ParamsOfQuery {
            query: GQL_MINING_EVENTS_QUERY.to_string(),
            variables: Some(variables),
        },
    )
    .await
    .map_err(|e| {
        crate::errors::AppError::from(e).with_context("Mining events GraphQL query failed")
    })?;

    let resp: GqlEventsResponse = serde_json::from_value(result.result).map_err(|e| {
        crate::errors::AppError::from(e).with_context("Parse mining events GQL response")
    })?;

    let GqlEvents { edges, page_info } = resp.data.blockchain.account.events;

    let game_root = MobileVerifiersGameRoot::new_default(tvm_client.clone());

    let msgs: Vec<EccMsg> = edges
        .into_iter()
        .filter_map(|edge| {
            let node = edge.node;
            let event = Event {
                id: node.msg_id.clone(),
                dst: node.dst.clone(),
                created_at: node.created_at,
                body: node.body.clone(),
            };
            let decoded = event.decode::<RewardedPopitGameData>(&game_root).ok()??;
            Some(EccMsg {
                id: node.msg_id,
                src: GAME_ROOT_ADDRESS.to_string(),
                dst: popitgame_address.to_string(),
                created_at: node.created_at,
                value_other: vec![ValueOther {
                    currency: currency_id,
                    value: decoded.reward.to_string(),
                }],
            })
        })
        .collect();

    Ok((msgs, page_info))
}

// ---------- Auto-pagination helpers ----------

/// Fetches ECC messages with auto-pagination until filtered results appear or
/// pages are exhausted. Uses reverse pagination (`last`/`before`) — newest
/// messages first.
async fn fetch_ecc_with_auto_pagination(
    tvm_client: &Arc<ClientContext>,
    address: &str,
    currency_id: u32,
    page_size: u32,
    initial_cursor: Option<String>,
) -> crate::errors::AppResult<(Vec<EccMsg>, Option<String>, bool)> {
    let mut all_msgs: Vec<EccMsg> = Vec::new();
    let mut current_cursor = initial_cursor;
    let mut next_cursor: Option<String> = None;
    let mut has_more: bool = false;

    for _ in 0..MAX_AUTO_FETCH_PAGES {
        let (msgs, page_info) =
            execute_gql_query(tvm_client, address, page_size, current_cursor.as_deref()).await?;

        let filtered: Vec<EccMsg> = msgs
            .into_iter()
            .filter(|m| m.value_other.iter().any(|vo| vo.currency == currency_id))
            .collect();

        all_msgs.extend(filtered);
        next_cursor = page_info.start_cursor;
        has_more = page_info.has_previous_page;

        if !all_msgs.is_empty() || !has_more {
            break;
        }
        current_cursor = next_cursor.clone();
    }

    Ok((all_msgs, next_cursor, has_more))
}

/// Fetches mining reward events with pagination. Events are already filtered
/// server-side by dst (popitgame address), so no client-side auto-pagination
/// through empty pages is needed.
async fn fetch_mining_with_auto_pagination(
    tvm_client: &Arc<ClientContext>,
    popitgame_address: &str,
    currency_id: u32,
    page_size: u32,
    initial_cursor: Option<String>,
) -> crate::errors::AppResult<(Vec<EccMsg>, Option<String>, bool)> {
    let (msgs, page_info) = execute_mining_events_query(
        tvm_client,
        popitgame_address,
        currency_id,
        page_size,
        initial_cursor.as_deref(),
    )
    .await?;

    Ok((msgs, page_info.start_cursor, page_info.has_previous_page))
}

// ---------- Archive helpers ----------

/// Wraps an archive fetch in a timeout. On timeout/error, returns an empty
/// result with no continuation — archive is best-effort, the user's hot
/// history must still surface.
async fn archive_call_or_empty<F>(timeout: Duration, fut: F) -> (Vec<EccMsg>, Option<String>, bool)
where
    F: std::future::Future<Output = crate::errors::AppResult<(Vec<EccMsg>, Option<String>, bool)>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) | Err(_) => (vec![], None, false),
    }
}

/// Cheap "does archive have *any* matching data?" probe done on the final
/// hot page. Returns `true` only if the archive responded within
/// `ARCHIVE_PROBE_TIMEOUT` AND has at least one message for `currency_id`.
/// Replaces the old behavior of unconditionally claiming `has_next=true`
/// just because an archive client was configured (which forced the frontend
/// to round-trip into a possibly-dead archive).
async fn archive_ecc_has_data(
    arc_client: &Arc<ClientContext>,
    address: &str,
    currency_id: u32,
) -> bool {
    let probe = fetch_ecc_with_auto_pagination(
        arc_client,
        address,
        currency_id,
        ARCHIVE_PROBE_PAGE_SIZE,
        None,
    );
    let (msgs, _, _) = archive_call_or_empty(ARCHIVE_PROBE_TIMEOUT, probe).await;
    !msgs.is_empty()
}

async fn archive_mining_has_data(
    arc_client: &Arc<ClientContext>,
    popitgame_address: &str,
    currency_id: u32,
) -> bool {
    let probe = fetch_mining_with_auto_pagination(
        arc_client,
        popitgame_address,
        currency_id,
        ARCHIVE_PROBE_PAGE_SIZE,
        None,
    );
    let (msgs, _, _) = archive_call_or_empty(ARCHIVE_PROBE_TIMEOUT, probe).await;
    !msgs.is_empty()
}

// ---------- Main entry point ----------

/// Fetches paginated ECC transaction history (incoming, outgoing, mining).
///
/// Uses `tvm_client` for hot data and optionally `archive_tvm_client` for
/// older data. Cursors are opaque strings — `a:` prefix means archive source.
/// Deduplicates messages by id when hot/archive overlap.
///
/// Archive is treated as a soft dependency: every call into it is bounded
/// by `ARCHIVE_FETCH_TIMEOUT` (or `ARCHIVE_PROBE_TIMEOUT` for the existence
/// check). A hung or broken archive node causes the result to surface
/// without older data instead of blocking the UI.
pub async fn get_ecc_txs(
    tvm_client: Arc<ClientContext>,
    archive_tvm_client: Option<Arc<ClientContext>>,
    params: ParamsOfGetHistory,
) -> crate::errors::AppResult<ResultOfGetHistory> {
    let currency_id = match parse_token_id(&params.token_id) {
        Ok(TokenKind::Ecc(id)) => id,
        _ => {
            return Err(crate::errors::AppError::new(format!(
                "ECC history requires numeric token_id, got: {}",
                params.token_id
            )))
        }
    };

    // --- 1. Resolve popitgame address (may not exist if user has no miner).
    //     Skip the lookup entirely for non-NACKL currencies — mining rewards
    //     are NACKL-only, so SHELL/USDC requests have no business polling the
    //     mining stream and saving the round-trip avoids leaking fake
    //     "Mining" entries that mis-stamp NACKL rewards as another currency. ---
    let popitgame_address: Option<String> = if currency_id == NACKL_CURRENCY_ID {
        let root = MobileVerifiersRoot::new_default(tvm_client.clone());
        root.get_popitgame(ParamsOfGetPopitgame {
            multifactor_address: params.multifactor_address.clone(),
        })
        .await
        .ok()
        .map(|pg| pg.address().to_string())
    } else {
        None
    };

    // --- 2. Decode cursors to determine data source (hot vs archive) ---
    let mf_source = decode_cursor(params.cursor.clone());
    let pg_source = decode_cursor(params.mining_cursor.clone());

    // --- 3. Fetch from the appropriate source, falling back to archive ---
    let (mf_msgs, mf_cursor, mf_has_next) = match mf_source {
        CursorSource::Hot(cursor) => {
            let (msgs, next_cursor, has_next) = fetch_ecc_with_auto_pagination(
                &tvm_client,
                &params.multifactor_address,
                currency_id,
                params.page_size,
                cursor,
            )
            .await?;

            if !has_next && msgs.is_empty() {
                // Hot exhausted with nothing — try archive (best-effort).
                match archive_tvm_client.as_ref() {
                    Some(arc_client) => {
                        let arc_fetch = fetch_ecc_with_auto_pagination(
                            arc_client,
                            &params.multifactor_address,
                            currency_id,
                            params.page_size,
                            None,
                        );
                        let (arc_msgs, arc_cursor, arc_has_next) =
                            archive_call_or_empty(ARCHIVE_FETCH_TIMEOUT, arc_fetch).await;
                        (arc_msgs, encode_archive_cursor(arc_cursor), arc_has_next)
                    }
                    None => (msgs, next_cursor, has_next),
                }
            } else if !has_next {
                // Hot has data on this page but no more pages. Probe archive
                // before claiming `has_next=true` — only signal continuation
                // if archive actually has older data and is responsive.
                match archive_tvm_client.as_ref() {
                    Some(arc_client)
                        if archive_ecc_has_data(
                            arc_client,
                            &params.multifactor_address,
                            currency_id,
                        )
                        .await =>
                    {
                        (msgs, encode_archive_cursor(None), true)
                    }
                    _ => (msgs, None, false),
                }
            } else {
                (msgs, next_cursor, has_next)
            }
        }
        CursorSource::Archive(cursor) => match archive_tvm_client.as_ref() {
            Some(arc_client) => {
                let arc_fetch = fetch_ecc_with_auto_pagination(
                    arc_client,
                    &params.multifactor_address,
                    currency_id,
                    params.page_size,
                    cursor,
                );
                let (msgs, next_cursor, has_next) =
                    archive_call_or_empty(ARCHIVE_FETCH_TIMEOUT, arc_fetch).await;
                (msgs, encode_archive_cursor(next_cursor), has_next)
            }
            None => (vec![], None, false),
        },
    };

    let (pg_msgs, pg_cursor, pg_has_next) = match pg_source {
        CursorSource::Hot(cursor) => match &popitgame_address {
            Some(addr) => {
                let (msgs, next_cursor, has_next) = fetch_mining_with_auto_pagination(
                    &tvm_client,
                    addr,
                    currency_id,
                    params.page_size,
                    cursor,
                )
                .await?;

                if !has_next && msgs.is_empty() {
                    match archive_tvm_client.as_ref() {
                        Some(arc_client) => {
                            let arc_fetch = fetch_mining_with_auto_pagination(
                                arc_client,
                                addr,
                                currency_id,
                                params.page_size,
                                None,
                            );
                            let (arc_msgs, arc_cursor, arc_has_next) =
                                archive_call_or_empty(ARCHIVE_FETCH_TIMEOUT, arc_fetch).await;
                            (arc_msgs, encode_archive_cursor(arc_cursor), arc_has_next)
                        }
                        None => (msgs, next_cursor, has_next),
                    }
                } else if !has_next {
                    match archive_tvm_client.as_ref() {
                        Some(arc_client)
                            if archive_mining_has_data(arc_client, addr, currency_id).await =>
                        {
                            (msgs, encode_archive_cursor(None), true)
                        }
                        _ => (msgs, None, false),
                    }
                } else {
                    (msgs, next_cursor, has_next)
                }
            }
            None => (vec![], None, false),
        },
        CursorSource::Archive(cursor) => match (&popitgame_address, &archive_tvm_client) {
            (Some(addr), Some(arc_client)) => {
                let arc_fetch = fetch_mining_with_auto_pagination(
                    arc_client,
                    addr,
                    currency_id,
                    params.page_size,
                    cursor,
                );
                let (msgs, next_cursor, has_next) =
                    archive_call_or_empty(ARCHIVE_FETCH_TIMEOUT, arc_fetch).await;
                (msgs, encode_archive_cursor(next_cursor), has_next)
            }
            _ => (vec![], None, false),
        },
    };

    // --- 4. Deduplicate messages by id (hot/archive overlap) ---
    let mut seen_ids = HashSet::new();
    let mf_msgs: Vec<EccMsg> =
        mf_msgs.into_iter().filter(|m| seen_ids.insert(m.id.clone())).collect();
    let pg_msgs: Vec<EccMsg> =
        pg_msgs.into_iter().filter(|m| seen_ids.insert(m.id.clone())).collect();

    // --- 3. Collect counterparty addresses (only from multifactor stream) ---
    let mut seen = HashSet::new();

    let counterparties: Vec<String> = mf_msgs
        .iter()
        .filter_map(|e| {
            if e.src == params.multifactor_address {
                Some(e.dst.clone())
            } else if e.dst == params.multifactor_address {
                Some(e.src.clone())
            } else {
                None
            }
        })
        .filter(|a| a != &params.multifactor_address)
        .filter(|a| known_name(a).is_none()) // skip well-known contracts
        .filter(|a| seen.insert(a.clone()))
        .collect();

    // --- 4. Resolve counterparty names in parallel ---
    const PAR: usize = 10;
    let mut decoded_map = HashMap::<String, AccountData>::new();

    let mut join_set = tokio::task::JoinSet::new();
    let mut iter = counterparties.into_iter();

    loop {
        while join_set.len() < PAR {
            if let Some(addr) = iter.next() {
                let tvm_client = tvm_client.clone();

                join_set.spawn(async move {
                    let contract = Multifactor::new_default(tvm_client.clone(), addr.clone());
                    let contract = Arc::new(contract);
                    let decoded = get_multifactor_decoded_data(&contract).await;
                    (addr, decoded)
                });
            } else {
                break;
            }
        }

        if join_set.is_empty() {
            break;
        }

        let (addr, res) = join_set
            .join_next()
            .await
            .ok_or_else(|| "JoinSet unexpectedly empty".to_string())?
            .map_err(|e| crate::errors::AppError::from(e).with_context("Join error"))?;

        // Graceful degradation: if we can't decode a counterparty, just skip
        if let Ok(decoded) = res {
            decoded_map.insert(addr, decoded);
        }
    }

    // --- 5. Build TxData from multifactor stream (Incoming / Outgoing) ---
    let mut data: Vec<TxData> = mf_msgs
        .into_iter()
        .map(|evt| {
            let vo = evt.value_other.into_iter().find(|vo| vo.currency == currency_id).ok_or_else(
                || format!("No value_other for currency {} in message {}", currency_id, evt.id),
            )?;

            let value = vo.value.parse::<u128>().map_err(|e| {
                crate::errors::AppError::from(e)
                    .with_context(format!("Failed to parse value '{}' in msg {}", vo.value, evt.id))
            })?;

            let tx_type = if evt.src == params.multifactor_address {
                TxType::Outgoing
            } else if evt.dst == params.multifactor_address {
                TxType::Incoming
            } else {
                return Err(crate::errors::AppError::new(format!(
                    "Event {} is unrelated: src={}, dst={}, expected addr={}",
                    evt.id, evt.src, evt.dst, params.multifactor_address
                )));
            };

            let counterparty_addr = match tx_type {
                TxType::Outgoing => Some(evt.dst),
                TxType::Incoming => Some(evt.src),
                TxType::Mining => None,
            };
            let src_name = match counterparty_addr {
                Some(ref addr) => {
                    known_name(addr).or_else(|| decoded_map.get(addr).map(|acc| acc.name.clone()))
                }
                None => None,
            };

            Ok(TxData { id: evt.id, tx_type, created_at: evt.created_at, value, src_name })
        })
        .collect::<crate::errors::AppResult<Vec<_>>>()?;

    // --- 6. Build TxData from mining stream (all are TxType::Mining) ---
    let mining_data: Vec<TxData> = pg_msgs
        .into_iter()
        .map(|evt| {
            let vo = evt.value_other.into_iter().find(|vo| vo.currency == currency_id).ok_or_else(
                || {
                    format!(
                        "No value_other for currency {} in mining message {}",
                        currency_id, evt.id
                    )
                },
            )?;

            let value = vo.value.parse::<u128>().map_err(|e| {
                crate::errors::AppError::from(e).with_context(format!(
                    "Failed to parse value '{}' in mining msg {}",
                    vo.value, evt.id
                ))
            })?;

            Ok(TxData {
                id: evt.id,
                tx_type: TxType::Mining,
                created_at: evt.created_at,
                value,
                src_name: None,
            })
        })
        .collect::<crate::errors::AppResult<Vec<_>>>()?;

    data.extend(mining_data);

    // --- 7. Sort by created_at DESC ---
    data.sort_by_key(|b| std::cmp::Reverse(b.created_at));

    Ok(ResultOfGetHistory {
        data,
        next_cursor: mf_cursor,
        next_mining_cursor: pg_cursor,
        has_next_page: mf_has_next || pg_has_next,
    })
}

/// Token (TIP-3) transfer history — stub, returns empty result.
/// TODO: implement using TokenRoot::get_wallet_address + query token wallet
/// messages
pub async fn get_token_txs(
    _tvm_client: Arc<ClientContext>,
    _params: ParamsOfGetHistory,
) -> crate::errors::AppResult<ResultOfGetHistory> {
    Ok(ResultOfGetHistory {
        data: vec![],
        next_cursor: None,
        next_mining_cursor: None,
        has_next_page: false,
    })
}

/// Unified history entry point. Routes to ECC or TIP-3 based on token_id
/// format.
pub async fn get_history(
    tvm_client: Arc<ClientContext>,
    archive_tvm_client: Option<Arc<ClientContext>>,
    params: ParamsOfGetHistory,
) -> crate::errors::AppResult<ResultOfGetHistory> {
    match parse_token_id(&params.token_id) {
        Ok(TokenKind::Ecc(_)) => get_ecc_txs(tvm_client, archive_tvm_client, params).await,
        Ok(TokenKind::Tip3(_)) => get_token_txs(tvm_client, params).await,
        Err(e) => Err(crate::errors::AppError::new(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAPP_T_1: &str = "0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4";
    const WAPP_T_2: &str = "0:b68ea8d8ab65081b535b962af6f4f1d2b10de5a418d0c54041083124b7931c71";
    const THIRD_PARTY: &str = "0:72d06fead593ad34a27a66bda087b9b9d20975b884be0b9fb9e28a812b9cdc0a";
    // ── JSON fixtures ────────────────────────────────────────────────

    /// 5 ECC messages for wapp_t_1, page 1, hasNextPage=true
    const GQL_PAGE1: &str = r#"{"data":{"blockchain":{"account":{"messages":{"edges":[{"node":{"id":"460d0ee64a1b016718235c4a5c185e3967eea36cc893fc38579f8260b36fbb3b","src":"0:72d06fead593ad34a27a66bda087b9b9d20975b884be0b9fb9e28a812b9cdc0a","dst":"0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4","created_at":1770747978,"value_other":[{"currency":1,"value":"1000000000"}]}},{"node":{"id":"6fd9e62b6c66c37ddca1a2864a7d6ed42d4dd55db779cf50680f9edcc6a267b9","src":"0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4","dst":"0:b68ea8d8ab65081b535b962af6f4f1d2b10de5a418d0c54041083124b7931c71","created_at":1770749208,"value_other":[{"currency":1,"value":"100000000"}]}},{"node":{"id":"e6f6c05eef0512a861f7cdbe524c3bc517d72058f79414924f1fb621f9220ebc","src":"0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4","dst":"0:b68ea8d8ab65081b535b962af6f4f1d2b10de5a418d0c54041083124b7931c71","created_at":1770749434,"value_other":[{"currency":1,"value":"100000000"}]}},{"node":{"id":"36aa16a808eb14ebe6620abbeeb2c881d8ef41781a42265cb73f68a537b66339","src":"0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4","dst":"0:b68ea8d8ab65081b535b962af6f4f1d2b10de5a418d0c54041083124b7931c71","created_at":1770749612,"value_other":[{"currency":1,"value":"100000000"}]}},{"node":{"id":"4e148b0c419928727426a8c7137f6a5078789bd1c4082de7a917f93d5b94e27e","src":"0:b68ea8d8ab65081b535b962af6f4f1d2b10de5a418d0c54041083124b7931c71","dst":"0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4","created_at":1770749616,"value_other":[{"currency":1,"value":"100000000"}]}}],"pageInfo":{"startCursor":"76994aab10001620948890900","hasPreviousPage":true}}}}}}"#;

    /// Empty response
    const GQL_EMPTY: &str = r#"{"data":{"blockchain":{"account":{"messages":{"edges":[],"pageInfo":{"startCursor":null,"hasPreviousPage":false}}}}}}"#;

    /// Message with currency=99
    const GQL_WRONG_CURRENCY: &str = r#"{"data":{"blockchain":{"account":{"messages":{"edges":[{"node":{"id":"aaa111","src":"0:72d06fead593ad34a27a66bda087b9b9d20975b884be0b9fb9e28a812b9cdc0a","dst":"0:2f50197761a36c34b43e696624b4738664d7f51a6915a61207589fd3e9d259c4","created_at":1770740000,"value_other":[{"currency":99,"value":"500000"}]}}],"pageInfo":{"startCursor":"somecursor123","hasPreviousPage":false}}}}}}"#;

    /// All IntIn to popitgame (junk + 1 real mining reward).
    /// Simulates what comes back when counterparties filter doesn't work.
    const GQL_POPITGAME_ALL: &str = r#"{"data":{"blockchain":{"account":{"messages":{"edges":[{"node":{"id":"544c01e98e238ce26440b34554f6b4c2dd3fc00e50cd3cf5cc5e27bc6d41412e","src":"0:652a99a9544782f4d93229180d0283a65c1af47c322337e172e8bfef22cf1713","dst":"0:74882e22b289107aaef0bae73f4b989856aebb0f9a423a6f04bbd30d26c7cb47","created_at":1771354583,"value_other":[{"currency":1,"value":"0"}]}},{"node":{"id":"af9f6f488bc3910adb52027090ce6aeda019b9ef8623fdf21e6e4e341a2a31f2","src":"0:0b426256ae8a35d636814dbcb8aeb2b677d440c7d1b8852cd9644bd07480ef1c","dst":"0:74882e22b289107aaef0bae73f4b989856aebb0f9a423a6f04bbd30d26c7cb47","created_at":1771354585,"value_other":[]}},{"node":{"id":"98734336130824965b265e37de80dde2b69e0ebfff7d47c47fd9ed3584a59adb","src":"0:0505050505050505050505050505050505050505050505050505050505050505","dst":"0:74882e22b289107aaef0bae73f4b989856aebb0f9a423a6f04bbd30d26c7cb47","created_at":1771355168,"value_other":[{"currency":1,"value":"86799"}]}}],"pageInfo":{"startCursor":"76994bc2000016209b71711a00","hasPreviousPage":false}}}}}}"#;

    /// Only the real mining reward (what counterparties *should* return)
    const GQL_MINING_ONLY: &str = r#"{"data":{"blockchain":{"account":{"messages":{"edges":[{"node":{"id":"98734336130824965b265e37de80dde2b69e0ebfff7d47c47fd9ed3584a59adb","src":"0:0505050505050505050505050505050505050505050505050505050505050505","dst":"0:74882e22b289107aaef0bae73f4b989856aebb0f9a423a6f04bbd30d26c7cb47","created_at":1771355168,"value_other":[{"currency":1,"value":"86799"}]}}],"pageInfo":{"startCursor":"76994bc2000016209b71711a00","hasPreviousPage":false}}}}}}"#;

    // ── Helpers ──────────────────────────────────────────────────────

    fn parse_msgs(json: &str) -> (Vec<EccMsg>, GqlPageInfo) {
        let resp: GqlResponse = serde_json::from_str(json).unwrap();
        let m = resp.data.blockchain.account.messages;
        (m.edges.into_iter().map(|e| e.node).collect(), m.page_info)
    }

    // ── Tests: parsing ──────────────────────────────────────────────

    #[test]
    fn parse_page1() {
        let (msgs, pi) = parse_msgs(GQL_PAGE1);
        assert_eq!(msgs.len(), 5);
        assert!(pi.has_previous_page);
        assert_eq!(pi.start_cursor.as_deref(), Some("76994aab10001620948890900"));
        assert_eq!(msgs[0].src, THIRD_PARTY);
        assert_eq!(msgs[0].dst, WAPP_T_1);
        assert_eq!(msgs[0].created_at, 1770747978);
        assert_eq!(msgs[0].value_other[0].currency, 1);
        assert_eq!(msgs[0].value_other[0].value, "1000000000");
    }

    #[test]
    fn parse_empty() {
        let (msgs, pi) = parse_msgs(GQL_EMPTY);
        assert!(msgs.is_empty());
        assert!(!pi.has_previous_page);
        assert!(pi.start_cursor.is_none());
    }

    #[test]
    fn parse_popitgame_all() {
        let (msgs, pi) = parse_msgs(GQL_POPITGAME_ALL);
        assert_eq!(msgs.len(), 3);
        assert!(!pi.has_previous_page);
        assert_eq!(msgs[2].src, GAME_ROOT_ADDRESS);
        assert_eq!(msgs[2].value_other[0].value, "86799");
    }

    #[test]
    fn parse_mining_only() {
        let (msgs, _) = parse_msgs(GQL_MINING_ONLY);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].src, GAME_ROOT_ADDRESS);
        assert_eq!(msgs[0].value_other[0].value.parse::<u128>().unwrap(), 86799);
    }

    // ── Tests: currency filtering ───────────────────────────────────

    #[test]
    fn filter_currency_1() {
        let (msgs, _) = parse_msgs(GQL_PAGE1);
        assert_eq!(
            msgs.iter().filter(|m| m.value_other.iter().any(|v| v.currency == 1)).count(),
            5
        );
        assert_eq!(
            msgs.iter().filter(|m| m.value_other.iter().any(|v| v.currency == 2)).count(),
            0
        );
    }

    #[test]
    fn filter_wrong_currency() {
        let (msgs, _) = parse_msgs(GQL_WRONG_CURRENCY);
        assert_eq!(
            msgs.iter().filter(|m| m.value_other.iter().any(|v| v.currency == 1)).count(),
            0
        );
        assert_eq!(
            msgs.iter().filter(|m| m.value_other.iter().any(|v| v.currency == 99)).count(),
            1
        );
    }

    // ── Tests: client-side mining guard ──────────────────────────────

    #[test]
    fn client_guard_filters_junk_from_popitgame() {
        let (msgs, _) = parse_msgs(GQL_POPITGAME_ALL);
        // Without guard: 3 messages (junk included)
        assert_eq!(msgs.len(), 3);
        // With guard: only from GAME_ROOT_ADDRESS + has currency=1
        let mining: Vec<&EccMsg> = msgs
            .iter()
            .filter(|m| m.src == GAME_ROOT_ADDRESS)
            .filter(|m| m.value_other.iter().any(|v| v.currency == 1))
            .collect();
        assert_eq!(mining.len(), 1);
        assert_eq!(
            mining[0].id,
            "98734336130824965b265e37de80dde2b69e0ebfff7d47c47fd9ed3584a59adb"
        );
    }

    // ── Tests: TxType determination ─────────────────────────────────

    #[test]
    fn determine_tx_type() {
        let (msgs, _) = parse_msgs(GQL_PAGE1);
        let mf = WAPP_T_1;
        // [0] src=THIRD_PARTY dst=WAPP_T_1 → Incoming
        assert_ne!(msgs[0].src, mf);
        assert_eq!(msgs[0].dst, mf);
        // [1] src=WAPP_T_1 dst=WAPP_T_2 → Outgoing
        assert_eq!(msgs[1].src, mf);
        // [4] src=WAPP_T_2 dst=WAPP_T_1 → Incoming
        assert_eq!(msgs[4].dst, mf);
        assert_ne!(msgs[4].src, mf);
    }

    // ── Tests: value parsing ────────────────────────────────────────

    #[test]
    fn parse_value() {
        let (msgs, _) = parse_msgs(GQL_PAGE1);
        let v0 = msgs[0].value_other.iter().find(|v| v.currency == 1).unwrap();
        assert_eq!(v0.value.parse::<u128>().unwrap(), 1_000_000_000);
        let v1 = msgs[1].value_other.iter().find(|v| v.currency == 1).unwrap();
        assert_eq!(v1.value.parse::<u128>().unwrap(), 100_000_000);
    }

    // ── Tests: TxData building ──────────────────────────────────────

    #[test]
    fn build_ecc_tx_data() {
        let (msgs, _) = parse_msgs(GQL_PAGE1);
        let mf = WAPP_T_1;
        let data: Vec<TxData> = msgs
            .into_iter()
            .map(|e| {
                let vo = e.value_other.into_iter().find(|v| v.currency == 1).unwrap();
                let val: u128 = vo.value.parse().unwrap();
                let tt = if e.src == mf { TxType::Outgoing } else { TxType::Incoming };
                TxData {
                    id: e.id,
                    tx_type: tt,
                    created_at: e.created_at,
                    value: val,
                    src_name: None,
                }
            })
            .collect();
        assert_eq!(data.len(), 5);
        assert!(matches!(data[0].tx_type, TxType::Incoming));
        assert_eq!(data[0].value, 1_000_000_000);
        assert!(matches!(data[1].tx_type, TxType::Outgoing));
        assert!(matches!(data[4].tx_type, TxType::Incoming));
    }

    #[test]
    fn build_mining_tx_data() {
        let (msgs, _) = parse_msgs(GQL_MINING_ONLY);
        let data: Vec<TxData> = msgs
            .into_iter()
            .filter_map(|e| {
                let vo = e.value_other.into_iter().find(|v| v.currency == 1)?;
                let val: u128 = vo.value.parse().ok()?;
                Some(TxData {
                    id: e.id,
                    tx_type: TxType::Mining,
                    created_at: e.created_at,
                    value: val,
                    src_name: None,
                })
            })
            .collect();
        assert_eq!(data.len(), 1);
        assert!(matches!(data[0].tx_type, TxType::Mining));
        assert_eq!(data[0].value, 86799);
        assert_eq!(data[0].created_at, 1771355168);
    }

    // ── Tests: sorting ──────────────────────────────────────────────

    #[test]
    fn sort_by_created_at_desc() {
        let (msgs, _) = parse_msgs(GQL_PAGE1);
        let mf = WAPP_T_1;
        let mut data: Vec<TxData> = msgs
            .into_iter()
            .map(|e| {
                let vo = e.value_other.into_iter().find(|v| v.currency == 1).unwrap();
                let val: u128 = vo.value.parse().unwrap();
                let tt = if e.src == mf { TxType::Outgoing } else { TxType::Incoming };
                TxData {
                    id: e.id,
                    tx_type: tt,
                    created_at: e.created_at,
                    value: val,
                    src_name: None,
                }
            })
            .collect();
        data.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        for w in data.windows(2) {
            assert!(w[0].created_at >= w[1].created_at);
        }
        assert_eq!(data.first().unwrap().created_at, 1770749616);
        assert_eq!(data.last().unwrap().created_at, 1770747978);
    }

    #[test]
    fn merge_ecc_and_mining_sorted() {
        let ecc = vec![
            TxData {
                id: "ecc1".into(),
                tx_type: TxType::Outgoing,
                created_at: 1770749208,
                value: 100_000_000,
                src_name: None,
            },
            TxData {
                id: "ecc2".into(),
                tx_type: TxType::Incoming,
                created_at: 1770749616,
                value: 100_000_000,
                src_name: None,
            },
        ];
        let mining = vec![
            TxData {
                id: "mine1".into(),
                tx_type: TxType::Mining,
                created_at: 1770749400,
                value: 500_000_000,
                src_name: None,
            },
            TxData {
                id: "mine2".into(),
                tx_type: TxType::Mining,
                created_at: 1770740000,
                value: 250_000_000,
                src_name: None,
            },
        ];
        let mut merged = Vec::new();
        merged.extend(ecc);
        merged.extend(mining);
        merged.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[0].id, "ecc2");
        assert_eq!(merged[1].id, "mine1");
        assert_eq!(merged[2].id, "ecc1");
        assert_eq!(merged[3].id, "mine2");
    }

    #[test]
    fn merge_real_ecc_and_mining() {
        let (ecc_msgs, _) = parse_msgs(GQL_PAGE1);
        let mf = WAPP_T_1;
        let ecc: Vec<TxData> = ecc_msgs
            .into_iter()
            .map(|e| {
                let vo = e.value_other.into_iter().find(|v| v.currency == 1).unwrap();
                let val: u128 = vo.value.parse().unwrap();
                let tt = if e.src == mf { TxType::Outgoing } else { TxType::Incoming };
                TxData {
                    id: e.id,
                    tx_type: tt,
                    created_at: e.created_at,
                    value: val,
                    src_name: None,
                }
            })
            .collect();
        let (pg_msgs, _) = parse_msgs(GQL_MINING_ONLY);
        let mining: Vec<TxData> = pg_msgs
            .into_iter()
            .filter_map(|e| {
                let vo = e.value_other.into_iter().find(|v| v.currency == 1)?;
                let val: u128 = vo.value.parse().ok()?;
                Some(TxData {
                    id: e.id,
                    tx_type: TxType::Mining,
                    created_at: e.created_at,
                    value: val,
                    src_name: None,
                })
            })
            .collect();
        let mut merged = Vec::new();
        merged.extend(ecc);
        merged.extend(mining);
        merged.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        assert_eq!(merged.len(), 6); // 5 ecc + 1 mining
                                     // Mining (1771355168) is newer than all ECC → first
        assert!(matches!(merged[0].tx_type, TxType::Mining));
        assert_eq!(merged[0].value, 86799);
    }

    // ── Tests: counterparty dedup ───────────────────────────────────

    #[test]
    fn counterparty_dedup() {
        let (msgs, _) = parse_msgs(GQL_PAGE1);
        let mf = WAPP_T_1;
        let mut seen = HashSet::new();
        let cps: Vec<String> = msgs
            .iter()
            .filter_map(|e| {
                if e.src == mf {
                    Some(e.dst.clone())
                } else if e.dst == mf {
                    Some(e.src.clone())
                } else {
                    None
                }
            })
            .filter(|a| a != mf)
            .filter(|a| seen.insert(a.clone()))
            .collect();
        assert_eq!(cps.len(), 2);
        assert!(cps.contains(&WAPP_T_2.to_string()));
        assert!(cps.contains(&THIRD_PARTY.to_string()));
    }

    // ── Tests: serialization / deserialization ───────────────────────

    #[test]
    fn tx_type_serialization() {
        assert_eq!(serde_json::to_value(TxType::Mining).unwrap(), "Mining");
        assert_eq!(serde_json::to_value(TxType::Incoming).unwrap(), "Incoming");
        assert_eq!(serde_json::to_value(TxType::Outgoing).unwrap(), "Outgoing");
    }

    #[test]
    fn params_defaults() {
        let p: ParamsOfGetHistory =
            serde_json::from_str(r#"{"multifactor_address":"0:1","token_id":"1"}"#).unwrap();
        assert_eq!(p.page_size, 20);
        assert!(p.cursor.is_none());
        assert!(p.mining_cursor.is_none());
    }

    #[test]
    fn params_custom() {
        let p: ParamsOfGetHistory = serde_json::from_str(r#"{"multifactor_address":"0:1","token_id":"1","page_size":50,"cursor":"a","mining_cursor":"b"}"#).unwrap();
        assert_eq!(p.page_size, 50);
        assert_eq!(p.cursor.as_deref(), Some("a"));
        assert_eq!(p.mining_cursor.as_deref(), Some("b"));
    }

    #[test]
    fn parse_token_id_ecc() {
        assert!(matches!(parse_token_id("1"), Ok(TokenKind::Ecc(1))));
        assert!(matches!(parse_token_id("2"), Ok(TokenKind::Ecc(2))));
    }

    #[test]
    fn parse_token_id_tip3() {
        let addr = "0:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(matches!(parse_token_id(addr), Ok(TokenKind::Tip3(_))));
    }

    // ── Tests: known_name ───────────────────────────────────────────

    #[test]
    fn known_name_giver() {
        assert_eq!(
            known_name("0:1111111111111111111111111111111111111111111111111111111111111111"),
            Some("Giver".to_string()),
        );
    }

    #[test]
    fn known_name_exchange() {
        assert_eq!(
            known_name("0:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"),
            Some("Exchange".to_string()),
        );
    }

    #[test]
    fn known_name_accumulator() {
        assert_eq!(
            known_name("0:3535353535353535353535353535353535353535353535353535353535353535"),
            Some("Accumulator".to_string()),
        );
    }

    #[test]
    fn known_name_unknown_returns_none() {
        assert_eq!(known_name(WAPP_T_1), None);
        assert_eq!(known_name(THIRD_PARTY), None);
    }

    #[test]
    fn known_addresses_skipped_in_counterparty_resolution() {
        let giver = "0:1111111111111111111111111111111111111111111111111111111111111111";
        let exchange = "0:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";
        let mf = WAPP_T_1;
        let msgs = vec![
            EccMsg {
                id: "m1".into(),
                src: giver.to_string(),
                dst: mf.to_string(),
                created_at: 100,
                value_other: vec![ValueOther { currency: 1, value: "100".into() }],
            },
            EccMsg {
                id: "m2".into(),
                src: exchange.to_string(),
                dst: mf.to_string(),
                created_at: 200,
                value_other: vec![ValueOther { currency: 1, value: "200".into() }],
            },
            EccMsg {
                id: "m3".into(),
                src: THIRD_PARTY.to_string(),
                dst: mf.to_string(),
                created_at: 300,
                value_other: vec![ValueOther { currency: 1, value: "300".into() }],
            },
        ];
        let mut seen = HashSet::new();
        let counterparties: Vec<String> = msgs
            .iter()
            .filter_map(|e| if e.src == mf { Some(e.dst.clone()) } else { Some(e.src.clone()) })
            .filter(|a| a != mf)
            .filter(|a| known_name(a).is_none())
            .filter(|a| seen.insert(a.clone()))
            .collect();
        // Only THIRD_PARTY should be in the list — giver/exchange are known
        assert_eq!(counterparties.len(), 1);
        assert_eq!(counterparties[0], THIRD_PARTY);
    }

    // ── Tests: cursor encoding/decoding ─────────────────────────────

    #[test]
    fn decode_cursor_none_is_hot() {
        assert!(matches!(decode_cursor(None), CursorSource::Hot(None)));
    }

    #[test]
    fn decode_cursor_plain_string_is_hot() {
        let c = Some("76994aab10001620948890900".to_string());
        match decode_cursor(c) {
            CursorSource::Hot(Some(v)) => assert_eq!(v, "76994aab10001620948890900"),
            _ => panic!("expected Hot(Some(...))"),
        }
    }

    #[test]
    fn decode_cursor_archive_prefix() {
        let c = Some("a:76994aab10001620948890900".to_string());
        match decode_cursor(c) {
            CursorSource::Archive(Some(v)) => assert_eq!(v, "76994aab10001620948890900"),
            _ => panic!("expected Archive(Some(...))"),
        }
    }

    #[test]
    fn decode_cursor_archive_prefix_empty() {
        let c = Some("a:".to_string());
        assert!(matches!(decode_cursor(c), CursorSource::Archive(None)));
    }

    #[test]
    fn encode_archive_cursor_with_value() {
        let r = encode_archive_cursor(Some("abc123".to_string()));
        assert_eq!(r, Some("a:abc123".to_string()));
    }

    #[test]
    fn encode_archive_cursor_none() {
        let r = encode_archive_cursor(None);
        assert_eq!(r, Some("a:".to_string()));
    }

    #[test]
    fn cursor_roundtrip() {
        let original = "76994aab10001620948890900".to_string();
        let encoded = encode_archive_cursor(Some(original.clone())).unwrap();
        match decode_cursor(Some(encoded)) {
            CursorSource::Archive(Some(v)) => assert_eq!(v, original),
            _ => panic!("expected Archive(Some(...))"),
        }
    }

    // ── Tests: dedup by message id ──────────────────────────────────

    #[test]
    fn dedup_messages_by_id() {
        let msg = |id: &str, ts: u64| EccMsg {
            id: id.to_string(),
            src: THIRD_PARTY.to_string(),
            dst: WAPP_T_1.to_string(),
            created_at: ts,
            value_other: vec![ValueOther { currency: 1, value: "100".into() }],
        };
        let hot_msgs = vec![msg("dup1", 300), msg("unique_hot", 200), msg("dup2", 100)];
        let arc_msgs = vec![msg("dup1", 300), msg("dup2", 100), msg("unique_arc", 50)];

        let mut seen_ids = HashSet::new();
        let deduped_hot: Vec<EccMsg> =
            hot_msgs.into_iter().filter(|m| seen_ids.insert(m.id.clone())).collect();
        let deduped_arc: Vec<EccMsg> =
            arc_msgs.into_iter().filter(|m| seen_ids.insert(m.id.clone())).collect();

        assert_eq!(deduped_hot.len(), 3); // all unique within hot
        assert_eq!(deduped_arc.len(), 1); // only unique_arc survives
        assert_eq!(deduped_arc[0].id, "unique_arc");
    }
}
