use std::sync::Arc;

use ackinacki_kit::contracts::accumulator::events::DecodedAccumulatorRootEvent;
use ackinacki_kit::contracts::accumulator::events::DecodedSellOrderLotEvent;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetOrdersBySeller;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetSellOrderAddress;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::SellerOrderInfo as KitSellerOrderInfo;
use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ShellAccumulatorRootUsdc;
use ackinacki_kit::contracts::accumulator::shell_sell_order_lot::ShellSellOrderLot;
use ackinacki_kit::contracts::event::Event as KitEvent;
use ackinacki_kit::contracts::mvsystem::mirror::Mirror;
use ackinacki_kit::contracts::mvsystem::mirror::ParamsOfGetMinerAddress;
use ackinacki_kit::contracts::mvsystem::multifactor::Multifactor;
use ackinacki_kit::contracts::mvsystem::root::MobileVerifiersRoot;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetIndexer;
use ackinacki_kit::contracts::mvsystem::root::ParamsOfGetPopitgame;
use ackinacki_kit::contracts::traits::AccountAccessor;
use ackinacki_kit::contracts::traits::AddressAccessor;
use ackinacki_kit::contracts::traits::FromEvent;
use ackinacki_kit::shared::traits::guarded::AsyncGuarded;
use ackinacki_kit::tvm_client::net::query as gql_query;
use ackinacki_kit::tvm_client::net::ParamsOfQuery as GqlParams;
use ackinacki_kit::tvm_client::ClientConfig;
use ackinacki_kit::tvm_client::ClientContext;

const NACKL_ECC_ID: u32 = 1;
const SHELL_ECC_ID: u32 = 2;
const USDC_ECC_ID: u32 = 3;
const NACKL_DECIMALS: u32 = 9;
const SHELL_DECIMALS: u32 = 9;
const USDC_DECIMALS: u32 = 6;
const MAINNET_ENDPOINT: &str = "https://mainnet.ackinacki.org";
const MAINNET_ARCHIVE_ENDPOINT: &str = "https://archive.mainnet.ackinacki.org";
const SHELLNET_ENDPOINT: &str = "shellnet.ackinacki.org";

fn create_tvm_client(endpoint: &str) -> Arc<ClientContext> {
    let mut config = ClientConfig::default();
    config.network.endpoints = Some(vec![endpoint.to_string()]);
    Arc::new(ClientContext::new(config).expect("failed to create tvm client"))
}

fn format_balance(raw: &num_bigint::BigInt, decimals: u32) -> String {
    use num_bigint::Sign;
    let divisor = num_bigint::BigInt::from(10u64.pow(decimals));
    let whole = raw / &divisor;
    let rem = raw % &divisor;
    let frac = if rem.sign() == Sign::Minus { -rem } else { rem };
    let frac_str = format!("{frac}");
    let padded = format!("{:0>width$}", frac_str, width = decimals as usize);
    let trimmed = padded.trim_end_matches('0');
    if trimmed.is_empty() {
        format!("{whole}")
    } else {
        format!("{whole}.{trimmed}")
    }
}

async fn resolve_address(ctx: &Arc<ClientContext>, name: &str) -> Result<String, String> {
    let root = MobileVerifiersRoot::new_default(ctx.clone());
    let indexer = root
        .get_indexer(ParamsOfGetIndexer { name: name.to_string() })
        .await
        .map_err(|e| format!("get_indexer failed: {e}"))?;
    let details = indexer.get_details().await.map_err(|e| format!("get_details failed: {e}"))?;
    Ok(details.multifactor_address)
}

async fn cmd_info(endpoint: &str, name: &str) {
    let ctx = create_tvm_client(endpoint);

    let address = match resolve_address(&ctx, name).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    println!("\n=== {name} ({endpoint}) ===\n");
    println!("multifactor: {address}");

    // Multifactor balances
    let mf = Multifactor::new_default(ctx.clone(), &address);
    if let Err(e) = mf.fetch_account().await {
        eprintln!("fetch multifactor failed: {e}");
        return;
    }
    let balance = mf.async_guarded(|acc| acc.balance.clone()).await;
    let ecc = mf.async_guarded(|acc| acc.ecc.clone()).await;

    if let Some(b) = &balance {
        println!("vmshell:     {} VMShell", format_balance(b, 9));
    }
    if let Some(nackl) = ecc.get(&NACKL_ECC_ID) {
        println!("nackl:       {} NACKL", format_balance(nackl, NACKL_DECIMALS));
    }
    if let Some(shell) = ecc.get(&SHELL_ECC_ID) {
        println!("shell:       {} SHELL", format_balance(shell, SHELL_DECIMALS));
    }
    if let Some(usdc) = ecc.get(&USDC_ECC_ID) {
        println!("usdc:        {} USDC", format_balance(usdc, USDC_DECIMALS));
    }

    // Popitgame
    let root = MobileVerifiersRoot::new_default(ctx.clone());
    match root.get_popitgame(ParamsOfGetPopitgame { multifactor_address: address.clone() }).await {
        Ok(pg) => {
            println!("\npopitgame:   {}", pg.address());
            if pg.fetch_account().await.is_ok() {
                let pg_ecc = pg.async_guarded(|acc| acc.ecc.clone()).await;
                if let Some(nackl) = pg_ecc.get(&NACKL_ECC_ID) {
                    println!("  rewards:   {} NACKL", format_balance(nackl, NACKL_DECIMALS));
                }
            }
            match pg.get_details().await {
                Ok(d) => println!("  boost:     {}", d.boosts_address),
                Err(e) => println!("  boost:     error ({e})"),
            }
        }
        Err(e) => println!("\npopitgame:   error ({e})"),
    }

    // Miner
    let tail = address.rsplit(':').next().unwrap();
    match Mirror::new_default(ctx.clone(), tail) {
        Ok(mirror) => {
            match mirror
                .get_miner(ParamsOfGetMinerAddress { multifactor_address: address.clone() })
                .await
            {
                Ok(miner) => {
                    println!("\nminer:       {}", miner.address());
                    if miner.fetch_account().await.is_ok() {
                        let deployed = miner.async_guarded(|acc| acc.is_deployed()).await;
                        println!("  deployed:  {deployed}");
                        if deployed {
                            match miner.get_details().await {
                                Ok(d) => {
                                    println!(
                                        "  mbi_cur:   {}",
                                        d.mbi_cur.map(|v| v.to_string()).unwrap_or("none".into())
                                    );
                                }
                                Err(e) => println!("  details:   error ({e})"),
                            }
                        }
                    }
                }
                Err(e) => println!("\nminer:       error ({e})"),
            }
        }
        Err(e) => println!("\nminer:       error ({e})"),
    }

    println!();
}

fn create_wallet(endpoint: &str, archive_endpoint: Option<&str>) -> bee_wallet::Wallet {
    bee_wallet::Wallet::new(bee_wallet::WalletConfig {
        endpoints: vec![endpoint.to_string()],
        archive_endpoints: archive_endpoint.map(|a| vec![a.to_string()]),
        api_url: "https://app-backend.ackinacki.org/api".to_string(),
        app_id: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ..Default::default()
    })
    .expect("create wallet")
}

async fn cmd_mining(endpoint: &str, archive_endpoint: Option<&str>, name: &str, count: usize) {
    use bee_wallet::ParamsOfGetHistory;

    let wallet = create_wallet(endpoint, archive_endpoint);

    let mf_data = match wallet.get_multifactor_data_by_name(name.to_string()).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            eprintln!("wallet '{name}' not found");
            return;
        }
        Err(e) => {
            eprintln!("error: {e:?}");
            return;
        }
    };

    println!("=== mining: {name} ({endpoint}) ===");
    println!("multifactor: {}\n", mf_data.address);

    let result = wallet
        .get_history(ParamsOfGetHistory {
            multifactor_address: mf_data.address,
            token_id: "1".to_string(),
            page_size: count as u32,
            cursor: None,
            mining_cursor: None,
        })
        .await;

    match result {
        Ok(history) => {
            let mut total = 0.0f64;
            let mut mining_count = 0;
            for tx in &history.data {
                if tx.tx_type == "Mining" {
                    let val: f64 = tx.value.parse().unwrap_or(0.0) / 1e9;
                    total += val;
                    mining_count += 1;
                    println!("  {} | {:>12.6} NACKL", tx.created_at, val);
                }
            }
            println!(
                "\n{mining_count} rewards, total: {total:.6} NACKL, has_next: {}",
                history.has_next_page
            );
        }
        Err(e) => eprintln!("error: {e:?}"),
    }
}

fn prompt(msg: &str) -> String {
    use std::io::Write;
    print!("{msg}");
    std::io::stdout().flush().unwrap();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

fn pick_endpoint() -> (&'static str, Option<&'static str>) {
    println!("Network:");
    println!("  1) mainnet");
    println!("  2) shellnet");
    let choice = prompt("Choose [1/2]: ");
    match choice.as_str() {
        "2" | "shell" | "shellnet" => (SHELLNET_ENDPOINT, None),
        _ => (MAINNET_ENDPOINT, Some(MAINNET_ARCHIVE_ENDPOINT)),
    }
}

/// Outcome of a query that has both hot and archive sources.
/// Distinguishes "really empty" (a definitive answer) from "everything failed".
enum Sourced<T> {
    /// Data successfully fetched (may be an empty vec — that's a definitive
    /// "nothing here").
    Ok { data: T, source: &'static str },
    /// All sources errored. Verdict must NOT treat this as "nothing happened".
    Inconclusive { hot_err: Option<String>, arc_err: Option<String> },
}

impl<T> Sourced<T> {
    fn is_inconclusive(&self) -> bool {
        matches!(self, Sourced::Inconclusive { .. })
    }

    fn print_status(&self, label: &str) {
        match self {
            Sourced::Ok { source, .. } => println!("  [{label}] source: {source}"),
            Sourced::Inconclusive { hot_err, arc_err } => {
                println!("  [{label}] INCONCLUSIVE — all sources failed");
                if let Some(e) = hot_err {
                    println!("    hot:     {e}");
                }
                if let Some(e) = arc_err {
                    println!("    archive: {e}");
                }
            }
        }
    }
}

/// Thin CLI-friendly wrapper around [`bee_infra::with_retry_policy`].
/// Folds the raw error into a `String` (CLI prints diagnostics — it
/// does not need to preserve typed errors) and prints a per-attempt
/// progress hint so the operator sees the retry happening on a slow
/// pool. 3 attempts × 500/1000 ms — matches the legacy local helper.
async fn with_retry<T, F, Fut, E>(label: &str, make: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let policy = bee_infra::RetryPolicy {
        max_attempts: 3,
        max_total: None,
        base_delay: std::time::Duration::from_millis(500),
        max_delay: std::time::Duration::from_millis(1000),
        jitter: false,
    };
    bee_infra::with_retry_policy(
        &policy,
        None,
        |e: &E| {
            // Cli retries on any error; the underlying tvm_client no
            // longer storms (`max_reconnect_timeout = 0` is set in
            // wallet/dex constructors), so each Err is one real miss.
            eprintln!("  [{label}] attempt failed: {e:?}");
            true
        },
        make,
    )
    .await
    .map_err(|e| format!("{e:?}"))
}

async fn cmd_audit_sell(endpoint: &str, archive_endpoint: Option<&str>, name: &str) {
    let wallet = create_wallet(endpoint, archive_endpoint);

    let mf_data = match wallet.get_multifactor_data_by_name(name.to_string()).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            eprintln!("wallet '{name}' not found");
            return;
        }
        Err(e) => {
            eprintln!("error: {e:?}");
            return;
        }
    };
    let mf = mf_data.address;

    println!("\n=== audit-sell: {name} ({endpoint}) ===");
    println!("multifactor: {mf}");
    println!("accumulator: {}", ShellAccumulatorRootUsdc::DEFAULT_ADDRESS);
    if let Some(a) = archive_endpoint {
        println!("archive:     {a}");
    }

    let hot_ctx = create_tvm_client(endpoint);
    let arc_ctx: Option<Arc<ClientContext>> = archive_endpoint.map(create_tvm_client);

    // Probe: is the accumulator at the expected address actually responsive?
    // If both hot and archive can't read getDetails, every subsequent answer
    // is meaningless — bail out loudly instead of pretending all is well.
    let acc_health = probe_accumulator(&hot_ctx, arc_ctx.as_ref()).await;
    println!("\nAccumulator health:");
    acc_health.print_status("getDetails");
    if acc_health.is_inconclusive() {
        println!("\nVerdict:");
        println!("  INCONCLUSIVE: cannot reach accumulator — investigation aborted");
        println!();
        return;
    }

    // Queue state per denom — needed to understand why kit's filter
    // `order_id >= queue_state.next_id` might drop a known order_id.
    println!("\nQueue state per denom:");
    let acc_hot = ShellAccumulatorRootUsdc::new_default(hot_ctx.clone());
    for denom in [1u16, 10, 100, 1000] {
        use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetQueueState;
        match acc_hot.get_queue_state(ParamsOfGetQueueState { d: denom }).await {
            Ok(s) => println!(
                "  denom={:<5} next_id={:<6} available={:<6} sold_prefix={:<6} owed_count={}",
                denom, s.next_id, s.available, s.sold_prefix, s.owed_count
            ),
            Err(e) => println!("  denom={denom}: error {e:?}"),
        }
    }

    // 1. Sell orders snapshot — call get_orders_by_seller directly so we can swap
    //    ctx between hot and archive on failure.
    // Diagnostic: explicitly run kit's get_orders_by_seller on hot AND
    // archive separately to compare. Helps catch the case where SDK fix
    // routes to archive but archive's run still returns empty for some
    // hidden reason (e.g. lot.get_details fails inside kit and order gets
    // silently skipped).
    {
        use ackinacki_kit::contracts::accumulator::shell_accumulator_root_usdc::ParamsOfGetOrdersBySeller;
        let acc_hot = ShellAccumulatorRootUsdc::new_default(hot_ctx.clone());
        match acc_hot
            .get_orders_by_seller(ParamsOfGetOrdersBySeller {
                seller: mf.clone(),
                limit: Some(50),
                cursor: None,
            })
            .await
        {
            Ok(r) => println!(
                "  [diag] kit.get_orders_by_seller(HOT only)     → {} orders",
                r.orders.len()
            ),
            Err(e) => println!("  [diag] kit.get_orders_by_seller(HOT only)     → ERROR: {e:?}"),
        }
        if let Some(arc) = arc_ctx.as_ref() {
            let acc_arc = ShellAccumulatorRootUsdc::new_default(arc.clone());
            match acc_arc
                .get_orders_by_seller(ParamsOfGetOrdersBySeller {
                    seller: mf.clone(),
                    limit: Some(50),
                    cursor: None,
                })
                .await
            {
                Ok(r) => {
                    println!(
                        "  [diag] kit.get_orders_by_seller(ARCHIVE only) → {} orders",
                        r.orders.len()
                    );
                    for o in &r.orders {
                        println!(
                            "    denom={} order_id={} sold={} claimed={} pos={} addr={}",
                            o.denom,
                            o.order_id,
                            o.sold,
                            o.claimed,
                            o.position_in_queue,
                            o.sell_order_address
                        );
                    }
                }
                Err(e) => {
                    println!("  [diag] kit.get_orders_by_seller(ARCHIVE only) → ERROR: {e:?}")
                }
            }
        }
    }

    let orders_outcome = fetch_orders_by_seller(&hot_ctx, arc_ctx.as_ref(), &mf).await;
    println!("\nSell orders (per accumulator state):");
    orders_outcome.print_status("get_orders_by_seller");
    let orders: Vec<KitSellerOrderInfo> = match &orders_outcome {
        Sourced::Ok { data, .. } => {
            if data.is_empty() {
                println!("  (none reported by accumulator for this seller)");
            }
            for o in data {
                let state = if o.claimed {
                    "CLAIMED".to_string()
                } else if o.sold {
                    "SOLD (claim_usdc not called)".to_string()
                } else {
                    format!("ACTIVE (queue pos {})", o.position_in_queue)
                };
                println!(
                    "  denom={:<5} order_id={:<6} {:<32} {}",
                    o.denom, o.order_id, state, o.sell_order_address
                );
            }
            data.clone()
        }
        Sourced::Inconclusive { .. } => Vec::new(),
    };

    // 2. Accumulator events filtered by seller — definitive proof of activity.
    let acc_events_outcome = fetch_accumulator_events(&hot_ctx, arc_ctx.as_ref(), &mf).await;
    println!("\nAccumulator events for this seller:");
    acc_events_outcome.print_status("query_events");
    if let Sourced::Ok { data, .. } = &acc_events_outcome {
        if data.is_empty() {
            println!(
                "  (none — accumulator never emitted SellOrderCreated/UsdcClaimed for this wallet)"
            );
        } else {
            for ev in data.iter().rev() {
                println!("  {}", format_acc_event(ev));
            }
        }
    }

    // 3. Per-lot drill-down. Union the lots we know about: those reported by
    //    get_orders_by_seller (current state) PLUS any (denom,order_id) pairs we
    //    saw in the SellOrderCreated event log (catches orders older than hot's 24h
    //    window which kit's get_orders_by_seller misses internally).
    let mut lots_to_inspect: Vec<(u16, u64, Option<String>)> =
        orders.iter().map(|o| (o.denom, o.order_id, Some(o.sell_order_address.clone()))).collect();
    if let Sourced::Ok { data: events, .. } = &acc_events_outcome {
        for ev in events {
            if let DecodedAccumulatorRootEvent::SellOrderCreated { data, .. } = ev {
                if !lots_to_inspect
                    .iter()
                    .any(|(d, oid, _)| *d == data.denom && *oid == data.order_id)
                {
                    lots_to_inspect.push((data.denom, data.order_id, None));
                }
            }
        }
    }

    if !lots_to_inspect.is_empty() {
        println!("\nLot drill-down:");
        let acc = ShellAccumulatorRootUsdc::new_default(hot_ctx.clone());
        for (denom, order_id, known_addr) in &lots_to_inspect {
            // Resolve the lot address. If we already had it from
            // get_orders_by_seller, use that; otherwise compute via the
            // accumulator getter (cheap, current-state, no archive needed).
            let address = match known_addr {
                Some(a) => a.clone(),
                None => match acc
                    .get_sell_order_address(ParamsOfGetSellOrderAddress {
                        d: *denom,
                        order_id: *order_id,
                    })
                    .await
                {
                    Ok(r) => r.sell_order_addr,
                    Err(e) => {
                        println!(
                            "\n  -- denom={denom} order_id={order_id} addr=?  (cannot derive: {e:?})"
                        );
                        continue;
                    }
                },
            };
            println!("\n  -- denom={denom} order_id={order_id} addr={address}");
            let state_outcome = fetch_lot_state(&hot_ctx, arc_ctx.as_ref(), &address).await;
            state_outcome.print_status("lot.fetchAccount");
            if let Sourced::Ok { data, .. } = &state_outcome {
                print_lot_state(data);
            }

            let lot_events_outcome = fetch_lot_events(&hot_ctx, arc_ctx.as_ref(), &address).await;
            lot_events_outcome.print_status("lot.queryEvents");
            if let Sourced::Ok { data, .. } = &lot_events_outcome {
                if data.is_empty() {
                    println!("    events: (none)");
                } else {
                    for ev in data.iter().rev() {
                        println!("    {}", format_lot_event(ev));
                    }
                }
            }
        }
    }

    // 4. Verdict — only fire conclusions for sources that actually returned.
    println!("\nVerdict:");
    print_verdict(&orders_outcome, &orders, &acc_events_outcome);

    println!();
}

async fn probe_accumulator(
    hot: &Arc<ClientContext>,
    arc: Option<&Arc<ClientContext>>,
) -> Sourced<()> {
    let hot_acc = ShellAccumulatorRootUsdc::new_default(hot.clone());
    let hot_res = with_retry("acc.getDetails(hot)", || hot_acc.get_details()).await;
    if hot_res.is_ok() {
        return Sourced::Ok { data: (), source: "hot" };
    }
    let hot_err = hot_res.err();

    if let Some(arc) = arc {
        let arc_acc = ShellAccumulatorRootUsdc::new_default(arc.clone());
        let arc_res = with_retry("acc.getDetails(archive)", || arc_acc.get_details()).await;
        if arc_res.is_ok() {
            return Sourced::Ok { data: (), source: "archive" };
        }
        return Sourced::Inconclusive { hot_err, arc_err: arc_res.err() };
    }
    Sourced::Inconclusive { hot_err, arc_err: None }
}

async fn fetch_orders_by_seller(
    hot: &Arc<ClientContext>,
    arc: Option<&Arc<ClientContext>>,
    seller: &str,
) -> Sourced<Vec<KitSellerOrderInfo>> {
    async fn paginate(
        ctx: &Arc<ClientContext>,
        seller: &str,
        label: &'static str,
    ) -> Result<Vec<KitSellerOrderInfo>, String> {
        let acc = ShellAccumulatorRootUsdc::new_default(ctx.clone());
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = ParamsOfGetOrdersBySeller {
                seller: seller.to_string(),
                limit: Some(50),
                cursor: cursor.clone(),
            };
            let page = with_retry(label, || acc.get_orders_by_seller(params.clone())).await?;
            out.extend(page.orders);
            if !page.has_next_page {
                break;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    let hot_res = paginate(hot, seller, "get_orders_by_seller(hot)").await;
    match hot_res {
        Ok(v) => return Sourced::Ok { data: v, source: "hot" },
        Err(hot_err) => {
            if let Some(arc) = arc {
                match paginate(arc, seller, "get_orders_by_seller(archive)").await {
                    Ok(v) => return Sourced::Ok { data: v, source: "archive (hot failed)" },
                    Err(arc_err) => {
                        return Sourced::Inconclusive {
                            hot_err: Some(hot_err),
                            arc_err: Some(arc_err),
                        }
                    }
                }
            }
            Sourced::Inconclusive { hot_err: Some(hot_err), arc_err: None }
        }
    }
}

/// Hand-rolled GraphQL query for `account.events`, lenient to a `null` events
/// field on the response (kit's strict deserializer chokes on that —
/// archive.mainnet.ackinacki.org returns `{"events": null}` when the account
/// has no events, instead of `{"events": {"edges": []}}`).
async fn lenient_query_account_events(
    ctx: &Arc<ClientContext>,
    address: &str,
    page_size: u32,
) -> Result<Vec<KitEvent>, String> {
    const GQL: &str = r#"
        query($address: String!, $last: Int!, $before: String) {
          blockchain {
            account(address: $address) {
              events(last: $last, before: $before) {
                edges {
                  cursor
                  node { msg_id created_at dst body }
                }
              }
            }
          }
        }
    "#;
    const GQL_V3: &str = r#"
        query($account_id: String!, $dapp_id: String!, $last: Int!, $before: String) {
          blockchain {
            account(account_id: $account_id, dapp_id: $dapp_id) {
              events(last: $last, before: $before) {
                edges {
                  cursor
                  node { msg_id created_at dst body }
                }
              }
            }
          }
        }
    "#;

    // Diagnostic accounts queried here are mvsystem (Mobile Verifiers dApp).
    let v3 = bee_wallet::dapp::server_uses_dapp_id(ctx).await.map_err(|e| e.to_string())?;
    let dapp_id = ackinacki_kit::contracts::dapp::SystemDapp::MobileVerifiers.dapp_id();
    let mut all = Vec::new();
    let before: Option<String> = None;
    loop {
        let raw = gql_query(
            ctx.clone(),
            GqlParams {
                query: if v3 { GQL_V3 } else { GQL }.to_string(),
                variables: Some(if v3 {
                    serde_json::json!({
                        "account_id": bee_wallet::dapp::account_id(address),
                        "dapp_id": dapp_id,
                        "last": page_size,
                        "before": before,
                    })
                } else {
                    serde_json::json!({
                        "address": address,
                        "last": page_size,
                        "before": before,
                    })
                }),
            },
        )
        .await
        .map_err(|e| format!("{e:?}"))?;

        // Walk the JSON manually so a `null` at events doesn't blow up.
        let events = raw
            .result
            .get("data")
            .and_then(|v| v.get("blockchain"))
            .and_then(|v| v.get("account"))
            .and_then(|v| v.get("events"));
        let edges = match events {
            None | Some(serde_json::Value::Null) => break,
            Some(v) => v.get("edges").and_then(|e| e.as_array()).cloned().unwrap_or_default(),
        };
        if edges.is_empty() {
            break;
        }

        let next_before = edges
            .first()
            .and_then(|e| e.get("cursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        for edge in &edges {
            let Some(node) = edge.get("node") else { continue };
            let msg_id =
                node.get("msg_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let dst = node.get("dst").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let body = node.get("body").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let created_at = node.get("created_at").and_then(|v| v.as_u64()).unwrap_or_default();
            all.push(KitEvent { id: msg_id, dst, created_at, body });
        }

        // Fetched a single page only — `limit` semantics in our caller mean
        // "give me up to this many"; one page covers it for our use case.
        let _ = next_before;
        break;
    }
    Ok(all)
}

async fn fetch_accumulator_events(
    hot: &Arc<ClientContext>,
    arc: Option<&Arc<ClientContext>>,
    seller: &str,
) -> Sourced<Vec<DecodedAccumulatorRootEvent>> {
    async fn run(
        ctx: &Arc<ClientContext>,
        seller: &str,
        label: &'static str,
    ) -> Result<Vec<DecodedAccumulatorRootEvent>, String> {
        let acc = ShellAccumulatorRootUsdc::new_default(ctx.clone());
        let raw_events = with_retry(label, || {
            lenient_query_account_events(ctx, ShellAccumulatorRootUsdc::DEFAULT_ADDRESS, 500)
        })
        .await?;
        let mut decoded = Vec::new();
        let mut all_sellers_count = std::collections::HashMap::<String, usize>::new();
        let mut total_sell_order_created = 0usize;
        for ev in raw_events {
            if let Ok(d) = DecodedAccumulatorRootEvent::from_event(&ev, &acc) {
                if let DecodedAccumulatorRootEvent::SellOrderCreated { data, .. } = &d {
                    total_sell_order_created += 1;
                    *all_sellers_count.entry(data.seller.clone()).or_default() += 1;
                }
                if event_concerns_seller(&d, seller) {
                    decoded.push(d);
                }
            }
        }
        if decoded.is_empty() && total_sell_order_created > 0 {
            eprintln!(
                "    [debug] {total_sell_order_created} SellOrderCreated event(s) from {} unique sellers; none match '{seller}'",
                all_sellers_count.len()
            );
            let mut sellers_sorted: Vec<(String, usize)> =
                all_sellers_count.iter().map(|(k, v)| (k.clone(), *v)).collect();
            sellers_sorted.sort_by(|a, b| b.1.cmp(&a.1));
            for (s, c) in &sellers_sorted {
                eprintln!("      {c:>3}x  {s}");
            }
        }
        Ok(decoded)
    }
    // Hot mainnet keeps only ~24h of message history. Empty on hot is NOT a
    // definitive answer for "no activity ever" — fall back to archive on both
    // error AND empty for event queries. (Getters that read current contract
    // state are different — see fetch_orders_by_seller; both nodes return the
    // same current state, so empty there is conclusive.)
    let hot_res = run(hot, seller, "acc.queryEvents(hot)").await;
    match (&hot_res, arc) {
        (Ok(v), _) if !v.is_empty() => {
            return Sourced::Ok { data: hot_res.unwrap(), source: "hot" }
        }
        (Ok(_), None) => {
            return Sourced::Ok { data: hot_res.unwrap(), source: "hot (no archive available)" }
        }
        (Ok(_), Some(arc_ctx)) => match run(arc_ctx, seller, "acc.queryEvents(archive)").await {
            Ok(v) => Sourced::Ok { data: v, source: "archive (hot was empty)" },
            Err(arc_err) => Sourced::Inconclusive {
                hot_err: Some("hot returned empty".to_string()),
                arc_err: Some(arc_err),
            },
        },
        (Err(_), None) => Sourced::Inconclusive { hot_err: hot_res.err(), arc_err: None },
        (Err(_), Some(arc_ctx)) => match run(arc_ctx, seller, "acc.queryEvents(archive)").await {
            Ok(v) => Sourced::Ok { data: v, source: "archive (hot failed)" },
            Err(arc_err) => {
                Sourced::Inconclusive { hot_err: hot_res.err(), arc_err: Some(arc_err) }
            }
        },
    }
}

async fn fetch_lot_state(
    hot: &Arc<ClientContext>,
    arc: Option<&Arc<ClientContext>>,
    address: &str,
) -> Sourced<LotState> {
    async fn read(
        ctx: &Arc<ClientContext>,
        address: &str,
        label: &'static str,
    ) -> Result<LotState, String> {
        let lot = ShellSellOrderLot::new_default(ctx.clone(), address);
        with_retry(label, || lot.fetch_account()).await?;
        let deployed = lot.async_guarded(|acc| acc.is_deployed()).await;
        let balance = lot.async_guarded(|acc| acc.balance.clone()).await;
        let ecc = lot.async_guarded(|acc| acc.ecc.clone()).await;
        Ok(LotState {
            deployed,
            vmshell: balance,
            shell: ecc.get(&SHELL_ECC_ID).cloned(),
            usdc: ecc.get(&USDC_ECC_ID).cloned(),
        })
    }
    match read(hot, address, "lot.fetchAccount(hot)").await {
        Ok(v) => Sourced::Ok { data: v, source: "hot" },
        Err(hot_err) => {
            if let Some(arc) = arc {
                match read(arc, address, "lot.fetchAccount(archive)").await {
                    Ok(v) => Sourced::Ok { data: v, source: "archive (hot failed)" },
                    Err(arc_err) => {
                        Sourced::Inconclusive { hot_err: Some(hot_err), arc_err: Some(arc_err) }
                    }
                }
            } else {
                Sourced::Inconclusive { hot_err: Some(hot_err), arc_err: None }
            }
        }
    }
}

async fn fetch_lot_events(
    hot: &Arc<ClientContext>,
    arc: Option<&Arc<ClientContext>>,
    address: &str,
) -> Sourced<Vec<DecodedSellOrderLotEvent>> {
    async fn run(
        ctx: &Arc<ClientContext>,
        address: &str,
        label: &'static str,
    ) -> Result<Vec<DecodedSellOrderLotEvent>, String> {
        let lot = ShellSellOrderLot::new_default(ctx.clone(), address);
        let raw_events =
            with_retry(label, || lenient_query_account_events(ctx, address, 50)).await?;
        let mut decoded = Vec::new();
        for ev in raw_events {
            if let Ok(d) = DecodedSellOrderLotEvent::from_event(&ev, &lot) {
                decoded.push(d);
            }
        }
        Ok(decoded)
    }
    // Same retention concern as accumulator events — fall back on empty too.
    let hot_res = run(hot, address, "lot.queryEvents(hot)").await;
    match (&hot_res, arc) {
        (Ok(v), _) if !v.is_empty() => Sourced::Ok { data: hot_res.unwrap(), source: "hot" },
        (Ok(_), None) => {
            Sourced::Ok { data: hot_res.unwrap(), source: "hot (no archive available)" }
        }
        (Ok(_), Some(arc_ctx)) => match run(arc_ctx, address, "lot.queryEvents(archive)").await {
            Ok(v) => Sourced::Ok { data: v, source: "archive (hot was empty)" },
            Err(arc_err) => Sourced::Inconclusive {
                hot_err: Some("hot returned empty".to_string()),
                arc_err: Some(arc_err),
            },
        },
        (Err(_), None) => Sourced::Inconclusive { hot_err: hot_res.err(), arc_err: None },
        (Err(_), Some(arc_ctx)) => match run(arc_ctx, address, "lot.queryEvents(archive)").await {
            Ok(v) => Sourced::Ok { data: v, source: "archive (hot failed)" },
            Err(arc_err) => {
                Sourced::Inconclusive { hot_err: hot_res.err(), arc_err: Some(arc_err) }
            }
        },
    }
}

fn format_acc_event(ev: &DecodedAccumulatorRootEvent) -> String {
    match ev {
        DecodedAccumulatorRootEvent::SellOrderCreated { event, data, .. } => format!(
            "{} SellOrderCreated  denom={} order_id={} shells={}",
            event.created_at, data.denom, data.order_id, data.shell_amount
        ),
        DecodedAccumulatorRootEvent::UsdcClaimed { event, data, .. } => format!(
            "{} UsdcClaimed       denom={} order_id={} payout={}",
            event.created_at, data.denom, data.order_id, data.payout
        ),
        DecodedAccumulatorRootEvent::ShellPurchased { event, data, .. } => format!(
            "{} ShellPurchased    buyer={} usdc={} from_sellers={} minted={}",
            event.created_at,
            data.buyer,
            data.usdc_amount,
            data.shell_from_sellers,
            data.shell_minted
        ),
        DecodedAccumulatorRootEvent::NacklRedeemed { event, data, .. } => format!(
            "{} NacklRedeemed     recipient={} burn={} payout={}",
            event.created_at, data.recipient, data.burn_amount, data.payout
        ),
        DecodedAccumulatorRootEvent::MatchedOrders { event, data, .. } => format!(
            "{} MatchedOrders     d1={} d10={} d100={} d1000={}",
            event.created_at,
            data.last_sold_1,
            data.last_sold_10,
            data.last_sold_100,
            data.last_sold_1000
        ),
    }
}

fn format_lot_event(ev: &DecodedSellOrderLotEvent) -> String {
    match ev {
        DecodedSellOrderLotEvent::ClaimInitiated { event, .. } => {
            format!("{} ClaimInitiated", event.created_at)
        }
        DecodedSellOrderLotEvent::OrderDestroyed { event, .. } => {
            format!("{} OrderDestroyed", event.created_at)
        }
    }
}

fn event_concerns_seller(ev: &DecodedAccumulatorRootEvent, seller: &str) -> bool {
    match ev {
        DecodedAccumulatorRootEvent::SellOrderCreated { data, .. } => data.seller == seller,
        DecodedAccumulatorRootEvent::UsdcClaimed { data, .. } => data.seller == seller,
        DecodedAccumulatorRootEvent::NacklRedeemed { data, .. } => data.recipient == seller,
        // Buys / matches don't carry the seller; they're network-wide signals.
        // Drop them from the per-seller timeline.
        _ => false,
    }
}

struct LotState {
    deployed: bool,
    vmshell: Option<num_bigint::BigInt>,
    shell: Option<num_bigint::BigInt>,
    usdc: Option<num_bigint::BigInt>,
}

fn print_lot_state(state: &LotState) {
    println!(
        "    state: deployed={}  vmshell={}  shell={}  usdc={}",
        state.deployed,
        state.vmshell.as_ref().map(|b| format_balance(b, 9)).unwrap_or_else(|| "-".into()),
        state
            .shell
            .as_ref()
            .map(|b| format_balance(b, SHELL_DECIMALS))
            .unwrap_or_else(|| "-".into()),
        state.usdc.as_ref().map(|b| format_balance(b, USDC_DECIMALS)).unwrap_or_else(|| "-".into()),
    );
}

fn print_verdict(
    orders_outcome: &Sourced<Vec<KitSellerOrderInfo>>,
    orders: &[KitSellerOrderInfo],
    acc_events_outcome: &Sourced<Vec<DecodedAccumulatorRootEvent>>,
) {
    // Hard rule: any inconclusive source means we don't know — never say CLEAN.
    if orders_outcome.is_inconclusive() || acc_events_outcome.is_inconclusive() {
        println!("  INCONCLUSIVE: at least one data source is unreachable.");
        if orders_outcome.is_inconclusive() {
            println!("    - get_orders_by_seller failed on all sources");
        }
        if acc_events_outcome.is_inconclusive() {
            println!("    - accumulator queryEvents failed on all sources");
        }
        println!("    Re-run later or use a different node before drawing conclusions.");
        return;
    }

    // Both sources answered — derive counts from outcomes (which own the data).
    let acc_events_data = match acc_events_outcome {
        Sourced::Ok { data, .. } => data.as_slice(),
        Sourced::Inconclusive { .. } => &[][..],
    };

    let active = orders.iter().filter(|o| !o.sold && !o.claimed).count();
    let pending_claim = orders.iter().filter(|o| o.sold && !o.claimed).count();
    let claimed = orders.iter().filter(|o| o.claimed).count();

    let created_in_events = acc_events_data
        .iter()
        .filter(|e| matches!(e, DecodedAccumulatorRootEvent::SellOrderCreated { .. }))
        .count();
    let claimed_in_events = acc_events_data
        .iter()
        .filter(|e| matches!(e, DecodedAccumulatorRootEvent::UsdcClaimed { .. }))
        .count();

    if pending_claim > 0 {
        println!("  ACTION: {pending_claim} order(s) sold but USDC not claimed — call claim_usdc");
    }
    if active > 0 {
        println!("  INFO:   {active} order(s) still active in queue (awaiting buyer)");
    }
    if claimed > 0 {
        println!("  INFO:   {claimed} order(s) already claimed");
    }
    if orders.is_empty() && created_in_events == 0 {
        println!(
            "  CLEAN:  no orders and no SellOrderCreated/UsdcClaimed events — wallet never interacted with accumulator"
        );
    }
    if created_in_events > orders.len() {
        // This isn't an anomaly: kit's get_orders_by_seller queries
        // SellOrderCreated events through hot's 24h window internally, so
        // older orders that DO show in our archive-backed event scan won't
        // appear in its result. Trust the event log + lot drill-down for
        // ground truth on those.
        let missing = created_in_events - orders.len();
        println!(
            "  NOTE:   archive shows {created_in_events} SellOrderCreated event(s); get_orders_by_seller only saw {} — {missing} order(s) older than hot's 24h window. Inspect lot drill-down for actual state.",
            orders.len()
        );
        if claimed_in_events == 0 {
            println!(
                "  ACTION: no UsdcClaimed event(s) for those — either still active, or sold-but-not-claimed (lot drill-down distinguishes which). If sold, call claim_usdc."
            );
        }
    }
    if claimed_in_events > 0
        && pending_claim == 0
        && claimed == 0
        && created_in_events == orders.len()
    {
        println!(
            "  NOTE:   {claimed_in_events} UsdcClaimed event(s) seen but no claimed orders surfaced — claimed lots typically self-destruct, so this is consistent."
        );
    }
}

/// Calls `Wallet.get_my_sell_orders` exactly as the mobile/web app would,
/// twice: once with the archive wired in (the new behavior after the SDK
/// fix), once without (the old behavior). Prints both results side-by-side
/// so you can see whether the archive is the thing producing/missing orders.
async fn cmd_sdk_orders(endpoint: &str, archive_endpoint: Option<&str>, name: &str) {
    use bee_wallet::GetMySellOrdersReq;

    // First resolve the multifactor address via the same path the app uses.
    let wallet_with_arc = create_wallet(endpoint, archive_endpoint);
    let mf = match wallet_with_arc.get_multifactor_data_by_name(name.to_string()).await {
        Ok(Some(d)) => d.address,
        Ok(None) => {
            eprintln!("wallet '{name}' not found");
            return;
        }
        Err(e) => {
            eprintln!("get_multifactor_data_by_name error: {e:?}");
            return;
        }
    };

    println!("\n=== sdk-orders: {name} ===");
    println!("multifactor: {mf}");
    println!("endpoint:    {endpoint}");
    println!("archive:     {}", archive_endpoint.unwrap_or("(none — running hot-only test only)"));

    async fn one_pass(wallet: &bee_wallet::Wallet, mf: &str, label: &str) {
        println!("\n--- {label} ---");
        let mut total = 0usize;
        let mut cursor: Option<String> = None;
        let mut page = 0;
        loop {
            page += 1;
            let req = GetMySellOrdersReq {
                multifactor_address: mf.to_string(),
                page_size: 50,
                cursor: cursor.clone(),
            };
            match wallet.get_my_sell_orders(req).await {
                Ok(r) => {
                    println!(
                        "page {page}: {} orders, has_next={}",
                        r.orders.len(),
                        r.has_next_page
                    );
                    for o in &r.orders {
                        let state = if o.claimed {
                            "CLAIMED".to_string()
                        } else if o.sold {
                            "SOLD (claim_usdc not called)".to_string()
                        } else {
                            format!("ACTIVE (pos {})", o.position_in_queue)
                        };
                        println!(
                            "  denom={:<5} order_id={:<6} {:<32} {}",
                            o.denom, o.order_id, state, o.sell_order_address
                        );
                    }
                    total += r.orders.len();
                    if !r.has_next_page {
                        break;
                    }
                    cursor = r.next_cursor;
                    if cursor.is_none() {
                        break;
                    }
                }
                Err(e) => {
                    println!("page {page}: ERROR — {e:?}");
                    break;
                }
            }
        }
        println!("total: {total} orders");
    }

    one_pass(&wallet_with_arc, &mf, "WITH archive (what the app sees now after SDK fix)").await;

    if archive_endpoint.is_some() {
        let wallet_hot_only = create_wallet(endpoint, None);
        one_pass(&wallet_hot_only, &mf, "WITHOUT archive (what the app used to see)").await;
    }

    println!();
}

#[tokio::main]
async fn main() {
    println!("Wallet Info\n");

    let (endpoint, archive_endpoint) = pick_endpoint();
    println!();

    loop {
        let name = prompt("wallet name (or 'q' to quit): ");
        if name.is_empty() {
            continue;
        }
        if name == "q" || name == "quit" || name == "exit" {
            break;
        }

        println!("  1) info");
        println!("  2) mining");
        println!("  3) audit-sell");
        println!("  4) sdk-orders (simulate app)");
        let choice = prompt("  choose [1/2/3/4]: ");

        match choice.as_str() {
            "2" | "mining" => {
                let count_str = prompt("  how many rewards? [20]: ");
                let count: usize = count_str.parse().unwrap_or(20);
                cmd_mining(endpoint, archive_endpoint, &name, count).await;
            }
            "3" | "audit" | "audit-sell" => {
                cmd_audit_sell(endpoint, archive_endpoint, &name).await;
            }
            "4" | "sdk" | "sdk-orders" => {
                cmd_sdk_orders(endpoint, archive_endpoint, &name).await;
            }
            _ => {
                cmd_info(endpoint, &name).await;
            }
        }
    }
}
