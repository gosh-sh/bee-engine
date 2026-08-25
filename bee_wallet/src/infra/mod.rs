pub use bee_infra::poll_until;

/// Like `poll_until`, but calls `rate_limiter.acquire()` before each fetch.
pub async fn poll_until_rated<T, E, FetchFn, FetchFut, VerifyFn>(
    rate_limiter: Option<&bee_infra::RateLimiter>,
    fetch_data: FetchFn,
    predicate: VerifyFn,
    max_attempts: Option<u32>,
    interval_ms: Option<u64>,
) -> Result<T, E>
where
    FetchFn: Fn() -> FetchFut,
    FetchFut: std::future::Future<Output = Result<T, E>>,
    VerifyFn: Fn(&T) -> bool,
    E: From<String>,
{
    poll_until(
        || async {
            bee_infra::maybe_acquire(rate_limiter).await;
            fetch_data().await
        },
        predicate,
        max_attempts,
        interval_ms,
    )
    .await
}

fn is_retryable_tvm_transient(err: &crate::errors::AppError) -> bool {
    if err.error_code.as_deref() == Some("52")
        && matches!(err.kind.as_deref(), Some("tvm_exit") | Some("tvm"))
    {
        return true;
    }

    if matches!(err.error_code.as_deref(), Some("621") | Some("623"))
        && err.kind.as_deref() == Some("tvm")
    {
        return true;
    }

    err.message.contains("exit_code=52")
        || err.details.as_deref().is_some_and(|details| {
            details.contains("exit_code=52")
                || details.contains("tvm_code=621")
                || details.contains("tvm_code=623")
        })
}

pub fn is_confirmation_pending_error(err: &crate::errors::AppError) -> bool {
    if err.message.contains("Wait for property. Max") && err.message.contains("attempts reached") {
        return true;
    }

    err.details.as_deref().is_some_and(|details| {
        (details.contains("Wait for property. Max") && details.contains("attempts reached"))
            || details.contains("timed out")
            || details.contains("timeout")
    }) || err.message.contains("timed out")
        || err.message.contains("timeout")
}

/// Bounded, classified retry around `op`. Preserves the legacy
/// signature so existing callers (deploy, multifactor flows) don't
/// have to change — internally delegates to
/// [`bee_infra::retry::with_retry_policy`]. This helper is not used for
/// on-chain sends; message delivery is owned by `message_delivery`.
///
/// Built-in classifier: TVM exit codes 52 / 621 / 623 (contract-level
/// transients). Callers can OR in their own `should_retry` predicate
/// when a read operation has an additional retryable condition.
pub async fn with_retry<T, Op, Fut, ShouldRetry>(
    op: Op,
    max_attempts: u32,
    delay_ms: u64,
    should_retry: Option<ShouldRetry>,
) -> crate::errors::AppResult<T>
where
    Op: FnMut() -> Fut,
    Fut: std::future::Future<Output = crate::errors::AppResult<T>>,
    ShouldRetry: Fn(&crate::errors::AppError) -> bool,
{
    if max_attempts == 0 {
        return Err(crate::errors::AppError::new("with_retry: max_attempts must be > 0"));
    }

    let policy = bee_infra::RetryPolicy {
        max_attempts,
        max_total: None,
        base_delay: std::time::Duration::from_millis(delay_ms),
        max_delay: std::time::Duration::from_millis(delay_ms),
        jitter: false,
    };
    bee_infra::with_retry_policy(
        &policy,
        None,
        |err: &crate::errors::AppError| {
            is_retryable_tvm_transient(err) || should_retry.as_ref().is_some_and(|r| r(err))
        },
        op,
    )
    .await
}

pub fn now_ms() -> crate::errors::AppResult<u64> {
    #[cfg(feature = "wasm")]
    {
        Ok(js_sys::Date::now() as u64)
    }
    #[cfg(not(feature = "wasm"))]
    {
        use std::time::SystemTime;
        use std::time::UNIX_EPOCH;

        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                crate::errors::AppError::new(format!("SystemTime before UNIX_EPOCH ({e})"))
            })?
            .as_millis() as u64)
    }
}

pub fn now_secs() -> u64 {
    {
        #[cfg(feature = "wasm")]
        {
            (js_sys::Date::now() / 1000.0) as u64
        }
        #[cfg(not(feature = "wasm"))]
        {
            use std::time::SystemTime;
            use std::time::UNIX_EPOCH;
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_bg<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(fut);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_bg<F>(fut: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(fut);
}

/// Checks that a transaction was not aborted and has zero exit code.
/// Returns the original result on success, or an AppError on failure.
pub fn ensure_tx_success(
    result: ackinacki_kit::tvm_client::processing::ResultOfSendMessage,
    context: &str,
) -> crate::errors::AppResult<ackinacki_kit::tvm_client::processing::ResultOfSendMessage> {
    let aborted = result.aborted.unwrap_or(false);
    let exit_code = result.exit_code.unwrap_or(0);

    if aborted || exit_code > 0 {
        return Err(crate::errors::AppError::new(format!(
            "{context}: tx aborted={aborted}, exit_code={exit_code}",
        )));
    }

    Ok(result)
}
