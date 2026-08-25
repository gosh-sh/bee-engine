#[cfg(feature = "message-delivery")]
pub mod message_delivery;
mod rate_limiter;
pub mod retry;
pub use rate_limiter::maybe_acquire;
pub use rate_limiter::RateLimiter;
pub use retry::with_retry_policy;
pub use retry::RetryPolicy;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub async fn sleep_ms(ms: u64) {
    use gloo_timers::future::TimeoutFuture;

    let ms_u32 = ms.min(u32::MAX as u64) as u32;
    TimeoutFuture::new(ms_u32).await;
}

#[cfg(all(not(all(feature = "wasm", target_arch = "wasm32")), feature = "tokio"))]
pub async fn sleep_ms(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}

#[cfg(all(not(all(feature = "wasm", target_arch = "wasm32")), not(feature = "tokio")))]
pub async fn sleep_ms(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

pub async fn poll_until<T, E, FetchFn, FetchFut, VerifyFn>(
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
    let mut attempts = 0;
    let max_attempts = max_attempts.unwrap_or(100);
    let interval_ms = interval_ms.unwrap_or(100);
    let max_attempts_err =
        || E::from(format!("Wait for property. Max {max_attempts} attempts reached."));

    if max_attempts == 0 {
        return Err(max_attempts_err());
    }

    loop {
        let data = fetch_data().await?;

        if predicate(&data) {
            return Ok(data);
        }

        attempts += 1;
        if attempts >= max_attempts {
            return Err(max_attempts_err());
        }

        sleep_ms(interval_ms).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    async fn poll_until_returns_when_predicate_passes_impl() {
        let attempts = AtomicUsize::new(0);

        let result = super::poll_until(
            || async {
                let current = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<usize, String>(current)
            },
            |value| *value >= 3,
            Some(10),
            Some(0),
        )
        .await
        .expect("poll_until should return value");

        assert_eq!(result, 3);
    }

    async fn poll_until_fails_when_attempts_exhausted_impl() {
        let attempts = AtomicUsize::new(0);

        let error = super::poll_until(
            || async {
                let current = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<usize, String>(current)
            },
            |_| false,
            Some(3),
            Some(0),
        )
        .await
        .expect_err("poll_until should fail");

        assert!(error.contains("Max 3 attempts reached"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn poll_until_returns_when_predicate_passes() {
        poll_until_returns_when_predicate_passes_impl().await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn poll_until_fails_when_attempts_exhausted() {
        poll_until_fails_when_attempts_exhausted_impl().await;
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    async fn poll_until_returns_when_predicate_passes() {
        poll_until_returns_when_predicate_passes_impl().await;
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    async fn poll_until_fails_when_attempts_exhausted() {
        poll_until_fails_when_attempts_exhausted_impl().await;
    }
}
