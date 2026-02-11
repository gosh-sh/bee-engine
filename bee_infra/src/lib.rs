#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
async fn sleep_ms(ms: u64) {
    use gloo_timers::future::TimeoutFuture;

    let ms_u32 = ms.min(u32::MAX as u64) as u32;
    TimeoutFuture::new(ms_u32).await;
}

#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
async fn sleep_ms(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

pub async fn poll_until<T, FetchFn, FetchFut, VerifyFn>(
    fetch_data: FetchFn,
    predicate: VerifyFn,
    max_attempts: Option<u32>,
    interval_ms: Option<u64>,
) -> Result<T, String>
where
    FetchFn: Fn() -> FetchFut,
    FetchFut: std::future::Future<Output = Result<T, String>>,
    VerifyFn: Fn(&T) -> bool,
{
    let mut attempts = 0;
    let max_attempts = max_attempts.unwrap_or(100);
    let interval_ms = interval_ms.unwrap_or(100);

    if max_attempts == 0 {
        return Err("Wait for property. Max 0 attempts reached.".to_string());
    }

    loop {
        let data = fetch_data().await?;

        if predicate(&data) {
            return Ok(data);
        }

        attempts += 1;
        if attempts >= max_attempts {
            return Err(format!("Wait for property. Max {max_attempts} attempts reached."));
        }

        sleep_ms(interval_ms).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use futures::executor::block_on;

    #[test]
    fn poll_until_returns_when_predicate_passes() {
        let attempts = AtomicUsize::new(0);

        let result = block_on(super::poll_until(
            || async {
                let current = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<usize, String>(current)
            },
            |value| *value >= 3,
            Some(10),
            Some(0),
        ))
        .expect("poll_until should return value");

        assert_eq!(result, 3);
    }

    #[test]
    fn poll_until_fails_when_attempts_exhausted() {
        let attempts = AtomicUsize::new(0);

        let error = block_on(super::poll_until(
            || async {
                let current = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<usize, String>(current)
            },
            |_| false,
            Some(3),
            Some(0),
        ))
        .expect_err("poll_until should fail");

        assert!(error.contains("Max 3 attempts reached"));
    }
}
