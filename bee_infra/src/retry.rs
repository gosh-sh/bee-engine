//! Classified retry wrapper for HTTP / RPC calls.
//!
//! The transport under us (tvm_client) historically had an unbounded
//! re-connect loop in `query_graphql` that, on multi-endpoint setups,
//! spun without sleep until `max_reconnect_timeout` (default 120 s),
//! turning a single 502 into a sustained ~60 rps storm against the
//! same BM. The shared client construction now sets that knob to 0,
//! so the transport returns the first failure verbatim. This module
//! puts a single, bounded, exponentially-backed-off retry on top.
//!
//! Known gap: `tvm_client` strips response headers before surfacing
//! errors, so we cannot honour `Retry-After` here. Worst case the
//! exponential backoff already gives the server time to recover; if
//! we ever need true `Retry-After` semantics we'd have to patch
//! tvm-sdk upstream.
//!
//! Callers supply:
//! - a [`RetryPolicy`] (attempts cap, total time cap, base/max delay, jitter
//!   on/off);
//! - an optional [`RateLimiter`] re-acquired on every attempt so retries
//!   actually count against the configured rps;
//! - a `should_retry` predicate over the error type — callers know their domain
//!   (TVM contract codes vs HTTP transient classes).

use std::time::Duration;

use crate::RateLimiter;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total number of attempts including the initial one.
    /// Setting this to 1 disables retries.
    pub max_attempts: u32,
    /// Wall-clock cap across all attempts. `None` = unbounded.
    /// The first attempt is always tried even if the budget is
    /// already exhausted; the cap gates whether to sleep+retry.
    pub max_total: Option<Duration>,
    /// Starting delay for the exponential backoff: `2^(attempt-1) * base`.
    pub base_delay: Duration,
    /// Per-attempt delay cap (after exponential growth and jitter).
    pub max_delay: Duration,
    /// Add up to `base_delay` of randomized jitter to each sleep
    /// so colliding clients don't all reconnect on the same tick.
    pub jitter: bool,
}

impl RetryPolicy {
    /// Default for HTTP-style transient errors. Matches the spec in
    /// `docs/bee_engine_issues/retry_policy.md` (5 attempts, 60 s
    /// total cap, 500 ms base, 30 s max, jitter on).
    pub const fn http_default() -> Self {
        Self {
            max_attempts: 5,
            max_total: Some(Duration::from_secs(60)),
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            jitter: true,
        }
    }

    /// Legacy preset used by `bee_wallet::infra::with_retry` callers
    /// (TVM-contract-level transient codes). 3 attempts, constant
    /// 1 s delay, no jitter — preserves existing behavior so the
    /// migration is a no-op for those call sites.
    pub const fn tvm_transient_legacy() -> Self {
        Self {
            max_attempts: 3,
            max_total: None,
            base_delay: Duration::from_millis(1000),
            max_delay: Duration::from_millis(1000),
            jitter: false,
        }
    }
}

/// Run `op` under `policy`, re-acquiring `rate_limiter` on every
/// attempt and stopping early if `should_retry` returns false for
/// the observed error or if `max_total` is exceeded.
///
/// Returns the last error verbatim on exhaustion so callers can
/// preserve their domain-specific error context.
pub async fn with_retry_policy<T, E, F, Fut, ShouldRetry>(
    policy: &RetryPolicy,
    rate_limiter: Option<&RateLimiter>,
    should_retry: ShouldRetry,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    ShouldRetry: Fn(&E) -> bool,
{
    assert!(policy.max_attempts >= 1, "RetryPolicy::max_attempts must be >= 1");

    let start_ms = now_ms();
    let mut last_err: Option<E> = None;

    for attempt in 1..=policy.max_attempts {
        crate::maybe_acquire(rate_limiter).await;

        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt == policy.max_attempts || !should_retry(&err) {
                    return Err(err);
                }
                if let Some(cap) = policy.max_total {
                    if now_ms().saturating_sub(start_ms) >= cap.as_millis() as u64 {
                        return Err(err);
                    }
                }
                last_err = Some(err);
                let delay = backoff_delay(policy, attempt);
                crate::sleep_ms(delay.as_millis() as u64).await;
            }
        }
    }

    // Loop invariant: we only reach here if max_attempts == 0, which
    // the assert above rejects. Keep the panic-free fallback for
    // future-proofing.
    Err(last_err.expect("retry loop ran at least once"))
}

fn backoff_delay(policy: &RetryPolicy, attempt: u32) -> Duration {
    let base = policy.base_delay.as_millis() as u64;
    let cap = policy.max_delay.as_millis() as u64;
    let factor = 1u64.checked_shl(attempt.saturating_sub(1)).unwrap_or(u64::MAX);
    let grown = base.saturating_mul(factor);
    let capped = grown.min(cap);
    let jitter_ms = if policy.jitter { jitter_up_to(base) } else { 0 };
    Duration::from_millis(capped.saturating_add(jitter_ms).min(cap))
}

/// Pseudo-random `[0, span_ms)` derived from a per-process counter
/// xor'd with the current wall-clock. Good enough to de-correlate
/// retries across colliding clients without pulling in `rand`.
fn jitter_up_to(span_ms: u64) -> u64 {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0x9E3779B97F4A7C15);
    if span_ms == 0 {
        return 0;
    }
    let n = COUNTER.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    let mixed = n ^ now_ms().rotate_left(13);
    let mixed = mixed.wrapping_mul(0xBF58476D1CE4E5B9);
    let mixed = mixed ^ (mixed >> 31);
    mixed % span_ms
}

fn now_ms() -> u64 {
    #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn succeeds_on_first_attempt() {
        let policy = RetryPolicy::http_default();
        let attempts = AtomicUsize::new(0);
        let res: Result<u32, &str> = with_retry_policy(
            &policy,
            None,
            |_| true,
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            },
        )
        .await;
        assert_eq!(res, Ok(42));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn retries_then_succeeds() {
        let policy = RetryPolicy {
            max_attempts: 3,
            max_total: None,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter: false,
        };
        let attempts = AtomicUsize::new(0);
        let res: Result<u32, &str> = with_retry_policy(
            &policy,
            None,
            |_| true,
            || async {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err("transient")
                } else {
                    Ok(7)
                }
            },
        )
        .await;
        assert_eq!(res, Ok(7));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn stops_when_classifier_rejects() {
        let policy = RetryPolicy {
            max_attempts: 5,
            max_total: None,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter: false,
        };
        let attempts = AtomicUsize::new(0);
        let res: Result<u32, &str> = with_retry_policy(
            &policy,
            None,
            |_| false,
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err("non-retryable")
            },
        )
        .await;
        assert_eq!(res, Err("non-retryable"));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn exhausts_after_max_attempts() {
        let policy = RetryPolicy {
            max_attempts: 4,
            max_total: None,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter: false,
        };
        let attempts = AtomicUsize::new(0);
        let res: Result<u32, &str> = with_retry_policy(
            &policy,
            None,
            |_| true,
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err("nope")
            },
        )
        .await;
        assert_eq!(res, Err("nope"));
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn honours_max_total_cap() {
        let policy = RetryPolicy {
            max_attempts: 100,
            max_total: Some(Duration::from_millis(40)),
            base_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(20),
            jitter: false,
        };
        let attempts = AtomicUsize::new(0);
        let started = std::time::Instant::now();
        let res: Result<u32, &str> = with_retry_policy(
            &policy,
            None,
            |_| true,
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err("slow")
            },
        )
        .await;
        assert_eq!(res, Err("slow"));
        let n = attempts.load(Ordering::SeqCst);
        // First attempt costs ~0, then 20ms sleep, then second attempt,
        // then the cap (40ms) trips and we bail. So 2-3 attempts max.
        assert!(n <= 3, "expected ≤ 3 attempts under 40ms cap, got {n}");
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn backoff_grows_and_caps() {
        let policy = RetryPolicy {
            max_attempts: 10,
            max_total: None,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(800),
            jitter: false,
        };
        assert_eq!(backoff_delay(&policy, 1).as_millis(), 100);
        assert_eq!(backoff_delay(&policy, 2).as_millis(), 200);
        assert_eq!(backoff_delay(&policy, 3).as_millis(), 400);
        assert_eq!(backoff_delay(&policy, 4).as_millis(), 800);
        assert_eq!(backoff_delay(&policy, 5).as_millis(), 800);
        assert_eq!(backoff_delay(&policy, 50).as_millis(), 800);
    }
}
