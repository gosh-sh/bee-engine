use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use ackinacki_kit::contracts::delivery::ContractContext;
use ackinacki_kit::contracts::delivery::PreparedMessage;
use ackinacki_kit::contracts::delivery::PreparedMessageSender;
use ackinacki_kit::tvm_client::error::ClientError;
use ackinacki_kit::tvm_client::error::ClientResult;
use ackinacki_kit::tvm_client::processing::ResultOfSendMessage;
use ackinacki_kit::tvm_client::ClientContext;
use async_trait::async_trait;

const MESSAGE_LIFETIME: Duration = Duration::from_secs(30);
const QUEUE_OVERFLOW_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const QUEUE_OVERFLOW_MAX_RETRIES: usize = 30;

#[derive(Debug, Default)]
struct QueueOverflowRetrySender;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PreparedMessageSender for QueueOverflowRetrySender {
    async fn send(
        &self,
        context: Arc<ClientContext>,
        message: &PreparedMessage,
    ) -> ClientResult<ResultOfSendMessage> {
        with_queue_overflow_retry(
            || message.send_once(context.clone()),
            |delay| crate::sleep_ms(delay.as_millis() as u64),
            || context.now_ms(),
            message.expires_at(),
        )
        .await
    }
}

/// Contract context shared by all bee-engine chain writers.
pub fn contract_context(client: Arc<ClientContext>) -> ContractContext {
    ContractContext::with_sender(client, Arc::new(QueueOverflowRetrySender), MESSAGE_LIFETIME)
}

async fn with_queue_overflow_retry<T, Attempt, AttemptFuture, Sleep, SleepFuture, Now>(
    mut attempt: Attempt,
    mut sleep: Sleep,
    now_millis: Now,
    expires_at: Option<u32>,
) -> ClientResult<T>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = ClientResult<T>>,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
    Now: Fn() -> u64,
{
    let Some(expires_at) = expires_at else {
        return attempt().await;
    };
    let deadline_millis = u64::from(expires_at) * 1_000;
    let mut retries = 0;

    loop {
        match attempt().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if !is_queue_overflow(&error) || retries >= QUEUE_OVERFLOW_MAX_RETRIES {
                    return Err(error);
                }

                let next_attempt_at =
                    now_millis().saturating_add(QUEUE_OVERFLOW_RETRY_INTERVAL.as_millis() as u64);
                if next_attempt_at >= deadline_millis {
                    return Err(error);
                }

                sleep(QUEUE_OVERFLOW_RETRY_INTERVAL).await;
                retries += 1;
            }
        }
    }
}

fn is_queue_overflow(error: &ClientError) -> bool {
    error.data().pointer("/node_error/extensions/code").and_then(serde_json::Value::as_str)
        == Some("QUEUE_OVERFLOW")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use serde_json::json;

    use super::*;

    fn queue_overflow() -> ClientError {
        ClientError::new(
            0,
            "queue is full",
            json!({ "node_error": { "extensions": { "code": "QUEUE_OVERFLOW" } } }),
        )
    }

    #[test]
    fn recognizes_only_structured_queue_overflow_code() {
        assert!(is_queue_overflow(&queue_overflow()));
        assert!(!is_queue_overflow(&ClientError::new(
            0,
            "QUEUE_OVERFLOW",
            json!({ "node_error": { "extensions": { "code": "OTHER" } } }),
        )));
    }

    #[tokio::test]
    async fn retries_until_the_same_operation_succeeds() {
        let attempts = Rc::new(Cell::new(0));
        let sleeps = Rc::new(Cell::new(0));
        let attempts_for_call = attempts.clone();
        let sleeps_for_call = sleeps.clone();

        let result = with_queue_overflow_retry(
            move || {
                let attempt = attempts_for_call.get() + 1;
                attempts_for_call.set(attempt);
                async move {
                    if attempt < 3 {
                        Err(queue_overflow())
                    } else {
                        Ok("sent")
                    }
                }
            },
            move |_| {
                sleeps_for_call.set(sleeps_for_call.get() + 1);
                async {}
            },
            || 1_000,
            Some(60),
        )
        .await;

        assert_eq!(result.unwrap(), "sent");
        assert_eq!(attempts.get(), 3);
        assert_eq!(sleeps.get(), 2);
    }

    #[tokio::test]
    async fn stops_before_the_next_retry_would_reach_expiry() {
        let attempts = Rc::new(Cell::new(0));
        let attempts_for_call = attempts.clone();

        let result: ClientResult<()> = with_queue_overflow_retry(
            move || {
                attempts_for_call.set(attempts_for_call.get() + 1);
                async { Err(queue_overflow()) }
            },
            |_| async {},
            || 29_000,
            Some(30),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn does_not_retry_other_errors() {
        let attempts = Rc::new(Cell::new(0));
        let attempts_for_call = attempts.clone();

        let result: ClientResult<()> = with_queue_overflow_retry(
            move || {
                attempts_for_call.set(attempts_for_call.get() + 1);
                async { Err(ClientError::new(0, "network", json!({}))) }
            },
            |_| async {},
            || 0,
            Some(30),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn caps_queue_overflow_retries_at_thirty() {
        let attempts = Rc::new(Cell::new(0));
        let sleeps = Rc::new(Cell::new(0));
        let attempts_for_call = attempts.clone();
        let sleeps_for_call = sleeps.clone();

        let result: ClientResult<()> = with_queue_overflow_retry(
            move || {
                attempts_for_call.set(attempts_for_call.get() + 1);
                async { Err(queue_overflow()) }
            },
            move |_| {
                sleeps_for_call.set(sleeps_for_call.get() + 1);
                async {}
            },
            || 0,
            Some(60),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.get(), QUEUE_OVERFLOW_MAX_RETRIES + 1);
        assert_eq!(sleeps.get(), QUEUE_OVERFLOW_MAX_RETRIES);
    }

    #[tokio::test]
    async fn does_not_retry_without_an_explicit_expiry() {
        let attempts = Rc::new(Cell::new(0));
        let attempts_for_call = attempts.clone();

        let result: ClientResult<()> = with_queue_overflow_retry(
            move || {
                attempts_for_call.set(attempts_for_call.get() + 1);
                async { Err(queue_overflow()) }
            },
            |_| async {},
            || 0,
            None,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }
}
