use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::to_bytes;
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::Request;
use axum::extract::State;
use axum::http::header::HeaderName;
use axum::http::header::{self};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use parking_lot::Mutex;
use serde_json::json;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: String,
    pub fail_first: usize,
}

#[derive(Clone, Debug)]
pub struct MessageAttempt {
    pub message_id: String,
    pub body_hash: String,
    pub attempt: usize,
    pub observed_at: Instant,
    pub forwarded: bool,
}

#[derive(Clone, Default)]
pub struct ProxyState {
    inner: Arc<Mutex<ProxyObservations>>,
}

impl ProxyState {
    pub fn attempts(&self) -> Vec<MessageAttempt> {
        self.inner.lock().attempts.clone()
    }
}

#[derive(Default)]
struct ProxyObservations {
    attempts_by_message: HashMap<String, usize>,
    attempts: Vec<MessageAttempt>,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    upstream: String,
    fail_first: usize,
    observations: ProxyState,
}

pub struct ProxyHandle {
    endpoint: String,
    observations: ProxyState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl ProxyHandle {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn state(&self) -> ProxyState {
        self.observations.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task
            .await
            .map_err(|error| format!("proxy task failed: {error}"))?
            .map_err(|error| format!("proxy server failed: {error}"))
    }
}

pub async fn spawn(config: ProxyConfig) -> Result<ProxyHandle, String> {
    validate_upstream(&config.upstream)?;

    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|error| format!("failed to bind {}: {error}", config.listen))?;
    let address =
        listener.local_addr().map_err(|error| format!("failed to read proxy address: {error}"))?;
    let observations = ProxyState::default();
    let app = router(AppState {
        client: reqwest::Client::new(),
        upstream: config.upstream.trim_end_matches('/').to_owned(),
        fail_first: config.fail_first,
        observations: observations.clone(),
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    Ok(ProxyHandle {
        endpoint: format!("http://{address}"),
        observations,
        shutdown: Some(shutdown_tx),
        task,
    })
}

pub async fn run_until_ctrl_c(config: ProxyConfig) -> Result<(), String> {
    let handle = spawn(config).await?;
    println!("queue-overflow proxy listening on {}", handle.endpoint());
    tokio::signal::ctrl_c().await.map_err(|error| format!("failed to wait for Ctrl-C: {error}"))?;
    handle.shutdown().await
}

fn router(state: AppState) -> Router {
    Router::new().fallback(proxy_request).with_state(state)
}

async fn proxy_request(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({ "error": format!("failed to read request body: {error}") }),
            );
        }
    };

    if parts.uri.path().ends_with("/v2/messages") {
        if let Some(message) = parse_message(&body) {
            let attempt = record_attempt(&state, &message);
            if attempt <= state.fail_first {
                return queue_overflow_response(&message.id);
            }
        }
    }

    forward_request(state, parts.method, parts.uri, parts.headers, body).await
}

struct MessageRequest {
    id: String,
    body_hash: String,
}

fn parse_message(body: &[u8]) -> Option<MessageRequest> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let message = value.as_array()?.first()?;
    let id = message.get("id")?.as_str()?.to_owned();
    let encoded_boc = message.get("body")?.as_str()?;
    let body_hash = blake3::hash(encoded_boc.as_bytes()).to_hex().to_string();
    Some(MessageRequest { id, body_hash })
}

fn record_attempt(state: &AppState, message: &MessageRequest) -> usize {
    let mut observations = state.observations.inner.lock();
    let attempt = {
        let attempts = observations.attempts_by_message.entry(message.id.clone()).or_default();
        *attempts += 1;
        *attempts
    };
    observations.attempts.push(MessageAttempt {
        message_id: message.id.clone(),
        body_hash: message.body_hash.clone(),
        attempt,
        observed_at: Instant::now(),
        forwarded: attempt > state.fail_first,
    });
    let action = if attempt <= state.fail_first { "inject" } else { "forward" };
    println!(
        "queue-overflow proxy: message_id={} boc_hash={} attempt={} action={}",
        message.id, message.body_hash, attempt, action,
    );
    attempt
}

fn queue_overflow_response(message_id: &str) -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "result": null,
            "error": {
                "code": "QUEUE_OVERFLOW",
                "message": "Message queue is full. Please try to send the message later.",
                "data": {
                    "message_hash": message_id,
                },
            },
            "ext_message_token": null,
        }),
    )
}

async fn forward_request(
    state: AppState,
    method: axum::http::Method,
    uri: axum::http::Uri,
    mut headers: HeaderMap,
    body: Bytes,
) -> Response {
    remove_hop_by_hop_request_headers(&mut headers);
    let path_and_query = uri.path_and_query().map(|value| value.as_str()).unwrap_or("/");
    let target = format!("{}{}", state.upstream, path_and_query);

    let response =
        match state.client.request(method, target).headers(headers).body(body).send().await {
            Ok(response) => response,
            Err(error) => {
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({ "error": format!("upstream request failed: {error}") }),
                );
            }
        };
    let status = response.status();
    let mut headers = response.headers().clone();
    remove_hop_by_hop_response_headers(&mut headers);
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({ "error": format!("failed to read upstream response: {error}") }),
            );
        }
    };

    let mut proxy_response = Response::new(Body::from(body));
    *proxy_response.status_mut() = status;
    *proxy_response.headers_mut() = headers;
    proxy_response
}

fn remove_hop_by_hop_request_headers(headers: &mut HeaderMap) {
    for name in [
        header::HOST,
        header::CONTENT_LENGTH,
        header::CONNECTION,
        header::TRANSFER_ENCODING,
        header::ACCEPT_ENCODING,
    ] {
        headers.remove(name);
    }
}

fn remove_hop_by_hop_response_headers(headers: &mut HeaderMap) {
    for name in [header::CONTENT_LENGTH, header::CONNECTION, header::TRANSFER_ENCODING] {
        headers.remove(name);
    }
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = Response::new(Body::from(value.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    response
        .headers_mut()
        .insert(HeaderName::from_static("access-control-allow-origin"), "*".parse().unwrap());
    response
}

fn validate_upstream(upstream: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(upstream)
        .map_err(|error| format!("invalid upstream URL {upstream:?}: {error}"))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(format!("unsupported upstream URL scheme {scheme:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tvm_message_and_hashes_only_the_prepared_boc() {
        let first = parse_message(br#"[{"id":"message-id","body":"same-boc","thread_id":"a"}]"#)
            .expect("message should parse");
        let second = parse_message(
            br#"[{"id":"message-id","body":"same-boc","thread_id":"b","ext_message_token":{}}]"#,
        )
        .expect("message should parse");

        assert_eq!(first.id, "message-id");
        assert_eq!(first.body_hash, second.body_hash);
    }

    #[test]
    fn ignores_non_message_payloads() {
        assert!(parse_message(br#"{"query":"{ info { version } }"}"#).is_none());
        assert!(parse_message(br#"[{"id":"missing-body"}]"#).is_none());
    }
}
