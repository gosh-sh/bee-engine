//! Coarse progress milestones for long-running wallet operations.
//!
//! Two commands are opaque to the wallet UI because they take a variable,
//! often long time and return only on full completion: the ZK proof fetch
//! (`complete_zk_login_with_prover_v1`) and `add_zkp_factor` (on-chain
//! build → submit → confirm). This module gives callers an opt-in channel
//! to observe milestones as they happen.
//!
//! Transport is [`futures::channel::mpsc`] (not `tokio` or a boxed callback)
//! so the exact same sink type compiles on native and `wasm32` without
//! `Send`/lifetime divergence. The adapter layer bridges it to the host:
//! a Tauri command drains the receiver into `window.emit`, and the wasm
//! adapter forwards each event to a JS callback.

use serde::Serialize;

/// A single progress milestone. Serialized shape matches what the wallet
/// listens for: `{ op, stage, detail?, pct? }`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    /// Operation this event belongs to: `"prove"` | `"add_factor"`.
    pub op: String,
    /// Milestone within the operation (e.g. `"started"`, `"submitted"`,
    /// `"confirming"`, `"confirmed"`, `"finished"`).
    pub stage: String,
    /// Optional human-readable detail (a hint or a failure reason).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Optional coarse percentage in `[0, 100]`, when one is meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pct: Option<u8>,
}

impl ProgressEvent {
    /// A bare milestone with no detail/pct.
    pub fn new(op: &str, stage: &str) -> Self {
        Self { op: op.to_string(), stage: stage.to_string(), detail: None, pct: None }
    }

    /// Attaches a human-readable detail string.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attaches a coarse percentage.
    pub fn with_pct(mut self, pct: u8) -> Self {
        self.pct = Some(pct);
        self
    }
}

/// Caller-supplied sink for [`ProgressEvent`]s. The operation runs identically
/// whether or not a sink is provided; events are sent best-effort.
pub type ProgressSink = futures::channel::mpsc::UnboundedSender<ProgressEvent>;

/// Fire-and-forget emit. A closed or absent receiver is never an error —
/// progress delivery must not block or fail the underlying operation.
pub(crate) fn emit(sink: Option<&ProgressSink>, event: ProgressEvent) {
    if let Some(tx) = sink {
        let _ = tx.unbounded_send(event);
    }
}

/// Emit a terminal `<op>:failed` event (error message as `detail`) when
/// `result` is `Err`, unless the error's kind equals `suppress_kind` — used to
/// avoid double-reporting a more specific terminal (e.g. `*_timeout`) that the
/// caller already emitted itself.
pub(crate) fn report_failure<T>(
    sink: Option<&ProgressSink>,
    op: &str,
    result: &Result<T, crate::errors::AppError>,
    suppress_kind: Option<&str>,
) {
    if let Err(e) = result {
        let suppressed = suppress_kind.is_some() && e.kind.as_deref() == suppress_kind;
        if !suppressed {
            emit(sink, ProgressEvent::new(op, "failed").with_detail(e.message.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;
    use crate::errors::AppError;

    #[test]
    fn serializes_camelcase_and_skips_none() {
        let ev = ProgressEvent::new("add_factor", "submitted");
        assert_eq!(
            serde_json::to_string(&ev).unwrap(),
            r#"{"op":"add_factor","stage":"submitted"}"#
        );

        let ev = ProgressEvent::new("prove", "proving").with_detail("x").with_pct(50);
        assert_eq!(
            serde_json::to_string(&ev).unwrap(),
            r#"{"op":"prove","stage":"proving","detail":"x","pct":50}"#
        );
    }

    #[test]
    fn emit_none_is_noop() {
        emit(None, ProgressEvent::new("add_factor", "submitted"));
    }

    #[test]
    fn emit_closed_receiver_does_not_panic() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        drop(rx);
        emit(Some(&tx), ProgressEvent::new("add_factor", "submitted"));
    }

    #[tokio::test]
    async fn emit_some_delivers() {
        let (tx, mut rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        emit(Some(&tx), ProgressEvent::new("add_factor", "confirmed"));
        drop(tx);
        let got = rx.next().await.unwrap();
        assert_eq!(got.stage, "confirmed");
        assert_eq!(got.op, "add_factor");
    }

    #[tokio::test]
    async fn report_failure_emits_failed_with_reason() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        let result: Result<(), AppError> = Err(AppError::new("boom"));
        report_failure(Some(&tx), "deploy", &result, None);
        drop(tx);
        let events: Vec<ProgressEvent> = rx.collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].op, "deploy");
        assert_eq!(events[0].stage, "failed");
        assert_eq!(events[0].detail.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn report_failure_suppresses_matching_kind() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        let result: Result<(), AppError> =
            Err(AppError::new("timed out").with_kind("add_factor_timeout"));
        report_failure(Some(&tx), "add_factor", &result, Some("add_factor_timeout"));
        drop(tx);
        let events: Vec<ProgressEvent> = rx.collect().await;
        assert!(events.is_empty(), "matching kind should be suppressed");
    }

    #[tokio::test]
    async fn report_failure_noop_on_ok() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<ProgressEvent>();
        let result: Result<u8, AppError> = Ok(1);
        report_failure(Some(&tx), "add_factor", &result, None);
        drop(tx);
        let events: Vec<ProgressEvent> = rx.collect().await;
        assert!(events.is_empty());
    }
}
