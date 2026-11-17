// SPDX-License-Identifier: AGPL-3.0-only

//! `[link-stage]` connector hop for the BUG-5 `finishSessionLink` stage
//! timing (2026-11-12). One fixed single-line shape keeps the link handshake
//! greppable with `grep '\[link-stage\]'` across the desktop Main log and
//! this connector's stderr:
//!
//! ```text
//! [link-stage] stage=<link-register|slot-promote> elapsed_ms=<millis> hop=conn link=<hash8> account=<id8|-> detail=<free text>
//! ```
//!
//! `elapsed_ms` is measured from the connector's receipt of `link.finish`
//! (the registry entry, immediately before the supervisor's finish lane), so
//! the two connector lines read as one cumulative timeline. The desktop's
//! `scan-confirmed` line anchors the same window on the Main clock, and its
//! `view-hydrate` line closes it after the first session-view read.
//!
//! The full link session id is never printed: it is reduced to eight hex
//! chars of SHA-256, the same irreversible shape `gate_trace::account8`
//! uses. Only the opaque account row id (already a random internal id) is
//! shown in prefix form. Pure emission: nothing in this module feeds a
//! decision (zero behavior change).

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::Duration;

/// Eight hex chars of SHA-256 over the link session id. Empty ids render `-`.
pub(crate) fn link_ref(link_session_id: &str) -> String {
    if link_session_id.is_empty() {
        return "-".to_string();
    }
    let digest = Sha256::digest(link_session_id.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest.iter() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded.truncate(8);
    encoded
}

/// The opaque account row id in its eight-char prefix form (desktop logs the
/// same prefix); absent/empty renders `-`.
pub(crate) fn account_ref(account_id: Option<&str>) -> String {
    match account_id.filter(|value| !value.is_empty()) {
        Some(account_id) => account_id.chars().take(8).collect(),
        None => "-".to_string(),
    }
}

/// Emit exactly one connector-hop stage line. WARN (not INFO) so the line
/// survives a `KT_SIGNAL_LOG=warn` capture — a repro may raise the floor.
pub(crate) fn line(
    stage: &str,
    elapsed: Duration,
    link_session_id: &str,
    account_id: Option<&str>,
    detail: &str,
) {
    tracing::warn!(
        target: "connector.link_stage",
        "[link-stage] stage={} elapsed_ms={} hop=conn link={} account={} detail={}",
        stage,
        elapsed.as_millis(),
        link_ref(link_session_id),
        account_ref(account_id),
        detail
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_log(log: impl FnOnce()) -> String {
        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, log);
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn line_shape_is_fixed_and_hides_the_raw_link_id() {
        let output = captured_log(|| {
            line(
                "link-register",
                Duration::from_millis(36861),
                "lk-secret-session-id",
                Some("0f7b8ea49c6e9ef1738538241e449c95"),
                "engine finishLink returned",
            );
        });
        assert!(
            output.contains("[link-stage] stage=link-register elapsed_ms=36861 hop=conn link="),
            "{output}"
        );
        assert!(output.contains("account=0f7b8ea4"), "{output}");
        assert!(
            output.contains("detail=engine finishLink returned"),
            "{output}"
        );
        assert!(!output.contains("lk-secret-session-id"), "{output}");
    }

    #[test]
    fn empty_ids_render_placeholders() {
        assert_eq!(link_ref(""), "-");
        assert_eq!(account_ref(None), "-");
        assert_eq!(account_ref(Some("")), "-");
        assert_eq!(
            account_ref(Some("0f7b8ea49c6e9ef1738538241e449c95")),
            "0f7b8ea4"
        );
    }
}
