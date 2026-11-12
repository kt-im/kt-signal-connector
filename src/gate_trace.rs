// SPDX-License-Identifier: AGPL-3.0-only

//! `[gate-trace]` connector hop for the inbox-gate four-hop localisation
//! (SIGNAL-GATE-TRACE-PLAN §2, 2026-11-12).
//!
//! One fixed single-line shape keeps every hop greppable with
//! `grep '\[gate-trace\]'`:
//!
//! ```text
//! [gate-trace] hop=conn event=<storage-pull|initial-sync|contact-sync> account=<id8> face=<ok|fail|-> detail=<free text>
//! ```
//!
//! The account face is the first eight hex chars of SHA-256 over the signal
//! account — irreversible, and the exact projection the engine's
//! `probe_account8` emits, so the engine and connector lines key the same
//! account. Numbers, names, message bodies and key material never land here.
//! Pure emission: nothing in this module feeds a decision (zero behavior
//! change).

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Eight hex chars of SHA-256 over the signal account (the engine's
/// `probe_account8` projection verbatim). Absent/empty accounts render `-`.
pub(crate) fn account8(signal_account: Option<&str>) -> String {
    let Some(signal_account) = signal_account.filter(|value| !value.is_empty()) else {
        return "-".to_string();
    };
    let digest = Sha256::digest(signal_account.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest.iter() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded.truncate(8);
    encoded
}

/// Emit exactly one connector-hop line. WARN (not INFO) so the line survives
/// a `KT_SIGNAL_LOG=warn` capture — incident repros may raise the floor.
pub(crate) fn line(event: &str, signal_account: Option<&str>, face: &str, detail: &str) {
    tracing::warn!(
        target: "connector.gate_trace",
        "[gate-trace] hop=conn event={} account={} face={} detail={}",
        event,
        account8(signal_account),
        face,
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
    fn account8_is_the_engine_projection_and_never_the_number() {
        let hash = account8(Some("+15555550100"));
        assert_eq!(hash, "0cbf0194");
        assert_eq!(hash.len(), 8);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hash.contains("1555"));
        assert_eq!(account8(None), "-");
        assert_eq!(account8(Some("")), "-");
    }

    #[test]
    fn line_shape_is_fixed_and_content_free() {
        let output = captured_log(|| {
            line(
                "storage-pull",
                Some("+15555550100"),
                "ok",
                "forwarded trigger=fetchLatest contactsOk=true groupsOk=false",
            );
        });
        assert!(
            output.contains(
                "[gate-trace] hop=conn event=storage-pull account=0cbf0194 face=ok detail=forwarded trigger=fetchLatest contactsOk=true groupsOk=false"
            ),
            "{output}"
        );
        assert!(!output.contains("+15555550100"), "{output}");
    }
}
