// SPDX-License-Identifier: AGPL-3.0-only

//! §4.166 boot-window send-integrity integration: the three audit questions
//! pinned against the fake engine. The generic upstream failure settles its
//! row failed and arms the automatic retry schedule; a duplicate
//! clientRequestId re-answers the stored row with no second engine call; and
//! a typing success writes no row at all.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::DEFAULT_PROXY_GROUP_ID;
use kt_signal_connector::engine::EngineConfig;
use kt_signal_connector::service::SendTarget;
use kt_signal_connector::store::{Store, StoreKey};
use kt_signal_connector::supervisor::RuntimeSupervisor;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

/// All supervisor-test stores are encrypted with one fixed key, so a seeded
/// store and the supervisor's own open see the same database.
fn test_store(dir: &Path) -> Arc<Store> {
    Arc::new(Store::open(dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap())
}

fn config_for(temp: &TempDir) -> EngineConfig {
    let mut config = EngineConfig::new(fixture(), temp.path().join("signal-data"));
    config.request_timeout = Duration::from_secs(1);
    config.shutdown_grace = Duration::from_millis(100);
    config
}

/// Seed the linked fixture account (+15555550100) and one direct peer
/// conversation; returns (account_id, conversation_id).
fn seed_account_and_conversation(store: &Store) -> (String, String) {
    let account = store
        .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
        .unwrap();
    let conversation = store
        .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
        .unwrap();
    (account.id.clone(), conversation.id.clone())
}

/// Arm the fixture's generic -32603 send answer in THIS test's own data dir
/// (test-local marker, never a process-global env): the plain internal-error
/// face with no embedded anchor is the Unbound-window failure shape — the
/// upstream family with nothing underneath.
fn arm_rejected(temp: &TempDir) {
    std::fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    std::fs::write(temp.path().join("signal-data/.fixture-send-rejected"), b"").unwrap();
}

fn disarm_rejected(temp: &TempDir) {
    std::fs::remove_file(temp.path().join("signal-data/.fixture-send-rejected")).unwrap();
}

/// Arm the fixture's one-shot dispatch-timeout send answer in THIS test's own
/// data dir (test-local marker, never a process-global env): the engine's real
/// `-32000` (EngineTimeoutException) face with its promised data.
fn arm_engine_timeout(temp: &TempDir) {
    std::fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    // Re-armable one-shot: a prior send's done marker must not swallow the
    // next arm (the text and attachment legs each arm their own answer).
    std::fs::remove_file(
        temp.path()
            .join("signal-data/.fixture-send-engine-timeout-done"),
    )
    .ok();
    std::fs::write(
        temp.path()
            .join("signal-data/.fixture-send-engine-timeout-armed"),
        b"",
    )
    .unwrap();
}

/// The row's status through the public read face; None when no such row.
fn status_of(store: &Store, account_id: &str, request: &str) -> Option<String> {
    store
        .message_by_client_request(account_id, request)
        .unwrap()
        .map(|record| record.status.to_string())
}

fn send_log(temp: &TempDir) -> Vec<serde_json::Value> {
    let path = temp.path().join("signal-data/.fixture-send-log.jsonl");
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Audit question (b): the generic upstream failure — the Unbound-window
/// shape — settles the row failed under the automatic Backoff schedule, the
/// API answer is `UPSTREAM_ERROR` retryable, and the worker's own beat then
/// settles the SAME row sent with exactly two upstream calls.
#[tokio::test]
async fn generic_upstream_failure_settles_failed_arms_the_schedule_and_answers_retryable() {
    let temp = TempDir::new().unwrap();
    arm_rejected(&temp);
    let store = test_store(temp.path());
    let (account_id, conversation_id) = seed_account_and_conversation(&store);

    let supervisor = Arc::new(RuntimeSupervisor::new(
        config_for(&temp),
        Arc::clone(&store),
        DEFAULT_PROXY_GROUP_ID.to_string(),
        None,
    ));
    supervisor.spawn_outbox_worker();
    supervisor.start().await.unwrap();

    let first = supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "unbound window".into(),
            "req-unbound-1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
    let error = first
        .expect_err("the armed answer must fail the send")
        .into_api();
    assert_eq!(error.code, "UPSTREAM_ERROR");
    assert!(error.retryable, "{error:?}");
    assert_eq!(
        status_of(&store, &account_id, "req-unbound-1").as_deref(),
        Some("failed"),
        "the pending row settles failed, never stranded pending"
    );
    assert!(
        store.next_retry_due_at().unwrap().is_some(),
        "the upstream family must arm the retry schedule"
    );

    // Disarm so the automatic retry answers normally; the disarm happens
    // synchronously after the failure returns, long before the worker's
    // first 190 ms beat.
    disarm_rejected(&temp);
    timeout(Duration::from_secs(15), async {
        loop {
            if status_of(&store, &account_id, "req-unbound-1").as_deref() == Some("sent") {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the automatic retry must settle the row sent");

    let sends = send_log(&temp);
    assert_eq!(sends.len(), 2, "original + automatic retry, nothing more");
    for send in &sends {
        assert_eq!(send["message"], serde_json::json!("unbound window"));
    }
    assert_eq!(
        store.next_retry_due_at().unwrap(),
        None,
        "the settled success leaves nothing queued"
    );
    let rows = store
        .list_messages(&account_id, &conversation_id, 10, None)
        .unwrap();
    assert_eq!(rows.items.len(), 1, "one row per logical message");
    assert_eq!(
        rows.items[0].client_request_id.as_deref(),
        Some("req-unbound-1")
    );
}

/// Audit question (a): the clientRequestId idempotent face re-answers the
/// already-stored row without a second engine call — the honest projection
/// (here a failed row) never flips state and never re-sends upstream.
#[tokio::test]
async fn duplicate_send_text_answers_the_persisted_row_without_engine_traffic() {
    let temp = TempDir::new().unwrap();
    arm_rejected(&temp);
    let store = test_store(temp.path());
    let (account_id, conversation_id) = seed_account_and_conversation(&store);

    let supervisor = Arc::new(RuntimeSupervisor::new(
        config_for(&temp),
        Arc::clone(&store),
        DEFAULT_PROXY_GROUP_ID.to_string(),
        None,
    ));
    supervisor.start().await.unwrap();

    let first = supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "once only".into(),
            "req-dup-1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
    assert!(first.is_err(), "the armed answer must fail the first send");
    assert_eq!(send_log(&temp).len(), 1, "the failure made one engine call");

    // The marker stays armed: a second engine call would fail again. The
    // duplicate answers from the stored row instead.
    let second = supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "once only".into(),
            "req-dup-1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("the duplicate answers the stored row");
    assert_eq!(
        second.status.to_string(),
        "failed",
        "the projection is the stored row's honest status, never flipped"
    );
    assert_eq!(
        second.client_request_id.as_deref(),
        Some("req-dup-1"),
        "the answered row is the original row, same identity"
    );
    assert_eq!(
        send_log(&temp).len(),
        1,
        "the duplicate must not reach the engine"
    );
    let rows = store
        .list_messages(&account_id, &conversation_id, 10, None)
        .unwrap();
    assert_eq!(rows.items.len(), 1, "no second row for the duplicate");
}

/// Contract 1.285 (§4.269): a cancelled MUTATING dispatch may already have
/// been written, so the engine's -32000 (EngineTimeoutException) answer folds
/// to the existing unknown outcome. Text and attachment sends ride the same
/// engine `send` method: the row settles `unknown` (never `failed`), the
/// answer is SEND_OUTCOME_UNKNOWN retryable=false, and no automatic retry is
/// ever armed (the AGENTS.md red line).
#[tokio::test]
async fn engine_dispatch_timeout_settles_send_rows_unknown_and_arms_no_retry() {
    let temp = TempDir::new().unwrap();
    let store = test_store(temp.path());
    let (account_id, conversation_id) = seed_account_and_conversation(&store);

    let supervisor = Arc::new(RuntimeSupervisor::new(
        config_for(&temp),
        Arc::clone(&store),
        DEFAULT_PROXY_GROUP_ID.to_string(),
        None,
    ));
    supervisor.start().await.unwrap();

    arm_engine_timeout(&temp);
    let text = supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "timeout window".into(),
            "req-engine-timeout-text".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
    let error = text
        .expect_err("the armed timeout must fail the text send")
        .into_api();
    assert_eq!(error.code, "SEND_OUTCOME_UNKNOWN");
    assert!(!error.retryable, "{error:?}");
    assert_eq!(
        status_of(&store, &account_id, "req-engine-timeout-text").as_deref(),
        Some("unknown"),
        "a cancelled mutating send may have been written: unknown, never failed"
    );
    assert_eq!(
        store.next_retry_due_at().unwrap(),
        None,
        "the unknown red line never arms an automatic retry"
    );

    // The attachment leg is the same engine `send` call and must fold the
    // same way.
    arm_engine_timeout(&temp);
    let attachment = supervisor
        .send_attachment(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "req-engine-timeout-attachment".into(),
            "aGVsbG8=".into(),
            5,
            Some("hi.txt".into()),
            Some("text/plain".into()),
            None,
            None,
            false,
            false,
            None,
            false,
        )
        .await;
    let error = attachment
        .expect_err("the armed timeout must fail the attachment send")
        .into_api();
    assert_eq!(error.code, "SEND_OUTCOME_UNKNOWN");
    assert!(!error.retryable, "{error:?}");
    assert_eq!(
        status_of(&store, &account_id, "req-engine-timeout-attachment").as_deref(),
        Some("unknown"),
        "the attachment row settles unknown too"
    );
    assert_eq!(store.next_retry_due_at().unwrap(), None);
    assert_eq!(
        send_log(&temp).len(),
        2,
        "exactly one engine call per send, never a retry"
    );
}

/// Audit question (c): a typing success settles nothing — no message row,
/// no receipt stamp, exactly its own upstream call on the engine face and
/// nothing else. A typing ok has no row to complete, by construction.
#[tokio::test]
async fn typing_success_writes_no_row_and_touches_no_send_face() {
    let temp = TempDir::new().unwrap();
    let store = test_store(temp.path());
    let (account_id, conversation_id) = seed_account_and_conversation(&store);

    let supervisor = Arc::new(RuntimeSupervisor::new(
        config_for(&temp),
        Arc::clone(&store),
        DEFAULT_PROXY_GROUP_ID.to_string(),
        None,
    ));
    supervisor.start().await.unwrap();

    let answer = supervisor
        .set_typing_message(account_id.clone(), conversation_id.clone(), true)
        .await
        .expect("the clean sendTyping answer settles the call");
    assert_eq!(answer, "sent");

    let rows = store
        .list_messages(&account_id, &conversation_id, 10, None)
        .unwrap();
    assert!(rows.items.is_empty(), "typing writes no message row");
    let sends = send_log(&temp);
    assert_eq!(sends.len(), 1, "exactly the typing call left the connector");
    assert_eq!(sends[0]["stop"], serde_json::json!(true));
    assert!(
        sends[0].get("message").is_none(),
        "the engine face is sendTyping, not a send: no message key"
    );
}
