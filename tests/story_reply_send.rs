// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! `messages.sendText` story-reply context (contract revision 1.156, §4.154;
//! the engine send-face storyContext keys, the official
//! `DataMessage.StoryContext` alignment at SendMessage.preload.ts:567-577):
//! the two optional keys (`storyReplyAuthor` / `storyReplyTimestamp`) ride
//! the engine `send` frame verbatim — each only when the caller sent it,
//! absence never becoming null. The frame also carries the send lane's own
//! `dispatchId` (the client request id, stamped on every dispatch), so the
//! story-reply keys are pinned beside it rather than on a bare body. The
//! pair discipline (both-present or both-absent, a single-sided presence
//! refused) and the timestamp's whole value domain
//! (zero/negative/fractional/non-integer) are the engine's fail-closed
//! parse, never a connector gate. The fixture plays the engine
//! (the stub answer pins the wire shape, the engine fake discipline); these
//! tests pin the connector's verbatim forward and error fidelity, never real
//! engine story-reply behavior (the real-device story reply is the engine
//! batch's own acceptance).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::engine::EngineConfig;
use kt_signal_connector::service::SendTarget;
use kt_signal_connector::store::{Store, StoreKey};
use kt_signal_connector::supervisor::RuntimeSupervisor;
use serde_json::{Value, json};
use tempfile::TempDir;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn test_store(dir: &Path) -> Arc<Store> {
    Arc::new(Store::open(dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap())
}

const SIGNAL_ACCOUNT: &str = "+15555550100";
const PEER: &str = "+15555550101";

/// `registry_accounts` is the raw JSON array body of the engine-side
/// registry — the store row and the engine registry are two separate
/// truths, and the unknown-account test needs them to disagree.
fn story_reply_supervisor(
    temp: &TempDir,
    data_dir: &Path,
    registry_accounts: &str,
) -> (Arc<Store>, Arc<RuntimeSupervisor>, String, String) {
    std::fs::create_dir_all(data_dir).unwrap();
    std::fs::write(
        data_dir.join("engine-state.json"),
        format!(r#"{{"version":2,"accounts":[{registry_accounts}]}}"#),
    )
    .unwrap();
    let store = test_store(temp.path());
    let account = store
        .upsert_account_from_signal(
            SIGNAL_ACCOUNT,
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
        .unwrap();
    let conversation = store
        .ensure_conversation(&account.id, "direct", PEER, "Peer")
        .unwrap();
    let mut config = EngineConfig::new(fixture().to_path_buf(), data_dir.to_path_buf());
    config.request_timeout = Duration::from_secs(5);
    config.shutdown_grace = Duration::from_millis(100);
    let supervisor = Arc::new(RuntimeSupervisor::new(
        config,
        Arc::clone(&store),
        kt_signal_connector::DEFAULT_PROXY_GROUP_ID.to_string(),
        None,
    ));
    (store, supervisor, account.id, conversation.id)
}

fn log_lines(data_dir: &Path) -> Vec<Value> {
    fs::read_to_string(data_dir.join(".fixture-send-log.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

/// The verbatim forward pinned byte-for-byte on the three key states: both
/// keys ride, a single-sided presence rides alone (the pair discipline is
/// the engine's face — the connector forwards it as-is), and the keyless
/// body stays the pre-1.156 shape (plus the send lane's dispatchId). The
/// raw-JSON timestamp posture rides too: a string-form stamp forwards
/// untouched (the engine's non-integer refusal, not a connector gate).
#[tokio::test]
async fn story_reply_context_rides_the_send_frame_verbatim() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("signal-data");
    let (_store, supervisor, account_id, conversation_id) = story_reply_supervisor(
        &temp,
        &data_dir,
        r#"{"number":"+15555550100","dir":"accounts/lk-abc"}"#,
    );
    supervisor.start().await.unwrap();

    // Both keys: the full story-reply context.
    let sent = supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "story reply body".into(),
            "req-story-reply-1".into(),
            None,
            None,
            None,
            None,
            Some("22222222-2222-2222-2222-222222222222".into()),
            Some(json!(1_727_000_000_000u64)),
        )
        .await
        .unwrap();
    assert_eq!(sent.status, "sent");

    let log = log_lines(&data_dir);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(
        log[0],
        json!({
            "account": SIGNAL_ACCOUNT,
            "message": "story reply body",
            "recipient": [PEER],
            "storyReplyAuthor": "22222222-2222-2222-2222-222222222222",
            "storyReplyTimestamp": 1_727_000_000_000u64,
            "dispatchId": "req-story-reply-1",
        })
    );

    // Author only: the single-sided presence forwards as-is (the engine's
    // pair-discipline refusal, not a connector gate).
    supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "author only".into(),
            "req-story-reply-2".into(),
            None,
            None,
            None,
            None,
            Some("22222222-2222-2222-2222-222222222222".into()),
            None,
        )
        .await
        .unwrap();
    let log = log_lines(&data_dir);
    assert_eq!(log.len(), 2, "{log:?}");
    assert_eq!(
        log[1]["storyReplyAuthor"],
        json!("22222222-2222-2222-2222-222222222222")
    );
    assert!(log[1].get("storyReplyTimestamp").is_none());

    // Timestamp only, in a shape the engine refuses (a string stamp): the
    // raw value forwards untouched — the 1.151 timestamp posture, the
    // value-domain gate is the engine's.
    supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "timestamp only".into(),
            "req-story-reply-3".into(),
            None,
            None,
            None,
            None,
            None,
            Some(json!("1727000000000")),
        )
        .await
        .unwrap();
    let log = log_lines(&data_dir);
    assert_eq!(log.len(), 3, "{log:?}");
    assert!(log[2].get("storyReplyAuthor").is_none());
    assert_eq!(log[2]["storyReplyTimestamp"], json!("1727000000000"));

    // Neither key: the pre-1.156 body plus the dispatchId every dispatch
    // frame carries.
    supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "plain body".into(),
            "req-story-reply-4".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let log = log_lines(&data_dir);
    assert_eq!(log.len(), 4, "{log:?}");
    assert!(log[3].get("storyReplyAuthor").is_none());
    assert!(log[3].get("storyReplyTimestamp").is_none());
    assert_eq!(
        log[3],
        json!({
            "account": SIGNAL_ACCOUNT,
            "message": "plain body",
            "recipient": [PEER],
            "dispatchId": "req-story-reply-4",
        })
    );
}

/// The error faces: the account-resolution face (an account id no store
/// row answers — the sendText path has no opaque-envelope gate to fail
/// first, the honest ACCOUNT_NOT_FOUND face) never reaching engine
/// traffic, the engine's parse-gate refusal (the marker standing for the
/// storyReply value-domain faces — single-sided presence, empty author,
/// zero stamp) degrading through the structured ladder to UPSTREAM_ERROR
/// retryable, and the engine-down shape answering RUNTIME_NOT_RUNNING
/// non-retryable.
#[tokio::test]
async fn story_reply_error_faces_ride_the_wire_verbatim() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("signal-data");
    let (_store, supervisor, account_id, conversation_id) = story_reply_supervisor(
        &temp,
        &data_dir,
        r#"{"number":"+15555550100","dir":"accounts/lk-abc"}"#,
    );
    supervisor.start().await.unwrap();

    // The connector-local account gate: an account id no store row
    // answers (the sendText face has no opaque-shape envelope gate — the
    // resolution ladder is the gate, the §4.65 read-face ladder) never
    // reaches the engine.
    let error = supervisor
        .send_text(
            "k".repeat(129),
            SendTarget::Conversation(conversation_id.clone()),
            "no upstream".into(),
            "req-story-reply-bad".into(),
            None,
            None,
            None,
            None,
            Some("22222222-2222-2222-2222-222222222222".into()),
            Some(json!(1_727_000_000_000u64)),
        )
        .await
        .err()
        .unwrap()
        .into_api();
    assert_eq!(error.code, "ACCOUNT_NOT_FOUND");
    assert!(!error.retryable, "{error:?}");
    assert!(
        !data_dir.join(".fixture-send-log.jsonl").exists(),
        "the unshaped account id must not reach the engine"
    );

    // The engine's parse-gate refusal: the fixture marker answers the
    // plain -32603 face the real engine's fail-closed parse answers for
    // every storyReply value-domain violation.
    fs::write(data_dir.join(".fixture-send-rejected"), "1").unwrap();
    let error = supervisor
        .send_text(
            account_id.clone(),
            SendTarget::Conversation(conversation_id.clone()),
            "rejected".into(),
            "req-story-reply-rejected".into(),
            None,
            None,
            None,
            None,
            Some("22222222-2222-2222-2222-222222222222".into()),
            Some(json!(1_727_000_000_000u64)),
        )
        .await
        .err()
        .unwrap()
        .into_api();
    assert_eq!(error.code, "UPSTREAM_ERROR");
    assert!(error.retryable, "{error:?}");

    // Engine down: no start, the store row resolves, the engine was never
    // spawned — RUNTIME_NOT_RUNNING, non-retryable (the send lane invents
    // no answer).
    let down = TempDir::new().unwrap();
    let down_data = down.path().join("signal-data");
    let (_down_store, down_supervisor, down_account, down_conversation) = story_reply_supervisor(
        &down,
        &down_data,
        r#"{"number":"+15555550100","dir":"accounts/lk-abc"}"#,
    );
    let error = down_supervisor
        .send_text(
            down_account,
            SendTarget::Conversation(down_conversation),
            "down".into(),
            "req-story-reply-down".into(),
            None,
            None,
            None,
            None,
            Some("22222222-2222-2222-2222-222222222222".into()),
            Some(json!(1_727_000_000_000u64)),
        )
        .await
        .err()
        .unwrap()
        .into_api();
    assert_eq!(error.code, "RUNTIME_NOT_RUNNING");
    assert!(!error.retryable, "{error:?}");
}
