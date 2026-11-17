// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! `accounts.getSyncState` end to end (contract revision 1.286, §4.281;
//! SIGNAL-STAGE1-DESIGN §二 P-B-3): the face resolves the account, forwards
//! exactly the engine's `{account}` frame, and passes the engine's four-key
//! projection through the closed-vocabulary shape gate. The fixture plays the
//! engine; the bad-shape marker pins the protocol-defect refusal (never a
//! guessed phase); two identical calls plus two identical upstream frames pin
//! the idempotency contract the desktop gate's polling fallback rides.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::engine::EngineConfig;
use kt_signal_connector::service::AccountsGetSyncStateParams;
use kt_signal_connector::store::{Store, StoreKey};
use kt_signal_connector::supervisor::RuntimeSupervisor;
use serde_json::Value;
use tempfile::TempDir;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn test_store(dir: &Path) -> Arc<Store> {
    Arc::new(Store::open(dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap())
}

const SIGNAL_ACCOUNT: &str = "+15555550100";

fn seed_engine_registry(data_dir: &Path) {
    let account_dir = data_dir.join("accounts").join("lk-abc");
    std::fs::create_dir_all(&account_dir).unwrap();
    std::fs::write(
        data_dir.join("engine-state.json"),
        format!(
            r#"{{"version":2,"accounts":[{{"number":"{SIGNAL_ACCOUNT}","dir":"accounts/lk-abc"}}]}}"#
        ),
    )
    .unwrap();
}

fn sync_state_supervisor(
    temp: &TempDir,
    data_dir: &Path,
) -> (Arc<Store>, Arc<RuntimeSupervisor>, String) {
    seed_engine_registry(data_dir);
    let store = test_store(temp.path());
    let account = store
        .upsert_account_from_signal(
            SIGNAL_ACCOUNT,
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
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
    (store, supervisor, account.id)
}

fn log_lines(data_dir: &Path) -> Vec<Value> {
    fs::read_to_string(data_dir.join(".fixture-send-log.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

/// The read projects the engine's three half phases + sinceMs verbatim behind
/// the shape gate, forwards exactly the resolved signal account, and a
/// repeated call answers the same face with a second identical upstream frame
/// (idempotency: the query is a pure snapshot, not a transition).
#[tokio::test]
async fn sync_state_projects_verbatim_and_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("signal-data");
    let (_store, supervisor, account_id) = sync_state_supervisor(&temp, &data_dir);
    supervisor.start().await.unwrap();

    let first = supervisor
        .get_sync_state(AccountsGetSyncStateParams {
            account_id: account_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(first.contacts, "done");
    assert_eq!(first.storage, "inflight");
    assert_eq!(first.profile, "failed");
    assert_eq!(first.since_ms, 1_760_000_000_000);

    let second = supervisor
        .get_sync_state(AccountsGetSyncStateParams {
            account_id: account_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(first, second, "the face is a pure snapshot");

    let log = log_lines(&data_dir);
    let frames: Vec<&Value> = log
        .iter()
        .filter(|params| {
            params.get("account").is_some() && params.as_object().is_some_and(|o| o.len() == 1)
        })
        .collect();
    assert_eq!(frames.len(), 2, "{frames:?}");
    assert_eq!(frames[0], frames[1], "the upstream frame is idempotent");
    assert_eq!(frames[0]["account"], SIGNAL_ACCOUNT);

    // The connector never forwards the engine's bare account identity: the
    // host face is exactly the four pinned keys.
    let host = serde_json::to_value(&first).unwrap();
    let object = host.as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["contacts", "profile", "sinceMs", "storage"]);
}

/// A phase word outside the closed vocabulary is a protocol defect: the face
/// answers UPSTREAM_PROTOCOL_ERROR instead of projecting a guessed phase.
#[tokio::test]
async fn sync_state_shape_gate_refuses_an_unknown_phase() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("signal-data");
    let (_store, supervisor, account_id) = sync_state_supervisor(&temp, &data_dir);
    supervisor.start().await.unwrap();
    fs::write(data_dir.join(".fixture-sync-state-bad"), b"").unwrap();

    let error = supervisor
        .get_sync_state(AccountsGetSyncStateParams {
            account_id: account_id.clone(),
        })
        .await
        .expect_err("a phase outside the vocabulary must not cross");
    assert_eq!(error.into_api().code, "UPSTREAM_PROTOCOL_ERROR");
}
