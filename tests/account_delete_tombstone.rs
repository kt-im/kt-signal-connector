// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! BUG-8 regression suite (docs/plan/signal-known-issues.md): a local-data
//! delete whose engine slot is gone used to leave its operation ledger
//! `started` forever, and the relink gate then answered
//! ACCOUNT_DELETE_IN_PROGRESS for that number on every scan — the phone showed
//! a connected device, the desktop had nothing, and no UI path could retry the
//! delete. Each test drives the real runtime + fake engine and asserts the
//! ledger converges and the **same number** links again.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kt_signal_connector::groups;
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::store::{Store, StoreKey};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];
/// The fake engine's pool-mode ladder hands this number to the first link, so
/// the seeded account and the re-link speak about the same number — exactly
/// the collision BUG-8 describes.
const FIRST_LINK_NUMBER: &str = "+15565550001";

/// These tests start real engine processes and one of them holds a delete open;
/// running them in parallel would contend on process startup and on the shared
/// fixture ladder. Serialize the file.
static BUG8_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvGuard {
    key: &'static str,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        unsafe { std::env::set_var(key, value) };
        Self { key }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.key) };
    }
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn state_dir(temp: &TempDir) -> PathBuf {
    temp.path().join("state")
}

fn signal_data(temp: &TempDir) -> PathBuf {
    temp.path().join("signal-data")
}

fn store_for(temp: &TempDir) -> Store {
    Store::open(&state_dir(temp), Some(key())).unwrap()
}

fn account_id(index: u8) -> String {
    format!("{index:032x}")
}

fn data_dir(temp: &TempDir, account: &str) -> PathBuf {
    signal_data(temp).join("engines").join(account)
}

/// One provisioned account: the store row, its own engine data directory, a
/// single-account engine registry, and a placeholder presage store (the same
/// shape `per_account_pool.rs` builds).
fn seed_account(store: &Store, signal_data: &Path, id: &str, number: &str, group: &str) {
    store
        .upsert_account_from_signal_with_id(number, Some(1), group, Some(id))
        .unwrap();
    let data_dir = signal_data.join("engines").join(id);
    let relative = format!("accounts/lk-{}", &id[..16]);
    fs::create_dir_all(data_dir.join(&relative)).unwrap();
    fs::write(data_dir.join(&relative).join("store.db"), b"fixture-store").unwrap();
    fs::write(
        data_dir.join("engine-state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 2,
            "accounts": [{"number": number, "dir": relative}],
        }))
        .unwrap(),
    )
    .unwrap();
}

fn open_pool(temp: &TempDir) -> Arc<ProxyGroupRuntime> {
    let plan = groups::build_group_plan(&[], None, None, &signal_data(temp)).unwrap();
    open_group_runtime_with_options(
        plan,
        fixture(),
        &state_dir(temp),
        None,
        Some(key()),
        false,
        Duration::from_millis(30),
        RuntimeOptions {
            per_account_engines: true,
            single_account_guard: false,
            pool_policy: EnginePoolPolicy {
                max_engines: 8,
                max_resident: 8,
                shutdown_budget: Duration::from_secs(8),
                list_accounts_budget: Duration::from_secs(3),
                demote_idle_after: Duration::from_secs(60),
            },
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    )
    .unwrap()
}

async fn start_link(runtime: &Arc<ProxyGroupRuntime>, device: &str) -> String {
    let link = runtime
        .start_link(device.to_string(), Some("default".into()))
        .await
        .expect("link.start provisions a slot");
    link["linkSessionId"]
        .as_str()
        .expect("link.start states its session id")
        .to_string()
}

fn has_quarantine(temp: &TempDir) -> bool {
    let root = signal_data(temp).join("engines");
    fs::read_dir(root).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".quarantine-")
        })
    })
}

/// Assert the two facts every self-heal test shares: no unfinished ledger and
/// the number is bound to a row again (read from a fresh store handle after the
/// runtime is gone, so the assertions see the durable state, not a cache).
fn assert_ledger_settled_and_number_bound(temp: &TempDir) {
    let store = store_for(temp);
    assert!(
        store.list_unfinished_account_deletes().unwrap().is_empty(),
        "no delete ledger may stay unfinished after the reconcile"
    );
    assert_eq!(
        store
            .unfinished_account_delete_state(FIRST_LINK_NUMBER)
            .unwrap(),
        None,
        "the relink gate must not see an unfinished delete for this number"
    );
    assert!(
        store
            .account_by_signal(FIRST_LINK_NUMBER)
            .unwrap()
            .is_some(),
        "the same number is bound again"
    );
}

/// BUG-8 item 1: the ledger of an account row that is already gone is only an
/// unsigned receipt. The connector restart signs it and the same number can be
/// scanned again.
#[tokio::test]
async fn a_restart_settles_the_orphaned_delete_ledger_and_the_same_number_relinks() {
    let _guard = BUG8_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let id = account_id(1);
    {
        let store = store_for(&temp);
        seed_account(
            &store,
            &signal_data(&temp),
            &id,
            FIRST_LINK_NUMBER,
            "default",
        );
        // The user asked for the delete...
        store
            .prepare_account_delete(&id, "bug8-orphan-op", 10)
            .unwrap();
    }
    // ...and the rows left through a path that did not carry this operation id
    // (the operation-id-less logout tail), leaving the ledger `started` after
    // the account row was gone.
    let runtime = open_pool(&temp);
    runtime.start().await.unwrap();
    runtime
        .delete_local_account(id.clone(), None)
        .await
        .expect("the local-data delete runs through the engine");
    assert_eq!(runtime.account_state(&id).await.unwrap(), None);
    runtime.shutdown().await.unwrap();
    drop(runtime);

    let runtime = open_pool(&temp);
    runtime.start().await.expect("the restarted pool starts");
    let session = start_link(&runtime, "bug8-orphan-relink-device").await;
    let summary = runtime
        .finish_link(session)
        .await
        .expect("the same number relinks once the orphaned ledger settles");
    assert_ne!(summary.id, id, "the re-link owns a fresh slot id");
    runtime.shutdown().await.unwrap();
    drop(runtime);

    assert_ledger_settled_and_number_bound(&temp);
}

/// BUG-8 item 2: the delete lost its executor when the slot was quarantined
/// (BUG-1 recovery), so the row stayed and the ledger stayed `started`. A
/// restart converges it — the deletion fact is achievable without an engine —
/// and the same number relinks.
#[tokio::test]
async fn a_restart_converges_a_delete_whose_engine_slot_is_gone() {
    let _guard = BUG8_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let id = account_id(1);
    {
        let store = store_for(&temp);
        seed_account(
            &store,
            &signal_data(&temp),
            &id,
            FIRST_LINK_NUMBER,
            "default",
        );
        store
            .prepare_account_delete(&id, "bug8-stuck-op", 10)
            .unwrap();
    }
    // The slot leaves the live namespace (quarantine); the delete has no engine
    // left to dispatch to.
    let quarantined = signal_data(&temp)
        .join("engines")
        .join(".quarantine-bug8-stuck");
    fs::rename(data_dir(&temp, &id), &quarantined).unwrap();

    let runtime = open_pool(&temp);
    runtime.start().await.expect("the restarted pool starts");
    assert_eq!(
        runtime.account_state(&id).await.unwrap(),
        None,
        "the ready edge finished the delete whose engine data is gone"
    );
    let session = start_link(&runtime, "bug8-stuck-relink-device").await;
    let summary = runtime
        .finish_link(session)
        .await
        .expect("the same number relinks after the stuck tombstone converges");
    assert_ne!(summary.id, id);
    runtime.shutdown().await.unwrap();
    drop(runtime);

    assert!(
        quarantined.is_dir(),
        "the quarantined bytes are a recovery clue, never this pass's to delete"
    );
    assert_ledger_settled_and_number_bound(&temp);
}

/// BUG-8 item 2 at the delete face itself: a delete whose slot was quarantined
/// converges to `completed` in one call instead of leaving a tombstone that
/// blocks the same number forever.
#[tokio::test]
async fn a_delete_of_an_account_whose_slot_was_quarantined_converges_without_an_engine() {
    let _guard = BUG8_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let id = account_id(1);
    {
        let store = store_for(&temp);
        seed_account(
            &store,
            &signal_data(&temp),
            &id,
            FIRST_LINK_NUMBER,
            "default",
        );
    }
    let runtime = open_pool(&temp);
    runtime.start().await.unwrap();
    let pool = runtime.account_pool().expect("full pooling");
    assert!(
        pool.discard_quarantined(&id).await,
        "the slot leaves the live namespace"
    );
    assert!(!data_dir(&temp, &id).exists());

    runtime
        .delete_local_account(id.clone(), Some("bug8-quarantined-delete-op".to_string()))
        .await
        .expect("a delete whose engine data is gone converges instead of leaving a tombstone");
    assert_eq!(
        runtime.account_state(&id).await.unwrap(),
        None,
        "the account rows are gone"
    );
    assert!(has_quarantine(&temp), "the quarantined bytes stay");
    runtime.shutdown().await.unwrap();
    drop(runtime);

    let store = store_for(&temp);
    assert!(
        store.list_unfinished_account_deletes().unwrap().is_empty(),
        "the operation ledger settled `completed`"
    );
    assert_eq!(
        store
            .unfinished_account_delete_state(FIRST_LINK_NUMBER)
            .unwrap(),
        None,
        "the number is free for a re-link"
    );
}

/// BUG-12 语义（2026-11-12 起）：休眠只停引擎、槽留在运行集，所以「冷槽」
/// 的删除不再是「池看不见 = 数据没了」的 fail-closed 场景——请求路径会先
/// 唤醒引擎，再走正常删除。本用例钉住这条新语义（旧版用例假设 hibernate
/// 会把槽移出 map，那正是 BUG-12 的缺陷形态）。
#[tokio::test]
async fn a_cold_slot_wakes_for_delete_instead_of_failing_closed() {
    let _guard = BUG8_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let id = account_id(9);
    {
        let store = store_for(&temp);
        seed_account(
            &store,
            &signal_data(&temp),
            &id,
            FIRST_LINK_NUMBER,
            "default",
        );
        store
            .prepare_account_delete(&id, "bug8-cold-slot-op", 10)
            .unwrap();
    }
    let runtime = open_pool(&temp);
    runtime.start().await.unwrap();
    let pool = runtime.account_pool().expect("full pooling");
    assert!(
        pool.hibernate_slot(&id).await,
        "the slot cools without losing its data directory"
    );
    assert!(data_dir(&temp, &id).is_dir());
    // 冷槽删除：唤醒引擎（一次 spawn）后正常删除，而不是答 ENGINE_NOT_PROVISIONED。
    runtime
        .delete_local_account(id.clone(), Some("bug8-cold-slot-op".to_string()))
        .await
        .expect("a cold slot wakes for the delete instead of failing closed");
    assert_eq!(runtime.account_state(&id).await.unwrap(), None);
}

/// BUG-8 item 4 (connector half): the phone-approved link must not be refused
/// into the phantom-device shape while a delete of the same number is only
/// settling. The finish waits (bounded) and commits once the delete lands.
#[tokio::test]
async fn a_link_finish_waits_for_a_concurrent_delete_of_the_same_number_then_commits() {
    let _guard = BUG8_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let id = account_id(1);
    {
        let store = store_for(&temp);
        seed_account(
            &store,
            &signal_data(&temp),
            &id,
            FIRST_LINK_NUMBER,
            "default",
        );
        store
            .prepare_account_delete(&id, "bug8-race-delete-op", 10)
            .unwrap();
    }
    // The engine parks the delete answer until the test releases it, so the
    // ledger is genuinely in flight while the finish arrives.
    let _hold = EnvGuard::set("KT_FAKE_DELETE_MODE", "hold");
    let runtime = open_pool(&temp);
    runtime.start().await.expect("the pool starts");
    let session = start_link(&runtime, "bug8-race-device").await;

    let finish = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            let started = Instant::now();
            let outcome = runtime.finish_link(session).await;
            (started.elapsed(), outcome)
        })
    };
    // Give the finish its first ledger probe before the delete starts: it must
    // see `started` and wait rather than refuse.
    sleep(Duration::from_secs(2)).await;
    let delete = {
        let runtime = Arc::clone(&runtime);
        let id = id.clone();
        tokio::spawn(async move {
            runtime
                .delete_local_account(id, Some("bug8-race-delete-op".to_string()))
                .await
        })
    };
    let running_marker = data_dir(&temp, &id).join(".fixture-delete-running");
    for _ in 0..250 {
        if running_marker.exists() {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        running_marker.exists(),
        "the engine received the held delete"
    );
    fs::write(data_dir(&temp, &id).join(".fixture-delete-release"), b"").unwrap();

    timeout(Duration::from_secs(20), delete)
        .await
        .expect("the delete settles in time")
        .expect("the delete task")
        .expect("the held delete completes");
    let (elapsed, outcome) = timeout(Duration::from_secs(30), finish)
        .await
        .expect("the finish settles in time")
        .expect("the finish task");
    let summary = outcome.expect("the commit lands once the delete settled");
    assert_ne!(summary.id, id);
    assert!(
        elapsed >= Duration::from_millis(4500),
        "the finish waited for the in-flight delete (elapsed {elapsed:?})"
    );
    runtime.shutdown().await.unwrap();
    drop(runtime);

    assert_ledger_settled_and_number_bound(&temp);
}
