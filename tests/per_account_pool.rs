// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! Full-pool (engine-pool S1, switch on) integration evidence over the real
//! runtime + fake engine:
//!
//! - every account owns an engine process and its own
//!   <signal-data>/engines/<accountId>/ data directory;
//! - per-account engine logs live in the account's own directory and never
//!   interleave;
//! - send / typing / read-receipt routing reaches exactly the owning engine;
//! - kill -9 restarts only the killed account;
//! - eight wedged engines still meet the accounts.list and shutdown budgets;
//! - the legacy -> pool migration (dry run + apply) is idempotent and the pool
//!   then serves the migrated accounts.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kt_signal_connector::engine::EngineState;
use kt_signal_connector::groups;
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::service::{
    MessagesMarkReadParams, PresenceSetTypingMessageParams, SendTarget,
};
use kt_signal_connector::store::{Store, StoreKey};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

/// These tests each start several real engine processes; running them in
/// parallel makes process startup/link timing contend with the pool under
/// test. Serialize the file's tests (they are a few seconds together).
static POOL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn store_for(temp: &TempDir) -> Store {
    Store::open(&temp.path().join("state"), Some(key())).unwrap()
}

fn account_id(index: u8) -> String {
    format!("{index:032x}")
}

/// One provisioned account: the store row, its own engine data directory, a
/// single-account engine registry, and a placeholder presage store.
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
        serde_json::to_vec_pretty(&json!({
            "version": 2,
            "accounts": [{"number": number, "dir": relative}],
        }))
        .unwrap(),
    )
    .unwrap();
}

fn seed_accounts(temp: &TempDir, count: u8) -> Vec<(String, String)> {
    let signal_data = temp.path().join("signal-data");
    let store = store_for(temp);
    let mut accounts = Vec::new();
    for index in 1..=count {
        let id = account_id(index);
        let number = format!("+1557555{index:08}");
        seed_account(&store, &signal_data, &id, &number, "default");
        accounts.push((id, number));
    }
    accounts
}

fn open_pool(temp: &TempDir, options: RuntimeOptions) -> Arc<ProxyGroupRuntime> {
    let signal_data = temp.path().join("signal-data");
    let plan = groups::build_group_plan(&[], None, None, &signal_data).unwrap();
    open_group_runtime_with_options(
        plan,
        fixture(),
        &temp.path().join("state"),
        None,
        Some(key()),
        false,
        Duration::from_millis(30),
        options,
    )
    .unwrap()
}

fn pool_options(
    max_resident: usize,
    list_budget: Duration,
    shutdown_budget: Duration,
) -> RuntimeOptions {
    RuntimeOptions {
        per_account_engines: true,
        pool_policy: EnginePoolPolicy {
            max_engines: 8,
            max_resident,
            shutdown_budget,
            list_accounts_budget: list_budget,
            demote_idle_after: Duration::from_secs(60),
        },
        watchdog_interval: Some(Duration::from_millis(50)),
    }
}

/// Live processes whose command line names this account's engine directory
/// (the fake engine's argv carries --data-dir <path>). Exactly one is the
/// I1/I2 invariant; two would be the 4409 shape.
fn engine_processes(data_dir: &Path) -> usize {
    let needle = data_dir.to_string_lossy().to_string();
    let output = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(&needle) && line.contains("fake-engine.py"))
        .count()
}

fn engine_log_pids(data_dir: &Path) -> Vec<u32> {
    let path = data_dir.join("logs").join("engine-stderr.log");
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = text
        .lines()
        .filter_map(|line| line.strip_prefix("pid="))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|pid| pid.parse().ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

fn data_dir(temp: &TempDir, id: &str) -> PathBuf {
    temp.path().join("signal-data").join("engines").join(id)
}

fn contains_quarantine(root: &Path) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_name() == "_quarantine" {
                return true;
            }
            if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                stack.push(entry.path());
            }
        }
    }
    false
}

async fn wait_for_engine_pid_change(
    runtime: &Arc<ProxyGroupRuntime>,
    account_id: &str,
    old_pid: u32,
) -> u32 {
    timeout(Duration::from_secs(15), async {
        loop {
            let status = runtime.status().await;
            if let Some(engine) = status
                .engines
                .iter()
                .find(|engine| engine.account_id == account_id)
                && let Some(pid) = engine.pid
                && pid != old_pid
            {
                return pid;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the watchdog restarts only the killed account")
}

fn send_target() -> SendTarget {
    SendTarget::Peer {
        kind: "direct".into(),
        peer_key: "+15555550101".into(),
        peer_title: None,
    }
}

/// The conversation a linked account already owns after the fixture's
/// post-link receive (the typing/receipt faces address a real row).
async fn conversation_for(runtime: &Arc<ProxyGroupRuntime>, account: &str) -> String {
    timeout(Duration::from_secs(5), async {
        loop {
            let page = runtime
                .list_conversations(account.to_string(), 10, None)
                .await
                .expect("conversation listing");
            if let Some(conversation) = page.items.first() {
                return conversation.id.clone();
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the post-link receive materializes a conversation")
}

async fn send(runtime: &Arc<ProxyGroupRuntime>, account: &str, text: &str) {
    runtime
        .send_text(
            account.to_string(),
            send_target(),
            text.to_string(),
            format!("req-{account}"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("send routes to the account's own engine");
}

/// Two linked accounts produce two engines, two data directories, two
/// disjoint log files, and send/typing/receipt traffic that never crosses the
/// account boundary.
#[tokio::test]
async fn linked_accounts_get_their_own_engine_dirs_pids_logs_and_traffic() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    let runtime = open_pool(
        &temp,
        pool_options(5, Duration::from_secs(3), Duration::from_secs(8)),
    );
    let started = runtime.start().await.expect("an empty pool starts");
    assert_eq!(started.engines.len(), 0);

    let mut accounts = Vec::new();
    for device in ["test-device-a", "test-device-b"] {
        let before: HashSet<String> = runtime
            .status()
            .await
            .engines
            .iter()
            .map(|engine| engine.account_id.clone())
            .collect();
        let link = runtime
            .start_link(device.to_string(), Some("default".into()))
            .await
            .expect("link.start provisions a slot");
        let session = link["linkSessionId"].as_str().unwrap().to_string();
        let status = runtime.status().await;
        assert_eq!(status.engines.len(), accounts.len() + 1);
        let account = status
            .engines
            .iter()
            .find(|engine| !before.contains(&engine.account_id))
            .expect("the new slot appears in engines[]")
            .account_id
            .clone();
        let dir = data_dir(&temp, &account);
        assert!(dir.is_dir(), "each link gets its own data directory");
        // Arm the fixture's engine log and read-receipt gate before the
        // finish call.
        fs::write(dir.join(".fixture-engine-log"), b"").unwrap();
        fs::write(dir.join(".fixture-read-receipts"), b"").unwrap();
        let summary = match runtime.finish_link(session).await {
            Ok(summary) => summary,
            Err(error) => {
                let status = runtime.status().await;
                let mut dirs = Vec::new();
                if let Ok(entries) = fs::read_dir(temp.path().join("signal-data").join("engines")) {
                    for entry in entries.flatten() {
                        let state = fs::read(entry.path().join("engine-state.json"))
                            .ok()
                            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
                        dirs.push(format!(
                            "{}={}",
                            entry.file_name().to_string_lossy(),
                            state
                                .map(|state| state["accounts"][0]["number"].to_string())
                                .unwrap_or_else(|| "none".into())
                        ));
                    }
                }
                panic!(
                    "link.finish failed {}: engines={dirs:?} status={}",
                    error.into_api().code,
                    serde_json::to_value(status).unwrap()
                );
            }
        };
        assert_eq!(summary.id, account);
        assert_eq!(summary.proxy_group, "default");
        assert_eq!(runtime.status().await.engines.len(), accounts.len() + 1);
        accounts.push(summary);
    }

    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 2);
    assert_eq!(status.aggregate.state, EngineState::Running);
    assert!(
        !status.aggregate.degraded,
        "two healthy engines must not degrade: {}",
        serde_json::to_value(&status).unwrap()
    );
    // The plan group is proxy policy only in full-pool mode.
    assert_eq!(status.proxy_groups.len(), 1);
    assert_eq!(status.proxy_groups[0].state, EngineState::Stopped);
    assert_eq!(status.proxy_groups[0].account_count, 2);

    let listed = runtime.list_accounts().await.unwrap();
    assert_eq!(listed.len(), 2);
    for account in &accounts {
        assert!(listed.iter().any(|row| row.id == account.id));
    }

    let pids: Vec<u32> = status
        .engines
        .iter()
        .filter_map(|engine| engine.pid)
        .collect();
    assert_eq!(pids.len(), 2);
    assert_ne!(pids[0], pids[1], "one process per account");

    for (index, account) in accounts.iter().enumerate() {
        let dir = data_dir(&temp, &account.id);
        assert_eq!(
            engine_processes(&dir),
            1,
            "exactly one engine process per account data directory"
        );
        assert!(dir.join("engine-state.json").is_file());
        let state: Value =
            serde_json::from_slice(&fs::read(dir.join("engine-state.json")).unwrap()).unwrap();
        assert_eq!(state["accounts"].as_array().unwrap().len(), 1);
        // Traffic: one send, one typing indicator, one read receipt each.
        send(&runtime, &account.id, &format!("hello-{index}")).await;
        let conversation = conversation_for(&runtime, &account.id).await;
        let incoming_ids: Vec<String> = runtime
            .list_messages(account.id.clone(), conversation.clone(), 10, None)
            .await
            .expect("message listing")
            .items
            .iter()
            .filter(|message| message.direction == "incoming")
            .map(|message| message.id.clone())
            .collect();
        assert!(
            !incoming_ids.is_empty(),
            "the post-link receive is a local incoming row"
        );
        runtime
            .set_typing_message(PresenceSetTypingMessageParams {
                account_id: account.id.clone(),
                conversation_id: conversation.clone(),
                stop: Some(false),
                operation_id: None,
            })
            .await
            .expect("typing routes to the owning engine");
        runtime
            .send_mark_read(MessagesMarkReadParams {
                account_id: account.id.clone(),
                conversation_id: conversation,
                message_ids: Some(incoming_ids),
                message_id: None,
            })
            .await
            .expect("read receipt routes to the owning engine");
    }

    // Each engine saw exactly its own send / typing / receipt methods.
    for account in &accounts {
        let log = fs::read_to_string(data_dir(&temp, &account.id).join("logs/engine-stderr.log"))
            .expect("engine log");
        let methods: HashSet<&str> = log
            .lines()
            .filter_map(|line| {
                line.split_whitespace()
                    .find(|part| part.starts_with("method="))
            })
            .collect();
        for expected in ["method=send", "method=sendTyping", "method=sendReadReceipt"] {
            assert!(
                methods.contains(expected),
                "account {} engine log missing {expected}: {methods:?}",
                account.id
            );
        }
    }

    // Each engine's log carries only its own pid; the sets are disjoint.
    let status = runtime.status().await;
    let mut log_pids = Vec::new();
    for account in &accounts {
        let pid = status
            .engines
            .iter()
            .find(|engine| engine.account_id == account.id)
            .and_then(|engine| engine.pid)
            .expect("running engine");
        let pids_in_log = engine_log_pids(&data_dir(&temp, &account.id));
        assert_eq!(
            pids_in_log,
            vec![pid],
            "account {} log must carry only its engine pid",
            account.id
        );
        log_pids.push(pid);
    }
    assert_ne!(log_pids[0], log_pids[1]);

    // Each engine's own send log holds only its account's send.
    for (index, account) in accounts.iter().enumerate() {
        let log = fs::read_to_string(data_dir(&temp, &account.id).join(".fixture-send-log.jsonl"))
            .expect("the owning engine saw the send");
        assert!(log.contains(&format!("hello-{index}")));
        let other = 1 - index;
        assert!(!log.contains(&format!("hello-{other}")));
    }

    let shutdown_started = Instant::now();
    runtime.shutdown().await.unwrap();
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(8),
        "two-engine shutdown stays inside the pool budget"
    );
}

/// kill -9 on one account's engine: only that account's engine is replaced;
/// the other account's pid is untouched and its send keeps working.
#[tokio::test]
async fn kill_9_restarts_only_the_killed_account() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let accounts = seed_accounts(&temp, 2);
    let runtime = open_pool(
        &temp,
        pool_options(2, Duration::from_secs(3), Duration::from_secs(8)),
    );
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 2);
    let pid_a = status.engines[0].pid.unwrap();
    let pid_b = status.engines[1].pid.unwrap();
    assert_ne!(pid_a, pid_b);

    unsafe {
        libc::kill(pid_a as i32, libc::SIGKILL);
    }

    // The survivor keeps serving while the killed account is down/restarting.
    let survivor_before = runtime.status().await.engines[1].pid.unwrap();
    send(&runtime, &accounts[1].0, "survivor-send").await;
    assert_eq!(
        runtime.status().await.engines[1].pid.unwrap(),
        survivor_before,
        "the other account's engine never restarts"
    );

    let new_pid = wait_for_engine_pid_change(&runtime, &accounts[0].0, pid_a).await;
    assert_ne!(new_pid, pid_a);
    assert_eq!(runtime.status().await.engines[1].pid.unwrap(), pid_b);
    // The killed account is usable again after its private restart.
    send(&runtime, &accounts[0].0, "recovered-send").await;
    assert_eq!(engine_processes(&data_dir(&temp, &accounts[0].0)), 1);
    assert_eq!(engine_processes(&data_dir(&temp, &accounts[1].0)), 1);

    runtime.shutdown().await.unwrap();
}

/// Eight wedged engines (the hard cap; the parallel code path is identical for
/// any N): the parallel accounts.list degrades to local rows at its budget,
/// and the whole pool still stops inside its shutdown budget.
#[tokio::test]
async fn wedged_engines_still_meet_the_list_and_shutdown_budgets() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let accounts = seed_accounts(&temp, 8);
    for (id, _) in &accounts {
        let dir = data_dir(&temp, id);
        fs::write(dir.join(".fixture-stall-list-accounts"), b"").unwrap();
        fs::write(dir.join(".fixture-stall-shutdown"), b"").unwrap();
    }
    let runtime = open_pool(
        &temp,
        pool_options(8, Duration::from_millis(200), Duration::from_millis(300)),
    );
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 8);
    let pids: Vec<u32> = status
        .engines
        .iter()
        .filter_map(|engine| engine.pid)
        .collect();
    assert_eq!(pids.len(), 8);

    for _ in 0..5 {
        let started = Instant::now();
        let listed = runtime.list_accounts().await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(listed.len(), 8, "degraded listing keeps the local rows");
        assert!(
            elapsed < Duration::from_secs(2),
            "accounts.list must stay near its budget, took {elapsed:?}"
        );
    }

    let started = Instant::now();
    runtime.shutdown().await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "the whole pool stops inside its budget, took {elapsed:?}"
    );
    timeout(Duration::from_secs(5), async {
        loop {
            if pids.iter().all(|pid| !process_alive(*pid)) {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("every engine process is gone after the pool shutdown");
}

/// A zombie is dead for our purposes (the killed child may not be reaped
/// yet); only a live/running/stopped state counts as alive.
fn process_alive(pid: u32) -> bool {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "state="])
        .output()
        .expect("ps");
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    !state.is_empty() && !state.starts_with('Z')
}

/// Production budgets at the eight-engine hard cap (the design's ten-engine
/// shape is capped at eight by MAX_PER_ACCOUNT_ENGINES; the parallel code path
/// is N-independent). Healthy engines must answer well inside the real 3 s
/// list budget and stop well inside the real 8 s shutdown budget.
#[tokio::test]
async fn production_budgets_hold_for_the_full_eight_engine_pool() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _accounts = seed_accounts(&temp, 8);
    let runtime = open_pool(
        &temp,
        RuntimeOptions {
            per_account_engines: true,
            pool_policy: EnginePoolPolicy {
                max_engines: 8,
                max_resident: 8,
                ..EnginePoolPolicy::default()
            },
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    );
    runtime.start().await.unwrap();
    assert_eq!(runtime.status().await.engines.len(), 8);

    for _ in 0..5 {
        let started = Instant::now();
        let listed = runtime.list_accounts().await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(listed.len(), 8);
        assert!(
            elapsed < Duration::from_secs(3),
            "accounts.list P95 budget (3 s) exceeded: {elapsed:?}"
        );
    }

    let started = Instant::now();
    runtime.shutdown().await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(8),
        "eight-engine shutdown budget (8 s) exceeded: {elapsed:?}"
    );
}

/// Legacy -> pool migration through the CLI: the dry run does not move
/// anything and reports exactly what the applied pass does; the pool then
/// serves the migrated accounts from their new directories.
#[tokio::test]
async fn migration_dry_run_matches_apply_and_the_pool_serves_the_result() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signal_data = temp.path().join("signal-data");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&signal_data).unwrap();

    // A legacy single-engine layout: two accounts in the default group's data
    // directory (the pre-pool shape).
    let store = store_for(&temp);
    let mut legacy_state = json!({"version": 2, "accounts": []});
    let mut seeded = Vec::new();
    for index in 1..=2u8 {
        let id = account_id(index);
        let number = format!("+1557555{index:08}");
        store
            .upsert_account_from_signal_with_id(&number, Some(1), "default", Some(&id))
            .unwrap();
        let store_name = format!("lk-legacy-{index}");
        let store_dir = signal_data.join("accounts").join(&store_name);
        fs::create_dir_all(&store_dir).unwrap();
        fs::write(store_dir.join("store.db"), b"legacy-store").unwrap();
        legacy_state["accounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"number": number, "dir": format!("accounts/{store_name}")}));
        seeded.push(id);
    }
    fs::write(
        signal_data.join("engine-state.json"),
        serde_json::to_vec_pretty(&legacy_state).unwrap(),
    )
    .unwrap();
    drop(store);

    // The migration CLI reads the bootstrap payload's store-key line without
    // consuming the file, so one launcher payload backs every invocation.
    let secret_file = temp.path().join("bootstrap.secret");
    fs::write(
        &secret_file,
        format!(
            "{}\n{}",
            hex::encode([7_u8; 32]),
            hex::encode(TEST_STORE_KEY)
        ),
    )
    .unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let migrate = |dry_run: bool| {
        let output = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"))
            .arg("migrate-pool")
            .arg("--signal-data-dir")
            .arg(&signal_data)
            .arg("--state-dir")
            .arg(&state_dir)
            .arg("--bootstrap-secret-file")
            .arg(&secret_file)
            .args(dry_run.then_some("--dry-run"))
            .output()
            .expect("migrate-pool runs");
        assert!(
            output.status.success(),
            "migrate-pool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("migration report")
    };

    let dry = migrate(true);
    assert_eq!(dry["dryRun"], true);
    assert_eq!(dry["migrated"], 0);
    assert!(
        dry["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["action"] == "wouldMigrate")
    );
    assert!(
        !signal_data.join("engines").exists(),
        "the dry run must not create engine directories"
    );

    let applied = migrate(false);
    assert_eq!(applied["migrated"], 2);
    for id in &seeded {
        let dir = data_dir(&temp, id);
        assert!(dir.join("engine-state.json").is_file());
        assert!(dir.join("accounts").is_dir());
    }
    let legacy_state: Value =
        serde_json::from_slice(&fs::read(signal_data.join("engine-state.json")).unwrap()).unwrap();
    assert!(
        legacy_state["accounts"].as_array().unwrap().is_empty(),
        "the legacy registry only keeps an empty shell"
    );

    // The pool starts from the migrated layout and serves both accounts.
    let runtime = open_pool(
        &temp,
        pool_options(5, Duration::from_secs(3), Duration::from_secs(8)),
    );
    runtime.start().await.unwrap();
    let listed = runtime.list_accounts().await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(
        !contains_quarantine(&signal_data),
        "no account store may land in quarantine"
    );
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 2);
    assert!(
        status
            .engines
            .iter()
            .all(|engine| engine.state == EngineState::Running)
    );
    send(&runtime, &seeded[0], "migrated-send").await;

    // A second run is a no-op (idempotent, resumable) and the CLI never
    // consumed the launcher's bootstrap payload.
    let again = migrate(false);
    assert_eq!(again["alreadyMigrated"], 2);
    assert_eq!(again["migrated"], 0);
    assert!(
        secret_file.is_file(),
        "the migration CLI must not delete the launcher's bootstrap file"
    );

    runtime.shutdown().await.unwrap();
}

/// Link one account through the real start/finish flow and return its
/// committed summary (the new slot is the id that appeared in engines[]).
async fn link_account(
    runtime: &Arc<ProxyGroupRuntime>,
    device: &str,
) -> kt_signal_connector::store::AccountSummary {
    let before: HashSet<String> = runtime
        .status()
        .await
        .engines
        .iter()
        .map(|engine| engine.account_id.clone())
        .collect();
    let link = runtime
        .start_link(device.to_string(), Some("default".into()))
        .await
        .expect("link.start provisions a slot");
    let session = link["linkSessionId"].as_str().unwrap().to_string();
    let account = runtime
        .status()
        .await
        .engines
        .iter()
        .find(|engine| !before.contains(&engine.account_id))
        .expect("the new slot appears in engines[]")
        .account_id
        .clone();
    let summary = runtime
        .finish_link(session)
        .await
        .expect("link.finish commits the account");
    assert_eq!(summary.id, account);
    summary
}

/// Product decision (2026-10-21): the resident window equals the hard ceiling,
/// so eight linked accounts are eight live engines that all keep receiving.
/// The old K=5 window would have left the 6th–8th cold (no real-time receive).
#[tokio::test]
async fn eight_linked_accounts_all_stay_hot_and_receive() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    let runtime = open_pool(
        &temp,
        RuntimeOptions {
            per_account_engines: true,
            pool_policy: EnginePoolPolicy {
                // Even the old demotion threshold is irrelevant with the
                // default window: it must not fire.
                demote_idle_after: Duration::from_millis(50),
                ..EnginePoolPolicy::default()
            },
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    );
    runtime.start().await.expect("an empty pool starts");

    let mut accounts = Vec::new();
    for index in 0..8 {
        accounts.push(link_account(&runtime, &format!("device-{index}")).await);
    }

    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 8);
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| engine.state == EngineState::Running)
            .count(),
        8,
        "every linked account engine is running"
    );
    assert!(
        status.engines.iter().all(|engine| engine.resident),
        "every linked account is resident by default"
    );
    let pids: HashSet<u32> = status
        .engines
        .iter()
        .filter_map(|engine| engine.pid)
        .collect();
    assert_eq!(pids.len(), 8, "eight distinct engine processes");

    for account in &accounts {
        assert_eq!(
            engine_processes(&data_dir(&temp, &account.id)),
            1,
            "one process per account directory"
        );
        // Receive evidence: the post-link envelope from this account's own
        // engine landed as a conversation + incoming row.
        let conversation = conversation_for(&runtime, &account.id).await;
        let messages = runtime
            .list_messages(account.id.clone(), conversation, 10, None)
            .await
            .expect("message listing");
        assert!(
            messages
                .items
                .iter()
                .any(|message| message.direction == "incoming"),
            "account {} is receiving",
            account.id
        );
    }

    // No idle demotion: even past the (artificially tiny) old threshold all
    // eight engines stay up.
    sleep(Duration::from_millis(300)).await;
    let status = runtime.status().await;
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| engine.state == EngineState::Running)
            .count(),
        8,
        "the default window never demotes an idle account"
    );
    assert!(status.engines.iter().all(|engine| engine.resident));

    runtime.shutdown().await.unwrap();
}

/// `KT_SIGNAL_POOL_MAX_RESIDENT=5` restores the opt-in window: only five
/// engines start, the other three remain cold until requested.
#[tokio::test]
async fn pool_max_resident_env_restores_the_opt_in_window() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _accounts = seed_accounts(&temp, 8);
    // Serialized by POOL_TEST_LOCK; other pool tests pass explicit policies.
    unsafe {
        std::env::set_var("KT_SIGNAL_POOL_MAX_RESIDENT", "5");
    }
    let policy = EnginePoolPolicy::from_env();
    unsafe {
        std::env::remove_var("KT_SIGNAL_POOL_MAX_RESIDENT");
    }
    assert_eq!(policy.max_resident, 5);
    let runtime = open_pool(
        &temp,
        RuntimeOptions {
            per_account_engines: true,
            pool_policy: policy,
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    );
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 8);
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| engine.state == EngineState::Running)
            .count(),
        5,
        "the opt-in window starts only its five slots"
    );
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| engine.resident)
            .count(),
        5
    );
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| !engine.resident)
            .count(),
        3
    );
    runtime.shutdown().await.unwrap();
}

/// Demotion still works when the operator opts into a smaller window: waking
/// a cold account pushes the resident set past five and the idle LRU resident
/// is stopped in the background.
#[tokio::test]
async fn opted_in_window_demotes_an_idle_resident() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _accounts = seed_accounts(&temp, 8);
    let runtime = open_pool(
        &temp,
        RuntimeOptions {
            per_account_engines: true,
            pool_policy: EnginePoolPolicy {
                max_engines: 8,
                max_resident: 5,
                shutdown_budget: Duration::from_secs(8),
                list_accounts_budget: Duration::from_secs(3),
                // Zero makes every resident immediately eligible; production
                // keeps the 60 s idle window.
                demote_idle_after: Duration::ZERO,
            },
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    );
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| engine.state == EngineState::Running)
            .count(),
        5
    );
    let cold = status
        .engines
        .iter()
        .find(|engine| engine.state != EngineState::Running)
        .expect("three slots stay cold")
        .account_id
        .clone();

    // A routed store read wakes the cold slot; the window then demotes one
    // idle resident in the background.
    runtime
        .list_conversations(cold.clone(), 10, None)
        .await
        .expect("routed call wakes the cold slot");
    timeout(Duration::from_secs(5), async {
        loop {
            let status = runtime.status().await;
            let running = status
                .engines
                .iter()
                .filter(|engine| engine.state == EngineState::Running)
                .count();
            let woken = status
                .engines
                .iter()
                .find(|engine| engine.account_id == cold)
                .expect("the woken slot is listed");
            if running == 5 && woken.state == EngineState::Running {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the opted-in window demotes an idle resident");

    let status = runtime.status().await;
    assert!(
        status
            .engines
            .iter()
            .find(|engine| engine.account_id == cold)
            .unwrap()
            .resident,
        "the woken account stays resident"
    );
    assert_eq!(
        status
            .engines
            .iter()
            .filter(|engine| engine.state == EngineState::Running)
            .count(),
        5
    );
    runtime.shutdown().await.unwrap();
}

/// Contract 1.286 (§4.272): a pooled link attempt rotates on its own engine
/// slot — rotation provisions no second account directory and no second
/// engine — and the rotated code finishes through the pool's routing face
/// (the new slot's session id was minted after the pool registered the
/// attempt, so routing cannot rely on the session map alone).
#[tokio::test]
async fn a_pooled_link_attempt_rotates_on_its_own_slot_and_commits_once() {
    let _guard = POOL_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    let runtime = open_pool(
        &temp,
        pool_options(5, Duration::from_secs(3), Duration::from_secs(8)),
    );
    runtime.start().await.expect("an empty pool starts");
    assert_eq!(runtime.status().await.engines.len(), 0);

    let link = runtime
        .start_link("pool-rotate".to_string(), Some("default".into()))
        .await
        .expect("link.start provisions a slot");
    let attempt = link["linkAttemptId"]
        .as_str()
        .expect("a rotate-capable fixture states the attempt")
        .to_string();
    let session0 = link["linkSessionId"].as_str().unwrap().to_string();
    let provisioned = runtime.status().await.engines.len();
    assert_eq!(provisioned, 1);

    let rotated = runtime
        .rotate_link(attempt.clone())
        .await
        .expect("the pooled attempt rotates on its own engine");
    assert_eq!(rotated["slot"], 1, "{rotated}");
    let session1 = rotated["linkSessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("the rotate answer names the new slot: {rotated}"))
        .to_string();
    assert_eq!(
        runtime.status().await.engines.len(),
        provisioned,
        "rotation reuses the attempt's own engine slot"
    );

    // The rotated code finishes through the pool routing face.
    let summary = runtime
        .finish_link(session1)
        .await
        .expect("the rotated slot commits");
    assert_eq!(summary.state, "ready");

    // The attempt committed once: the other code replays the same account.
    let replay = runtime
        .finish_link(session0)
        .await
        .expect("the committed attempt replays from its first code");
    assert_eq!(replay.id, summary.id);
    assert_eq!(runtime.status().await.engines.len(), provisioned);

    runtime.shutdown().await.unwrap();
}
