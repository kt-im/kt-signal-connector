// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! P1 runtime isolation (contract revision 1.288, §4.274) — the connector half:
//!
//! - the single-account guard (`KT_ENGINE_SINGLE_ACCOUNT=1`) is handed to every
//!   pooled engine child, and a slot that names a second account is an explicit
//!   startup failure (never a cold account that silently never starts);
//! - the guard and the legacy topology are mutually exclusive (the legacy
//!   engine shares one process across a group);
//! - a data directory that mixes the legacy and pooled layouts fails closed
//!   with the `migrate-pool` command in the message, never a guess;
//! - startup prints exactly one mode line (legacy/pooled + resident cap) with
//!   no account material;
//! - `migrate-pool --dry-run` is a read-only, actionable plan: layout, account
//!   count, resident/cold split, expected exit code, next steps.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use kt_signal_connector::engine::EngineState;
use kt_signal_connector::groups;
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{RuntimeOptions, open_group_runtime_with_options};
use kt_signal_connector::store::{Store, StoreKey};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn account_id(index: u8) -> String {
    format!("{index:032x}")
}

fn slot_dir(root: &Path, id: &str) -> PathBuf {
    root.join("signal-data").join("engines").join(id)
}

/// One provisioned account: store row, slot directory, registry naming exactly
/// that account, and a placeholder presage store.
fn seed_slot(root: &Path, id: &str, number: &str) -> Store {
    let store = Store::open(&root.join("state"), Some(key())).unwrap();
    store
        .upsert_account_from_signal_with_id(number, Some(1), "default", Some(id))
        .unwrap();
    let dir = slot_dir(root, id);
    let relative = format!("accounts/lk-{}", &id[..16]);
    fs::create_dir_all(dir.join(&relative)).unwrap();
    fs::write(dir.join(&relative).join("store.db"), b"fixture-store").unwrap();
    fs::write(
        dir.join("engine-state.json"),
        serde_json::to_vec(&json!({
            "version": 2,
            "accounts": [{"number": number, "dir": relative}],
        }))
        .unwrap(),
    )
    .unwrap();
    store
}

/// A legacy (pre-pool) account: store row, proxy-group directory, registry
/// entry, and the presage store in `accounts/lk-*`.
fn seed_legacy_account(root: &Path, store: &Store, id: &str, number: &str, store_name: &str) {
    store
        .upsert_account_from_signal_with_id(number, Some(1), "default", Some(id))
        .unwrap();
    let signal_data = root.join("signal-data");
    let dir = signal_data.join("accounts").join(store_name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("store.db"), b"legacy-store").unwrap();
    let mut state: Value = fs::read(signal_data.join("engine-state.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| json!({"version": 2, "accounts": []}));
    state["accounts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"number": number, "dir": format!("accounts/{store_name}")}));
    fs::write(
        signal_data.join("engine-state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn pool_options(guard: bool) -> RuntimeOptions {
    RuntimeOptions {
        per_account_engines: true,
        single_account_guard: guard,
        pool_policy: EnginePoolPolicy::default(),
        watchdog_interval: Some(Duration::from_millis(50)),
    }
}

/// Every entry the connector could create under a directory tree — name plus
/// the SHA-256 of each file's bytes (a dry run must leave the whole list
/// identical, and a digest keeps a mismatched store from dumping megabytes
/// into the failure message).
fn tree_snapshot(root: &Path) -> Vec<(String, Option<String>)> {
    use sha2::{Digest, Sha256};

    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(children) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in children.flatten() {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                entries.push((relative, None));
                stack.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                let digest = format!("{:x} ({} bytes)", Sha256::digest(&bytes), bytes.len());
                entries.push((relative, Some(digest)));
            }
        }
    }
    entries.sort();
    entries
}

/// The server half of a `serve` spawn: the stdin bootstrap payload (secret +
/// store key) and stderr captured for the mode line.
async fn spawn_serve(root: &Path, pooled: bool) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--bootstrap-secret-stdin")
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--signal-data-dir")
        .arg(root.join("signal-data"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .env_remove("KT_SIGNAL_STORE_KEY")
        .env_remove("KT_ENGINE_SINGLE_ACCOUNT")
        .env_remove("KT_SIGNAL_POOL_MAX_RESIDENT")
        .kill_on_drop(true);
    if pooled {
        command.arg("--per-account-engines");
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("connector binary runs");
    let mut stdin = child.stdin.take().expect("stdin piped");
    let payload = format!(
        "{}\n{}",
        hex::encode([0x11_u8; 32]),
        hex::encode(TEST_STORE_KEY)
    );
    stdin.write_all(payload.as_bytes()).await.unwrap();
    // The loader reads the two-line payload to EOF; EOF on the connector's own
    // stdin does not end serve (the engine has its own stdio).
    stdin.shutdown().await.unwrap();
    child
}

/// Read stderr lines until the one-shot mode line appears (bounded), then keep
/// draining for a short window so a second line would be caught.
async fn read_mode_lines(child: &mut Child) -> Vec<String> {
    let stderr = child.stderr.take().expect("stderr piped");
    let mut lines = BufReader::new(stderr).lines();
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let line = match timeout(Duration::from_millis(500), lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => break,
            Ok(Err(_)) => break,
            Err(_) => continue,
        };
        if line.contains("connector runtime mode") {
            seen.push(line);
            break;
        }
    }
    // The line is logged once at assembly; a second one inside this window
    // would be a duplicate.
    let probe = Instant::now() + Duration::from_millis(400);
    while Instant::now() < probe {
        match timeout(Duration::from_millis(100), lines.next_line()).await {
            Ok(Ok(Some(line))) if line.contains("connector runtime mode") => seen.push(line),
            _ => {}
        }
    }
    seen
}

/// One startup line names the topology and the resident cap, and carries no
/// account material (ids, numbers, paths). Pooled and legacy each print it once.
#[tokio::test]
async fn startup_prints_the_mode_and_resident_cap_exactly_once() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();

    let mut pooled = spawn_serve(temp.path(), true).await;
    let pooled_lines = read_mode_lines(&mut pooled).await;
    let _ = pooled.kill().await;
    assert_eq!(
        pooled_lines.len(),
        1,
        "exactly one pooled mode line: {pooled_lines:?}"
    );
    let line = &pooled_lines[0];
    assert!(line.contains(r#"mode="pooled""#), "{line}");
    assert!(line.contains("resident_cap=8"), "{line}");
    assert!(line.contains("single_account_guard=false"), "{line}");
    for forbidden in ["+1555", "engines/", "account_id"] {
        assert!(!line.contains(forbidden), "{line} carries {forbidden}");
    }

    let legacy_temp = TempDir::new().unwrap();
    fs::set_permissions(legacy_temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(legacy_temp.path().join("signal-data")).unwrap();
    let mut legacy = spawn_serve(legacy_temp.path(), false).await;
    let legacy_lines = read_mode_lines(&mut legacy).await;
    let _ = legacy.kill().await;
    assert_eq!(
        legacy_lines.len(),
        1,
        "exactly one legacy mode line: {legacy_lines:?}"
    );
    let line = &legacy_lines[0];
    assert!(line.contains(r#"mode="legacy""#), "{line}");
    assert!(line.contains("resident_cap=unbounded"), "{line}");
}

/// The guard is a connector decision handed to each pooled child explicitly;
/// the fixture records the environment it was launched with.
#[tokio::test]
async fn the_guard_reaches_each_pooled_engine_child() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    let id = account_id(1);
    let store = seed_slot(temp.path(), &id, "+15555550201");
    drop(store);

    let plan = groups::build_group_plan(&[], None, None, &temp.path().join("signal-data")).unwrap();
    let runtime = open_group_runtime_with_options(
        plan,
        fixture(),
        &temp.path().join("state"),
        None,
        Some(key()),
        false,
        Duration::from_millis(30),
        pool_options(true),
    )
    .expect("a single-account slot opens");
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 1);
    assert_eq!(status.engines[0].state, EngineState::Running);

    let probe = slot_dir(temp.path(), &id).join(".fixture-env.json");
    timeout(Duration::from_secs(10), async {
        while !probe.is_file() {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the engine wrote its env probe");
    let env: Value = serde_json::from_slice(&fs::read(&probe).unwrap()).unwrap();
    assert_eq!(
        env["KT_ENGINE_SINGLE_ACCOUNT"], "1",
        "the guard must be pinned on the child: {env}"
    );
    runtime.shutdown().await.unwrap();
}

/// The dry run is a read-only plan: layout, accounts, resident/cold split,
/// exit code, next steps — and not one byte under the signal data directory
/// changes (no lock file, no journal, no slot, no store move).
#[test]
fn migrate_pool_dry_run_writes_nothing_and_prints_the_actionable_plan() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path();
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    fs::create_dir_all(&signal_data).unwrap();
    let store = Store::open(&state_dir, Some(key())).unwrap();
    for index in 1..=2u8 {
        let id = account_id(index);
        seed_legacy_account(
            root,
            &store,
            &id,
            &format!("+155555503{index:02}"),
            &format!("lk-legacy-{index}"),
        );
    }
    drop(store);
    let before = tree_snapshot(&signal_data);

    let secret_file = root.join("bootstrap.secret");
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"))
        .arg("migrate-pool")
        .arg("--signal-data-dir")
        .arg(&signal_data)
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--dry-run")
        .env_remove("KT_SIGNAL_STORE_KEY")
        .env_remove("KT_SIGNAL_POOL_MAX_RESIDENT")
        .output()
        .expect("migrate-pool runs");
    assert!(
        output.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("migration report");
    assert_eq!(report["dryRun"], true);
    assert_eq!(report["layout"], "legacy");
    assert_eq!(report["accounts"], 2);
    assert_eq!(report["residentCap"], 8);
    assert_eq!(report["residentOnStart"], 2);
    assert_eq!(report["coldStarts"], 0);
    assert_eq!(report["expectedExitCode"], 0);
    assert_eq!(report["blockers"], json!([]));
    assert!(
        report["nextSteps"]
            .as_array()
            .is_some_and(|steps| !steps.is_empty()),
        "{report}"
    );
    assert_eq!(
        tree_snapshot(&signal_data),
        before,
        "a dry run writes nothing"
    );
    assert!(
        !signal_data.join(".kt-signal-connector.lock").exists(),
        "the dry-run occupancy probe must not create the lock file"
    );
    assert!(!signal_data.join("migration").exists(), "no journal");
    assert!(!signal_data.join("engines").exists(), "no slots");
}

/// A refuse-to-migrate state is still a plan: the dry run prints the blocker
/// and the expected exit code on stdout, and the process exits 1.
#[test]
fn a_blocked_dry_run_still_prints_the_plan_and_exits_one() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path();
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    fs::create_dir_all(&signal_data).unwrap();
    let id = account_id(1);
    let store = Store::open(&state_dir, Some(key())).unwrap();
    seed_legacy_account(root, &store, &id, "+15555550401", "lk-copy");
    // The same account's store was copied into its pool slot: two copies, a
    // mixed layout, and no way to prove which one is authoritative.
    let slot = signal_data.join("engines").join(&id);
    fs::create_dir_all(slot.join("accounts/lk-copy")).unwrap();
    fs::write(slot.join("accounts/lk-copy/store.db"), b"copied").unwrap();
    fs::write(
        slot.join("engine-state.json"),
        serde_json::to_vec(&json!({
            "version": 2,
            "accounts": [{"number": "+15555550401", "dir": "accounts/lk-copy"}],
        }))
        .unwrap(),
    )
    .unwrap();
    drop(store);

    let secret_file = root.join("bootstrap.secret");
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"))
        .arg("migrate-pool")
        .arg("--signal-data-dir")
        .arg(&signal_data)
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--dry-run")
        .env_remove("KT_SIGNAL_STORE_KEY")
        .env_remove("KT_SIGNAL_POOL_MAX_RESIDENT")
        .output()
        .expect("migrate-pool runs");
    assert_eq!(output.status.code(), Some(1), "a blocked plan exits 1");
    let report: Value = serde_json::from_slice(&output.stdout).expect("blocked plan on stdout");
    assert_eq!(report["dryRun"], true);
    assert_eq!(report["expectedExitCode"], 1);
    assert_eq!(report["layout"], "mixed");
    assert!(
        report["blockers"]
            .as_array()
            .is_some_and(|blockers| blockers.iter().any(|blocker| blocker
                .as_str()
                .is_some_and(|text| text.contains("two copies")))),
        "{report}"
    );
    // Both copies are still on disk: the refusal changed nothing.
    assert!(
        signal_data.join("accounts/lk-copy/store.db").is_file(),
        "legacy copy intact"
    );
    assert!(
        signal_data
            .join("engines")
            .join(&id)
            .join("accounts/lk-copy/store.db")
            .is_file(),
        "pool copy intact"
    );
}

/// A dry run over a `--state-dir` that does not exist yet must not create it.
///
/// This is the CLI's own promise ("without touching the filesystem"). `Store::open`
/// used to serve the dry run, and it created the state directory (mode 0700)
/// and `connector.sqlite3` beside it before the plan existed. The account set
/// now comes from a read-only probe, and an absent store is simply the empty
/// set.
#[test]
fn a_dry_run_without_a_state_dir_creates_neither_the_directory_nor_the_store() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path();
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    fs::create_dir_all(signal_data.join("accounts/lk-legacy-1")).unwrap();
    fs::write(
        signal_data.join("accounts/lk-legacy-1/store.db"),
        b"legacy-store",
    )
    .unwrap();
    fs::write(
        signal_data.join("engine-state.json"),
        serde_json::to_vec(&json!({
            "version": 2,
            "accounts": [{"number": "+15555550501", "dir": "accounts/lk-legacy-1"}],
        }))
        .unwrap(),
    )
    .unwrap();
    let before = tree_snapshot(&signal_data);

    let first = migrate_pool_dry_run(root, &signal_data, &state_dir);
    assert!(
        first.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        !state_dir.exists(),
        "the dry run must not create the state directory"
    );
    assert_eq!(
        tree_snapshot(&signal_data),
        before,
        "a dry run writes nothing"
    );

    // Running it again is the same read: no directory appears on the second
    // pass either, and the plan is byte-identical (idempotent, no side effect
    // accumulates).
    let second = migrate_pool_dry_run(root, &signal_data, &state_dir);
    assert!(second.status.success());
    assert!(!state_dir.exists(), "nor on a repeated dry run");
    assert_eq!(tree_snapshot(&signal_data), before);
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&second.stdout),
        "a repeated dry run prints the same plan"
    );

    let report: Value = serde_json::from_slice(&first.stdout).expect("migration report");
    assert_eq!(report["dryRun"], true);
    assert_eq!(report["layout"], "legacy");
    // The account set lives in the store; an absent store is the empty set, and
    // the plan says so instead of inventing rows from the layout on disk.
    assert_eq!(report["accounts"], 0);
    assert_eq!(report["expectedExitCode"], 0);
    assert_eq!(report["blockers"], json!([]));
}

/// The same dry run over an existing store reads it read-only: the state
/// directory tree (store bytes, no fresh WAL, no snapshot, no chmod) and the
/// signal data tree are byte-identical afterwards, twice over.
#[test]
fn a_dry_run_over_an_existing_store_leaves_both_trees_byte_identical() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().to_path_buf();
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    fs::create_dir_all(&signal_data).unwrap();
    let store = Store::open(&state_dir, Some(key())).unwrap();
    for index in 1..=2u8 {
        let id = account_id(index);
        seed_legacy_account(
            &root,
            &store,
            &id,
            &format!("+155555506{index:02}"),
            &format!("lk-dry-{index}"),
        );
    }
    drop(store);
    // A serving open hardens the directory to 0700; loosen it so a stray
    // `prepare_state_dir` on the dry-run path would show up as a chmod.
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let state_before = tree_snapshot(&state_dir);
    let signal_before = tree_snapshot(&signal_data);

    let first = migrate_pool_dry_run(&root, &signal_data, &state_dir);
    assert!(
        first.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        tree_snapshot(&state_dir),
        state_before,
        "the read-only probe adds no WAL/shm/snapshot and rewrites no byte of the store"
    );
    assert_eq!(tree_snapshot(&signal_data), signal_before);
    assert_eq!(
        fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
        0o755,
        "the dry run must not chmod the state directory"
    );

    let second = migrate_pool_dry_run(&root, &signal_data, &state_dir);
    assert!(second.status.success());
    assert_eq!(tree_snapshot(&state_dir), state_before);
    assert_eq!(tree_snapshot(&signal_data), signal_before);
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&second.stdout)
    );

    let report: Value = serde_json::from_slice(&first.stdout).expect("migration report");
    assert_eq!(
        report["accounts"], 2,
        "the probe reads the same rows the runtime sees"
    );
    assert_eq!(report["layout"], "legacy");
    assert_eq!(report["expectedExitCode"], 0);
    let actions: Vec<&str> = report["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|entry| entry["action"].as_str())
        .collect();
    assert_eq!(actions, vec!["wouldMigrate", "wouldMigrate"], "{report}");
}

/// A store whose last connector died with commits still in its WAL is refused,
/// not read stale: a side-effect-free read cannot replay the log, and a plan
/// that disagrees with the applied pass is worse than no plan.
#[test]
fn a_dry_run_refuses_a_store_with_an_uncheckpointed_wal() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().to_path_buf();
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    fs::create_dir_all(&signal_data).unwrap();
    let store = Store::open(&state_dir, Some(key())).unwrap();
    let id = account_id(1);
    seed_legacy_account(&root, &store, &id, "+15555550801", "lk-wal");
    drop(store);
    // What an unclean shutdown leaves behind: a WAL holding the last commits.
    let wal = state_dir.join("connector.sqlite3-wal");
    fs::write(&wal, b"pending-commits").unwrap();
    let state_before = tree_snapshot(&state_dir);
    let signal_before = tree_snapshot(&signal_data);

    let output = migrate_pool_dry_run(&root, &signal_data, &state_dir);
    assert_eq!(output.status.code(), Some(1), "the probe fails closed");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("un-checkpointed write-ahead log"),
        "the diagnostic must name the WAL: {stderr}"
    );
    assert!(
        stderr.contains("--dry-run"),
        "the diagnostic must say how to get a plan: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "no plan is printed from a stale main file"
    );
    assert_eq!(
        tree_snapshot(&state_dir),
        state_before,
        "the refusal changes nothing, the WAL included"
    );
    assert_eq!(tree_snapshot(&signal_data), signal_before);
}

/// A store written by a newer connector is refused by the dry run exactly the
/// way the applied pass refuses it: the same classified text, the same fixed
/// `KT_FATAL code=STORE_SCHEMA_NEWER ...` launcher line, exit 1 — and no next
/// step tells the operator to drop `--dry-run`, because the applied pass
/// cannot succeed against that store either. The dry run still writes nothing:
/// `schema-newer.json` is the applied refusal's record, never the plan's.
#[test]
fn a_dry_run_refuses_a_newer_store_schema_exactly_like_apply() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().to_path_buf();
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    fs::create_dir_all(&signal_data).unwrap();
    let store = Store::open(&state_dir, Some(key())).unwrap();
    seed_legacy_account(&root, &store, &account_id(1), "+15555550901", "lk-newer");
    let store_path = store.path().to_path_buf();
    drop(store);

    // What a newer connector's ladder leaves behind: a stamp above this build.
    let current = kt_signal_connector::store::SCHEMA_VERSION + 1;
    let supported = kt_signal_connector::store::SCHEMA_VERSION;
    let key_spec = format!("x'{}'", "5a".repeat(32));
    let conn = rusqlite::Connection::open(&store_path).unwrap();
    conn.execute_batch(&format!("PRAGMA key = \"{key_spec}\";"))
        .unwrap();
    conn.execute(
        "UPDATE meta SET value=?1 WHERE key='schema_version'",
        [current.to_string()],
    )
    .unwrap();
    // Fold the stamp into the main file: the probe refuses an un-checkpointed
    // WAL first, and this test is about the schema gate behind that refusal.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(conn);
    assert!(
        !state_dir.join("connector.sqlite3-wal").exists(),
        "the seeded stamp must be checkpointed before the probe reads"
    );
    let state_before = tree_snapshot(&state_dir);
    let signal_before = tree_snapshot(&signal_data);

    let dry = migrate_pool(&root, &signal_data, &state_dir, true);
    assert_eq!(
        dry.status.code(),
        Some(1),
        "the dry run refuses the newer store"
    );
    let report: Value = serde_json::from_slice(&dry.stdout).expect("blocked plan on stdout");
    assert_eq!(report["dryRun"], true);
    assert_eq!(report["expectedExitCode"], 1);
    assert_eq!(
        report["accounts"], 0,
        "no account row is read from a schema this build does not know"
    );
    assert_eq!(report["layout"], "legacy");
    let blockers: Vec<&str> = report["blockers"]
        .as_array()
        .expect("blockers")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let classified = format!(
        "connector store schema is newer than this build supports (current: {current}, supported: {supported})"
    );
    let fatal = format!(
        "KT_FATAL code=STORE_SCHEMA_NEWER retryable=false current={current} supported={supported}"
    );
    assert!(blockers.contains(&classified.as_str()), "{report}");
    assert!(blockers.contains(&fatal.as_str()), "{report}");
    let steps: Vec<&str> = report["nextSteps"]
        .as_array()
        .expect("next steps")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !steps.iter().any(|step| step.contains("without")),
        "no step may suggest applying the plan: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|step| step.contains("upgrade the connector")),
        "the only move is a newer connector: {steps:?}"
    );
    assert_eq!(
        tree_snapshot(&state_dir),
        state_before,
        "the refusal changes not one byte of the store's directory"
    );
    assert_eq!(tree_snapshot(&signal_data), signal_before);
    assert!(
        !state_dir.join("schema-newer.json").exists(),
        "a dry-run probe records no refusal marker"
    );
    assert!(!state_dir.join("connector.sqlite3-shm").exists());
    assert!(!state_dir.join("connector.sqlite3-wal").exists());

    // The applied pass refuses the same store with the same words.
    let apply = migrate_pool(&root, &signal_data, &state_dir, false);
    assert_eq!(
        apply.status.code(),
        Some(1),
        "the applied pass refuses the newer store"
    );
    let stderr = String::from_utf8(apply.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.lines().any(|line| line == fatal),
        "apply prints the same fixed launcher line: {stderr}"
    );
    assert!(
        stderr.contains(&classified),
        "apply prints the same classified text: {stderr}"
    );
    assert!(
        state_dir.join("schema-newer.json").is_file(),
        "the applied refusal is what records the marker"
    );
}

/// The guard and the legacy topology are refused at the CLI face, before a data
/// directory, an occupancy lock, a secret, or a listening endpoint is touched:
/// exit 1 with the connector's own words (contract revision 1.288, §4.274).
#[test]
fn the_single_account_guard_without_pooling_fails_the_cli_launch() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path();
    let secret_file = root.join("bootstrap.secret");
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
    let signal_data = root.join("signal-data");
    let state_dir = root.join("state");
    let endpoint = root.join("connector.sock");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"))
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--signal-data-dir")
        .arg(&signal_data)
        .arg("--state-dir")
        .arg(&state_dir)
        .env("KT_ENGINE_SINGLE_ACCOUNT", "1")
        .env_remove("KT_SIGNAL_STORE_KEY")
        .output()
        .expect("connector binary runs");
    assert_eq!(output.status.code(), Some(1), "the mismatch fails closed");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("single-account"),
        "the diagnostic must name the guard: {stderr}"
    );
    assert!(
        stderr.contains("--per-account-engines"),
        "the diagnostic must name the flag that makes it hold: {stderr}"
    );
    // Refused before any work: no data directory, no store, no socket, and
    // nothing announced on stdout for a launcher to parse.
    assert!(!signal_data.exists());
    assert!(!state_dir.exists());
    assert!(!endpoint.exists());
    assert!(output.stdout.is_empty());
}

/// One `migrate-pool` invocation against a fixed state directory; `dry_run`
/// adds the flag and changes nothing else.
fn migrate_pool(
    root: &Path,
    signal_data: &Path,
    state_dir: &Path,
    dry_run: bool,
) -> std::process::Output {
    let secret_file = root.join("bootstrap.secret");
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
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("migrate-pool")
        .arg("--signal-data-dir")
        .arg(signal_data)
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .env_remove("KT_SIGNAL_STORE_KEY")
        .env_remove("KT_SIGNAL_POOL_MAX_RESIDENT");
    if dry_run {
        command.arg("--dry-run");
    }
    command.output().expect("migrate-pool runs")
}

/// One `migrate-pool --dry-run` invocation against a fixed state directory.
fn migrate_pool_dry_run(root: &Path, signal_data: &Path, state_dir: &Path) -> std::process::Output {
    migrate_pool(root, signal_data, state_dir, true)
}
