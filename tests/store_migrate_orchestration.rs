// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! M6 phase D3 evidence: the connector-side store-migration orchestration
//! (stop the slot -> migrate with that account's derived key -> start the
//! engine), driven end to end through the real pool and a stub engine binary
//! that answers the `storeMigrate` argv mode on demand.
//!
//! Every failure shape the gate can take has a test here that fails if the
//! behaviour regresses:
//!
//! - off (the default) spawns no migrator and changes nothing;
//! - apply migrates **before** the engine is spawned, with exactly the account's
//!   HKDF derivation of the root key (never the root itself);
//! - dry-run plans only and still starts the engine whatever the plan says;
//! - exit 10 is retried within the pass, bounded, and stays retryable after;
//! - exit 11 latches a block with an actionable sentence and is never retried;
//! - exit 2 is a connector bug: no start, no latch, no retry;
//! - a timeout is not retried in the same pass;
//! - a missing data directory is not a terminal failure;
//! - every log line names the mode, a short account fingerprint and the exit -
//!   and never the key.
//!
//! `set_var` is process-global in edition 2024, so every test here holds the
//! file's environment lock for its whole body; the mode is read once at runtime
//! assembly, which is why the lock covers the open call and not just the spawn.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use kt_signal_connector::groups;
use kt_signal_connector::pool::{EnginePoolPolicy, StoreMigrationOptions, account_fingerprint};
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::service::{AccountsGetUsernameParams, ServiceError};
use kt_signal_connector::store::{Store, StoreKey, derive_engine_store_key};
use serde_json::{Value, json};
use tempfile::TempDir;

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];
const MIGRATE_ENV: &str = "KT_ENGINE_STORE_MIGRATE";
const BUDGET_ENV: &str = "KT_ENGINE_STORE_MIGRATE_BUDGET_MS";

/// One migration switch per process at a time: the env is global, so the tests
/// that set it take this lock for their whole body.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn account_id() -> String {
    "0123456789abcdef0123456789abcdef".to_string()
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

/// The stub engine: forwards every `jsonRpc` launch to the repository's fake
/// engine (so the pool's handshake is the real one) and answers the
/// `storeMigrate` argv mode from a per-test sequence file. It records every
/// invocation before doing anything else, which is what makes "the migrator ran
/// before the engine" checkable.
fn write_stub(dir: &Path) -> PathBuf {
    let path = dir.join("stub-engine.py");
    let script = r#"#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path

argv = sys.argv[1:]
log_path = Path(os.environ["TEST_STUB_LOG"])
state_dir = Path(os.environ["TEST_STUB_DIR"])
state_dir.mkdir(parents=True, exist_ok=True)


def value_of(flag):
    for index, arg in enumerate(argv):
        if arg == flag and index + 1 < len(argv):
            return argv[index + 1]
    return ""


migrate = "storeMigrate" in argv
key = os.environ.get("KT_SIGNAL_STORE_KEY")
with log_path.open("a") as handle:
    handle.write(json.dumps({
        "mode": "migrate" if migrate else "jsonrpc",
        "argv": argv,
        "dataDir": value_of("--data-dir"),
        "hasKey": key is not None,
        "pid": os.getpid(),
    }) + "\n")

if not migrate:
    os.execv(sys.executable, [sys.executable, os.environ["TEST_FAKE_ENGINE"], *argv])

# Only a migration run observes the key; the capture file exists so the test can
# compare it against the derivation it expects, and it never enters a log line.
with (state_dir / "last-key").open("w") as handle:
    handle.write(key or "")

sequence_path = state_dir / "sequence.json"
count_path = state_dir / "count"
sequence = json.loads(sequence_path.read_text()) if sequence_path.exists() else {}
exits = sequence.get("exits") or [0]
sleep_ms = int(sequence.get("sleepMs") or 0)
count = int(count_path.read_text()) if count_path.exists() else 0
count_path.write_text(str(count + 1))
exit_code = exits[min(count, len(exits) - 1)]
if sleep_ms:
    time.sleep(sleep_ms / 1000.0)
dry = "--dry-run" in argv
code = sequence.get("code") or ("store_migration_planned" if dry else ("store_migrated" if exit_code == 0 else "store_busy"))
print(json.dumps({
    "ok": exit_code == 0,
    "dryRun": dry,
    "freeBytes": 1,
    "needBytes": 1,
    "accounts": [{
        "lk": "lk-0123456789abcdef",
        "action": "dry-run" if dry else ("migrate" if exit_code == 0 else "failed"),
        "code": code,
        "bytes": 1,
        "elapsedMs": 1,
        "keyid": "0123456789abcdef",
        "backup": None,
        "checks": [],
    }],
    "plan": ["checkpoint", "backup", "export", "verify", "swap"],
    "did": [],
}))
sys.exit(exit_code)
"#;
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// One provisioned account: the store row, its own engine data directory, a
/// single-account engine registry, and a placeholder store file.
fn seed_account(temp: &TempDir, id: &str, number: &str) {
    let store = Store::open(&temp.path().join("state"), Some(key())).unwrap();
    store
        .upsert_account_from_signal_with_id(number, Some(1), "default", Some(id))
        .unwrap();
    let data_dir = temp.path().join("signal-data").join("engines").join(id);
    let relative = format!("accounts/lk-{}", &id[..16]);
    std::fs::create_dir_all(data_dir.join(&relative)).unwrap();
    std::fs::write(
        data_dir.join(&relative).join("store.db"),
        b"plaintext-store-bytes",
    )
    .unwrap();
    std::fs::write(
        data_dir.join("engine-state.json"),
        serde_json::to_vec(&json!({
            "version": 2,
            "accounts": [{"number": number, "dir": relative}],
        }))
        .unwrap(),
    )
    .unwrap();
}

struct Harness {
    temp: TempDir,
    stub: PathBuf,
    account: String,
}

impl Harness {
    fn new(sequence: Value) -> Self {
        let temp = TempDir::new().unwrap();
        let stub = write_stub(temp.path());
        std::fs::write(
            temp.path().join("sequence.json"),
            serde_json::to_vec(&sequence).unwrap(),
        )
        .unwrap();
        let account = account_id();
        seed_account(&temp, &account, "+15555550100");
        // The stub reads these from its (inherited) environment.
        unsafe {
            std::env::set_var("TEST_STUB_LOG", temp.path().join("calls.log"));
            std::env::set_var("TEST_STUB_DIR", temp.path());
            std::env::set_var("TEST_FAKE_ENGINE", fixture());
        }
        Self {
            temp,
            stub,
            account,
        }
    }

    fn data_dir(&self) -> PathBuf {
        self.temp
            .path()
            .join("signal-data")
            .join("engines")
            .join(&self.account)
    }

    fn store_bytes(&self) -> Vec<u8> {
        std::fs::read(
            self.data_dir()
                .join(format!("accounts/lk-{}", &self.account[..16]))
                .join("store.db"),
        )
        .unwrap()
    }

    async fn open(&self, mode: &str, budget_ms: Option<u64>) -> Arc<ProxyGroupRuntime> {
        self.open_with(mode, budget_ms, Some(Duration::from_millis(50)))
            .await
    }

    /// `open` with an explicit watchdog cadence. The default test watchdog is
    /// fast (50 ms), which is right for the pass-level cases but restarts a
    /// deliberately stopped engine within a tick; a case that stops and starts
    /// on purpose asks for a quiet watchdog instead of racing it.
    async fn open_with(
        &self,
        mode: &str,
        budget_ms: Option<u64>,
        watchdog: Option<Duration>,
    ) -> Arc<ProxyGroupRuntime> {
        unsafe { std::env::set_var(MIGRATE_ENV, mode) };
        match budget_ms {
            Some(ms) => unsafe { std::env::set_var(BUDGET_ENV, ms.to_string()) },
            None => unsafe { std::env::remove_var(BUDGET_ENV) },
        }
        let signal_data = self.temp.path().join("signal-data");
        let plan = groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let runtime = open_group_runtime_with_options(
            plan,
            self.stub.clone(),
            &self.temp.path().join("state"),
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
                    ..EnginePoolPolicy::default()
                },
                watchdog_interval: watchdog,
            },
        )
        .expect("runtime assembles");
        unsafe { std::env::remove_var(MIGRATE_ENV) };
        unsafe { std::env::remove_var(BUDGET_ENV) };
        runtime
    }

    fn calls(&self) -> Vec<Value> {
        let Ok(text) = std::fs::read_to_string(self.temp.path().join("calls.log")) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|call| {
                call.get("dataDir")
                    .and_then(Value::as_str)
                    .is_some_and(|dir| dir.ends_with(self.account.as_str()))
            })
            .collect()
    }

    fn migrate_calls(&self) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|call| call.get("mode").and_then(Value::as_str) == Some("migrate"))
            .collect()
    }

    fn engine_calls(&self) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|call| call.get("mode").and_then(Value::as_str) == Some("jsonrpc"))
            .collect()
    }

    fn last_key(&self) -> String {
        std::fs::read_to_string(self.temp.path().join("last-key")).unwrap_or_default()
    }

    fn pool(
        &self,
        runtime: &Arc<ProxyGroupRuntime>,
    ) -> Arc<kt_signal_connector::pool::AccountPool> {
        Arc::clone(runtime.account_pool().expect("per-account pool"))
    }

    /// A second handle on the connector's own store, for the assertions that
    /// have to outlive the runtime's view (a deleted account row).
    fn store(&self) -> Store {
        Store::open(&self.temp.path().join("state"), Some(key())).unwrap()
    }

    /// The live engine process of this account, if it has one.
    async fn engine_pid(&self, runtime: &Arc<ProxyGroupRuntime>) -> Option<u32> {
        self.pool(runtime)
            .statuses()
            .await
            .into_iter()
            .find(|status| status.account_id == self.account)
            .and_then(|status| status.pid)
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Capture the connector's own log lines for the whole binary. Installed once,
/// on the first test that needs it; every later line lands in the same buffer.
fn captured_logs() -> Arc<Mutex<Vec<u8>>> {
    static CAPTURE: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let capture = Capture::default();
            let buffer = Arc::clone(&capture.0);
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_ansi(false)
                .with_writer(capture)
                .try_init();
            buffer
        })
        .clone()
}

#[tokio::test]
async fn unset_switch_is_off_and_an_unrecognised_value_stays_off() {
    let _guard = ENV_LOCK.lock().await;
    unsafe { std::env::remove_var(MIGRATE_ENV) };
    assert_eq!(
        StoreMigrationOptions::from_env().mode,
        kt_signal_connector::pool::StoreMigrationMode::Off
    );
    unsafe { std::env::set_var(MIGRATE_ENV, "yes please") };
    assert_eq!(
        StoreMigrationOptions::from_env().mode,
        kt_signal_connector::pool::StoreMigrationMode::Off,
        "a typo must not arm a migration pass"
    );
    unsafe { std::env::remove_var(MIGRATE_ENV) };
}

#[tokio::test]
async fn off_mode_spawns_no_migrator_and_starts_the_engine() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [0]}));
    let runtime = harness.open("off", None).await;
    let _ = runtime.start().await;
    assert!(
        harness.migrate_calls().is_empty(),
        "off must not spawn the migrator at all: {:?}",
        harness.migrate_calls()
    );
    assert_eq!(harness.engine_calls().len(), 1, "the engine still starts");
    assert!(
        harness
            .pool(&runtime)
            .migration_block(&harness.account)
            .is_none()
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn apply_mode_migrates_before_the_engine_and_hands_over_the_derived_key() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [0]}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;

    let calls = harness.calls();
    assert_eq!(calls.len(), 2, "one migration, one engine: {calls:?}");
    assert_eq!(
        calls[0]["mode"], "migrate",
        "stop -> migrate -> start: {calls:?}"
    );
    assert_eq!(
        calls[1]["mode"], "jsonrpc",
        "the engine starts only after the migration: {calls:?}"
    );

    let migrate = harness.migrate_calls();
    let argv: Vec<&str> = migrate[0]["argv"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(argv.contains(&"storeMigrate"), "{argv:?}");
    assert!(argv.contains(&"--json"), "{argv:?}");
    assert!(!argv.contains(&"--dry-run"), "{argv:?}");
    assert_eq!(migrate[0]["hasKey"], true, "the migrator needs the key");

    // K1: the key that encrypts is the key that opens - exactly the account's
    // HKDF derivation of the connector root, never the root itself.
    let expected = derive_engine_store_key(&key(), &harness.account);
    assert_eq!(harness.last_key(), expected.to_hex().as_str());
    assert_ne!(
        harness.last_key(),
        key().to_hex().as_str(),
        "the root key must never reach a child"
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn dry_run_only_plans_and_still_starts_the_engine() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [0]}));
    let before = harness.store_bytes();
    let runtime = harness.open("dry-run", None).await;
    let _ = runtime.start().await;

    let migrate = harness.migrate_calls();
    assert_eq!(migrate.len(), 1, "{migrate:?}");
    let argv: Vec<&str> = migrate[0]["argv"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(argv.contains(&"--dry-run"), "{argv:?}");
    assert_eq!(harness.store_bytes(), before, "a dry run writes no byte");
    assert_eq!(
        harness.engine_calls().len(),
        1,
        "dry-run never withholds a start"
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn a_retryable_exit_ten_is_retried_within_the_pass_and_then_succeeds() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [10, 10, 0]}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;
    assert_eq!(
        harness.migrate_calls().len(),
        3,
        "two retries, then success"
    );
    assert_eq!(
        harness.engine_calls().len(),
        1,
        "success unblocks the start"
    );
    assert!(
        harness
            .pool(&runtime)
            .migration_block(&harness.account)
            .is_none()
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn an_exhausted_retryable_failure_stays_retryable_and_never_starts_the_engine() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [10], "code": "store_busy"}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;
    assert_eq!(
        harness.migrate_calls().len(),
        3,
        "exit 10 is bounded, not a spin"
    );
    assert!(
        harness.engine_calls().is_empty(),
        "the engine must not open a store the migrator did not finish"
    );
    assert!(
        harness
            .pool(&runtime)
            .migration_block(&harness.account)
            .is_none(),
        "exit 10 is not terminal: the next start must retry"
    );
    let _ = runtime.start().await;
    assert_eq!(
        harness.migrate_calls().len(),
        6,
        "the next start retries the migration"
    );
}

#[tokio::test]
async fn a_terminal_exit_eleven_latches_a_block_and_is_never_retried() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [11], "code": "store_key_rejected"}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;

    assert_eq!(
        harness.migrate_calls().len(),
        1,
        "exit 11 is terminal: one attempt, no retry"
    );
    assert!(
        harness.engine_calls().is_empty(),
        "a blocked slot never starts"
    );

    let pool = harness.pool(&runtime);
    let block = pool
        .migration_block(&harness.account)
        .expect("exit 11 latches a block");
    assert_eq!(block.code, "store_key_rejected");
    assert_eq!(block.exit, Some(11));
    assert!(
        block.message.contains("Re-link the account"),
        "the message has to tell a human what to do: {}",
        block.message
    );

    // No restart storm: the second start answers from the latch without
    // spawning anything.
    let _ = runtime.start().await;
    assert_eq!(harness.migrate_calls().len(), 1, "latched, not retried");

    // A wake answers the host with the same actionable sentence, not retryably.
    let slot = pool.get(&harness.account).expect("slot");
    match pool.ensure_resident(&slot).await {
        Err(ServiceError::Api(error)) => {
            assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
            assert!(!error.retryable, "exit 11 will not resolve by retrying");
            assert!(error.message.contains("Re-link the account"), "{error:?}");
        }
        other => panic!("a blocked slot must answer an actionable error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_usage_error_exit_two_is_a_connector_bug_not_a_blocked_account() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [2]}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;
    assert_eq!(harness.migrate_calls().len(), 1, "no retry within the pass");
    assert!(
        harness.engine_calls().is_empty(),
        "do not run a half-configured slot"
    );
    assert!(
        harness
            .pool(&runtime)
            .migration_block(&harness.account)
            .is_none(),
        "an integration bug must not latch an account as broken"
    );
    let _ = runtime.start().await;
    assert_eq!(
        harness.migrate_calls().len(),
        2,
        "the next start tries again, so fixing the bug is enough"
    );

    // D3 review M5: the host-facing sentence is the human one - what exit 2
    // actually means (mixed versions, or an engine build without the mode), with
    // no stray formatting - and it never offers the data remedy, because the
    // data is fine.
    let pool = harness.pool(&runtime);
    let slot = pool.get(&harness.account).expect("slot");
    match pool.ensure_resident(&slot).await {
        Err(ServiceError::Api(error)) => {
            assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
            assert!(
                !error.retryable,
                "a version skew will not resolve by retrying"
            );
            assert!(error.message.contains("storeMigrate"), "{}", error.message);
            assert!(
                error.message.contains("different versions"),
                "{}",
                error.message
            );
            assert!(
                !error.message.contains("Re-link"),
                "the account's data is not the problem: {}",
                error.message
            );
            assert!(
                !error.message.contains("  "),
                "no run of spaces: {}",
                error.message
            );
        }
        other => panic!("exit 2 must answer an API error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_timeout_is_not_retried_within_the_same_pass() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [0], "sleepMs": 20000}));
    let runtime = harness.open("apply", Some(1500)).await;
    let _ = runtime.start().await;
    assert_eq!(
        harness.migrate_calls().len(),
        1,
        "retrying a wedged copy would stretch startup to attempts x budget"
    );
    assert!(
        harness.engine_calls().is_empty(),
        "a timed-out migration withholds the start"
    );
    assert!(
        harness
            .pool(&runtime)
            .migration_block(&harness.account)
            .is_none()
    );
}

#[tokio::test]
async fn a_missing_data_directory_is_not_a_terminal_failure() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [11], "code": "store_migrate_data_dir_missing"}));
    let runtime = harness.open("apply", None).await;
    // The slot is discovered, then its directory disappears (unprovisioned or
    // unmounted): the engine creates its own store, so this must not block.
    std::fs::remove_dir_all(harness.data_dir()).unwrap();
    let _ = runtime.start().await;
    assert!(
        harness.migrate_calls().is_empty(),
        "nothing to migrate: no migrator, no terminal data_dir_missing"
    );
    assert_eq!(
        harness.engine_calls().len(),
        1,
        "the engine starts and creates its store"
    );
    assert!(
        harness
            .pool(&runtime)
            .migration_block(&harness.account)
            .is_none()
    );
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn migration_logs_name_the_mode_the_fingerprint_and_the_exit_but_never_the_key() {
    let _guard = ENV_LOCK.lock().await;
    let logs = captured_logs();
    let harness = Harness::new(json!({"exits": [0]}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;
    runtime.stop().await.unwrap();

    // A terminal failure must obey the same discipline: the blocked line names
    // the mode, the fingerprint and the exit, and the actionable sentence still
    // carries no key material.
    let blocked = Harness::new(json!({"exits": [11], "code": "store_corrupt"}));
    let blocked_runtime = blocked.open("apply", None).await;
    let _ = blocked_runtime.start().await;

    let text = String::from_utf8_lossy(&logs.lock().unwrap()).to_string();
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("store_migration"))
        .collect();
    assert!(!lines.is_empty(), "the gate has to say something: {text}");
    let fingerprint = account_fingerprint(&harness.account);
    for line in &lines {
        assert!(
            !line.contains(&harness.account),
            "a log line carries the short fingerprint, not the account id: {line}"
        );
        assert!(line.contains(&fingerprint), "{line}");
        assert!(
            !line
                .split(|c: char| !c.is_ascii_hexdigit())
                .any(|run| run.len() >= 64),
            "no key material in a log line: {line}"
        );
    }
    // The key and its derivation never appear anywhere in the connector's log.
    assert!(
        !text.contains(
            derive_engine_store_key(&key(), &harness.account)
                .to_hex()
                .as_str()
        )
    );
    assert!(!text.contains(key().to_hex().as_str()));
    assert!(lines.iter().any(|line| line.contains("apply")), "{lines:?}");

    // D3 review M5: one slot refused three times emits the exit-2 line **once**.
    // A start storm must not turn one connector/engine version skew into one
    // error a second - that is how the fact gets ignored.
    let skewed = Harness::new(json!({"exits": [2]}));
    let skewed_runtime = skewed.open("apply", None).await;
    for _ in 0..3 {
        let _ = skewed_runtime.start().await;
    }
    assert_eq!(
        skewed.migrate_calls().len(),
        3,
        "every start still tries (exit 2 never latches)"
    );
    let text = String::from_utf8_lossy(&logs.lock().unwrap()).to_string();
    let refused: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("does not understand the storeMigrate mode"))
        .collect();
    assert_eq!(refused.len(), 1, "throttled to one line: {refused:?}");
    assert!(refused[0].contains("mixed"), "{refused:?}");
    assert!(!refused[0].contains("  "), "no run of spaces: {refused:?}");
}

// ———————————————— D3 review fixes: M1 / M2 / M4 / M6 ————————————————

/// M1: a slot whose engine is already live must **not** be stopped-and-migrated
/// by a second runtime.start. A live engine is success (the same reading
/// ensure_resident applies), the engine keeps its process — so nothing
/// in-flight can be cut — and no second migrator runs.
#[tokio::test]
async fn a_second_start_leaves_the_live_engine_alone() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [0]}));
    // Dry-run on purpose: it never sets the "already migrated" marker, so this
    // case isolates M1 (a live engine is not restarted) from M4 (a migrated
    // store is not re-verified). With apply, M4's marker would mask a missing
    // M1 guard.
    let runtime = harness.open("dry-run", None).await;
    runtime
        .start()
        .await
        .expect("the first start migrates and starts the engine");
    let pid = harness.engine_pid(&runtime).await.expect("engine is live");
    assert_eq!(harness.migrate_calls().len(), 1);
    assert_eq!(harness.engine_calls().len(), 1);

    // A real account request runs concurrently with the repeated starts: an
    // engine that is never stopped cannot cut it.
    let params = AccountsGetUsernameParams {
        account_id: harness.account.clone(),
    };
    let (first, second, request) = tokio::join!(
        runtime.start(),
        runtime.start(),
        runtime.get_username(params),
    );
    assert!(first.is_ok(), "a repeated start is not an error");
    assert!(second.is_ok(), "a repeated start is not an error");
    assert!(request.is_ok(), "the in-flight request survived");

    assert_eq!(
        harness.migrate_calls().len(),
        1,
        "a live engine is not a reason to migrate"
    );
    assert_eq!(
        harness.engine_calls().len(),
        1,
        "the engine was not restarted"
    );
    assert_eq!(
        harness.engine_pid(&runtime).await,
        Some(pid),
        "same process: it was never stopped"
    );
    runtime.stop().await.unwrap();
}

/// M4: a store this process has already migrated is not migrated (and, above
/// all, not whole-store-verified) again on a later start.
#[tokio::test]
async fn a_migrated_slot_skips_the_second_migration_run() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [0]}));
    // A quiet watchdog: this case stops the engine on purpose and a 50 ms
    // watchdog would restart it underneath the second start.
    let runtime = harness
        .open_with("apply", None, Some(Duration::from_secs(3600)))
        .await;
    runtime.start().await.expect("the first start migrates");
    assert_eq!(harness.migrate_calls().len(), 1);
    runtime.stop().await.unwrap();

    runtime.start().await.expect("the second start runs");
    assert_eq!(
        harness.migrate_calls().len(),
        1,
        "an already-migrated store is not verified a second time in this process"
    );
    assert_eq!(
        harness.engine_calls().len(),
        2,
        "the engine still starts again after a stop: {:?}",
        harness.calls()
    );
    runtime.stop().await.unwrap();
}

/// M2: the migration gate may refuse this slot an engine; it must not refuse
/// the delete that its own block message prescribes.
#[tokio::test]
async fn a_latched_slot_still_deletes_its_local_data_and_frees_the_slot() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [11], "code": "store_key_rejected"}));
    let runtime = harness.open("apply", None).await;
    // A pool whose every slot is refused answers RUNTIME_START_FAILED (there is
    // no live engine to report); the runtime is still up, which is what the
    // delete path below depends on.
    let _ = runtime.start().await;
    let pool = harness.pool(&runtime);
    assert!(
        pool.migration_block(&harness.account).is_some(),
        "exit 11 latches"
    );

    let result = runtime
        .delete_local_account(harness.account.clone(), None)
        .await
        .expect("a latched account must still be deletable");
    assert!(
        result.get("deleted").is_some(),
        "a recorded receipt, not an empty answer: {result}"
    );
    assert!(
        result["deleted"]["rowsDeleted"].as_u64().unwrap_or(0) > 0,
        "the rows this account owned were counted and removed: {result}"
    );

    assert!(
        harness
            .store()
            .account_by_id(&harness.account)
            .unwrap()
            .is_none(),
        "the account rows are gone"
    );
    assert!(
        pool.get(&harness.account).is_none(),
        "the slot is reclaimed"
    );
    assert!(
        pool.migration_block(&harness.account).is_none(),
        "the latch went with the slot"
    );
    assert!(
        !harness.data_dir().exists(),
        "the slot directory is removed"
    );
}

/// M6 D3 follow-up (task-16 item 1): the engine-free delete is a second door
/// into the same destructive face, and it opens with the same bound. A
/// malformed operationId is a caller bug — the engine path refuses it before
/// the idempotency ledger sees it (`RuntimeSupervisor::delete_local_account`),
/// and the branch that answers around a refused engine must not launder it
/// into a completed delete.
#[tokio::test]
async fn a_malformed_operation_id_is_refused_on_the_engine_free_path() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [11], "code": "store_key_rejected"}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;
    let pool = harness.pool(&runtime);
    assert!(
        pool.migration_block(&harness.account).is_some(),
        "exit 11 latches, so the delete below takes the engine-free path"
    );

    let too_long = "x".repeat(kt_signal_connector::service::MAX_OPAQUE_ID_BYTES + 1);
    let error = runtime
        .delete_local_account(harness.account.clone(), Some(too_long))
        .await
        .expect_err("a malformed operationId must be refused");
    match error {
        ServiceError::Api(api) => {
            assert_eq!(api.code, "INVALID_REQUEST", "{api:?}");
            assert!(
                api.message.contains("operationId"),
                "the refusal names the field: {}",
                api.message
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    // Nothing moved: a refused delete is not a partial one.
    assert!(
        harness
            .store()
            .account_by_id(&harness.account)
            .unwrap()
            .is_some(),
        "the account rows must survive the refusal"
    );
    assert!(
        pool.get(&harness.account).is_some(),
        "the slot must survive the refusal"
    );
    assert!(
        harness.data_dir().exists(),
        "the engine data directory must survive the refusal"
    );

    // The same delete with a well-formed (absent) operationId still lands, so
    // the refusal is about the id, not about the path.
    runtime
        .delete_local_account(harness.account.clone(), None)
        .await
        .expect("the engine-free delete still answers");
    assert!(
        harness
            .store()
            .account_by_id(&harness.account)
            .unwrap()
            .is_none(),
        "a well-formed delete still removes the rows"
    );
}

/// M6 D3 follow-up (task-16 item 2): §4.115 plaintext export products live in
/// the connector's own `state-dir`, so `pool.discard` cannot take them with
/// the slot directory. The engine path clears them through its supervisor's
/// `clear_account_delete_files`; the engine-free path has no supervisor and
/// must clear them itself — an export product never outlives its account.
#[tokio::test]
async fn an_engine_free_delete_leaves_no_plaintext_export_artifacts() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [11], "code": "store_key_rejected"}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;
    let pool = harness.pool(&runtime);
    assert!(
        pool.migration_block(&harness.account).is_some(),
        "exit 11 latches, so the delete below takes the engine-free path"
    );

    // An export product of this account, exactly where the §4.115 builder puts
    // it (the state dir, never the engine tree).
    let root = kt_signal_connector::backup_export::plaintext_export_root(
        harness.store().state_dir(),
        &harness.account,
    );
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("plaintext-export-2026-01-01-00-00-00.jsonl"),
        b"{\"kind\":\"message\"}\n",
    )
    .unwrap();
    // A second account's export proves the cleanup is account-scoped.
    let bystander = "fedcba9876543210fedcba9876543210".to_string();
    let bystander_root = kt_signal_connector::backup_export::plaintext_export_root(
        harness.store().state_dir(),
        &bystander,
    );
    std::fs::create_dir_all(&bystander_root).unwrap();
    std::fs::write(
        bystander_root.join("plaintext-export-2026-01-01-00-00-00.jsonl"),
        b"{\"kind\":\"message\"}\n",
    )
    .unwrap();

    runtime
        .delete_local_account(harness.account.clone(), None)
        .await
        .expect("the engine-free delete answers");

    assert!(
        !root.exists(),
        "the deleted account's plaintext export products must not survive it"
    );
    assert!(
        bystander_root.exists(),
        "another account's export products are untouched"
    );
    assert!(
        !harness.data_dir().exists(),
        "the slot directory is still removed wholesale"
    );
}

/// M6: an engine build without the store cipher is a deployment problem. Its
/// block message must say so, and must not offer the re-link remedy that would
/// destroy a store a correct build opens as it is.
#[tokio::test]
async fn a_cipherless_engine_build_gets_the_deployment_remedy() {
    let _guard = ENV_LOCK.lock().await;
    let harness = Harness::new(json!({"exits": [11], "code": "StoreCipherUnavailable"}));
    let runtime = harness.open("apply", None).await;
    let _ = runtime.start().await;

    let block = harness
        .pool(&runtime)
        .migration_block(&harness.account)
        .expect("exit 11 latches");
    assert_eq!(block.code, "StoreCipherUnavailable");
    assert!(
        block.message.contains("deployment problem"),
        "{}",
        block.message
    );
    assert!(
        block.message.contains("Do not delete or re-link"),
        "{}",
        block.message
    );
    assert!(
        !block.message.contains("Re-link the account"),
        "the data remedy is wrong for this code: {}",
        block.message
    );
}

/// M3: the plan must not tell an operator that a retryable failure leaves the
/// "old path" usable — it stops the slot for the round, and the remedy is the
/// switch or a restart.
#[test]
fn the_plan_says_what_a_retryable_migration_really_does() {
    let plan = include_str!("../docs/implementation-plan.md");
    let section = plan
        .split("## §4.276")
        .nth(1)
        .expect("the D3 section is in the plan");
    assert!(
        !section.contains("引擎可用的旧路径"),
        "the old-path claim is exactly what D3 review M3 corrected"
    );
    assert!(
        section.contains("该槽当轮停服"),
        "a retryable failure stops this slot for the round"
    );
    assert!(
        section.contains("关掉（off）"),
        "the operator remedy names the switch"
    );
    assert!(
        section.contains("重启连接器"),
        "and the restart that also restores the plaintext path"
    );
    assert!(
        section.contains("锁存槽的删除出口"),
        "the engine-free delete is documented"
    );
    assert!(
        section.contains("StoreCipherUnavailable"),
        "the deployment-only code is documented separately"
    );
}
