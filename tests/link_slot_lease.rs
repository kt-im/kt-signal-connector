// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! BUG-1 regression suite (docs/plan/signal-known-issues.md): a preallocated
//! `link.start` slot is owned by its link attempt, so every terminal answer —
//! a definite finish failure, a cancellation, or a finish timeout — must run
//! the same idempotent reclaim and leave **zero orphan slots** behind. The
//! startup quarantine scan stays as the crash backstop; these tests drive the
//! live process and assert the slot, its engine process and its data
//! directory are all gone (or, for a committed link, that reclaim refuses to
//! delete it).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::groups;
use kt_signal_connector::pool::{EnginePoolPolicy, LinkReclaimOutcome};
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::store::StoreKey;
use serde_json::Value;
use tempfile::TempDir;
use tokio::time::sleep;

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

/// One link flow at a time: every test starts a real engine process, and the
/// fake engine's fixture delay is measured in process starts, not CPU.
static LINK_LEASE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn open_pool(temp: &TempDir) -> Arc<ProxyGroupRuntime> {
    open_pool_with_list_budget(temp, Duration::from_secs(3))
}

/// Same runtime assembly with an explicit `listAccounts` budget: the
/// post-commit probe reuses the pool policy's bound (one knob for every
/// engine account list the connector issues), so the probe-timeout case can
/// shrink it instead of waiting out the production budget.
fn open_pool_with_list_budget(temp: &TempDir, list_budget: Duration) -> Arc<ProxyGroupRuntime> {
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    let plan = groups::build_group_plan(&[], None, None, &signal_data).unwrap();
    open_group_runtime_with_options(
        plan,
        fixture(),
        &temp.path().join("state"),
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
                list_accounts_budget: list_budget,
                demote_idle_after: Duration::from_secs(60),
            },
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    )
    .unwrap()
}

/// How many `listAccounts` requests this slot's engine actually received.
/// The fixture appends one line per request beside the slot (the slot's own
/// data directory does not survive a reclaim). The reclaim probe is one of
/// them; an assertion of "at least one" proves the soften path asked the
/// engine instead of tearing the slot down blindly.
fn list_account_calls(temp: &TempDir, account: &str) -> usize {
    let path = temp
        .path()
        .join("signal-data")
        .join("engines")
        .join(format!(".fixture-list-accounts-calls-{account}"));
    fs::read_to_string(path)
        .map(|text| text.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or(0)
}

/// Restores an env var the fake engine reads at spawn time, even when the
/// assertion below panics. The fixture tests are serialized by the file lock,
/// so a scoped set/remove pair cannot leak into a sibling case.
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

fn data_dir(temp: &TempDir, account: &str) -> PathBuf {
    temp.path()
        .join("signal-data")
        .join("engines")
        .join(account)
}

/// Every directory the pool would adopt as an account slot: exactly the
/// 32-lowercase-hex names. Quarantine entries (`.quarantine-*`) are not slots.
fn live_slot_dirs(temp: &TempDir) -> Vec<PathBuf> {
    let root = temp.path().join("signal-data").join("engines");
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 32
                && name
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect()
}

fn has_quarantine(temp: &TempDir) -> bool {
    let root = temp.path().join("signal-data").join("engines");
    fs::read_dir(root).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".quarantine-")
        })
    })
}

/// Live processes whose argv names this engine directory (the fake engine's
/// argv carries `--data-dir <path>`). Zero is the post-reclaim invariant.
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

/// Wait until the fake engine's executable is truly gone after `discard`
/// (shutdown is bounded but asynchronous at the OS level).
async fn wait_for_no_engine_process(data_dir: &Path) {
    for _ in 0..100 {
        if engine_processes(data_dir) == 0 {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        engine_processes(data_dir),
        0,
        "the reclaimed slot must not keep an engine process alive"
    );
}

fn only_engine(status: &Value) -> String {
    status["engines"][0]["accountId"]
        .as_str()
        .unwrap_or_else(|| panic!("the fresh slot is listed: {status}"))
        .to_string()
}

fn engines_count(status: &Value) -> usize {
    status["engines"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default()
}

async fn status_value(runtime: &ProxyGroupRuntime) -> Value {
    serde_json::to_value(runtime.status().await).unwrap()
}

async fn start_link(runtime: &Arc<ProxyGroupRuntime>, device: &str) -> (String, String, String) {
    let link = runtime
        .start_link(device.to_string(), Some("default".into()))
        .await
        .expect("link.start provisions a slot");
    let attempt = link["linkAttemptId"]
        .as_str()
        .expect("link.start states its attempt id")
        .to_string();
    let session = link["linkSessionId"]
        .as_str()
        .expect("link.start states its session id")
        .to_string();
    let status = status_value(runtime).await;
    assert_eq!(
        engines_count(&status),
        1,
        "one live QR owns exactly one slot: {status}"
    );
    (attempt, session, only_engine(&status))
}

/// The shared post-condition for all three terminal paths: no live slot, no
/// account-id directory, no engine process, no open lease, and a replay of the
/// reclaim is a quiet no-op.
async fn assert_zero_orphan_slot(
    runtime: &Arc<ProxyGroupRuntime>,
    temp: &TempDir,
    attempt: &str,
    account: &str,
) {
    let status = status_value(runtime).await;
    assert_eq!(engines_count(&status), 0, "{status}");
    assert!(
        live_slot_dirs(temp).is_empty(),
        "the reclaimed slot's directory must not stay in the live namespace"
    );
    let dir = data_dir(temp, account);
    assert!(!dir.exists(), "{} must be gone", dir.display());
    wait_for_no_engine_process(&dir).await;
    let pool = runtime.account_pool().expect("full pooling");
    assert!(pool.get(account).is_none(), "the slot left the pool table");
    assert_eq!(
        pool.open_link_leases(),
        0,
        "no uncommitted lease may survive a terminal answer"
    );
    // Idempotent replay: the same attempt id answers AlreadySettled, never an
    // error and never a second deletion.
    assert_eq!(
        pool.reclaim_link_attempt(attempt).await,
        LinkReclaimOutcome::AlreadySettled
    );
    assert!(
        live_slot_dirs(temp).is_empty(),
        "the replay must not recreate or misreport a slot"
    );
}

/// Path 1 — a definite finish failure. The engine answers LINK_LOST: the
/// attempt can never commit, so its slot is reclaimed in the same call.
#[tokio::test]
async fn a_failed_link_finish_reclaims_the_leased_slot() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _env = EnvGuard::set("KT_FAKE_FINISH_LINK_LOST", "1");
    let runtime = open_pool(&temp);
    runtime.start().await.expect("an empty pool starts");
    let (attempt, session, account) = start_link(&runtime, "lease-failure-device").await;

    let error = runtime
        .finish_link(session)
        .await
        .expect_err("the engine's definite LINK_LOST fails the finish");
    assert_eq!(error.into_api().code, "LINK_LOST");

    assert_zero_orphan_slot(&runtime, &temp, &attempt, &account).await;
    assert!(
        !has_quarantine(&temp),
        "an uncommitted slot holds no credentials: it is deleted, not quarantined"
    );
    runtime.shutdown().await.unwrap();
}

/// Path 2 — `link.cancel`. The QR never gets scanned; the cancel is the
/// terminal answer that must take the slot with it.
#[tokio::test]
async fn a_cancelled_link_reclaims_the_leased_slot() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let runtime = open_pool(&temp);
    runtime.start().await.expect("an empty pool starts");
    let (attempt, session, account) = start_link(&runtime, "lease-cancel-device").await;

    runtime
        .cancel_link(session)
        .await
        .expect("link.cancel answers without waiting for phone approval");

    assert_zero_orphan_slot(&runtime, &temp, &attempt, &account).await;
    assert!(
        !has_quarantine(&temp),
        "a cancelled pre-credential slot is deleted, not quarantined"
    );
    runtime.shutdown().await.unwrap();
}

/// Path 3 — a finish timeout. The engine's own dispatch budget expires on the
/// mutating call: the answer is the link-class unknown outcome, and the slot
/// must not be left behind for a retry that can never adopt it.
#[tokio::test]
async fn a_link_finish_timeout_reclaims_the_leased_slot() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _env = EnvGuard::set("KT_FAKE_FINISH_ENGINE_TIMEOUT", "1");
    let runtime = open_pool(&temp);
    runtime.start().await.expect("an empty pool starts");
    let (attempt, session, account) = start_link(&runtime, "lease-timeout-device").await;

    let error = runtime
        .finish_link(session)
        .await
        .expect_err("the engine's finish-budget timeout fails the finish");
    assert_eq!(error.into_api().code, "LINK_OUTCOME_UNKNOWN");

    assert_zero_orphan_slot(&runtime, &temp, &attempt, &account).await;
    assert!(
        !has_quarantine(&temp),
        "a timed-out pre-credential slot is deleted, not quarantined"
    );
    runtime.shutdown().await.unwrap();
}

/// The reclaim never deletes a committed slot. A late reclaim race (the lease
/// cleanup a crash window could lose) answers Promoted and leaves every byte
/// and the account row untouched.
#[tokio::test]
async fn a_committed_link_is_promoted_never_deleted() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let runtime = open_pool(&temp);
    runtime.start().await.expect("an empty pool starts");

    let (attempt, session, account) = start_link(&runtime, "lease-commit-device").await;
    let summary = runtime
        .finish_link(session)
        .await
        .expect("link.finish commits the account");
    assert_eq!(summary.id, account);
    let dir = data_dir(&temp, &account);
    assert!(dir.is_dir(), "a committed slot keeps its directory");

    // The successful finish promoted the attempt: its old id cannot reclaim.
    let pool = runtime.account_pool().expect("full pooling");
    assert_eq!(
        pool.reclaim_link_attempt(&attempt).await,
        LinkReclaimOutcome::AlreadySettled
    );
    assert!(dir.is_dir(), "the committed slot is untouched");

    // Simulate the crash-window race directly: a lease still open on a slot
    // whose account row exists must be promoted, not deleted.
    let slot = pool.get(&account).expect("the committed slot");
    assert!(
        pool.open_link_lease(&slot, "late-cleanup-attempt")
            .is_some()
    );
    assert_eq!(
        pool.reclaim_link_attempt("late-cleanup-attempt").await,
        LinkReclaimOutcome::Promoted
    );
    assert!(
        dir.is_dir(),
        "a committed row wins the race: reclaim never deletes it"
    );
    assert!(pool.link_lease("late-cleanup-attempt").is_none());
    assert_eq!(pool.open_link_leases(), 0);
    assert_eq!(engines_count(&status_value(&runtime).await), 1);
    runtime.shutdown().await.unwrap();
}

/// BUG-1 softening, arm 1 — the engine committed the link, the connector's
/// finish budget expired first. The reclaim must ask the engine once (one
/// bounded, read-only `listAccounts`) and **promote** the provisioned slot:
/// the missing account row is materialized, the credential-bearing directory
/// and its engine stay, and nothing is quarantined.
#[tokio::test]
async fn a_finish_timeout_after_the_engine_commit_promotes_the_provisioned_slot() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _timeout = EnvGuard::set("KT_FAKE_FINISH_ENGINE_TIMEOUT", "1");
    let _committed = EnvGuard::set("KT_FAKE_FINISH_TIMEOUT_AFTER_COMMIT", "1");
    let runtime = open_pool(&temp);
    runtime.start().await.expect("an empty pool starts");
    let (attempt, session, account) = start_link(&runtime, "lease-provisioned-device").await;

    let error = runtime
        .finish_link(session)
        .await
        .expect_err("the engine's dispatch budget expires before its answer");
    assert_eq!(error.into_api().code, "LINK_OUTCOME_UNKNOWN");

    // The reclaim asked the engine before touching the slot (the fixture
    // records every listAccounts request in this slot's own data dir).
    assert!(
        list_account_calls(&temp, &account) >= 1,
        "the reclaim must ask the engine whether provisioning completed"
    );
    // Promoted, not reclaimed: the account row the connector never wrote now
    // exists (store-only read — this call must not materialize it itself)...
    assert_eq!(
        runtime.account_state(&account).await.expect("store read"),
        Some("ready"),
        "a completed provisioning is materialized into an account row"
    );
    // ...the slot, its directory and its engine all stay...
    let dir = data_dir(&temp, &account);
    assert!(dir.is_dir(), "a promoted slot keeps its directory");
    let pool = runtime.account_pool().expect("full pooling");
    let slot = pool
        .get(&account)
        .expect("the promoted slot stays resident");
    assert!(
        slot.is_provisioned(),
        "the promoted slot carries the durable provisioned marker"
    );
    assert_eq!(pool.open_link_leases(), 0, "the attempt was settled");
    assert!(
        !has_quarantine(&temp),
        "a completed provisioning must never be quarantined"
    );
    assert_eq!(
        engines_count(&status_value(&runtime).await),
        1,
        "the promoted slot keeps its engine"
    );
    // The host's account list answers the same row (with the engine's ACI).
    let accounts = runtime.list_accounts().await.expect("account list");
    let row = accounts
        .iter()
        .find(|row| row.id == account)
        .expect("the promoted account rides the account list");
    assert_eq!(row.state, "ready");
    assert!(
        row.aci.is_some(),
        "the engine's own ACI rides the promoted row"
    );
    // Idempotent: the settled attempt reclaims nothing further.
    assert_eq!(
        pool.reclaim_link_attempt(&attempt).await,
        LinkReclaimOutcome::AlreadySettled
    );
    assert!(dir.is_dir());
    runtime.shutdown().await.unwrap();
}

/// BUG-1 softening, arm 2 — the probe cannot answer (the engine refuses the
/// read call). The pre-softening reclaim stays: the slot is torn down and no
/// account row is invented from a failed query.
#[tokio::test]
async fn a_failed_provisioning_probe_keeps_the_reclaim() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _timeout = EnvGuard::set("KT_FAKE_FINISH_ENGINE_TIMEOUT", "1");
    let _fail = EnvGuard::set("KT_FAKE_LIST_ACCOUNTS_FAIL", "1");
    let runtime = open_pool(&temp);
    runtime.start().await.expect("an empty pool starts");
    let (attempt, session, account) = start_link(&runtime, "lease-probe-failure-device").await;

    let error = runtime
        .finish_link(session)
        .await
        .expect_err("the finish budget expires before the engine answers");
    assert_eq!(error.into_api().code, "LINK_OUTCOME_UNKNOWN");

    // The probe was attempted (the reclaim is not allowed to skip the query),
    // and its failure kept the pre-softening teardown.
    assert!(
        list_account_calls(&temp, &account) >= 1,
        "the reclaim must still ask the engine before tearing the slot down"
    );
    assert_zero_orphan_slot(&runtime, &temp, &attempt, &account).await;
    assert!(
        !has_quarantine(&temp),
        "a credential-less slot is deleted, not quarantined"
    );
    assert!(
        runtime
            .list_accounts()
            .await
            .expect("account list")
            .is_empty(),
        "a failed probe must not materialize an account row"
    );
    runtime.shutdown().await.unwrap();
}

/// BUG-1 softening, arm 3 — the probe never answers. Its budget must expire
/// **inside** the reclaim (the link path must not stretch), and the slot is
/// still torn down: an unbounded query would be a liveness bug of its own.
#[tokio::test]
async fn a_hung_provisioning_probe_expires_and_keeps_the_reclaim() {
    let _guard = LINK_LEASE_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let _timeout = EnvGuard::set("KT_FAKE_FINISH_ENGINE_TIMEOUT", "1");
    let _hang = EnvGuard::set("KT_FAKE_LIST_ACCOUNTS_HANG", "1");
    // Short listAccounts budget: the probe reuses the pool policy's bound, so
    // this test shrinks it instead of waiting out the production budget.
    let runtime = open_pool_with_list_budget(&temp, Duration::from_millis(250));
    runtime.start().await.expect("an empty pool starts");
    let (attempt, session, account) = start_link(&runtime, "lease-probe-timeout-device").await;

    let started = std::time::Instant::now();
    let error = runtime
        .finish_link(session)
        .await
        .expect_err("the finish budget expires before the engine answers");
    let elapsed = started.elapsed();
    assert_eq!(error.into_api().code, "LINK_OUTCOME_UNKNOWN");
    assert!(
        list_account_calls(&temp, &account) >= 1,
        "the reclaim must still ask the engine before tearing the slot down"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the probe is bounded and must not stall the reclaim: {elapsed:?}"
    );
    assert_zero_orphan_slot(&runtime, &temp, &attempt, &account).await;
    assert!(
        !has_quarantine(&temp),
        "a credential-less slot is deleted, not quarantined"
    );
    runtime.shutdown().await.unwrap();
}

/// The startup scan (the crash backstop) keeps one dedicated invariant name,
/// so a log query over the live reclaim path and the quarantine path matches.
#[test]
fn startup_scan_keeps_the_leak_invariant_name() {
    assert_eq!(
        kt_signal_connector::pool::LINK_SLOT_LEAK_INVARIANT,
        "link_attempt_slot_leaked"
    );
}
