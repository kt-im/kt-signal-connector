// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! M6 C phase (contract revision 1.289, §4.275) — the connector half of the
//! engine store-key channel:
//!
//! - every pooled engine child is handed `KT_SIGNAL_STORE_KEY` in canonical
//!   64-lowercase-hex form, equal to `HKDF(salt = accountId, info =
//!   "kt-signal-engine-store-key")` over the connector's root store key;
//! - two accounts never share that key, no child's environment carries a
//!   sibling's key, and the root itself never reaches a child;
//! - the same account keeps its key across a supervisor restart;
//! - a legacy group engine — several accounts behind one process — carries no
//!   account key at all, even when a root key is configured;
//! - without a root key nothing is invented (the engine stays on its plaintext
//!   legacy store) and the decision is warned about exactly once;
//! - no log line carries the key or its derivation.
//!
//! The log assertions need a capturing subscriber installed once per test
//! binary, which is why this file is its own binary.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use kt_signal_connector::engine::EngineState;
use kt_signal_connector::groups;
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::store::{
    EngineStoreKey, Store, StoreError, StoreKey, derive_engine_store_key,
    engine_store_key_for_account,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, timeout};

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];
/// One test at a time: the capturing subscriber is process-global, so a
/// concurrent test's lines would otherwise blur the slice each test asserts on.
static TEST_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn root_key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn root_key_hex() -> String {
    hex::encode(TEST_STORE_KEY)
}

fn account_id(index: u8) -> String {
    format!("{index:032x}")
}

/// The engine's own data directory: the pooled slot, or the legacy group
/// directory (which is the signal-data root itself).
fn engine_data_dir(root: &Path, account: Option<&str>) -> PathBuf {
    match account {
        Some(id) => root.join("signal-data").join("engines").join(id),
        None => root.join("signal-data"),
    }
}

/// One provisioned account: store row, slot directory, registry naming exactly
/// that account, and a placeholder presage store.
fn seed_slot(root: &Path, store: &Store, id: &str, number: &str) {
    store
        .upsert_account_from_signal_with_id(number, Some(1), "default", Some(id))
        .unwrap();
    let dir = engine_data_dir(root, Some(id));
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
}

/// A legacy (pre-pool) account: store row, group directory, registry entry and
/// the presage store in `accounts/lk-*`.
fn seed_legacy_account(root: &Path, store: &Store, id: &str, number: &str) {
    store
        .upsert_account_from_signal_with_id(number, Some(1), "default", Some(id))
        .unwrap();
    let signal_data = root.join("signal-data");
    let store_name = format!("lk-{}", &id[..16]);
    let dir = signal_data.join("accounts").join(&store_name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("store.db"), b"legacy-store").unwrap();
    fs::write(
        signal_data.join("engine-state.json"),
        serde_json::to_vec(&json!({
            "version": 2,
            "accounts": [{"number": number, "dir": format!("accounts/{store_name}")}],
        }))
        .unwrap(),
    )
    .unwrap();
}

fn options(pooled: bool) -> RuntimeOptions {
    RuntimeOptions {
        per_account_engines: pooled,
        single_account_guard: false,
        pool_policy: EnginePoolPolicy::default(),
        watchdog_interval: Some(Duration::from_millis(50)),
    }
}

async fn open_runtime(
    root: &Path,
    store_key: Option<StoreKey>,
    pooled: bool,
) -> Arc<ProxyGroupRuntime> {
    fs::create_dir_all(root.join("signal-data")).unwrap();
    let plan = groups::build_group_plan(&[], None, None, &root.join("signal-data")).unwrap();
    open_group_runtime_with_options(
        plan,
        fixture(),
        &root.join("state"),
        None,
        store_key,
        false,
        Duration::from_millis(30),
        options(pooled),
    )
    .expect("the runtime opens")
}

async fn wait_for_probe(path: &Path) {
    timeout(Duration::from_secs(15), async {
        while !path.is_file() {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the engine wrote its env probe at {}", path.display()));
}

async fn probe(root: &Path, account: Option<&str>) -> Value {
    let path = engine_data_dir(root, account).join(".fixture-env.json");
    wait_for_probe(&path).await;
    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap()
}

#[derive(Default)]
struct Capture {
    written: Mutex<Vec<u8>>,
}

impl Capture {
    fn push(&self, bytes: &[u8]) {
        self.written.lock().unwrap().extend_from_slice(bytes);
    }

    /// Where the buffer stands now: a test asserts on its own slice, so a
    /// neighbour's lines cannot make an absence assertion lie.
    fn mark(&self) -> usize {
        self.written.lock().unwrap().len()
    }

    fn text_since(&self, mark: usize) -> String {
        let written = self.written.lock().unwrap();
        let start = mark.min(written.len());
        String::from_utf8_lossy(&written[start..]).into_owned()
    }
}

#[derive(Clone)]
struct CaptureWriter(Arc<Capture>);

impl Write for CaptureWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.push(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static CAPTURE: OnceLock<Arc<Capture>> = OnceLock::new();

/// Install the capturing subscriber once for this test binary and hand back the
/// buffer every log line lands in.
fn capture() -> Arc<Capture> {
    CAPTURE
        .get_or_init(|| {
            let capture = Arc::new(Capture::default());
            let subscriber = tracing_subscriber::fmt()
                .with_writer(CaptureWriter(Arc::clone(&capture)))
                .with_max_level(tracing::Level::TRACE)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("the capturing subscriber installs once");
            capture
        })
        .clone()
}

fn prepared_temp() -> TempDir {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    temp
}

/// Each pooled engine receives its own account's stable derivation — and
/// nothing belonging to a sibling account or to the root key.
#[tokio::test]
async fn pooled_engines_receive_their_own_accounts_stable_key() {
    let _guard = TEST_LOCK.lock().await;
    let logs = capture();
    let mark = logs.mark();
    let temp = prepared_temp();
    let ids = [account_id(1), account_id(2)];
    {
        let store = Store::open(&temp.path().join("state"), Some(root_key())).unwrap();
        seed_slot(temp.path(), &store, &ids[0], "+15555550801");
        seed_slot(temp.path(), &store, &ids[1], "+15555550802");
    }

    let runtime = open_runtime(temp.path(), Some(root_key()), true).await;
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 2);
    for engine in &status.engines {
        assert_eq!(
            engine.state,
            EngineState::Running,
            "{engine:?} did not start"
        );
    }

    let mut injected: Vec<(String, String)> = Vec::new();
    for id in &ids {
        let env = probe(temp.path(), Some(id)).await;
        let key = env["KT_SIGNAL_STORE_KEY"]
            .as_str()
            .unwrap_or_else(|| panic!("account {id} must receive a store key: {env}"))
            .to_string();
        assert_eq!(
            key,
            derive_engine_store_key(&root_key(), id)
                .to_hex()
                .to_string(),
            "account {id} must receive exactly its own derivation"
        );
        assert_eq!(key.len(), 64, "canonical hex only: {key}");
        assert!(
            key.bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "lowercase hex only: {key}"
        );
        assert_ne!(
            key,
            root_key_hex(),
            "the root itself never crosses the boundary"
        );
        injected.push((id.clone(), key));
    }
    assert_ne!(
        injected[0].1, injected[1].1,
        "two accounts must never share an engine store key"
    );

    // No child's environment carries a sibling's key or the root key.
    for (id, _) in &injected {
        let path = engine_data_dir(temp.path(), Some(id)).join(".fixture-env.json");
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains(&root_key_hex()),
            "the root key must never reach a child ({id}): {raw}"
        );
        for (other, other_key) in &injected {
            if other != id {
                assert!(
                    !raw.contains(other_key),
                    "{id} must not see {other}'s key: {raw}"
                );
            }
        }
    }

    // Stable across a restart: kill -9 this slot's engine, let the watchdog
    // replace it, and read what the replacement child was handed.
    let observed = status
        .engines
        .iter()
        .find(|engine| engine.account_id == ids[0])
        .and_then(|engine| engine.pid)
        .expect("the first slot reports its pid");
    let probe_path = engine_data_dir(temp.path(), Some(&ids[0])).join(".fixture-env.json");
    fs::remove_file(&probe_path).unwrap();
    unsafe { libc::kill(observed as i32, libc::SIGKILL) };
    timeout(Duration::from_secs(15), async {
        loop {
            let status = runtime.status().await;
            let replaced = status
                .engines
                .iter()
                .find(|engine| engine.account_id == ids[0])
                .and_then(|engine| engine.pid)
                .is_some_and(|pid| pid != observed);
            if replaced {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the watchdog restarts the killed slot");
    let restarted = probe(temp.path(), Some(&ids[0])).await;
    assert_eq!(
        restarted["KT_SIGNAL_STORE_KEY"].as_str(),
        Some(injected[0].1.as_str()),
        "a restarted engine must keep its account's key"
    );

    // The decision is logged; the key and its derivation never are.
    let text = logs.text_since(mark);
    assert!(
        text.contains("engine child store key injected"),
        "the injection decision must be logged: {text}"
    );
    assert!(
        text.matches("engine child store key injected").count() >= 2,
        "one injection line per child, plus the restarted slot's: {text}"
    );
    assert!(
        !text.contains(&root_key_hex()),
        "no log line carries the root key"
    );
    for (_, key) in &injected {
        assert!(!text.contains(key), "no log line carries a derived key");
    }

    runtime.shutdown().await.unwrap();
}

/// A legacy group engine serves every account of its group from one process, so
/// it must carry no account key even when the connector holds a root key.
#[tokio::test]
async fn a_legacy_group_engine_carries_no_account_key() {
    let _guard = TEST_LOCK.lock().await;
    let logs = capture();
    let mark = logs.mark();
    let temp = prepared_temp();
    let id = account_id(4);
    {
        let store = Store::open(&temp.path().join("state"), Some(root_key())).unwrap();
        seed_legacy_account(temp.path(), &store, &id, "+15555550804");
    }

    let runtime = open_runtime(temp.path(), Some(root_key()), false).await;
    runtime.start().await.unwrap();
    let env = probe(temp.path(), None).await;
    assert!(
        env["KT_SIGNAL_STORE_KEY"].is_null(),
        "a group engine serves several accounts, so no account key may ride along: {env}"
    );
    // The decision is logged as the legacy topology, not as a missing root key:
    // this connector does hold a root key, it just may not hand it to a process
    // that serves several accounts.
    let text = logs.text_since(mark);
    assert!(
        text.contains("group_engine_no_account_key"),
        "a keyless legacy group engine must say so: {text}"
    );
    assert!(
        !text.contains("root_key_missing"),
        "a group engine with a root key configured is not a missing-root downgrade: {text}"
    );
    assert!(
        !text.contains("not_configured"),
        "the collapsed old label must not come back: {text}"
    );
    assert!(
        !text.contains(&root_key_hex()),
        "no log line carries the root key"
    );
    for account in [account_id(1), account_id(2), account_id(3), id.clone()] {
        let derived = derive_engine_store_key(&root_key(), &account)
            .to_hex()
            .to_string();
        assert!(
            !text.contains(&derived),
            "no log line carries a derived key"
        );
    }
    runtime.shutdown().await.unwrap();
}

/// No root key configured: nothing is derived (never a generated stand-in), and
/// the plaintext-legacy decision is warned about exactly once per process.
///
/// The connector's own `Store::open` fails closed without a store key, so in
/// the `serve` topology this branch is a defensive one: what it pins is that the
/// `Option` never becomes an invented key on this side either, and that the
/// downgrade is announced rather than silent. A `None` engine config reaching a
/// child is covered by the legacy test above, which proves the variable is
/// absent from the environment and the engine still starts.
#[tokio::test]
async fn a_missing_root_key_injects_nothing_and_warns_once() {
    let _guard = TEST_LOCK.lock().await;
    let logs = capture();
    let mark = logs.mark();
    let id = account_id(3);
    // Two decisions, one warning: the latch is process-wide, not per slot.
    assert!(matches!(
        engine_store_key_for_account(None, &id),
        EngineStoreKey::RootKeyMissing
    ));
    assert!(matches!(
        engine_store_key_for_account(None, &id),
        EngineStoreKey::RootKeyMissing
    ));
    // With a root key the decision is the account's own derivation, never the
    // root and never a keyless state.
    assert!(matches!(
        engine_store_key_for_account(Some(&root_key()), &id),
        EngineStoreKey::Account(_)
    ));

    let text = logs.text_since(mark);
    assert_eq!(
        text.matches("engine children stay on the plaintext legacy store")
            .count(),
        1,
        "the missing-root warning fires exactly once: {text}"
    );
    assert_eq!(
        text.matches(EngineStoreKey::RootKeyMissing.decision())
            .count(),
        1,
        "the warning carries the missing-root label exactly once: {text}"
    );
    // The derivation this account *would* have had is the sentinel that must
    // never appear: an unconfigured root key yields no key material anywhere.
    let never_derived = derive_engine_store_key(&root_key(), &id)
        .to_hex()
        .to_string();
    assert!(!text.contains(&never_derived), "no log line carries a key");
    assert!(
        !text.contains(&root_key_hex()),
        "no log line carries the root key"
    );

    // Why this branch is a gate rather than a run mode: the connector's own
    // store refuses to open without a key (the Phase 3 fail-closed contract),
    // so a keyless `serve` runtime never gets as far as spawning an engine.
    let temp = TempDir::new().unwrap();
    assert!(matches!(
        Store::open(&temp.path().join("state"), None),
        Err(StoreError::StoreKeyRequired)
    ));
}
