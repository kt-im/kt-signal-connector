// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! M6 C phase (contract revision 1.289, §4.275) — the anti-inheritance half of
//! the engine store-key channel.
//!
//! `EngineHandle::start` hands every child an explicit decision: a pooled slot
//! gets `KT_SIGNAL_STORE_KEY = HKDF(root, accountId)`, every keyless child — the
//! legacy group engine included — gets `env_remove`. Neither half is observable
//! unless the connector's *own* environment carries a store key, so this test
//! exports the root hex here and reads both children back. Without that export
//! the legacy assertion is vacuous: a null probe would only prove the parent
//! never had the variable either.
//!
//! This file holds exactly one test on purpose: `set_var` in edition 2024 is
//! process-global, and keeping the export in its own binary means no other
//! integration test can observe (or be raced by) it — the same discipline as
//! `tests/engine_child_env.rs`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::engine::{EngineConfig, EngineHandle, EngineState};
use kt_signal_connector::groups;
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::store::{
    STORE_KEY_ENV, Store, StoreKey, derive_engine_store_key, store_key_from_env,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn root_hex() -> String {
    key().to_hex().to_string()
}

fn account_id(index: u8) -> String {
    format!("{index:032x}")
}

fn prepared_temp() -> TempDir {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    temp
}

/// One provisioned account: store row, slot directory, registry naming exactly
/// that account, and a placeholder presage store.
fn seed_slot(root: &Path, store: &Store, id: &str, number: &str) {
    store
        .upsert_account_from_signal_with_id(number, Some(1), "default", Some(id))
        .unwrap();
    let dir = root.join("signal-data").join("engines").join(id);
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

async fn open_runtime(root: &Path, pooled: bool) -> Arc<ProxyGroupRuntime> {
    fs::create_dir_all(root.join("signal-data")).unwrap();
    let plan = groups::build_group_plan(&[], None, None, &root.join("signal-data")).unwrap();
    open_group_runtime_with_options(
        plan,
        fixture(),
        &root.join("state"),
        None,
        Some(key()),
        false,
        Duration::from_millis(30),
        options(pooled),
    )
    .expect("the runtime opens")
}

async fn probe(path: &Path) -> Value {
    timeout(Duration::from_secs(15), async {
        while !path.is_file() {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the engine wrote its env probe at {}", path.display()));
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// The connector's own environment carries the root key (the dev/test override
/// path); no child may inherit it. A pooled slot is handed its account's
/// derivation instead, and the legacy group engine gets nothing at all.
#[tokio::test]
async fn no_engine_child_inherits_the_connectors_store_key() {
    // Only test in this binary: the export cannot race anything else.
    unsafe { std::env::set_var(STORE_KEY_ENV, root_hex()) };
    let expected = root_hex();
    assert_eq!(
        store_key_from_env()
            .unwrap()
            .map(|key| key.to_hex().to_string())
            .as_deref(),
        Some(expected.as_str()),
        "the parent process really carries the root key for this assertion to mean anything"
    );

    // 1) Pooled slot: its own derivation, and explicitly not the inherited root.
    let pooled = prepared_temp();
    let id = account_id(1);
    {
        let store = Store::open(&pooled.path().join("state"), Some(key())).unwrap();
        seed_slot(pooled.path(), &store, &id, "+15555550901");
    }
    let runtime = open_runtime(pooled.path(), true).await;
    runtime.start().await.unwrap();
    let status = runtime.status().await;
    assert_eq!(status.engines.len(), 1);
    assert_eq!(status.engines[0].state, EngineState::Running);
    let env = probe(
        &pooled
            .path()
            .join("signal-data/engines")
            .join(&id)
            .join(".fixture-env.json"),
    )
    .await;
    let injected = env["KT_SIGNAL_STORE_KEY"]
        .as_str()
        .unwrap_or_else(|| panic!("a pooled slot must be handed its own key: {env}"));
    assert_eq!(
        injected,
        derive_engine_store_key(&key(), &id).to_hex().as_str(),
        "a pooled slot gets HKDF(root, accountId), not whatever the parent exported"
    );
    assert_ne!(
        injected,
        root_hex(),
        "the root itself must never be inherited by a child"
    );
    runtime.shutdown().await.unwrap();

    // 2) Legacy group engine: the parent still carries the root, the child must
    //    not — no account's key can stand for a process that serves several.
    let legacy = prepared_temp();
    let legacy_id = account_id(2);
    {
        let store = Store::open(&legacy.path().join("state"), Some(key())).unwrap();
        seed_legacy_account(legacy.path(), &store, &legacy_id, "+15555550902");
    }
    let runtime = open_runtime(legacy.path(), false).await;
    runtime.start().await.unwrap();
    let env = probe(&legacy.path().join("signal-data/.fixture-env.json")).await;
    assert!(
        env["KT_SIGNAL_STORE_KEY"].is_null(),
        "an exported root key must be removed from a legacy group engine's environment: {env}"
    );
    runtime.shutdown().await.unwrap();

    // 3) The defensive keyless default: an engine driven through
    //    `EngineHandle::start` with `RootKeyMissing` removes the variable too.
    //    (The `serve` topology cannot reach this branch without a key — the
    //    connector's own store fails closed first — so the handle is driven
    //    directly.)
    let direct = prepared_temp();
    let data_dir = direct.path().join("engine-data");
    let config = EngineConfig::new(fixture(), data_dir.clone());
    assert!(matches!(
        config.store_key,
        kt_signal_connector::store::EngineStoreKey::RootKeyMissing
    ));
    let (events, _subscription) = tokio::sync::broadcast::channel(16);
    let (ingress, _receiver) = kt_signal_connector::engine::receive_channel();
    let handle = EngineHandle::start(config, events, ingress)
        .await
        .expect("the keyless engine starts");
    let env = probe(&data_dir.join(".fixture-env.json")).await;
    assert!(
        env["KT_SIGNAL_STORE_KEY"].is_null(),
        "a missing-root engine must not inherit the exported root key: {env}"
    );
    drop(handle);

    unsafe { std::env::remove_var(STORE_KEY_ENV) };
}
