// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! P1 runtime isolation (contract revision 1.288, §4.274): the single-account
//! guard is a **connector decision handed to each engine child explicitly** —
//! `EngineHandle::start` pins `KT_ENGINE_SINGLE_ACCOUNT=1` for an armed slot and
//! `env_remove`s it for every other slot, so a variable exported in the
//! connector's own environment can never arm an engine the connector did not
//! reason about.
//!
//! This file holds exactly one test on purpose: the assertion needs
//! `KT_ENGINE_SINGLE_ACCOUNT=1` in the *parent* environment to prove the removal,
//! and `set_var` in edition 2024 is process-global. Keeping it in its own test
//! binary means no other integration test can observe (or be raced by) that
//! export.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kt_signal_connector::engine::EngineState;
use kt_signal_connector::groups;
use kt_signal_connector::pool::{EnginePoolPolicy, SINGLE_ACCOUNT_ENV};
use kt_signal_connector::registry::{RuntimeOptions, open_group_runtime_with_options};
use kt_signal_connector::store::{Store, StoreKey};
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

/// The unarmed slot removes the guard even though this process exported it.
#[tokio::test]
async fn an_unarmed_slot_removes_the_guard_from_the_child_environment() {
    // Only test in this binary: the export cannot race anything else.
    unsafe { std::env::set_var(SINGLE_ACCOUNT_ENV, "1") };
    assert!(
        kt_signal_connector::pool::single_account_guard_from_env(),
        "the parent process really carries the guard for this assertion to mean anything"
    );

    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    let id = account_id(1);
    drop(seed_slot(temp.path(), &id, "+15555550701"));

    let plan = groups::build_group_plan(&[], None, None, &temp.path().join("signal-data")).unwrap();
    let runtime = open_group_runtime_with_options(
        plan,
        fixture(),
        &temp.path().join("state"),
        None,
        Some(key()),
        false,
        Duration::from_millis(30),
        RuntimeOptions {
            per_account_engines: true,
            // The connector decided this slot is unarmed; the exported dev
            // variable must not reach the child anyway.
            single_account_guard: false,
            pool_policy: EnginePoolPolicy::default(),
            watchdog_interval: Some(Duration::from_millis(50)),
        },
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
    assert!(
        env["KT_ENGINE_SINGLE_ACCOUNT"].is_null(),
        "an unarmed slot must not inherit the connector's exported guard: {env}"
    );

    runtime.shutdown().await.unwrap();
    unsafe { std::env::remove_var(SINGLE_ACCOUNT_ENV) };
}
