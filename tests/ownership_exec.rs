// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

//! D4 所有权执行面回归(阶段1 批1-5c,SIGNAL-STAGE1-DESIGN §三):Main 的
//! 所有权表裁决 → connector 执行臂。覆盖三件事:
//! 1. **隔离**:停引擎 + 凭据目录移 `.quarantine-*`(字节保留可审计),
//!    且**幂等**——重放返回 already-settled(false),绝不重复移动目录。
//! 2. **休眠**:停引擎 + 目录原地保留(冷槽语义),同样幂等。
//! 3. **无槽/垃圾输入**:静默 already-settled,不 panic——孤儿槽的定义就
//!    是"绑定已消失",执行面绝不依赖账号行解析。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::groups;
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{
    ProxyGroupRuntime, RuntimeOptions, open_group_runtime_with_options,
};
use kt_signal_connector::store::StoreKey;
use serde_json::Value;
use tempfile::TempDir;

const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

/// 与 link_slot_lease 同款串行锁:真引擎进程的夹具延迟按进程起算。
static OWNERSHIP_EXEC_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn key() -> StoreKey {
    StoreKey::from_bytes(TEST_STORE_KEY)
}

fn open_pool(temp: &TempDir) -> Arc<ProxyGroupRuntime> {
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
                list_accounts_budget: Duration::from_secs(3),
                demote_idle_after: Duration::from_secs(60),
            },
            watchdog_interval: Some(Duration::from_millis(50)),
        },
    )
    .unwrap()
}

fn data_dir(temp: &TempDir, account: &str) -> PathBuf {
    temp.path()
        .join("signal-data")
        .join("engines")
        .join(account)
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

async fn status_value(runtime: &ProxyGroupRuntime) -> Value {
    serde_json::to_value(runtime.status().await).unwrap()
}

fn engines_count(status: &Value) -> usize {
    status["engines"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default()
}

async fn start_link_slot(runtime: &Arc<ProxyGroupRuntime>) -> String {
    runtime.start().await.expect("an empty pool starts");
    let link = runtime
        .start_link("ownership-exec-test".to_string(), Some("default".into()))
        .await
        .expect("link.start provisions a slot");
    let _attempt = link["linkAttemptId"]
        .as_str()
        .expect("attempt id")
        .to_string();
    let _session = link["linkSessionId"]
        .as_str()
        .expect("session id")
        .to_string();
    let status = status_value(runtime).await;
    status["engines"][0]["accountId"]
        .as_str()
        .unwrap_or_else(|| panic!("the fresh slot is listed: {status}"))
        .to_string()
}

#[tokio::test]
async fn ownership_quarantine_moves_directory_and_is_idempotent() {
    let _guard = OWNERSHIP_EXEC_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let runtime = open_pool(&temp);
    let account = start_link_slot(&runtime).await;
    assert_eq!(engines_count(&status_value(&runtime).await), 1);

    let removed = runtime
        .ownership_quarantine_slot(&account, "stale-generation")
        .await;
    assert!(removed, "a live slot must be torn down on the first call");
    assert_eq!(engines_count(&status_value(&runtime).await), 0);
    assert!(
        !data_dir(&temp, &account).exists(),
        "slot dir is moved aside"
    );
    assert!(
        has_quarantine(&temp),
        "bytes land in .quarantine-* (auditable)"
    );

    // 幂等重放:无槽 = already-settled,目录不再动
    let replay = runtime
        .ownership_quarantine_slot(&account, "stale-generation")
        .await;
    assert!(!replay, "replay must be a quiet already-settled no-op");
}

#[tokio::test]
async fn ownership_hibernate_keeps_directory_and_is_idempotent() {
    let _guard = OWNERSHIP_EXEC_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let runtime = open_pool(&temp);
    let account = start_link_slot(&runtime).await;

    let removed = runtime.ownership_hibernate_slot(&account).await;
    assert!(removed, "a live slot must hibernate on the first call");
    assert_eq!(engines_count(&status_value(&runtime).await), 0);
    assert!(
        data_dir(&temp, &account).exists(),
        "hibernate keeps the directory cold (wake on next request)"
    );
    assert!(!has_quarantine(&temp), "hibernate never quarantines bytes");

    let replay = runtime.ownership_hibernate_slot(&account).await;
    assert!(!replay, "replay must be a quiet already-settled no-op");
}

#[tokio::test]
async fn ownership_exec_on_absent_slot_is_a_quiet_no_op() {
    let _guard = OWNERSHIP_EXEC_TEST_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let runtime = open_pool(&temp);
    // 从未存在的槽 + 垃圾输入:already-settled,不 panic(孤儿语义)
    assert!(
        !runtime
            .ownership_quarantine_slot("never-provisioned", "binding-absent")
            .await
    );
    assert!(!runtime.ownership_hibernate_slot("never-provisioned").await);
    assert!(
        !runtime
            .ownership_quarantine_slot("", "session-unbound")
            .await
    );
    assert_eq!(engines_count(&status_value(&runtime).await), 0);
    assert!(!has_quarantine(&temp));
}
