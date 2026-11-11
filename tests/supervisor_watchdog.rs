// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kt_signal_connector::engine::{
    CallClass, EngineConfig, EngineEvent, EngineHandle, event_channel, receive_channel,
};
use kt_signal_connector::store::{Store, StoreKey};
use kt_signal_connector::supervisor::RuntimeSupervisor;
use serde_json::json;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

/// All watchdog-test stores are encrypted with one fixed key (Phase 3), so a
/// seeded store and the supervisor's own open see the same database.
fn test_store(dir: &std::path::Path) -> Arc<Store> {
    Arc::new(Store::open(dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap())
}

fn watchdog_supervisor(temp: &TempDir) -> (Arc<RuntimeSupervisor>, PathBuf) {
    watchdog_supervisor_with_throttle(temp, Duration::ZERO)
}

fn watchdog_supervisor_with_throttle(
    temp: &TempDir,
    min_restart_interval: Duration,
) -> (Arc<RuntimeSupervisor>, PathBuf) {
    build_watchdog_supervisor(temp, min_restart_interval, None)
}

/// A fixture whose retry pace equals the window it configures. The watchdog
/// paces a deferred restart with `watchdog_liveness_backoff_base` (ten seconds
/// in production); `watchdog_min_restart_interval` is only the anti-storm
/// window that resets the episode. A test written around "the throttle window
/// passes" must wire both, or its second restart lands ten seconds out.
fn watchdog_supervisor_with_pacing(
    temp: &TempDir,
    min_restart_interval: Duration,
) -> (Arc<RuntimeSupervisor>, PathBuf) {
    build_watchdog_supervisor(temp, min_restart_interval, Some(min_restart_interval))
}

fn build_watchdog_supervisor(
    temp: &TempDir,
    min_restart_interval: Duration,
    liveness_backoff_base: Option<Duration>,
) -> (Arc<RuntimeSupervisor>, PathBuf) {
    let store = test_store(temp.path());
    let data_dir = temp.path().join("signal-data");
    let mut config = EngineConfig::new(fixture(), data_dir.clone());
    config.request_timeout = Duration::from_secs(1);
    config.shutdown_grace = Duration::from_millis(100);
    config.watchdog_interval = Duration::from_millis(50);
    config.watchdog_min_restart_interval = min_restart_interval;
    if let Some(base) = liveness_backoff_base {
        config.watchdog_liveness_backoff_base = base;
    }
    let supervisor = Arc::new(RuntimeSupervisor::new(
        config,
        store,
        kt_signal_connector::DEFAULT_PROXY_GROUP_ID.to_string(),
        None,
    ));
    supervisor.spawn_watchdog();
    (supervisor, data_dir)
}

async fn wait_for_pid_change(supervisor: &Arc<RuntimeSupervisor>, pid_before: u32) -> u32 {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(pid) = supervisor.status().await.pid
                && pid != pid_before
            {
                break pid;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("watchdog restarts the engine within the timeout")
}

#[tokio::test]
async fn engine_stderr_lines_are_broadcast_to_subscribers() {
    let temp = TempDir::new().unwrap();
    let mut config = EngineConfig::new(fixture(), temp.path().join("signal-data"));
    config.request_timeout = Duration::from_secs(1);
    config.shutdown_grace = Duration::from_millis(100);
    let (events, _) = event_channel();
    let (receive_ingress, _receives) = receive_channel();
    let engine = EngineHandle::start(config, events, receive_ingress)
        .await
        .unwrap();
    let mut stderr = engine.subscribe_stderr();

    engine
        .call("emitStderr", json!({}), CallClass::ReadOnly)
        .await
        .unwrap();
    let line = timeout(Duration::from_secs(2), stderr.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(line.to_lowercase().contains("websocket"));
    engine.shutdown().await.unwrap();
}

/// Phase 1a regression: with the receive queue full and its consumer not
/// draining (storage keeps failing every persist, so the persistence loop
/// retries the queue head forever), a shutdown request must still complete
/// within a bounded time. Before the fix the actor parked on an unbounded
/// enqueue wait, starved its command lane, and shutdown hung forever. Also
/// asserts the degradation surfaces as the engine-side storage event.
#[tokio::test]
async fn shutdown_completes_when_the_receive_queue_is_full_and_storage_is_down() {
    let temp = TempDir::new().unwrap();
    let mut config = EngineConfig::new(fixture(), temp.path().join("signal-data"));
    config.request_timeout = Duration::from_secs(1);
    config.shutdown_grace = Duration::from_millis(100);
    config.receive_enqueue_timeout = Duration::from_millis(50);
    let (events, _) = event_channel();
    let (receive_ingress, receives) = receive_channel();
    let engine = EngineHandle::start(config, events, receive_ingress)
        .await
        .unwrap();
    let mut engine_events = engine.subscribe();

    // Hold the receiver without ever draining it: exactly what the engine
    // sees while storage is down and the persistence loop retries the head.
    let _undrained = receives;
    // Overfill the bounded receive queue (message capacity 256).
    for _ in 0..(256 + 20) {
        engine
            .call("emitReceive", json!({}), CallClass::ReadOnly)
            .await
            .unwrap();
    }

    // Once the queue stays full past the enqueue timeout, receives are
    // dropped and the engine reports degraded storage exactly once.
    timeout(Duration::from_secs(15), async {
        loop {
            if let EngineEvent::StorageChanged {
                state: "unavailable",
            } = engine_events.recv().await.unwrap()
            {
                break;
            }
        }
    })
    .await
    .expect("a saturated receive queue must surface as degraded storage");

    // The core assertion: shutdown answers within its internal budget
    // (grace + margin, here ~2.1s) instead of hanging behind a parked actor.
    timeout(Duration::from_secs(10), engine.shutdown())
        .await
        .expect("shutdown must not hang behind receive backpressure")
        .unwrap();
}

#[tokio::test]
async fn watchdog_restarts_engine_on_fatal_receive_stderr() {
    let temp = TempDir::new().unwrap();
    let (supervisor, data_dir) = watchdog_supervisor(&temp);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join(".fixture-stderr-websocket-error"), "").unwrap();

    let pid_before = supervisor.start().await.unwrap().pid.unwrap();
    let pid_after = wait_for_pid_change(&supervisor, pid_before).await;
    assert_ne!(pid_after, pid_before);
    supervisor.shutdown().await.unwrap();
}

#[tokio::test]
async fn watchdog_restarts_engine_after_repeated_ping_failures() {
    let temp = TempDir::new().unwrap();
    // Seed one linked account so the watchdog has a ping target.
    {
        let seed = test_store(temp.path());
        seed.upsert_account_from_signal(
            "+15555550100",
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
        .unwrap();
    }
    let (supervisor, data_dir) = watchdog_supervisor(&temp);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join(".fixture-fail-user-status"), "").unwrap();

    let pid_before = supervisor.start().await.unwrap().pid.unwrap();
    let pid_after = wait_for_pid_change(&supervisor, pid_before).await;
    assert_ne!(pid_after, pid_before);
    supervisor.shutdown().await.unwrap();
}

/// Contract 1.21: an authorization-failed ping means the account holder
/// unlinked this device. The credential is dead — restarting cannot fix it —
/// so the engine pid must stay put while the supervisor's account watcher
/// marks the account `device_unlinked` in the shared store.
#[tokio::test]
async fn unauthorized_ping_marks_account_device_unlinked_without_restart() {
    let temp = TempDir::new().unwrap();
    {
        let seed = test_store(temp.path());
        seed.upsert_account_from_signal(
            "+15555550100",
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
        .unwrap();
    }
    let (supervisor, data_dir) = watchdog_supervisor(&temp);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join(".fixture-auth-failed-user-status"), "").unwrap();

    let pid = supervisor.start().await.unwrap().pid.unwrap();
    // Several watchdog ticks: auth failures never count as ping failures.
    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        supervisor.status().await.pid,
        Some(pid),
        "a dead credential must not churn engine restarts"
    );

    let store = test_store(temp.path());
    let account = store
        .list_accounts()
        .unwrap()
        .into_iter()
        .find(|account| account.state == "device_unlinked")
        .expect("auth-failed ping must mark the account device_unlinked");
    assert_eq!(account.unread_count, 0);
    supervisor.shutdown().await.unwrap();
}

/// The post-mortem unlink form: after the first authorization failure
/// signal-cli persists `registered=false` and every later command fails
/// locally with "User <account> is not registered." (USER_ERROR -1) — the
/// 0-17 ms instant-failure shape that previously slipped past the
/// unauthorized classification and churned restarts forever. Same contract
/// 1.21 outcome as the live form: pid stays put, account flips
/// `device_unlinked`.
#[tokio::test]
async fn unregistered_post_mortem_ping_marks_account_device_unlinked_without_restart() {
    let temp = TempDir::new().unwrap();
    {
        let seed = test_store(temp.path());
        seed.upsert_account_from_signal(
            "+15555550100",
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
        .unwrap();
    }
    let (supervisor, data_dir) = watchdog_supervisor(&temp);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join(".fixture-unregistered-user-status"), "").unwrap();

    let pid = supervisor.start().await.unwrap().pid.unwrap();
    // Several watchdog ticks: post-mortem failures never count as ping failures.
    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        supervisor.status().await.pid,
        Some(pid),
        "a dead credential must not churn engine restarts"
    );

    let store = test_store(temp.path());
    let account = store
        .list_accounts()
        .unwrap()
        .into_iter()
        .find(|account| account.state == "device_unlinked")
        .expect("unregistered ping must mark the account device_unlinked");
    assert_eq!(account.unread_count, 0);
    supervisor.shutdown().await.unwrap();
}

#[tokio::test]
async fn watchdog_leaves_a_healthy_engine_alone() {
    let temp = TempDir::new().unwrap();
    {
        let seed = test_store(temp.path());
        seed.upsert_account_from_signal(
            "+15555550100",
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
        .unwrap();
    }
    let (supervisor, _data_dir) = watchdog_supervisor(&temp);

    let pid_before = supervisor.start().await.unwrap().pid.unwrap();
    // Several watchdog ticks with successful pings: no restart.
    sleep(Duration::from_millis(500)).await;
    assert_eq!(supervisor.status().await.pid, Some(pid_before));
    supervisor.shutdown().await.unwrap();
}

/// A restart request landing inside the throttle window must not be dropped:
/// the fixture keeps reporting a dead receive WebSocket, so the second trigger
/// becomes pending and fires once the retry backoff passes (pid changes again).
/// The fixture wires the backoff base to the same window, so "the window"
/// paces the retry and the assertion stays seconds-scale.
#[tokio::test]
async fn throttled_stderr_restart_is_retried_after_the_throttle_window() {
    let temp = TempDir::new().unwrap();
    let (supervisor, data_dir) =
        watchdog_supervisor_with_pacing(&temp, Duration::from_millis(1000));
    std::fs::create_dir_all(&data_dir).unwrap();
    let marker = data_dir.join(".fixture-stderr-websocket-error");
    std::fs::write(&marker, "").unwrap();

    let pid_a = supervisor.start().await.unwrap().pid.unwrap();
    // First stderr report: immediate ("initial") restart.
    let pid_b = wait_for_pid_change(&supervisor, pid_a).await;
    // The restarted engine reports the dead WebSocket again inside the
    // throttle window; the request goes pending and is retried after it.
    let pid_c = wait_for_pid_change(&supervisor, pid_b).await;
    assert_ne!(pid_c, pid_b);

    std::fs::remove_file(&marker).unwrap();
    supervisor.shutdown().await.unwrap();
}

/// A ping-sourced pending restart is cancelled when pings recover inside the
/// throttle window: REST liveness recovering means the ping concern is gone.
#[tokio::test]
async fn ping_pending_restart_is_cleared_when_pings_recover() {
    let temp = TempDir::new().unwrap();
    {
        let seed = test_store(temp.path());
        seed.upsert_account_from_signal(
            "+15555550100",
            Some(1),
            kt_signal_connector::DEFAULT_PROXY_GROUP_ID,
        )
        .unwrap();
    }
    let (supervisor, data_dir) =
        watchdog_supervisor_with_throttle(&temp, Duration::from_millis(1000));
    std::fs::create_dir_all(&data_dir).unwrap();
    // Fail 6 getUserStatus pings: 2 trigger the initial restart, the next ones
    // raise a ping-sourced pending restart, then pings recover and clear it.
    std::fs::write(data_dir.join(".fixture-fail-user-status-count"), "6").unwrap();

    let pid_a = supervisor.start().await.unwrap().pid.unwrap();
    let pid_b = wait_for_pid_change(&supervisor, pid_a).await;

    // Well past the throttle window: had the pending restart survived, the
    // watchdog would have restarted the engine again.
    sleep(Duration::from_millis(2000)).await;
    assert_eq!(
        supervisor.status().await.pid,
        Some(pid_b),
        "recovered pings must clear the ping-sourced pending restart"
    );
    supervisor.shutdown().await.unwrap();
}

/// Continuous failure triggers are paced, never executed back to back: the
/// first restart of an episode is immediate and every later one waits a
/// doubling backoff (`watchdog_liveness_backoff_base`: 1x, 2x, 4x, 8x …), so
/// the four restarts observed here land a full window, two, four and then
/// eight windows apart. The next retry therefore sits far outside the
/// observation below — the pid stays put even though stderr keeps reporting a
/// dead WebSocket (the capped schedule retries forever; nothing "gives up").
#[tokio::test]
async fn continuous_failures_exhaust_the_episode_retry_budget() {
    let temp = TempDir::new().unwrap();
    let (supervisor, data_dir) =
        watchdog_supervisor_with_pacing(&temp, Duration::from_millis(1500));
    std::fs::create_dir_all(&data_dir).unwrap();
    let marker = data_dir.join(".fixture-stderr-websocket-error");
    std::fs::write(&marker, "").unwrap();

    let pid_a = supervisor.start().await.unwrap().pid.unwrap();
    let mut pids = vec![pid_a];
    let mut last = pid_a;
    for _ in 0..4 {
        last = wait_for_pid_change(&supervisor, last).await;
        pids.push(last);
    }
    // initial + 3 deferred retries = 4 restarts; the next backoff is 8x.
    assert_eq!(pids.len(), 5);

    // Well inside the next (8x) backoff window after the last restart: a
    // retry executing now would show up as a pid change.
    sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        supervisor.status().await.pid,
        Some(last),
        "the doubling backoff must keep the next retry outside the observation window"
    );

    std::fs::remove_file(&marker).unwrap();
    supervisor.shutdown().await.unwrap();
}
