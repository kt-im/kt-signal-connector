// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use kt_signal_connector::engine::{
    CallClass, EngineConfig, EngineError, EngineEvent, EngineHandle, EngineState,
    STDIN_WRITE_QUEUE_CAPACITY, event_channel, receive_channel,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::task::JoinSet;
use tokio::time::timeout;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

async fn engine(
    request_timeout: Duration,
) -> (
    TempDir,
    EngineHandle,
    tokio::sync::mpsc::Receiver<kt_signal_connector::engine::QueuedReceive>,
) {
    let temp = TempDir::new().unwrap();
    let mut config = EngineConfig::new(fixture(), temp.path().join("signal-data"));
    config.request_timeout = request_timeout;
    config.shutdown_grace = Duration::from_millis(100);
    let (events, _) = event_channel();
    let (receive_ingress, receives) = receive_channel();
    let engine = EngineHandle::start(config, events, receive_ingress)
        .await
        .unwrap();
    (temp, engine, receives)
}

#[tokio::test]
async fn matches_success_and_normalizes_receive_without_private_fields() {
    let (_temp, engine, mut receives) = engine(Duration::from_secs(1)).await;

    let result = engine
        .call("emitReceive", json!({}), CallClass::ReadOnly)
        .await
        .unwrap();
    assert_eq!(result, json!({ "method": "emitReceive" }));

    let queued = timeout(Duration::from_secs(1), receives.recv())
        .await
        .unwrap()
        .unwrap();
    let receive = queued.receive();
    let encoded = serde_json::to_string(&receive).unwrap();
    assert_eq!(receive.timestamp, Some(42));
    assert!(!encoded.contains("private text"));
    assert!(!encoded.contains("+155"));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_output_faults_runtime() {
    let (_temp, engine, _receives) = engine(Duration::from_secs(3)).await;
    let running_pid = engine.status().pid;
    let mut events = engine.subscribe();
    let result = engine
        .call("malformed", json!({}), CallClass::ReadOnly)
        .await;
    assert_eq!(result, Err(EngineError::Protocol));
    assert_eq!(engine.status().state, EngineState::Faulted);
    let faulted = timeout(Duration::from_secs(1), async {
        loop {
            if let EngineEvent::StateChanged(status) = events.recv().await.unwrap()
                && status.state == EngineState::Faulted
            {
                break status;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(faulted.pid, running_pid);
}

#[tokio::test]
async fn read_timeout_and_send_timeout_have_distinct_outcomes() {
    let (_temp, engine, _receives) = engine(Duration::from_millis(50)).await;
    assert_eq!(
        engine.call("hang", json!({}), CallClass::ReadOnly).await,
        Err(EngineError::Timeout)
    );
    assert_eq!(
        engine
            .call("sendHang", json!({}), CallClass::Mutating)
            .await,
        Err(EngineError::UnknownOutcome)
    );
    engine.shutdown().await.unwrap();
}

/// Contract 1.285 (§4.269): the engine's -32000 (EngineTimeoutException)
/// dispatch face is class-split. A READ-ONLY call cannot have written
/// anything and keeps the structured `EngineRequestTimeout` face with the
/// engine's promised data (the supervisor answers ENGINE_TIMEOUT); the same
/// answer on a MUTATING call may already have been written and folds to the
/// existing `UnknownOutcome` (SEND_OUTCOME_UNKNOWN, row unknown, no retry).
#[tokio::test]
async fn engine_dispatch_timeout_is_class_split_between_read_and_mutating() {
    let (temp, engine, _receives) = engine(Duration::from_secs(3)).await;
    std::fs::write(
        temp.path()
            .join("signal-data/.fixture-version-engine-timeout"),
        b"",
    )
    .unwrap();
    std::fs::write(
        temp.path()
            .join("signal-data/.fixture-send-engine-timeout-armed"),
        b"",
    )
    .unwrap();

    match engine.call("version", json!({}), CallClass::ReadOnly).await {
        Err(EngineError::EngineRequestTimeout { data }) => {
            let data = data.expect("the read-only face keeps the engine payload");
            assert_eq!(data["reason"], json!("REQUEST_TIMEOUT"));
            assert_eq!(data["retryable"], json!(false));
            assert_eq!(data["timeoutMs"], json!(60000));
        }
        other => panic!("read-only timeout must keep the structured face, got {other:?}"),
    }

    assert_eq!(
        engine.call("send", json!({}), CallClass::Mutating).await,
        Err(EngineError::UnknownOutcome),
        "a cancelled mutating dispatch may have been written: unknown outcome"
    );
    engine.shutdown().await.unwrap();
}

/// Polls the engine event stream until the actor reports a response whose id
/// no pending entry claims (`pending.remove` miss in `handle_upstream_line`)
/// — the deterministic barrier proving a late answer landed and was dropped
/// instead of resolving or being misattributed to another request.
async fn assert_late_answer_dropped(events: &mut tokio::sync::broadcast::Receiver<EngineEvent>) {
    let warning = timeout(Duration::from_secs(2), async {
        loop {
            if let EngineEvent::ProtocolWarning { kind } = events.recv().await.unwrap() {
                break kind;
            }
        }
    })
    .await
    .expect("the late answer must surface as a dropped unknown id");
    assert_eq!(warning, "unknownOrDuplicateResponseId");
}

/// Read-only deadline convergence: a read-only call whose answer lands after
/// the request deadline resolves to `Timeout`, the late answer then surfaces
/// as a dropped unknown id (the deadline's Cancel already retired the pending
/// entry), and a later unrelated request resolves with its own response —
/// never the late payload (the pending map dispatches by exact id).
#[tokio::test]
async fn read_only_late_response_is_dropped_not_misattributed() {
    let (_temp, engine, _receives) = engine(Duration::from_millis(100)).await;
    let mut events = engine.subscribe();

    // Warm the engine past the child's startup latency (a generous budget)
    // so the 100 ms deadline below measures the fixture's deliberate slow
    // answer, never the child's first-read time.
    let warmup = engine
        .call_with_timeout(
            "version",
            json!({}),
            CallClass::ReadOnly,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(warmup["name"], json!("kt-signal-engine"));

    assert_eq!(
        engine
            .call("slowRead", json!({}), CallClass::ReadOnly)
            .await,
        Err(EngineError::Timeout)
    );

    // The late answer (~350 ms in the fixture) arrives after the deadline's
    // Cancel (~100 ms): it must be dropped as an unknown id.
    assert_late_answer_dropped(&mut events).await;

    // A subsequent unrelated request resolves with its own response.
    let result = engine
        .call("version", json!({}), CallClass::ReadOnly)
        .await
        .unwrap();
    assert_eq!(result["name"], json!("kt-signal-engine"));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn duplicate_response_is_reported_without_resolving_twice() {
    let (_temp, engine, _receives) = engine(Duration::from_secs(1)).await;
    let mut events = engine.subscribe();
    let result = engine
        .call("duplicate", json!({}), CallClass::ReadOnly)
        .await
        .unwrap();
    assert_eq!(result, json!({ "method": "duplicate" }));

    let warning = timeout(Duration::from_secs(1), async {
        loop {
            if let EngineEvent::ProtocolWarning { kind } = events.recv().await.unwrap() {
                break kind;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(warning, "unknownOrDuplicateResponseId");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn crash_exits_and_a_new_engine_can_start() {
    let (temp, engine, _receives) = engine(Duration::from_secs(1)).await;
    let result = engine.call("crash", json!({}), CallClass::ReadOnly).await;
    assert_eq!(result, Err(EngineError::Exited));
    assert_eq!(engine.status().state, EngineState::Exited);

    let mut config = EngineConfig::new(fixture(), temp.path().join("signal-data"));
    config.shutdown_grace = Duration::from_millis(100);
    let (events, _) = event_channel();
    let (receive_ingress, _receives) = receive_channel();
    let restarted = EngineHandle::start(config, events, receive_ingress)
        .await
        .unwrap();
    let result = restarted
        .call("version", json!({}), CallClass::ReadOnly)
        .await
        .unwrap();
    assert_eq!(result["name"], json!("kt-signal-engine"));
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn mutating_request_crash_is_an_unknown_outcome() {
    let (_temp, engine, _receives) = engine(Duration::from_secs(3)).await;
    let result = engine
        .call("crashSend", json!({}), CallClass::Mutating)
        .await;
    assert_eq!(result, Err(EngineError::UnknownOutcome));
    assert_eq!(engine.status().state, EngineState::Exited);
}

/// remoteDelete is Mutating on both indeterminate paths: a slow answer past
/// the request timeout (fixture targetTimestamp 350, answered after 0.35s)
/// and a one-shot crash mid-call (fixture targetTimestamp 421) each resolve
/// to UnknownOutcome — never to a retryable timeout — so the supervisor can
/// surface the explicit `{"status":"unknown"}` response.
#[tokio::test]
async fn remote_delete_slow_answer_and_crash_are_unknown_outcomes() {
    let (_temp, slow_engine, _receives) = engine(Duration::from_millis(100)).await;
    let mut events = slow_engine.subscribe();
    // Warm the engine past the child's startup latency (a generous budget)
    // so the 100 ms deadline below measures the fixture's deliberate slow
    // answer, never the child's first-read time.
    slow_engine
        .call_with_timeout(
            "version",
            json!({}),
            CallClass::ReadOnly,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(
        slow_engine
            .call(
                "remoteDelete",
                json!({ "targetTimestamp": 350 }),
                CallClass::Mutating
            )
            .await,
        Err(EngineError::UnknownOutcome)
    );
    // The late fixture answer converges deterministically: it surfaces as a
    // dropped unknown id instead of resolving anything afterwards.
    assert_late_answer_dropped(&mut events).await;
    slow_engine.shutdown().await.unwrap();

    let (_temp, crashed_engine, _receives) = engine(Duration::from_secs(3)).await;
    assert_eq!(
        crashed_engine
            .call(
                "remoteDelete",
                json!({ "targetTimestamp": 421 }),
                CallClass::Mutating
            )
            .await,
        Err(EngineError::UnknownOutcome)
    );
    assert_eq!(crashed_engine.status().state, EngineState::Exited);
}

/// sendReaction is Mutating on both indeterminate paths: a slow answer past
/// the request timeout (fixture targetTimestamp 351, answered after 0.35s)
/// and a one-shot crash mid-call (fixture targetTimestamp 423) each resolve
/// to UnknownOutcome — never to a retryable timeout — so the supervisor can
/// surface the explicit `{"status":"unknown"}` response.
#[tokio::test]
async fn send_reaction_slow_answer_and_crash_are_unknown_outcomes() {
    let (_temp, slow_engine, _receives) = engine(Duration::from_millis(100)).await;
    let mut events = slow_engine.subscribe();
    // Warm the engine past the child's startup latency (a generous budget)
    // so the 100 ms deadline below measures the fixture's deliberate slow
    // answer, never the child's first-read time.
    slow_engine
        .call_with_timeout(
            "version",
            json!({}),
            CallClass::ReadOnly,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(
        slow_engine
            .call(
                "sendReaction",
                json!({ "targetTimestamp": 351 }),
                CallClass::Mutating
            )
            .await,
        Err(EngineError::UnknownOutcome)
    );
    // The late fixture answer converges deterministically: it surfaces as a
    // dropped unknown id instead of resolving anything afterwards.
    assert_late_answer_dropped(&mut events).await;
    slow_engine.shutdown().await.unwrap();

    let (_temp, crashed_engine, _receives) = engine(Duration::from_secs(3)).await;
    assert_eq!(
        crashed_engine
            .call(
                "sendReaction",
                json!({ "targetTimestamp": 423 }),
                CallClass::Mutating
            )
            .await,
        Err(EngineError::UnknownOutcome)
    );
    assert_eq!(crashed_engine.status().state, EngineState::Exited);
}

#[tokio::test]
async fn oversized_output_faults_runtime() {
    let temp = TempDir::new().unwrap();
    let mut config = EngineConfig::new(fixture(), temp.path().join("signal-data"));
    config.line_limit = 64;
    config.request_timeout = Duration::from_secs(3);
    config.shutdown_grace = Duration::from_millis(100);
    let (events, _) = event_channel();
    let (receive_ingress, _receives) = receive_channel();
    let engine = EngineHandle::start(config, events, receive_ingress)
        .await
        .unwrap();

    let result = engine
        .call("oversized", json!({}), CallClass::ReadOnly)
        .await;
    assert_eq!(result, Err(EngineError::Protocol));
    assert_eq!(engine.status().state, EngineState::Faulted);
}

#[tokio::test]
async fn pending_requests_apply_backpressure_at_the_hard_limit() {
    let (_temp, engine, _receives) = engine(Duration::from_millis(250)).await;
    let mut tasks = JoinSet::new();
    for _ in 0..129 {
        let engine = engine.clone();
        tasks.spawn(async move { engine.call("hang", json!({}), CallClass::ReadOnly).await });
    }

    let mut backpressure = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap() == Err(EngineError::Backpressure) {
            backpressure += 1;
        }
    }
    assert!(backpressure >= 1);
    engine.shutdown().await.unwrap();
}

/// Regression (optimization-plan A7): the actor used to write each request to
/// the child's stdin inline, so a signal-cli that stopped reading its stdin
/// parked the whole actor inside `write_all` — the stdout pump, the receive
/// ingress and the command lane stalled with it. The dedicated writer task
/// keeps the actor free: with the writer parked on a full pipe, a receive
/// notification still reaches the queue, and once the bounded write queue
/// fills, the next request answers Backpressure instead of hanging.
#[tokio::test]
async fn stalled_stdin_does_not_block_the_actor() {
    let (_temp, engine, mut receives) = engine(Duration::from_secs(20)).await;

    // Arm a receive notification that fires in 400 ms without reading stdin.
    engine
        .call(
            "armDelayedReceive",
            json!({ "delayMs": 400 }),
            CallClass::ReadOnly,
        )
        .await
        .unwrap();
    // Wedge the child: it answers this request, then stops reading stdin for
    // good while staying alive.
    engine
        .call("stallStdin", json!({}), CallClass::ReadOnly)
        .await
        .unwrap();

    // Oversized requests jam the pipe and then the bounded write queue: the
    // writer parks mid-frame on the full pipe holding one frame, the queue
    // holds STDIN_WRITE_QUEUE_CAPACITY more, and the child (sleeping, method
    // "hang") never answers the rest. Pigeonhole: with capacity + 4 calls at
    // least two must be refused on the spot once that in-flight budget is
    // exhausted — the queue is bounded, so admission fails fast instead of
    // parking the actor.
    let blob = "x".repeat(200 * 1024);
    let mut jammed = JoinSet::new();
    for _ in 0..(STDIN_WRITE_QUEUE_CAPACITY + 4) {
        let engine = engine.clone();
        let blob = blob.clone();
        jammed.spawn(async move {
            engine
                .call("hang", json!({ "blob": blob }), CallClass::Mutating)
                .await
        });
    }

    // The writer is parked on a full pipe, yet the actor still pumps stdout:
    // the armed receive must land while the stdin jam holds.
    let queued = timeout(Duration::from_secs(2), receives.recv())
        .await
        .expect("receive must arrive while stdin is stalled")
        .expect("receive channel must stay open");
    assert_eq!(queued.receive().timestamp, Some(42));

    engine.shutdown().await.unwrap();
    let mut backpressure = 0;
    while let Some(outcome) = jammed.join_next().await {
        match outcome.unwrap() {
            Err(EngineError::Backpressure) => backpressure += 1,
            Err(EngineError::UnknownOutcome) => {}
            other => panic!("unexpected jam outcome: {other:?}"),
        }
    }
    assert!(
        backpressure >= 2,
        "a full write queue must refuse admission, got {backpressure} refusals"
    );
}

/// Real-sidecar smoke for the experimental kt-engine mode (implementation
/// plan §5): drives the actual `kt-signal-engine` binary through this
/// crate's engine actor — spawn validation, stdio JSON-RPC round-trips, and
/// graceful shutdown. Gated so the hermetic test suite stays hermetic: run
/// it with the engine binary and its fake service selected, e.g.
///
/// ```text
/// KT_SMOKE_ENGINE_BIN=/path/to/kt-signal-engine KT_ENGINE_FAKE_SERVICE=1 \
///   cargo test --test engine_integration kt_engine_sidecar -- --nocapture
/// ```
///
/// Without `KT_SMOKE_ENGINE_BIN` (and the fake-service flag, which the child
/// inherits from this environment) the test returns immediately. Fake mode
/// keeps every round-trip offline; the real-service paths are exercised by
/// the engine repository's own contract suite.
#[tokio::test]
async fn kt_engine_sidecar_round_trips_over_the_engine_actor() {
    let Ok(bin) = std::env::var("KT_SMOKE_ENGINE_BIN") else {
        return;
    };
    if std::env::var("KT_ENGINE_FAKE_SERVICE").is_err() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let mut config = EngineConfig::new(PathBuf::from(bin), temp.path().join("signal-data"));
    config.shutdown_grace = Duration::from_secs(2);
    let (events, _) = event_channel();
    let (receive_ingress, _receives) = receive_channel();
    let engine = EngineHandle::start(config, events, receive_ingress)
        .await
        .expect("kt-signal-engine spawns");

    let accounts = engine
        .call("listAccounts", json!({}), CallClass::ReadOnly)
        .await
        .expect("listAccounts round-trips");
    assert_eq!(accounts, json!([]));

    let status = engine
        .call(
            "getUserStatus",
            json!({ "account": "+15559990000" }),
            CallClass::ReadOnly,
        )
        .await
        .expect("getUserStatus round-trips");
    assert_eq!(status, json!({ "isRegistered": true }));

    // Contract 1.74 (§4.65): the username read faces round-trip over the
    // engine actor — getUsername's fake never-set shape (both keys absent)
    // and usernameLookup's per-entry degraded array.
    let read = engine
        .call(
            "getUsername",
            json!({ "account": "+15559990000" }),
            CallClass::ReadOnly,
        )
        .await
        .expect("getUsername round-trips");
    assert_eq!(read, json!({}));
    let lookup = engine
        .call(
            "usernameLookup",
            json!({
                "account": "+15559990000",
                "usernames": ["kt_smoke.01"]
            }),
            CallClass::ReadOnly,
        )
        .await
        .expect("usernameLookup round-trips");
    assert_eq!(
        lookup,
        json!([{ "recipient": "kt_smoke.01", "isRegistered": false }])
    );

    // Contract 1.75 (§4.66): the write faces round-trip over the engine
    // actor — reserve adopts the bare nickname's candidate and carries a
    // hash, confirm lands the full link, delete answers {}.
    let reserved = engine
        .call(
            "usernameReserve",
            json!({ "account": "+15559990000", "username": "kt_smoke" }),
            CallClass::Mutating,
        )
        .await
        .expect("usernameReserve round-trips");
    let adopted = reserved["username"].as_str().expect("candidate");
    assert!(adopted.starts_with("kt_smoke."), "candidate: {adopted}");
    assert!(reserved["usernameHash"].is_string());
    let confirmed = engine
        .call(
            "usernameConfirm",
            json!({
                "account": "+15559990000",
                "username": adopted,
                "usernameHash": reserved["usernameHash"],
            }),
            CallClass::Mutating,
        )
        .await
        .expect("usernameConfirm round-trips");
    assert_eq!(confirmed["username"], json!(adopted));
    assert!(
        confirmed["usernameLink"]
            .as_str()
            .expect("link")
            .starts_with("https://signal.me/#eu/"),
        "link shape: {confirmed}"
    );
    let deleted = engine
        .call(
            "usernameDelete",
            json!({ "account": "+15559990000" }),
            CallClass::Mutating,
        )
        .await
        .expect("usernameDelete round-trips");
    assert_eq!(deleted, json!({}));

    // Contract 1.76 (§4.67): the story send face round-trips over the
    // engine actor — the write-back shape {timestamp, results}; the fake
    // service answers the empty per-recipient list (the honest offline
    // face).
    let story = engine
        .call(
            "sendStory",
            json!({
                "account": "+15559990000",
                "message": "smoke story",
                "recipients": ["+15551112222"],
                "allowsReplies": false,
            }),
            CallClass::Mutating,
        )
        .await
        .expect("sendStory round-trips");
    assert!(
        story
            .get("timestamp")
            .is_some_and(serde_json::Value::is_u64)
    );
    assert_eq!(story.get("results"), Some(&json!([])));

    let sent = engine
        .call(
            "send",
            json!({
                "account": "+15559990000",
                "recipient": "+15551112222",
                "message": "smoke"
            }),
            CallClass::Mutating,
        )
        .await
        .expect("send round-trips");
    assert!(sent.get("results").is_some(), "send mirrors the shape");

    engine.shutdown().await.expect("graceful shutdown");
    assert_eq!(engine.status().state, EngineState::Stopped);
}
