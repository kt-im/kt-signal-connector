// SPDX-License-Identifier: AGPL-3.0-only

//! Rotating link attempts over the real runtime + fake engine (connector
//! contract 1.286, §4.272).
//!
//! The dual-slot face is exercised end to end:
//!
//! - two rotations leave two live codes and the third one retires the oldest;
//! - any live code finishes the attempt, and it commits exactly once — the
//!   other codes replay the same account instead of minting a second binding;
//! - a code a rotation retired still routes: a new finish on it answers the
//!   definite LINK_LOST, never LINK_NOT_FOUND — the dispatch face — while the
//!   last bullet covers the commit face;
//! - an engine without the rotate face degrades to NOT_SUPPORTED while the
//!   single slot keeps working, and an engine that states a rotate key but
//!   answers the method as unknown folds into the same NOT_SUPPORTED;
//! - a rotation while a finish is in flight never clears the finish lane (a
//!   duplicate finish still answers LINK_IN_PROGRESS and the cancel still
//!   reaches the parked call);
//! - a rotation that retires the very code `finishLink` was dispatched with
//!   still commits the engine's success (the commit gate accepts Retired; only
//!   the dispatch gate folds it into LINK_LOST), so one account row exists and
//!   every code of the attempt replays it.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tempfile::TempDir;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tokio_util::codec::{Framed, LinesCodec};

const API_VERSION: &str = "1.0";
const HARNESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const HARNESS_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn bootstrap_payload(secret: &[u8; 32]) -> String {
    format!("{}\n{}", hex::encode(secret), hex::encode(TEST_STORE_KEY))
}

/// One connector + a fake engine. `rotate_mode` drives the fixture's rotate
/// face: `None` is the rotate-capable default, `"0"` a pre-rotate engine,
/// `"method_not_found"` an engine that states a key but answers -32601.
async fn spawn(root: &Path, rotate_mode: Option<&str>) -> (Child, Framed<UnixStream, LinesCodec>) {
    let endpoint = root.join("connector.sock");
    let secret_file = root.join("bootstrap.secret");
    let secret = [7_u8; 32];
    fs::write(&secret_file, bootstrap_payload(&secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--signal-data-dir")
        .arg(root.join("signal-data"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_FAKE_EXPECT_NO_JAVA", "1");
    if let Some(mode) = rotate_mode {
        command.env("KT_FAKE_LINK_ROTATE", mode);
    }
    let child = command.spawn().unwrap();
    timeout(Duration::from_secs(3), async {
        while !endpoint.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("connector socket should appear");
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    (child, client)
}

/// Spawn the connector and start the runtime (link.start needs a live engine
/// slot).
async fn spawn_running(
    root: &Path,
    rotate_mode: Option<&str>,
) -> (Child, Framed<UnixStream, LinesCodec>) {
    let (child, mut client) = spawn(root, rotate_mode).await;
    let started = request(&mut client, "runtime-start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running", "{started}");
    (child, client)
}

async fn authenticate(client: &mut Framed<UnixStream, LinesCodec>, secret: &[u8; 32]) {
    let challenge: Value = timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    .expect("authentication challenge should arrive");
    let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
    let client_nonce = hex::encode([9_u8; 32]);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(b"kt-signal-connector-v1\0");
    mac.update(server_nonce.as_bytes());
    mac.update(b"\0");
    mac.update(client_nonce.as_bytes());
    mac.update(b"\0");
    mac.update(API_VERSION.as_bytes());
    let proof = hex::encode(mac.finalize().into_bytes());
    client
        .send(
            json!({
                "apiVersion": API_VERSION,
                "requestId": "handshake-1",
                "method": "handshake",
                "params": { "clientNonce": client_nonce, "proof": proof }
            })
            .to_string(),
        )
        .await
        .unwrap();
    let response: Value = timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    .expect("handshake response should arrive");
    assert_eq!(response["result"]["apiVersion"], API_VERSION);
    assert!(
        response["result"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "link.rotate"),
        "the rotate face is advertised: {response}"
    );
}

async fn request(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) -> Value {
    send_frame(client, request_id, method, params).await;
    await_response(client, request_id).await
}

async fn send_frame(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) {
    timeout(
        HARNESS_REQUEST_TIMEOUT,
        client.send(
            json!({
                "apiVersion": API_VERSION,
                "requestId": request_id,
                "method": method,
                "params": params
            })
            .to_string(),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("frame write {request_id} ({method}) stalled"))
    .unwrap();
}

async fn await_response(client: &mut Framed<UnixStream, LinesCodec>, request_id: &str) -> Value {
    timeout(HARNESS_REQUEST_TIMEOUT, async {
        loop {
            let response: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if response.get("requestId").and_then(Value::as_str) == Some(request_id) {
                return response;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("response {request_id} should arrive"))
}

/// Wait until the fixture has logged one engine dispatch of `method`. The
/// fixture logs every request it reads into the group data dir (the default
/// group's data dir is the `--signal-data-dir` root), so a test can order a
/// rotation after a `finishLink` dispatch without a wall-clock guess.
async fn wait_for_engine_method(root: &Path, method: &str) {
    let log = root
        .join("signal-data")
        .join("logs")
        .join("engine-stderr.log");
    let needle = format!("method={method}");
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(text) = fs::read_to_string(&log)
                && text.lines().any(|line| line == needle.as_str())
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the fixture should log the {method} dispatch"));
}

/// Start a link and return (client, attempt id, slot-0 session id, slot-0 code).
async fn start_link(
    client: &mut Framed<UnixStream, LinesCodec>,
    device_name: &str,
) -> (String, String, String) {
    let started = request(
        client,
        "link-start",
        "link.start",
        json!({ "deviceName": device_name }),
    )
    .await;
    let result = &started["result"];
    let attempt = result["linkAttemptId"]
        .as_str()
        .unwrap_or_else(|| panic!("link.start should answer an attempt id: {started}"))
        .to_string();
    let session = result["linkSessionId"].as_str().unwrap().to_string();
    let code = result["deviceLinkUri"]
        .as_str()
        .unwrap_or_else(|| panic!("link.start should answer deviceLinkUri: {started}"))
        .to_string();
    assert_eq!(result["qrPayload"], code, "slot 0 answers both names");
    assert_eq!(
        result["slots"],
        json!([{ "deviceLinkUri": code, "slot": 0 }])
    );
    (attempt, session, code)
}

#[tokio::test]
async fn rotating_twice_keeps_two_slots_and_the_third_retires_the_oldest() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (_connector, mut client) = spawn_running(temp.path(), None).await;
    let (attempt, slot0_session, slot0_code) = start_link(&mut client, "KT-Rotate").await;

    let first = request(
        &mut client,
        "rotate-1",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(first["result"]["slot"], 1, "{first}");
    assert_eq!(first["result"]["slots"].as_array().unwrap().len(), 2);
    let slot1_session = first["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();
    let slot1_code = first["result"]["deviceLinkUri"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(slot1_code, slot0_code);

    let second = request(
        &mut client,
        "rotate-2",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(second["result"]["slot"], 2, "{second}");
    let slots = second["result"]["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 2, "never more than two live codes: {second}");
    assert_eq!(slots[0]["slot"], 1);
    assert_eq!(slots[1]["slot"], 2);
    assert!(
        slots.iter().all(|slot| slot["deviceLinkUri"] != slot0_code),
        "the retired code is no longer offered: {second}"
    );
    let slot2_session = second["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();

    // Dispatch face: the retired code still routes, so a *new* finish on it
    // answers the definite LINK_LOST before any engine call — never
    // LINK_NOT_FOUND. The commit face is the other side of this seam and is
    // deliberately different: a finish already in flight when the code was
    // retired still commits the engine's success (§4.272; see
    // `a_rotation_that_retires_the_finish_code_keeps_the_engine_success`).
    let retired = request(
        &mut client,
        "finish-retired",
        "link.finish",
        json!({ "linkSessionId": slot0_session }),
    )
    .await;
    assert_eq!(retired["error"]["code"], "LINK_LOST", "{retired}");
    assert_eq!(retired["error"]["retryable"], true);
    assert_ne!(retired["error"]["code"], "LINK_NOT_FOUND");

    // Any live code finishes the attempt, and it commits exactly once.
    let finished = request(
        &mut client,
        "finish-slot1",
        "link.finish",
        json!({ "linkSessionId": slot1_session }),
    )
    .await;
    assert_eq!(finished["result"]["state"], "ready", "{finished}");
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    let replay = request(
        &mut client,
        "finish-slot2",
        "link.finish",
        json!({ "linkSessionId": slot2_session }),
    )
    .await;
    assert_eq!(replay["result"]["id"], account_id, "{replay}");
    let accounts = request(&mut client, "accounts", "accounts.list", json!({})).await;
    assert_eq!(
        accounts["result"].as_array().unwrap().len(),
        1,
        "the attempt committed once: {accounts}"
    );
}

/// A pre-rotate engine states no rotate key: link.start answers a connector
/// attempt id with one slot, rotation answers NOT_SUPPORTED, and the single
/// slot still finishes.
#[tokio::test]
async fn a_pre_rotate_engine_degrades_to_the_single_slot() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (_connector, mut client) = spawn_running(temp.path(), Some("0")).await;
    let (attempt, session, _code) = start_link(&mut client, "KT-Old-Engine").await;

    let refused = request(
        &mut client,
        "rotate-old",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "NOT_SUPPORTED", "{refused}");
    assert_eq!(refused["error"]["retryable"], false);

    let finished = request(
        &mut client,
        "finish-old",
        "link.finish",
        json!({ "linkSessionId": session }),
    )
    .await;
    assert_eq!(finished["result"]["state"], "ready", "{finished}");
}

/// An engine that states a rotate key but answers the method as unknown
/// (JSON-RPC -32601) folds into the same NOT_SUPPORTED answer.
#[tokio::test]
async fn an_engine_without_the_rotate_method_folds_to_not_supported() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (_connector, mut client) = spawn_running(temp.path(), Some("method_not_found")).await;
    let (attempt, session, _code) = start_link(&mut client, "KT-No-Method").await;
    let refused = request(
        &mut client,
        "rotate-missing",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "NOT_SUPPORTED", "{refused}");

    let finished = request(
        &mut client,
        "finish-after-refusal",
        "link.finish",
        json!({ "linkSessionId": session }),
    )
    .await;
    assert_eq!(finished["result"]["state"], "ready", "{finished}");
}

/// Contract 1.286 (§4.272): a rotation while finishLink is parked must not
/// clear the finish lane — the duplicate finish still answers LINK_IN_PROGRESS
/// and the cancel still reaches the parked call.
#[tokio::test]
async fn a_finish_in_flight_survives_a_rotation() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (_connector, mut client) = spawn_running(temp.path(), None).await;
    let (attempt, session, _code) = start_link(&mut client, "[slow-link-test]").await;

    // The fixture never answers finishLink for this device name: the call
    // parks on the phone-approval wait until the cancel arrives.
    send_frame(
        &mut client,
        "slow-finish",
        "link.finish",
        json!({ "linkSessionId": session }),
    )
    .await;
    sleep(Duration::from_millis(100)).await;

    let rotated = request(
        &mut client,
        "rotate-during-finish",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(rotated["result"]["slot"], 1, "{rotated}");

    let duplicate = request(
        &mut client,
        "duplicate-finish",
        "link.finish",
        json!({ "linkSessionId": session }),
    )
    .await;
    assert_eq!(
        duplicate["error"]["code"], "LINK_IN_PROGRESS",
        "the rotation must leave the finish lane taken: {duplicate}"
    );

    send_frame(
        &mut client,
        "cancel-finish",
        "link.cancel",
        json!({ "linkSessionId": session }),
    )
    .await;
    let mut cancelled = false;
    let mut cancel_answered = false;
    timeout(Duration::from_secs(5), async {
        while !cancelled || !cancel_answered {
            let response: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            match response.get("requestId").and_then(Value::as_str) {
                Some("slow-finish") => {
                    assert_eq!(response["error"]["code"], "LINK_CANCELLED");
                    cancelled = true;
                }
                Some("cancel-finish") => {
                    assert!(response.get("result").is_some());
                    cancel_answered = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the cancel must reach the parked finish");
}

/// Review must-fix (contract 1.286, §4.272): a rotation that retires the very
/// code `finishLink` was dispatched with must not fold the engine's success
/// into LINK_LOST. Start slot 0 → rotate slot 1 → finish(slot 0) in flight →
/// rotate slot 2 retires slot 0 → the engine approves → the commit owns that
/// success: one account row, the attempt committed, and every code of the
/// attempt replays the same account.
#[tokio::test]
async fn a_rotation_that_retires_the_finish_code_keeps_the_engine_success() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (_connector, mut client) = spawn_running(temp.path(), None).await;
    let (attempt, slot0_session, _slot0_code) =
        start_link(&mut client, "[deferred-link-test]").await;

    // Slot 1: two live codes, nothing retired yet.
    let first = request(
        &mut client,
        "rotate-1",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(first["result"]["slot"], 1, "{first}");
    let slot1_session = first["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(first["result"]["slots"].as_array().unwrap().len(), 2);

    // The phone approves slot 0's code; the fixture parks its answer, so this
    // finish is genuinely in flight.
    send_frame(
        &mut client,
        "inflight-finish",
        "link.finish",
        json!({ "linkSessionId": slot0_session }),
    )
    .await;
    wait_for_engine_method(temp.path(), "finishLink").await;

    // Slot 2 retires slot 0 while that finish is still parked.
    let second = request(
        &mut client,
        "rotate-2",
        "link.rotate",
        json!({ "linkAttemptId": attempt.clone() }),
    )
    .await;
    assert_eq!(second["result"]["slot"], 2, "{second}");
    let slot2_session = second["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();
    let slots = second["result"]["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 2, "never more than two live codes: {second}");
    assert_eq!(slots[0]["slot"], 1, "{second}");
    assert_eq!(slots[1]["slot"], 2, "{second}");
    assert!(
        slots.iter().all(|slot| slot["slot"] != 0),
        "slot 0 was retired by this rotation: {second}"
    );

    // Release the parked approval: the engine's success now arrives with slot 0
    // already Retired in the connector, which is exactly the seam this fixes.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-release-finish"),
        b"release",
    )
    .unwrap();
    let finished = await_response(&mut client, "inflight-finish").await;
    assert!(
        finished.get("error").is_none(),
        "the retired code's engine success must commit, not answer LINK_LOST: {finished}"
    );
    assert_eq!(finished["result"]["state"], "ready", "{finished}");
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The attempt took its single commit: rotation now refuses.
    let after_commit = request(
        &mut client,
        "rotate-after-commit",
        "link.rotate",
        json!({ "linkAttemptId": attempt }),
    )
    .await;
    assert_eq!(
        after_commit["error"]["code"], "INVALID_REQUEST",
        "{after_commit}"
    );
    assert!(
        after_commit["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("committed"),
        "the attempt answers as committed: {after_commit}"
    );

    // One account row — no second binding from the retired code.
    let accounts = request(&mut client, "accounts", "accounts.list", json!({})).await;
    let rows = accounts["result"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "the attempt committed once: {accounts}");
    assert_eq!(rows[0]["id"], account_id, "{accounts}");

    // Every code of the attempt replays that account: the retired one first.
    for (request_id, session) in [
        ("replay-slot0", &slot0_session),
        ("replay-slot1", &slot1_session),
        ("replay-slot2", &slot2_session),
    ] {
        let replay = request(
            &mut client,
            request_id,
            "link.finish",
            json!({ "linkSessionId": session }),
        )
        .await;
        assert_eq!(replay["result"]["id"], account_id, "{request_id}: {replay}");
    }
    let after_replay = request(
        &mut client,
        "accounts-after-replay",
        "accounts.list",
        json!({}),
    )
    .await;
    assert_eq!(
        after_replay["result"].as_array().unwrap().len(),
        1,
        "a replay mints nothing: {after_replay}"
    );
}
