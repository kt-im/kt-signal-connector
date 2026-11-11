// SPDX-License-Identifier: AGPL-3.0-only

//! O1 engine contract handshake end to end (contract revision 1.285, section
//! 4.269): the connector asks a freshly started engine for its identity
//! (`version`) and contract revision (`engine.protocolCapabilities`), and
//! either serves it, degrades it (legacy engine), or refuses it with the
//! structured non-retryable fatal.
//!
//! The fixture rows are driven by the fake engine's environment
//! (tests/fixtures/fake-engine.py): a stated revision, a pre-face engine
//! (capabilities answers the upstream error class), and a version answer that
//! lands past the five-second probe budget. The connector child inherits the
//! environment the test sets on its own spawn, so no test process env is
//! mutated and the rows stay parallel-safe.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

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
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

/// One connector process with the test's fixture environment rows and its
/// stderr captured to a file (the fatal line's only launcher channel).
fn spawn_connector(
    root: &Path,
    endpoint: &Path,
    rows: &[(&str, &str)],
    stderr_path: &Path,
) -> Child {
    let secret_file = root.join("bootstrap.secret");
    let secret = [7_u8; 32];
    fs::write(
        &secret_file,
        format!("{}\n{}", hex::encode(secret), hex::encode(TEST_STORE_KEY)),
    )
    .unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let stderr = fs::File::create(stderr_path).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    for (key, value) in rows {
        command.env(key, value);
    }
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(endpoint)
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
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn wait_for_path(path: &Path) {
    timeout(Duration::from_secs(10), async {
        while !path.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("endpoint path must appear");
}

async fn authenticate(client: &mut Framed<UnixStream, LinesCodec>, secret: &[u8; 32]) {
    let challenge: Value = serde_json::from_str(
        &timeout(AUTH_TIMEOUT, client.next())
            .await
            .expect("challenge")
            .expect("challenge frame")
            .unwrap(),
    )
    .unwrap();
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
    let response: Value = serde_json::from_str(
        &timeout(AUTH_TIMEOUT, client.next())
            .await
            .expect("handshake response")
            .expect("handshake frame")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response["result"]["apiVersion"], API_VERSION);
}

async fn request(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) -> Value {
    timeout(REQUEST_TIMEOUT, async {
        client
            .send(
                json!({
                    "apiVersion": API_VERSION,
                    "requestId": request_id,
                    "method": method,
                    "params": params
                })
                .to_string(),
            )
            .await
            .unwrap();
        loop {
            let response: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if response.get("requestId").and_then(Value::as_str) == Some(request_id) {
                return response;
            }
        }
    })
    .await
    .expect("request round trip")
}

/// Poll the captured stderr until the needle appears (the connector keeps
/// serving after a refusal, so the process never exits to flush an EOF).
async fn stderr_contains(path: &Path, needle: &str, budget: Duration) -> bool {
    timeout(budget, async {
        loop {
            if fs::read_to_string(path)
                .map(|text| text.contains(needle))
                .unwrap_or(false)
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

async fn connect(
    temp: &TempDir,
    rows: &[(&str, &str)],
) -> (Child, Framed<UnixStream, LinesCodec>, PathBuf, PathBuf) {
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let stderr_path = temp.path().join("connector.stderr");
    let child = spawn_connector(temp.path(), &endpoint, rows, &stderr_path);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &[7_u8; 32]).await;
    (child, client, endpoint, stderr_path)
}

/// A matching engine contract starts normally and both halves of the verdict
/// reach the doctor face.
#[tokio::test]
async fn a_matching_engine_contract_starts_and_reaches_the_doctor() {
    let temp = TempDir::new().unwrap();
    let (_child, mut client, _endpoint, _stderr) =
        connect(&temp, &[("KT_FAKE_ENGINE_CONTRACT_REVISION", "1.285")]).await;

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    let report = request(&mut client, "doctor-1", "runtime.doctor", json!({})).await;
    let engine = &report["result"]["groups"][0]["engine"];
    assert_eq!(engine["engineVersion"], json!("0.1.0-fixture"));
    assert_eq!(engine["engineContractRevision"], json!("1.285"));
    assert_eq!(engine["engineContractStatus"], json!("match"));
    assert!(
        engine.get("engineContractReason").is_none(),
        "a matched handshake has no refusal reason"
    );
}

/// A revision outside the supported interval is the structured fatal: the
/// RPC answer is non-retryable, the launcher's byte-stable line rides stderr,
/// the engine never reaches the account pipeline, and a second start is
/// refused from the latch without re-probing.
#[tokio::test]
async fn a_contract_mismatch_is_a_structured_fatal_without_self_healing() {
    let temp = TempDir::new().unwrap();
    let (mut child, mut client, _endpoint, stderr_path) =
        connect(&temp, &[("KT_FAKE_ENGINE_CONTRACT_REVISION", "1.100")]).await;

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    let error = &started["error"];
    assert_eq!(error["code"], json!("ENGINE_CONTRACT_MISMATCH"));
    assert_eq!(error["retryable"], json!(false));
    assert_eq!(error["data"]["engine"], json!("0.1.0-fixture"));
    assert_eq!(error["data"]["supported"], json!("1.200-1.285"));
    assert_eq!(error["data"]["reason"], json!("revision_out_of_range"));
    assert!(
        stderr_contains(
            &stderr_path,
            "KT_FATAL code=ENGINE_CONTRACT_MISMATCH retryable=false engine=0.1.0-fixture \
             supported=1.200-1.285",
            Duration::from_secs(10),
        )
        .await,
        "the launcher's fixed fatal line must ride stderr"
    );

    // Not self-healing: the same start answers the latched fault at once,
    // with no second engine spawn or probe budget.
    let began = Instant::now();
    let again = request(&mut client, "start-2", "runtime.start", json!({})).await;
    assert_eq!(again["error"]["code"], json!("ENGINE_CONTRACT_MISMATCH"));
    assert_eq!(again["error"]["retryable"], json!(false));
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "a latched mismatch must not spend the probe budget again: {:?}",
        began.elapsed()
    );

    // The refusal is diagnosable: the killed engine is not running, the
    // verdict and the stated revision stay visible.
    let report = request(&mut client, "doctor-1", "runtime.doctor", json!({})).await;
    let engine = &report["result"]["groups"][0]["engine"];
    assert_eq!(engine["reachable"], json!(false));
    assert_eq!(engine["engineContractStatus"], json!("mismatch"));
    assert_eq!(engine["engineVersion"], json!("0.1.0-fixture"));
    assert_eq!(engine["engineContractRevision"], json!("1.100"));
    assert_eq!(
        engine["engineContractReason"],
        json!("revision_out_of_range")
    );

    // No engine child survived the refusal.
    let status = request(&mut client, "status-1", "runtime.status", json!({})).await;
    assert_eq!(status["result"]["state"], json!("stopped"));

    let _ = child.start_kill();
}

/// A `version` answer past the five-second budget is a retryable startup
/// failure: no fatal line, no latch, and the honest unreachable doctor face.
#[tokio::test]
async fn a_version_probe_timeout_is_retryable() {
    let temp = TempDir::new().unwrap();
    let (_child, mut client, _endpoint, stderr_path) =
        connect(&temp, &[("KT_FAKE_ENGINE_VERSION_DELAY_MS", "9000")]).await;

    let began = Instant::now();
    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    let elapsed = began.elapsed();
    assert_eq!(started["error"]["code"], json!("RUNTIME_START_FAILED"));
    assert_eq!(started["error"]["retryable"], json!(true));
    assert!(
        elapsed >= Duration::from_millis(4500),
        "the probe must spend its five-second budget before failing: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(9),
        "the probe must fail on its own deadline, not the engine's late answer: {elapsed:?}"
    );
    // A retryable failure is not a contract verdict: no fatal line, no latch.
    assert!(
        !stderr_contains(
            &stderr_path,
            "KT_FATAL code=ENGINE_CONTRACT_MISMATCH",
            Duration::from_millis(500),
        )
        .await,
        "a probe timeout must not emit the mismatch fatal"
    );
    let report = request(&mut client, "doctor-1", "runtime.doctor", json!({})).await;
    let engine = &report["result"]["groups"][0]["engine"];
    assert_eq!(engine["engineContractStatus"], json!("unreachable"));
    assert!(engine.get("engineContractRevision").is_none());
}

/// The handshake has no environment bypass. `KT_DISABLE_CONTRACT_PROBE` was
/// an escape hatch that turned the gate off process-wide; a production switch
/// that skips the one check standing between an unverified engine and the
/// account pipeline is drift, not debugging. Both arms prove the variable is
/// inert now: a matching engine is still probed and recorded, and an
/// out-of-range engine is still the non-retryable fatal. Debugging goes through
/// the fake engine's own fixture parameters (the `KT_FAKE_ENGINE_*` rows),
/// never through a shipping env switch.
#[tokio::test]
async fn the_removed_probe_bypass_env_cannot_skip_the_handshake() {
    // Arm 1: the probe still runs — the verdict reaches the doctor.
    let matching = TempDir::new().unwrap();
    let (_child, mut client, _endpoint, _stderr) = connect(
        &matching,
        &[
            ("KT_DISABLE_CONTRACT_PROBE", "1"),
            ("KT_FAKE_ENGINE_CONTRACT_REVISION", "1.285"),
        ],
    )
    .await;
    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], json!("running"));
    let report = request(&mut client, "doctor-1", "runtime.doctor", json!({})).await;
    let engine = &report["result"]["groups"][0]["engine"];
    assert_eq!(
        engine["engineContractStatus"],
        json!("match"),
        "the removed bypass must not skip the probe: {report}"
    );
    assert_eq!(engine["engineContractRevision"], json!("1.285"));

    // Arm 2: the refusal is not softened either.
    let mismatched = TempDir::new().unwrap();
    let (mut child, mut client, _endpoint, _stderr) = connect(
        &mismatched,
        &[
            ("KT_DISABLE_CONTRACT_PROBE", "1"),
            ("KT_FAKE_ENGINE_CONTRACT_REVISION", "1.100"),
        ],
    )
    .await;
    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["error"]["code"], json!("ENGINE_CONTRACT_MISMATCH"));
    assert_eq!(started["error"]["retryable"], json!(false));
    assert_eq!(
        started["error"]["data"]["reason"],
        json!("revision_out_of_range")
    );
    let _ = child.start_kill();
}

/// An engine that predates the self-certification face keeps working: the
/// identity is enough, the verdict is `legacy`, and no revision is invented.
#[tokio::test]
async fn a_legacy_engine_without_capabilities_degrades() {
    let temp = TempDir::new().unwrap();
    let (_child, mut client, _endpoint, _stderr) =
        connect(&temp, &[("KT_FAKE_ENGINE_NO_CAPABILITIES", "1")]).await;

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], json!("running"));

    let report = request(&mut client, "doctor-1", "runtime.doctor", json!({})).await;
    let engine = &report["result"]["groups"][0]["engine"];
    assert_eq!(engine["engineVersion"], json!("0.1.0-fixture"));
    assert_eq!(engine["engineContractStatus"], json!("legacy"));
    assert!(
        engine.get("engineContractRevision").is_none(),
        "a legacy engine states no revision, and none is invented"
    );
    assert!(engine.get("engineContractReason").is_none());
}
