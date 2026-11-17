// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end coverage for the read-only `runtime.doctor` face (contract
//! revision 1.97 §4.79, credential face 1.101): the whole payload over a
//! real authenticated socket against the fake engine — the version chain
//! (both engine faces ride the fake's own answers through verbatim; the fake
//! echoes any method it does not know, so both arrive `present`, and the
//! unit suite pins the honest `absent`-with-reason side), the data-dir and
//! lock faces (the connector holds its own occupancy locks, so `held` with
//! its own pid), the recent-error ring fed by real failed dispatches, the
//! Signal service-plane face (field presence in the whole-payload answer;
//! the `not_configured` path over the wire with the proxy environment
//! removed), and the per-group credential face (the healthy literal in the
//! whole-payload answer; the `credentialsInvalid` literal with the fixture's
//! unlink signature planted). The unit suite in
//! `src/doctor.rs` pins the pure halves — structure, unreachable
//! degradation, the three lock forms, the read-only discipline, and the
//! service-probe and credential-state classification literals.

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
use tokio::process::Child;
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use tokio_util::codec::{Framed, LinesCodec};

const API_VERSION: &str = "1.0";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn spawn_connector(root: &Path, endpoint: &Path) -> Child {
    spawn_connector_inner(root, endpoint, false)
}

/// A connector booted without the launcher's proxy environment: the doctor's
/// service-plane face must answer `not_configured` without any attempt.
fn spawn_connector_without_proxy_env(root: &Path, endpoint: &Path) -> Child {
    spawn_connector_inner(root, endpoint, true)
}

fn spawn_connector_inner(root: &Path, endpoint: &Path, remove_proxy_env: bool) -> Child {
    let secret_file = root.join("bootstrap.secret");
    let secret = [7_u8; 32];
    fs::write(
        &secret_file,
        format!("{}\n{}", hex::encode(secret), hex::encode(TEST_STORE_KEY)),
    )
    .unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    if remove_proxy_env {
        command.env_remove("KT_SIGNAL_SOCKS_PROXY");
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
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn wait_for_path(path: &Path) {
    // Cold starts on a loaded machine can exceed a couple of seconds; the
    // handshake timeout below is already 30s, so give the bind the same
    // order of headroom instead of flaking on the first poll window.
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

/// The whole doctor payload over the wire: the version chain with the fake
/// engine live (the fake echoes any method it does not know, so both engine
/// faces arrive `present` with their verbatim answers — the `absent` with
/// reason half is pinned by the unit suite), the connector's own lock
/// reported held with its own pid, and real failed dispatches feeding the
/// ring.
#[tokio::test]
async fn doctor_reports_versions_data_dir_lock_errors_and_reachability() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret = [7_u8; 32];
    let mut connector = spawn_connector(temp.path(), &endpoint);
    wait_for_path(&endpoint).await;

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    // Materialize the group's account row (the engine's listAccounts sync)
    // so the credentials probe has its target.
    let accounts = request(&mut client, "accounts-1", "accounts.list", json!({})).await;
    assert!(
        accounts["result"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "the fake engine reports one linked account"
    );

    let empty = request(
        &mut client,
        "doctor-params",
        "runtime.doctor",
        json!({"extra": 1}),
    )
    .await;
    assert_eq!(empty["error"]["code"], "INVALID_REQUEST");

    // One real failed dispatch to feed the recent-error ring.
    let seeded = request(
        &mut client,
        "seed-1",
        "accounts.list",
        json!({"bogus": true}),
    )
    .await;
    assert_eq!(seeded["error"]["code"], "INVALID_REQUEST");

    let report = request(&mut client, "doctor-1", "runtime.doctor", json!({})).await;
    let result = &report["result"];

    let connector_face = &result["connector"];
    assert!(
        connector_face["version"]
            .as_str()
            .is_some_and(|version| !version.is_empty()),
        "connector version present"
    );
    assert_eq!(connector_face["apiVersion"], json!(API_VERSION));
    assert!(connector_face["pid"].is_u64());

    // Contract revision 1.282 (§4.266): the store face rides every payload —
    // the schema version next to its target, the integrity verdict of this
    // process (a first start migrates nothing, so no gate ran), the file
    // sizes, and the snapshot outcome. A healthy start reports no failure.
    let store = &result["store"];
    assert_eq!(
        store["schemaVersion"],
        json!(kt_signal_connector::store::SCHEMA_VERSION)
    );
    assert_eq!(
        store["schemaTarget"],
        json!(kt_signal_connector::store::SCHEMA_VERSION)
    );
    assert_eq!(store["integrity"], json!("notChecked"));
    assert!(
        store["dbBytes"].as_u64().is_some_and(|bytes| bytes > 0),
        "the store file exists and its size is reported"
    );
    assert!(store["walBytes"].is_u64());
    assert_eq!(store["snapshots"]["count"], json!(0));
    assert_eq!(store["snapshots"]["lastResult"], json!("notNeeded"));
    assert!(
        store.get("lastMigrationFailure").is_none(),
        "a healthy start has no migration failure to report"
    );
    // Contract revision 1.284 (§4.268): no start has refused this state
    // directory, so the newer-schema record is absent — not a fabricated
    // "false" object.
    assert!(
        store.get("schemaNewer").is_none(),
        "a healthy start has no refused-open record"
    );

    // Contract revision 1.283 (§4.267): the event ledger's face — a fresh
    // store seeds generation 1 at floor 0 with an empty ledger, and the token
    // itself never rides the diagnostic payload.
    let events = &result["events"];
    assert_eq!(events["readable"], json!(true));
    assert_eq!(events["tokenGeneration"], json!(1));
    assert_eq!(events["trimmedThroughSeq"], json!(0));
    assert_eq!(events["seqMax"], json!(0));
    assert_eq!(events["rows"], json!(0));
    assert_eq!(events["bytes"], json!(0));
    assert!(
        events.get("token").is_none(),
        "the ledger token never reaches doctor",
    );
    assert_eq!(
        events["retention"]["maxRows"],
        json!(kt_signal_connector::store::EVENT_LOG_MAX_ROWS)
    );
    assert_eq!(
        events["retention"]["maxBytes"],
        json!(kt_signal_connector::store::EVENT_LOG_MAX_BYTES)
    );

    let group = &result["groups"][0];
    assert_eq!(group["groupId"], json!("default"));

    let engine = &group["engine"];
    assert_eq!(engine["state"], json!("running"));
    assert_eq!(engine["reachable"], json!(true));
    assert!(engine["pid"].is_u64());
    assert!(engine.get("unreachableReason").is_none());
    // The fake engine carries `version` — the connector passes the answer
    // through verbatim instead of re-deriving it.
    let version = &engine["version"];
    assert_eq!(version["present"], json!(true));
    assert!(version["face"].is_object(), "engine answer rides verbatim");
    // The fake is signal-cli-shaped: its fallback answers any method it does
    // not implement by echoing `{method}`, so the doctor sees a carried
    // self-certification face and rides the answer through verbatim. The two
    // forms are mutually exclusive by contract: either the engine answered
    // (present, the answer verbatim) or it did not (absent, with a reason).
    let capabilities = &engine["protocolCapabilities"];
    if capabilities["present"] == json!(true) {
        assert!(
            capabilities["face"].is_object(),
            "a carried face answers verbatim"
        );
    } else {
        assert_eq!(capabilities["present"], json!(false));
        assert!(
            capabilities["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "the unavailable self-certification face carries its reason"
        );
    }

    // Contract revision 1.133 (§4.116): the engine.perfMetrics probe rides
    // the same reachability gate — present with a whitelist-projected face
    // (never the verbatim passthrough; unknown keys drop and count), or
    // absent with the same reason family. The fake engine echoes
    // `{method}` for methods it does not implement, so the projection here
    // is exactly the lossy-but-honest case: one unknown key dropped, only
    // `connectorDroppedKeys` surviving.
    let perf = &engine["perfMetrics"];
    if perf["present"] == json!(true) {
        let face = perf["face"].as_object().expect("projected face object");
        assert!(
            face.contains_key("connectorDroppedKeys"),
            "the projection always carries its drop count"
        );
        assert_eq!(face["connectorDroppedKeys"].as_u64(), Some(1));
    } else {
        assert_eq!(perf["present"], json!(false));
        assert!(
            perf["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "the unavailable perf-metrics face carries its reason"
        );
    }

    let data_dir = &group["dataDir"];
    assert_eq!(data_dir["exists"], json!(true));
    assert_eq!(data_dir["writable"], json!(true));
    assert!(
        data_dir["freeBytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert!(
        data_dir["totalBytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert!(
        data_dir["path"]
            .as_str()
            .is_some_and(|path| !path.is_empty())
    );

    // The connector holds its own plan locks for process lifetime: held,
    // with the pid it wrote at acquire time — its own.
    let lock = &group["lock"];
    assert_eq!(lock["present"], json!(true));
    assert_eq!(lock["held"], json!(true));
    assert_eq!(lock["classification"], json!("held"));
    assert_eq!(lock["holderAlive"], json!(true));
    assert_eq!(lock["pid"], connector_face["pid"]);

    let recent = &result["recentErrors"];
    assert_eq!(recent["window"], json!(64));
    assert!(
        recent["recordedTotal"]
            .as_u64()
            .is_some_and(|total| total >= 2)
    );
    let invalid = recent["families"]
        .as_array()
        .unwrap()
        .iter()
        .find(|family| family["family"] == "INVALID_REQUEST")
        .expect("the seeded dispatch failure feeds the ring");
    assert_eq!(invalid["source"], json!("host"));
    assert_eq!(invalid["retryable"], json!(false));
    assert!(invalid["count"].as_u64().is_some_and(|count| count >= 2));

    let network = &result["network"];
    assert!(network["watchdogRestartsTotal"].is_u64());
    assert!(network["receiveDroppedTotal"].is_u64());

    // The service-plane face (revision 1.97): fixed classification literals
    // only; `status`/`latencyMs` ride exclusively with `http`. The
    // environment here is whatever the test host exported, so only the
    // contract shape is pinned, not a specific classification. The 1.163
    // system-trust leg is additive and environment-tolerant: present exactly
    // when a proxy was configured, riding the same literal family and the
    // same status/latency discipline.
    let service = &result["service"];
    assert!(service["proxyConfigured"].is_boolean());
    let literals = [
        "not_configured",
        "socks_refused",
        "tls_failed",
        "http",
        "timeout",
    ];
    for probe in ["chat", "storage"] {
        let classification = service[probe]["classification"]
            .as_str()
            .unwrap_or_default();
        assert!(
            literals.contains(&classification),
            "{probe} classification must be a contract literal, got {classification:?}"
        );
        if classification == "http" {
            assert!(service[probe]["status"].is_u64());
            assert!(service[probe]["latencyMs"].is_u64());
        } else {
            assert_eq!(
                service[probe].get("status"),
                None,
                "{probe}: status rides only with http"
            );
            assert_eq!(
                service[probe].get("latencyMs"),
                None,
                "{probe}: latencyMs rides only with http"
            );
        }
    }
    match service
        .as_object()
        .expect("service face")
        .get("systemTrust")
    {
        Some(system_trust) => {
            assert!(
                service["proxyConfigured"] == json!(true),
                "the system-trust leg is present only on the configured face"
            );
            let classification = system_trust["classification"].as_str().unwrap_or_default();
            assert!(
                literals.contains(&classification),
                "systemTrust classification must be a contract literal, got {classification:?}"
            );
            if classification == "http" {
                assert!(system_trust["status"].is_u64());
                assert!(system_trust["latencyMs"].is_u64());
            } else {
                assert_eq!(system_trust.get("status"), None);
                assert_eq!(system_trust.get("latencyMs"), None);
            }
        }
        None => {
            assert!(
                service["proxyConfigured"] == json!(false),
                "an absent system-trust leg is the unconfigured face only"
            );
        }
    }

    // The per-group credential face (revision 1.101): the fake engine
    // answers `getUserStatus` with the registered face here, so the probe
    // folds to the healthy literal — and the face carries no probe-target
    // trace.
    let credentials = &group["credentials"];
    assert_eq!(credentials["state"], json!("healthy"));
    assert!(credentials.get("account").is_none());

    drop(client);
    let _ = connector.kill().await;
}

/// The credential-death path over the wire (contract revision 1.101): with
/// the fixture's auth-failure marker planted, the group's `getUserStatus`
/// probe answers the unlink face, the connector's classifier folds it to
/// `EngineError::Unauthorized`, and the doctor reports the independent
/// `credentialsInvalid` state — the credential layer the unauthenticated
/// service probes cannot see.
#[tokio::test]
async fn doctor_credentials_face_reports_credentials_invalid_on_auth_failure() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret = [7_u8; 32];
    let mut connector = spawn_connector(temp.path(), &endpoint);
    wait_for_path(&endpoint).await;

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    // Materialize the group's account row so the probe has a target, then
    // plant the unlink signature.
    let accounts = request(&mut client, "accounts-1", "accounts.list", json!({})).await;
    assert!(
        accounts["result"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "the fake engine reports one linked account"
    );
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-auth-failed-user-status"),
        "",
    )
    .unwrap();

    let report = request(&mut client, "doctor-cred", "runtime.doctor", json!({})).await;
    let group = &report["result"]["groups"][0];
    assert_eq!(group["credentials"]["state"], json!("credentialsInvalid"));

    drop(client);
    let _ = connector.kill().await;
}

/// The unconfigured service-plane path over the wire: a connector booted
/// without the launcher proxy environment answers `proxyConfigured: false`
/// and both probes `not_configured`, with no `status`/`latencyMs` anywhere —
/// the only path where the doctor deliberately never touches the network.
/// The 1.163 system-trust leg stays absent on this face: no probe ran, and
/// absence (not a literal) is how the wire says so.
#[tokio::test]
async fn doctor_service_face_answers_not_configured_without_proxy_env() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret = [7_u8; 32];
    let mut connector = spawn_connector_without_proxy_env(temp.path(), &endpoint);
    wait_for_path(&endpoint).await;

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let report = request(&mut client, "doctor-service", "runtime.doctor", json!({})).await;
    let service = &report["result"]["service"];
    assert_eq!(service["proxyConfigured"], json!(false));
    for probe in ["chat", "storage"] {
        assert_eq!(service[probe]["classification"], json!("not_configured"));
        assert_eq!(service[probe].get("status"), None);
        assert_eq!(service[probe].get("latencyMs"), None);
    }
    assert_eq!(
        service
            .as_object()
            .expect("service face")
            .get("systemTrust"),
        None,
        "the unconfigured face carries no system-trust leg at all"
    );

    drop(client);
    let _ = connector.kill().await;
}
