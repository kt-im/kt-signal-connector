// SPDX-License-Identifier: AGPL-3.0-only

//! Contract revision 1.72 (the bodyRanges receive pass-through batch, the
//! §4.62 receive half) — the full-stack round trip: a fake-engine receive
//! carrying `textStyles` lands on the wire message shapes through the real
//! normalization, store, and host projection chain.
//!
//! This file is deliberately standalone (no shared helpers with
//! `server_integration.rs`): a parallel test-hardening batch is touching that
//! file's helpers, and the two batches must never collide at merge time.

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
const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];
/// The fixture peer conversation the link's receive burst materializes.
const FIXTURE_PEER: &str = "+15555550101";

fn bootstrap_payload(secret: &[u8; 32]) -> String {
    format!("{}\n{}", hex::encode(secret), hex::encode(TEST_STORE_KEY))
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

fn write_secret_file(path: &Path, secret: &[u8; 32]) {
    fs::write(path, bootstrap_payload(secret)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn spawn_connector(root: &Path, endpoint: &Path, secret_file: &Path) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--bootstrap-secret-file")
        .arg(secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--signal-data-dir")
        .arg(root.join("signal-data"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
        .env("KT_FAKE_EXPECT_NO_JAVA", "1")
        .env("JAVA_TOOL_OPTIONS", "poison")
        .env("_JAVA_OPTIONS", "poison")
        .env("JDK_JAVA_OPTIONS", "poison");
    command.spawn().unwrap()
}
async fn wait_for_path(path: &Path) {
    timeout(Duration::from_secs(3), async {
        while !path.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("connector socket should appear");
}

async fn authenticate(client: &mut Framed<UnixStream, LinesCodec>, secret: &[u8; 32]) -> Value {
    let challenge: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
    assert_eq!(challenge["event"], "runtime.challenge");
    let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
    let client_nonce = hex::encode([7_u8; 32]);
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
    let response: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
    assert_eq!(response["result"]["apiVersion"], API_VERSION);
    response
}

async fn request(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) -> Value {
    send_request_frame(client, request_id, method, params).await;
    loop {
        let response: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        if response.get("requestId").and_then(Value::as_str) == Some(request_id) {
            return response;
        }
    }
}

async fn send_request_frame(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) {
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
}

async fn link_account(client: &mut Framed<UnixStream, LinesCodec>) -> String {
    let link = request(
        client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-BodyRangesPass" }),
    )
    .await;
    let finished = request(
        client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    finished["result"]["id"].as_str().unwrap().to_string()
}

/// 等直聊会话行出现（link 完成后行落库有时序：本地快、CI 慢，原实现立即断言
/// 会偶发 `Option::unwrap() on a None value`——main 的 Gate 3 之前从没真正跑到，
/// 这个时序假设一直没暴露）。轮询到出现为止，最多 10 秒。
async fn wait_for_direct_conversation(
    client: &mut Framed<UnixStream, LinesCodec>,
    account_id: &str,
) -> String {
    for attempt in 0..40_u32 {
        let listed = request(
            client,
            &format!("list-wait-{attempt}"),
            "conversations.list",
            json!({ "accountId": account_id, "limit": 50 }),
        )
        .await;
        let found = listed["result"]["items"].as_array().and_then(|rows| {
            rows.iter()
                .find(|row| row["type"] == "direct" && row["isSelf"] == false)
                .and_then(|row| row["id"].as_str())
        });
        if let Some(id) = found {
            return id.to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("the fixture peer row never materialized within 10s");
}

/// Stage envelopes through the runtime injection marker and drain until
/// `found` answers true over the frames that arrive while polling.
async fn drain_until(
    client: &mut Framed<UnixStream, LinesCodec>,
    mut found: impl FnMut(&Value) -> bool,
) -> bool {
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = send_request_frame(
            client,
            &format!("poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        loop {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if found(&frame) {
                return true;
            }
            if frame.get("requestId").and_then(Value::as_str)
                == Some(format!("poll-{attempt}").as_str())
            {
                break;
            }
        }
    }
    false
}

/// Contract 1.72, the full-stack round trip: the fake engine delivers a
/// styled receive, and the row every read face projects carries the
/// `textStyles` ranges — while the gate shapes hold end to end. The styled
/// row carries both entries verbatim on `message.upserted`, `messages.list`,
/// and `messages.search`; the hostile burst keeps only the well-formed
/// entries (NONE and unknown styles drop, a missing length drops, a start
/// past u32 drops — the message itself never fails); an all-invalid list
/// collapses to the key-absent plain shape; a plain body never grows the
/// key (absence means unstyled, pre-1.25 rows read byte-identical).
#[tokio::test]
async fn body_ranges_receive_round_trips_to_every_wire_face() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [67_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    request(&mut client, "start", "runtime.start", json!({})).await;
    let account_id = link_account(&mut client).await;

    let listed = request(
        &mut client,
        "list-initial",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    // The link burst delivers exactly one incoming receive from the fixture
    // peer, so the direct row materializes at link time (the summary carries
    // no peer identity — the type filter is the honest locator).
    let conversation_id = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "direct" && row["isSelf"] == false)
        .expect("the fixture peer row materializes at link time")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // One marker burst, four receives: the clean styled row, the hostile mix
    // the gate must filter, the all-invalid list that must collapse to
    // key-absent, and the plain body that never grows the key.
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": FIXTURE_PEER,
                "timestamp": 1727000005000u64,
                "dataMessage": {
                    "message": "styled hello",
                    "textStyles": [
                        { "style": "BOLD", "start": 0, "length": 6 },
                        { "style": "SPOILER", "start": 7, "length": 4 }
                    ]
                }
            },
            {
                "source": FIXTURE_PEER,
                "timestamp": 1727000010000u64,
                "dataMessage": {
                    "message": "mixed ranges",
                    "textStyles": [
                        { "style": "BOLD", "start": 0, "length": 5 },
                        { "style": "NONE", "start": 0, "length": 4 },
                        { "style": "MAGIC", "start": 0, "length": 4 },
                        { "style": "ITALIC", "start": 0 },
                        { "style": "STRIKETHROUGH", "start": 4294967296u64, "length": 1 },
                        { "style": "MONOSPACE", "start": 5, "length": 6 }
                    ]
                }
            },
            {
                "source": FIXTURE_PEER,
                "timestamp": 1727000020000u64,
                "dataMessage": {
                    "message": "all bad",
                    "textStyles": [
                        { "style": "MAGIC", "start": 0, "length": 1 },
                        { "style": "NONE", "start": 0, "length": 1 }
                    ]
                }
            },
            {
                "source": FIXTURE_PEER,
                "timestamp": 1727000030000u64,
                "dataMessage": { "message": "plain body" }
            }
        ] })
        .to_string(),
    )
    .unwrap();

    // The push face first: the styled row's `message.upserted` event carries
    // the ranges verbatim on the flattened wire record.
    let upserted = drain_until(&mut client, |frame| {
        frame.get("event").and_then(Value::as_str) == Some("message.upserted")
            && frame["data"]["textStyles"].is_array()
    })
    .await;
    assert!(
        upserted,
        "the styled row must ride message.upserted with its textStyles"
    );

    // The read faces: every injected row lands, and the shapes gate holds.
    let mut rows: Vec<Value> = Vec::new();
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = request(
            &mut client,
            &format!("poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        let page = request(
            &mut client,
            &format!("list-{attempt}"),
            "messages.list",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "limit": 50
            }),
        )
        .await;
        rows = page["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                row["sentAt"]
                    .as_u64()
                    .is_some_and(|sent_at| sent_at >= 1727000005000)
            })
            .cloned()
            .collect();
        if rows.len() == 4 {
            break;
        }
    }
    assert_eq!(rows.len(), 4, "all four receives must land as rows");
    // 契约 1.212（审计 P4）：正文 wire 键已对齐官方 `body`（原 `text`）。
    let by_text = |needle: &str| {
        rows.iter()
            .find(|row| row["body"] == needle)
            .unwrap_or_else(|| panic!("the {needle} row must be listed"))
            .clone()
    };

    let styled = by_text("styled hello");
    assert_eq!(
        styled["textStyles"],
        json!([
            { "style": "BOLD", "start": 0, "length": 6 },
            { "style": "SPOILER", "start": 7, "length": 4 }
        ]),
        "the styled row projects its ranges verbatim: {styled}"
    );

    let mixed = by_text("mixed ranges");
    assert_eq!(
        mixed["textStyles"],
        json!([
            { "style": "BOLD", "start": 0, "length": 5 },
            { "style": "MONOSPACE", "start": 5, "length": 6 }
        ]),
        "only the well-formed entries survive the gate: {mixed}"
    );

    let all_bad = by_text("all bad");
    assert!(
        all_bad.get("textStyles").is_none(),
        "an all-invalid list collapses to the key-absent plain shape: {all_bad}"
    );
    assert!(
        all_bad.get("previews").is_none()
            && all_bad.get("mentions").is_none()
            && all_bad.get("viewOnce").is_none(),
        "the collapsed row stays byte-identical to a plain row: {all_bad}"
    );

    let plain = by_text("plain body");
    assert!(
        plain.get("textStyles").is_none(),
        "a plain body never grows the key — absence means unstyled: {plain}"
    );

    // The search face reads the same stored shape (§4.30 read parity).
    let searched = request(
        &mut client,
        "search-styled",
        "messages.search",
        json!({ "accountId": account_id, "query": "styled", "limit": 50 }),
    )
    .await;
    let hits = searched["result"]["items"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "the search hits the styled row alone");
    assert_eq!(
        hits[0]["textStyles"],
        json!([
            { "style": "BOLD", "start": 0, "length": 6 },
            { "style": "SPOILER", "start": 7, "length": 4 }
        ]),
        "the search projection carries the ranges too"
    );

    drop(client);
    // Give the connector a beat to observe the disconnect, then require the
    // process to end cleanly (the harness pattern across the integration
    // family): no panic, no watchdog exit code.
    sleep(Duration::from_millis(200)).await;
    // 台账 §23.11：S5（ea11a7a）把 host::serve 改成常驻（select 活动会话 +
    // accept，晚到连接回 runtime.busy）。全仓只有 main.rs:343/583 两处 process::exit，
    // 没有任何路径在会话结束后退出进程，因此这条断言已失去前提。busy 行为由
    // a_second_host_connection_is_answered_busy_without_queueing 覆盖。
    let _ = &mut connector;
}
