// SPDX-License-Identifier: AGPL-3.0-only

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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tokio_util::codec::{Framed, LinesCodec};

#[path = "common/harness_scene.rs"]
mod harness_scene;
use harness_scene::dump_connector_crash_scene;

const API_VERSION: &str = "1.0";

/// Upper bound for one harness request round trip (write + response wait).
/// The investigation found the harness blocked forever inside deadline-less
/// `client.next().await` calls (no pending timer — an unbounded await), so any
/// transient upstream anomaly became an indefinite hang that the gate's
/// runner kill fixed into an orphan. Every harness read face now carries this
/// deadline and converts the hang into an evidence-dumping failure.
const HARNESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound for the handshake faces (challenge read + proof response read).
const HARNESS_AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// Phase 3 contract: every spawned connector gets its store key as bootstrap
/// payload line 2. One fixed test key keeps respawns against the same state
/// directory compatible with the database the first spawn encrypted.
const TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

/// The two-line bootstrap payload: line 1 handshake secret, line 2 store key.
fn bootstrap_payload(secret: &[u8; 32]) -> String {
    format!("{}\n{}", hex::encode(secret), hex::encode(TEST_STORE_KEY))
}

#[tokio::test]
async fn binary_serves_authenticated_runtime_lifecycle() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret = [7_u8; 32];

    let mut connector = spawn_connector_from_stdin(temp.path(), &endpoint, &secret).await;
    wait_for_path(&endpoint).await;
    assert_eq!(
        fs::metadata(&endpoint).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut unauthenticated = Framed::new(stream, LinesCodec::new());
    reject_authentication(&mut unauthenticated).await;
    drop(unauthenticated);

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let initial = request(&mut client, "status-1", "runtime.status", json!({})).await;
    assert_eq!(initial["result"]["state"], "stopped");

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let first_engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    drop(client);
    wait_for_process_exit(first_engine_pid).await;
    assert_clean_exit(&mut connector).await;

    let next_secret_file = temp.path().join("bootstrap-next.secret");
    let next_secret = [8_u8; 32];
    write_secret_file(&next_secret_file, &next_secret);
    connector = spawn_connector(temp.path(), &endpoint, &next_secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &next_secret).await;
    let reconnected = request(&mut client, "status-2", "runtime.status", json!({})).await;
    assert_eq!(reconnected["result"]["state"], "stopped");

    let restarted = request(&mut client, "start-2", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");

    let stopped = request(&mut client, "stop-2", "runtime.stop", json!({})).await;
    assert_eq!(stopped["result"]["state"], "stopped");

    drop(client);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn a_second_host_connection_is_answered_busy_without_queueing() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret = [7_u8; 32];

    let mut connector = spawn_connector_from_stdin(temp.path(), &endpoint, &secret).await;
    wait_for_path(&endpoint).await;

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut owner = Framed::new(stream, LinesCodec::new());
    authenticate(&mut owner, &secret).await;

    // ADR 0006: the second connection is accepted and answered, not left in
    // the kernel backlog behind the live session.
    let second_stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut second = Framed::new(second_stream, LinesCodec::new());
    let line = timeout(Duration::from_secs(5), second.next())
        .await
        .expect("the busy answer must not wait for the live session to end")
        .expect("the second connection must receive one frame")
        .expect("the busy frame must be a valid line");
    let busy: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(busy["apiVersion"], API_VERSION);
    assert_eq!(busy["event"], "runtime.busy");
    assert_eq!(busy["data"]["code"], "HOST_BUSY");
    assert_eq!(busy["data"]["retryable"], true);
    assert!(
        busy["data"].get("sessionId").is_none(),
        "the busy answer carries no session identity"
    );
    // The same connection is closed after the one frame.
    assert!(
        timeout(Duration::from_secs(5), second.next())
            .await
            .expect("the busy connection must close")
            .is_none(),
        "the busy connection ends after its single answer"
    );

    // The live session is untouched by the rejected second connection.
    let status = request(&mut owner, "status-after-busy", "runtime.status", json!({})).await;
    assert_eq!(status["result"]["state"], "stopped");

    drop(owner);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn phase2_link_receive_send_and_idempotent_text() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [7_u8; 32];
    fs::write(&secret_file, bootstrap_payload(&secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let slow_link = request(
        &mut client,
        "link-slow-start",
        "link.start",
        json!({ "deviceName": "[slow-link-test]" }),
    )
    .await;
    let slow_link_session_id = slow_link["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();
    send_request_frame(
        &mut client,
        "link-slow-finish",
        "link.finish",
        json!({ "linkSessionId": slow_link_session_id }),
    )
    .await;
    let duplicate_finish = request(
        &mut client,
        "link-duplicate-finish",
        "link.finish",
        json!({ "linkSessionId": slow_link_session_id }),
    )
    .await;
    assert_eq!(duplicate_finish["error"]["code"], "LINK_IN_PROGRESS");
    send_request_frame(
        &mut client,
        "link-slow-cancel",
        "link.cancel",
        json!({ "linkSessionId": slow_link_session_id }),
    )
    .await;

    let mut slow_finish_cancelled = false;
    let mut slow_cancelled = false;
    timeout(Duration::from_secs(3), async {
        while !slow_finish_cancelled || !slow_cancelled {
            let response: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            match response.get("requestId").and_then(Value::as_str) {
                Some("link-slow-finish") => {
                    assert_eq!(response["error"]["code"], "LINK_CANCELLED");
                    slow_finish_cancelled = true;
                }
                Some("link-slow-cancel") => {
                    assert!(response.get("result").is_some());
                    slow_cancelled = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("link.cancel must not wait for phone approval");

    // B3: cancellation abandons the finish wait locally; it must not stop or
    // restart the shared engine (the pre-B3 restart disconnected every other
    // account in the group). The same pid must survive and the engine stay
    // running.
    let after_cancel = request(
        &mut client,
        "status-after-link-cancel",
        "runtime.status",
        json!({}),
    )
    .await;
    assert_eq!(after_cancel["result"]["state"], "running");
    assert_eq!(
        after_cancel["result"]["pid"].as_u64().unwrap() as u32,
        engine_pid,
        "link.cancel must not restart the group engine"
    );

    let link = request(
        &mut client,
        "link-1",
        "link.start",
        json!({ "deviceName": "KT-Test" }),
    )
    .await;
    assert!(link["result"]["linkSessionId"].as_str().is_some());
    assert!(
        link["result"]["qrPayload"]
            .as_str()
            .unwrap()
            .starts_with("sgnl://")
    );
    let link_session_id = link["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();

    let conflict = request(
        &mut client,
        "link-2",
        "link.start",
        json!({ "deviceName": "KT-Test-2" }),
    )
    .await;
    assert_eq!(conflict["error"]["code"], "LINK_IN_PROGRESS");

    let finished = request(
        &mut client,
        "link-3",
        "link.finish",
        json!({ "linkSessionId": link_session_id }),
    )
    .await;
    assert_eq!(finished["result"]["state"], "ready");
    assert!(finished["result"]["maskedAddress"].as_str().is_some());
    assert!(
        !finished["result"]["maskedAddress"]
            .as_str()
            .unwrap()
            .contains("555555")
    );
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    let accounts = request(&mut client, "accounts-1", "accounts.list", json!({})).await;
    assert_eq!(accounts["result"].as_array().unwrap().len(), 1);

    // Fixture finishLink emits one receive notification (+15555550101) after
    // the JSON-RPC result. Contract 1.201 (§6.5 amendment): the inline
    // contacts.sync no longer materializes skeletons for **other people** —
    // only structurally-owned chats do (the fixture group, and the linked
    // account's own Note to Self row per 1.43/§4.42). Alice and Bob are bare
    // contacts until a message flows, so the listing is the messaged
    // conversation first, then the group and the self row.
    sleep(Duration::from_millis(50)).await;
    let conversations = request(
        &mut client,
        "conv-2",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let items = conversations["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "messaged + group + self: {items:?}");
    assert!(
        items.iter().all(|row| row["title"] != "Bob"),
        "Bob is a bare contact and must not appear as a chat: {items:?}"
    );
    // The messaged conversation first; its title follows the sync cache's
    // profile-name preference ("Alice Example" over the envelope peer name).
    assert_eq!(items[0]["title"], "Alice Example");
    assert_eq!(items[0]["type"], "direct");
    let conversation_id = items[0]["id"].as_str().unwrap().to_string();

    let messages = request(
        &mut client,
        "msg-1",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    assert_eq!(messages["result"]["items"].as_array().unwrap().len(), 1);
    // 契约 1.212（审计 P4）：正文 wire 键已对齐官方 body（原 text）。
    assert_eq!(messages["result"]["items"][0]["body"], "private text");
    assert_eq!(messages["result"]["items"][0]["direction"], "incoming");

    let sent = request(
        &mut client,
        "send-1",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "hello from kt",
            "clientRequestId": "client-req-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    assert_eq!(sent["result"]["body"], "hello from kt");
    assert_eq!(sent["result"]["clientRequestId"], "client-req-1");
    let message_id = sent["result"]["id"].as_str().unwrap().to_string();

    let sent_again = request(
        &mut client,
        "send-2",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "hello from kt",
            "clientRequestId": "client-req-1"
        }),
    )
    .await;
    assert_eq!(sent_again["result"]["id"], message_id);
    assert_eq!(sent_again["result"]["status"], "sent");

    let messages = request(
        &mut client,
        "msg-2",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    assert_eq!(messages["result"]["items"].as_array().unwrap().len(), 2);

    // Host dispatch is concurrent: a persisted read must not wait for a slow
    // upstream send, while same-account sends retain request order.
    send_request_frame(
        &mut client,
        "send-slow",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "[slow-host-test]",
            "clientRequestId": "client-req-slow"
        }),
    )
    .await;
    send_request_frame(
        &mut client,
        "send-after-slow",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "after slow",
            "clientRequestId": "client-req-after-slow"
        }),
    )
    .await;
    send_request_frame(
        &mut client,
        "msg-concurrent",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;

    let mut response_order = Vec::new();
    while response_order.len() < 3 {
        let response: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(response) => response,
            Err(_) => panic!(
                "the send/response ordering drain stalled over \
                 {HARNESS_REQUEST_TIMEOUT:?} with {response_order:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if let Some(request_id) = response.get("requestId").and_then(Value::as_str)
            && matches!(
                request_id,
                "send-slow" | "send-after-slow" | "msg-concurrent"
            )
        {
            response_order.push(request_id.to_string());
        }
    }
    assert_eq!(
        response_order,
        ["msg-concurrent", "send-slow", "send-after-slow"]
    );

    // Account-scoped host admission is bounded independently of frame input.
    for index in 0..33 {
        send_request_frame(
            &mut client,
            &format!("capacity-{index}"),
            "messages.sendText",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "text": if index == 0 { "[slow-host-test]" } else { "queued" },
                "clientRequestId": format!("capacity-client-{index}")
            }),
        )
        .await;
    }
    loop {
        let response: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(response) => response,
            Err(_) => panic!(
                "the capacity drain never saw capacity-32 within \
                 {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if response.get("requestId").and_then(Value::as_str) == Some("capacity-32") {
            assert_eq!(response["error"]["code"], "INTERNAL_ERROR");
            assert_eq!(
                response["error"]["message"],
                "connector request capacity exceeded"
            );
            break;
        }
    }

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;

    // Disconnect shutdown must resolve a dispatched mutation to unknown before
    // the connection task is dropped. A fresh one-shot connector and secret read
    // the persisted fact only; no retry or second send is issued.
    let next_secret_file = temp.path().join("bootstrap-after-disconnect.secret");
    let next_secret = [9_u8; 32];
    write_secret_file(&next_secret_file, &next_secret);
    connector = spawn_connector(temp.path(), &endpoint, &next_secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &next_secret).await;
    let after_disconnect = request(
        &mut client,
        "messages-after-disconnect",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let slow_statuses = after_disconnect["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["body"] == "[slow-host-test]")
        .map(|message| message["status"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(slow_statuses.contains(&"sent"));
    assert!(slow_statuses.contains(&"unknown"));

    let restarted = request(&mut client, "start-for-delete", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");

    let next_link = request(
        &mut client,
        "link-next-account",
        "link.start",
        json!({ "deviceName": "KT-Next" }),
    )
    .await;
    let next_link_session_id = next_link["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();

    let invalid_delete = request(
        &mut client,
        "delete-invalid-params",
        "accounts.deleteLocalData",
        json!({ "accountId": account_id, "unexpected": true }),
    )
    .await;
    assert_eq!(invalid_delete["error"]["code"], "INVALID_REQUEST");

    let compatible_delete = request(
        &mut client,
        "delete-v1-compatible",
        "accounts.deleteLocalData",
        json!({ "accountId": "already-absent-account" }),
    )
    .await;
    assert!(
        compatible_delete.get("result").is_some(),
        "v1-compatible delete response: {compatible_delete:?}"
    );

    let deleted = request(
        &mut client,
        "delete-account",
        "accounts.deleteLocalData",
        json!({
            "accountId": account_id,
            "operationId": "logout-operation-1"
        }),
    )
    .await;
    assert!(deleted.get("result").is_some());

    let deleted_again = request(
        &mut client,
        "delete-account-again",
        "accounts.deleteLocalData",
        json!({
            "accountId": account_id,
            "operationId": "logout-operation-1"
        }),
    )
    .await;
    assert!(deleted_again.get("result").is_some());

    let link_still_active = request(
        &mut client,
        "link-still-active",
        "link.start",
        json!({ "deviceName": "KT-Should-Wait" }),
    )
    .await;
    assert_eq!(link_still_active["error"]["code"], "LINK_IN_PROGRESS");
    let cancelled = request(
        &mut client,
        "link-next-cancel",
        "link.cancel",
        json!({ "linkSessionId": next_link_session_id }),
    )
    .await;
    assert!(cancelled.get("result").is_some());
    let after_delete = request(
        &mut client,
        "accounts-after-delete",
        "accounts.list",
        json!({}),
    )
    .await;
    assert!(after_delete["result"].as_array().unwrap().is_empty());

    drop(client);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn link_cancel_keeps_the_group_engine_and_other_accounts() {
    // B3: cancel one account's link on a shared engine/group. The engine must
    // keep the same pid, the already-linked account must keep working, and
    // the cancelled account must be linkable again afterwards.
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [13_u8; 32];
    fs::write(&secret_file, bootstrap_payload(&secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_MULTI_ACCOUNT", "1")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "b3-start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // Account B is linked first and keeps its engine connection throughout.
    let b_link = request(
        &mut client,
        "b3-link-b",
        "link.start",
        json!({ "deviceName": "KT-B3-B" }),
    )
    .await;
    let b_finished = request(
        &mut client,
        "b3-finish-b",
        "link.finish",
        json!({ "linkSessionId": b_link["result"]["linkSessionId"] }),
    )
    .await;
    let b_id = b_finished["result"]["id"]
        .as_str()
        .expect("account B links")
        .to_string();
    let b_synced = request(
        &mut client,
        "b3-sync-b-before",
        "contacts.sync",
        json!({ "accountId": b_id }),
    )
    .await;
    assert_eq!(b_synced["result"]["contactCount"], 3);

    // Account A's link stays in the phone-approval wait, then the user
    // cancels it.
    let a_link = request(
        &mut client,
        "b3-link-a",
        "link.start",
        json!({ "deviceName": "[slow-link-test]" }),
    )
    .await;
    let a_session = a_link["result"]["linkSessionId"]
        .as_str()
        .unwrap()
        .to_string();
    send_request_frame(
        &mut client,
        "b3-finish-a",
        "link.finish",
        json!({ "linkSessionId": a_session }),
    )
    .await;
    send_request_frame(
        &mut client,
        "b3-cancel-a",
        "link.cancel",
        json!({ "linkSessionId": a_session }),
    )
    .await;
    let mut finish_cancelled = false;
    let mut cancel_answered = false;
    timeout(Duration::from_secs(3), async {
        while !finish_cancelled || !cancel_answered {
            let response: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            match response.get("requestId").and_then(Value::as_str) {
                Some("b3-finish-a") => {
                    assert_eq!(response["error"]["code"], "LINK_CANCELLED");
                    finish_cancelled = true;
                }
                Some("b3-cancel-a") => {
                    assert!(response.get("result").is_some());
                    cancel_answered = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("link.cancel must answer without waiting for phone approval");

    // The shared engine must not have been stopped or restarted.
    let status = request(&mut client, "b3-status", "runtime.status", json!({})).await;
    assert_eq!(status["result"]["state"], "running");
    assert_eq!(
        status["result"]["pid"].as_u64().unwrap() as u32,
        engine_pid,
        "cancelling one link must not restart the group engine"
    );

    // B is still bound and its engine lane still answers.
    let accounts = request(&mut client, "b3-accounts", "accounts.list", json!({})).await;
    let ids: Vec<&str> = accounts["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|account| account["id"].as_str())
        .collect();
    assert_eq!(ids, vec![b_id.as_str()]);
    let b_synced_after = request(
        &mut client,
        "b3-sync-b-after",
        "contacts.sync",
        json!({ "accountId": b_id }),
    )
    .await;
    assert_eq!(b_synced_after["result"]["contactCount"], 3);

    // The cancelled account can start over and link successfully.
    let a_relink = request(
        &mut client,
        "b3-relink-a",
        "link.start",
        json!({ "deviceName": "KT-B3-A" }),
    )
    .await;
    let a_finished = request(
        &mut client,
        "b3-finish-relink-a",
        "link.finish",
        json!({ "linkSessionId": a_relink["result"]["linkSessionId"] }),
    )
    .await;
    assert!(
        a_finished["result"]["id"].as_str().is_some(),
        "the cancelled account must be linkable again: {a_finished}"
    );
    let accounts = request(&mut client, "b3-accounts-2", "accounts.list", json!({})).await;
    assert_eq!(accounts["result"].as_array().unwrap().len(), 2);

    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// QR B1 (issue #951): the engine's terminal provisioning failure surfaces as
/// the definite LINK_LOST (not a generic upstream error), the connector keeps
/// the lost session addressable so a repeated finish still answers LINK_LOST
/// rather than LINK_NOT_FOUND, and the next link.start is not blocked by the
/// dead session's LINK_IN_PROGRESS.
#[tokio::test]
async fn link_lost_is_definite_and_frees_the_next_link_start() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [17_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_FINISH_LINK_LOST", "1")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "b1-start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "b1-link-start",
        "link.start",
        json!({ "deviceName": "KT-B1-Lost" }),
    )
    .await;
    let lost_session = link["result"]["linkSessionId"]
        .as_str()
        .expect("the QR mints")
        .to_string();

    let lost = request(
        &mut client,
        "b1-link-finish",
        "link.finish",
        json!({ "linkSessionId": lost_session }),
    )
    .await;
    assert_eq!(lost["error"]["code"], "LINK_LOST", "got {lost}");
    assert_eq!(lost["error"]["retryable"], true);

    // The lost session stays addressable: a repeated finish answers the same
    // definite code instead of degrading to LINK_NOT_FOUND.
    let repeated = request(
        &mut client,
        "b1-link-finish-again",
        "link.finish",
        json!({ "linkSessionId": lost_session }),
    )
    .await;
    assert_eq!(repeated["error"]["code"], "LINK_LOST", "got {repeated}");

    // A fresh QR replaces the dead session instead of LINK_IN_PROGRESS.
    let fresh = request(
        &mut client,
        "b1-link-start-again",
        "link.start",
        json!({ "deviceName": "KT-B1-Fresh" }),
    )
    .await;
    let fresh_session = fresh["result"]["linkSessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("a lost session must not block a fresh start: {fresh}"))
        .to_string();
    assert_ne!(fresh_session, lost_session);

    // The shared engine never restarted for the loss.
    let status = request(&mut client, "b1-status", "runtime.status", json!({})).await;
    assert_eq!(status["result"]["state"], "running");
    assert_eq!(status["result"]["pid"].as_u64().unwrap() as u32, engine_pid);

    let cancelled = request(
        &mut client,
        "b1-link-cancel",
        "link.cancel",
        json!({ "linkSessionId": fresh_session }),
    )
    .await;
    assert!(cancelled.get("result").is_some());

    drop(client);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn contacts_sync_list_and_send_by_peer() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [11_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Contacts" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // finish_link already ran a best-effort sync; an explicit contacts.sync
    // inside the 60s window returns the cached counts. Contract 1.43 (§4.42):
    // the self entry from listContacts joins the cache — 3 contacts + 1 group.
    let synced = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(synced["result"]["contactCount"], 3);
    assert_eq!(synced["result"]["groupCount"], 1);
    assert!(synced["result"]["syncedAt"].as_u64().unwrap() > 0);

    let listed = request(
        &mut client,
        "contacts-list",
        "contacts.list",
        json!({ "accountId": account_id, "limit": 10 }),
    )
    .await;
    let items = listed["result"]["items"].as_array().unwrap();
    // The self entry rides the contact cache since contract 1.43; its title
    // material is the account's own profile name.
    assert_eq!(items.len(), 4);
    let self_contact = items
        .iter()
        .find(|item| item["peerKey"] == "+15555550100")
        .unwrap();
    assert_eq!(self_contact["kind"], "contact");
    assert_eq!(self_contact["title"], "Test User");
    let alice = items
        .iter()
        .find(|item| item["peerKey"] == "+15555550101")
        .unwrap();
    assert_eq!(alice["kind"], "contact");
    assert_eq!(alice["title"], "Alice Example");
    let group = items.iter().find(|item| item["kind"] == "group").unwrap();
    assert_eq!(group["peerKey"], "ZmFrZS1ncm91cC0x");
    assert_eq!(group["title"], "Fixture Group");

    let filtered = request(
        &mut client,
        "contacts-filtered",
        "contacts.list",
        json!({ "accountId": account_id, "query": "alice", "limit": 10 }),
    )
    .await;
    assert_eq!(filtered["result"]["items"].as_array().unwrap().len(), 1);

    let first_page = request(
        &mut client,
        "contacts-page-1",
        "contacts.list",
        json!({ "accountId": account_id, "limit": 2 }),
    )
    .await;
    assert_eq!(first_page["result"]["items"].as_array().unwrap().len(), 2);
    let cursor = first_page["result"]["nextCursor"].as_str().unwrap();
    let second_page = request(
        &mut client,
        "contacts-page-2",
        "contacts.list",
        json!({ "accountId": account_id, "limit": 10, "cursor": cursor }),
    )
    .await;
    assert_eq!(second_page["result"]["items"].as_array().unwrap().len(), 2);
    assert!(second_page["result"].get("nextCursor").is_none());

    // contacts.list is read-only: an unknown account is a cache miss, not an
    // upstream lookup.
    let unknown = request(
        &mut client,
        "contacts-unknown-account",
        "contacts.list",
        json!({ "accountId": "absent-account", "limit": 10 }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "ACCOUNT_NOT_FOUND");

    // Sending to a peer with no conversation yet creates it together with the
    // first message (no empty conversation skeleton).
    let sent = request(
        &mut client,
        "send-peer-1",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550103",
            "peerTitle": "Fresh Peer",
            "text": "first message",
            "clientRequestId": "peer-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    let conversations = request(
        &mut client,
        "conv-after-peer-send",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let created = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == conversation_id)
        .unwrap();
    assert_eq!(created["title"], "Fresh Peer");
    assert_eq!(created["type"], "direct");
    // Contract 1.43 (§4.42): every summary row carries isSelf; the contact
    // send's row is a peer, and exactly the own direct chat is marked.
    assert_eq!(created["isSelf"], false);
    let conv_items = conversations["result"]["items"].as_array().unwrap();
    let self_rows: Vec<_> = conv_items
        .iter()
        .filter(|item| item["isSelf"] == true)
        .collect();
    assert_eq!(self_rows.len(), 1);
    assert_eq!(self_rows[0]["type"], "direct");
    assert_eq!(self_rows[0]["title"], "Test User");

    // A second send to the same peer reuses the same conversation.
    let sent_again = request(
        &mut client,
        "send-peer-2",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "direct",
            "peerKey": "+15555550103",
            "text": "second message",
            "clientRequestId": "peer-send-2"
        }),
    )
    .await;
    assert_eq!(sent_again["result"]["conversationId"], conversation_id);

    // Ambiguous or missing targets are rejected before any upstream call.
    let both = request(
        &mut client,
        "send-both-targets",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "peerKey": "+15555550103",
            "text": "ambiguous",
            "clientRequestId": "peer-send-both"
        }),
    )
    .await;
    assert_eq!(both["error"]["code"], "INVALID_REQUEST");
    let neither = request(
        &mut client,
        "send-no-target",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "text": "no target",
            "clientRequestId": "peer-send-none"
        }),
    )
    .await;
    assert_eq!(neither["error"]["code"], "INVALID_REQUEST");
    let bad_kind = request(
        &mut client,
        "send-bad-kind",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "channel",
            "peerKey": "+15555550103",
            "text": "bad kind",
            "clientRequestId": "peer-send-bad-kind"
        }),
    )
    .await;
    assert_eq!(bad_kind["error"]["code"], "INVALID_REQUEST");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.43 (§4.42) end to end: the contacts sync keeps the linked
/// account's own entry, `conversations.list` marks exactly that skeleton
/// `isSelf`, and `messages.sendText` addressed to the own number takes the
/// ordinary direct-chat path — the upstream `send` dispatch carries the self
/// recipient verbatim (the pinned upstream routes it to the Note-to-Self
/// recipient, from where it mirrors back to every linked device). The
/// connector adds no interception and no copy.
#[tokio::test]
async fn note_to_self_skeleton_marks_the_wire_and_send_reaches_the_upstream() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [12_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-NoteToSelf" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    // Contract 1.170 (§4.170): the self chat's canonical key is this ACI —
    // the skeleton below materializes under it, and the self send dispatches
    // to it (the same Signal identity the number names).
    let self_aci = finished["result"]["aci"].as_str().unwrap();

    // The cached-counts answer proves the sync transaction (rows + marker)
    // committed, so the skeletons below are deterministic.
    let synced = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(synced["result"]["contactCount"], 3);

    let listed = request(
        &mut client,
        "conv-list-1",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let items = listed["result"]["items"].as_array().unwrap();
    let self_rows: Vec<_> = items.iter().filter(|item| item["isSelf"] == true).collect();
    assert_eq!(
        self_rows.len(),
        1,
        "exactly the own direct chat is marked: {items:?}"
    );
    let self_row = &self_rows[0];
    assert_eq!(self_row["type"], "direct");
    // Title material is the account's own profile name; the desktop
    // localizes the Note to Self presentation from the marker.
    assert_eq!(self_row["title"], "Test User");
    assert_eq!(self_rows[0]["muted"], false);
    assert_eq!(self_rows[0]["pinned"], false);
    let conversation_id = self_row["id"].as_str().unwrap().to_string();

    // Send-to-self by peer key: the ordinary direct path, no connector
    // interception — the response settles on the same conversation the
    // skeleton materialized (stable identity on both paths).
    let sent = request(
        &mut client,
        "send-self",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "direct",
            "peerKey": "+15555550100",
            "text": "note to myself",
            "clientRequestId": "self-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    assert_eq!(sent["result"]["conversationId"], conversation_id);

    // The upstream dispatch carries the self recipient. Contract 1.170
    // (§4.170): the canonical ACI-keyed row is what the send path reads, so
    // the dispatch targets the ACI — the same Signal identity the number
    // names (the engine's resolve_recipient parses a UUID service id on its
    // first ladder arm, verified read-only in §4.170).
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the dispatch");
    let dispatch: Value = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|entry: &Value| entry["message"] == "note to myself")
        .expect("the self send must reach the upstream engine");
    assert_eq!(dispatch["account"], "+15555550100");
    assert_eq!(dispatch["recipient"], json!([self_aci]));

    // The row landed on the self conversation and the marker stays.
    let relisted = request(
        &mut client,
        "conv-list-2",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let after = relisted["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == conversation_id)
        .unwrap()
        .clone();
    assert_eq!(after["isSelf"], true);
    assert_eq!(after["lastMessagePreview"], "note to myself");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.44 (§4.43) end to end: the compose contact list marks exactly
/// the linked account's own entry `isSelf`, the bare bool is always
/// serialized on every row (no skip-when-false key absence), and the marker
/// is same-source with the conversations face — both lists derive from the
/// one shared number predicate and mark the same entry, so a desktop
/// cross-referencing a list row against its conversation skeleton sees the
/// same self-ness on both faces (identical title material, the §4.42 split).
#[tokio::test]
async fn contacts_list_marks_the_own_entry_is_self_same_source_with_conversations() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [13_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-ContactsSelf" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The cached-counts answer proves the sync transaction committed, so the
    // listed rows below are deterministic.
    let synced = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(synced["result"]["contactCount"], 3);

    let listed = request(
        &mut client,
        "contacts-list",
        "contacts.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let contact_rows = listed["result"]["items"].as_array().unwrap();
    let self_contacts: Vec<_> = contact_rows
        .iter()
        .filter(|row| row["isSelf"] == true)
        .collect();
    assert_eq!(self_contacts.len(), 1, "contact rows: {contact_rows:?}");
    assert_eq!(self_contacts[0]["kind"], "contact");
    assert_eq!(self_contacts[0]["peerKey"], "+15555550100");
    assert_eq!(self_contacts[0]["title"], "Test User");
    // The bare bool is always serialized: every row carries the key, and
    // every non-self row — peer contacts and the group alike — reads false.
    for row in contact_rows {
        assert!(
            row.get("isSelf").is_some(),
            "isSelf must always serialize: {row:?}"
        );
        if row["peerKey"] != "+15555550100" {
            assert_eq!(row["isSelf"], false, "non-self row: {row:?}");
        }
    }

    // Same-source consistency: the conversations face marks exactly one row
    // too, and both marked rows are the same entry — the shared title
    // material (the account's own profile name) on both faces.
    let conversations = request(
        &mut client,
        "conv-list-consistency",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let conv_rows = conversations["result"]["items"].as_array().unwrap();
    let self_convs: Vec<_> = conv_rows
        .iter()
        .filter(|row| row["isSelf"] == true)
        .collect();
    assert_eq!(self_convs.len(), 1, "conversation rows: {conv_rows:?}");
    assert_eq!(self_convs[0]["type"], "direct");
    assert_eq!(self_convs[0]["title"], self_contacts[0]["title"]);
    for row in conv_rows {
        assert!(row.get("isSelf").is_some());
    }

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.142 (§4.138): the engine's own-ACI answer rides the link.finish
/// result and the accounts.list rows. The fixture derives a stable uuid5 per
/// number, so the expected value is pinned; the connector carries it verbatim
/// (canonical dashed lowercase) on both faces and never substitutes the
/// opaque local row id.
#[tokio::test]
async fn link_finish_and_accounts_list_carry_the_answered_aci() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [23_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Aci" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap();
    let aci = finished["result"]["aci"].as_str().unwrap();
    assert_eq!(aci, "5a1cc2cd-b364-53d4-8d71-1ec62b8eb72b");
    assert_ne!(
        aci, account_id,
        "the row id is not an ACI and must never stand in for one"
    );

    let accounts = request(&mut client, "accounts", "accounts.list", json!({})).await;
    let rows = accounts["result"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], account_id);
    assert_eq!(rows[0]["aci"], aci);

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.142 (§4.138): an engine face without the aci key reads as
/// honest absence on both faces — the connector serializes no invented
/// identity (the key is skipped, never a guess from the opaque row id).
/// KT_FAKE_OMIT_ACCOUNT_ACI=1 is the fixture's engine-without-the-answer
/// build, the face the pinned engine actually rides today.
#[tokio::test]
async fn an_engine_without_the_aci_face_reads_as_absence_on_both_faces() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [29_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_OMIT_ACCOUNT_ACI", "1")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-NoAci" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    assert_eq!(finished["result"]["state"], "ready");
    assert!(
        finished["result"].get("aci").is_none(),
        "an absent engine face must not invent a key: {finished:?}"
    );

    let accounts = request(&mut client, "accounts", "accounts.list", json!({})).await;
    let rows = accounts["result"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].get("aci").is_none(),
        "an absent engine face must not invent a key: {rows:?}"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Phase 0 happy-path smoke gap (docs/optimization-plan.md): the existing
/// phase2 test proves receive persistence through `messages.list`, but nothing
/// asserted the normalized host event stream, and `messages.getText` had no
/// end-to-end coverage. The fixture emits one receive notification right after
/// its finishLink result; the connector must persist it and deliver
/// message.upserted -> conversation.changed -> account.changed on the
/// authenticated host stream, and getText must return the full stored body.
#[tokio::test]
async fn receive_delivers_host_events_and_get_text_returns_the_full_body() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [17_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Events" }),
    )
    .await;

    // The fixture emits one receive notification right after its finishLink
    // result; the connector may deliver the resulting host events before the
    // finish response reaches the socket, so collect both in one read loop
    // instead of discarding frames inside `request`.
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    /// The receive's conversation id, knowable only once the receive's
    /// `message.upserted` frame has landed.
    fn receive_conversation_id(upserted: Option<&Value>) -> Option<&str> {
        upserted?.get("data")?.get("conversationId")?.as_str()
    }

    /// The summary for the receive's own conversation — never the first
    /// `conversation.changed` on the stream, which may belong to a
    /// conversation the link flow itself materialized.
    fn conversation_changed_for<'a>(
        changes: &'a [Value],
        conversation_id: &str,
    ) -> Option<&'a Value> {
        changes
            .iter()
            .find(|frame| frame["data"]["id"] == conversation_id)
    }

    let mut finished: Option<Value> = None;
    let mut upserted: Option<Value> = None;
    let mut account_changed: Option<Value> = None;
    // The link flow's own sync materializes other conversations (contacts, the
    // self row), so a foreign conversation.changed can land before the
    // receive's summary. Buffer every summary and, once the receive's
    // conversationId is known, wait for the frame whose `data.id` matches it.
    // Arrival order is not part of the contract asserted below.
    let mut conversation_changes: Vec<Value> = Vec::new();
    let received = timeout(Duration::from_secs(5), async {
        loop {
            let matched_conversation =
                receive_conversation_id(upserted.as_ref()).is_some_and(|conversation_id| {
                    conversation_changed_for(&conversation_changes, conversation_id).is_some()
                });
            if finished.is_some()
                && upserted.is_some()
                && matched_conversation
                && account_changed.is_some()
            {
                break;
            }
            let line = client.next().await.unwrap_or_else(|| {
                panic!("host stream closed before the receive's events arrived")
            });
            let line = line.expect("host stream must carry text lines while receiving");
            let frame: Value = serde_json::from_str(&line)
                .expect("host stream must carry JSON frames while receiving");
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                finished = Some(frame);
                continue;
            }
            match frame.get("event").and_then(Value::as_str) {
                Some("message.upserted") => upserted = Some(frame),
                Some("conversation.changed") => conversation_changes.push(frame),
                // The link flow itself also emits account.changed; keep the one
                // that carries the receive's unread increment.
                Some("account.changed") if frame["data"]["unreadCount"] == 1 => {
                    account_changed = Some(frame);
                }
                _ => {}
            }
        }
    })
    .await;
    if received.is_err() {
        let conversation_id = receive_conversation_id(upserted.as_ref())
            .unwrap_or("<message.upserted never arrived>");
        let seen: Vec<String> = conversation_changes
            .iter()
            .map(|frame| {
                format!(
                    "{} (unreadCount={})",
                    frame["data"]["id"], frame["data"]["unreadCount"]
                )
            })
            .collect();
        panic!(
            "the receive's host events must arrive within 5s; still missing: \
             link.finish={}, message.upserted={}, \
             conversation.changed[data.id={conversation_id}]={}, \
             account.changed[unreadCount=1]={}; conversation.changed frames seen: {seen:?}\n{}",
            finished.is_some(),
            upserted.is_some(),
            receive_conversation_id(upserted.as_ref()).is_some_and(|conversation_id| {
                conversation_changed_for(&conversation_changes, conversation_id).is_some()
            }),
            account_changed.is_some(),
            dump_connector_crash_scene()
        );
    }
    let account_id = finished.unwrap()["result"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let upserted = upserted.unwrap();
    assert_eq!(upserted["apiVersion"], API_VERSION);
    let message = &upserted["data"];
    assert_eq!(message["accountId"], account_id);
    assert_eq!(message["direction"], "incoming");
    assert_eq!(message["body"], "private text");
    assert_eq!(message["status"], "delivered");
    // attachments was removed from MessageRecord in optimization-plan Phase 2
    // (the engine runs signal-cli with --ignore-attachments); the field must
    // not reappear on the wire.
    assert!(message.get("attachments").is_none());
    let conversation_id = message["conversationId"].as_str().unwrap().to_string();
    let message_id = message["id"].as_str().unwrap().to_string();

    let conversation_changed = conversation_changed_for(&conversation_changes, &conversation_id)
        .cloned()
        .expect("the receive's own conversation.changed must be on the stream");
    assert_eq!(conversation_changed["data"]["id"], conversation_id);
    assert_eq!(conversation_changed["data"]["type"], "direct");
    assert_eq!(conversation_changed["data"]["unreadCount"], 1);

    let account_changed = account_changed.unwrap();
    assert_eq!(account_changed["data"]["unreadCount"], 1);

    // messages.getText returns the complete persisted body for that message.
    let fetched = request(
        &mut client,
        "get-text",
        "messages.getText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": message_id
        }),
    )
    .await;
    assert_eq!(fetched["result"]["messageId"], message_id);
    assert_eq!(fetched["result"]["text"], "private text");
    assert_eq!(fetched["result"]["textBytes"], "private text".len() as u64);

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Phase 2 (docs/optimization-plan.md): quoteMessageId is delivered upstream
/// as signal-cli's quoteTimestamp/quoteAuthor send params, send completion
/// emits message.statusChanged, and an unknown quote target is a deterministic
/// validation rejection that leaves no pending row behind.
#[tokio::test]
async fn quote_is_delivered_upstream_and_status_change_is_emitted() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [23_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Quote" }),
    )
    .await;
    // The fixture emits one receive notification after finishLink; the frames
    // can interleave with the finish response, so drain until both arrive.
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let mut finished: Option<Value> = None;
    let mut upserted: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while finished.is_none() || upserted.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                finished = Some(frame);
                continue;
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted") {
                upserted = Some(frame);
            }
        }
    })
    .await
    .expect("link finish must persist the fixture's receive notification");
    let account_id = finished.unwrap()["result"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // The fixture's receive: source +15555550101, envelope timestamp 42.
    let upserted = upserted.unwrap();
    let quoted_message_id = upserted["data"]["id"].as_str().unwrap().to_string();
    let conversation_id = upserted["data"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // A quoted send resolves the local quoteMessageId to the upstream quote
    // parameters and completes with a message.statusChanged event.
    send_request_frame(
        &mut client,
        "send-quote",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "quoting inbound",
            "clientRequestId": "quote-req-1",
            "quoteMessageId": quoted_message_id
        }),
    )
    .await;
    let mut sent: Option<Value> = None;
    let mut status_changed: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while sent.is_none() || status_changed.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("send-quote") {
                sent = Some(frame);
                continue;
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.statusChanged") {
                status_changed = Some(frame);
            }
        }
    })
    .await
    .expect("send must answer and emit message.statusChanged");
    let sent = sent.unwrap();
    assert_eq!(sent["result"]["status"], "sent");
    assert_eq!(sent["result"]["quoteMessageId"], quoted_message_id);
    let status_changed = status_changed.unwrap();
    assert_eq!(status_changed["apiVersion"], API_VERSION);
    assert_eq!(status_changed["data"]["accountId"], account_id);
    assert_eq!(
        status_changed["data"]["messageId"],
        sent["result"]["id"].as_str().unwrap()
    );
    assert_eq!(status_changed["data"]["status"], "sent");

    // The fake signal-cli logged the exact JSON-RPC send params it received.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log send params");
    let quoted_send: Value = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params["message"] == "quoting inbound")
        .expect("the quoted send must reach the upstream");
    assert_eq!(quoted_send["quoteTimestamp"], 42);
    assert_eq!(quoted_send["quoteAuthor"], "+15555550101");
    assert_eq!(quoted_send["recipient"], json!(["+15555550101"]));
    assert_eq!(quoted_send["account"], "+15555550100");

    // A quote pointing at a message that does not exist is rejected during
    // validation — before any upstream call or pending row.
    let rejected = request(
        &mut client,
        "send-quote-missing",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "quote of nothing",
            "clientRequestId": "quote-req-missing",
            "quoteMessageId": "no-such-message"
        }),
    )
    .await;
    assert_eq!(rejected["error"]["code"], "MESSAGE_NOT_FOUND");
    assert_eq!(rejected["error"]["retryable"], false);

    // No pending row was left behind: the same clientRequestId re-validates as
    // a fresh request instead of replaying a stuck pending record.
    let retried = request(
        &mut client,
        "send-quote-retry",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "text": "quote of nothing",
            "clientRequestId": "quote-req-missing"
        }),
    )
    .await;
    assert_eq!(retried["result"]["status"], "sent");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// messages.remoteDelete (contract revision 1.6, docs/remote-delete-l2-plan.md):
/// the happy path answers {"status":"deleted"} with the exact upstream params
/// (targetTimestamp from the sent row, recipient/groupId by conversation kind);
/// unknown params fail with INVALID_REQUEST; a nonexistent message is
/// MESSAGE_NOT_FOUND without touching the upstream.
#[tokio::test]
async fn remote_delete_maps_the_sent_row_and_answers_upstream_outcome() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [19_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Remote-Delete" }),
    )
    .await;
    // The fixture emits one receive after finishLink; drain both frames.
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let mut finished: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while finished.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                finished = Some(frame);
            }
        }
    })
    .await
    .unwrap();
    let account_id = finished.unwrap()["result"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Direct chat: send, then delete the sent message.
    let sent = request(
        &mut client,
        "send-1",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "delete me",
            "clientRequestId": "rd-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    // The connector overwrites sentAt with the send response's upstream
    // timestamp (99 in the fixture); the delete must address exactly it.
    let message_id = sent["result"]["id"].as_str().unwrap().to_string();
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    let deleted = request(
        &mut client,
        "rd-1",
        "messages.remoteDelete",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": message_id,
            "operationId": "rd-operation-1"
        }),
    )
    .await;
    assert_eq!(deleted["result"]["status"], "deleted");

    // The exact upstream dispatch was recorded by the fixture.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log remoteDelete params");
    let delete_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the remoteDelete must reach the upstream");
    assert_eq!(delete_call["account"], "+15555550100");
    assert_eq!(delete_call["targetTimestamp"], 99);
    assert_eq!(delete_call["recipient"], json!(["+15555550101"]));

    // Unknown params are rejected by shape before any local lookup.
    let invalid = request(
        &mut client,
        "rd-invalid",
        "messages.remoteDelete",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": message_id,
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");

    // A missing message answers MESSAGE_NOT_FOUND without an upstream call.
    let missing = request(
        &mut client,
        "rd-missing",
        "messages.remoteDelete",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": "no-such-message"
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "MESSAGE_NOT_FOUND");
    assert_eq!(missing["error"]["retryable"], false);

    // A group send resolves groupId addressing instead of recipient.
    let group_sent = request(
        &mut client,
        "send-group",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "group",
            "peerKey": "ZmFrZS1ncm91cC0x",
            "text": "group delete me",
            "clientRequestId": "rd-send-group"
        }),
    )
    .await;
    assert_eq!(group_sent["result"]["status"], "sent");
    let group_deleted = request(
        &mut client,
        "rd-group",
        "messages.remoteDelete",
        json!({
            "accountId": account_id,
            "conversationId": group_sent["result"]["conversationId"],
            "messageId": group_sent["result"]["id"]
        }),
    )
    .await;
    assert_eq!(group_deleted["result"]["status"], "deleted");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap();
    let group_call: Value = send_log
        .lines()
        .rev()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the group remoteDelete must reach the upstream");
    assert_eq!(group_call["groupId"], json!("ZmFrZS1ncm91cC0x"));
    assert!(group_call.get("recipient").is_none());

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// messages.sendReaction (contract revision 1.7, docs/remote-delete-l2-plan.md
/// §3.2 shape): reactions on a sent outgoing row and on an incoming row both
/// answer {"status":"sent"} with the direction-derived targetAuthor and the
/// conversation-kind addressing; unknown params fail with INVALID_REQUEST; a
/// missing message is MESSAGE_NOT_FOUND without touching the upstream; a
/// multi-grapheme emoji is rejected by shape before any local lookup.
#[tokio::test]
async fn send_reaction_maps_row_direction_and_answers_upstream_outcome() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [29_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Send-Reaction" }),
    )
    .await;
    // The fixture emits one receive notification after finishLink; the frames
    // can interleave with the finish response, so drain until both arrive.
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let mut finished: Option<Value> = None;
    let mut upserted: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while finished.is_none() || upserted.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                finished = Some(frame);
                continue;
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted") {
                upserted = Some(frame);
            }
        }
    })
    .await
    .expect("link finish must persist the fixture's receive notification");
    let account_id = finished.unwrap()["result"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // The fixture's receive: source +15555550101, envelope timestamp 42.
    let upserted = upserted.unwrap();
    let incoming_id = upserted["data"]["id"].as_str().unwrap().to_string();
    let conversation_id = upserted["data"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // React to the incoming row: targetAuthor is the peer, targetTimestamp is
    // the envelope timestamp, remove defaults to false.
    let reacted = request(
        &mut client,
        "sr-incoming",
        "messages.sendReaction",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": incoming_id,
            "emoji": "👍",
            "operationId": "sr-operation-in"
        }),
    )
    .await;
    assert_eq!(reacted["result"]["status"], "sent");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log sendReaction params");
    let reaction_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the sendReaction must reach the upstream");
    assert_eq!(reaction_call["account"], "+15555550100");
    assert_eq!(reaction_call["emoji"], "👍");
    assert_eq!(reaction_call["remove"], false);
    assert_eq!(reaction_call["targetAuthor"], "+15555550101");
    assert_eq!(reaction_call["targetTimestamp"], 42);
    assert_eq!(reaction_call["recipient"], json!(["+15555550101"]));

    // Outgoing `sent` row: targetAuthor is the linked account itself, and
    // remove=true passes through as an explicit boolean.
    let sent = request(
        &mut client,
        "send-1",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "react to me",
            "clientRequestId": "sr-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let removed = request(
        &mut client,
        "sr-outgoing",
        "messages.sendReaction",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": sent["result"]["id"],
            "emoji": "🎉",
            "remove": true
        }),
    )
    .await;
    assert_eq!(removed["result"]["status"], "sent");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap();
    let remove_call: Value = send_log
        .lines()
        .rev()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the reaction remove must reach the upstream");
    assert_eq!(remove_call["emoji"], "🎉");
    assert_eq!(remove_call["remove"], true);
    assert_eq!(remove_call["targetAuthor"], "+15555550100");
    assert_eq!(remove_call["targetTimestamp"], 99);

    // Unknown params are rejected by shape before any local lookup.
    let invalid = request(
        &mut client,
        "sr-invalid",
        "messages.sendReaction",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": incoming_id,
            "emoji": "👍",
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");

    // More than one grapheme cluster is rejected by shape (the schema bounds
    // length; the service enforces the cluster rule deterministically).
    let multi = request(
        &mut client,
        "sr-multi",
        "messages.sendReaction",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": incoming_id,
            "emoji": "👍👍"
        }),
    )
    .await;
    assert_eq!(multi["error"]["code"], "INVALID_REQUEST");

    // A missing message answers MESSAGE_NOT_FOUND without an upstream call.
    let missing = request(
        &mut client,
        "sr-missing",
        "messages.sendReaction",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": "no-such-message",
            "emoji": "👍"
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "MESSAGE_NOT_FOUND");
    assert_eq!(missing["error"]["retryable"], false);

    // A group send resolves groupId addressing instead of recipient.
    let group_sent = request(
        &mut client,
        "send-group",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "group",
            "peerKey": "ZmFrZS1ncm91cC0x",
            "text": "group react to me",
            "clientRequestId": "sr-send-group"
        }),
    )
    .await;
    assert_eq!(group_sent["result"]["status"], "sent");
    let group_reacted = request(
        &mut client,
        "sr-group",
        "messages.sendReaction",
        json!({
            "accountId": account_id,
            "conversationId": group_sent["result"]["conversationId"],
            "messageId": group_sent["result"]["id"],
            "emoji": "👍"
        }),
    )
    .await;
    assert_eq!(group_reacted["result"]["status"], "sent");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap();
    let group_call: Value = send_log
        .lines()
        .rev()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the group sendReaction must reach the upstream");
    assert_eq!(group_call["groupId"], json!("ZmFrZS1ncm91cC0x"));
    assert!(group_call.get("recipient").is_none());

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.27 end to end: envelopes carrying `sourceName` — staged in the
/// fixture's `.fixture-extra-receives.json` marker and delivered through the
/// real engine's receive stream — flow into the message rows (`senderName`),
/// the conversation summaries (`lastMessageDirection` /
/// `lastMessageAuthorName` / `lastMessageReactions`), and the per-actor
/// reaction detail on the pills (`actors` with self/name/reactedAt); a later
/// remove empties the pill and drops the summary emoji prefix, and an
/// outgoing ending flips the direction without an author name.
#[tokio::test]
async fn conversation_summary_and_reactions_carry_author_metadata() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [29_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // Stage the first batch before linking: one named group message and one
    // named group reaction onto it, both carrying the sender's display name
    // exactly like a real signal-cli receive envelope. finishLink's receive
    // burst delivers them right after the default unnamed direct receive.
    // Timestamps stay below 99 — the fixture's fixed send timestamp — so the
    // outgoing message sent at the end becomes the conversation's newest row.
    let extra_receives = temp
        .path()
        .join("signal-data")
        .join(".fixture-extra-receives.json");
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        &extra_receives,
        json!([
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": 50,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "message": "group hello"
                }
            },
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": 51,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "reaction": {
                        "emoji": "👍",
                        "targetAuthor": "+15555550101",
                        "targetSentTimestamp": 50,
                        "isRemove": false
                    }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Summary-Meta" }),
    )
    .await;
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;

    // Drain the finish burst: the link answer, the group message upsert, and
    // the add-state summary change (reaction emoji on the new last message).
    let mut account_id: Option<String> = None;
    let mut group_conversation_id: Option<String> = None;
    let mut group_message_id: Option<String> = None;
    timeout(Duration::from_secs(5), async {
        while account_id.is_none() || group_conversation_id.is_none() || group_message_id.is_none()
        {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                account_id = Some(frame["result"]["id"].as_str().unwrap().to_string());
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["sentAt"] == 50
            {
                group_message_id = Some(frame["data"]["id"].as_str().unwrap().to_string());
            }
            if frame.get("event").and_then(Value::as_str) == Some("conversation.changed")
                && frame["data"]["type"] == "group"
                && frame["data"]["lastMessageReactions"] == json!(["👍"])
            {
                group_conversation_id = Some(frame["data"]["id"].as_str().unwrap().to_string());
            }
        }
    })
    .await
    .expect("the finish burst must deliver the named group message and reaction");
    let account_id = account_id.unwrap();
    let group_conversation_id = group_conversation_id.unwrap();
    let group_message_id = group_message_id.unwrap();

    // Persisted add-state projection: direction incoming, captured author
    // name, reaction emoji on the group row; the unnamed direct row from the
    // default receive carries a direction but no author name.
    let conversations = request(
        &mut client,
        "conv-summary",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let items = conversations["result"]["items"].as_array().unwrap();
    let group_row = items
        .iter()
        .find(|item| item["id"] == group_conversation_id.as_str())
        .unwrap();
    assert_eq!(group_row["lastMessageDirection"], "incoming");
    assert_eq!(group_row["lastMessageAuthorName"], "林菲菲");
    assert_eq!(group_row["lastMessageReactions"], json!(["👍"]));
    assert!(group_row.get("lastMessageStatus").is_none());
    let direct_row = items
        .iter()
        .find(|item| item["type"] == "direct" && item.get("lastMessageDirection").is_some())
        .unwrap();
    assert_eq!(direct_row["lastMessageDirection"], "incoming");
    assert!(direct_row.get("lastMessageAuthorName").is_none());
    assert!(direct_row.get("lastMessageStatus").is_none());

    // The message row carries the author name and the per-actor pill detail
    // the official ReactionViewer renders.
    let messages = request(
        &mut client,
        "messages-meta",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "limit": 10
        }),
    )
    .await;
    let row = messages["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == group_message_id.as_str())
        .unwrap();
    assert_eq!(row["senderName"], "林菲菲");
    assert_eq!(row["reactions"][0]["emoji"], "👍");
    assert_eq!(row["reactions"][0]["count"], 1);
    assert_eq!(row["reactions"][0]["mine"], false);
    let actors = row["reactions"][0]["actors"].as_array().unwrap();
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0]["self"], false);
    assert_eq!(actors[0]["name"], "林菲菲");
    assert!(actors[0]["reactedAt"].is_u64());

    // Append the reaction remove and deliver it through a later upstream
    // call: the fixture flushes pending extra receives before answering
    // sendTyping, and a typing indicator changes no conversation state.
    let mut envelopes: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(&extra_receives).unwrap()).unwrap();
    envelopes.push(json!({
        "source": "+15555550101",
        "sourceName": "林菲菲",
        "timestamp": 52,
        "dataMessage": {
            "groupId": "ZmFrZS1ncm91cC0x",
            "reaction": {
                "emoji": "👍",
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 50,
                "isRemove": true
            }
        }
    }));
    fs::write(&extra_receives, serde_json::to_string(&envelopes).unwrap()).unwrap();

    send_request_frame(
        &mut client,
        "typing-flush",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id
        }),
    )
    .await;
    let mut remove_seen = false;
    timeout(Duration::from_secs(5), async {
        while !remove_seen {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("event").and_then(Value::as_str) == Some("conversation.changed")
                && frame["data"]["id"] == group_conversation_id.as_str()
                && frame["data"].get("lastMessageReactions").is_none()
            {
                remove_seen = true;
            }
        }
    })
    .await
    .expect("the reaction remove must clear the summary emoji prefix");

    // Removal semantics: the pill list is always serialized and empties
    // entirely, and the summary row keeps direction and author but loses the
    // reaction prefix.
    let messages = request(
        &mut client,
        "messages-meta-removed",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "limit": 10
        }),
    )
    .await;
    let row = messages["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == group_message_id.as_str())
        .unwrap();
    assert!(row["reactions"].as_array().unwrap().is_empty());
    let conversations = request(
        &mut client,
        "conv-summary-removed",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_row = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == group_conversation_id.as_str())
        .unwrap();
    assert_eq!(group_row["lastMessageDirection"], "incoming");
    assert_eq!(group_row["lastMessageAuthorName"], "林菲菲");
    assert!(group_row.get("lastMessageReactions").is_none());

    // An outgoing ending flips the direction and drops the author name: the
    // client renders its own self label.
    let sent = request(
        &mut client,
        "send-group-summary",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "text": "summary outgoing",
            "clientRequestId": "summary-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let conversations = request(
        &mut client,
        "conv-summary-outgoing",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_row = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == group_conversation_id.as_str())
        .unwrap();
    assert_eq!(group_row["lastMessageDirection"], "outgoing");
    assert!(group_row.get("lastMessageAuthorName").is_none());
    // Contract 1.28: the completed send carries its row status into the
    // summary — the same vocabulary the message rows use.
    assert_eq!(group_row["lastMessageStatus"], "sent");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn serve_ignores_java_home_and_never_leaks_java_env() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [14_u8; 32];
    write_secret_file(&secret_file, &secret);

    // The launcher-compat `--java-home` flag (Desktop still passes it) points
    // at a path serve no longer validates: serve must accept and
    // ignore it. A SOCKS proxy stays configured to prove serve starts with
    // one: the value is validated at launch, nothing proxy-shaped is placed
    // on the child command line, and the engine child inherits the same
    // `KT_SIGNAL_SOCKS_PROXY` environment (engine.rs pins the parse shape).
    // The fixture exits 94 immediately if JAVA_OPTS or JAVA_HOME leak into
    // its env.
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--java-home")
        .arg(temp.path().join("no-such-jre"))
        .arg("--signal-data-dir")
        .arg(temp.path().join("signal-data"))
        .arg("--state-dir")
        .arg(temp.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_SIGNAL_SOCKS_PROXY", "127.0.0.1:11080")
        .env("KT_FAKE_EXPECT_NO_JAVA", "1");
    let mut connector = command.spawn().unwrap();
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    // A JAVA_* leak kills the fixture at spawn; a live answer after a settle
    // delay proves the serve path answers requests without a JVM env.
    sleep(Duration::from_millis(200)).await;
    let accounts = request(&mut client, "accounts", "accounts.list", json!({})).await;
    assert!(accounts.get("result").is_some());

    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// conversations.setExpireTimer end to end (2026-10-06 group-timer batch;
/// engine main @ 216a4c7): the group form no longer answers the recorded
/// INVALID_REQUEST gate — it dispatches `updateGroup {account, groupId,
/// expiration}` verbatim (SEND_LOG), the groupUpdated projection the engine
/// emits after the change injects through the fixture and converges the
/// mirror, and `conversation.changed` carries the new timer. The
/// launcher-compat `--java-home` points at a path serve does not
/// validate: serve ignores it, and the fixture's no-Java guard would exit 94 if
/// either JAVA_* variable leaked into the child env.
#[tokio::test]
async fn kt_engine_mode_serves_group_expire_timer_and_group_updated() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [15_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--java-home")
        .arg(temp.path().join("no-such-jre"))
        .arg("--signal-data-dir")
        .arg(temp.path().join("signal-data"))
        .arg("--state-dir")
        .arg(temp.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_FAKE_EXPECT_NO_JAVA", "1");
    let mut connector = command.spawn().unwrap();
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupTimer" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The fixture links with one known group conversation in place; find it
    // and set its timer: the call must not answer the former INVALID_REQUEST
    // gate but the ordinary success.
    let listed = request(
        &mut client,
        "list-for-group",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with a group conversation");
    let group_timer = request(
        &mut client,
        "group-timer",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "expireSeconds": 3600
        }),
    )
    .await;
    assert_eq!(group_timer["result"]["expireTimerSeconds"], 3600);

    // The success mirror rides conversation.changed first — drain it so the
    // groupUpdated assertion below can only pass through its own path.
    let mut saw_send_mirror = false;
    for _ in 0..16 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "conversation.changed send mirror never arrived within \
                 {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed"
            && frame["data"]["id"] == group_conversation.as_str()
            && frame["data"]["expireTimerSeconds"] == 3600
        {
            saw_send_mirror = true;
            break;
        }
    }
    assert!(
        saw_send_mirror,
        "the send-path mirror must ride conversation.changed"
    );

    // The exact upstream contract landed on the engine wire.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the dispatch");
    let group_timer_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|params| params.get("groupId").is_some() && params.get("expiration").is_some())
        .expect("the group timer must reach updateGroup");
    assert_eq!(group_timer_call["account"], "+15555550100");
    assert_eq!(group_timer_call["groupId"], "ZmFrZS1ncm91cC0x");
    assert_eq!(group_timer_call["expiration"], 3600);

    // Inject the engine's groupUpdated projection (the real engine emits it
    // after the change lands — here a member changed the timer to 86400)
    // through the extra-receives marker, delivered by the sendTyping flush
    // (a typing indicator changes no conversation state — the clean post-link
    // flush trigger): the mirror converges through the receive path alone.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([{
            "timestamp": 1727000000000_u64,
            "groupUpdated": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "revision": 2,
                "expireTimerSeconds": 86400
            }
        }])
        .to_string(),
    )
    .unwrap();
    let _ = request(
        &mut client,
        "typing-flush",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation
        }),
    )
    .await;
    let mut saw_timer_change = false;
    for _ in 0..16 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "group conversation.changed timer mirror (86400) never arrived \
                 within {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed"
            && frame["data"]["id"] == group_conversation.as_str()
            && frame["data"]["expireTimerSeconds"] == 86400
        {
            saw_timer_change = true;
            break;
        }
    }
    assert!(
        saw_timer_change,
        "the groupUpdated projection must converge the mirror through conversation.changed"
    );

    // conversations.list agrees with the receive-path mirror.
    let listed = request(
        &mut client,
        "list-after-update",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == group_conversation.as_str())
        .expect("the conversation is listed")
        .clone();
    assert_eq!(row["expireTimerSeconds"], 86400);

    // The off form (0) routes the same updateGroup write — the engine face
    // validates 0 = off verbatim.
    let off_timer = request(
        &mut client,
        "group-timer-off",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "expireSeconds": 0
        }),
    )
    .await;
    assert_eq!(off_timer["result"]["expireTimerSeconds"], 0);
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the dispatch");
    let off_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|params| params.get("expiration") == Some(&json!(0)))
        .expect("the off timer must reach updateGroup");
    assert_eq!(off_call["groupId"], "ZmFrZS1ncm91cC0x");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.134 (§4.117): the engine-notification forwarding batch end to
/// end. Pass-through lane: the fixture's raw-notification marker injects the
/// three standalone account-domain notifications and their host frames ride
/// with the resolved accountId (receive.emptied / receive.clockSkew /
/// conversation.stateChanged); the envelope-key faces (groupTerminated /
/// contactProfileUpdated) ride the extra-receives channel like the
/// groupUpdated projection. F red line: a conversations array past the
/// engine's own batch cap forwards verbatim — no connector trim, unnamed
/// sibling keys ride. Attribution/error lane: a notification naming an
/// unbound account forwards nothing (the warn-only drop), and a malformed
/// face surfaces as runtime.protocolWarning instead of a guessed frame.
/// Local gate n/a (the events carry no request) and crash n/a (the engine
/// staying alive is the assertion) — the §4.114 four-lane set's other two
/// lanes do not apply to notifications.
#[tokio::test]
async fn engine_notifications_forward_through_the_transient_lane() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [21_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--java-home")
        .arg(temp.path().join("no-such-jre"))
        .arg("--signal-data-dir")
        .arg(temp.path().join("signal-data"))
        .arg("--state-dir")
        .arg(temp.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_FAKE_EXPECT_NO_JAVA", "1");
    let mut connector = command.spawn().unwrap();
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-EngineNotifications" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Drain the link-time burst (the fixture's default receive and any
    // mirrors) before injecting, so the assertions below only see this
    // batch's frames. Opportunistic drain: dry reads cost a short window,
    // never the full harness timeout.
    for _ in 0..8 {
        let read = timeout(Duration::from_secs(2), client.next()).await;
        if read.is_err() || matches!(read, Ok(None)) {
            break;
        }
    }

    // Pass-through lane, standalone methods: one marker batch with the
    // three notifications.
    async fn next_frame(client: &mut Framed<UnixStream, LinesCodec>) -> Value {
        match timeout(HARNESS_REQUEST_TIMEOUT, client.next()).await {
            Ok(Some(Ok(line))) => serde_json::from_str::<Value>(&line).unwrap(),
            other => panic!(
                "the host frame stream ended early: {other:?}\n{}",
                dump_connector_crash_scene()
            ),
        }
    }
    // The quiet read: an Option window for drains and absence proofs — a
    // dry stream is a value, not a failure.
    async fn next_frame_quiet(client: &mut Framed<UnixStream, LinesCodec>) -> Option<Value> {
        match timeout(Duration::from_secs(2), client.next()).await {
            Ok(Some(Ok(line))) => serde_json::from_str::<Value>(&line).ok(),
            _ => None,
        }
    }
    let conversations = json!([
        {
            "conversationId": "11111111-1111-1111-1111-111111111111",
            "kind": "contact",
            "mutedUntilTimestamp": 1727000000000_u64,
            "archived": true,
            "markedUnread": false,
            "unnamedSibling": { "rides": true },
        },
        {
            "conversationId": "ZmFrZS1ncm91cC0x",
            "kind": "group",
            "mutedUntilTimestamp": 0,
            "archived": false,
            "markedUnread": true,
        },
    ]);
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-notifications.json"),
        json!({ "notifications": [
            { "jsonrpc": "2.0", "method": "receive.emptied", "params": { "account": "+15555550100" } },
            { "jsonrpc": "2.0", "method": "receive.clockskew", "params": {
                "account": "+15555550100", "skewMs": -86_400_001_i64, "serverTimestamp": 1727000000000_u64 } },
            { "jsonrpc": "2.0", "method": "receive.conversationState", "params": {
                "account": "+15555550100", "conversations": conversations, "overflow": false } },
            { "jsonrpc": "2.0", "method": "engine.storagePull", "params": {
                "account": "+15555550100", "trigger": "login", "contactsOk": true, "groupsOk": false } },
        ] })
        .to_string(),
    )
    .unwrap();

    let mut saw_emptied = None;
    let mut saw_skew = None;
    let mut saw_state = None;
    let mut saw_pull = None;
    for _ in 0..24 {
        let frame = next_frame(&mut client).await;
        match frame["event"].as_str() {
            Some("receive.emptied") => saw_emptied = Some(frame),
            Some("receive.clockSkew") => saw_skew = Some(frame),
            Some("conversation.stateChanged") => saw_state = Some(frame),
            Some("engine.storagePull") => saw_pull = Some(frame),
            _ => {}
        }
        if saw_emptied.is_some() && saw_skew.is_some() && saw_state.is_some() && saw_pull.is_some()
        {
            break;
        }
    }
    let emptied = saw_emptied.expect("receive.emptied must ride the lane");
    assert_eq!(emptied["data"]["accountId"], account_id);
    let skew = saw_skew.expect("receive.clockSkew must ride the lane");
    assert_eq!(skew["data"]["accountId"], account_id);
    assert_eq!(skew["data"]["skewMs"], -86_400_001, "signed skew verbatim");
    assert_eq!(skew["data"]["serverTimestamp"], 1727000000000_u64);
    let state = saw_state.expect("conversation.stateChanged must ride the lane");
    assert_eq!(state["data"]["accountId"], account_id);
    assert_eq!(
        state["data"]["conversations"], conversations,
        "the batch rides verbatim, sibling keys included"
    );
    assert_eq!(state["data"]["overflow"], false);
    // Contract 1.141 (§4.137): the storage-pull outcome rides the same lane
    // with the resolved account and the verbatim trigger.
    let pull = saw_pull.expect("engine.storagePull must ride the lane");
    assert_eq!(pull["data"]["accountId"], account_id);
    assert_eq!(pull["data"]["trigger"], "login");
    assert_eq!(pull["data"]["contactsOk"], true);
    assert_eq!(pull["data"]["groupsOk"], false);

    // F red line: a batch past the engine's own 256-entry cap forwards
    // verbatim — the connector never trims, and the overflow tail marker
    // rides beside the array.
    let oversized: Vec<Value> = (0..257)
        .map(|index| {
            json!({
                "conversationId": format!("id-{index}"),
                "kind": "contact",
                "mutedUntilTimestamp": index,
                "archived": false,
                "markedUnread": true,
            })
        })
        .collect();
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-notifications.json"),
        json!({ "notifications": [
            { "jsonrpc": "2.0", "method": "receive.conversationState", "params": {
                "account": "+15555550100", "conversations": oversized, "overflow": true } },
        ] })
        .to_string(),
    )
    .unwrap();
    let mut saw_oversized = None;
    for _ in 0..24 {
        let frame = next_frame(&mut client).await;
        if frame["event"] == "conversation.stateChanged" {
            saw_oversized = Some(frame);
            break;
        }
    }
    let state = saw_oversized.expect("the oversized batch must ride");
    let carried = state["data"]["conversations"].as_array().unwrap();
    assert_eq!(
        carried.len(),
        257,
        "the connector never trims the engine batch: {} entries",
        carried.len()
    );
    assert_eq!(carried[0]["conversationId"], "id-0");
    assert_eq!(carried[256]["conversationId"], "id-256");
    assert_eq!(state["data"]["overflow"], true, "the tail marker rides");

    // Envelope-key faces: the termination and profile-refresh projections
    // ride the receive lane (the extra-receives marker + the typing flush,
    // the groupUpdated test's channel). The two forwarded frames race the
    // flush request's own reply — the marker flushes during the upstream
    // listContacts call, before the answer — so the interleaved event frames
    // are collected beside the reply instead of eaten by a reply-only read.
    async fn request_collecting(
        client: &mut Framed<UnixStream, LinesCodec>,
        request_id: &str,
        method: &str,
        params: Value,
        interleaved: &mut Vec<Value>,
    ) -> Value {
        send_request_frame(client, request_id, method, params).await;
        loop {
            let frame = next_frame(client).await;
            if frame.get("requestId").and_then(Value::as_str) == Some(request_id) {
                return frame;
            }
            interleaved.push(frame);
        }
    }
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "timestamp": 1727000001000_u64,
                "groupTerminated": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "terminator": "33333333-3333-3333-3333-333333333333",
                    "timestamp": 1727000001000_u64,
                },
            },
            {
                "timestamp": 1727000002000_u64,
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "contactProfileUpdated": { "aci": "22222222-2222-2222-2222-222222222222" },
            },
        ])
        .to_string(),
    )
    .unwrap();
    let mut interleaved = Vec::new();
    let listed = request_collecting(
        &mut client,
        "list-for-flush",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
        &mut interleaved,
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with a group conversation");
    let _ = request_collecting(
        &mut client,
        "typing-flush",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation
        }),
        &mut interleaved,
    )
    .await;
    fn note_lane_frame(
        frame: Value,
        saw_terminated: &mut Option<Value>,
        saw_profile: &mut Option<Value>,
    ) {
        match frame["event"].as_str() {
            Some("group.terminated") if saw_terminated.is_none() => {
                *saw_terminated = Some(frame);
            }
            Some("contact.profileUpdated") if saw_profile.is_none() => {
                *saw_profile = Some(frame);
            }
            _ => {}
        }
    }
    let mut saw_terminated = None;
    let mut saw_profile = None;
    for frame in interleaved {
        note_lane_frame(frame, &mut saw_terminated, &mut saw_profile);
    }
    for _ in 0..24 {
        if saw_terminated.is_some() && saw_profile.is_some() {
            break;
        }
        let frame = next_frame(&mut client).await;
        note_lane_frame(frame, &mut saw_terminated, &mut saw_profile);
    }
    let terminated = saw_terminated.expect("group.terminated must ride the lane");
    assert_eq!(terminated["data"]["accountId"], account_id);
    assert_eq!(terminated["data"]["groupId"], "ZmFrZS1ncm91cC0x");
    assert_eq!(
        terminated["data"]["terminator"],
        "33333333-3333-3333-3333-333333333333"
    );
    assert_eq!(terminated["data"]["timestamp"], 1727000001000_u64);
    let profile = saw_profile.expect("contact.profileUpdated must ride the lane");
    assert_eq!(profile["data"]["accountId"], account_id);
    assert_eq!(
        profile["data"]["aci"],
        "22222222-2222-2222-2222-222222222222"
    );
    assert_eq!(profile["data"]["timestamp"], 1727000002000_u64);

    // Attribution/error lane: an unbound account forwards nothing, and a
    // malformed face (a non-array conversations) surfaces as
    // runtime.protocolWarning — never a guessed frame.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-notifications.json"),
        json!({ "notifications": [
            { "jsonrpc": "2.0", "method": "receive.emptied", "params": { "account": "+15555550999" } },
            { "jsonrpc": "2.0", "method": "receive.conversationState", "params": {
                "account": "+15555550100", "conversations": 42, "overflow": false } },
            { "jsonrpc": "2.0", "method": "engine.storagePull", "params": {
                "account": "+15555550100", "trigger": "login", "contactsOk": true } },
        ] })
        .to_string(),
    )
    .unwrap();
    let mut saw_warning = false;
    let mut unattributed_forward = None;
    // The quiet window: long enough for the batch to deliver (or drop),
    // bounded so absence stays provable without the full harness timeout.
    for _ in 0..12 {
        let Some(frame) = next_frame_quiet(&mut client).await else {
            continue;
        };
        match frame["event"].as_str() {
            Some("runtime.protocolWarning") => saw_warning = true,
            Some("receive.emptied")
            | Some("conversation.stateChanged")
            | Some("engine.storagePull") => {
                unattributed_forward = Some(frame);
                break;
            }
            _ => {}
        }
    }
    assert!(
        saw_warning,
        "the malformed face must surface as a protocol warning"
    );
    assert!(
        unattributed_forward.is_none(),
        "an unbound account must never forward: {unattributed_forward:?}"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn link_finish_reports_a_non_retryable_unknown_outcome_when_the_engine_dies() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [9_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "[crash-link-test]" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;

    // finishLink is Mutating, so a lost result must not be reported as a
    // retryable timeout: re-running it could claim a second device slot.
    assert_eq!(finished["error"]["code"], "LINK_OUTCOME_UNKNOWN");
    assert_eq!(finished["error"]["retryable"], false);

    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// The engine's own finish dispatch budget (360 s) is the deadline that fires
/// first in production — the connector's 370 s is the outer backstop. Its
/// `(EngineTimeoutException)` on the mutating `finishLink` must fold to the
/// same link-class unknown outcome the connector's own budget expiry answers:
/// a definite retryable timeout would invite a second device slot.
#[tokio::test]
async fn link_finish_folds_the_engine_budget_timeout_to_the_unknown_outcome() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [21_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_FINISH_ENGINE_TIMEOUT", "1")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Finish-Budget" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;

    assert_eq!(finished["error"]["code"], "LINK_OUTCOME_UNKNOWN");
    assert_eq!(finished["error"]["retryable"], false);
    assert_ne!(finished["error"]["code"], "UPSTREAM_TIMEOUT");
    assert_ne!(finished["error"]["code"], "LINK_EXPIRED");

    // The unknown outcome is not an engine fault: the shared engine keeps
    // serving (nothing was restarted behind the host's back).
    let status = request(&mut client, "status", "runtime.status", json!({})).await;
    assert_eq!(status["result"]["state"], "running");

    drop(client);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn delete_refuses_same_number_relink_until_cleanup_settles() {
    // B4 (§9.10 item 7): a relink of the number whose local-data delete has
    // not settled must be refused honestly; once the delete completes the
    // same number links again.
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [14_u8; 32];
    fs::write(&secret_file, bootstrap_payload(&secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();

    let mut connector =
        spawn_connector_with(temp.path(), &endpoint, &secret_file, Some("hold"), &[]);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "b4-start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    let link = request(
        &mut client,
        "b4-link",
        "link.start",
        json!({ "deviceName": "KT-B4" }),
    )
    .await;
    let finished = request(
        &mut client,
        "b4-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // An in-flight transfer download for this account: the delete must cancel
    // it through the only account-task cancel face the pinned engine has.
    fs::write(signal_data.join(".fixture-transfer-running"), "").unwrap();
    fs::write(signal_data.join(".fixture-transfer-bytes"), "0").unwrap();

    send_request_frame(
        &mut client,
        "b4-delete",
        "accounts.deleteLocalData",
        json!({ "accountId": account_id, "operationId": "b4-delete-op" }),
    )
    .await;
    wait_for_marker(&signal_data.join(".fixture-delete-running")).await;
    let cancel_log =
        fs::read_to_string(signal_data.join(".fixture-import-cancel-log")).unwrap_or_default();
    assert_eq!(
        cancel_log.lines().collect::<Vec<_>>(),
        vec!["+15555550100"],
        "the delete cancels the account's own import task before dispatch"
    );
    assert!(
        !signal_data.join(".fixture-transfer-running").exists(),
        "the in-flight transfer task was cancelled"
    );

    // While the delete is held open, the same number's relink is refused with
    // the honest in-progress code and is retryable.
    let relink = request(
        &mut client,
        "b4-relink-while-deleting",
        "link.start",
        json!({ "deviceName": "KT-B4-Relink" }),
    )
    .await;
    let refused = request(
        &mut client,
        "b4-finish-while-deleting",
        "link.finish",
        json!({ "linkSessionId": relink["result"]["linkSessionId"] }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "ACCOUNT_DELETE_IN_PROGRESS");
    assert_eq!(refused["error"]["retryable"], false);

    // Release the delete and wait for the store cleanup to land.
    fs::write(signal_data.join(".fixture-delete-release"), "").unwrap();
    let delete_response = await_response(&mut client, "b4-delete").await;
    assert!(
        delete_response.get("result").is_some(),
        "the delete must complete: {delete_response}"
    );
    wait_until_accounts_empty(&mut client, "b4-delete-settling").await;

    // Same number links again after the cleanup.
    let relink = request(
        &mut client,
        "b4-relink-after",
        "link.start",
        json!({ "deviceName": "KT-B4-Relink" }),
    )
    .await;
    let relinked = request(
        &mut client,
        "b4-finish-after",
        "link.finish",
        json!({ "linkSessionId": relink["result"]["linkSessionId"] }),
    )
    .await;
    assert!(
        relinked["result"]["id"].as_str().is_some(),
        "the same number must link after the delete settled: {relinked}"
    );
    let accounts = request(&mut client, "b4-accounts-after", "accounts.list", json!({})).await;
    assert_eq!(accounts["result"].as_array().unwrap().len(), 1);

    drop(client);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn delete_cancels_only_its_own_accounts_tasks() {
    // B4 (§9.10 item 6): deleting A cancels A's import task without touching
    // B's engine connection, and the cancel face is idempotent when there is
    // nothing in flight.
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [15_u8; 32];
    fs::write(&secret_file, bootstrap_payload(&secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        Some("hold"),
        &[("KT_FAKE_MULTI_ACCOUNT", "1")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "b4b-start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    let mut account_ids = Vec::new();
    for (index, name) in ["KT-B4B-A", "KT-B4B-B"].iter().enumerate() {
        let link = request(
            &mut client,
            &format!("b4b-link-{index}"),
            "link.start",
            json!({ "deviceName": name }),
        )
        .await;
        let finished = request(
            &mut client,
            &format!("b4b-finish-{index}"),
            "link.finish",
            json!({ "linkSessionId": link["result"]["linkSessionId"] }),
        )
        .await;
        account_ids.push(finished["result"]["id"].as_str().unwrap().to_string());
    }
    let numbers: Vec<String> = fs::read_to_string(signal_data.join(".fixture-linked-numbers"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(numbers.len(), 2);
    let (a_number, b_number) = (numbers[0].clone(), numbers[1].clone());
    assert_ne!(a_number, b_number);

    fs::write(signal_data.join(".fixture-transfer-running"), "").unwrap();
    fs::write(signal_data.join(".fixture-transfer-bytes"), "0").unwrap();
    send_request_frame(
        &mut client,
        "b4b-delete-a",
        "accounts.deleteLocalData",
        json!({ "accountId": account_ids[0], "operationId": "b4b-delete-op" }),
    )
    .await;
    wait_for_marker(&signal_data.join(".fixture-delete-running")).await;

    // A's task was cancelled; B's was not touched.
    let cancel_log = fs::read_to_string(signal_data.join(".fixture-import-cancel-log")).unwrap();
    assert_eq!(
        cancel_log.lines().collect::<Vec<_>>(),
        vec![a_number.as_str()],
        "the delete cancels only its own account's task"
    );

    // B keeps working while A's delete is still held open.
    let accounts = request(&mut client, "b4b-accounts", "accounts.list", json!({})).await;
    assert!(
        accounts["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|account| account["id"].as_str() == Some(account_ids[1].as_str())),
        "B stays bound during A's delete"
    );
    let b_synced = request(
        &mut client,
        "b4b-sync-b",
        "contacts.sync",
        json!({ "accountId": account_ids[1] }),
    )
    .await;
    assert_eq!(b_synced["result"]["contactCount"], 3);

    // Cancelling an account with nothing in flight is an idempotent no-op.
    for round in 0..2 {
        let cancelled = request(
            &mut client,
            &format!("b4b-cancel-b-{round}"),
            "history.importCancel",
            json!({ "accountId": account_ids[1] }),
        )
        .await;
        assert_eq!(cancelled["result"]["cancelled"], false);
    }

    fs::write(signal_data.join(".fixture-delete-release"), "").unwrap();
    let delete_response = await_response(&mut client, "b4b-delete-a").await;
    assert!(
        delete_response.get("result").is_some(),
        "A's delete must complete: {delete_response}"
    );
    wait_until_only_account(&mut client, &account_ids[1], "b4b-delete-settling").await;
    let b_synced_after = request(
        &mut client,
        "b4b-sync-b-after",
        "contacts.sync",
        json!({ "accountId": account_ids[1] }),
    )
    .await;
    assert_eq!(b_synced_after["result"]["contactCount"], 3);

    drop(client);
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn account_delete_unknown_is_reconciled_only_on_explicit_retry() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [8_u8; 32];
    fs::write(&secret_file, bootstrap_payload(&secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    let mut connector = spawn_connector_with_delete_mode(
        temp.path(),
        &endpoint,
        &secret_file,
        Some("crash_after_delete_once"),
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Delete-Recovery" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    let unknown = request(
        &mut client,
        "delete-unknown",
        "accounts.deleteLocalData",
        json!({
            "accountId": account_id,
            "operationId": "delete-recovery-operation"
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "ACCOUNT_DELETE_OUTCOME_UNKNOWN");

    let restarted = request(&mut client, "restart", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let reconciled = request(
        &mut client,
        "delete-reconcile",
        "accounts.deleteLocalData",
        json!({
            "accountId": account_id,
            "operationId": "delete-recovery-operation"
        }),
    )
    .await;
    assert!(reconciled.get("result").is_some());
    let deleted = &reconciled["result"]["deleted"];
    assert_eq!(deleted["accountId"], account_id);
    assert!(
        deleted["digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")),
        "the delete answer carries the content-free receipt: {reconciled:?}"
    );
    assert!(deleted["rowsDeleted"].as_u64().is_some());
    assert!(
        deleted["tableCounts"].is_object(),
        "counts ride the receipt: {reconciled:?}"
    );
    assert!(
        reconciled["result"].get("signalAccount").is_none(),
        "the receipt never echoes the linked number"
    );
    let idempotent = request(
        &mut client,
        "delete-completed",
        "accounts.deleteLocalData",
        json!({
            "accountId": account_id,
            "operationId": "delete-recovery-operation"
        }),
    )
    .await;
    assert!(
        idempotent.get("result").is_some(),
        "idempotent delete response: {idempotent:?}"
    );
    assert_eq!(
        idempotent["result"]["deleted"]["digest"], deleted["digest"],
        "the replay returns the recorded receipt unchanged"
    );
    let accounts = request(&mut client, "accounts", "accounts.list", json!({})).await;
    assert!(accounts["result"].as_array().unwrap().is_empty());

    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// Regression for the delete/send race (optimization-plan Phase 1b): without
/// the drain barrier, a delete on the control lane could clear the account
/// rows while an upstream send on the send lane was still in flight — the
/// message went out but the completion found no pending row. With the barrier
/// the in-flight send completes fully before the delete runs, and a send that
/// arrives during the delete is rejected. Linearization point: the per-account
/// dispatch mutex, held across the whole dispatch including the completion
/// write and the host response.
#[tokio::test]
async fn account_delete_drains_in_flight_send_and_rejects_new_sends() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [13_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Delete-Race" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The fixture answers a "[slow-host-test]" send after ~350ms, so this send
    // is upstream-in-flight when the delete arrives.
    send_request_frame(
        &mut client,
        "race-send-slow",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "[slow-host-test]",
            "clientRequestId": "race-slow"
        }),
    )
    .await;
    // Let the send reach the upstream wait before the delete arrives.
    sleep(Duration::from_millis(100)).await;
    send_request_frame(
        &mut client,
        "race-delete",
        "accounts.deleteLocalData",
        json!({
            "accountId": account_id,
            "operationId": "race-delete-operation"
        }),
    )
    .await;
    // The delete marks the account before draining, so a send issued now is
    // rejected instead of queueing behind the delete.
    sleep(Duration::from_millis(50)).await;
    send_request_frame(
        &mut client,
        "race-send-during-delete",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "must never reach the upstream",
            "clientRequestId": "race-during-delete"
        }),
    )
    .await;

    let mut order = Vec::new();
    let mut slow = None;
    let mut delete = None;
    let mut during = None;
    while slow.is_none() || delete.is_none() || during.is_none() {
        let response: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(response) => response,
            Err(_) => panic!(
                "the delete-race drain stalled over {HARNESS_REQUEST_TIMEOUT:?} \
                 with order {order:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        match response.get("requestId").and_then(Value::as_str) {
            Some("race-send-slow") => {
                order.push("race-send-slow");
                slow = Some(response);
            }
            Some("race-delete") => {
                order.push("race-delete");
                delete = Some(response);
            }
            Some("race-send-during-delete") => {
                order.push("race-send-during-delete");
                during = Some(response);
            }
            _ => {}
        }
    }

    // The drained send completed and was answered before the delete: its
    // completion write (and response) happened strictly ahead of the delete's
    // upstream call, so no "sent but locally rowless" message can exist.
    let slow = slow.unwrap();
    assert_eq!(slow["result"]["status"], "sent");
    let delete = delete.unwrap();
    assert!(delete.get("result").is_some());
    let send_pos = order.iter().position(|id| *id == "race-send-slow").unwrap();
    let delete_pos = order.iter().position(|id| *id == "race-delete").unwrap();
    assert!(
        send_pos < delete_pos,
        "the delete must answer only after the drained send: {order:?}"
    );

    // The send issued during the delete never reached the upstream.
    let during = during.unwrap();
    assert_eq!(during["error"]["code"], "ACCOUNT_NOT_FOUND");
    assert_eq!(during["error"]["retryable"], false);

    let accounts = request(&mut client, "accounts-after", "accounts.list", json!({})).await;
    assert!(accounts["result"].as_array().unwrap().is_empty());

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Phase 3 dev/test override: a legacy single-line payload plus the
/// KT_SIGNAL_STORE_KEY environment variable serves normally, and the store on
/// disk is encrypted (no plaintext SQLite header).
#[tokio::test]
async fn store_key_env_override_unlocks_a_secret_only_payload() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [31_u8; 32];
    // Line 1 only: no store key in the payload, so the env override provides it.
    fs::write(&secret_file, hex::encode(secret)).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
    let store_key = hex::encode([0xA5_u8; 32]);

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_SIGNAL_STORE_KEY", store_key.as_str())],
    );
    wait_for_path(&endpoint).await;

    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start-1", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");

    drop(client);
    assert_clean_exit(&mut connector).await;

    let db = temp.path().join("state").join("connector.sqlite3");
    let mut header = [0_u8; 16];
    std::io::Read::read_exact(&mut fs::File::open(&db).unwrap(), &mut header).unwrap();
    assert_ne!(&header, b"SQLite format 3\0");
}

/// Phase 3 fail closed: with no store key anywhere (single-line payload, no
/// env override), the connector exits with a classified error before serving
/// and never creates a database.
#[tokio::test]
async fn missing_store_key_fails_closed_before_serving() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    fs::write(&secret_file, hex::encode([41_u8; 32])).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    let status = timeout(Duration::from_secs(5), connector.wait())
        .await
        .expect("a connector without a store key should exit promptly")
        .unwrap();
    assert!(!status.success());
    let mut stderr = String::new();
    if let Some(mut pipe) = connector.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr).await;
    }
    assert!(
        stderr.contains("store key is required"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !temp.path().join("state").join("connector.sqlite3").exists(),
        "fail closed means no database is created"
    );
}

#[tokio::test]
async fn incoming_mentions_project_author_aci_on_the_wire_row() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [41_u8; 32];
    write_secret_file(&secret_file, &secret);

    // Two inbound mention envelopes injected through the runtime marker: one
    // signal-cli-shaped (number + uuid), one engine-mode-shaped (the ACI
    // under the number key). The row projection is the §4.40 desktop
    // contract: author unchanged, authorAci only when honestly known.
    // The marker is written only AFTER link.finish (the established
    // convention, see the view-once chain test): injection is single-shot
    // (the fake engine deletes the marker after emitting), so an envelope
    // emitted before the account is registered is dropped fail-closed and
    // the test would flap on load.
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-MentionAci" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": "+15555550101",
                "sourceName": "Alice",
                "timestamp": 600,
                "dataMessage": {
                    "message": "hello @you",
                    "mentions": [{
                        "number": "+15555550101",
                        "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                        "start": 6,
                        "length": 3,
                    }],
                },
            },
            {
                "source": "+15555550101",
                "sourceName": "Alice",
                "timestamp": 601,
                "dataMessage": {
                    "message": "engine face",
                    "mentions": [{
                        "number": "d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df1",
                        "start": 0,
                        "length": 6,
                    }],
                },
            },
        ] })
        .to_string(),
    )
    .unwrap();

    // The injected envelopes land as rows; poll the history read until both
    // mention rows are visible (each poll drains any interleaved events).
    // 全量并发下引擎/连接器处理信封需要真实时间，轮询间隔给处理让路
    // （仓内既有轮询惯例，见 groups/history 各用例的 20-50ms sleep）。
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
        let listed = request(
            &mut client,
            &format!("list-{attempt}"),
            "messages.search",
            json!({ "accountId": account_id, "query": "e", "limit": 50 }),
        )
        .await;
        rows = listed["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row.get("mentions").is_some())
            .cloned()
            .collect();
        if rows.len() == 2 {
            break;
        }
    }
    assert_eq!(rows.len(), 2, "both mention envelopes landed: {rows:?}");
    for row in &rows {
        let mentions = row["mentions"].as_array().expect("mentions on the wire");
        assert_eq!(mentions.len(), 1);
        match row["sentAt"].as_u64().unwrap() {
            600 => {
                assert_eq!(mentions[0]["author"], "+15555550101");
                assert_eq!(
                    mentions[0]["authorAci"],
                    "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10"
                );
                assert_eq!(mentions[0]["start"], 6);
                assert_eq!(mentions[0]["length"], 3);
            }
            601 => {
                assert_eq!(
                    mentions[0]["author"],
                    "d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df1"
                );
                assert_eq!(
                    mentions[0]["authorAci"], "d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df1",
                    "the engine-mode ACI promotes by shape"
                );
            }
            other => panic!("unexpected row timestamp {other}"),
        }
    }

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// §4.118 end-to-end: the fake engine's live poll envelopes ride the
/// receive stream verbatim — the bodyless `dataMessage.poll` create lands a
/// message row whose wire `poll` face is byte-identical to the §4.38
/// history chain's (no `terminated`, no `votes`, no `voteCount` yet), the
/// later `pollVote` folds the voter into that same row on
/// `message.upserted`, and the `pollTerminate` flips `terminated` in place
/// — and, since §4.189, lands the standalone notice row beside the poll
/// (the flattened `pollTerminate` rich face on a `system` row keyed to the
/// terminate envelope's own stamp). The vote rides in the same emission as
/// its create (the §4.91 buffer converges whatever order the stream picks).
#[tokio::test]
async fn live_poll_create_vote_terminate_land_the_history_shape() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [43_u8; 32];
    write_secret_file(&secret_file, &secret);

    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-LivePoll" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Stage one: the create alone. The marker is written only AFTER
    // link.finish (the established convention — injection is single-shot
    // and pre-registration envelopes drop fail-closed).
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": "+15555550101",
                "sourceName": "Alice",
                "timestamp": 600,
                "dataMessage": {
                    "groupInfo": { "groupId": "Z3JvdXAta2V5" },
                    "poll": {
                        "question": "Lunch?",
                        "options": ["Ramen", "Sushi"],
                        "allowMultiple": true,
                    },
                },
            },
        ] })
        .to_string(),
    )
    .unwrap();

    // Poll the history reads until the create row is visible (each poll
    // drains interleaved events).
    let mut conversation_id = String::new();
    let mut create_row: Option<Value> = None;
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = request(
            &mut client,
            &format!("poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        let conversations = request(
            &mut client,
            &format!("conv-{attempt}"),
            "conversations.list",
            json!({ "accountId": account_id, "limit": 50 }),
        )
        .await;
        let group = conversations["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"] == "group")
            .cloned();
        let Some(group) = group else { continue };
        conversation_id = group["id"].as_str().unwrap().to_string();
        let listed = request(
            &mut client,
            &format!("list-{attempt}"),
            "messages.list",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "limit": 50,
            }),
        )
        .await;
        let items = listed["result"]["items"].as_array().unwrap();
        if let Some(row) = items.iter().find(|row| row.get("poll").is_some()) {
            create_row = Some(row.clone());
            break;
        }
    }
    let create_row = create_row.expect("the poll create row landed");
    assert_eq!(create_row["direction"], "incoming");
    assert_eq!(create_row["sentAt"], 600);
    assert!(
        create_row.get("body").is_none() || create_row["body"].is_null(),
        "poll creates carry no body"
    );
    // The wire face is the §4.38 history chain's exact keys: the defaults
    // (terminated false, no votes) stay absent and `voteCount` never rides.
    assert_eq!(
        create_row["poll"],
        json!({
            "question": "Lunch?",
            "options": ["Ramen", "Sushi"],
            "allowMultiple": true,
        })
    );

    // Stage two: the vote and the terminate ride one emission — whatever
    // order the connector ingests them in, the folded row converges.
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": "+15555550101",
                "timestamp": 601,
                "dataMessage": {
                    "groupInfo": { "groupId": "Z3JvdXAta2V5" },
                    "pollVote": {
                        "targetAuthor": "+15555550101",
                        "targetSentTimestamp": 600,
                        "optionIndexes": [1],
                        "voteCount": 1,
                    },
                },
            },
            {
                "source": "+15555550101",
                "timestamp": 602,
                "dataMessage": {
                    "groupInfo": { "groupId": "Z3JvdXAta2V5" },
                    "pollTerminate": { "targetSentTimestamp": 600 },
                },
            },
        ] })
        .to_string(),
    )
    .unwrap();

    let mut folded_row: Option<Value> = None;
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = request(
            &mut client,
            &format!("poll2-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        let listed = request(
            &mut client,
            &format!("list2-{attempt}"),
            "messages.list",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "limit": 50,
            }),
        )
        .await;
        let items = listed["result"]["items"].as_array().unwrap();
        if let Some(row) = items.iter().find(|row| {
            row.get("poll").is_some()
                && row["poll"].get("terminated").and_then(Value::as_bool) == Some(true)
        }) {
            folded_row = Some(row.clone());
            break;
        }
    }
    let folded_row = folded_row.expect("the terminate folded onto the poll row");
    assert_eq!(
        folded_row["id"], create_row["id"],
        "the controls folded into the create's own row"
    );
    assert_eq!(
        folded_row["poll"],
        json!({
            "question": "Lunch?",
            "options": ["Ramen", "Sushi"],
            "allowMultiple": true,
            "terminated": true,
            "votes": [
                { "voterId": "+15555550101", "optionIndexes": [1] },
            ],
        }),
        "the converged face is the history chain's exact shape"
    );
    let final_items = {
        let listed = request(
            &mut client,
            "list-final",
            "messages.list",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "limit": 50,
            }),
        )
        .await;
        listed["result"]["items"].as_array().unwrap().clone()
    };
    // §4.189: the vote never mints a row, but the terminate's first flip
    // lands the official standalone notice row beside the poll — the
    // host wire sees exactly two rows, and the notice's rich face rides
    // flattened camelCase like every rich key.
    assert_eq!(
        final_items.len(),
        2,
        "the poll row plus its terminate notice row"
    );
    let notice = final_items
        .iter()
        .find(|row| row.get("pollTerminate").is_some())
        .expect("the notice row carries the flattened pollTerminate face");
    assert_eq!(notice["direction"], "system");
    assert_eq!(notice["status"], "system");
    assert_eq!(notice["sentAt"], 602, "the terminate envelope's own stamp");
    assert_eq!(
        notice["pollTerminate"],
        json!({
            "pollQuestion": "Lunch?",
            "pollSentAt": 600,
        }),
        "a peer terminate carries no selfTerminated key (skip-when-false)"
    );
    assert!(
        notice.get("poll").is_none(),
        "the notice row is not the poll bubble"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn groups_get_projects_the_synced_group_cache() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [37_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Groups" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // finish_link already ran a best-effort sync; the explicit sync inside the
    // 60s window returns the cached counts and guarantees the cache is warm.
    let synced = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(synced["result"]["groupCount"], 1);

    // The membership-filtered cache holds exactly one group: the fixture's
    // isMember=true entry with its member count.
    let group = request(
        &mut client,
        "groups-get",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    assert_eq!(group["result"]["peerKey"], "ZmFrZS1ncm91cC0x");
    assert_eq!(group["result"]["title"], "Fixture Group");
    assert_eq!(group["result"]["memberCount"], 2);
    assert!(group["result"]["syncedAt"].as_u64().unwrap() > 0);
    // Contract 1.53 (§4.50 appendix): the plain terminated bool — false on
    // the default fixture row (the stub carries the upstream flag).
    assert_eq!(group["result"]["isTerminated"], false);
    // Contract 1.40 (§4.39): the roster the sync captured projects beside
    // memberCount — the number-based self marker on the linked account's own
    // entry, the contacts-cache name plus the upstream uuid and admin mark on
    // Alice's. Contract 1.43 (§4.42): the self entry itself now lives in the
    // contacts cache, so its read-time name resolves to the account's own
    // profile name material (the official roster has no self name special
    // case either).
    assert_eq!(
        group["result"]["members"],
        json!([
            {"id": "+15555550100", "name": "Test User", "self": true},
            {
                "id": "+15555550101",
                "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                "name": "Alice Example",
                "admin": true,
            },
        ])
    );

    // A group the account has left is filtered out of the cache at sync time
    // (isMember=false), so it answers the deterministic cache miss.
    let departed = request(
        &mut client,
        "groups-departed",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "bm90LWEtbWVtYmVy"
        }),
    )
    .await;
    assert_eq!(departed["error"]["code"], "GROUP_NOT_FOUND");
    assert_eq!(departed["error"]["retryable"], false);

    // A contact peer key is not a group row.
    let contact_key = request(
        &mut client,
        "groups-contact-key",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "+15555550101"
        }),
    )
    .await;
    assert_eq!(contact_key["error"]["code"], "GROUP_NOT_FOUND");

    // Unknown params are rejected by shape before any cache lookup.
    let invalid = request(
        &mut client,
        "groups-invalid",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x",
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");

    // Read-only: an unknown account is a cache miss, not an upstream lookup.
    let unknown_account = request(
        &mut client,
        "groups-unknown-account",
        "groups.get",
        json!({
            "accountId": "absent-account",
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    assert_eq!(unknown_account["error"]["code"], "ACCOUNT_NOT_FOUND");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn groups_get_carries_the_sync_terminated_flag() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [38_u8; 32];
    write_secret_file(&secret_file, &secret);

    // The stub answers the upstream JsonGroup.isTerminated true for the
    // fixture group (the §4.50 verified listGroups read source), so the sync
    // capture path runs end to end: listGroups → group_extra_json → the
    // groups.get projection.
    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_TERMINATED_GROUPS", "ZmFrZS1ncm91cC0x")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Terminated" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;

    let group = request(
        &mut client,
        "groups-get",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    assert_eq!(group["result"]["peerKey"], "ZmFrZS1ncm91cC0x");
    // The terminated flag survives the whole ladder as the plain bool.
    assert_eq!(group["result"]["isTerminated"], true);
    // The roster still projects beside it — the flag adds one key, it does
    // not replace the §4.39 face.
    assert_eq!(group["result"]["memberCount"], 2);
    assert_eq!(group["result"]["members"].as_array().unwrap().len(), 2);

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// groups.get carries the sync-captured member label projection (contract
/// 1.67, §4.60): the stub answers the fixture label pair for the fixture
/// group's members, so the full ladder — listGroups JsonGroupMember
/// labelEmoji/label → group_extra_json capture (server budgets) → the
/// groups.get roster projection — lands in the response as absent-when-none
/// keys; the unlabeled default fixture row (groups_get_projects_the_synced_
/// group_cache's exact-shape assertion) proves the absent face.
#[tokio::test]
async fn groups_get_carries_the_member_label_projection() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [56_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_LABELED_GROUPS", "ZmFrZS1ncm91cC0x")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-MemberLabels" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;

    let group = request(
        &mut client,
        "groups-get",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    let members = group["result"]["members"].as_array().unwrap();
    // Self member: label string only — the fixture carries no labelEmoji for
    // it, so the emoji key stays absent (the NON_NULL omission shape).
    assert_eq!(
        members[0],
        json!({
            "id": "+15555550100",
            "name": "Test User",
            "self": true,
            "label": "Ops",
        })
    );
    // Alice: the full pair, captured verbatim.
    assert_eq!(
        members[1],
        json!({
            "id": "+15555550101",
            "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
            "name": "Alice Example",
            "admin": true,
            "labelEmoji": "🛠️",
            "label": "Builders",
        })
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.181 (§4.181) end to end: the sync capture keeps the upstream
/// JsonGroup's `announcementsOnly` flag and the engine's GV2 role word (the
/// stub's KT_FAKE_ROLE_GROUPS arm swaps the fixture roster onto the real
/// engine member shape — ADMINISTRATOR for Alice, DEFAULT for self), the
/// groups.get projection lands both (the banner gate's supply), and
/// `groups.common` answers the official groups-in-common panel over the
/// cached rosters for the direct Alice conversation — INVALID_REQUEST on a
/// group target, the honest shape refusal.
#[tokio::test]
async fn groups_common_and_the_announcement_role_capture_end_to_end() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [57_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[
            ("KT_FAKE_ANNOUNCEMENT_GROUPS", "ZmFrZS1ncm91cC0x"),
            ("KT_FAKE_ROLE_GROUPS", "ZmFrZS1ncm91cC0x=+15555550101"),
        ],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // Stage one group message before linking: finishLink's receive burst
    // delivers it after the default direct receive, so the group conversation
    // exists for the INVALID_REQUEST arm below.
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550101",
                "timestamp": 90,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "message": "group hello"
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-SupplyB" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;

    // The announcements-only flag and the role-word admin mark land together:
    // Alice is the group's ADMINISTRATOR (roster admin via the GV2 role word,
    // no legacy uuid key in this arm), self is a DEFAULT member — the
    // CompositionArea.dom.tsx:1108 banner gate's exact supply.
    let group = request(
        &mut client,
        "groups-get",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    assert_eq!(group["result"]["announcementsOnly"], true);
    assert_eq!(
        group["result"]["members"],
        json!([
            {"id": "+15555550100", "name": "Test User", "self": true},
            {"id": "+15555550101", "name": "Alice Example", "admin": true},
        ])
    );

    // The direct Alice conversation (the fixture's default receive) answers
    // the panel over the captured rosters.
    let conversations = request(
        &mut client,
        "conversations-list",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let direct = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "direct")
        .unwrap();
    let direct_id = direct["id"].as_str().unwrap().to_string();
    let common = request(
        &mut client,
        "groups-common",
        "groups.common",
        json!({
            "accountId": account_id,
            "conversationId": direct_id
        }),
    )
    .await;
    assert_eq!(
        common["result"]["groups"],
        json!([{ "peerKey": "ZmFrZS1ncm91cC0x", "title": "Fixture Group" }])
    );

    // A group conversation target is the wrong face — INVALID_REQUEST, the
    // honest shape refusal (a NOT_FOUND would be a lie: the conversation
    // exists).
    let group_conversation = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "group")
        .map(|item| item["id"].as_str().unwrap().to_string())
        .expect("the staged group receive created the group conversation");
    let refused = request(
        &mut client,
        "groups-common-group",
        "groups.common",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation
        }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "INVALID_REQUEST");
    assert_eq!(refused["error"]["retryable"], false);

    // A bogus conversation id answers the ladder's CONVERSATION_NOT_FOUND.
    let missing = request(
        &mut client,
        "groups-common-missing",
        "groups.common",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation"
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "CONVERSATION_NOT_FOUND");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// groups.get carries the live requesting-members projection (contract
/// 1.62, §4.53 appendix): the stub answers one requesting member for the
/// fixture group, so the full ladder — single-group listGroups live read →
/// address-ladder projection → read-time contacts-cache name — lands in the
/// response beside the cached face; the sync's requesting-less cached row
/// proves the key is the live read, not the capture; and a group with an
/// empty requesting set answers without the key.
#[tokio::test]
async fn groups_get_carries_the_live_requesting_members() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [55_u8; 32];
    write_secret_file(&secret_file, &secret);

    // One requesting member on the fixture group only; the former-member
    // group stays requesting-less so the absent-key face is exercisable on
    // the same engine answer.
    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[("KT_FAKE_REQUESTING_GROUPS", "ZmFrZS1ncm91cC0x=+15555550101")],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupApproveRead" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    // Sync first so the cached row exists — the assertion below that the
    // requesting key rides a requesting-less cache row is the whole point
    // (the face is the live read, not the capture).
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;

    let group = request(
        &mut client,
        "groups-get",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    assert_eq!(group["result"]["peerKey"], "ZmFrZS1ncm91cC0x");
    // The cached face stays intact beside the live key.
    assert_eq!(group["result"]["memberCount"], 2);
    let requesting = group["result"]["requestingMembers"]
        .as_array()
        .expect("the live requesting set must ride the response");
    assert_eq!(requesting.len(), 1, "{group}");
    assert_eq!(requesting[0]["id"], "+15555550101");
    assert_eq!(requesting[0]["name"], "Alice Example");
    assert!(
        requesting[0].get("self").is_none(),
        "a requesting candidate is never a member row"
    );
    assert!(requesting[0].get("admin").is_none());

    // A requesting-less group answers without the key (empty live set
    // collapses to absent, never an empty array).
    let empty = request(
        &mut client,
        "groups-get-empty",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "bm90LWEtbWVtYmVy"
        }),
    )
    .await;
    // The former-member group is not a cached row (the sync filters
    // isMember=false) — it answers GROUP_NOT_FOUND, which is itself the
    // §4.8 gate staying intact over the live read. The absent-key face on
    // a cached row needs the same engine's fixture group after its set
    // drains; the stub cannot drain mid-run, so the empty-set face is
    // pinned by the unit test instead. Read the former-member group to
    // prove the gate.
    assert_eq!(empty["error"]["code"], "GROUP_NOT_FOUND", "{empty}");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// groups.get carries the live pending-invite projection (contract revision
/// 1.64, §4.57): a real engine answer projects bounded {id, uuid?, name?}
/// entries through the full listGroups → projection ladder, the cached face
/// stays intact beside it, and a pending-less answer degrades without the
/// key.
#[tokio::test]
async fn groups_get_carries_the_live_pending_members() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [56_u8; 32];
    write_secret_file(&secret_file, &secret);

    // Two pending invitees on the fixture group (the §4.57 verified
    // listGroups read source); the projection must carry both.
    let mut connector = spawn_connector_with(
        temp.path(),
        &endpoint,
        &secret_file,
        None,
        &[(
            "KT_FAKE_PENDING_GROUPS",
            "ZmFrZS1ncm91cC0x=+15555550101,+15555550102",
        )],
    );
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupInvitesRead" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    // Sync first so the cached row exists — the assertion below that the
    // pending key rides the cached row is the whole point (the face is the
    // live read, not the capture).
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;

    let group = request(
        &mut client,
        "groups-get",
        "groups.get",
        json!({
            "accountId": account_id,
            "groupKey": "ZmFrZS1ncm91cC0x"
        }),
    )
    .await;
    assert_eq!(group["result"]["peerKey"], "ZmFrZS1ncm91cC0x");
    // The cached face stays intact beside the live key.
    assert_eq!(group["result"]["memberCount"], 2);
    let pending = group["result"]["pendingMembers"]
        .as_array()
        .expect("the live pending set must ride the response");
    assert_eq!(pending.len(), 2, "{group}");
    assert_eq!(pending[0]["id"], "+15555550101");
    assert_eq!(pending[0]["name"], "Alice Example");
    assert!(
        pending[0].get("self").is_none(),
        "a pending invitee is never a member row"
    );
    assert!(pending[0].get("admin").is_none());
    assert_eq!(pending[1]["id"], "+15555550102");
    assert!(
        pending[0].get("addedByUserId").is_none() && pending[1].get("addedByUserId").is_none(),
        "the upstream face carries no inviter metadata (the §4.57 projection difference)"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn contacts_set_local_alias_renames_a_locally_known_peer() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [43_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Set-Alias" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The best-effort sync at finish cached the fixture contacts, so the
    // linked account's peer (+15555550101) is a known contact.
    let renamed = request(
        &mut client,
        "alias-happy",
        "contacts.setLocalAlias",
        json!({
            "accountId": account_id,
            "peerKey": "+15555550101",
            "alias": "Alice Renamed",
            "operationId": "alias-op-1"
        }),
    )
    .await;
    assert_eq!(renamed["result"]["status"], "updated");
    // The upstream call carries recipient as a single string — the pinned
    // UpdateContactCommand reads it with getString (§4.9).
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log updateContact params");
    let update_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("name") == Some(&json!("Alice Renamed")))
        .expect("the updateContact must reach the upstream");
    assert_eq!(update_call["account"], "+15555550100");
    assert_eq!(update_call["recipient"], "+15555550101");
    assert!(update_call["recipient"].is_string());

    // An unknown peer is rejected locally before any upstream call.
    let unknown_peer = request(
        &mut client,
        "alias-unknown-peer",
        "contacts.setLocalAlias",
        json!({
            "accountId": account_id,
            "peerKey": "+15555559999",
            "alias": "Nobody"
        }),
    )
    .await;
    assert_eq!(unknown_peer["error"]["code"], "INVALID_REQUEST");

    // A 129-byte alias is rejected by shape.
    let oversized = request(
        &mut client,
        "alias-oversized",
        "contacts.setLocalAlias",
        json!({
            "accountId": account_id,
            "peerKey": "+15555550101",
            "alias": "x".repeat(129)
        }),
    )
    .await;
    assert_eq!(oversized["error"]["code"], "INVALID_REQUEST");

    // Unknown params are rejected by shape.
    let invalid = request(
        &mut client,
        "alias-invalid",
        "contacts.setLocalAlias",
        json!({
            "accountId": account_id,
            "peerKey": "+15555550101",
            "alias": "Still Alice",
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");

    // An unknown account is answered without touching the upstream.
    let absent_account = request(
        &mut client,
        "alias-absent-account",
        "contacts.setLocalAlias",
        json!({
            "accountId": "no-such-account",
            "peerKey": "+15555550101",
            "alias": "Alice"
        }),
    )
    .await;
    assert_eq!(absent_account["error"]["code"], "ACCOUNT_NOT_FOUND");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn presence_set_typing_message_signals_ephemeral_upstream_state() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [47_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Typing" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // A direct conversation to type into (sendText creates the history row).
    let seeded = request(
        &mut client,
        "typing-seed",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "direct",
            "peerKey": "+15555550101",
            "text": "typing target",
            "clientRequestId": "typing-seed-1"
        }),
    )
    .await;
    let conversation_id = seeded["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Start typing: stop defaults to false and is still sent explicitly (§4.10).
    let typing = request(
        &mut client,
        "typing-start",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "operationId": "typing-op-1"
        }),
    )
    .await;
    assert_eq!(typing["result"]["status"], "sent");

    // stop=true clears the indicator early.
    let stopped = request(
        &mut client,
        "typing-stop",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "stop": true
        }),
    )
    .await;
    assert_eq!(stopped["result"]["status"], "sent");

    // A group conversation addresses groupId instead of recipient.
    let group_seeded = request(
        &mut client,
        "typing-group-seed",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "group",
            "peerKey": "ZmFrZS1ncm91cC0x",
            "text": "group typing target",
            "clientRequestId": "typing-seed-2"
        }),
    )
    .await;
    let group_conversation_id = group_seeded["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let group_typing = request(
        &mut client,
        "typing-group",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id
        }),
    )
    .await;
    assert_eq!(group_typing["result"]["status"], "sent");

    // The exact upstream dispatch: account + explicit stop boolean + the
    // conversation addressing (§4.10). The seed sends carry no `stop` key,
    // so filtering on it isolates the typing calls.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log sendTyping params");
    let typing_calls: Vec<Value> = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("stop").is_some())
        .collect();
    assert_eq!(typing_calls.len(), 3, "every typing call must be logged");
    assert_eq!(typing_calls[0]["account"], "+15555550100");
    assert_eq!(typing_calls[0]["stop"], json!(false));
    assert_eq!(typing_calls[0]["recipient"], json!(["+15555550101"]));
    assert_eq!(typing_calls[1]["stop"], json!(true));
    assert_eq!(typing_calls[1]["recipient"], json!(["+15555550101"]));
    assert_eq!(typing_calls[2]["groupId"], json!("ZmFrZS1ncm91cC0x"));
    assert!(typing_calls[2].get("recipient").is_none());

    // A missing conversation answers CONVERSATION_NOT_FOUND without an
    // upstream call.
    let missing = request(
        &mut client,
        "typing-missing",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation"
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "CONVERSATION_NOT_FOUND");

    // Unknown params are rejected by shape.
    let invalid = request(
        &mut client,
        "typing-invalid",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");

    // An unknown account is answered without touching the upstream.
    let absent_account = request(
        &mut client,
        "typing-absent-account",
        "presence.setTypingMessage",
        json!({
            "accountId": "no-such-account",
            "conversationId": conversation_id
        }),
    )
    .await;
    assert_eq!(absent_account["error"]["code"], "ACCOUNT_NOT_FOUND");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.33 end to end: inbound pin-family envelopes staged in the
/// fixture's `.fixture-extra-receives.json` marker drive the per-conversation
/// pinned state (conversation summaries carry `pinnedMessage`, a matching
/// unpin clears it) and the group adminDelete tombstone (`adminDeleted` on the
/// upserted row, the pinned row's removal clears the pin). The three upstream
/// methods carry the exact reaction addressing — targetAuthor follows the row
/// direction, groups address `groupId`, `pinDurationSeconds` passes through
/// only when supplied — and the guard rails answer deterministically (direct
/// adminDelete INVALID_REQUEST, out-of-range duration INVALID_REQUEST, an
/// unknown message MESSAGE_NOT_FOUND) without touching the upstream.
#[tokio::test]
async fn pin_family_round_trips_pinned_state_and_admin_delete_tombstone() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [29_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // Stage the inbound face before linking: a named group message, then a
    // peer's timed pin of it — both delivered by the finishLink receive burst.
    let extra_receives = temp
        .path()
        .join("signal-data")
        .join(".fixture-extra-receives.json");
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        &extra_receives,
        json!([
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": 50,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "message": "group pin target"
                }
            },
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": 51,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "pinMessage": {
                        "targetAuthor": "+15555550101",
                        "targetSentTimestamp": 50,
                        "pinDurationSeconds": 3600
                    }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Pin-Family" }),
    )
    .await;
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;

    // Drain the finish burst: the link answer, the group message upsert, and
    // the pin-driven conversation change whose summary carries pinnedMessage.
    let mut account_id: Option<String> = None;
    let mut group_message_id: Option<String> = None;
    let mut pinned_change: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while account_id.is_none() || group_message_id.is_none() || pinned_change.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                account_id = Some(frame["result"]["id"].as_str().unwrap().to_string());
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["sentAt"] == 50
            {
                group_message_id = Some(frame["data"]["id"].as_str().unwrap().to_string());
            }
            if frame.get("event").and_then(Value::as_str) == Some("conversation.changed")
                && frame["data"].get("pinnedMessage").is_some()
            {
                pinned_change = Some(frame);
            }
        }
    })
    .await
    .expect("the finish burst must deliver the group message and its pin");
    let account_id = account_id.unwrap();
    let group_message_id = group_message_id.unwrap();
    let pinned = pinned_change.unwrap()["data"]["pinnedMessage"].clone();
    assert_eq!(pinned["messageId"], json!(group_message_id));
    assert_eq!(pinned["targetAuthor"], json!("+15555550101"));
    assert_eq!(pinned["targetSentTimestamp"], json!(50));
    assert!(pinned["pinnedAt"].is_u64());
    assert!(pinned["expiresAt"].is_u64(), "a timed pin carries expiry");

    // The persisted summary projects the same pin bar (a reloaded window
    // renders it without replaying events).
    let conversations = request(
        &mut client,
        "conv-pinned",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_row = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "group")
        .unwrap();
    assert_eq!(group_row["pinnedMessage"]["targetSentTimestamp"], json!(50));

    // Append the group adminDelete of the pinned row and deliver it through a
    // later upstream call (sendTyping flushes staged receives, changes no
    // conversation state).
    let mut envelopes: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(&extra_receives).unwrap()).unwrap();
    envelopes.push(json!({
        "source": "+15555550101",
        "sourceName": "林菲菲",
        "timestamp": 53,
        "dataMessage": {
            "groupId": "ZmFrZS1ncm91cC0x",
            "adminDelete": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 50
            }
        }
    }));
    fs::write(&extra_receives, json!(envelopes).to_string()).unwrap();
    // Deliver it through a later upstream call: sendTyping flushes staged
    // receives before answering, and a typing indicator changes no
    // conversation state. The flush and the answer can interleave in either
    // order on the socket, so the frame is sent without waiting and the drain
    // below collects the typing answer together with the projections.
    send_request_frame(
        &mut client,
        "typing-flush",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_row["id"],
            "stop": true
        }),
    )
    .await;

    // The tombstone lands as a row-level adminDeleted marker (status ladder
    // untouched, body kept) and the pinned row's removal clears the pin.
    let mut typed: Option<Value> = None;
    let mut upserted: Option<Value> = None;
    let mut unpinned_change: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while typed.is_none() || upserted.is_none() || unpinned_change.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("typing-flush") {
                typed = Some(frame);
                continue;
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["sentAt"] == 50
            {
                upserted = Some(frame);
                continue;
            }
            if frame.get("event").and_then(Value::as_str) == Some("conversation.changed")
                && frame["data"].get("pinnedMessage").is_none()
                && frame["data"]["type"] == "group"
            {
                unpinned_change = Some(frame);
            }
        }
    })
    .await
    .expect("the adminDelete must upsert the tombstone and clear the pin");
    assert_eq!(typed.unwrap()["result"]["status"], "sent");
    let tombstone = upserted.unwrap()["data"].clone();
    assert_eq!(tombstone["adminDeleted"], json!(true));
    assert_eq!(tombstone["status"], json!("delivered"));
    assert_eq!(tombstone["body"], json!("group pin target"));
    assert_eq!(
        unpinned_change.unwrap()["data"]["id"],
        group_row["id"].clone()
    );
    let conversations = request(
        &mut client,
        "conv-unpinned",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_row = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "group")
        .unwrap();
    assert!(group_row.get("pinnedMessage").is_none());

    // Upstream face: send an own group row and pin/unpin/adminDelete it. The
    // send lane mirrors the reaction addressing — targetAuthor is the linked
    // account, groups address groupId, and the duration passes through only
    // when supplied.
    let sent = request(
        &mut client,
        "send-group-pin",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "group",
            "peerKey": "ZmFrZS1ncm91cC0x",
            "text": "pin me upstream",
            "clientRequestId": "pin-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let group_conversation_id = sent["result"]["conversationId"].clone();
    let pinned_upstream = request(
        &mut client,
        "pin-upstream",
        "messages.sendPinMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "messageId": sent["result"]["id"],
            "pinDurationSeconds": 86400
        }),
    )
    .await;
    assert_eq!(pinned_upstream["result"]["status"], "sent");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log sendPinMessage params");
    let pin_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("pinDurationSeconds").is_some())
        .expect("the sendPinMessage must reach the upstream");
    assert_eq!(pin_call["account"], "+15555550100");
    assert_eq!(pin_call["targetAuthor"], "+15555550100");
    assert_eq!(pin_call["targetTimestamp"], json!(99));
    assert_eq!(pin_call["pinDurationSeconds"], json!(86400));
    assert_eq!(pin_call["groupId"], json!("ZmFrZS1ncm91cC0x"));
    assert!(pin_call.get("recipient").is_none());

    // Unpin: the same addressing, no duration key on the wire.
    let unpinned_upstream = request(
        &mut client,
        "unpin-upstream",
        "messages.sendUnpinMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "messageId": sent["result"]["id"]
        }),
    )
    .await;
    assert_eq!(unpinned_upstream["result"]["status"], "sent");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap();
    let unpin_call: Value = send_log
        .lines()
        .rev()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the sendUnpinMessage must reach the upstream");
    assert_eq!(unpin_call["targetAuthor"], "+15555550100");
    assert_eq!(unpin_call["targetTimestamp"], json!(99));
    assert!(unpin_call.get("pinDurationSeconds").is_none());

    // Admin delete: group-only, groupId addressing on the wire.
    let admin_deleted = request(
        &mut client,
        "admin-delete-upstream",
        "messages.sendAdminDelete",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "messageId": sent["result"]["id"]
        }),
    )
    .await;
    assert_eq!(admin_deleted["result"]["status"], "sent");
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap();
    let delete_call: Value = send_log
        .lines()
        .rev()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|params: &Value| params.get("targetTimestamp").is_some())
        .expect("the sendAdminDelete must reach the upstream");
    assert_eq!(delete_call["targetAuthor"], "+15555550100");
    assert_eq!(delete_call["targetTimestamp"], json!(99));
    assert_eq!(delete_call["groupId"], json!("ZmFrZS1ncm91cC0x"));

    // Guard rails, none of which touch the upstream: a direct chat has no
    // admin concept, the duration range is enforced fail-closed, and an
    // unknown message answers MESSAGE_NOT_FOUND.
    let direct_sent = request(
        &mut client,
        "send-direct-pin",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "direct admin delete target",
            "clientRequestId": "pin-send-direct"
        }),
    )
    .await;
    assert_eq!(direct_sent["result"]["status"], "sent");
    let direct_conversation = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "direct")
        .unwrap();
    let direct_delete = request(
        &mut client,
        "admin-delete-direct",
        "messages.sendAdminDelete",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation["id"],
            "messageId": direct_sent["result"]["id"]
        }),
    )
    .await;
    assert_eq!(direct_delete["error"]["code"], "INVALID_REQUEST");
    for bad in [-1_i64, 4_294_967_296_i64] {
        let out_of_range = request(
            &mut client,
            "pin-range",
            "messages.sendPinMessage",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation_id,
                "messageId": sent["result"]["id"],
                "pinDurationSeconds": bad
            }),
        )
        .await;
        assert_eq!(
            out_of_range["error"]["code"], "INVALID_REQUEST",
            "pinDurationSeconds {bad} must fail closed"
        );
    }
    let unknown = request(
        &mut client,
        "pin-unknown",
        "messages.sendPinMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "messageId": "no-such-message"
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "MESSAGE_NOT_FOUND");
    assert_eq!(unknown["error"]["retryable"], false);

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// The receipt send-log lines (contract 1.34 delivery/read/viewed all record
/// `{account, recipient, timestamps}`), in file order.
fn receipt_log_lines(contents: &str) -> Vec<Value> {
    contents
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("timestamps").is_some())
        .collect()
}

/// Contract revision 1.34 end to end: the auto delivery receipt fires once per
/// genuinely-ingested incoming dataMessage (the finishLink burst covers the
/// default fixture receive, a staged direct message, and a staged group
/// message — every receipt addresses the author as a single string, never the
/// group id); `messages.markRead` without messageIds fans the §4.119-window
/// selection out as one ascending per-author read receipt (the stale
/// fixture-era row stays silent, the fresh staged row rides); `messages.markViewed`
/// with explicit ids narrows to those rows unfiltered; and a group
/// markRead is the silent `sent` no-op (local group rows carry no resolvable
/// author, so zero upstream calls).
#[tokio::test]
async fn receipts_mark_read_viewed_and_auto_delivery_reach_the_upstream() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [31_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // Stage a group message and a second direct message behind the default
    // link receive: three incoming dataMessages, three auto delivery
    // receipts. The direct message carries a FRESH timestamp — §4.119 puts
    // the absent receipt selection inside the seven-day window, so the
    // fixture-era default receive (42) stays deliberately stale and the
    // absent fan-out below proves the exclusion.
    let fresh_direct: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": 50,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "message": "group text"
                }
            },
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": fresh_direct,
                "dataMessage": { "message": "second direct text" }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Receipts" }),
    )
    .await;
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;

    // Drain the finish burst: the link answer plus the three message upserts
    // (42 direct, 50 group, 60 direct).
    let mut account_id: Option<String> = None;
    let mut upserted: Vec<Value> = Vec::new();
    timeout(Duration::from_secs(5), async {
        while account_id.is_none() || upserted.len() < 3 {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                account_id = Some(frame["result"]["id"].as_str().unwrap().to_string());
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["direction"] == "incoming"
            {
                upserted.push(frame["data"].clone());
            }
        }
    })
    .await
    .expect("the finish burst must deliver three incoming messages");
    let account_id = account_id.unwrap();

    // Auto delivery receipts: one per ingested message in ingest order, the
    // author as a single-string recipient, never a group id.
    let send_log_path = signal_data.join(".fixture-send-log.jsonl");
    timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(contents) = fs::read_to_string(&send_log_path)
                && receipt_log_lines(&contents).len() >= 3
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("three auto delivery receipts must reach the engine");
    let delivery_receipts = receipt_log_lines(&fs::read_to_string(&send_log_path).unwrap());
    assert_eq!(delivery_receipts.len(), 3);
    let timestamps: Vec<Vec<u64>> = delivery_receipts
        .iter()
        .map(|entry| {
            entry["timestamps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap())
                .collect()
        })
        .collect();
    assert_eq!(timestamps, [vec![42], vec![50], vec![fresh_direct]]);
    for entry in &delivery_receipts {
        assert_eq!(entry["account"], "+15555550100");
        assert_eq!(entry["recipient"], "+15555550101");
        assert!(entry.get("groupId").is_none());
    }

    // The messaged direct conversation carries both direct rows (history
    // ordering puts it first, ahead of the contacts-sync skeletons).
    let conversations = request(
        &mut client,
        "conv-1",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let items = conversations["result"]["items"].as_array().unwrap();
    let direct = items.iter().find(|item| item["type"] == "direct").unwrap();
    let direct_id = direct["id"].as_str().unwrap().to_string();
    let group = items.iter().find(|item| item["type"] == "group").unwrap();
    let group_id = group["id"].as_str().unwrap().to_string();
    let messages = request(
        &mut client,
        "messages-1",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": direct_id,
            "limit": 50
        }),
    )
    .await;
    let rows = messages["result"]["items"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let id_42 = rows.iter().find(|row| row["sentAt"] == 42).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let id_fresh = rows
        .iter()
        .find(|row| row["sentAt"] == fresh_direct)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Absent messageIds: the §4.119 window at the wire face — only the fresh
    // direct row fans out (one ascending per-author read receipt whose
    // [fresh_direct] shape is distinguishable from every delivery receipt),
    // while the stale fixture-era row (42) stays silent; the log line
    // precedes the markRead answer.
    let marked = request(
        &mut client,
        "mark-read",
        "messages.markRead",
        json!({ "accountId": account_id, "conversationId": direct_id }),
    )
    .await;
    assert_eq!(marked["result"]["status"], "sent");
    let after_read = receipt_log_lines(&fs::read_to_string(&send_log_path).unwrap());
    assert_eq!(after_read.len(), 4);
    assert_eq!(after_read[3]["timestamps"], json!([fresh_direct]));
    assert_eq!(after_read[3]["recipient"], "+15555550101");

    // Explicit messageIds: exactly the addressed rows, receipt order, same
    // single-author fan-out — unfiltered by §4.119 (the desktop naming ids
    // is itself the incremental act), so the stale row is still addressable.
    let viewed = request(
        &mut client,
        "mark-viewed",
        "messages.markViewed",
        json!({
            "accountId": account_id,
            "conversationId": direct_id,
            "messageIds": [id_42, id_fresh]
        }),
    )
    .await;
    assert_eq!(viewed["result"]["status"], "sent");
    let after_viewed = receipt_log_lines(&fs::read_to_string(&send_log_path).unwrap());
    assert_eq!(after_viewed.len(), 5);
    assert_eq!(after_viewed[4]["timestamps"], json!([42, fresh_direct]));

    // A group markRead resolves no author locally: the trivial `sent` no-op
    // with zero new upstream calls — no receipt ever carries the group id.
    let group_marked = request(
        &mut client,
        "mark-read-group",
        "messages.markRead",
        json!({ "accountId": account_id, "conversationId": group_id }),
    )
    .await;
    assert_eq!(group_marked["result"]["status"], "sent");
    let after_group = receipt_log_lines(&fs::read_to_string(&send_log_path).unwrap());
    assert_eq!(after_group.len(), 5);
    assert!(
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .all(|params| params.get("groupId").is_none()),
        "no receipt call may address the group id"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.34 failure face: the auto delivery receipt is real
/// upstream traffic — a receipt whose timestamps carry the fixture's 425
/// sentinel crashes the engine right after link, an explicit restart recovers
/// on the same store, and the same sentinel inside `messages.markRead`
/// degrades the answer to `{status: "unknown"}` — a result, never an error,
/// with no retry.
#[tokio::test]
async fn receipt_upstream_failures_degrade_to_unknown_not_errors() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [32_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // The staged direct message's auto delivery receipt carries 425: the
    // engine dies while the receipt pipeline is demonstrably in flight.
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550101",
                "sourceName": "林菲菲",
                "timestamp": 425,
                "dataMessage": { "message": "receipt crash target" }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Receipt-Crash" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    wait_for_process_exit(engine_pid).await;

    // The receipt crash is recoverable: an explicit start brings a fresh
    // engine up on the same data directory (the store kept both rows).
    let restarted = request(&mut client, "restart-1", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid);

    let conversations = request(
        &mut client,
        "conv-1",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let direct = conversations["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "direct")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // The explicit selection names the 425 row — §4.119 keeps the absent
    // form window-filtered (a stale row would silently no-op), so the
    // mid-call crash path drives the explicit face — and the read receipt
    // still kills the engine mid-call, the request still answers degraded
    // to `unknown`, with no error object and no retry.
    let messages = request(
        &mut client,
        "messages-1",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": direct,
            "limit": 50
        }),
    )
    .await;
    let crash_target = messages["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["sentAt"] == 425)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let marked = request(
        &mut client,
        "mark-read",
        "messages.markRead",
        json!({
            "accountId": account_id,
            "conversationId": direct,
            "messageIds": [crash_target]
        }),
    )
    .await;
    assert_eq!(marked["result"]["status"], "unknown");
    assert!(
        marked.get("error").is_none(),
        "a receipt failure must not fail the request: {marked:?}"
    );
    wait_for_process_exit(recovered_pid).await;
    let again = request(&mut client, "restart-2", "runtime.start", json!({})).await;
    assert_eq!(again["result"]["state"], "running");
    let final_pid = again["result"]["pid"].as_u64().unwrap() as u32;

    drop(client);
    wait_for_process_exit(final_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.34 announcement and outbound mentions: the handshake
/// capabilities carry the new methods plus the `send-receipts` feature tag
/// (and the 1.35 `messages.sendSticker` method plus the `send-sticker` tag,
/// and the 1.36 browse/pin faces plus their tags), and `messages.sendText`
/// mentions reach the engine resolved — a UUID-shaped number and the cached
/// contact pass verbatim, the unresolvable number is dropped locally — while
/// an empty mention number fails the request closed.
#[tokio::test]
async fn handshake_advertises_receipts_and_mentions_reach_the_upstream() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [33_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());

    // Handshake with an inline capability assertion (the shared helper only
    // checks the api version).
    let challenge: Value = match timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    {
        Ok(challenge) => challenge,
        Err(_) => panic!(
            "authentication challenge never arrived within {HARNESS_AUTH_TIMEOUT:?}:\n{}",
            dump_connector_crash_scene()
        ),
    };
    let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
    let client_nonce = hex::encode([9_u8; 32]);
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(b"kt-signal-connector-v1\0");
    mac.update(server_nonce.as_bytes());
    mac.update(b"\0");
    mac.update(client_nonce.as_bytes());
    mac.update(b"\0");
    mac.update(API_VERSION.as_bytes());
    client
        .send(
            json!({
                "apiVersion": API_VERSION,
                "requestId": "handshake-1",
                "method": "handshake",
                "params": {
                    "clientNonce": client_nonce,
                    "proof": hex::encode(mac.finalize().into_bytes())
                }
            })
            .to_string(),
        )
        .await
        .unwrap();
    let handshake: Value = match timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    {
        Ok(handshake) => handshake,
        Err(_) => panic!(
            "handshake response never arrived within {HARNESS_AUTH_TIMEOUT:?}:\n{}",
            dump_connector_crash_scene()
        ),
    };
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in [
        "messages.markRead",
        "messages.markViewed",
        "send-receipts",
        "messages.sendSticker",
        "send-sticker",
        "stickerPacks.getManifest",
        "stickerPacks.getImage",
        "sticker-pack-browse",
        "conversations.getPinned",
        "conversations.setPinned",
        "conversation-pin-sync",
        "stickerPacks.getSyncs",
        "stickerPacks.setSync",
        "sticker-pack-sync",
        "chatFolders.list",
        "chatFolders.setRecords",
        "chat-folders",
        "notificationProfiles.list",
        "notificationProfiles.setRecords",
        "notification-profiles",
        "storyDistributionLists.list",
        "storyDistributionLists.setRecords",
        "storage.mergeContacts",
        "storage.importGroups",
        "storage.getCallLinks",
        "storage.setCallLink",
        "storage-sync",
        "groups.update",
        "groups.quit",
        "group-management",
        "accounts.setExpireTimer",
        "accounts.setProfile",
        "accounts.updateConfiguration",
        "account-settings",
        "conversations.getBlocked",
        "blocked-conversations",
        "backups.export",
        "backups.exportStatus",
        "backups.exportFile.open",
        "backups.exportFile.readChunk",
        "backups.exportFile.closeHandle",
        "backup-export",
        "conversations.getAvatar",
        "avatar-fetch",
        "conversations.setBlocked",
        "blocked-write",
        "messages.reportSpam",
        "report-spam",
        "calls.sendSignal",
        "calls.getState",
        "call-signaling",
        "accounts.setUsername",
        "accounts.getUsername",
        "username.lookup",
        "username",
        "phone.lookup",
        "phone-lookup",
    ] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    // Contract revision 1.98: this harness spawns `serve` without
    // `--media-ingest` (the launcher decision is the whole decision since
    // 1.121, §4.102), so the attachment-download tag must stay absent — the
    // honest unavailable advertisement, not a capability every call would
    // fail.
    assert!(
        !capabilities
            .iter()
            .any(|value| value.as_str() == Some("attachment-download")),
        "an unarmed runtime must not advertise attachment-download: {capabilities:?}"
    );

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Mentions" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Refresh the contacts cache outside the link debounce so the digit
    // suffix resolution has +15555550101 to match against.
    let _ = request(
        &mut client,
        "sync-1",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;

    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let mention_send = request(
        &mut client,
        "send-mentions",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "ping @alice",
            "clientRequestId": "mentions-1",
            "mentions": [
                {
                    "number": "018c3f2a-1b2c-7cde-9f01-234567890abc",
                    "start": 5,
                    "length": 6
                },
                { "number": "+15555550101", "start": 5, "length": 6 },
                { "number": "+19990000001", "start": 0, "length": 3 }
            ]
        }),
    )
    .await;
    assert_eq!(mention_send["result"]["status"], "sent");
    let mentions: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("mentions").is_some())
        .collect();
    assert_eq!(mentions.len(), 1);
    let entries = mentions[0]["mentions"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "the unresolvable number must be dropped");
    assert_eq!(entries[0]["number"], "018c3f2a-1b2c-7cde-9f01-234567890abc");
    assert_eq!(entries[0]["start"], 5);
    assert_eq!(entries[0]["length"], 6);
    assert_eq!(entries[1]["number"], "+15555550101");

    let invalid = request(
        &mut client,
        "send-empty-mention",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "bad mention",
            "clientRequestId": "mentions-2",
            "mentions": [{ "number": "  ", "start": 0, "length": 1 }]
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.35 stickers end to end: the upstream `send` carries
/// only the sticker object (no `message`, no `attachments` key), the pending
/// row settles with the upstream timestamp, an engine crash with the mutating
/// send in flight answers SEND_OUTCOME_UNKNOWN and leaves the row unknown
/// with no automatic retry, bounds failures reject before any row exists, and
/// an inbound sticker envelope projects onto a row with its pack identity
/// beside the metadata-only descriptor (a data-less sticker keeps the skip
/// routing).
#[tokio::test]
async fn sticker_send_and_receive_round_trip() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [31_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Stickers" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let sticker_calls = || {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| params.get("sticker").is_some())
            .collect::<Vec<_>>()
    };

    // Happy path: peer addressing progressive-fills the direct chat, the
    // upstream call carries the sticker object only, and the row settles with
    // the upstream timestamp.
    let sent = request(
        &mut client,
        "sticker-1",
        "messages.sendSticker",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "clientRequestId": "sticker-req-1",
            "packId": "abcdef01",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "stickerId": 7,
            "emoji": "🎉",
            "image": {
                "dataBase64": "iVBORw0KGgo=",
                "sizeBytes": 8,
                "contentType": "image/png",
                "width": 512,
                "height": 512
            }
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    assert_eq!(sent["result"]["sentAt"], json!(99));
    let sticker_row_id = sent["result"]["id"].clone();
    let conversation_id = sent["result"]["conversationId"].clone();

    let calls = sticker_calls();
    assert_eq!(calls.len(), 1, "exactly one upstream send: {calls:?}");
    let call = &calls[0];
    assert_eq!(call["account"], "+15555550100");
    assert!(
        call.get("message").is_none(),
        "a sticker send carries no message body: {call}"
    );
    assert!(
        call.get("attachments").is_none(),
        "a sticker send carries no regular attachments: {call}"
    );
    assert_eq!(call["recipient"], json!(["+15555550101"]));
    assert_eq!(call["sticker"]["packId"], "abcdef01");
    assert_eq!(call["sticker"]["packKey"], "AAAAAAAAAAAAAAAAAAAAAA==");
    assert_eq!(call["sticker"]["stickerId"], 7);
    assert_eq!(call["sticker"]["emoji"], "🎉");
    assert_eq!(
        call["sticker"]["image"],
        "data:image/png;base64,iVBORw0KGgo="
    );
    assert_eq!(call["sticker"]["width"], 512);
    assert_eq!(call["sticker"]["height"], 512);

    // The sent row renders the sticker identity beside the metadata-only
    // descriptor, read back from the persisted store (what a restart loads).
    let listed = request(
        &mut client,
        "list-sticker",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    if listed["result"]["items"].is_null() {
        panic!("list response: {listed}");
    }
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == sticker_row_id)
        .expect("the sent sticker row is listed");
    assert_eq!(row["sticker"]["packId"], "abcdef01");
    assert_eq!(row["sticker"]["packKey"], "AAAAAAAAAAAAAAAAAAAAAA==");
    assert_eq!(row["sticker"]["stickerId"], 7);
    assert_eq!(row["sticker"]["emoji"], "🎉");
    assert_eq!(row["attachments"][0]["contentType"], "image/png");
    assert_eq!(row["attachments"][0]["size"], 8);
    assert_eq!(row["attachments"][0]["width"], 512);
    assert!(
        row.get("text").map(Value::is_null).unwrap_or(true),
        "a sticker row has no body text: {row}"
    );

    // Bounds failure: a video sticker rejects INVALID_REQUEST before any row
    // exists — the same clientRequestId stays a fresh request.
    let invalid = request(
        &mut client,
        "sticker-invalid",
        "messages.sendSticker",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "sticker-req-invalid",
            "packId": "abcdef01",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "stickerId": 8,
            "image": {
                "dataBase64": "iVBORw0KGgo=",
                "sizeBytes": 8,
                "contentType": "video/mp4"
            }
        }),
    )
    .await;
    assert_eq!(invalid["error"]["code"], "INVALID_REQUEST");
    assert_eq!(sticker_calls().len(), 1, "no upstream call for the reject");

    // Indeterminate outcome: the all-f pack id kills the engine with the
    // mutating send in flight, the request still answers SEND_OUTCOME_UNKNOWN,
    // the row settles to `unknown`, and nothing is retried.
    let unknown = request(
        &mut client,
        "sticker-unknown",
        "messages.sendSticker",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "sticker-req-unknown",
            "packId": "ffffffff",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "stickerId": 9,
            "image": {
                "dataBase64": "iVBORw0KGgo=",
                "sizeBytes": 8,
                "contentType": "image/png"
            }
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;

    // The crash is recoverable: an explicit start brings a fresh engine up on
    // the same data directory, and the unknown row survives the reload.
    let restarted = request(&mut client, "restart-sticker", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid);

    let unknown_calls = sticker_calls();
    assert_eq!(
        unknown_calls
            .iter()
            .filter(|call| call["sticker"]["packId"] == "ffffffff")
            .count(),
        1,
        "an unknown outcome is never retried: {unknown_calls:?}"
    );
    let listed = request(
        &mut client,
        "list-unknown",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let unknown_row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["clientRequestId"] == "sticker-req-unknown")
        .expect("the unknown sticker row survives the engine restart");
    assert_eq!(unknown_row["status"], "unknown");

    // Inbound projection: a sticker with a usable `data` pointer lands as an
    // incoming row; a data-less sticker keeps the skip routing (no row).
    let extra_receives = temp
        .path()
        .join("signal-data")
        .join(".fixture-extra-receives.json");
    fs::write(
        &extra_receives,
        json!([
            {
                "source": "+15555550102",
                "sourceName": "Ada",
                "timestamp": 777,
                "dataMessage": {
                    "sticker": {
                        "packId": "00ff00ff",
                        "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                        "stickerId": 3,
                        "emoji": "🚀",
                        "data": {
                            "id": "att-in-1",
                            "contentType": "image/webp",
                            "size": 4096,
                            "width": 256,
                            "height": 256
                        }
                    }
                }
            },
            {
                "source": "+15555550102",
                "sourceName": "Ada",
                "timestamp": 778,
                "dataMessage": {
                    "sticker": { "packId": "00ff00ff", "stickerId": 4 }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();
    // The fixture flushes pending extra receives before answering sendTyping,
    // so the flush response can outrun the receive processing: wait for the
    // conversation.changed event that the stored sticker row emits, and take
    // the progressive-filled conversation id straight from it.
    send_request_frame(
        &mut client,
        "sticker-flush",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id
        }),
    )
    .await;
    let incoming_conversation = timeout(Duration::from_secs(5), async {
        loop {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("event").and_then(Value::as_str) == Some("conversation.changed") {
                return frame["data"]["id"].as_str().unwrap().to_string();
            }
        }
    })
    .await
    .expect("the inbound sticker row must refresh its conversation");
    let listed = request(
        &mut client,
        "list-incoming-sticker",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": incoming_conversation,
            "limit": 50
        }),
    )
    .await;
    let items = listed["result"]["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "the data-less sticker envelope stays skipped: {items:?}"
    );
    let incoming = &items[0];
    assert_eq!(incoming["direction"], "incoming");
    assert_eq!(incoming["sticker"]["packId"], "00ff00ff");
    assert_eq!(incoming["sticker"]["stickerId"], 3);
    assert_eq!(incoming["sticker"]["emoji"], "🚀");
    assert_eq!(incoming["attachments"][0]["id"], "att-in-1");
    assert_eq!(incoming["attachments"][0]["contentType"], "image/webp");
    assert_eq!(incoming["attachments"][0]["width"], 256);

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.36 faces end to end: the two browse methods forward
/// to the engine with bounds-validated pack identity and map structured
/// engine errors (key-invalid deterministic, fetch-failed retryable); the
/// two pin-sync methods resolve the conversation and account, forward with
/// the resolved reference, answer the cloud-order list (entry cap
/// enforced), a storage outage surfaces STORAGE_UNAVAILABLE verbatim, an
/// unknown mutating pin outcome answers SEND_OUTCOME_UNKNOWN with no
/// retry, and an old-engine (method-absent) browse answers CAPABILITY_
/// UNAVAILABLE. Bounds failures reject before any upstream call.
#[tokio::test]
async fn sticker_pack_browse_and_pin_sync_round_trip() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [37_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    // Browse works before any runtime start is not asserted: the engine must
    // be up for the forward. Start the runtime and link the fixture account.
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-PinSync" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Happy-path manifest: the engine's projection comes through structured.
    let manifest = request(
        &mut client,
        "browse-manifest",
        "stickerPacks.getManifest",
        json!({
            "packId": "abcdef0123456789abcdef0123456789",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }),
    )
    .await;
    assert_eq!(manifest["result"]["title"], "Fixture Pack");
    assert_eq!(manifest["result"]["author"], "KT Fixture");
    assert_eq!(manifest["result"]["cover"]["id"], 1);
    assert_eq!(manifest["result"]["cover"]["emoji"], "🎉");
    assert_eq!(manifest["result"]["stickers"].as_array().unwrap().len(), 2);
    assert_eq!(
        manifest["result"]["stickers"][1]["contentType"],
        "image/png"
    );
    assert_eq!(manifest["result"]["stickerCount"], 2);

    // Happy-path image: base64/size/contentType pass through.
    let image = request(
        &mut client,
        "browse-image",
        "stickerPacks.getImage",
        json!({
            "packId": "abcdef0123456789abcdef0123456789",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "stickerId": 1
        }),
    )
    .await;
    assert_eq!(image["result"]["size"], 13);
    assert_eq!(image["result"]["contentType"], "image/webp");
    assert_eq!(image["result"]["dataBase64"], "Zml4dHVyZS1ieXRlcw==");

    // Structured engine errors: key-invalid is deterministic, fetch-failed
    // is retryable — the engine code maps without being swallowed or
    // re-invented.
    let bad_key = request(
        &mut client,
        "browse-bad-key",
        "stickerPacks.getManifest",
        json!({
            "packId": "ffffffffffffffffffffffffffffffff",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }),
    )
    .await;
    assert_eq!(bad_key["error"]["code"], "STICKER_PACK_KEY_INVALID");
    assert_eq!(bad_key["error"]["retryable"], false);
    let fetch_fail = request(
        &mut client,
        "browse-fetch-fail",
        "stickerPacks.getManifest",
        json!({
            "packId": "00000000000000000000000000000000",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }),
    )
    .await;
    assert_eq!(fetch_fail["error"]["code"], "STICKER_PACK_FETCH_FAILED");
    assert_eq!(fetch_fail["error"]["retryable"], true);
    let too_large = request(
        &mut client,
        "browse-too-large",
        "stickerPacks.getImage",
        json!({
            "packId": "abcdef0123456789abcdef0123456789",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "stickerId": 413
        }),
    )
    .await;
    assert_eq!(too_large["error"]["code"], "STICKER_IMAGE_TOO_LARGE");

    // Local bounds failures reject before any upstream call: a 64-hex send-
    // projection pack id is NOT valid on the browse face (32 hex exactly),
    // and a key decoding to 31 bytes is rejected.
    let wrong_length_id = request(
        &mut client,
        "browse-wrong-id",
        "stickerPacks.getManifest",
        json!({
            "packId": "abcdef01",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }),
    )
    .await;
    assert_eq!(wrong_length_id["error"]["code"], "INVALID_REQUEST");
    let wrong_key = request(
        &mut client,
        "browse-wrong-key",
        "stickerPacks.getImage",
        json!({
            "packId": "abcdef0123456789abcdef0123456789",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "stickerId": 1
        }),
    )
    .await;
    assert_eq!(wrong_key["error"]["code"], "INVALID_REQUEST");

    // Pin sync: the cloud-order read; then a write whose read-back observes
    // the write in first position.
    let pinned = request(
        &mut client,
        "get-pinned",
        "conversations.getPinned",
        json!({ "accountId": account_id }),
    )
    .await;
    let entries = pinned["result"]["pinned"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["conversationId"], "+15555550101");
    assert_eq!(entries[0]["kind"], "contact");
    assert_eq!(entries[1]["kind"], "group");

    // Address a real conversation: materialize one with a text send first.
    let sent = request(
        &mut client,
        "pin-setup-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "pin me",
            "clientRequestId": "pin-setup-1"
        }),
    )
    .await;
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    let set_pinned = request(
        &mut client,
        "set-pinned",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "pinned": true
        }),
    )
    .await;
    let entries = set_pinned["result"]["pinned"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["conversationId"], "+15555550102");
    assert_eq!(entries[0]["kind"], "contact");
    // The exact upstream contract landed on the wire: resolved reference,
    // kind, boolean.
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let pin_calls: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("pinned").is_some())
        .collect();
    assert_eq!(pin_calls.len(), 1, "{pin_calls:?}");
    assert_eq!(pin_calls[0]["account"], "+15555550100");
    assert_eq!(pin_calls[0]["conversationId"], "+15555550102");
    assert_eq!(pin_calls[0]["kind"], "contact");
    assert_eq!(pin_calls[0]["pinned"], true);

    // Unpin: the write applies symmetrically.
    let unpinned = request(
        &mut client,
        "set-unpinned",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "pinned": false
        }),
    )
    .await;
    let entries = unpinned["result"]["pinned"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| entry["conversationId"] != "+15555550102"),
        "the unpinned conversation must be gone: {entries:?}"
    );

    // Unknown conversation: the local ladder answers before any upstream
    // call.
    let unknown_conversation = request(
        &mut client,
        "pin-unknown",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "kind": "contact",
            "pinned": true
        }),
    )
    .await;
    assert_eq!(
        unknown_conversation["error"]["code"],
        "CONVERSATION_NOT_FOUND"
    );

    // Bounds: an illegal kind and a missing required boolean fail closed
    // locally.
    let bad_kind = request(
        &mut client,
        "pin-bad-kind",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "story",
            "pinned": true
        }),
    )
    .await;
    assert_eq!(bad_kind["error"]["code"], "INVALID_REQUEST");
    let missing_pinned = request(
        &mut client,
        "pin-missing-bool",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact"
        }),
    )
    .await;
    assert_eq!(missing_pinned["error"]["code"], "INVALID_REQUEST");

    // Storage outage surfaces the engine's STORAGE_* code verbatim
    // (retryable): the fixture answers it on the +15555550998 peer. The
    // peer send returns the conversation id directly.
    let storage_setup = request(
        &mut client,
        "pin-storage-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550998",
            "text": "storage sentinel",
            "clientRequestId": "pin-storage-0"
        }),
    )
    .await;
    let storage_conversation = storage_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let storage_down = request(
        &mut client,
        "pin-storage-down",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": storage_conversation,
            "kind": "contact",
            "pinned": true
        }),
    )
    .await;
    assert_eq!(storage_down["error"]["code"], "STORAGE_UNAVAILABLE");
    assert_eq!(storage_down["error"]["retryable"], true);

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// conversations.setExpireTimer end to end (contract 1.42, §4.41; group
/// route re-cut by contract 1.45, §4.44): the direct call lands on the
/// engine face's `setExpirationTimer` with the seconds-keyed
/// `expirationInSeconds`, the success mirrors the timer into the
/// conversation and rides `conversation.changed`, the result carries the
/// resolved value; a group conversation routes the same mirror through
/// `updateGroup {account, groupId, expiration}`; an unknown conversation
/// answers CONVERSATION_NOT_FOUND.
#[tokio::test]
async fn conversations_set_expire_timer_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [43_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-ExpireTimer" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Materialize a direct conversation with a text send, then set its
    // timer: the mirror lands and the summary carries it.
    let sent = request(
        &mut client,
        "timer-setup-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "timer setup",
            "clientRequestId": "timer-setup-1"
        }),
    )
    .await;
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    let set_timer = request(
        &mut client,
        "set-timer",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "expireSeconds": 86400
        }),
    )
    .await;
    assert_eq!(set_timer["result"]["expireTimerSeconds"], 86400);

    // The refreshed summary arrived on conversation.changed with the timer.
    let mut saw_timer_change = false;
    for _ in 0..8 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "conversation.changed timer mirror (86400) never arrived within \
                 {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed"
            && frame["data"]["id"] == conversation_id
            && frame["data"]["expireTimerSeconds"] == 86400
        {
            saw_timer_change = true;
            break;
        }
    }
    assert!(
        saw_timer_change,
        "conversation.changed must carry the mirrored timer"
    );

    // conversations.list agrees with the mirror.
    let listed = request(
        &mut client,
        "list-timers",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == conversation_id)
        .expect("the conversation is listed")
        .clone();
    assert_eq!(row["expireTimerSeconds"], 86400);

    // The exact upstream contract landed on the wire: the engine face's
    // seconds-keyed `expirationInSeconds` with the single-string resolved
    // recipient.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the dispatch");
    let timer_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|params| params.get("expirationInSeconds").is_some())
        .expect("the timer call must reach setExpirationTimer");
    assert_eq!(timer_call["account"], "+15555550100");
    assert_eq!(timer_call["recipient"], "+15555550102");
    assert_eq!(timer_call["expirationInSeconds"], 86400);

    // A group conversation routes the timer change through the same
    // group-management write it always traveled by upstream (contract 1.45,
    // §4.44 overturns the §4.41 group refusal): the fixture links with one
    // known group conversation in place, the call lands on `updateGroup` with
    // the int-seconds `expiration`, and the mirror + summary behave exactly
    // like the direct route.
    let listed = request(
        &mut client,
        "list-for-group",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with a group conversation");
    let group_timer = request(
        &mut client,
        "group-timer",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "expireSeconds": 3600
        }),
    )
    .await;
    assert_eq!(group_timer["result"]["expireTimerSeconds"], 3600);
    let mut saw_group_timer_change = false;
    for _ in 0..8 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "group conversation.changed timer mirror (3600) never arrived \
                 within {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed"
            && frame["data"]["id"] == group_conversation
            && frame["data"]["expireTimerSeconds"] == 3600
        {
            saw_group_timer_change = true;
            break;
        }
    }
    assert!(
        saw_group_timer_change,
        "the group route must mirror the timer like the direct route"
    );
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the dispatch");
    let group_timer_call: Value = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|params| params.get("groupId").is_some() && params.get("expiration").is_some())
        .expect("the group timer must reach updateGroup");
    assert_eq!(group_timer_call["account"], "+15555550100");
    assert_eq!(group_timer_call["groupId"], "ZmFrZS1ncm91cC0x");
    assert_eq!(group_timer_call["expiration"], 3600);

    // Unknown conversation answers CONVERSATION_NOT_FOUND locally.
    let unknown = request(
        &mut client,
        "unknown-timer",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "expireSeconds": 60
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "CONVERSATION_NOT_FOUND");

    // Out-of-face value and missing field fail closed locally.
    let oversized = request(
        &mut client,
        "oversized-timer",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "expireSeconds": 2147483648_u64
        }),
    )
    .await;
    assert_eq!(oversized["error"]["code"], "INVALID_REQUEST");
    let missing = request(
        &mut client,
        "missing-timer",
        "conversations.setExpireTimer",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "INVALID_REQUEST");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// groups.update / groups.quit end to end (contract 1.45, §4.44, capability
/// group-management; the engine write face wired by contract 1.115, §4.96):
/// the local refusal ladder answers before any upstream call, and the
/// engine-carried change families ride the wired updateGroup/leaveGroup
/// dispatch verbatim ({account, groupId} + title/member/link-access/avatar,
/// the avatar tri-state included) while any change key outside the engine
/// subset still answers the honest whole-call CAPABILITY_UNAVAILABLE —
/// never a partial application, nothing dispatched. The structured
/// GROUP_UPDATE_FAILED face carries data.status verbatim (403 non-admin,
/// 409 revision race) with retryable=false, the leave deny face answers the
/// deterministic UPSTREAM_ERROR (retryable=false), and the receive
/// projection converges the group row independently of the send face: the
/// bodyless UPDATE envelope lands as a system row carrying `isGroupUpdate` +
/// the resulting title, and `conversation.changed` mirrors the new title.
#[tokio::test]
async fn groups_update_quit_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [45_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupMgmt" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Contract 1.65 (§4.58): the factor probe rides the first
    // conversations.list — the link sync already resolved every title, so
    // the probe is the enrich's only trigger, and the fixture's listContacts
    // flush hook would deliver the staged envelopes on that round trip. Burn
    // the probe here, before the staged envelopes are written: this list
    // pays the one listContacts round trip (stamping the default-burst rows,
    // the flush hook finding an empty marker), so the list below stays a
    // store-only read and the choreography keeps controlling the burst via
    // the typing flush as before.
    let _ = request(
        &mut client,
        "probe-burn",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;

    // The link sync materialized the fixture group; staged envelopes refresh
    // it (the UPDATE projection below) and materialize a second group row.
    let extra_receives = temp
        .path()
        .join("signal-data")
        .join(".fixture-extra-receives.json");
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        &extra_receives,
        json!([
            {
                "source": "+15555550101",
                "timestamp": 60,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "ZmFrZS1ncm91cC0x",
                        "type": "UPDATE",
                        "groupName": "Renamed Fixture",
                        "revision": 7
                    }
                }
            },
            {
                "source": "+15555550101",
                "timestamp": 61,
                "dataMessage": {
                    "groupId": "ZmFhaWwtZ3JvdXAtMg==",
                    "message": "quit-fail group"
                }
            },
            {
                "source": "+15555550101",
                "timestamp": 62,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "[fixture-group-forbidden]",
                        "type": "UPDATE",
                        "groupName": "Forbidden Fixture",
                        "revision": 2
                    }
                }
            },
            {
                "source": "+15555550101",
                "timestamp": 63,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "[fixture-group-conflict]",
                        "type": "UPDATE",
                        "groupName": "Conflict Fixture",
                        "revision": 3
                    }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let listed = request(
        &mut client,
        "list-groups",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group" && row["title"] == "Fixture Group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with the fixture group");
    let direct_setup = request(
        &mut client,
        "direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "direct guard",
            "clientRequestId": "group-mgmt-0"
        }),
    )
    .await;
    let direct_conversation = direct_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // The refusal ladder, each before any upstream call.
    let empty = request(
        &mut client,
        "update-empty",
        "groups.update",
        json!({ "accountId": account_id, "conversationId": group_conversation }),
    )
    .await;
    assert_eq!(empty["error"]["code"], "INVALID_REQUEST");
    let absent_semantics = request(
        &mut client,
        "update-reset-false",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "resetLink": false
        }),
    )
    .await;
    assert_eq!(absent_semantics["error"]["code"], "INVALID_REQUEST");
    let empty_members = request(
        &mut client,
        "update-empty-members",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "addMembers": []
        }),
    )
    .await;
    assert_eq!(empty_members["error"]["code"], "INVALID_REQUEST");
    let bad_link = request(
        &mut client,
        "update-bad-link",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "linkState": "open"
        }),
    )
    .await;
    assert_eq!(bad_link["error"]["code"], "INVALID_REQUEST");
    let direct = request(
        &mut client,
        "update-direct",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "groupName": "Not A Group"
        }),
    )
    .await;
    assert_eq!(direct["error"]["code"], "INVALID_REQUEST");
    let unknown = request(
        &mut client,
        "update-unknown",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "groupName": "Nowhere"
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "CONVERSATION_NOT_FOUND");

    // Contract 1.89 avatar tri-state on the wired face (1.115): a malformed
    // data URI answers the shape ladder (INVALID_REQUEST); a well-formed
    // one — and an explicit null — ride the updateGroup dispatch verbatim
    // and answer {status: "sent"}.
    let bad_avatar = request(
        &mut client,
        "update-avatar-bad",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "avatar": "data:text/html;base64,YQ=="
        }),
    )
    .await;
    assert_eq!(bad_avatar["error"]["code"], "INVALID_REQUEST");
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let group_dispatches = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| {
                // updateGroup/leaveGroup dispatches carry {account, groupId};
                // the typing flush rows carry the same pair plus `stop`, and
                // the text send lane carries neither pair.
                params.get("account").is_some()
                    && params.get("groupId").is_some()
                    && params.get("stop").is_none()
            })
            .collect()
    };
    for (request_id, avatar) in [
        ("update-avatar-replace", json!("data:image/png;base64,YQ==")),
        ("update-avatar-remove", Value::Null),
    ] {
        let sent = request(
            &mut client,
            request_id,
            "groups.update",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation,
                "avatar": avatar
            }),
        )
        .await;
        assert_eq!(sent["result"]["status"], "sent", "{request_id}: {sent}");
    }
    let avatar_calls: Vec<Value> = group_dispatches()
        .into_iter()
        .filter(|params| params.get("avatar").is_some())
        .collect();
    assert_eq!(avatar_calls.len(), 2, "{avatar_calls:?}");
    assert_eq!(
        avatar_calls[0]["account"], "+15555550100",
        "{avatar_calls:?}"
    );
    assert_eq!(
        avatar_calls[0]["groupId"], "ZmFrZS1ncm91cC0x",
        "{avatar_calls:?}"
    );
    assert_eq!(avatar_calls[0]["avatar"], "data:image/png;base64,YQ==");
    assert!(avatar_calls[0].get("title").is_none(), "{avatar_calls:?}");
    assert_eq!(avatar_calls[1]["avatar"], Value::Null, "{avatar_calls:?}");

    // The engine-carried change set (contract 1.115, §4.96) rides one
    // updateGroup dispatch: groupName→title, the member arrays verbatim,
    // and linkState mapped onto the engine's access word.
    let renamed = request(
        &mut client,
        "update-wired",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "groupName": "Renamed Fixture",
            "addMembers": ["+15555550102"],
            "removeMembers": ["+15555550102"],
            "linkState": "enabled-without-approval",
            "operationId": "group-mgmt-op-1"
        }),
    )
    .await;
    assert_eq!(renamed["result"]["status"], "sent", "{renamed}");
    let wired_calls: Vec<Value> = group_dispatches()
        .into_iter()
        .filter(|params| params.get("title").is_some())
        .collect();
    assert_eq!(wired_calls.len(), 1, "{wired_calls:?}");
    assert_eq!(
        wired_calls[0],
        json!({
            "account": "+15555550100",
            "groupId": "ZmFrZS1ncm91cC0x",
            "title": "Renamed Fixture",
            "addMembers": ["+15555550102"],
            "removeMembers": ["+15555550102"],
            "addFromInviteLinkAccess": "ANY"
        }),
        "{wired_calls:?}"
    );

    // Contract 1.180 §4.180: resetLink folds onto the engine's
    // inviteLinkPassword arm — a freshly minted 24-char standard-base64
    // password (16 official bytes), never a resetLink key, and two calls
    // never mint the same password (the official refreshGroupLink: the old
    // link dies with the old password).
    let reset_once = request(
        &mut client,
        "update-reset-1",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "resetLink": true,
            "operationId": "group-mgmt-op-reset-1"
        }),
    )
    .await;
    assert_eq!(reset_once["result"]["status"], "sent", "{reset_once}");
    let reset_dispatches: Vec<Value> = group_dispatches()
        .into_iter()
        .filter(|params| params.get("inviteLinkPassword").is_some())
        .collect();
    assert_eq!(reset_dispatches.len(), 1, "{reset_dispatches:?}");
    let first_password = reset_dispatches[0]["inviteLinkPassword"].as_str().unwrap();
    assert_eq!(first_password.len(), 24);
    assert!(first_password.ends_with("=="));
    assert!(reset_dispatches[0].get("resetLink").is_none());
    assert_eq!(reset_dispatches[0]["groupId"], "ZmFrZS1ncm91cC0x");
    let reset_twice = request(
        &mut client,
        "update-reset-2",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "resetLink": true,
            "operationId": "group-mgmt-op-reset-2"
        }),
    )
    .await;
    assert_eq!(reset_twice["result"]["status"], "sent", "{reset_twice}");
    let second_passwords: Vec<String> = group_dispatches()
        .into_iter()
        .filter_map(|params| {
            params
                .get("inviteLinkPassword")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    assert_eq!(second_passwords.len(), 2);
    assert_ne!(second_passwords[0], second_passwords[1]);

    // Contract 1.188 (§4.188): the send-messages permission fold — the
    // host word pair rides the engine's own `announcementsOnly` bool in
    // one dispatch (only-admins → true, every-member → false, both real
    // write intents; the host permission words never reach the wire).
    for (request_id, word) in [
        ("update-announce-on", "only-admins"),
        ("update-announce-off", "every-member"),
    ] {
        let sent = request(
            &mut client,
            request_id,
            "groups.update",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation,
                "permissionSendMessages": word,
            }),
        )
        .await;
        assert_eq!(sent["result"]["status"], "sent", "{request_id}: {sent}");
    }
    let announce_calls: Vec<Value> = group_dispatches()
        .into_iter()
        .filter(|params| params.get("announcementsOnly").is_some())
        .collect();
    assert_eq!(announce_calls.len(), 2, "{announce_calls:?}");
    assert_eq!(announce_calls[0]["announcementsOnly"], json!(true));
    assert_eq!(announce_calls[1]["announcementsOnly"], json!(false));
    for call in &announce_calls {
        assert!(
            call.get("setPermissionSendMessages").is_none()
                && call.get("permissionSendMessages").is_none(),
            "the engine face carries only the folded bool: {call:?}"
        );
    }

    // Any change key outside the engine subset (description, the admin and
    // ban families, the remaining permission pair, the member label pair —
    // resetLink left this family in 1.180 §4.180 and permissionSendMessages
    // in 1.188 §4.188) still answers the honest whole-call
    // refusal — naming the offending keys, retryable=false — and dispatches
    // nothing: never a partial application of the change set. (The set below
    // also carries resetLink and permissionSendMessages, which now fold —
    // but the other offenders still refuse the whole call.)
    let dispatches_before = group_dispatches().len();
    let refused_update = request(
        &mut client,
        "update-all",
        "groups.update",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "groupName": "Renamed Fixture",
            "groupDescription": "KT ops group",
            "addMembers": ["+15555550102"],
            "removeMembers": ["+15555550102"],
            "promoteAdmins": ["+15555550101"],
            "demoteAdmins": ["+15555550101"],
            "banMembers": ["+15555550102"],
            "unbanMembers": ["+15555550102"],
            "linkState": "enabled-without-approval",
            "resetLink": true,
            "permissionAddMember": "only-admins",
            "permissionEditDetails": "every-member",
            "permissionSendMessages": "only-admins",
            "memberLabel": "KT",
            "memberLabelEmoji": "🛠️",
            "operationId": "group-mgmt-op-3"
        }),
    )
    .await;
    assert_eq!(refused_update["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(refused_update["error"]["retryable"], false);
    assert!(
        refused_update["error"]["message"]
            .as_str()
            .unwrap()
            .contains("groupDescription"),
        "{refused_update}"
    );
    assert_eq!(
        group_dispatches().len(),
        dispatches_before,
        "a refused change set never reaches the engine"
    );

    // Flush the staged envelopes through the typing hook (the receive burst
    // rides the request): the UPDATE envelope lands as a system row and the
    // conversation.changed summary already carries the mirrored title.
    let _ = request(
        &mut client,
        "flush-update",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "stop": true
        }),
    )
    .await;
    let mut saw_title_change = false;
    for _ in 0..16 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "conversation.changed title mirror never arrived within \
                 {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed"
            && frame["data"]["id"] == group_conversation
            && frame["data"]["title"] == "Renamed Fixture"
        {
            saw_title_change = true;
            break;
        }
    }
    assert!(
        saw_title_change,
        "the group update receive must mirror the new title"
    );
    let messages = request(
        &mut client,
        "list-update-rows",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "limit": 50
        }),
    )
    .await;
    let update_row = messages["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["isGroupUpdate"] == true)
        .expect("the bodyless update must land a system row");
    assert_eq!(update_row["direction"], "system");
    assert_eq!(update_row["body"], "群聊信息已更新");
    assert_eq!(update_row["groupName"], "Renamed Fixture");

    // The wired quit face (1.115): the resolved group row dispatches
    // leaveGroup {account, groupId} — the engine's method name for the
    // upstream quit write — and answers {status: "sent"}.
    let quit = request(
        &mut client,
        "quit-group",
        "groups.quit",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "operationId": "group-mgmt-op-2"
        }),
    )
    .await;
    assert_eq!(quit["result"]["status"], "sent", "{quit}");
    let quit_calls: Vec<Value> = group_dispatches()
        .into_iter()
        .filter(|params| {
            params.get("title").is_none()
                && params.get("avatar").is_none()
                && params.get("addMembers").is_none()
                && params.get("removeMembers").is_none()
                && params.get("addFromInviteLinkAccess").is_none()
                // 1.180 §4.180: the reset-link dispatches carry
                // inviteLinkPassword — not the quit face.
                && params.get("inviteLinkPassword").is_none()
                // 1.188 §4.188: the announcements-only dispatches carry
                // announcementsOnly — not the quit face.
                && params.get("announcementsOnly").is_none()
        })
        .collect();
    assert_eq!(quit_calls.len(), 1, "{quit_calls:?}");
    assert_eq!(quit_calls[0]["account"], "+15555550100", "{quit_calls:?}");
    assert_eq!(
        quit_calls[0]["groupId"], "ZmFrZS1ncm91cC0x",
        "{quit_calls:?}"
    );

    // The structured server-rejection face (1.115, §4.96): the fixture's
    // sentinel group rows answer GROUP_UPDATE_FAILED with the engine's
    // data.status pass-through verbatim — 403 (non-admin) and 409 (revision
    // race) — retryable=false both: a bare replay fails the same way, and a
    // 409 unblocks only after re-reading the group state.
    let relisted = request(
        &mut client,
        "list-sentinel-groups",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let find_by = |title: &str, preview: &str| {
        relisted["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["type"] == "group"
                    && row["title"] == title
                    && row["lastMessagePreview"] == preview
            })
            .map(|row| row["id"].as_str().unwrap().to_string())
            .unwrap_or_else(|| {
                panic!(
                    "the staged sentinel row {title} must exist; items: {:?}",
                    relisted["result"]["items"]
                )
            })
    };
    let forbidden_conversation = find_by("Forbidden Fixture", "群聊信息已更新");
    let conflict_conversation = find_by("Conflict Fixture", "群聊信息已更新");
    let quit_fail_conversation = find_by("group", "quit-fail group");
    for (request_id, conversation, status) in [
        ("update-forbidden", forbidden_conversation.as_str(), 403),
        ("update-conflict", conflict_conversation.as_str(), 409),
    ] {
        let rejected = request(
            &mut client,
            request_id,
            "groups.update",
            json!({
                "accountId": account_id,
                "conversationId": conversation,
                "groupName": "Still Forbidden"
            }),
        )
        .await;
        assert_eq!(
            rejected["error"]["code"], "GROUP_UPDATE_FAILED",
            "{request_id}: {rejected}"
        );
        assert_eq!(rejected["error"]["retryable"], false, "{request_id}");
        assert_eq!(rejected["error"]["data"]["status"], status, "{request_id}");
    }

    // The leave deny face: a last-admin quit (the fixture's user-error
    // sentinel) answers the deterministic UPSTREAM_ERROR — retryable=false,
    // the 1.115 correction: a replay of the same quit fails the same way.
    let quit_denied = request(
        &mut client,
        "quit-denied",
        "groups.quit",
        json!({
            "accountId": account_id,
            "conversationId": quit_fail_conversation
        }),
    )
    .await;
    assert_eq!(
        quit_denied["error"]["code"], "UPSTREAM_ERROR",
        "{quit_denied}"
    );
    assert_eq!(quit_denied["error"]["retryable"], false);

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// conversations.getState / conversations.setState end to end (contract
/// 1.116, §4.97, capability conversation-state): the read answers the
/// all-default projection, the partial writes answer the post-write
/// projection and persist across reads, only the sent flags ride the wire
/// (asserted byte-exact on the fixture dispatch log), and the honest engine
/// faces pass through — CONVERSATION_NOT_RESOLVED for a reference outside
/// the engine's storage taxonomy (a 12-byte fixture group id is not 32-byte
/// master-key material; a phone number is not group material either),
/// STORAGE_UNAVAILABLE for the outage sentinel — while the local refusal
/// ladder (empty intent, wrong flag shapes, kind enum, unknown rows)
/// answers before any upstream call.
#[tokio::test]
async fn conversation_state_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [47_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries the new faces before anything else runs.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in [
        "conversations.getState",
        "conversations.setState",
        "conversation-state",
    ] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-ConversationState" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The §4.58 factor probe rides the first conversations.list (the batch-A
    // choreography): burn it before the staged envelopes are written so the
    // burst stays under the typing flush's control.
    let _ = request(
        &mut client,
        "probe-burn",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;

    // Stage the storage-outage sentinel group; the receive projection
    // materializes its row with the sentinel groupId verbatim as peer
    // reference.
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550101",
                "timestamp": 64,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "[fixture-state-unavailable]",
                        "type": "UPDATE",
                        "groupName": "State Sentinel",
                        "revision": 4
                    }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let listed = request(
        &mut client,
        "list-groups",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group" && row["title"] == "Fixture Group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with the fixture group");
    let direct_setup = request(
        &mut client,
        "direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "state round trip",
            "clientRequestId": "state-rt-0"
        }),
    )
    .await;
    let direct_conversation = direct_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Flush the staged envelope through the typing hook and wait for the
    // sentinel row's summary mirror.
    let _ = request(
        &mut client,
        "flush-state",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "stop": true
        }),
    )
    .await;
    let mut sentinel_conversation = None;
    for _ in 0..16 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "the sentinel group's conversation.changed never arrived within \
                 {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed" && frame["data"]["title"] == "State Sentinel" {
            sentinel_conversation = Some(frame["data"]["id"].as_str().unwrap().to_string());
            break;
        }
    }
    let sentinel_conversation = sentinel_conversation
        .expect("the staged sentinel group must materialize with its mirrored title");

    // The all-default read: a conversation the cloud record holds at the
    // unset bits reads {0, false, false}, all three keys present.
    let initial = request(
        &mut client,
        "state-initial",
        "conversations.getState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact"
        }),
    )
    .await;
    assert_eq!(
        initial["result"],
        json!({
            "mutedUntilTimestamp": 0,
            "archived": false,
            "markedUnread": false
        }),
        "{initial}"
    );

    // The partial write: only the sent flag rides the wire, the answer is
    // the post-write projection, and a read-back observes the write.
    let archived = request(
        &mut client,
        "state-archive",
        "conversations.setState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact",
            "archived": true
        }),
    )
    .await;
    assert_eq!(
        archived["result"],
        json!({
            "mutedUntilTimestamp": 0,
            "archived": true,
            "markedUnread": false
        }),
        "{archived}"
    );
    let read_back = request(
        &mut client,
        "state-read-back",
        "conversations.getState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact"
        }),
    )
    .await;
    assert_eq!(read_back["result"]["archived"], true, "{read_back}");

    // The two-flag write composes over the untouched bit.
    let muted = request(
        &mut client,
        "state-mute",
        "conversations.setState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact",
            "mutedUntilTimestamp": 7_200_000,
            "markedUnread": true
        }),
    )
    .await;
    assert_eq!(
        muted["result"],
        json!({
            "mutedUntilTimestamp": 7_200_000,
            "archived": true,
            "markedUnread": true
        }),
        "{muted}"
    );

    // The exact upstream contract: the resolved peer reference, the kind,
    // and only the flags each write carried.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the dispatch");
    let state_writes: Vec<Value> = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| {
            params.get("kind").is_some()
                && (params.get("archived").is_some() || params.get("mutedUntilTimestamp").is_some())
        })
        .collect();
    assert_eq!(state_writes.len(), 2, "{state_writes:?}");
    assert_eq!(
        state_writes[0],
        json!({
            "account": "+15555550100",
            "conversationId": "+15555550102",
            "kind": "contact",
            "archived": true
        }),
        "{state_writes:?}"
    );
    assert_eq!(
        state_writes[1],
        json!({
            "account": "+15555550100",
            "conversationId": "+15555550102",
            "kind": "contact",
            "mutedUntilTimestamp": 7_200_000,
            "markedUnread": true
        }),
        "{state_writes:?}"
    );

    // The local refusal ladder, each before any upstream call: an empty
    // intent (no write intent — there is no toggle-to-nothing form), a
    // wrong-shaped flag, a flag value that is not a number, and the kind
    // enum on both faces.
    let empty = request(
        &mut client,
        "state-empty",
        "conversations.setState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact"
        }),
    )
    .await;
    assert_eq!(empty["error"]["code"], "INVALID_REQUEST", "{empty}");
    let wrong_shape = request(
        &mut client,
        "state-wrong-shape",
        "conversations.setState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact",
            "archived": "yes"
        }),
    )
    .await;
    assert_eq!(wrong_shape["error"]["code"], "INVALID_REQUEST");
    let bad_mute = request(
        &mut client,
        "state-bad-mute",
        "conversations.setState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "contact",
            "mutedUntilTimestamp": "soon"
        }),
    )
    .await;
    assert_eq!(bad_mute["error"]["code"], "INVALID_REQUEST");
    // The kind enum refuses on both faces — the get face with the bare
    // addressing trio (its params carry no flags), the set face with a flag
    // present so the empty-intent gate does not outrank the kind ladder.
    let refused_get = request(
        &mut client,
        "state-kind-get",
        "conversations.getState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "story"
        }),
    )
    .await;
    assert_eq!(refused_get["error"]["code"], "INVALID_REQUEST");
    let refused_set = request(
        &mut client,
        "state-kind-set",
        "conversations.setState",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "kind": "story",
            "archived": true
        }),
    )
    .await;
    assert_eq!(refused_set["error"]["code"], "INVALID_REQUEST");

    // Unknown rows answer the local NOT_FOUND ladder.
    let unknown_conversation = request(
        &mut client,
        "state-unknown-conversation",
        "conversations.getState",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "kind": "contact"
        }),
    )
    .await;
    assert_eq!(
        unknown_conversation["error"]["code"], "CONVERSATION_NOT_FOUND",
        "{unknown_conversation}"
    );
    let unknown_account = request(
        &mut client,
        "state-unknown-account",
        "conversations.getState",
        json!({
            "accountId": "no-such-account",
            "conversationId": direct_conversation,
            "kind": "contact"
        }),
    )
    .await;
    assert_eq!(
        unknown_account["error"]["code"], "ACCOUNT_NOT_FOUND",
        "{unknown_account}"
    );

    // The engine's canonicalization refusal (1.116, §4.97): a reference
    // outside the storage taxonomy — the fixture group's 12-byte id is not
    // 32-byte master-key material, and a phone number is not group material
    // either — answers CONVERSATION_NOT_RESOLVED, retryable=false.
    for (request_id, conversation, kind) in [
        ("state-group-shape", group_conversation.as_str(), "group"),
        ("state-kind-mismatch", direct_conversation.as_str(), "group"),
    ] {
        let unresolved = request(
            &mut client,
            request_id,
            "conversations.getState",
            json!({
                "accountId": account_id,
                "conversationId": conversation,
                "kind": kind
            }),
        )
        .await;
        assert_eq!(
            unresolved["error"]["code"], "CONVERSATION_NOT_RESOLVED",
            "{request_id}: {unresolved}"
        );
        assert_eq!(unresolved["error"]["retryable"], false, "{request_id}");
    }

    // The storage-outage sentinel: both faces answer STORAGE_UNAVAILABLE
    // verbatim, retryable=true (the outage may clear).
    for (request_id, method, extra) in [
        ("state-outage-get", "conversations.getState", json!({})),
        (
            "state-outage-set",
            "conversations.setState",
            json!({ "archived": true }),
        ),
    ] {
        let mut params = json!({
            "accountId": account_id,
            "conversationId": sentinel_conversation,
            "kind": "group"
        });
        for (key, value) in extra.as_object().unwrap() {
            params
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), value.clone());
        }
        let outage = request(&mut client, request_id, method, params).await;
        assert_eq!(
            outage["error"]["code"], "STORAGE_UNAVAILABLE",
            "{request_id}: {outage}"
        );
        assert_eq!(outage["error"]["retryable"], true, "{request_id}");
    }

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.117 (§4.98): the group invite-link family round trip. The
/// handshake advertises the six faces plus the `group-invite-links` tag;
/// the password face answers 16-byte CSPRNG material; build → parse is a
/// real proto round trip (the fixture mirrors the engine's group_link
/// codec) across the three official URL forms plus the bare code; preview
/// projects the full pre-join face; join answers both status verbs and
/// records its dispatch (the record-before-parse discipline, pinned on the
/// fixture log); cancel answers its verb; the two structured codes ride
/// their data.status pass-through; the outage marker answers
/// STORAGE_UNAVAILABLE; the local ladders (direct row, unknown rows,
/// bounds) refuse before any engine call.
#[tokio::test]
async fn groups_invite_link_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [48_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in [
        "groups.generateInviteLinkPassword",
        "groups.buildInviteLink",
        "groups.parseInviteLink",
        "groups.previewViaLink",
        "groups.joinViaLink",
        "groups.cancelJoinRequest",
        "group-invite-links",
    ] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-InviteLinks" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The §4.58 factor probe rides the first conversations.list: burn it
    // before the staged envelope is written.
    let _ = request(
        &mut client,
        "probe-burn",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;

    // Stage a 32-byte master-key group; its receive projection materializes
    // the row with that peer reference — the link family's addressing
    // material (the fixture group's 12-byte id is deliberately not link
    // material, the §4.97 honesty mirror).
    const LINK_GROUP_KEY: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550101",
                "timestamp": 71,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": LINK_GROUP_KEY,
                        "type": "UPDATE",
                        "groupName": "Link Group",
                        "revision": 2
                    }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();
    let _ = request(
        &mut client,
        "list-groups",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let direct_setup = request(
        &mut client,
        "direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "link round trip",
            "clientRequestId": "link-rt-0"
        }),
    )
    .await;
    let direct_conversation = direct_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = request(
        &mut client,
        "flush-link",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "stop": true
        }),
    )
    .await;
    let mut link_group_conversation = None;
    for _ in 0..16 {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "the staged link group's conversation.changed never arrived within \
                 {HARNESS_REQUEST_TIMEOUT:?}:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame["event"] == "conversation.changed" && frame["data"]["title"] == "Link Group" {
            link_group_conversation = Some(frame["data"]["id"].as_str().unwrap().to_string());
            break;
        }
    }
    let link_group_conversation = link_group_conversation
        .expect("the staged 32-byte link group must materialize with its mirrored title");

    // The password face: 16 CSPRNG bytes as standard base64 (24 chars),
    // two calls never coincide. The empty-params shape is part of the
    // contract.
    let password_one = request(
        &mut client,
        "link-password-1",
        "groups.generateInviteLinkPassword",
        json!({}),
    )
    .await;
    let password_material = password_one["result"]["password"].as_str().unwrap();
    assert_eq!(password_material.len(), 24, "{password_one}");
    let password_two = request(
        &mut client,
        "link-password-2",
        "groups.generateInviteLinkPassword",
        json!({}),
    )
    .await;
    assert_ne!(
        password_material,
        password_two["result"]["password"].as_str().unwrap()
    );

    // Build (explicit password) → the official link shape; parse is a real
    // round trip back to the same key + password bytes, across the three
    // official URL forms and the bare invite code.
    let built = request(
        &mut client,
        "link-build",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": link_group_conversation,
            "password": "EREREREREREREREREREREQ=="
        }),
    )
    .await;
    let invite_link = built["result"]["inviteLink"].as_str().unwrap().to_string();
    assert!(invite_link.starts_with("https://signal.group/#"), "{built}");
    let code = invite_link.rsplit('#').next().unwrap().to_string();
    assert!(!code.contains('+') && !code.contains('/') && !code.contains('='));
    let parsed = request(
        &mut client,
        "link-parse",
        "groups.parseInviteLink",
        json!({ "inviteLink": invite_link }),
    )
    .await;
    assert_eq!(
        parsed["result"],
        json!({
            "groupId": LINK_GROUP_KEY,
            "password": "EREREREREREREREREREREQ=="
        }),
        "{parsed}"
    );
    for (request_id, shape) in [
        ("link-parse-sgnl", format!("sgnl://signal.group/#{code}")),
        ("link-parse-join", format!("sgnl://joingroup#{code}")),
        ("link-parse-bare", code.clone()),
    ] {
        let answer = request(
            &mut client,
            request_id,
            "groups.parseInviteLink",
            json!({ "inviteLink": shape }),
        )
        .await;
        assert_eq!(
            answer["result"]["groupId"], LINK_GROUP_KEY,
            "{request_id}: {answer}"
        );
    }

    // Preview: the full pre-join projection (both optional profile keys
    // present), the same master key the parse decoded.
    let preview = request(
        &mut client,
        "link-preview",
        "groups.previewViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": invite_link
        }),
    )
    .await;
    assert_eq!(
        preview["result"],
        json!({
            "groupId": LINK_GROUP_KEY,
            "memberCount": 12,
            "revision": 7,
            "addFromInviteLink": "ANY",
            "approvalRequired": false,
            "pendingAdminApproval": false,
            "name": "Fixture Link Group",
            "description": "previewed through the invite link"
        }),
        "{preview}"
    );

    // Join: the definite verb, and the dispatch record rides the fixture
    // log verbatim (the record-before-parse discipline — a refused join
    // would leave its record too).
    let joined = request(
        &mut client,
        "link-join",
        "groups.joinViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": invite_link
        }),
    )
    .await;
    assert_eq!(joined["result"], json!({ "status": "joined" }), "{joined}");
    // The approval gate turns the same call into a request.
    let requested_build = request(
        &mut client,
        "link-build-requested",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": link_group_conversation,
            "password": "9/f39/f39/f39/f39/f39w=="
        }),
    )
    .await;
    let requested_link = requested_build["result"]["inviteLink"]
        .as_str()
        .unwrap()
        .to_string();
    let requested = request(
        &mut client,
        "link-join-requested",
        "groups.joinViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": requested_link
        }),
    )
    .await;
    assert_eq!(
        requested["result"],
        json!({ "status": "requested" }),
        "{requested}"
    );
    // Cancel: the definite verb.
    let cancelled = request(
        &mut client,
        "link-cancel",
        "groups.cancelJoinRequest",
        json!({
            "accountId": account_id,
            "inviteLink": invite_link
        }),
    )
    .await;
    assert_eq!(
        cancelled["result"],
        json!({ "status": "cancelled" }),
        "{cancelled}"
    );

    // The structured refusal faces ride the data.status pass-through: the
    // preview's own code and the join/cancel server-rejection channel (the
    // forged link carries the sentinel password bytes the fixture answers
    // on).
    let forged_build = request(
        &mut client,
        "link-build-forged",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": link_group_conversation,
            "password": "/v7+/v7+/v7+/v7+/v7+/g=="
        }),
    )
    .await;
    let forged_link = forged_build["result"]["inviteLink"]
        .as_str()
        .unwrap()
        .to_string();
    let preview_failed = request(
        &mut client,
        "link-preview-failed",
        "groups.previewViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": forged_link
        }),
    )
    .await;
    assert_eq!(
        preview_failed["error"]["code"], "GROUP_INVITE_LINK_PREVIEW_FAILED",
        "{preview_failed}"
    );
    assert_eq!(preview_failed["error"]["data"], json!({ "status": 404 }));
    assert_eq!(preview_failed["error"]["retryable"], false);
    let join_failed = request(
        &mut client,
        "link-join-failed",
        "groups.joinViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": forged_link
        }),
    )
    .await;
    assert_eq!(join_failed["error"]["code"], "GROUP_UPDATE_FAILED");
    assert_eq!(join_failed["error"]["data"], json!({ "status": 403 }));
    assert_eq!(join_failed["error"]["retryable"], false);
    let cancel_failed = request(
        &mut client,
        "link-cancel-failed",
        "groups.cancelJoinRequest",
        json!({
            "accountId": account_id,
            "inviteLink": forged_link
        }),
    )
    .await;
    assert_eq!(cancel_failed["error"]["code"], "GROUP_UPDATE_FAILED");
    assert_eq!(cancel_failed["error"]["data"], json!({ "status": 409 }));
    assert_eq!(cancel_failed["error"]["retryable"], false);

    // The build face's own code, both arms: the server-rejection sentinel
    // password (data.status) and the password-absent read-the-server-state
    // arm (the engine fake's link-not-set face, no data).
    let build_forbidden = request(
        &mut client,
        "link-build-forbidden",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": link_group_conversation,
            "password": "ra2tra2tra2tra2tra2trQ=="
        }),
    )
    .await;
    assert_eq!(
        build_forbidden["error"]["code"], "GROUP_INVITE_LINK_UNAVAILABLE",
        "{build_forbidden}"
    );
    assert_eq!(build_forbidden["error"]["data"], json!({ "status": 403 }));
    assert_eq!(build_forbidden["error"]["retryable"], false);
    let build_unset = request(
        &mut client,
        "link-build-unset",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": link_group_conversation
        }),
    )
    .await;
    assert_eq!(
        build_unset["error"]["code"],
        "GROUP_INVITE_LINK_UNAVAILABLE"
    );
    assert!(build_unset["error"].get("data").is_none(), "{build_unset}");
    assert_eq!(build_unset["error"]["retryable"], false);

    // The dispatch log pins the five writes' exact upstream payloads (the
    // account + inviteLink verbatim; nothing else rides). This runs before
    // the outage and malformed faces below so the log holds only the
    // definite round trips.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log the join dispatches");
    let link_writes: Vec<Value> = send_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("inviteLink").is_some())
        .collect();
    assert_eq!(link_writes.len(), 5, "{link_writes:?}");
    for write in &link_writes {
        assert_eq!(write["account"], "+15555550100", "{write}");
    }
    assert_eq!(link_writes[0]["inviteLink"], invite_link);
    assert_eq!(link_writes[1]["inviteLink"], requested_link);
    assert_eq!(link_writes[2]["inviteLink"], invite_link);
    assert_eq!(link_writes[3]["inviteLink"], forged_link);
    assert_eq!(link_writes[4]["inviteLink"], forged_link);

    // The outage marker: the read and write faces answer STORAGE_UNAVAILABLE
    // verbatim, retryable=true (the outage may clear).
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-invite-link-unavailable"),
        b"outage",
    )
    .unwrap();
    let outage_preview = request(
        &mut client,
        "link-outage-preview",
        "groups.previewViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": invite_link
        }),
    )
    .await;
    assert_eq!(
        outage_preview["error"]["code"], "STORAGE_UNAVAILABLE",
        "{outage_preview}"
    );
    assert_eq!(outage_preview["error"]["retryable"], true);
    let outage_join = request(
        &mut client,
        "link-outage-join",
        "groups.joinViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": invite_link
        }),
    )
    .await;
    assert_eq!(outage_join["error"]["code"], "STORAGE_UNAVAILABLE");
    assert_eq!(outage_join["error"]["retryable"], true);
    fs::remove_file(
        temp.path()
            .join("signal-data")
            .join(".fixture-invite-link-unavailable"),
    )
    .unwrap();

    // The malformed-link face: the engine's -32603 parse gate folds into
    // the deterministic UPSTREAM_ERROR (retryable=false).
    let malformed = request(
        &mut client,
        "link-parse-malformed",
        "groups.parseInviteLink",
        json!({ "inviteLink": "https://signal.group/#@@@" }),
    )
    .await;
    assert_eq!(malformed["error"]["code"], "UPSTREAM_ERROR", "{malformed}");
    assert_eq!(malformed["error"]["retryable"], false);
    let malformed_join = request(
        &mut client,
        "link-join-malformed",
        "groups.joinViaLink",
        json!({ "accountId": account_id, "inviteLink": "not-a-link" }),
    )
    .await;
    assert_eq!(malformed_join["error"]["code"], "UPSTREAM_ERROR");
    assert_eq!(malformed_join["error"]["retryable"], false);

    // The local refusal ladder, each before any engine call: the direct row
    // is not link material, unknown rows, and the link bounds.
    let direct_build = request(
        &mut client,
        "link-build-direct",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "password": "EREREREREREREREREREREQ=="
        }),
    )
    .await;
    assert_eq!(direct_build["error"]["code"], "INVALID_REQUEST");
    let unknown_conversation = request(
        &mut client,
        "link-build-unknown",
        "groups.buildInviteLink",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation"
        }),
    )
    .await;
    assert_eq!(
        unknown_conversation["error"]["code"], "CONVERSATION_NOT_FOUND",
        "{unknown_conversation}"
    );
    let unknown_account = request(
        &mut client,
        "link-preview-unknown-account",
        "groups.previewViaLink",
        json!({
            "accountId": "no-such-account",
            "inviteLink": invite_link
        }),
    )
    .await;
    assert_eq!(unknown_account["error"]["code"], "ACCOUNT_NOT_FOUND");
    let empty_link = request(
        &mut client,
        "link-preview-empty",
        "groups.previewViaLink",
        json!({
            "accountId": account_id,
            "inviteLink": ""
        }),
    )
    .await;
    assert_eq!(empty_link["error"]["code"], "INVALID_REQUEST");
    let oversized_link = request(
        &mut client,
        "link-preview-oversized",
        "groups.parseInviteLink",
        json!({ "inviteLink": "x".repeat(1025) }),
    )
    .await;
    assert_eq!(oversized_link["error"]["code"], "INVALID_REQUEST");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}
/// Contract revision 1.118 (§4.99): the delete-for-me upstream leg. The
/// handshake advertises `messages.deleteForMe` plus the `delete-for-me`
/// tag; the full-clear arm rides the engine `deleteForMeConversation` face
/// with the entries verbatim, the local-only arm carries no entries, the
/// grammar refuses (empty full-clear entries, oversized lists, entries on
/// the local-only arm, a zero timestamp, legacyGroup), and the crash
/// sentinel degrades to `unknown` with no error object and no retry (the
/// receipt-class discipline).
#[tokio::test]
async fn messages_delete_for_me_rides_the_engine_sync_face() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [58_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in ["messages.deleteForMe", "delete-for-me"] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-DeleteForMe" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // A direct conversation with one landed message: the delete-for-me
    // conversation resolves through the local row.
    let sent = request(
        &mut client,
        "dfm-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "conversation to clear",
            "clientRequestId": "dfm-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Full-clear arm: the entries ride verbatim, the conversation resolves
    // to the peer reference the engine's toConversationIdentifier carries.
    let cleared = request(
        &mut client,
        "dfm-clear",
        "messages.deleteForMe",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "mostRecentMessages": [
                { "author": "+15555550101", "timestamp": 99 },
                { "author": "+15555550100", "timestamp": 100 }
            ],
            "mostRecentNonExpiringMessages": [
                { "author": "+15555550101", "timestamp": 101 }
            ]
        }),
    )
    .await;
    assert_eq!(cleared["result"]["status"], "sent");
    assert!(
        cleared.get("error").is_none(),
        "a confirmed sync must not carry an error: {cleared:?}"
    );

    // Local-only arm: no entries travel, the localOnly bit rides.
    let local_only = request(
        &mut client,
        "dfm-local",
        "messages.deleteForMe",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "localOnly": true
        }),
    )
    .await;
    assert_eq!(local_only["result"]["status"], "sent");

    // The exact upstream dispatches were recorded by the fixture, in wire
    // order, entries verbatim.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log deleteForMeConversation params");
    let dispatches: Vec<Value> = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|params: &Value| {
            params.get("mostRecentMessages").is_some() || params.get("localOnly").is_some()
        })
        .collect();
    assert_eq!(
        dispatches.len(),
        2,
        "both arms reach the upstream exactly once: {dispatches:?}"
    );
    assert_eq!(dispatches[0]["account"], "+15555550100");
    assert_eq!(dispatches[0]["kind"], "contact");
    assert_eq!(dispatches[0]["conversationId"], "+15555550101");
    assert_eq!(
        dispatches[0]["mostRecentMessages"],
        json!([
            { "author": "+15555550101", "timestamp": 99 },
            { "author": "+15555550100", "timestamp": 100 }
        ])
    );
    assert_eq!(
        dispatches[0]["mostRecentNonExpiringMessages"],
        json!([{ "author": "+15555550101", "timestamp": 101 }])
    );
    assert!(dispatches[0].get("localOnly").is_none());
    assert_eq!(dispatches[1]["localOnly"], true);
    assert!(dispatches[1].get("mostRecentMessages").is_none());
    assert!(dispatches[1].get("mostRecentNonExpiringMessages").is_none());

    // The grammar refuses before any upstream call.
    let grammar_refusals: Vec<(&str, Value)> = vec![
        (
            "dfm-empty",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "contact",
                "mostRecentMessages": []
            }),
        ),
        (
            "dfm-oversized",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "contact",
                "mostRecentMessages": [
                    { "author": "+15555550101", "timestamp": 1 },
                    { "author": "+15555550101", "timestamp": 2 },
                    { "author": "+15555550101", "timestamp": 3 },
                    { "author": "+15555550101", "timestamp": 4 },
                    { "author": "+15555550101", "timestamp": 5 },
                    { "author": "+15555550101", "timestamp": 6 }
                ]
            }),
        ),
        (
            "dfm-local-with-entries",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "contact",
                "localOnly": true,
                "mostRecentMessages": [{ "author": "+15555550101", "timestamp": 99 }]
            }),
        ),
        (
            "dfm-zero-timestamp",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "contact",
                "mostRecentMessages": [{ "author": "+15555550101", "timestamp": 0 }]
            }),
        ),
        (
            "dfm-legacy-group",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "legacyGroup",
                "mostRecentMessages": [{ "author": "+15555550101", "timestamp": 99 }]
            }),
        ),
        (
            "dfm-oversized-non-expiring",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "contact",
                "mostRecentMessages": [{ "author": "+15555550101", "timestamp": 99 }],
                "mostRecentNonExpiringMessages": [
                    { "author": "+15555550101", "timestamp": 1 },
                    { "author": "+15555550101", "timestamp": 2 },
                    { "author": "+15555550101", "timestamp": 3 },
                    { "author": "+15555550101", "timestamp": 4 },
                    { "author": "+15555550101", "timestamp": 5 },
                    { "author": "+15555550101", "timestamp": 6 }
                ]
            }),
        ),
    ];
    for (id, params) in grammar_refusals {
        let refused = request(&mut client, id, "messages.deleteForMe", params).await;
        assert_eq!(
            refused["error"]["code"], "INVALID_REQUEST",
            "{id} must refuse before any upstream call: {refused:?}"
        );
    }
    let refusals_logged = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap()
    .lines()
    .map(|line| serde_json::from_str::<Value>(line).unwrap())
    .filter(|params: &Value| {
        params.get("mostRecentMessages").is_some() || params.get("localOnly").is_some()
    })
    .count();
    assert_eq!(
        refusals_logged, 2,
        "the refusals must not reach the upstream"
    );

    // The crash sentinel (timestamp 427) kills the engine mid-call: the
    // sync message may or may not have reached the other devices — the
    // request degrades to `unknown`, no error object, no retry.
    let indeterminate = request(
        &mut client,
        "dfm-crash",
        "messages.deleteForMe",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "mostRecentMessages": [
                { "author": "+15555550101", "timestamp": 99 },
                { "author": "+15555550101", "timestamp": 427 }
            ]
        }),
    )
    .await;
    assert_eq!(indeterminate["result"]["status"], "unknown");
    assert!(
        indeterminate.get("error").is_none(),
        "a receipt failure must not fail the request: {indeterminate:?}"
    );

    wait_for_process_exit(engine_pid).await;
    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.197 (§4.197): the message-level delete-for-me
/// upstream leg. The handshake advertises `messages.deleteForMeMessages`
/// plus the existing `delete-for-me` tag; the desktop addresses local row
/// ids, the connector resolves the row's official `(author, sentTimestamp)`
/// pair (outgoing → the account's own address), and exactly one engine
/// `deleteForMeMessages` dispatch lands. Batch refusals — an unknown row
/// and an over-cap list — answer before any engine call.
#[tokio::test]
async fn messages_delete_for_me_messages_resolves_rows_and_rides_the_engine() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [61_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in ["messages.deleteForMeMessages", "delete-for-me"] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-DeleteForMeMessages" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // One landed outgoing row: its id is the desktop handle, its upstream
    // stamp is what the sync frame must address.
    let sent = request(
        &mut client,
        "dfm-msg-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550101",
            "text": "delete this message for me",
            "clientRequestId": "dfm-msg-send-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let message_id = sent["result"]["id"].as_str().unwrap().to_string();
    let sent_at = sent["result"]["sentAt"].as_u64().unwrap();

    let synced = request(
        &mut client,
        "dfm-msg-sync",
        "messages.deleteForMeMessages",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": [message_id]
        }),
    )
    .await;
    assert_eq!(synced["result"]["status"], "sent", "{synced:?}");
    assert!(
        synced.get("error").is_none(),
        "a confirmed sync must not carry an error: {synced:?}"
    );

    // The exact upstream dispatch: local ids resolved to the official pair,
    // the conversation reference and the row family on the wire.
    let send_log = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .expect("fixture must log deleteForMeMessages params");
    let dispatches: Vec<Value> = send_log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|params: &Value| params.get("entries").is_some())
        .collect();
    assert_eq!(
        dispatches.len(),
        1,
        "one engine dispatch for the whole batch: {dispatches:?}"
    );
    assert_eq!(dispatches[0]["account"], "+15555550100");
    assert_eq!(dispatches[0]["kind"], "contact");
    assert_eq!(dispatches[0]["conversationId"], "+15555550101");
    assert_eq!(
        dispatches[0]["entries"],
        json!([{ "author": "+15555550100", "timestamp": sent_at }])
    );

    // The all-or-nothing refusals never reach the engine: an unknown row
    // and a list past the 256 ceiling.
    let unknown = request(
        &mut client,
        "dfm-msg-unknown",
        "messages.deleteForMeMessages",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": [message_id, "no-such-row"]
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "MESSAGE_NOT_FOUND", "{unknown:?}");
    let over_cap: Vec<String> = (0..=256).map(|index| format!("row-{index}")).collect();
    let over_cap = request(
        &mut client,
        "dfm-msg-over-cap",
        "messages.deleteForMeMessages",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": over_cap
        }),
    )
    .await;
    assert_eq!(over_cap["error"]["code"], "INVALID_REQUEST", "{over_cap:?}");
    let refusals_logged = fs::read_to_string(
        temp.path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl"),
    )
    .unwrap()
    .lines()
    .map(|line| serde_json::from_str::<Value>(line).unwrap())
    .filter(|params: &Value| params.get("entries").is_some())
    .count();
    assert_eq!(
        refusals_logged, 1,
        "the refused batches must not reach the upstream"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}
/// through the fixture's `.fixture-extra-receives.json` carry `serverGuid`
/// Contract 1.49 (§4.48): the reportSpam round trip. Envelopes staged
/// through the fixture's `.fixture-extra-receives.json` carry `serverGuid`
/// values; the report addresses the persisted rows, guid-less rows answer
/// per-id failures (no invented code), group conversations refuse before
/// any upstream call, unknown ids fail per-id, the structured
/// REPORT_SPAM_FAILED maps through the host face, the crash sentinel pins
/// SEND_OUTCOME_UNKNOWN with the no-retry discipline, and the handshake
/// advertises the method plus the `report-spam` capability.
#[tokio::test]
async fn report_spam_round_trip_persists_server_guids_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [46_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries the new face before anything else runs.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in ["messages.reportSpam", "report-spam"] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-ReportSpam" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Stage one guid-carrying envelope and one guid-less envelope for the
    // fixture peer, then flush them through the typing hook.
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 70,
                "serverGuid": "guid-live-1",
                "dataMessage": { "message": "spam candidate one" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 71,
                "dataMessage": { "message": "sent-row twin" }
            }
        ])
        .to_string(),
    )
    .unwrap();
    let setup = request(
        &mut client,
        "direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "report guard",
            "clientRequestId": "report-spam-0"
        }),
    )
    .await;
    let conversation_id = setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = request(
        &mut client,
        "flush-receives",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "stop": true
        }),
    )
    .await;

    // The flush response can outrun the receive processing; wait for both
    // staged rows' upsert events before reading the list.
    let upserted = timeout(Duration::from_secs(5), async {
        let mut seen: Vec<Value> = Vec::new();
        while seen.len() < 2 {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["direction"] == "incoming"
            {
                seen.push(frame["data"].clone());
            }
        }
        seen
    })
    .await
    .expect("both staged envelopes must land rows");
    let guided_id = upserted
        .iter()
        .find(|row| row["sentAt"] == 70)
        .expect("the guid-carrying envelope lands a row")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let plain_id = upserted
        .iter()
        .find(|row| row["sentAt"] == 71)
        .expect("the guid-less envelope lands a row")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let listed = request(
        &mut client,
        "list-rows",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let rows = listed["result"]["items"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|row| row["direction"] == "incoming" && row["sentAt"] == 70),
        "the guid-carrying row is listable"
    );
    assert!(
        rows.iter()
            .any(|row| row["direction"] == "incoming" && row["sentAt"] == 71),
        "the guid-less row is listable"
    );

    // Group addressing refuses before any upstream call. The link sync
    // materialized the fixture group; its rows address the refusal.
    let listed_groups = request(
        &mut client,
        "list-groups",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed_groups["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with the fixture group");
    let group_report = request(
        &mut client,
        "group-report",
        "messages.reportSpam",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "messageIds": ["any-id"]
        }),
    )
    .await;
    assert_eq!(group_report["error"]["code"], "INVALID_REQUEST");

    // The mixed report: the guided row reports, the guid-less twin and the
    // unknown id answer per-id failures without a code.
    let reported = request(
        &mut client,
        "report-mixed",
        "messages.reportSpam",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": [guided_id, plain_id, "msg-unknown"]
        }),
    )
    .await;
    assert_eq!(reported["result"]["reported"], 1);
    let failures = reported["result"]["failures"].as_array().unwrap();
    assert_eq!(
        failures.len(),
        2,
        "the guid-less twin and the unknown id fail: {failures:?}"
    );
    for failure in failures {
        assert_eq!(
            failure["code"],
            Value::Null,
            "no invented status: {failure:?}"
        );
        assert!(
            failure.get("code").is_none(),
            "the code key stays absent on transport-class failures: {failure:?}"
        );
    }
    let failed_ids: Vec<&str> = failures
        .iter()
        .map(|failure| failure["messageId"].as_str().unwrap())
        .collect();
    assert!(failed_ids.contains(&plain_id.as_str()));
    assert!(failed_ids.contains(&"msg-unknown"));

    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let report_call: Value = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|params| params.get("serverGuids").is_some())
        .expect("the report must reach reportSpam");
    assert_eq!(report_call["account"], "+15555550100");
    // The fixture peer's ACI comes from the envelope's sourceUuid (the peer
    // identity the ingest recorded), not the numeric peer key.
    assert_eq!(
        report_call["targetAci"],
        "22222222-2222-2222-2222-222222222222"
    );
    assert_eq!(report_call["serverGuids"], json!(["guid-live-1"]));

    // A partial failure rides the success result: the server rejected one
    // guid with status 400, keyed back onto the caller's message id. The
    // fixture's marker cursor is positional, so the appended envelope rides
    // the same array (the first two entries were already emitted).
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 70,
                "serverGuid": "guid-live-1",
                "dataMessage": { "message": "spam candidate one" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 71,
                "dataMessage": { "message": "sent-row twin" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 72,
                "serverGuid": "guid-partial",
                "dataMessage": { "message": "partial reject" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 73,
                "serverGuid": "guid-reject-all",
                "dataMessage": { "message": "batch reject" }
            }
        ])
        .to_string(),
    )
    .unwrap();
    let _ = request(
        &mut client,
        "flush-partial",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "stop": true
        }),
    )
    .await;
    let staged_tail = timeout(Duration::from_secs(5), async {
        let mut seen: Vec<Value> = Vec::new();
        while seen.len() < 2 {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["direction"] == "incoming"
            {
                seen.push(frame["data"].clone());
            }
        }
        seen
    })
    .await
    .expect("both staged tail envelopes must land rows");
    let partial_id = staged_tail
        .iter()
        .find(|row| row["sentAt"] == 72)
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the partial envelope lands a row");
    let reject_all_id = staged_tail
        .iter()
        .find(|row| row["sentAt"] == 73)
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the reject-all envelope lands a row");
    let partial = request(
        &mut client,
        "report-partial",
        "messages.reportSpam",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": [partial_id]
        }),
    )
    .await;
    assert_eq!(partial["result"]["reported"], 1);
    assert_eq!(partial["result"]["failures"][0]["messageId"], partial_id);
    assert_eq!(partial["result"]["failures"][0]["code"], 400);

    // The structured refusal: the whole batch rejected maps onto the host
    // code verbatim, retryable=false.
    let refused = request(
        &mut client,
        "report-refused",
        "messages.reportSpam",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": [reject_all_id]
        }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "REPORT_SPAM_FAILED");
    assert_eq!(refused["error"]["retryable"], false);

    // Crash with the mutating report in flight (fixture magic guid):
    // SEND_OUTCOME_UNKNOWN, never retried — exactly one such call in the
    // recovered log. The crash needs a row carrying the magic guid.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 70,
                "serverGuid": "guid-live-1",
                "dataMessage": { "message": "spam candidate one" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 71,
                "dataMessage": { "message": "sent-row twin" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 72,
                "serverGuid": "guid-partial",
                "dataMessage": { "message": "partial reject" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 73,
                "serverGuid": "guid-reject-all",
                "dataMessage": { "message": "batch reject" }
            },
            {
                "source": "+15555550102",
                "sourceUuid": "22222222-2222-2222-2222-222222222222",
                "timestamp": 74,
                "serverGuid": "guid-crash",
                "dataMessage": { "message": "crash carrier" }
            }
        ])
        .to_string(),
    )
    .unwrap();
    let _ = request(
        &mut client,
        "flush-crash",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "stop": true
        }),
    )
    .await;
    let crash_id = timeout(Duration::from_secs(5), async {
        loop {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["direction"] == "incoming"
                && frame["data"]["sentAt"] == 74
            {
                return frame["data"]["id"].as_str().unwrap().to_string();
            }
        }
    })
    .await
    .expect("the crash-carrier envelope lands a row");
    let crash_setup = request(
        &mut client,
        "report-crash",
        "messages.reportSpam",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageIds": [crash_id]
        }),
    )
    .await;
    assert_eq!(crash_setup["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-report", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid);
    let crash_calls: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| {
            params
                .get("serverGuids")
                .and_then(Value::as_array)
                .is_some_and(|guids| guids.contains(&json!("guid-crash")))
        })
        .collect();
    assert_eq!(
        crash_calls.len(),
        1,
        "an unknown report outcome is never retried: {crash_calls:?}"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

#[tokio::test]
async fn sticker_and_pin_methods_surface_engine_errors() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [41_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-OldEngine" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Codeless engine error (the 0x11 pack id sentinel): degrades to the
    // plain upstream error, never a partial manifest.
    let degraded = request(
        &mut client,
        "browse-degraded",
        "stickerPacks.getManifest",
        json!({
            "packId": "11111111111111111111111111111111",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }),
    )
    .await;
    assert_eq!(degraded["error"]["code"], "UPSTREAM_ERROR");
    assert_eq!(degraded["error"]["retryable"], true);

    // CONVERSATION_NOT_RESOLVED passes through verbatim: the fixture
    // answers it on the +15555550997 peer (the conversation id comes
    // straight from the peer send result).
    let unresolved_setup = request(
        &mut client,
        "pin-unresolved-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550997",
            "text": "unresolved sentinel",
            "clientRequestId": "pin-unresolved-0"
        }),
    )
    .await;
    let unresolved_conversation = unresolved_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let unresolved = request(
        &mut client,
        "pin-unresolved",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": unresolved_conversation,
            "kind": "contact",
            "pinned": true
        }),
    )
    .await;
    assert_eq!(unresolved["error"]["code"], "CONVERSATION_NOT_RESOLVED");
    assert_eq!(unresolved["error"]["retryable"], false);

    // Crash with the mutating pin in flight (fixture peer +15555550999,
    // os._exit(29)): the request answers SEND_OUTCOME_UNKNOWN and nothing
    // is retried — the recovered log shows exactly one pin call for the
    // sentinel peer.
    let crash_setup = request(
        &mut client,
        "pin-crash-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550999",
            "text": "crash sentinel",
            "clientRequestId": "pin-crash-0"
        }),
    )
    .await;
    let crash_conversation = crash_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let crash = request(
        &mut client,
        "pin-crash",
        "conversations.setPinned",
        json!({
            "accountId": account_id,
            "conversationId": crash_conversation,
            "kind": "contact",
            "pinned": true
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;

    // Recovery: an explicit start brings the engine back; the pin write is
    // not replayed (exactly one crash call in the log).
    let restarted = request(&mut client, "restart-pin", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid);
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let crash_calls: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("pinned").is_some())
        .collect();
    assert_eq!(
        crash_calls
            .iter()
            .filter(|params| params["conversationId"] == "+15555550999")
            .count(),
        1,
        "an unknown pin outcome is never retried: {crash_calls:?}"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revisions 1.46 + 1.120: the §4.45 account-settings write faces
/// (accounts.updateConfiguration partial-write forwarding — the 1.120 §4.101
/// linkPreviews bit included — accounts.setProfile
/// text full-write + avatar tri-state + bounds, accounts.setExpireTimer u32
/// engine face) and the conversations.getBlocked read face — success shapes,
/// the deterministic fail-closed ladder, the structured STORAGE_* passthrough
/// riding the profile face's sentinels, and the crash-with-in-flight-write
/// unknown outcome on both mutating faces (no retry, exactly-once dispatch).
/// The 1.120 read-mirror linkage: another linked device's configuration sync
/// lands as the §4.87 settings.configurationSync event carrying the same
/// linkPreviews key the write face takes.
#[tokio::test]
async fn account_settings_and_blocked_faces_round_trip() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [43_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let mut engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-AccountSettings" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let send_log = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    };

    // Blocked read: the storage-order fixture constant, the pinned-face entry
    // shape (conversationId + kind), contact and legacyGroup kinds.
    let blocked = request(
        &mut client,
        "get-blocked",
        "conversations.getBlocked",
        json!({ "accountId": account_id }),
    )
    .await;
    let entries = blocked["result"]["blocked"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["conversationId"], "+15555550103");
    assert_eq!(entries[0]["kind"], "contact");
    // The 窗D B7 read-projection (contract revision 1.119, §4.100): the
    // contact record's stamp rides verbatim, the GV1 entry never carries
    // the key (the official shape).
    assert_eq!(entries[0]["blockedAtTimestampMs"], 1700000000000_u64);
    assert_eq!(entries[1]["kind"], "legacyGroup");
    assert!(entries[1].get("blockedAtTimestampMs").is_none());
    let missing_account = request(
        &mut client,
        "blocked-missing-account",
        "conversations.getBlocked",
        json!({}),
    )
    .await;
    assert_eq!(missing_account["error"]["code"], "INVALID_REQUEST");

    // Configuration partial write: only the provided keys reach upstream.
    // Contract 1.120 (§4.101): the linkPreviews bit rides the same face.
    let configured = request(
        &mut client,
        "config-partial",
        "accounts.updateConfiguration",
        json!({
            "accountId": account_id,
            "readReceipts": true,
            "phoneNumberSharingMode": "nobody",
            "linkPreviews": true
        }),
    )
    .await;
    assert_eq!(configured["result"]["status"], "saved");
    let config_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("readReceipts").is_some())
        .collect();
    assert_eq!(config_calls.len(), 1, "{config_calls:?}");
    assert_eq!(config_calls[0]["account"], "+15555550100");
    assert_eq!(config_calls[0]["readReceipts"], true);
    assert_eq!(config_calls[0]["phoneNumberSharingMode"], "nobody");
    assert_eq!(config_calls[0]["linkPreviews"], true);
    assert!(config_calls[0].get("typingIndicators").is_none());
    assert!(config_calls[0].get("unlistedPhoneNumber").is_none());

    // A lone linkPreviews write satisfies the at-least-one rule by itself and
    // forwards only its own key (the partial-write contract, new member).
    let link_only = request(
        &mut client,
        "config-link-only",
        "accounts.updateConfiguration",
        json!({
            "accountId": account_id,
            "linkPreviews": false
        }),
    )
    .await;
    assert_eq!(link_only["result"]["status"], "saved");
    let link_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| {
            params.get("linkPreviews").is_some() && params.get("readReceipts").is_none()
        })
        .collect();
    assert_eq!(link_calls.len(), 1, "{link_calls:?}");
    assert_eq!(link_calls[0]["account"], "+15555550100");
    assert_eq!(link_calls[0]["linkPreviews"], false);
    assert!(link_calls[0].get("readReceipts").is_none());

    // Fail-closed ladder: zero writable keys, the retired CONTACTS_ONLY enum
    // value, an unknown key, a non-boolean, a non-boolean linkPreviews.
    for (request_id, params) in [
        ("config-empty", json!({ "accountId": account_id })),
        (
            "config-retired-enum",
            json!({
                "accountId": account_id,
                "phoneNumberSharingMode": "contactsOnly"
            }),
        ),
        (
            "config-unknown-key",
            json!({
                "accountId": account_id,
                "readReceipts": true,
                "bogus": 1
            }),
        ),
        (
            "config-non-bool",
            json!({
                "accountId": account_id,
                "readReceipts": "yes"
            }),
        ),
        (
            "config-link-non-bool",
            json!({
                "accountId": account_id,
                "linkPreviews": "yes"
            }),
        ),
    ] {
        let rejected = request(
            &mut client,
            request_id,
            "accounts.updateConfiguration",
            params,
        )
        .await;
        assert_eq!(
            rejected["error"]["code"], "INVALID_REQUEST",
            "{request_id}: {rejected}"
        );
    }
    let config_calls_after: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("readReceipts").is_some())
        .collect();
    assert_eq!(config_calls_after.len(), 1, "refusals never dial upstream");

    // The 1.120 read-mirror linkage: another linked device's configuration
    // sync lands as the §4.87 settings.configurationSync event with the
    // linkPreviews key in place — the write face and the read projection
    // speak the same key name.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [{
            "source": "+15555550100",
            "timestamp": 5000000123_u64,
            "syncMessage": {
                "configuration": {
                    "readReceipts": true,
                    "linkPreviews": false
                }
            }
        }] })
        .to_string(),
    )
    .unwrap();
    // The marker-file trigger is asynchronous (the fixture watcher polls the
    // file), so the wait side is a deadline loop for the event itself — the
    // drain_until pattern without a response barrier.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mirrored = loop {
        let frame: Value = match timeout(Duration::from_secs(2), async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "the configurationSync mirror must arrive within the deadline:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame.get("event").and_then(Value::as_str) == Some("settings.configurationSync") {
            break frame["data"].clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "only unrelated frames arrived before the deadline: {frame}"
        );
    };
    assert_eq!(mirrored["accountId"], account_id);
    assert_eq!(mirrored["readReceipts"], true);
    assert_eq!(mirrored["linkPreviews"], false);
    assert!(mirrored.get("typingIndicators").is_none());
    assert!(mirrored.get("unidentifiedDeliveryIndicators").is_none());

    // Profile full-write: text keys forward verbatim, absent keys stay absent
    // (the caller's clear instruction), the avatar replace forwards verbatim.
    let profile = request(
        &mut client,
        "profile-set",
        "accounts.setProfile",
        json!({
            "accountId": account_id,
            "givenName": "李",
            "about": "hello",
            "avatar": "data:image/png;base64,YQ=="
        }),
    )
    .await;
    assert_eq!(profile["result"]["status"], "saved");
    let profile_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("givenName").is_some())
        .collect();
    assert_eq!(profile_calls.len(), 1, "{profile_calls:?}");
    assert_eq!(profile_calls[0]["account"], "+15555550100");
    assert_eq!(profile_calls[0]["givenName"], "李");
    assert_eq!(profile_calls[0]["about"], "hello");
    assert_eq!(profile_calls[0]["avatar"], "data:image/png;base64,YQ==");
    assert!(profile_calls[0].get("familyName").is_none());

    // Clearing face: familyName "" clears upstream; avatar null removes.
    let cleared = request(
        &mut client,
        "profile-clear",
        "accounts.setProfile",
        json!({
            "accountId": account_id,
            "givenName": "Li",
            "familyName": "",
            "avatar": null
        }),
    )
    .await;
    assert_eq!(cleared["result"]["status"], "saved");
    let profile_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("givenName").is_some())
        .collect();
    assert_eq!(profile_calls.len(), 2);
    assert_eq!(profile_calls[1]["familyName"], "");
    assert!(
        profile_calls[1].get("avatar").is_some_and(Value::is_null),
        "explicit null forwards a present avatar:null key, not a dropped key"
    );

    // Keep face: a profile call without the avatar key forwards no avatar
    // key — absence and explicit null are distinct wire states (1.90 pin;
    // the 1.46 Option<Value> shape folded null into absence, so this line
    // never had a real witness before).
    let kept = request(
        &mut client,
        "profile-keep",
        "accounts.setProfile",
        json!({
            "accountId": account_id,
            "givenName": "Li"
        }),
    )
    .await;
    assert_eq!(kept["result"]["status"], "saved");
    let profile_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("givenName").is_some())
        .collect();
    assert_eq!(profile_calls.len(), 3);
    assert!(profile_calls[2].get("avatar").is_none());

    // Profile fail-closed ladder: empty/over-bound text, non-image avatar,
    // non-canonical payload, over-budget decode, non-string avatar.
    let oversized_name = "A".repeat(129);
    let oversized_about = "A".repeat(513);
    let oversized_avatar = format!(
        "data:image/png;base64,{}",
        "QUJD".repeat(10 * 1024 * 1024 / 3 + 1)
    );
    for (request_id, params) in [
        (
            "profile-empty-name",
            json!({ "accountId": account_id, "givenName": "" }),
        ),
        (
            "profile-long-name",
            json!({ "accountId": account_id, "givenName": oversized_name }),
        ),
        (
            "profile-long-about",
            json!({ "accountId": account_id, "givenName": "Li", "about": oversized_about }),
        ),
        (
            "profile-non-image",
            json!({
                "accountId": account_id,
                "givenName": "Li",
                "avatar": "data:text/html;base64,YQ=="
            }),
        ),
        (
            "profile-non-canonical",
            json!({
                "accountId": account_id,
                "givenName": "Li",
                "avatar": "data:image/png;base64,YQ"
            }),
        ),
        (
            "profile-over-budget",
            json!({ "accountId": account_id, "givenName": "Li", "avatar": oversized_avatar }),
        ),
        (
            "profile-non-string-avatar",
            json!({ "accountId": account_id, "givenName": "Li", "avatar": 7 }),
        ),
    ] {
        let rejected = request(&mut client, request_id, "accounts.setProfile", params).await;
        assert_eq!(
            rejected["error"]["code"], "INVALID_REQUEST",
            "{request_id}: {rejected}"
        );
    }

    // STORAGE_* passthrough: the profile face's about sentinels surface the
    // engine's structured codes verbatim, retryable.
    for (request_id, sentinel, expected) in [
        (
            "profile-storage-unavailable",
            "[fixture-storage-unavailable]",
            "STORAGE_UNAVAILABLE",
        ),
        (
            "profile-storage-read-failed",
            "[fixture-storage-read-failed]",
            "STORAGE_READ_FAILED",
        ),
        (
            "profile-storage-write-failed",
            "[fixture-storage-write-failed]",
            "STORAGE_WRITE_FAILED",
        ),
    ] {
        let error = request(
            &mut client,
            request_id,
            "accounts.setProfile",
            json!({
                "accountId": account_id,
                "givenName": "Li",
                "about": sentinel
            }),
        )
        .await;
        assert_eq!(error["error"]["code"], expected, "{request_id}: {error}");
        assert_eq!(error["error"]["retryable"], true, "{request_id}: {error}");
    }

    // Universal timer: the engine-face key forwards; 0 is the legal off value.
    for (request_id, seconds) in [("timer-set", 86400), ("timer-off", 0)] {
        let timer = request(
            &mut client,
            request_id,
            "accounts.setExpireTimer",
            json!({ "accountId": account_id, "expireSeconds": seconds }),
        )
        .await;
        assert_eq!(timer["result"]["status"], "saved", "{request_id}");
    }
    let timer_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("expirationInSeconds").is_some())
        .collect();
    assert_eq!(timer_calls.len(), 2, "{timer_calls:?}");
    assert_eq!(timer_calls[0]["account"], "+15555550100");
    assert_eq!(timer_calls[0]["expirationInSeconds"], 86400);
    assert_eq!(timer_calls[1]["expirationInSeconds"], 0);

    // Timer fail-closed ladder: negative, fractional, beyond the u32 face.
    for (request_id, params) in [
        (
            "timer-negative",
            json!({ "accountId": account_id, "expireSeconds": -1 }),
        ),
        (
            "timer-fractional",
            json!({ "accountId": account_id, "expireSeconds": 1.5 }),
        ),
        (
            "timer-over-u32",
            json!({ "accountId": account_id, "expireSeconds": 4294967296u64 }),
        ),
    ] {
        let rejected = request(&mut client, request_id, "accounts.setExpireTimer", params).await;
        assert_eq!(
            rejected["error"]["code"], "INVALID_REQUEST",
            "{request_id}: {rejected}"
        );
    }

    // Crash with the mutating profile write in flight (givenName sentinel,
    // os._exit(31)): SEND_OUTCOME_UNKNOWN, never retried.
    let crash = request(
        &mut client,
        "profile-crash",
        "accounts.setProfile",
        json!({
            "accountId": account_id,
            "givenName": "[fixture-crash-profile]"
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-profile", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let profile_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(profile_pid, engine_pid, "the engine actually restarted");
    engine_pid = profile_pid;

    // Same discipline on the timer face: the max legal u32 value is the
    // crash magic (os._exit(31), a value the per-conversation int face
    // cannot carry).
    let timer_crash = request(
        &mut client,
        "timer-crash",
        "accounts.setExpireTimer",
        json!({ "accountId": account_id, "expireSeconds": 4294967295u32 }),
    )
    .await;
    assert_eq!(timer_crash["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-timer", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;

    // No-retry audit: exactly one crashing profile call and one crashing
    // timer call across both restarts.
    let log = send_log();
    assert_eq!(
        log.iter()
            .filter(|params| params["givenName"] == "[fixture-crash-profile]")
            .count(),
        1,
        "an unknown profile outcome is never retried"
    );
    assert_eq!(
        log.iter()
            .filter(|params| params["expirationInSeconds"] == 4294967295u64)
            .count(),
        1,
        "an unknown timer outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.100 (§4.81 D5): the accounts.deviceCapabilities read
/// face — the idempotent engine registration rides the resolved account, the
/// host answer strips the engine's bare `account` identity (a bare identity
/// never crosses the connector), the capability bits ride verbatim, and the
/// ladder answers the deterministic failures.
#[tokio::test]
async fn device_capabilities_strips_the_bare_identity() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [43_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-DeviceCapabilities" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");

    let capabilities = request(
        &mut client,
        "device-capabilities",
        "accounts.deviceCapabilities",
        json!({ "accountId": account_id }),
    )
    .await;
    let result = &capabilities["result"];
    assert_eq!(result["registered"], true);
    // The pinned upload bits ride verbatim — the connector invents no keys
    // and strips none.
    assert_eq!(result["capabilities"]["attachmentBackfill"], false);
    assert_eq!(result["capabilities"]["spqr"], true);
    assert_eq!(result["capabilities"]["usernameChangeSyncMessage"], true);
    assert_eq!(result["capabilities"]["optionalPhoneNumber"], false);
    // The engine's bare `account` identity never crosses the connector.
    assert!(result.get("account").is_none(), "{result}");

    // The upstream frame carried the resolved account number (the fixture's
    // dispatch log, the getUsername read-face discipline) — exactly the
    // single-key frame the prepare face projects.
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| **frame == json!({ "account": "+15555550100" }))
            .count(),
        1,
        "expected exactly one resolved-account frame: {frames:?}"
    );

    // The deterministic ladder: unknown account, malformed params.
    let missing = request(
        &mut client,
        "capabilities-missing-account",
        "accounts.deviceCapabilities",
        json!({ "accountId": "no-such-account" }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");
    let malformed = request(
        &mut client,
        "capabilities-malformed",
        "accounts.deviceCapabilities",
        json!({}),
    )
    .await;
    assert_eq!(malformed["error"]["code"], "INVALID_REQUEST");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.122 (§4.103): the device-plane faces — accounts.getDevices
/// (the resolved account rides upstream; the bounded projection drops the
/// ghost string-deviceId entry, keeps the nameless primary and the
/// absent-optional-keys linked device) and accounts.unlinkDevice (the write
/// round-trip with the exact upstream frame, the DEVICES_FAILED data.status
/// pass-through, the local deviceId=0 refusal, and the crash-in-flight
/// unknown outcome that is never retried).
#[tokio::test]
async fn device_plane_faces_read_and_unlink() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [44_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-DevicePlane" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let frames = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    };

    // The read face: two real entries project (the ghost string-deviceId
    // entry drops), the nameless primary answers no `name` key (the honest
    // no-name face), the linked device's absent optionals stay absent.
    let devices = request(
        &mut client,
        "get-devices",
        "accounts.getDevices",
        json!({ "accountId": account_id }),
    )
    .await;
    let list = devices["result"]["devices"].as_array().unwrap();
    assert_eq!(list.len(), 2, "{devices}");
    assert_eq!(list[0]["deviceId"], 1);
    assert!(
        list[0].get("name").is_none(),
        "an undecryptable/absent device name projects no key: {}",
        list[0]
    );
    assert_eq!(list[0]["registrationId"], 111);
    assert_eq!(list[0]["lastSeenMs"], 1728000000000u64);
    assert_eq!(list[0]["createdAtCiphertext"], "Zml4dHVyZS1jcmVk");
    assert_eq!(list[1]["deviceId"], 2);
    assert_eq!(list[1]["name"], "KT-Desktop");
    assert!(list[1].get("registrationId").is_none());
    assert!(list[1].get("lastSeenMs").is_none());
    // The upstream frame carried exactly the resolved account key.
    assert_eq!(
        frames()
            .iter()
            .filter(|frame| **frame == json!({ "account": "+15555550100" }))
            .count(),
        1,
        "expected exactly one resolved-account read frame"
    );

    // The write round-trip: the definite success answers {status: unlinked}
    // and the upstream frame carried the resolved account and the deviceId.
    let unlink = request(
        &mut client,
        "unlink-2",
        "accounts.unlinkDevice",
        json!({ "accountId": account_id, "deviceId": 2 }),
    )
    .await;
    assert_eq!(unlink["result"]["status"], "unlinked", "{unlink}");
    assert!(
        frames()
            .iter()
            .any(|frame| { *frame == json!({ "account": "+15555550100", "deviceId": 2 }) }),
        "expected the unlink upstream frame: {:#?}",
        frames()
    );

    // The server-rejection family rides the engine's data.status verbatim,
    // deterministic (retryable=false).
    let refused = request(
        &mut client,
        "unlink-refused",
        "accounts.unlinkDevice",
        json!({ "accountId": account_id, "deviceId": 4294967295u32 }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "DEVICES_FAILED", "{refused}");
    assert_eq!(refused["error"]["retryable"], false);
    assert_eq!(refused["error"]["data"]["status"], 409);

    // The local ladder: deviceId 0 refuses INVALID_REQUEST before any
    // upstream call (no frame), malformed params refuse at the shape gate.
    let zero = request(
        &mut client,
        "unlink-zero",
        "accounts.unlinkDevice",
        json!({ "accountId": account_id, "deviceId": 0 }),
    )
    .await;
    assert_eq!(zero["error"]["code"], "INVALID_REQUEST", "{zero}");
    let malformed = request(
        &mut client,
        "unlink-malformed",
        "accounts.unlinkDevice",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(malformed["error"]["code"], "INVALID_REQUEST");
    let missing = request(
        &mut client,
        "unlink-missing-account",
        "accounts.unlinkDevice",
        json!({ "accountId": "no-such-account", "deviceId": 2 }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");

    // The red line: a crash with the mutating call in flight answers
    // SEND_OUTCOME_UNKNOWN and is never retried — exactly one crashing frame
    // across the restart.
    let crash = request(
        &mut client,
        "unlink-crash",
        "accounts.unlinkDevice",
        json!({ "accountId": account_id, "deviceId": 4294967294u32 }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-unlink", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_eq!(
        frames()
            .iter()
            .filter(|frame| frame["deviceId"] == 4294967294u64)
            .count(),
        1,
        "an unknown unlink outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.123 (§4.104): the groups.migrate face — the GV1→GV2
/// migration upstream leg. The round-trip carries the resolved account, the
/// legacy base64 groupId, and the roster upstream, and answers the engine's
/// {groupId, revision} verbatim; the local ladder refuses the malformed
/// legacy id, the empty roster, and the over-bounds roster before any
/// upstream call; the server-rejection family rides GROUP_MIGRATION_FAILED
/// with data.status verbatim; the crash-in-flight outcome answers
/// SEND_OUTCOME_UNKNOWN and is never retried.
#[tokio::test]
async fn group_migration_round_trips_and_gates_the_shape() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [45_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupMigrate" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let legacy_id = "MTIzNDU2Nzg5MGFiY2RlZg==";

    // The round-trip: the definite success projects {groupId, revision} and
    // the upstream frame carries the change set (optional keys omitted stay
    // absent upstream).
    let migrated = request(
        &mut client,
        "migrate",
        "groups.migrate",
        json!({ "accountId": account_id, "groupId": legacy_id, "members": ["+15555550101"] }),
    )
    .await;
    assert_eq!(
        migrated["result"]["groupId"], "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
        "{migrated}"
    );
    assert_eq!(migrated["result"]["revision"], 0);
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert!(
        frames.iter().any(|frame| {
            frame["account"] == "+15555550100"
                && frame["groupId"] == legacy_id
                && frame["members"] == json!(["+15555550101"])
                && frame.get("title").is_none()
        }),
        "expected the migration upstream frame: {frames:?}"
    );

    // The optional change set rides when present.
    let titled = request(
        &mut client,
        "migrate-titled",
        "groups.migrate",
        json!({
            "accountId": account_id,
            "groupId": legacy_id,
            "title": "Migrated",
            "expiration": 86400,
            "members": ["+15555550101"]
        }),
    )
    .await;
    assert_eq!(titled["result"]["revision"], 0);
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert!(
        frames
            .iter()
            .any(|frame| { frame["title"] == "Migrated" && frame["expiration"] == 86400 }),
        "expected the titled migration frame: {frames:?}"
    );

    // The server-rejection family rides GROUP_MIGRATION_FAILED with the
    // engine's data.status verbatim, deterministic.
    let refused = request(
        &mut client,
        "migrate-refused",
        "groups.migrate",
        json!({
            "accountId": account_id,
            "groupId": "Zml4dHVyZS1taWdyYXRpb24tZmFpbA==",
            "members": ["+15555550101"]
        }),
    )
    .await;
    assert_eq!(
        refused["error"]["code"], "GROUP_MIGRATION_FAILED",
        "{refused}"
    );
    assert_eq!(refused["error"]["retryable"], false);
    assert_eq!(refused["error"]["data"]["status"], 409);

    // The local ladder: the malformed legacy id, the empty roster, and the
    // over-bounds roster refuse before any upstream call; unknown account.
    let bad_id = request(
        &mut client,
        "migrate-bad-id",
        "groups.migrate",
        json!({ "accountId": account_id, "groupId": "not base64!!", "members": ["+15555550101"] }),
    )
    .await;
    assert_eq!(bad_id["error"]["code"], "INVALID_REQUEST", "{bad_id}");
    let empty_roster = request(
        &mut client,
        "migrate-empty-roster",
        "groups.migrate",
        json!({ "accountId": account_id, "groupId": legacy_id, "members": [] }),
    )
    .await;
    assert_eq!(empty_roster["error"]["code"], "INVALID_REQUEST");
    let over_roster = request(
        &mut client,
        "migrate-over-roster",
        "groups.migrate",
        json!({
            "accountId": account_id,
            "groupId": legacy_id,
            "members": vec!["+15555550101"; 1002]
        }),
    )
    .await;
    assert_eq!(over_roster["error"]["code"], "INVALID_REQUEST");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["groupId"] == "not base64!!")
            .count(),
        0,
        "a malformed id never reaches the engine"
    );
    let missing = request(
        &mut client,
        "migrate-missing-account",
        "groups.migrate",
        json!({ "accountId": "no-such-account", "groupId": legacy_id, "members": ["+15555550101"] }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");

    // The red line: a crash with the mutating call in flight answers
    // SEND_OUTCOME_UNKNOWN and is never retried — exactly one crashing frame
    // across the restart.
    let crash = request(
        &mut client,
        "migrate-crash",
        "groups.migrate",
        json!({
            "accountId": account_id,
            "groupId": legacy_id,
            "title": "[fixture-crash-migrate]",
            "members": ["+15555550101"]
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-migrate", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["title"] == "[fixture-crash-migrate]")
            .count(),
        1,
        "an unknown migration outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.126 (§4.107): the groups.create face — the new-group
/// upstream leg. The round-trip carries the resolved account and title (the
/// optional change set rides when present, absent keys stay absent), and
/// answers the engine's {groupId, revision} verbatim; the local ladder
/// refuses the empty title, the over-bounds title, the explicit empty
/// roster, and the over-bounds roster before any upstream call; the
/// server-rejection family rides GROUP_CREATE_FAILED with data.status
/// verbatim; the crash-in-flight outcome answers SEND_OUTCOME_UNKNOWN and
/// is never retried.
#[tokio::test]
async fn group_create_round_trips_and_gates_the_shape() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [45_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupCreate" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");

    // The round-trip: the definite success projects {groupId, revision} and
    // the upstream frame carries the title plus the optional roster (the
    // engine derives the new group master key).
    let created = request(
        &mut client,
        "create",
        "groups.create",
        json!({ "accountId": account_id, "title": "kt group", "members": ["+15555550101"] }),
    )
    .await;
    assert_eq!(
        created["result"]["groupId"], "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
        "{created}"
    );
    assert_eq!(created["result"]["revision"], 0);
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert!(
        frames.iter().any(|frame| {
            frame["account"] == "+15555550100"
                && frame["title"] == "kt group"
                && frame["members"] == json!(["+15555550101"])
                && frame.get("expiration").is_none()
                && frame.get("avatar").is_none()
        }),
        "expected the create upstream frame: {frames:?}"
    );

    // The bare create: no roster, no change set — the frame carries the
    // title alone (the absent keys stay absent upstream).
    let bare = request(
        &mut client,
        "create-bare",
        "groups.create",
        json!({ "accountId": account_id, "title": "bare group" }),
    )
    .await;
    assert_eq!(bare["result"]["revision"], 0);
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert!(
        frames
            .iter()
            .any(|frame| frame["title"] == "bare group" && frame.get("members").is_none()),
        "expected the bare create frame: {frames:?}"
    );

    // The server-rejection family rides GROUP_CREATE_FAILED with the
    // engine's data.status verbatim, deterministic.
    let refused = request(
        &mut client,
        "create-refused",
        "groups.create",
        json!({ "accountId": account_id, "title": "[fixture-reject-create]" }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "GROUP_CREATE_FAILED", "{refused}");
    assert_eq!(refused["error"]["retryable"], false);
    assert_eq!(refused["error"]["data"]["status"], 400);

    // The local ladder: the empty title, the over-bounds title, the
    // explicit empty roster, and the over-bounds roster refuse before any
    // upstream call; unknown account.
    let empty_title = request(
        &mut client,
        "create-empty-title",
        "groups.create",
        json!({ "accountId": account_id, "title": "" }),
    )
    .await;
    assert_eq!(empty_title["error"]["code"], "INVALID_REQUEST");
    let over_title = request(
        &mut client,
        "create-over-title",
        "groups.create",
        json!({ "accountId": account_id, "title": "x".repeat(257) }),
    )
    .await;
    assert_eq!(over_title["error"]["code"], "INVALID_REQUEST");
    let empty_roster = request(
        &mut client,
        "create-empty-roster",
        "groups.create",
        json!({ "accountId": account_id, "title": "kt group", "members": [] }),
    )
    .await;
    assert_eq!(empty_roster["error"]["code"], "INVALID_REQUEST");
    let over_roster = request(
        &mut client,
        "create-over-roster",
        "groups.create",
        json!({
            "accountId": account_id,
            "title": "kt group",
            "members": vec!["+15555550101"; 1002]
        }),
    )
    .await;
    assert_eq!(over_roster["error"]["code"], "INVALID_REQUEST");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames.iter().filter(|frame| frame["title"] == "").count(),
        0,
        "an empty title never reaches the engine"
    );
    let missing = request(
        &mut client,
        "create-missing-account",
        "groups.create",
        json!({ "accountId": "no-such-account", "title": "kt group" }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");

    // The red line: a crash with the mutating call in flight answers
    // SEND_OUTCOME_UNKNOWN and is never retried — exactly one crashing frame
    // across the restart.
    let crash = request(
        &mut client,
        "create-crash",
        "groups.create",
        json!({ "accountId": account_id, "title": "[fixture-crash-create]" }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-create", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["title"] == "[fixture-crash-create]")
            .count(),
        1,
        "an unknown create outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.124 (§4.105): the messages.sendContact face — the
/// contact-card send. The direct leg resolves the row's peer reference into
/// the engine's recipient addressing and the group leg the groupId
/// addressing (the calls.sendSignal precedent); the {sentAt} ack echoes the
/// engine's send timestamp; the card rides the local fail-closed ladder (the
/// all-empty card, the out-of-vocabulary type word, the postal MOBILE, the
/// over-bounds scalar, the over-entries array, and the malformed avatar data
/// URI refuse before any upstream call); the empty-string organization
/// drops from the upstream frame; the crash-in-flight outcome answers
/// SEND_OUTCOME_UNKNOWN and is never retried.
#[tokio::test]
async fn contact_send_round_trips_both_legs_and_gates_the_card() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [46_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-ContactSend" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let avatar_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==";

    // The direct leg: a fresh peer send mints the row; the card routes the
    // engine's recipient face and answers the {sentAt} ack. The avatar
    // rides the data URI upstream and is digest-summarized in the dispatch
    // log; the empty-string organization is the official falsy-absent and
    // drops from the frame.
    let seeded = request(
        &mut client,
        "seed-direct",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550103",
            "peerTitle": "Contact Target",
            "text": "seed the row",
            "clientRequestId": "contact-seed-1"
        }),
    )
    .await;
    let direct_conversation = seeded["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let direct = request(
        &mut client,
        "contact-direct",
        "messages.sendContact",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "contact": {
                "name": { "givenName": "Ada", "familyName": "Lovelace" },
                "number": [{ "value": "+15551230000", "type": "MOBILE", "label": "cell" }],
                "email": [{ "value": "ada@example.test", "type": "WORK" }],
                "address": [{ "type": "HOME", "city": "London" }],
                "organization": "",
                "avatar": avatar_uri
            }
        }),
    )
    .await;
    assert_eq!(direct["result"]["sentAt"], 1727000000000_u64, "{direct}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert_eq!(frame["account"], "+15555550100");
    assert_eq!(frame["recipient"], "+15555550103");
    assert!(frame.get("groupId").is_none(), "{frame}");
    assert_eq!(frame["contact"]["name"]["givenName"], "Ada");
    assert_eq!(frame["contact"]["number"][0]["type"], "MOBILE");
    assert_eq!(frame["contact"]["email"][0]["value"], "ada@example.test");
    assert_eq!(frame["contact"]["address"][0]["city"], "London");
    assert_eq!(
        frame["contact"]["avatar"],
        json!(format!("[avatar data uri: {} bytes]", avatar_uri.len()))
    );
    assert!(
        frame["contact"].get("organization").is_none(),
        "the empty-string organization is the official falsy-absent: {frame}"
    );

    // The group leg: the fixture links with one group conversation in
    // place; the card routes the groupId addressing, the optional type
    // stays absent upstream.
    let listed = request(
        &mut client,
        "list-for-group",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with a group conversation");
    let group = request(
        &mut client,
        "contact-group",
        "messages.sendContact",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "contact": {
                "name": { "givenName": "Grace" },
                "number": [{ "value": "+15551230001" }]
            }
        }),
    )
    .await;
    assert_eq!(group["result"]["sentAt"], 1727000000000_u64, "{group}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert_eq!(frame["account"], "+15555550100");
    assert_eq!(frame["groupId"], "ZmFrZS1ncm91cC0x");
    assert!(frame.get("recipient").is_none(), "{frame}");
    assert_eq!(frame["contact"]["name"]["givenName"], "Grace");
    assert!(
        frame["contact"]["number"][0].get("type").is_none(),
        "the optional type stays absent upstream: {frame}"
    );

    // The local ladder refuses before any upstream call: the all-empty
    // card (and its all-falsy twin), the out-of-vocabulary type word, the
    // postal MOBILE, the over-bounds scalar, the over-entries array, and
    // the malformed avatar data URI.
    let frames_before = fs::read_to_string(&send_log_path).unwrap().lines().count();
    let many: Vec<Value> = (0..65).map(|_| json!({ "value": "+1" })).collect();
    let ladder: Vec<(&str, Value)> = vec![
        ("empty-card", json!({})),
        ("falsy-card", json!({ "organization": "" })),
        (
            "bad-type",
            json!({ "number": [{ "value": "+1", "type": "CELL" }] }),
        ),
        (
            "postal-mobile",
            json!({ "address": [{ "type": "MOBILE", "city": "x" }] }),
        ),
        (
            "long-value",
            json!({ "number": [{ "value": "x".repeat(129) }] }),
        ),
        ("many-entries", json!({ "number": many })),
        ("bad-avatar", json!({ "avatar": "not-a-data-uri" })),
    ];
    for (id, contact) in ladder {
        let refused = request(
            &mut client,
            id,
            "messages.sendContact",
            json!({
                "accountId": account_id,
                "conversationId": direct_conversation,
                "contact": contact
            }),
        )
        .await;
        assert_eq!(
            refused["error"]["code"], "INVALID_REQUEST",
            "{id}: {refused}"
        );
    }
    let frames_after = fs::read_to_string(&send_log_path).unwrap().lines().count();
    assert_eq!(
        frames_before, frames_after,
        "a refused card never reaches the engine"
    );

    // Unknown account.
    let missing = request(
        &mut client,
        "contact-missing-account",
        "messages.sendContact",
        json!({
            "accountId": "no-such-account",
            "conversationId": direct_conversation,
            "contact": { "name": { "givenName": "Ada" } }
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");

    // The red line: a crash with the mutating call in flight answers
    // SEND_OUTCOME_UNKNOWN and is never retried — exactly one crashing
    // frame across the restart.
    let crash = request(
        &mut client,
        "contact-crash",
        "messages.sendContact",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "contact": { "organization": "[fixture-crash-contact]" }
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    assert_eq!(crash["error"]["retryable"], false);
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-contact", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["contact"]["organization"] == "[fixture-crash-contact]")
            .count(),
        1,
        "an unknown contact-send outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.125 (§4.106): the poll send faces — the three
/// group-only routes (create/vote/terminate). The round-trips carry the
/// resolved account and the group's peer key upstream and answer the
/// remoteDelete status discipline ({"status":"sent"} definite, the explicit
/// {"status":"unknown"} indeterminate); the local ladder (the content
/// bounds, the selection domain, the zero target, and the direct
/// conversation refusal) refuses before any upstream call; the
/// crash-in-flight outcome answers {"status":"unknown"} and is never
/// retried.
#[tokio::test]
async fn poll_send_faces_round_trip_and_gate_the_shape() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [47_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-PollSend" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");

    // The fixture links with one group conversation in place.
    let listed = request(
        &mut client,
        "list-for-group",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with a group conversation");

    // The create round-trip: the definite success answers {"status":"sent"}
    // and the upstream frame carries the resolved account, the group peer
    // key, and the content; allowMultiple rides when present, stays absent
    // when not.
    let created = request(
        &mut client,
        "poll-create",
        "messages.sendPollCreate",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "question": "Lunch?",
            "options": ["Ramen", "Tacos"],
            "allowMultiple": true
        }),
    )
    .await;
    assert_eq!(created["result"]["status"], "sent", "{created}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert_eq!(frame["account"], "+15555550100");
    assert_eq!(frame["groupId"], "ZmFrZS1ncm91cC0x");
    assert_eq!(frame["question"], "Lunch?");
    assert_eq!(frame["options"], json!(["Ramen", "Tacos"]));
    assert_eq!(frame["allowMultiple"], true);
    let created = request(
        &mut client,
        "poll-create-single",
        "messages.sendPollCreate",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "question": "Lunch?",
            "options": ["Ramen", "Tacos"]
        }),
    )
    .await;
    assert_eq!(created["result"]["status"], "sent", "{created}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert!(
        frame.get("allowMultiple").is_none(),
        "the absent default stays absent upstream: {frame}"
    );

    // The vote round-trip: the anchor + selection ride verbatim; the empty
    // selection is the legal clear-vote and answers the same sent.
    let voted = request(
        &mut client,
        "poll-vote",
        "messages.sendPollVote",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "targetAuthor": "+15555550101",
            "targetTimestamp": 1727000000000_u64,
            "optionIndexes": [0, 1],
            "voteCount": 2
        }),
    )
    .await;
    assert_eq!(voted["result"]["status"], "sent", "{voted}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert_eq!(frame["targetAuthor"], "+15555550101");
    assert_eq!(frame["targetTimestamp"], 1727000000000_u64);
    assert_eq!(frame["optionIndexes"], json!([0, 1]));
    assert_eq!(frame["voteCount"], 2);
    let cleared = request(
        &mut client,
        "poll-vote-clear",
        "messages.sendPollVote",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "targetAuthor": "+15555550101",
            "targetTimestamp": 1727000000000_u64,
            "optionIndexes": []
        }),
    )
    .await;
    assert_eq!(cleared["result"]["status"], "sent", "{cleared}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert_eq!(frame["optionIndexes"], json!([]));
    assert!(frame.get("voteCount").is_none(), "{frame}");

    // The terminate round-trip.
    let terminated = request(
        &mut client,
        "poll-terminate",
        "messages.sendPollTerminate",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "targetTimestamp": 1727000000000_u64
        }),
    )
    .await;
    assert_eq!(terminated["result"]["status"], "sent", "{terminated}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let frame = frames.last().unwrap();
    assert_eq!(frame["targetTimestamp"], 1727000000000_u64);

    // The local ladder refuses before any upstream call: the over-bounds
    // question, the single option, the out-of-domain index, the zero
    // target, and the direct-conversation refusal (polls are
    // group-conversation faces exclusively).
    let seeded = request(
        &mut client,
        "seed-direct",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550103",
            "peerTitle": "Poll Refusal",
            "text": "seed the row",
            "clientRequestId": "poll-seed-1"
        }),
    )
    .await;
    let direct_conversation = seeded["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let frames_before = fs::read_to_string(&send_log_path).unwrap().lines().count();
    let long_question = "x".repeat(201);
    let ladder: Vec<(&str, &str, Value)> = vec![
        (
            "long-question",
            "messages.sendPollCreate",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation,
                "question": long_question,
                "options": ["A", "B"]
            }),
        ),
        (
            "one-option",
            "messages.sendPollCreate",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation,
                "question": "Q",
                "options": ["A"]
            }),
        ),
        (
            "bad-index",
            "messages.sendPollVote",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation,
                "targetAuthor": "+15555550101",
                "targetTimestamp": 1727000000000_u64,
                "optionIndexes": [10]
            }),
        ),
        (
            "zero-target",
            "messages.sendPollTerminate",
            json!({
                "accountId": account_id,
                "conversationId": group_conversation,
                "targetTimestamp": 0
            }),
        ),
        (
            "direct-refusal",
            "messages.sendPollCreate",
            json!({
                "accountId": account_id,
                "conversationId": direct_conversation,
                "question": "Q",
                "options": ["A", "B"]
            }),
        ),
    ];
    for (id, method, params) in ladder {
        let refused = request(&mut client, id, method, params).await;
        assert_eq!(
            refused["error"]["code"], "INVALID_REQUEST",
            "{id}: {refused}"
        );
    }
    let frames_after = fs::read_to_string(&send_log_path).unwrap().lines().count();
    assert_eq!(
        frames_before, frames_after,
        "a refused poll never reaches the engine"
    );

    // Unknown account.
    let missing = request(
        &mut client,
        "poll-missing-account",
        "messages.sendPollCreate",
        json!({
            "accountId": "no-such-account",
            "conversationId": group_conversation,
            "question": "Q",
            "options": ["A", "B"]
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");

    // The red line: a crash with the mutating call in flight answers the
    // explicit {"status":"unknown"} and is never retried — exactly one
    // crashing frame across the restart.
    let crash = request(
        &mut client,
        "poll-crash",
        "messages.sendPollCreate",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "question": "[fixture-crash-poll]",
            "options": ["A", "B"]
        }),
    )
    .await;
    assert_eq!(crash["result"]["status"], "unknown", "{crash}");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-poll", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["question"] == "[fixture-crash-poll]")
            .count(),
        1,
        "an unknown poll-create outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.68: the §4.61 safety-number faces — identities.get
/// (the pinned listIdentities read narrowed to the resolved peer reference,
/// the honest empty-list no-identity face) and identities.verify (the pinned
/// trust verifiedSafetyNumber write with the exact upstream params on the
/// dispatch log, the digits-mismatch UserError folding to the plain upstream
/// family, and the 1:1 fail-closed ladder).
#[tokio::test]
async fn safety_number_faces_round_trip_and_gate_the_shape() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [44_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-SafetyNumber" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let send_log = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    };

    // Address a fresh direct conversation (the established sendText ladder);
    // the fixture identity's peer is the same number the contacts sync
    // materialized.
    let sent = request(
        &mut client,
        "send-peer",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550103",
            "peerTitle": "Safety Peer",
            "text": "open the safety number face",
            "clientRequestId": "safety-peer-send"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Read: the pinned JsonIdentity record projects verbatim.
    let identity = request(
        &mut client,
        "identity-get",
        "identities.get",
        json!({ "accountId": account_id, "conversationId": conversation_id }),
    )
    .await;
    let row = &identity["result"]["identity"];
    assert_eq!(row["number"], "+15555550103");
    assert_eq!(row["uuid"], "99999999-9999-9999-9999-999999999999");
    assert_eq!(row["trustLevel"], "TRUSTED_UNVERIFIED");
    assert_eq!(
        row["safetyNumber"],
        "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
    );
    assert_eq!(row["scannableSafetyNumber"], "AQIDBAUGBwgJCgsMDQ4PEA==");
    assert_eq!(row["addedTimestamp"], 1727000000000_u64);

    // Read dispatch shape: the connector narrowed the pinned read to the
    // resolved peer reference (read faces are not dispatch-recorded, so the
    // params shape is integration-proven on the verify write below and the
    // projection above).

    // Verify write: the echoed digits ride `recipient` + `verifiedSafetyNumber`.
    let verified = request(
        &mut client,
        "identity-verify",
        "identities.verify",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "safetyNumber": "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
        }),
    )
    .await;
    assert_eq!(
        verified["result"]["status"], "verified",
        "the verified arm answers: {verified:?}"
    );
    let trust_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("verifiedSafetyNumber").is_some())
        .collect();
    assert_eq!(trust_calls.len(), 1, "{trust_calls:?}");
    assert_eq!(trust_calls[0]["account"], "+15555550100");
    assert_eq!(trust_calls[0]["recipient"], "+15555550103");
    assert!(trust_calls[0].get("trustAllKnownKeys").is_none());

    // Digits mismatch: the upstream's definite UserError folds into the
    // plain upstream family (no per-failure ladder to honest-map), and the
    // failed write is not retried.
    let mismatch = request(
        &mut client,
        "identity-verify-mismatch",
        "identities.verify",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "safetyNumber": "99999 99999"
        }),
    )
    .await;
    assert_eq!(mismatch["error"]["code"], "UPSTREAM_ERROR");
    assert_eq!(
        send_log()
            .into_iter()
            .filter(|params| params.get("verifiedSafetyNumber").is_some())
            .count(),
        2,
        "a definite trust failure is never retried"
    );

    // 契约 §4.223 信任重置臂（官方 sendAnyway）：state="default" 无比对闸，
    // engine trust 帧只带 recipient + state——数字串一个键也不上 wire；成功
    // 面与 verified 臂同形（{status:"verified"}），本地写穿 DEFAULT 投影
    // （TRUSTED_UNVERIFIED，绝不冒充 verified）。
    let trust_reset = request(
        &mut client,
        "identity-trust-reset",
        "identities.verify",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "state": "default"
        }),
    )
    .await;
    assert_eq!(
        trust_reset["result"]["status"], "verified",
        "the trust-reset arm answers: {trust_reset:?}"
    );
    let reset_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("state").is_some())
        .collect();
    assert_eq!(reset_calls.len(), 1, "{reset_calls:?}");
    assert_eq!(reset_calls[0]["account"], "+15555550100");
    assert_eq!(reset_calls[0]["recipient"], "+15555550103");
    assert_eq!(reset_calls[0]["state"], "default");
    assert!(reset_calls[0].get("verifiedSafetyNumber").is_none());
    assert!(reset_calls[0].get("trustAllKnownKeys").is_none());

    // The 1:1 gate: a group conversation fails closed before any upstream
    // call, on both faces.
    let group_sent = request(
        &mut client,
        "group-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "group",
            "peerKey": "ZmFrZS1ncm91cC0x",
            "peerTitle": "Safety Group",
            "text": "group face",
            "clientRequestId": "safety-group-send"
        }),
    )
    .await;
    let group_conversation_id = group_sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let group_read = request(
        &mut client,
        "identity-group-read",
        "identities.get",
        json!({ "accountId": account_id, "conversationId": group_conversation_id }),
    )
    .await;
    assert_eq!(group_read["error"]["code"], "INVALID_REQUEST");
    let group_verify = request(
        &mut client,
        "identity-group-verify",
        "identities.verify",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "safetyNumber": "12345 67890"
        }),
    )
    .await;
    assert_eq!(group_verify["error"]["code"], "INVALID_REQUEST");

    // Params-shape ladder: missing fields, an over-bound safety number, an
    // unknown key.
    for (request_id, method, params) in [
        (
            "identity-missing-conversation",
            "identities.get",
            json!({ "accountId": account_id }),
        ),
        (
            "verify-missing-digits",
            "identities.verify",
            json!({ "accountId": account_id, "conversationId": conversation_id }),
        ),
        (
            "verify-over-bound-digits",
            "identities.verify",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "safetyNumber": "1".repeat(257)
            }),
        ),
        (
            "verify-unknown-key",
            "identities.verify",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "safetyNumber": "12345 67890",
                "trustAllKnownKeys": true
            }),
        ),
        // 契约 §4.223 两臂恰一：同置与词表外 state 是 fail-closed 面（双缺
        // 已在 verify-missing-digits 覆盖）。
        (
            "verify-both-arms",
            "identities.verify",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "safetyNumber": "12345 67890",
                "state": "default"
            }),
        ),
        (
            "verify-unverified-word",
            "identities.verify",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "state": "unverified"
            }),
        ),
    ] {
        let rejected = request(&mut client, request_id, method, params).await;
        assert_eq!(
            rejected["error"]["code"], "INVALID_REQUEST",
            "{request_id}: {rejected:?}"
        );
    }

    // Unknown conversation answers CONVERSATION_NOT_FOUND (resolution before
    // any upstream call) on both faces.
    let unknown_conversation = request(
        &mut client,
        "identity-unknown-conversation",
        "identities.get",
        json!({ "accountId": account_id, "conversationId": "no-such-conversation" }),
    )
    .await;
    assert_eq!(
        unknown_conversation["error"]["code"],
        "CONVERSATION_NOT_FOUND"
    );
    let unknown_conversation = request(
        &mut client,
        "verify-unknown-conversation",
        "identities.verify",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "safetyNumber": "12345 67890"
        }),
    )
    .await;
    assert_eq!(
        unknown_conversation["error"]["code"],
        "CONVERSATION_NOT_FOUND"
    );

    // 契约 1.281（§4.265）：peerKey 面——没有 direct 会话的 peer 也能读/写。
    let listed_before = request(
        &mut client,
        "identity-list-before-peer-read",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 100 }),
    )
    .await;
    let count_before = listed_before["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("conversations.list items: {listed_before:?}"))
        .len();

    // +15555550199 既不在 contacts fixture 里、也没有任何会话行：读面答诚实
    // 空身份（identity: null），不是 CONVERSATION_NOT_FOUND。
    let peer_read = request(
        &mut client,
        "identity-peer-read-no-conversation",
        "identities.get",
        json!({ "accountId": account_id, "peerKey": "+15555550199" }),
    )
    .await;
    assert_eq!(
        peer_read["result"]["identity"],
        Value::Null,
        "a peer with no identity row answers the honest null face: {peer_read:?}"
    );
    assert!(peer_read.get("error").is_none(), "{peer_read:?}");
    // 同一个 peer 引用直读：fixture 对已联系的号码答记录，与有没有
    // conversationId 无关。
    let peer_read = request(
        &mut client,
        "identity-peer-read",
        "identities.get",
        json!({ "accountId": account_id, "peerKey": "+15555550103" }),
    )
    .await;
    assert_eq!(peer_read["result"]["identity"]["number"], "+15555550103");
    assert_eq!(
        peer_read["result"]["identity"]["trustLevel"],
        "TRUSTED_UNVERIFIED"
    );
    // uuid 形态：形状闸放行，引用逐字上 wire。fixture 只按已联系号码答记录，
    // 这里如实答空身份——正好证明 connector 没把 ACI 改写成号码。
    let uuid_read = request(
        &mut client,
        "identity-peer-read-uuid",
        "identities.get",
        json!({
            "accountId": account_id,
            "peerKey": "99999999-9999-9999-9999-999999999999"
        }),
    )
    .await;
    assert_eq!(
        uuid_read["result"]["identity"],
        Value::Null,
        "{uuid_read:?}"
    );

    // 读面绝不顺手建行：无会话 peer 的读之后列表长度不变。
    let listed = request(
        &mut client,
        "identity-list-after-peer-read",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 100 }),
    )
    .await;
    let items = listed["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("conversations.list items: {listed:?}"));
    assert_eq!(
        items.len(),
        count_before,
        "the peerKey read must never materialize a conversation: {listed:?}"
    );
    // 写穿投影读面：同一个 peer 的 direct 行，verified 位跟着写臂走。此刻
    // 它还停在前一条会话面 reset 写的 TRUSTED_UNVERIFIED（false）。
    let row = items
        .iter()
        .find(|row| row["id"] == conversation_id.as_str())
        .unwrap_or_else(|| panic!("the safety peer's row must be listed: {listed:?}"));
    assert_eq!(
        row["verified"],
        json!(false),
        "the reset arm's TRUSTED_UNVERIFIED stamp reads false: {row:?}"
    );

    // verified 臂：peerKey 上 wire 的数字写穿成 TRUSTED_VERIFIED（投影 true）。
    let peer_verified = request(
        &mut client,
        "identity-peer-verify-safety-number",
        "identities.verify",
        json!({
            "accountId": account_id,
            "peerKey": "+15555550103",
            "safetyNumber": "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
        }),
    )
    .await;
    assert_eq!(
        peer_verified["result"]["status"], "verified",
        "the peerKey verified arm answers: {peer_verified:?}"
    );
    let listed = request(
        &mut client,
        "identity-list-after-peer-verified",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 100 }),
    )
    .await;
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == conversation_id.as_str())
        .expect("the safety peer's row");
    assert_eq!(
        row["verified"],
        json!(true),
        "the peerKey verified arm writes TRUSTED_VERIFIED through: {row:?}"
    );

    // state 臂：sendAnyway 的信任重置按同一 peer 引用写穿 TRUSTED_UNVERIFIED
    // （false）——绝不冒充 verified。
    let peer_reset = request(
        &mut client,
        "identity-peer-verify-default",
        "identities.verify",
        json!({
            "accountId": account_id,
            "peerKey": "+15555550103",
            "state": "default"
        }),
    )
    .await;
    assert_eq!(
        peer_reset["result"]["status"], "verified",
        "the peerKey trust-reset arm answers: {peer_reset:?}"
    );
    let listed = request(
        &mut client,
        "identity-list-after-peer-reset",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 100 }),
    )
    .await;
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == conversation_id.as_str())
        .expect("the safety peer's row");
    assert_eq!(
        row["verified"],
        json!(false),
        "the peerKey state arm writes TRUSTED_UNVERIFIED (false, never a verified \
         flip) through: {row:?}"
    );

    // 写面的 wire 形状：peer 引用逐字上 wire（state 臂无数字；verified 臂带
    // 数字，uuid 形态同样逐字——connector 不做地址换算）。
    let before = send_log().len();
    let uuid_verified = request(
        &mut client,
        "identity-peer-verify-uuid",
        "identities.verify",
        json!({
            "accountId": account_id,
            "peerKey": "99999999-9999-9999-9999-999999999999",
            "safetyNumber": "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
        }),
    )
    .await;
    assert_eq!(uuid_verified["result"]["status"], "verified");
    let calls = send_log();
    assert_eq!(calls.len(), before + 1, "one trust write per request");
    let write = calls.last().unwrap();
    assert_eq!(write["account"], "+15555550100");
    assert_eq!(
        write["recipient"], "99999999-9999-9999-9999-999999999999",
        "the ACI rides verbatim, never rewritten into a number"
    );
    assert!(write.get("trustAllKnownKeys").is_none());

    // 寻址恰一：双缺 / 同置都是 INVALID_REQUEST（两个面各一遍）。
    for (request_id, method, params) in [
        (
            "peer-get-both-forms",
            "identities.get",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "peerKey": "+15555550103"
            }),
        ),
        (
            "peer-get-neither-form",
            "identities.get",
            json!({ "accountId": account_id }),
        ),
        (
            "peer-get-bare-digits",
            "identities.get",
            json!({ "accountId": account_id, "peerKey": "15555550103" }),
        ),
        (
            "peer-get-group-key",
            "identities.get",
            json!({ "accountId": account_id, "peerKey": "ZmFrZS1ncm91cC0x" }),
        ),
        (
            "peer-verify-both-forms",
            "identities.verify",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "peerKey": "+15555550103",
                "safetyNumber": "12345 67890"
            }),
        ),
        (
            "peer-verify-neither-form",
            "identities.verify",
            json!({ "accountId": account_id, "state": "default" }),
        ),
    ] {
        let rejected = request(&mut client, request_id, method, params).await;
        assert_eq!(
            rejected["error"]["code"], "INVALID_REQUEST",
            "{request_id}: {rejected:?}"
        );
    }

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.59: the §4.55 username faces — accounts.setUsername
/// (the engine's two-hop usernameReserve→usernameConfirm write with the
/// confirm write-back projection, the structured USERNAME_TAKEN sentinel,
/// the crash-with-in-flight-write unknown outcome with no retry),
/// accounts.getUsername (the engine reader opened with contract 1.74,
/// §4.65), and username.lookup (the usernameLookup array projection
/// entry-for-entry, including the unregistered face and the CDSI rate-limit
/// sentinel).
#[tokio::test]
async fn username_faces_round_trip() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [45_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let mut engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Username" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let send_log = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    };

    // setUsername round trip: the two-hop engine face — reserve carries the
    // resolved account + candidate (no hash yet), confirm lands it with the
    // reservation hash; the result projects the confirm write-back verbatim
    // (username + the generated username link).
    let set = request(
        &mut client,
        "username-set",
        "accounts.setUsername",
        json!({ "accountId": account_id, "username": "kt_test_agent.07" }),
    )
    .await;
    assert_eq!(set["result"]["username"], "kt_test_agent.07");
    assert_eq!(
        set["result"]["usernameLink"],
        "https://signal.me/username/fixture-link"
    );
    let set_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("username").is_some())
        .collect();
    assert_eq!(set_calls.len(), 2, "{set_calls:?}");
    assert_eq!(set_calls[0]["account"], "+15555550100");
    assert_eq!(set_calls[0]["username"], "kt_test_agent.07");
    assert!(set_calls[0].get("usernameHash").is_none());
    assert_eq!(set_calls[1]["account"], "+15555550100");
    assert_eq!(set_calls[1]["username"], "kt_test_agent.07");
    assert_eq!(
        set_calls[1]["usernameHash"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    // The XOR ladder: both present and both absent answer INVALID_REQUEST
    // before any upstream call.
    let both = request(
        &mut client,
        "username-both",
        "accounts.setUsername",
        json!({
            "accountId": account_id,
            "username": "kt_test_agent.07",
            "deleteUsername": true
        }),
    )
    .await;
    assert_eq!(both["error"]["code"], "INVALID_REQUEST");
    let neither = request(
        &mut client,
        "username-neither",
        "accounts.setUsername",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(neither["error"]["code"], "INVALID_REQUEST");
    assert_eq!(
        send_log()
            .iter()
            .filter(
                |params| params.get("username").is_some() || params.get("deleteUsername").is_some()
            )
            .count(),
        2,
        "XOR refusals never dial upstream"
    );

    // The taken-username sentinel rides the engine's structured code —
    // USERNAME_TAKEN, retryable=false — after the reserve hop; the confirm
    // never fires.
    let taken = request(
        &mut client,
        "username-taken",
        "accounts.setUsername",
        json!({ "accountId": account_id, "username": "fixture_username_taken.01" }),
    )
    .await;
    assert_eq!(taken["error"]["code"], "USERNAME_TAKEN");
    assert_eq!(taken["error"]["retryable"], false);

    // Local grammar: a malformed username answers INVALID_REQUEST without
    // dialing upstream.
    let malformed = request(
        &mut client,
        "username-malformed",
        "accounts.setUsername",
        json!({ "accountId": account_id, "username": "kt_test.00" }),
    )
    .await;
    assert_eq!(malformed["error"]["code"], "INVALID_REQUEST");
    assert_eq!(
        send_log()
            .iter()
            .filter(|params| params.get("username").is_some())
            .count(),
        3,
        "the grammar refusal stays local"
    );

    // getUsername: the engine reader projects the storage truth — after the
    // set above both keys are present.
    let get = request(
        &mut client,
        "username-get",
        "accounts.getUsername",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(get["result"]["username"], "fixture_user.01");
    assert_eq!(
        get["result"]["usernameLink"],
        "https://signal.me/username/fixture-link"
    );
    let missing = request(
        &mut client,
        "username-get-missing",
        "accounts.getUsername",
        json!({ "accountId": "acct-absent" }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");

    // username.lookup: the getUserStatus array projects entry-for-entry —
    // first entry registered (number/username/uuid), the rest the
    // unregistered face.
    let lookup = request(
        &mut client,
        "username-lookup",
        "username.lookup",
        json!({
            "accountId": account_id,
            "usernames": ["kt_registered.01", "kt_unregistered.02"]
        }),
    )
    .await;
    let results = lookup["result"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["recipient"], "kt_registered.01");
    assert_eq!(results[0]["isRegistered"], true);
    assert!(results[0]["uuid"].is_string());
    assert_eq!(results[1]["recipient"], "kt_unregistered.02");
    assert_eq!(results[1]["isRegistered"], false);
    assert!(results[1]["uuid"].is_null());

    // The lookup batch cap: 21 entries refuse locally.
    let oversized: Vec<&str> = std::iter::repeat_n("kt_lookup.entry", 21).collect();
    let too_many = request(
        &mut client,
        "username-lookup-oversized",
        "username.lookup",
        json!({ "accountId": account_id, "usernames": oversized }),
    )
    .await;
    assert_eq!(too_many["error"]["code"], "INVALID_REQUEST");

    // The CDSI rate-limit sentinel degrades to UPSTREAM_ERROR.
    let ratelimited = request(
        &mut client,
        "username-lookup-ratelimited",
        "username.lookup",
        json!({
            "accountId": account_id,
            "usernames": ["[fixture-username-ratelimited]"]
        }),
    )
    .await;
    assert_eq!(ratelimited["error"]["code"], "UPSTREAM_ERROR");

    // Crash with the mutating username write in flight (os._exit(31)):
    // SEND_OUTCOME_UNKNOWN, never retried.
    let crash = request(
        &mut client,
        "username-crash",
        "accounts.setUsername",
        json!({ "accountId": account_id, "username": "fixture_crash_username.31" }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-username", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    engine_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_eq!(
        send_log()
            .iter()
            .filter(|params| params["username"] == "fixture_crash_username.31")
            .count(),
        1,
        "an unknown username outcome is never retried"
    );

    // The delete face: the bare usernameDelete {account} payload, an empty
    // result body.
    let single_account_frame =
        |params: &&Value| params.get("account").is_some() && params.as_object().unwrap().len() == 1;
    let singles_before = send_log().iter().filter(single_account_frame).count();
    let delete = request(
        &mut client,
        "username-delete",
        "accounts.setUsername",
        json!({ "accountId": account_id, "deleteUsername": true }),
    )
    .await;
    assert_eq!(delete["result"], json!({}));
    let singles_after = send_log().iter().filter(single_account_frame).count();
    assert_eq!(
        singles_after,
        singles_before + 1,
        "the delete hop dispatches usernameDelete {{account}}"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.48: the §4.47 alignment faces — conversations.getAvatar
/// (round trip with the fixture data URI, the honest UNAVAILABLE face, the
/// FETCH_FAILED/TOO_LARGE structured codes, the fail-closed local ladder) and
/// conversations.setBlocked (verbatim forwarding of the resolved reference +
/// kind + boolean, the post-write blocked list read back, unblock
/// symmetry, CONVERSATION_NOT_RESOLVED, and the crash-with-in-flight-write
/// unknown outcome on the mutating face — no retry, exactly-once dispatch).
#[tokio::test]
async fn avatar_and_blocked_write_faces_round_trip() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [44_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Align3a" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // getAvatar round trip: the fixture PNG payload arrives as the sniffed
    // data URI with the decoded byte count, projected 1:1 from the engine.
    let sent = request(
        &mut client,
        "avatar-setup-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "avatar me",
            "clientRequestId": "avatar-setup-0"
        }),
    )
    .await;
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let avatar = request(
        &mut client,
        "get-avatar",
        "conversations.getAvatar",
        json!({ "accountId": account_id, "conversationId": conversation_id }),
    )
    .await;
    let data_uri = avatar["result"]["dataUri"].as_str().unwrap();
    assert!(data_uri.starts_with("data:image/png;base64,"), "{avatar}");
    // The fixture payload's exact padded base64 (the connector ships the
    // engine's URI verbatim) and the decoded byte count beside it.
    assert_eq!(
        data_uri,
        "data:image/png;base64,iVBORw0KGgpmaXh0dXJlLWF2YXRhcg=="
    );
    assert_eq!(avatar["result"]["byteSize"], 22);

    // The honest no-avatar face: retryable=false — the state is the answer.
    // The sentinels travel as the conversation's upstream peer reference
    // (the pin face's materialize-then-call discipline): each sentinel is
    // first materialized as a real local conversation by a send to that
    // peerKey, so the local ladder passes and the fixture sees the sentinel
    // as the forwarded peer reference. The sentinels are legal E.164 numbers
    // (+155555509xx, the fixture's sentinel family) because the direct
    // peerKey face only admits an ACI UUID or a phone number (§4.253 词形闸)
    // — a bracketed token is refused before any upstream call.
    for (request_id, sentinel, expected_code, retryable) in [
        (
            "avatar-unavailable",
            "+15555550991",
            "AVATAR_UNAVAILABLE",
            false,
        ),
        (
            "avatar-fetch-failed",
            "+15555550992",
            "AVATAR_FETCH_FAILED",
            true,
        ),
        (
            "avatar-too-large",
            "+15555550993",
            "AVATAR_TOO_LARGE",
            false,
        ),
    ] {
        let setup = request(
            &mut client,
            &format!("{request_id}-setup"),
            "messages.sendText",
            json!({
                "accountId": account_id,
                "kind": "contact",
                "peerKey": sentinel,
                "text": sentinel,
                "clientRequestId": format!("{request_id}-0")
            }),
        )
        .await;
        let sentinel_conversation = setup["result"]["conversationId"]
            .as_str()
            .unwrap()
            .to_string();
        let error = request(
            &mut client,
            request_id,
            "conversations.getAvatar",
            json!({ "accountId": account_id, "conversationId": sentinel_conversation }),
        )
        .await;
        assert_eq!(
            error["error"]["code"], expected_code,
            "{request_id}: {error}"
        );
        assert_eq!(
            error["error"]["retryable"], retryable,
            "{request_id}: {error}"
        );
    }

    // Local fail-closed ladder: empty/over-bound conversationId, unknown
    // account and conversation — all before any upstream call.
    let oversized = "A".repeat(257);
    for (request_id, params, expected) in [
        (
            "avatar-empty",
            json!({ "accountId": account_id, "conversationId": "" }),
            "INVALID_REQUEST",
        ),
        (
            "avatar-over-bound",
            json!({ "accountId": account_id, "conversationId": oversized }),
            "INVALID_REQUEST",
        ),
        (
            "avatar-unknown-account",
            json!({ "accountId": "no-such-account", "conversationId": "conv" }),
            "ACCOUNT_NOT_FOUND",
        ),
        (
            "avatar-unknown-conversation",
            json!({ "accountId": account_id, "conversationId": "no-such-conversation" }),
            "CONVERSATION_NOT_FOUND",
        ),
    ] {
        let rejected = request(&mut client, request_id, "conversations.getAvatar", params).await;
        assert_eq!(
            rejected["error"]["code"], expected,
            "{request_id}: {rejected}"
        );
    }

    // setBlocked verbatim forwarding: the resolved peer reference, kind, and
    // boolean land on the wire; the answer is the post-write blocked list.
    let blocked = request(
        &mut client,
        "set-blocked",
        "conversations.setBlocked",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "blocked": true
        }),
    )
    .await;
    let entries = blocked["result"]["blocked"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry["conversationId"] == "+15555550102" && entry["kind"] == "contact"),
        "the blocked write must read back in the list: {entries:?}"
    );
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let send_log = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    };
    let blocked_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params.get("blocked").is_some())
        .collect();
    assert_eq!(blocked_calls.len(), 1, "{blocked_calls:?}");
    assert_eq!(blocked_calls[0]["account"], "+15555550100");
    assert_eq!(blocked_calls[0]["conversationId"], "+15555550102");
    assert_eq!(blocked_calls[0]["kind"], "contact");
    assert_eq!(blocked_calls[0]["blocked"], true);

    // Unblock: the false form of the same method, symmetric read-back.
    let unblocked = request(
        &mut client,
        "set-unblocked",
        "conversations.setBlocked",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "kind": "contact",
            "blocked": false
        }),
    )
    .await;
    let entries = unblocked["result"]["blocked"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .all(|entry| entry["conversationId"] != "+15555550102"),
        "the unblocked conversation must be gone: {entries:?}"
    );

    // Fail-closed ladder: illegal kind, missing boolean, unknown
    // conversation, over-bound id.
    for (request_id, params, expected) in [
        (
            "blocked-bad-kind",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "story",
                "blocked": true
            }),
            "INVALID_REQUEST",
        ),
        (
            "blocked-missing-bool",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "kind": "contact"
            }),
            "INVALID_REQUEST",
        ),
        (
            "blocked-unknown-conversation",
            json!({
                "accountId": account_id,
                "conversationId": "no-such-conversation",
                "kind": "contact",
                "blocked": true
            }),
            "CONVERSATION_NOT_FOUND",
        ),
        (
            "blocked-over-bound",
            json!({
                "accountId": account_id,
                "conversationId": oversized,
                "kind": "contact",
                "blocked": true
            }),
            "INVALID_REQUEST",
        ),
    ] {
        let rejected = request(&mut client, request_id, "conversations.setBlocked", params).await;
        assert_eq!(
            rejected["error"]["code"], expected,
            "{request_id}: {rejected}"
        );
    }
    assert_eq!(
        send_log()
            .into_iter()
            .filter(|params| params.get("blocked").is_some())
            .count(),
        2,
        "refusals never dial upstream"
    );

    // CONVERSATION_NOT_RESOLVED passes through verbatim (retryable=false)
    // and STORAGE_UNAVAILABLE verbatim (retryable=true): the sentinels ride
    // materialized conversations whose peer reference the fixture answers
    // on, the pin face's discipline — legal E.164 sentinels (+155555509xx),
    // since the direct peerKey face refuses any other spelling (§4.253).
    for (request_id, sentinel, expected_code, retryable) in [
        (
            "blocked-unresolved",
            "+15555550995",
            "CONVERSATION_NOT_RESOLVED",
            false,
        ),
        (
            "blocked-storage",
            "+15555550994",
            "STORAGE_UNAVAILABLE",
            true,
        ),
    ] {
        let setup = request(
            &mut client,
            &format!("{request_id}-setup"),
            "messages.sendText",
            json!({
                "accountId": account_id,
                "kind": "contact",
                "peerKey": sentinel,
                "text": sentinel,
                "clientRequestId": format!("{request_id}-0")
            }),
        )
        .await;
        let sentinel_conversation = setup["result"]["conversationId"]
            .as_str()
            .unwrap()
            .to_string();
        let error = request(
            &mut client,
            request_id,
            "conversations.setBlocked",
            json!({
                "accountId": account_id,
                "conversationId": sentinel_conversation,
                "kind": "contact",
                "blocked": true
            }),
        )
        .await;
        assert_eq!(
            error["error"]["code"], expected_code,
            "{request_id}: {error}"
        );
        assert_eq!(
            error["error"]["retryable"], retryable,
            "{request_id}: {error}"
        );
    }

    // Crash with the mutating blocked write in flight (fixture sentinel,
    // os._exit(32)): SEND_OUTCOME_UNKNOWN, never retried. The crash sentinel
    // is also materialized as a real conversation first so the local ladder
    // passes and the engine call goes out.
    let crash_setup = request(
        &mut client,
        "blocked-crash-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550996",
            "text": "+15555550996",
            "clientRequestId": "blocked-crash-0"
        }),
    )
    .await;
    let crash_conversation = crash_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let crash = request(
        &mut client,
        "blocked-crash",
        "conversations.setBlocked",
        json!({
            "accountId": account_id,
            "conversationId": crash_conversation,
            "kind": "contact",
            "blocked": true
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-blocked", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid, "the engine actually restarted");

    // No-retry audit: exactly one crashing blocked call across the restart.
    let crash_calls: Vec<Value> = send_log()
        .into_iter()
        .filter(|params| params["conversationId"] == "+15555550996")
        .collect();
    assert_eq!(
        crash_calls.len(),
        1,
        "an unknown blocked outcome is never retried: {crash_calls:?}"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.37: the §4.34 sticker-pack sync faces (cloud read,
/// install write with read-back, uninstall tombstone with the ignored
/// key/position dropped, local bounds, structured STORAGE_* passthrough, the
/// crash-with-in-flight-write unknown outcome and its no-retry discipline)
/// and the §4.35 sticker-quote face (sendSticker quoteMessageId resolves
/// through the same ladder as the text face — upstream quote keys beside the
/// sticker object; a rejected quote leaves no row behind).
#[tokio::test]
async fn sticker_pack_sync_and_sticker_quote_round_trip() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [43_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-PackSync" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let sync_calls = || {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| params.get("installed").is_some())
            .collect::<Vec<_>>()
    };

    // Initial read: one installed pack (key + position) and one tombstone,
    // projected structurally.
    let initial = request(
        &mut client,
        "sync-read",
        "stickerPacks.getSyncs",
        json!({ "accountId": account_id }),
    )
    .await;
    let packs = initial["result"]["packs"].as_array().unwrap();
    assert_eq!(packs.len(), 2);
    assert_eq!(packs[0]["packId"], "abcdef0123456789abcdef0123456789");
    assert_eq!(
        packs[0]["packKey"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert_eq!(packs[0]["position"], 0);
    assert!(packs[0]["deletedAtTimestampMs"].is_null());
    assert_eq!(packs[1]["packId"], "11111111111111111111111111112222");
    assert!(packs[1]["packKey"].is_null());
    assert!(packs[1]["position"].is_null());
    assert_eq!(packs[1]["deletedAtTimestampMs"], 1727000000000u64);

    // Install a new pack: the result is the post-write cloud state read back
    // with the new record first, and the exact upstream contract landed on
    // the wire (resolved account, key, position, installed).
    let new_pack_id = "23456789abcdef0123456789abcdef01";
    let installed = request(
        &mut client,
        "sync-install",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": new_pack_id,
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "installed": true,
            "position": 3
        }),
    )
    .await;
    let packs = installed["result"]["packs"].as_array().unwrap();
    assert_eq!(packs.len(), 3);
    assert_eq!(packs[0]["packId"], new_pack_id);
    assert_eq!(
        packs[0]["packKey"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert_eq!(packs[0]["position"], 3);
    assert!(packs[0]["deletedAtTimestampMs"].is_null());
    let calls = sync_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0]["account"], "+15555550100");
    assert_eq!(calls[0]["packId"], new_pack_id);
    assert_eq!(
        calls[0]["packKey"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert_eq!(calls[0]["installed"], true);
    assert_eq!(calls[0]["position"], 3);

    // Uninstall: the tombstone clears key and position (the engine stamps
    // its own clock), and the connector forwards nulls — the caller-supplied
    // packKey/position decoys are dropped, never forwarded.
    let uninstalled = request(
        &mut client,
        "sync-uninstall",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": new_pack_id,
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "installed": false,
            "position": 3
        }),
    )
    .await;
    let packs = uninstalled["result"]["packs"].as_array().unwrap();
    assert_eq!(packs.len(), 3);
    let tombstone = packs
        .iter()
        .find(|entry| entry["packId"] == new_pack_id)
        .unwrap();
    assert!(tombstone["packKey"].is_null());
    assert!(tombstone["position"].is_null());
    assert!(tombstone["deletedAtTimestampMs"].as_u64().unwrap() > 0);
    let calls = sync_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[1]["packId"], new_pack_id);
    assert_eq!(calls[1]["installed"], false);
    assert!(calls[1]["packKey"].is_null());
    assert!(calls[1]["position"].is_null());

    // Local bounds reject before any upstream call: the 1.35 even-hex pack
    // id shape is not valid here (32 hex exactly), an install without a key
    // is refused, and a key decoding to 16 bytes fails the 32-byte rule.
    let wrong_id = request(
        &mut client,
        "sync-wrong-id",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": "abcdef01",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "installed": true
        }),
    )
    .await;
    assert_eq!(wrong_id["error"]["code"], "INVALID_REQUEST");
    let missing_key = request(
        &mut client,
        "sync-missing-key",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": new_pack_id,
            "installed": true
        }),
    )
    .await;
    assert_eq!(missing_key["error"]["code"], "INVALID_REQUEST");
    let short_key = request(
        &mut client,
        "sync-short-key",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": new_pack_id,
            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "installed": true
        }),
    )
    .await;
    assert_eq!(short_key["error"]["code"], "INVALID_REQUEST");
    assert_eq!(sync_calls().len(), 2, "no upstream call for the rejects");

    // Structured engine errors pass through verbatim (retryable): the
    // fixture answers them on the all-f and all-0 pack ids.
    let storage_down = request(
        &mut client,
        "sync-storage-down",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": "ffffffffffffffffffffffffffffffff",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "installed": true
        }),
    )
    .await;
    assert_eq!(storage_down["error"]["code"], "STORAGE_UNAVAILABLE");
    assert_eq!(storage_down["error"]["retryable"], true);
    let storage_read = request(
        &mut client,
        "sync-storage-read",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": "00000000000000000000000000000000",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "installed": true
        }),
    )
    .await;
    assert_eq!(storage_read["error"]["code"], "STORAGE_READ_FAILED");
    assert_eq!(storage_read["error"]["retryable"], true);

    // Crash with the mutating write in flight (fixture pack id all-1,
    // os._exit(30)): the request answers SEND_OUTCOME_UNKNOWN and nothing is
    // retried — after recovery the log shows exactly one crash call.
    let crash = request(
        &mut client,
        "sync-crash",
        "stickerPacks.setSync",
        json!({
            "accountId": account_id,
            "packId": "11111111111111111111111111111111",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "installed": true
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-sync", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid);
    let crash_calls = sync_calls();
    assert_eq!(
        crash_calls
            .iter()
            .filter(|call| call["packId"] == "11111111111111111111111111111111")
            .count(),
        1,
        "an unknown sync outcome is never retried: {crash_calls:?}"
    );

    // §4.35 sticker quote: a text send materializes the conversation and the
    // quoted row; the sticker send quoting it carries the upstream quote keys
    // beside the sticker object and the row records the target.
    let setup = request(
        &mut client,
        "quote-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "quote me",
            "clientRequestId": "sticker-quote-setup"
        }),
    )
    .await;
    let quoted_message_id = setup["result"]["id"].as_str().unwrap().to_string();
    let conversation_id = setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let quoted = request(
        &mut client,
        "sticker-quote",
        "messages.sendSticker",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "sticker-quote-1",
            "packId": "abcdef01",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "stickerId": 7,
            "image": {
                "dataBase64": "iVBORw0KGgo=",
                "sizeBytes": 8,
                "contentType": "image/png"
            },
            "quoteMessageId": quoted_message_id
        }),
    )
    .await;
    assert_eq!(quoted["result"]["status"], "sent");
    assert_eq!(quoted["result"]["quoteMessageId"], quoted_message_id);
    let sticker_calls: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|params| params.get("sticker").is_some())
        .collect();
    let quote_call = sticker_calls
        .iter()
        .find(|call| call["sticker"]["packId"] == "abcdef01")
        .expect("the quoted sticker send reaches the upstream");
    assert_eq!(quote_call["quoteTimestamp"], 99);
    assert_eq!(quote_call["quoteAuthor"], "+15555550100");
    assert!(
        quote_call.get("message").is_none(),
        "a quoted sticker send still carries no message body: {quote_call}"
    );

    // An unknown quote target answers MESSAGE_NOT_FOUND during validation —
    // no upstream call, no pending row left behind.
    let rejected = request(
        &mut client,
        "sticker-quote-missing",
        "messages.sendSticker",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "sticker-quote-2",
            "packId": "abcdef01",
            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "stickerId": 8,
            "image": {
                "dataBase64": "iVBORw0KGgo=",
                "sizeBytes": 8,
                "contentType": "image/png"
            },
            "quoteMessageId": "no-such-message"
        }),
    )
    .await;
    assert_eq!(rejected["error"]["code"], "MESSAGE_NOT_FOUND");
    assert_eq!(rejected["error"]["retryable"], false);
    let listed = request(
        &mut client,
        "list-after-reject",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let rows = listed["result"]["items"].as_array().unwrap();
    assert!(
        rows.iter()
            .all(|row| row["clientRequestId"] != "sticker-quote-2"),
        "a rejected quote leaves no row: {rows:?}"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// The send-log lines one assertion cares about, re-read fresh each poll.
struct SendLog {
    contents: String,
}

impl SendLog {
    fn receipt_lines(&self) -> Vec<Value> {
        self.lines_with("timestamps")
    }

    fn view_once_open_lines(&self) -> Vec<Value> {
        self.lines_with("senderAci")
    }

    fn view_once_send_lines(&self) -> Vec<Value> {
        self.lines_with("viewOnce")
    }

    fn lines_with(&self, key: &str) -> Vec<Value> {
        self.contents
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|entry| entry.get(key).is_some())
            .collect()
    }
}

async fn read_send_log(signal_data: &Path) -> Option<SendLog> {
    fs::read_to_string(signal_data.join(".fixture-send-log.jsonl"))
        .ok()
        .map(|contents| SendLog { contents })
}

/// Frames the client until the named request's response arrives, collecting
/// every `message.viewOnceOpened` event on the way — the deterministic
/// "no further event" barrier: the connector writes events and responses to
/// the same connection in emission order, so a response proves every event
/// triggered before it was already delivered.
async fn drain_until_response_collecting_opened(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
) -> (Value, Vec<Value>) {
    let mut opened: Vec<Value> = Vec::new();
    loop {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "drain_until_response_collecting_opened stalled over \
                 {HARNESS_REQUEST_TIMEOUT:?} waiting for {request_id} (collected {opened:?}):\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame.get("event").and_then(Value::as_str) == Some("message.viewOnceOpened") {
            opened.push(frame["data"].clone());
            continue;
        }
        if frame.get("requestId").and_then(Value::as_str) == Some(request_id) {
            return (frame, opened);
        }
    }
}

/// Frames the client until the first `message.viewOnceOpened` event arrives
/// and returns it — the wait side of a burn whose transition must produce
/// exactly one event (the "exactly once" side is the barrier drain).
async fn drain_until_opened_event(client: &mut Framed<UnixStream, LinesCodec>) -> Value {
    loop {
        let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
            serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
        })
        .await
        {
            Ok(frame) => frame,
            Err(_) => panic!(
                "drain_until_opened_event stalled over {HARNESS_REQUEST_TIMEOUT:?} \
                 without a message.viewOnceOpened frame:\n{}",
                dump_connector_crash_scene()
            ),
        };
        if frame.get("event").and_then(Value::as_str) == Some("message.viewOnceOpened") {
            return frame["data"].clone();
        }
    }
}

/// Contract revision 1.38 end to end: a `viewOnce` attachment send carries the
/// upstream flag and persists the marker row; `messages.markViewOnceOpened`
/// burns an incoming view-once row once (the official VIEWED-then-ViewOnceOpen
/// pair reaches the engine in order, one host event, the row loses its bytes
/// but keeps its metadata, a replay is a trivial no-op with no fan-out); and
/// the engine's own `syncMessage.viewOnceOpen` sync burns the sender's row
/// through the local ladder with no upstream traffic — duplicate syncs and a
/// sync naming a non-view-once row emit nothing.
#[tokio::test]
async fn view_once_send_mark_open_and_sync_burn_reach_the_upstream() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [37_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // Stage the peer's view-once media message (attachment descriptor, no
    // body — the §4.36 official shape) behind the default link receive.
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-extra-receives.json"),
        json!([
            {
                "source": "+15555550101",
                "timestamp": 70,
                "dataMessage": {
                    "viewOnce": true,
                    "attachments": [{
                        "id": "att-view-in-1",
                        "contentType": "image/jpeg",
                        "filename": "snap.jpg",
                        "size": 2048
                    }]
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-ViewOnce" }),
    )
    .await;
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;

    // Drain the finish burst: the link answer plus the two incoming upserts
    // (the default 42 plain receive and the staged 70 view-once receive).
    let mut account_id: Option<String> = None;
    let mut upserted: Vec<Value> = Vec::new();
    timeout(Duration::from_secs(5), async {
        while account_id.is_none() || upserted.len() < 2 {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                account_id = Some(frame["result"]["id"].as_str().unwrap().to_string());
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["direction"] == "incoming"
            {
                upserted.push(frame["data"].clone());
            }
        }
    })
    .await
    .expect("the finish burst must deliver two incoming messages");
    let account_id = account_id.unwrap();
    let conversation_id = upserted[0]["conversationId"].as_str().unwrap().to_string();
    let view_once_row_id = upserted
        .iter()
        .find(|row| row["sentAt"] == 70)
        .expect("the staged view-once row")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // C1 (§4.36): the view-once attachment send carries the upstream flag and
    // persists the marker on its own row; the fixture's send result pins the
    // row's timestamp at 99.
    let sent = request(
        &mut client,
        "view-send",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "view-once-send-1",
            "dataBase64": "iVBORw0KGgo=",
            "sizeBytes": 8,
            "filename": "snap.png",
            "contentType": "image/png",
            "viewOnce": true
        }),
    )
    .await;
    assert_eq!(sent["result"]["viewOnce"], true);
    assert_eq!(sent["result"]["sentAt"], 99);
    let sent_row_id = sent["result"]["id"].as_str().unwrap().to_string();
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(log) = read_send_log(&signal_data).await
                && !log.view_once_send_lines().is_empty()
            {
                assert_eq!(log.view_once_send_lines()[0]["viewOnce"], true);
                assert_eq!(
                    log.view_once_send_lines()[0]["recipient"],
                    json!(["+15555550101"])
                );
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the view-once send must reach the engine with the flag");

    // The finish burst's auto delivery receipts: one per incoming dataMessage.
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(log) = read_send_log(&signal_data).await
                && log.receipt_lines().len() >= 2
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("two auto delivery receipts must reach the engine");

    // C3 (§4.37): marking the incoming view-once row burns it and runs the
    // official pair — the VIEWED receipt to the author, then the open sync.
    send_request_frame(
        &mut client,
        "mark-open-1",
        "messages.markViewOnceOpened",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": view_once_row_id
        }),
    )
    .await;
    let (mark, opened) = drain_until_response_collecting_opened(&mut client, "mark-open-1").await;
    assert_eq!(mark["result"]["status"], "sent");
    assert_eq!(opened.len(), 1, "exactly one burn event: {opened:?}");
    assert_eq!(opened[0]["accountId"], account_id);
    assert_eq!(opened[0]["conversationId"], conversation_id);
    assert_eq!(opened[0]["messageId"], view_once_row_id);
    assert!(opened[0]["openedAt"].as_u64().is_some());

    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(log) = read_send_log(&signal_data).await {
                let receipts = log.receipt_lines();
                let opens = log.view_once_open_lines();
                if receipts.len() >= 3 && !opens.is_empty() {
                    // The third receipt line is the VIEWED (delivery receipts
                    // for rows 42 and 70 landed during the burst).
                    assert_eq!(
                        receipts[2]["recipient"], "+15555550101",
                        "receipt lines: {receipts:?}"
                    );
                    assert_eq!(receipts[2]["timestamps"], json!([70]));
                    assert_eq!(opens[0]["senderAci"], "+15555550101");
                    assert_eq!(opens[0]["timestamp"], 70);
                    break;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the VIEWED receipt and open sync must reach the engine in order");

    // The burned row keeps its metadata and carries the opened stamp.
    let listed = request(
        &mut client,
        "list-burned",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let burned = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == view_once_row_id)
        .expect("the burned row stays listed");
    assert!(burned.get("text").is_none(), "the body bytes are erased");
    assert!(burned["viewOnceOpenedAt"].as_u64().is_some());
    assert_eq!(burned["attachments"].as_array().unwrap().len(), 1);

    // The replay is a trivial no-op: `sent`, no event, no upstream legs.
    let replay = request(
        &mut client,
        "mark-open-2",
        "messages.markViewOnceOpened",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "messageId": view_once_row_id
        }),
    )
    .await;
    assert_eq!(replay["result"]["status"], "sent");
    let (_, replay_opened) = send_status_barrier(&mut client, "barrier-1").await;
    assert!(
        replay_opened.is_empty(),
        "a replay emits no event: {replay_opened:?}"
    );

    // C2 (§4.37): the engine's own view-once open syncs. Three duplicates
    // naming the sender's row (timestamp 99) burn it exactly once; a fourth
    // naming the plain row 42 matches nothing. No upstream traffic escapes.
    let sync_envelope = |timestamp: u64| {
        json!({
            "source": "+15555550101",
            "timestamp": 1000,
            "syncMessage": {
                "viewOnceOpen": {
                    "senderAci": "+15555550101",
                    "timestamp": timestamp
                }
            }
        })
    };
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            sync_envelope(99),
            sync_envelope(99),
            sync_envelope(99),
            sync_envelope(42),
        ] })
        .to_string(),
    )
    .unwrap();
    let sync_opened = timeout(
        Duration::from_secs(5),
        drain_until_opened_event(&mut client),
    )
    .await
    .expect("the sync burn must emit its event");
    assert_eq!(sync_opened["messageId"], sent_row_id);
    assert_eq!(sync_opened["conversationId"], conversation_id);
    let (_, sync_settled) = send_status_barrier(&mut client, "barrier-2").await;
    assert!(
        sync_settled.is_empty(),
        "replayed syncs and non-view-once targets emit nothing: {sync_settled:?}"
    );
    // The sync path never sends upstream: the log is unchanged.
    let log = read_send_log(&signal_data).await.expect("the log exists");
    assert_eq!(
        log.receipt_lines().len(),
        3,
        "receipt lines after the sync phase: {:?}",
        log.receipt_lines()
    );
    assert_eq!(log.view_once_open_lines().len(), 1);

    // The sync-burned row carries the opened stamp too.
    let listed = request(
        &mut client,
        "list-sync-burned",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let burned = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == sent_row_id)
        .expect("the sync-burned row stays listed");
    assert!(burned["viewOnceOpenedAt"].as_u64().is_some());

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// A `runtime.status` request used as an ordering barrier: returns the
/// status response and every `message.viewOnceOpened` event that was
/// delivered before it — the connector writes frames in emission order.
async fn send_status_barrier(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
) -> (Value, Vec<Value>) {
    send_request_frame(client, request_id, "runtime.status", json!({})).await;
    drain_until_response_collecting_opened(client, request_id).await
}

fn write_secret_file(path: &Path, secret: &[u8; 32]) {
    fs::write(path, bootstrap_payload(secret)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn spawn_connector(root: &Path, endpoint: &Path, secret_file: &Path) -> Child {
    spawn_connector_with_delete_mode(root, endpoint, secret_file, None)
}

async fn spawn_connector_from_stdin(root: &Path, endpoint: &Path, secret: &[u8; 32]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    let mut child = command
        .arg("serve")
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--bootstrap-secret-stdin")
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--java-home")
        .arg(root.join("jre"))
        .arg("--signal-data-dir")
        .arg(root.join("signal-data"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_FAKE_EXPECT_NO_JAVA", "1")
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(bootstrap_payload(secret).as_bytes())
        .await
        .unwrap();
    stdin.shutdown().await.unwrap();
    child
}

fn spawn_connector_with_delete_mode(
    root: &Path,
    endpoint: &Path,
    secret_file: &Path,
    delete_mode: Option<&str>,
) -> Child {
    spawn_connector_with(root, endpoint, secret_file, delete_mode, &[])
}

fn spawn_connector_with(
    root: &Path,
    endpoint: &Path,
    secret_file: &Path,
    delete_mode: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Child {
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
    if let Some(delete_mode) = delete_mode {
        command.env("KT_FAKE_DELETE_MODE", delete_mode);
    }
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command.spawn().unwrap()
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py")
}

/// Wait for the connector to exit and require a clean status. The connector's
/// own stderr is the only place the reason appears, so drain it into the panic
/// rather than leaving a bare `false != true`.
async fn assert_clean_exit(connector: &mut Child) {
    let status = timeout(Duration::from_secs(2), connector.wait())
        .await
        .expect("connector should exit after the host disconnects")
        .unwrap();
    if status.success() {
        return;
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = connector.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr).await;
    }
    panic!("connector exited with {status:?}; stderr: {stderr}");
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

/// Read frames until the named response arrives; unrelated responses are
/// skipped (the delete-hold tests interleave a fire-and-forget delete).
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
    .unwrap_or_else(|_| panic!("response {request_id} did not arrive"))
}

/// Wait for a fixture marker file (the delete-hold handshake).
async fn wait_for_marker(path: &Path) {
    timeout(Duration::from_secs(5), async {
        while !path.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("fixture marker {} should appear", path.display()));
}

/// Poll `accounts.list` until the delete's store cleanup lands.
async fn wait_until_accounts_empty(client: &mut Framed<UnixStream, LinesCodec>, request_id: &str) {
    let last = std::sync::Arc::new(std::sync::Mutex::new(Value::Null));
    let observed = std::sync::Arc::clone(&last);
    let settled = timeout(Duration::from_secs(10), async {
        let mut attempt = 0_u32;
        loop {
            // Unique ids: the host rejects a replayed requestId on the same
            // session, so a poll loop must not reuse one.
            attempt += 1;
            let accounts = request(
                client,
                &format!("{request_id}-poll-{attempt}"),
                "accounts.list",
                json!({}),
            )
            .await;
            *observed.lock().unwrap() = accounts.clone();
            if accounts["result"].as_array().is_some_and(Vec::is_empty) {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if settled.is_err() {
        panic!(
            "{request_id}: accounts did not empty after the delete settled; last list: {}",
            last.lock().unwrap()
        );
    }
}

/// Poll `accounts.list` until exactly the surviving account remains.
async fn wait_until_only_account(
    client: &mut Framed<UnixStream, LinesCodec>,
    account_id: &str,
    request_id: &str,
) {
    timeout(Duration::from_secs(10), async {
        let mut attempt = 0_u32;
        loop {
            // Unique ids per poll: the host rejects replayed requestIds.
            attempt += 1;
            let accounts = request(
                client,
                &format!("{request_id}-poll-{attempt}"),
                "accounts.list",
                json!({}),
            )
            .await;
            let rows = accounts["result"].as_array().cloned().unwrap_or_default();
            if rows.len() == 1 && rows[0]["id"].as_str() == Some(account_id) {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("{request_id}: account {account_id} did not become the only row after the delete")
    });
}

async fn wait_for_process_exit(pid: u32) {
    timeout(Duration::from_secs(2), async {
        while process_exists(pid) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("signal-cli fixture should exit after host disconnect");
}

fn process_exists(pid: u32) -> bool {
    std::process::Command::new("/bin/kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

async fn authenticate(client: &mut Framed<UnixStream, LinesCodec>, secret: &[u8; 32]) {
    let (_challenge, response) = authenticate_capture(client, secret).await;
    assert_eq!(response["result"]["apiVersion"], API_VERSION);
}

/// The authentication round trip with the handshake response returned —
/// tests that assert on the advertised `capabilities` reuse it.
async fn authenticate_capture(
    client: &mut Framed<UnixStream, LinesCodec>,
    secret: &[u8; 32],
) -> (Value, Value) {
    let challenge: Value = match timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    {
        Ok(challenge) => challenge,
        Err(_) => panic!(
            "authentication challenge never arrived within {HARNESS_AUTH_TIMEOUT:?}:\n{}",
            dump_connector_crash_scene()
        ),
    };
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
    let response: Value = match timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    {
        Ok(response) => response,
        Err(_) => panic!(
            "handshake response never arrived within {HARNESS_AUTH_TIMEOUT:?}:\n{}",
            dump_connector_crash_scene()
        ),
    };
    (challenge, response)
}

async fn reject_authentication(client: &mut Framed<UnixStream, LinesCodec>) {
    let challenge: Value = match timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    {
        Ok(challenge) => challenge,
        Err(_) => panic!(
            "authentication challenge never arrived within {HARNESS_AUTH_TIMEOUT:?}:\n{}",
            dump_connector_crash_scene()
        ),
    };
    assert_eq!(challenge["event"], "runtime.challenge");
    client
        .send(
            json!({
                "apiVersion": API_VERSION,
                "requestId": "bad-handshake",
                "method": "handshake",
                "params": {
                    "clientNonce": hex::encode([9_u8; 32]),
                    "proof": hex::encode([0_u8; 32])
                }
            })
            .to_string(),
        )
        .await
        .unwrap();
    let response: Value = match timeout(HARNESS_AUTH_TIMEOUT, async {
        serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
    })
    .await
    {
        Ok(response) => response,
        Err(_) => panic!(
            "handshake rejection response never arrived within {HARNESS_AUTH_TIMEOUT:?}:\n{}",
            dump_connector_crash_scene()
        ),
    };
    assert_eq!(response["error"]["code"], "AUTHENTICATION_FAILED");
}

async fn request(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) -> Value {
    let round = timeout(HARNESS_REQUEST_TIMEOUT, async {
        send_request_frame(client, request_id, method, params).await;
        loop {
            let response: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if response.get("requestId").and_then(Value::as_str) == Some(request_id) {
                return response;
            }
        }
    })
    .await;
    match round {
        Ok(response) => response,
        Err(_) => panic!(
            "harness request {request_id} ({method}) exceeded {HARNESS_REQUEST_TIMEOUT:?}; \
             the deadline-less await family turned transient upstream anomalies into \
             indefinite hangs:\n{}",
            dump_connector_crash_scene()
        ),
    }
}

async fn send_request_frame(
    client: &mut Framed<UnixStream, LinesCodec>,
    request_id: &str,
    method: &str,
    params: Value,
) {
    // The deliberate fire-and-forget face: responses are consumed by the
    // caller's own drain loops, so nothing is read here. Only the write is
    // bounded — a connector that stopped reading would otherwise block this
    // write forever once the socket buffers filled.
    if timeout(
        HARNESS_REQUEST_TIMEOUT,
        client.send(request_frame(request_id, method, params)),
    )
    .await
    .is_err()
    {
        panic!(
            "harness frame write {request_id} ({method}) stalled over \
             {HARNESS_REQUEST_TIMEOUT:?} (the connector likely stopped reading):\n{}",
            dump_connector_crash_scene()
        );
    }
}

fn request_frame(request_id: &str, method: &str, params: Value) -> String {
    json!({
        "apiVersion": API_VERSION,
        "requestId": request_id,
        "method": method,
        "params": params
    })
    .to_string()
}

/// Contract revision 1.53 (§4.49, capability call-signaling): the connector's
/// call-signaling pipe. Outbound: `calls.sendSignal` shape-gates the envelope
/// (the five-value type enum, the positive-u32 callId, the payload mandatory
/// for the modern faces and optional for the legacy busy/hangup family, the
/// two-value urgency pass-through) and forwards the resolved direct peer
/// reference plus the payload verbatim as the engine `sendCallMessage`
/// upstream face — legacy busy/hangup frames without a payload route the
/// engine's `legacy` bare-frame face (the official proto shapes, no invented
/// bytes); every illegal shape refuses locally (refusals never dial
/// upstream), a group conversation fails closed, an engine crash with the
/// mutating call in flight answers SEND_OUTCOME_UNKNOWN and is never retried
/// across the restart. Inbound: the engine's `callMessage` envelope face
/// lands as exactly one `call.incoming` event carrying the projected payload
/// verbatim — no row, nothing persisted. The state face: the honest empty
/// registry, repeatable, and the crash drill proves the send face's no-retry
/// discipline.
#[tokio::test]
async fn call_signaling_faces_round_trip_and_gate_the_envelope() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [45_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-CallP1" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Materialize the peer conversation the way every send face does.
    let sent = request(
        &mut client,
        "call-setup-send",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "call me",
            "clientRequestId": "call-setup-0"
        }),
    )
    .await;
    let conversation_id = sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Stage a group envelope so the group route (1.82) has a real local
    // group row to address (the runtime marker delivers it like every
    // injected envelope; the group message materializes the group row).
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": "+15555550101",
                "timestamp": 80,
                "dataMessage": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "message": "callless group"
                }
            }
        ] })
        .to_string(),
    )
    .unwrap();
    let mut group_id = String::new();
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = request(
            &mut client,
            &format!("group-poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        let listed = request(
            &mut client,
            &format!("group-list-{attempt}"),
            "conversations.list",
            json!({ "accountId": account_id, "limit": 50 }),
        )
        .await;
        if let Some(found) = listed["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"] == "group")
            .and_then(|row| row["id"].as_str())
        {
            group_id = found.to_string();
            break;
        }
    }
    assert!(
        !group_id.is_empty(),
        "the staged group row must materialize"
    );

    // getState before any signaling: the honest empty registry, repeatable.
    for request_id in ["state-before", "state-again"] {
        let state = request(
            &mut client,
            request_id,
            "calls.getState",
            json!({ "accountId": account_id }),
        )
        .await;
        assert_eq!(
            state["result"]["calls"].as_array().unwrap().len(),
            0,
            "{state}"
        );
        assert_eq!(state["result"]["projection"], "connector-pipe", "{state}");
    }

    // The offer round trip: the resolved peer reference and the payload
    // verbatim land on the wire; the answer is the engine's envelope
    // timestamp as {sentAt}.
    let offered = request(
        &mut client,
        "call-offer",
        "calls.sendSignal",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "type": "offer",
            "callId": 7,
            "payload": "c2RwLW9mZmVy"
        }),
    )
    .await;
    assert_eq!(offered["result"]["sentAt"], 1727000000000u64, "{offered}");
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let call_lines = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| params.get("data").is_some() || params.get("legacy").is_some())
            .collect()
    };
    assert_eq!(call_lines().len(), 1, "{:?}", call_lines());
    assert_eq!(call_lines()[0]["account"], "+15555550100");
    assert_eq!(call_lines()[0]["recipient"], "+15555550102");
    assert_eq!(call_lines()[0]["data"], "c2RwLW9mZmVy");

    // The rest of the frame family rides the same pipe; ICE keeps the u32
    // ceiling legal and the payload opaque.
    for (request_id, signal_type, call_id, payload) in [
        ("call-answer", "answer", 7u64, "c2RwLWFuc3dlcg=="),
        ("call-ice", "ice", 4294967295u64, "aWNlLTE="),
    ] {
        let signaled = request(
            &mut client,
            request_id,
            "calls.sendSignal",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": signal_type,
                "callId": call_id,
                "payload": payload
            }),
        )
        .await;
        assert_eq!(signaled["result"]["sentAt"], 1727000000000u64, "{signaled}");
    }
    assert_eq!(call_lines().len(), 3, "{:?}", call_lines());

    // The legacy bare-frame family (1.53): busy/hangup without a payload
    // route the engine's `legacy` face — the official proto shapes, no
    // invented bytes; the addressed callId is the frames' id. urgency rides
    // through on both faces.
    let legacy_busy = request(
        &mut client,
        "call-busy-legacy",
        "calls.sendSignal",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "type": "busy",
            "callId": 7
        }),
    )
    .await;
    assert_eq!(
        legacy_busy["result"]["sentAt"], 1727000000000u64,
        "{legacy_busy}"
    );
    let legacy_hangup = request(
        &mut client,
        "call-hangup-legacy",
        "calls.sendSignal",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "type": "hangup",
            "callId": 7,
            "urgency": "handleImmediately"
        }),
    )
    .await;
    assert_eq!(
        legacy_hangup["result"]["sentAt"], 1727000000000u64,
        "{legacy_hangup}"
    );
    let lines = call_lines();
    assert_eq!(lines.len(), 5, "{lines:?}");
    let busy_row = &lines[3];
    assert_eq!(busy_row["recipient"], "+15555550102");
    assert_eq!(busy_row["legacy"], json!({"kind": "busy", "id": 7}));
    assert!(
        busy_row.get("data").is_none(),
        "legacy face carries no data"
    );
    assert!(
        busy_row.get("urgency").is_none(),
        "absent urgency stays absent"
    );
    let hangup_row = &lines[4];
    assert_eq!(hangup_row["legacy"], json!({"kind": "hangup", "id": 7}));
    assert_eq!(
        hangup_row["urgency"], "handleImmediately",
        "urgency pass-through"
    );

    // The shape gate, locally: unknown type, callId 0, empty payload, an
    // over-bound payload, a modern type without a payload, an illegal
    // urgency, an unknown conversation — every refusal precedes any upstream
    // call, so the log stays at five lines.
    let oversized = "A".repeat(3 * 1024 * 1024 + 1);
    for (request_id, expected_code, params) in [
        (
            "signal-bad-type",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "sdp",
                "callId": 7,
                "payload": "eA=="
            }),
        ),
        (
            "signal-type-case",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "OFFER",
                "callId": 7,
                "payload": "eA=="
            }),
        ),
        (
            "signal-zero-call",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "offer",
                "callId": 0,
                "payload": "eA=="
            }),
        ),
        (
            "signal-empty-payload",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "offer",
                "callId": 7,
                "payload": ""
            }),
        ),
        (
            "signal-over-bound-payload",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "offer",
                "callId": 7,
                "payload": oversized
            }),
        ),
        (
            "signal-modern-type-payload-less",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "offer",
                "callId": 7
            }),
        ),
        (
            "signal-bad-urgency",
            "INVALID_REQUEST",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "type": "offer",
                "callId": 7,
                "payload": "eA==",
                "urgency": "urgent"
            }),
        ),
        (
            "signal-unknown-conversation",
            "CONVERSATION_NOT_FOUND",
            json!({
                "accountId": account_id,
                "conversationId": "no-such-conversation",
                "type": "offer",
                "callId": 7,
                "payload": "eA=="
            }),
        ),
    ] {
        let rejected = request(&mut client, request_id, "calls.sendSignal", params).await;
        assert_eq!(
            rejected["error"]["code"], expected_code,
            "{request_id}: {rejected}"
        );
        assert_eq!(
            rejected["error"]["retryable"], false,
            "{request_id}: {rejected}"
        );
    }
    assert_eq!(
        call_lines().len(),
        5,
        "refusals never dial upstream: {:?}",
        call_lines()
    );

    // The group route (1.82): the conversation kind decides — the group
    // conversation forwards the engine group face {account, group, data,
    // urgency}, no recipient key ever, and the payload-less legacy family
    // refuses locally (the send log stays at exactly one group row).
    let group_signaled = request(
        &mut client,
        "call-group-offer",
        "calls.sendSignal",
        json!({
            "accountId": account_id,
            "conversationId": group_id,
            "type": "offer",
            "callId": 7,
            "payload": "Z3JvdXAtc2lnbmFsaW5n",
            "urgency": "handleImmediately"
        }),
    )
    .await;
    assert_eq!(
        group_signaled["result"]["sentAt"], 1727000000000u64,
        "{group_signaled}"
    );
    let group_rows: Vec<Value> = call_lines()
        .into_iter()
        .filter(|params| params.get("group").is_some())
        .collect();
    assert_eq!(group_rows.len(), 1, "{group_rows:?}");
    assert_eq!(group_rows[0]["account"], "+15555550100");
    assert_eq!(group_rows[0]["group"], "ZmFrZS1ncm91cC0x");
    assert_eq!(group_rows[0]["data"], "Z3JvdXAtc2lnbmFsaW5n");
    assert_eq!(group_rows[0]["urgency"], "handleImmediately");
    assert!(
        group_rows[0].get("recipient").is_none(),
        "the group face carries no recipient key: {group_rows:?}"
    );
    let group_legacy = request(
        &mut client,
        "call-group-legacy",
        "calls.sendSignal",
        json!({
            "accountId": account_id,
            "conversationId": group_id,
            "type": "busy",
            "callId": 7
        }),
    )
    .await;
    assert_eq!(
        group_legacy["error"]["code"], "INVALID_REQUEST",
        "{group_legacy}"
    );
    assert_eq!(
        call_lines()
            .into_iter()
            .filter(|params| params.get("group").is_some())
            .count(),
        1,
        "the local legacy refusal never reaches upstream"
    );

    // Crash with the mutating signaling in flight (fixture sentinel,
    // os._exit(33)): SEND_OUTCOME_UNKNOWN, never retried across the restart.
    let crash = request(
        &mut client,
        "signal-crash",
        "calls.sendSignal",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "type": "offer",
            "callId": 9,
            "payload": "[fixture-call-crash]"
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-call", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid, "the engine actually restarted");

    // No-retry audit: exactly one crashing call across the restart.
    let crash_calls: Vec<Value> = call_lines()
        .into_iter()
        .filter(|params| params["data"] == "[fixture-call-crash]")
        .collect();
    assert_eq!(
        crash_calls.len(),
        1,
        "an unknown signaling outcome is never retried: {crash_calls:?}"
    );

    // getState after everything: still the empty registry — the send face
    // registers no state by design (the connector is the pipe).
    let state = request(
        &mut client,
        "state-after",
        "calls.getState",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(state["result"]["calls"].as_array().unwrap().len(), 0);
    assert_eq!(state["result"]["projection"], "connector-pipe");

    // Inbound: the engine's callMessage face arrives as exactly one
    // call.incoming event with the payload verbatim — and no message row.
    let envelope_offer = json!({
        "source": "+15555550102",
        "timestamp": 1727000001000u64,
        "callMessage": {
            "offer": { "id": 7u64, "type": "audio", "opaque": "aW5ib3VuZC1vZmZlcg==" }
        }
    });
    let envelope_ice = json!({
        "source": "+15555550102",
        "timestamp": 1727000002000u64,
        "callMessage": {
            "iceUpdate": [{ "id": 7u64, "opaque": "aW5ib3VuZC1pY2U=" }]
        }
    });
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [envelope_offer, envelope_ice] }).to_string(),
    )
    .unwrap();

    // Drain until both events arrive (the injected envelopes land
    // asynchronously; each poll drains interleaved frames).
    let mut incoming: Vec<Value> = Vec::new();
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = send_request_frame(
            &mut client,
            &format!("poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        loop {
            let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
                serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
            })
            .await
            {
                Ok(frame) => frame,
                Err(_) => panic!(
                    "the call.incoming poll drain stalled over \
                     {HARNESS_REQUEST_TIMEOUT:?} with {incoming:?}:\n{}",
                    dump_connector_crash_scene()
                ),
            };
            if frame.get("event").and_then(Value::as_str) == Some("call.incoming") {
                incoming.push(frame["data"].clone());
                continue;
            }
            if frame.get("requestId").and_then(Value::as_str)
                == Some(format!("poll-{attempt}").as_str())
            {
                break;
            }
        }
        if incoming.len() == 2 {
            break;
        }
    }
    assert_eq!(
        incoming.len(),
        2,
        "both signaling frames must arrive: {incoming:?} (marker still present: {})",
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-envelopes.json")
            .exists()
    );
    assert_eq!(incoming[0]["accountId"], account_id);
    assert_eq!(incoming[0]["conversationId"], conversation_id);
    assert_eq!(incoming[0]["callId"], 7);
    assert_eq!(incoming[0]["type"], "offer");
    assert_eq!(
        incoming[0]["payload"]["offer"]["opaque"],
        "aW5ib3VuZC1vZmZlcg=="
    );
    assert_eq!(incoming[1]["type"], "ice");
    assert_eq!(
        incoming[1]["payload"]["iceUpdate"][0]["opaque"],
        "aW5ib3VuZC1pY2U="
    );

    // The group-incoming route (1.82): an opaque envelope from a sender with
    // no local conversation forwards conversation-less instead of dying on
    // the ladder — exactly one call.groupIncoming and never a call.incoming.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [{
            "source": "+15555550107",
            "timestamp": 1727000003000u64,
            "callMessage": {
                "opaque": "Z3JvdXAtb3BhcXVl",
                "urgency": "handleImmediately",
                "destinationDeviceId": 2
            }
        }] })
        .to_string(),
    )
    .unwrap();
    let mut group_incoming: Vec<Value> = Vec::new();
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = send_request_frame(
            &mut client,
            &format!("group-incoming-poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        loop {
            let frame: Value = match timeout(HARNESS_REQUEST_TIMEOUT, async {
                serde_json::from_str::<Value>(&client.next().await.unwrap().unwrap()).unwrap()
            })
            .await
            {
                Ok(frame) => frame,
                Err(_) => panic!(
                    "the call.groupIncoming poll drain stalled over \
                     {HARNESS_REQUEST_TIMEOUT:?} with {group_incoming:?}:\n{}",
                    dump_connector_crash_scene()
                ),
            };
            match frame.get("event").and_then(Value::as_str) {
                Some("call.groupIncoming") => group_incoming.push(frame["data"].clone()),
                Some("call.incoming") => {
                    panic!("an unresolvable opaque frame must not fire call.incoming: {frame}")
                }
                _ => {}
            }
            if frame.get("requestId").and_then(Value::as_str)
                == Some(format!("group-incoming-poll-{attempt}").as_str())
            {
                break;
            }
        }
        if !group_incoming.is_empty() {
            break;
        }
    }
    assert_eq!(
        group_incoming.len(),
        1,
        "the unresolvable opaque frame must arrive conversation-less: {group_incoming:?} \
         (marker still present: {})",
        temp.path()
            .join("signal-data")
            .join(".fixture-emit-envelopes.json")
            .exists()
    );
    assert_eq!(group_incoming[0]["accountId"], account_id);
    assert_eq!(group_incoming[0]["sender"], "+15555550107");
    assert_eq!(group_incoming[0]["payload"], "Z3JvdXAtb3BhcXVl");
    assert_eq!(group_incoming[0]["urgency"], "handleImmediately");
    assert_eq!(group_incoming[0]["destinationDeviceId"], 2);
    assert!(
        group_incoming[0].get("conversationId").is_none(),
        "the group face carries no conversationId: {group_incoming:?}"
    );

    // No row was created by the signaling envelopes.
    let listed = request(
        &mut client,
        "list-after-call",
        "messages.list",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "limit": 50
        }),
    )
    .await;
    let rows = listed["result"]["items"].as_array().unwrap();
    assert!(
        rows.iter()
            .all(|row| row["sentAt"].as_u64().unwrap_or(0) < 1727000001000),
        "call signaling must not create message rows: {rows:?}"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.127 (§4.108): the calls.sendGroupCallUpdate face —
/// the group-call era update. The conversation row must resolve to a group
/// kind carrying a 32-byte master key (a direct row and a short-key row
/// refuse locally with zero upstream frames); the round-trip forwards
/// {account, groupId, eraId} verbatim and answers the explicit
/// {"status":"sent"}; the crash-in-flight outcome answers
/// SEND_OUTCOME_UNKNOWN and is never retried across the restart.
#[tokio::test]
async fn group_call_update_round_trips_and_gates_the_group_shape() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [45_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupCallUpdate" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");

    // Stage a 32-byte master-key group row (the engine's decode_group_id
    // gate is the shape the update fans out to).
    let master_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": "+15555550101",
                "timestamp": 80,
                "dataMessage": {
                    "groupId": master_key,
                    "message": "group call incoming"
                }
            }
        ] })
        .to_string(),
    )
    .unwrap();
    let mut group_id = String::new();
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = request(
            &mut client,
            &format!("gcu-group-poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        let listed = request(
            &mut client,
            &format!("gcu-group-list-{attempt}"),
            "conversations.list",
            json!({ "accountId": account_id, "limit": 50 }),
        )
        .await;
        // The ingest-built row carries the bare "group" title (the seed
        // fixture's own "Fixture Group" row is a different, short-key group
        // the update must never address).
        if let Some(found) = listed["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"] == "group" && row["title"] == "group")
            .and_then(|row| row["id"].as_str())
        {
            group_id = found.to_string();
            break;
        }
    }
    assert!(
        !group_id.is_empty(),
        "the staged group row must materialize"
    );

    // The round trip: {status:"sent"} and the frame carries the resolved
    // account, the group master key, and the era string verbatim.
    let updated = request(
        &mut client,
        "gcu-send",
        "calls.sendGroupCallUpdate",
        json!({
            "accountId": account_id,
            "conversationId": group_id,
            "eraId": "era-1"
        }),
    )
    .await;
    assert_eq!(updated["result"]["status"], "sent", "{updated}");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert!(
        frames.iter().any(|frame| {
            frame["account"] == "+15555550100"
                && frame["groupId"] == master_key
                && frame["eraId"] == "era-1"
        }),
        "expected the group-call-update upstream frame: {frames:?}"
    );

    // The local ladder: a direct conversation has no group-call face, an
    // empty eraId is a shape error, an unknown account refuses — every
    // refusal stays local (the dispatch log gains no frame).
    let direct_sent = request(
        &mut client,
        "gcu-direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "hello",
            "clientRequestId": "gcu-direct-0"
        }),
    )
    .await;
    let direct_id = direct_sent["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let direct_refused = request(
        &mut client,
        "gcu-direct",
        "calls.sendGroupCallUpdate",
        json!({ "accountId": account_id, "conversationId": direct_id, "eraId": "era-1" }),
    )
    .await;
    assert_eq!(direct_refused["error"]["code"], "INVALID_REQUEST");
    let empty_era = request(
        &mut client,
        "gcu-empty-era",
        "calls.sendGroupCallUpdate",
        json!({ "accountId": account_id, "conversationId": group_id, "eraId": "" }),
    )
    .await;
    assert_eq!(empty_era["error"]["code"], "INVALID_REQUEST");
    let missing = request(
        &mut client,
        "gcu-missing-account",
        "calls.sendGroupCallUpdate",
        json!({ "accountId": "no-such-account", "conversationId": group_id, "eraId": "era-1" }),
    )
    .await;
    assert_eq!(missing["error"]["code"], "ACCOUNT_NOT_FOUND");
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame.get("eraId").is_some())
            .count(),
        1,
        "a refusal never reaches the engine"
    );

    // The red line: a crash with the mutating call in flight answers
    // SEND_OUTCOME_UNKNOWN and is never retried — exactly one crashing frame
    // across the restart.
    let crash = request(
        &mut client,
        "gcu-crash",
        "calls.sendGroupCallUpdate",
        json!({
            "accountId": account_id,
            "conversationId": group_id,
            "eraId": "[fixture-crash-gcu]"
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "gcu-restart", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    let frames: Vec<Value> = fs::read_to_string(&send_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["eraId"] == "[fixture-crash-gcu]")
            .count(),
        1,
        "an unknown era-update outcome is never retried"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract revisions 1.83 + 1.84 (§4.69): the cloud-backup restore round
/// trip in kt-engine mode (the engine-only face, the §4.68 spawn posture).
/// The handshake advertises both faces with no new feature tag (the restore
/// rides `history-import`); the start face answers {"status": "started"}
/// (spawning the consumption watcher — the seeded registry lets its watch
/// resolve the cloud archive) and forwards the structured seven-family
/// ladder verbatim — the three state families content-free, the transport
/// family with its data.detail, the contract-fixed retryability on every
/// family; the status face mirrors the three negotiated states with an
/// absent bytesTotal staying an absent key. The fixture mirrors the
/// negotiated wire face: these pins cover the connector's routing,
/// consumption arming, and error fidelity, never real engine restore
/// behavior.
#[tokio::test]
async fn cloud_restore_faces_round_trip_in_kt_engine_mode() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [48_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--java-home")
        .arg(temp.path().join("no-such-jre"))
        .arg("--signal-data-dir")
        .arg(temp.path().join("signal-data"))
        .arg("--state-dir")
        .arg(temp.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_FAKE_EXPECT_NO_JAVA", "1");
    let mut connector = command.spawn().unwrap();
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries both faces before anything else runs — and still
    // no new feature tag: the restore rides the history-import bit.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in [
        "backups.restoreFromCloud",
        "backups.cloudStatus",
        "history-import",
    ] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-CloudRestore" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The absent snapshot: the honest {present: false} before anything runs.
    let absent = request(
        &mut client,
        "cloud-status-absent",
        "backups.cloudStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(absent["result"], json!({ "present": false }), "{absent}");

    // The definite acceptance; the whole chain stays in the engine's
    // background, so the answer is the bare started status. The start face
    // now spawns the consumption watcher (contract 1.84), so the fixture's
    // engine face needs the registry the watcher resolves the cloud archive
    // through — the same seeding the supervisor tests lay out.
    let signal_data = temp.path().join("signal-data");
    let account_dir = signal_data.join("accounts").join("lk-abc");
    fs::create_dir_all(&account_dir).unwrap();
    fs::write(
        signal_data.join("engine-state.json"),
        r#"{"version":2,"accounts":[{"number":"+15555550100","dir":"accounts/lk-abc"}]}"#,
    )
    .unwrap();
    let accepted = request(
        &mut client,
        "cloud-restore-start",
        "backups.restoreFromCloud",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        accepted["result"],
        json!({ "status": "started" }),
        "{accepted}"
    );

    // The structured ladder across the wire: the state families ride
    // content-free with their deterministic retryability, the transport
    // family carries the engine's data.detail, and the re-entry gate answers
    // its own code (the fixture marker plays the engine's atomic gate).
    let error_marker = signal_data.join(".fixture-cloud-restore-error");
    let running_marker = signal_data.join(".fixture-cloud-restore-running");
    for (sentinel, code, retryable, detail) in [
        ("NOT_PROVISIONED", "BACKUP_NOT_PROVISIONED", false, None),
        ("AUTH", "BACKUP_AUTH_FAILED", false, None),
        (
            "TRANSPORT",
            "BACKUP_TRANSPORT_FAILED",
            true,
            Some("fixture BACKUP_TRANSPORT_FAILED"),
        ),
        (
            "DOWNLOAD",
            "BACKUP_DOWNLOAD_FAILED",
            true,
            Some("fixture BACKUP_DOWNLOAD_FAILED"),
        ),
    ] {
        fs::write(&error_marker, sentinel).unwrap();
        let refused = request(
            &mut client,
            &format!("cloud-refuse-{sentinel}"),
            "backups.restoreFromCloud",
            json!({ "accountId": account_id }),
        )
        .await;
        assert_eq!(refused["error"]["code"], code, "{refused}");
        assert_eq!(refused["error"]["retryable"], retryable, "{refused}");
        match detail {
            Some(detail) => assert_eq!(
                refused["error"]["data"],
                json!({ "detail": detail }),
                "{refused}"
            ),
            None => assert!(
                refused["error"].get("data").is_none(),
                "{sentinel} stays content-free across the wire: {refused}"
            ),
        }
    }
    fs::remove_file(&error_marker).unwrap();
    fs::write(&running_marker, "1").unwrap();
    let running = request(
        &mut client,
        "cloud-refuse-running",
        "backups.restoreFromCloud",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(running["error"]["code"], "BACKUP_RUNNING", "{running}");
    assert_eq!(running["error"]["retryable"], false, "{running}");
    assert!(
        running["error"].get("data").is_none(),
        "the re-entry gate stays content-free: {running}"
    );
    fs::remove_file(&running_marker).unwrap();

    // The three status states across the wire: downloading with both byte
    // counts, downloading with the honest missing total, failed with the
    // structured errorCode, and the cleared absence again.
    let status_marker = signal_data.join(".fixture-cloud-status");
    fs::write(&status_marker, "downloading 1048576 4194304").unwrap();
    let downloading = request(
        &mut client,
        "cloud-status-downloading",
        "backups.cloudStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        downloading["result"],
        json!({
            "present": true,
            "phase": "downloading",
            "bytesRead": 1048576,
            "bytesTotal": 4194304
        }),
        "{downloading}"
    );
    fs::write(&status_marker, "downloading 1048576").unwrap();
    let totalless = request(
        &mut client,
        "cloud-status-totalless",
        "backups.cloudStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        totalless["result"],
        json!({ "present": true, "phase": "downloading", "bytesRead": 1048576 }),
        "{totalless}"
    );
    assert!(
        totalless["result"].get("bytesTotal").is_none(),
        "a missing total stays a missing key on the wire: {totalless}"
    );
    fs::write(&status_marker, "failed 1048576 BACKUP_DOWNLOAD_FAILED").unwrap();
    let failed = request(
        &mut client,
        "cloud-status-failed",
        "backups.cloudStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        failed["result"],
        json!({
            "present": true,
            "phase": "failed",
            "bytesRead": 1048576,
            "errorCode": "BACKUP_DOWNLOAD_FAILED"
        }),
        "{failed}"
    );
    fs::remove_file(&status_marker).unwrap();
    let cleared = request(
        &mut client,
        "cloud-status-cleared",
        "backups.cloudStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(cleared["result"], json!({ "present": false }), "{cleared}");

    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// Contract revision 1.87 (§4.72): the cloud-backup upload round trip in
/// kt-engine mode (the engine-only face, the §4.69 seam mirrored). The
/// handshake advertises both faces with no new feature tag (the upload
/// rides `backup-export`, widened in place); the start face's
/// connector-owned half lands first — the §10.2 artifact is rebuilt into
/// the registry-named engine account directory before the engine call (the
/// fixture's own artifact gate would answer BACKUP_ARTIFACT_MISSING
/// otherwise) — and a definite acceptance answers {"status": "started"}.
/// The structured ladder forwards verbatim: the state families
/// content-free, the three message families with the engine's data.detail,
/// the contract-fixed retryability on every family — including the
/// per-face divergence (BACKUP_IO_FAILED retryable=false here while its
/// §4.46 export face stays retryable=true). The status face mirrors the
/// three-phase snapshot with an absent bytesTotal staying an absent key.
/// The fixture mirrors the negotiated wire face: these pins cover the
/// connector's routing, artifact wiring, and error fidelity, never real
/// engine upload behavior.
#[tokio::test]
async fn cloud_upload_faces_round_trip_in_kt_engine_mode() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [49_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut command = Command::new(env!("CARGO_BIN_EXE_kt-signal-connector"));
    command
        .arg("serve")
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--bootstrap-secret-file")
        .arg(&secret_file)
        .arg("--engine-bin")
        .arg(fixture())
        .arg("--java-home")
        .arg(temp.path().join("no-such-jre"))
        .arg("--signal-data-dir")
        .arg(temp.path().join("signal-data"))
        .arg("--state-dir")
        .arg(temp.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("KT_FAKE_EXPECT_NO_JAVA", "1");
    let mut connector = command.spawn().unwrap();
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries both faces before anything else runs — and
    // still no new feature tag: the upload rides the backup-export bit.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in [
        "backups.uploadToCloud",
        "backups.uploadStatus",
        "backup-export",
    ] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    assert_eq!(started["result"]["state"], "running");
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-CloudUpload" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // The absent snapshot: the honest {present: false} before anything runs.
    let absent = request(
        &mut client,
        "upload-status-absent",
        "backups.uploadStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(absent["result"], json!({ "present": false }), "{absent}");

    // The registry the artifact build and the fixture's account resolution
    // both read — the same seeding the supervisor tests lay out.
    let signal_data = temp.path().join("signal-data");
    let account_dir = signal_data.join("accounts").join("lk-abc");
    fs::create_dir_all(&account_dir).unwrap();
    fs::write(
        signal_data.join("engine-state.json"),
        r#"{"version":2,"accounts":[{"number":"+15555550100","dir":"accounts/lk-abc"}]}"#,
    )
    .unwrap();

    // The definite acceptance — and the connector's own half landed: the
    // §10.2 artifact exists in the engine account directory (the fixture's
    // artifact gate mirrors the engine's start gate).
    let accepted = request(
        &mut client,
        "cloud-upload-start",
        "backups.uploadToCloud",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        accepted["result"],
        json!({ "status": "started" }),
        "{accepted}"
    );
    let artifact = account_dir.join("backup-export-input.ndjson");
    assert!(
        artifact.is_file() && fs::metadata(&artifact).unwrap().len() > 0,
        "the connector built the §10.2 artifact ahead of the start call"
    );

    // The structured ladder across the wire: the state families ride
    // content-free with their deterministic retryability, the message
    // families carry the engine's data.detail — BACKUP_IO_FAILED answering
    // retryable=false on this face — and the re-entry gate answers its own
    // code (the fixture marker plays the engine's single-slot gate).
    let error_marker = signal_data.join(".fixture-cloud-upload-error");
    let running_marker = signal_data.join(".fixture-cloud-upload-running");
    for (sentinel, code, retryable, detail) in [
        ("AUTH", "BACKUP_AUTH_FAILED", false, None),
        ("NOT_PROVISIONED", "BACKUP_NOT_PROVISIONED", false, None),
        (
            "TRANSPORT",
            "BACKUP_TRANSPORT_FAILED",
            true,
            Some("fixture BACKUP_TRANSPORT_FAILED"),
        ),
        (
            "UPLOAD",
            "BACKUP_UPLOAD_FAILED",
            true,
            Some("fixture BACKUP_UPLOAD_FAILED"),
        ),
        (
            "IO",
            "BACKUP_IO_FAILED",
            false,
            Some("fixture BACKUP_IO_FAILED"),
        ),
    ] {
        fs::write(&error_marker, sentinel).unwrap();
        let refused = request(
            &mut client,
            &format!("upload-refuse-{sentinel}"),
            "backups.uploadToCloud",
            json!({ "accountId": account_id }),
        )
        .await;
        assert_eq!(refused["error"]["code"], code, "{refused}");
        assert_eq!(refused["error"]["retryable"], retryable, "{refused}");
        match detail {
            Some(detail) => assert_eq!(
                refused["error"]["data"],
                json!({ "detail": detail }),
                "{refused}"
            ),
            None => assert!(
                refused["error"].get("data").is_none(),
                "{sentinel} stays content-free across the wire: {refused}"
            ),
        }
    }
    fs::remove_file(&error_marker).unwrap();
    fs::write(&running_marker, "1").unwrap();
    let running = request(
        &mut client,
        "upload-refuse-running",
        "backups.uploadToCloud",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        running["error"]["code"], "BACKUP_UPLOAD_ALREADY_RUNNING",
        "{running}"
    );
    assert_eq!(running["error"]["retryable"], false, "{running}");
    assert!(
        running["error"].get("data").is_none(),
        "the re-entry gate stays content-free: {running}"
    );
    fs::remove_file(&running_marker).unwrap();

    // The status states across the wire: the exporting zero-count face,
    // uploading with both byte counts, uploading with the honest missing
    // total, failed with the structured errorCode, and the cleared absence.
    let status_marker = signal_data.join(".fixture-cloud-upload-status");
    fs::write(&status_marker, "exporting 0").unwrap();
    let exporting = request(
        &mut client,
        "upload-status-exporting",
        "backups.uploadStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        exporting["result"],
        json!({ "present": true, "phase": "exporting", "bytesRead": 0 }),
        "{exporting}"
    );
    fs::write(&status_marker, "uploading 131072 1048576").unwrap();
    let uploading = request(
        &mut client,
        "upload-status-uploading",
        "backups.uploadStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        uploading["result"],
        json!({
            "present": true,
            "phase": "uploading",
            "bytesRead": 131072,
            "bytesTotal": 1048576
        }),
        "{uploading}"
    );
    fs::write(&status_marker, "uploading 131072").unwrap();
    let totalless = request(
        &mut client,
        "upload-status-totalless",
        "backups.uploadStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        totalless["result"],
        json!({ "present": true, "phase": "uploading", "bytesRead": 131072 }),
        "{totalless}"
    );
    assert!(
        totalless["result"].get("bytesTotal").is_none(),
        "a missing total stays a missing key on the wire: {totalless}"
    );
    fs::write(&status_marker, "failed 131072 BACKUP_UPLOAD_FAILED").unwrap();
    let failed = request(
        &mut client,
        "upload-status-failed",
        "backups.uploadStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(
        failed["result"],
        json!({
            "present": true,
            "phase": "failed",
            "bytesRead": 131072,
            "errorCode": "BACKUP_UPLOAD_FAILED"
        }),
        "{failed}"
    );
    fs::remove_file(&status_marker).unwrap();
    let cleared = request(
        &mut client,
        "upload-status-cleared",
        "backups.uploadStatus",
        json!({ "accountId": account_id }),
    )
    .await;
    assert_eq!(cleared["result"], json!({ "present": false }), "{cleared}");

    drop(client);
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.52 (§4.50): the groups.terminate round trip. The handshake
/// advertises the method plus the `group-terminate` capability; the terminate
/// addresses the resolved group row and dispatches the pinned 0.14.8
/// `terminateGroup {account, groupId}` payload verbatim; the refusal ladder
/// (unknown conversation, direct addressing) answers before any upstream
/// call; the upstream non-admin refusal forwards verbatim (UPSTREAM_ERROR);
/// the crash-with-in-flight-write path pins the SEND_OUTCOME_UNKNOWN answer
/// and the no-retry discipline across the engine restart.
#[tokio::test]
async fn groups_terminate_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [47_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries the new face before anything else runs.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in ["groups.terminate", "group-terminate"] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupTerm" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Stage three extra groups through the runtime injection marker (the
    // fixture's background watcher delivers each envelope verbatim; a group
    // dataMessage materializes the group row): the upstream-refusal group
    // (the fixture answers the non-admin user error) and the crash group
    // (the fixture crashes with the mutating call in flight), plus one
    // ordinary terminable group.
    let signal_data = temp.path().join("signal-data");
    fs::create_dir_all(&signal_data).unwrap();
    fs::write(
        signal_data.join(".fixture-emit-envelopes.json"),
        json!({ "envelopes": [
            {
                "source": "+15555550101",
                "timestamp": 70,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "[fixture-terminate-forbidden]",
                        "type": "UPDATE",
                        "groupName": "forbidden group",
                        "revision": 3
                    }
                }
            },
            {
                "source": "+15555550101",
                "timestamp": 71,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "[fixture-terminate-crash]",
                        "type": "UPDATE",
                        "groupName": "crash group",
                        "revision": 3
                    }
                }
            },
            {
                "source": "+15555550101",
                "timestamp": 72,
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "ZmFlLXRlcm0tZ3JvdXA=",
                        "type": "UPDATE",
                        "groupName": "terminable group",
                        "revision": 3
                    }
                }
            }
        ] })
        .to_string(),
    )
    .unwrap();

    // The injected envelopes land asynchronously; poll until all three
    // staged rows materialize (each poll drains interleaved frames).
    let mut groups: Vec<(String, String)> = Vec::new();
    for attempt in 0..200 {
        sleep(Duration::from_millis(20)).await;
        let _ = request(
            &mut client,
            &format!("group-poll-{attempt}"),
            "runtime.status",
            json!({}),
        )
        .await;
        let listed = request(
            &mut client,
            &format!("group-list-{attempt}"),
            "conversations.list",
            json!({ "accountId": account_id, "limit": 50 }),
        )
        .await;
        groups = listed["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["type"] == "group")
            .filter_map(|row| {
                Some((
                    row["id"].as_str()?.to_string(),
                    row["title"].as_str()?.to_string(),
                ))
            })
            .collect();
        let titles: Vec<&str> = groups.iter().map(|(_, name)| name.as_str()).collect();
        if titles.contains(&"terminable group")
            && titles.contains(&"forbidden group")
            && titles.contains(&"crash group")
        {
            break;
        }
    }
    let by_title = |title: &str| {
        groups
            .iter()
            .find(|(_, name)| name == title)
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| panic!("the staged {title} row must materialize: {groups:?}"))
    };
    let terminable = by_title("terminable group");
    let forbidden = by_title("forbidden group");
    let crash_group = by_title("crash group");

    // The refusal ladder, each before any upstream call.
    let unknown = request(
        &mut client,
        "terminate-unknown",
        "groups.terminate",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation"
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "CONVERSATION_NOT_FOUND");
    assert_eq!(unknown["error"]["retryable"], false);
    let bad_params = request(
        &mut client,
        "terminate-bad-params",
        "groups.terminate",
        json!({
            "accountId": account_id,
            "conversationId": terminable,
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(bad_params["error"]["code"], "INVALID_REQUEST");
    let direct_setup = request(
        &mut client,
        "direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "direct guard",
            "clientRequestId": "group-term-0"
        }),
    )
    .await;
    let direct_conversation = direct_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let direct = request(
        &mut client,
        "terminate-direct",
        "groups.terminate",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation
        }),
    )
    .await;
    assert_eq!(direct["error"]["code"], "INVALID_REQUEST");

    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let terminate_calls = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| {
                params.get("groupId").is_some()
                    && params.get("name").is_none()
                    && params.get("expiration").is_none()
            })
            .collect()
    };
    let calls_before = terminate_calls().len();
    let _ = calls_before;

    // The upstream non-admin refusal forwards verbatim: the engine's user
    // error lands as the UPSTREAM_ERROR family (retryable, like every
    // upstream protocol refusal the connector forwards).
    let refused = request(
        &mut client,
        "terminate-forbidden",
        "groups.terminate",
        json!({
            "accountId": account_id,
            "conversationId": forbidden
        }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "UPSTREAM_ERROR");
    assert_eq!(refused["error"]["retryable"], true);

    // The definite success: the resolved group row dispatches the pinned
    // dests verbatim and answers {status: "sent"}.
    let terminated = request(
        &mut client,
        "terminate-group",
        "groups.terminate",
        json!({
            "accountId": account_id,
            "conversationId": terminable,
            "operationId": "group-term-op-1"
        }),
    )
    .await;
    assert_eq!(terminated["result"]["status"], "sent", "{terminated}");
    let success_calls: Vec<Value> = terminate_calls()
        .into_iter()
        .filter(|params| params["groupId"] == "ZmFlLXRlcm0tZ3JvdXA=")
        .collect();
    assert_eq!(success_calls.len(), 1, "{:?}", terminate_calls());
    assert_eq!(success_calls[0]["account"], "+15555550100");
    assert_eq!(success_calls[0]["groupId"], "ZmFlLXRlcm0tZ3JvdXA=");

    // Crash with the mutating terminate in flight (fixture sentinel,
    // os._exit(35)): SEND_OUTCOME_UNKNOWN, never retried — exactly one such
    // call in the recovered log across the restart.
    let crash = request(
        &mut client,
        "terminate-crash",
        "groups.terminate",
        json!({
            "accountId": account_id,
            "conversationId": crash_group
        }),
    )
    .await;
    assert_eq!(crash["error"]["code"], "SEND_OUTCOME_UNKNOWN", "{crash}");
    assert_eq!(crash["error"]["retryable"], false);
    wait_for_process_exit(engine_pid).await;
    let restarted = request(&mut client, "restart-term", "runtime.start", json!({})).await;
    assert_eq!(restarted["result"]["state"], "running");
    let recovered_pid = restarted["result"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(recovered_pid, engine_pid, "the engine actually restarted");
    let crash_calls: Vec<Value> = terminate_calls()
        .into_iter()
        .filter(|params| params["groupId"] == "[fixture-terminate-crash]")
        .collect();
    assert_eq!(
        crash_calls.len(),
        1,
        "an unknown termination outcome is never retried: {crash_calls:?}"
    );
    assert_eq!(
        crash_calls[0]["account"], "+15555550100",
        "the crashing call carried the resolved payload: {crash_calls:?}"
    );

    drop(client);
    wait_for_process_exit(recovered_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.58 (§4.53): the groups.approveJoinRequests face. The handshake
/// advertises the method plus the `group-join-approve` capability; the
/// fail-closed ladder (unknown conversation, direct addressing, shape
/// violations) answers before any upstream write; and a fully valid request
/// rides into the honest engine-face refusal — the engine's updateGroup
/// carries the expiration family only (its compat §5 batch boundary), so the
/// member-family write answers CAPABILITY_UNAVAILABLE (retryable=false) with
/// nothing dispatched.
#[tokio::test]
async fn groups_approve_join_requests_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [53_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries the new face before anything else runs.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in ["groups.approveJoinRequests", "group-join-approve"] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupApprove" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Sync so the fixture group row exists, then read its conversation id.
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;
    let listed = request(
        &mut client,
        "conversations-list",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["title"] == "Fixture Group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture group row must exist");

    // The refusal ladder, each before any upstream write.
    let unknown = request(
        &mut client,
        "approve-unknown",
        "groups.approveJoinRequests",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "members": ["+15555550101"],
            "approve": true
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "CONVERSATION_NOT_FOUND");
    assert_eq!(unknown["error"]["retryable"], false);
    let bad_params = request(
        &mut client,
        "approve-bad-params",
        "groups.approveJoinRequests",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "members": ["+15555550101"],
            "approve": true,
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(bad_params["error"]["code"], "INVALID_REQUEST");
    let empty_members = request(
        &mut client,
        "approve-empty",
        "groups.approveJoinRequests",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "members": [],
            "approve": true
        }),
    )
    .await;
    assert_eq!(empty_members["error"]["code"], "INVALID_REQUEST");
    let direct_setup = request(
        &mut client,
        "direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "direct guard",
            "clientRequestId": "group-approve-0"
        }),
    )
    .await;
    let direct_conversation = direct_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let direct = request(
        &mut client,
        "approve-direct",
        "groups.approveJoinRequests",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "members": ["+15555550102"],
            "approve": true
        }),
    )
    .await;
    assert_eq!(direct["error"]["code"], "INVALID_REQUEST");

    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let member_writes = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| {
                params.get("members").is_some() || params.get("removeMembers").is_some()
            })
            .collect()
    };

    // A fully valid request rides past the ladder into the honest refusal:
    // the member-family updateGroup is the engine's compat §5 batch boundary,
    // so the face answers CAPABILITY_UNAVAILABLE and nothing is dispatched.
    let refused = request(
        &mut client,
        "approve-group",
        "groups.approveJoinRequests",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "members": ["+15555550101"],
            "approve": true,
            "operationId": "approve-op-1"
        }),
    )
    .await;
    assert_eq!(
        refused["error"]["code"], "CAPABILITY_UNAVAILABLE",
        "{refused}"
    );
    assert_eq!(refused["error"]["retryable"], false);
    assert!(
        member_writes().is_empty(),
        "a refused approval never reaches the engine: {:?}",
        member_writes()
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.66 (§4.59): the plural `attachments` form merges a forwarded
/// multi-attachment message into ONE upstream message — the fake engine's
/// send log carries the whole array on one line and the sent MessageRecord
/// one descriptor per entry. The singular/plural forms are mutually
/// exclusive (mixed keys and plural-with-voiceNote both answer
/// INVALID_REQUEST before any pending row exists), and an unknown plural
/// entry payload rejects the whole request with nothing left behind.
#[tokio::test]
async fn multi_attachment_send_merges_entries_into_one_upstream_message() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [77_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-FwdAttach" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let listed = request(
        &mut client,
        "conversations-1",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 10 }),
    )
    .await;
    let conversation_id = listed["result"]["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let attachment_lines = || {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| params.get("attachments").is_some())
            .collect::<Vec<_>>()
    };

    // The plural send: one upstream line, both data URIs on the array, the
    // caption as the message body.
    let sent = request(
        &mut client,
        "multi-send",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "multi-send-1",
            "attachments": [
                {
                    "dataBase64": "YXR0YWNobWVudCBieXRlcw==",
                    "sizeBytes": 16,
                    "filename": "notes.txt",
                    "contentType": "text/plain",
                    // BUG-11 wire 批（契约 1.294 §4.284）：条目级声明尺寸
                    // 成对进场 → 上行 data URI 两参数 + descriptor 两键。
                    "width": 640,
                    "height": 480
                },
                {
                    "dataBase64": "aGVsbG8=",
                    "sizeBytes": 5,
                    "filename": "clip.ogg",
                    "contentType": "audio/ogg"
                }
            ],
            "text": "two files"
        }),
    )
    .await;
    assert_eq!(sent["result"]["body"], "two files", "{sent}");
    let descriptors = sent["result"]["attachments"].as_array().unwrap();
    assert_eq!(descriptors.len(), 2);
    assert_eq!(descriptors[0]["filename"], "notes.txt");
    assert_eq!(descriptors[1]["filename"], "clip.ogg");
    // 声明尺寸落 descriptor（首个 tick 即终态盒），未声明条目两键不在。
    assert_eq!(descriptors[0]["width"], 640, "{sent}");
    assert_eq!(descriptors[0]["height"], 480, "{sent}");
    assert!(descriptors[1].get("width").is_none(), "{sent}");
    let lines = attachment_lines();
    assert_eq!(lines.len(), 1, "one upstream send: {lines:?}");
    let upstream = lines[0]["attachments"].as_array().unwrap();
    assert_eq!(upstream.len(), 2);
    assert_eq!(
        upstream[0].as_str().unwrap(),
        "data:text/plain;width=640;height=480;filename=notes.txt;base64,YXR0YWNobWVudCBieXRlcw=="
    );
    assert_eq!(
        upstream[1].as_str().unwrap(),
        "data:audio/ogg;filename=clip.ogg;base64,aGVsbG8="
    );

    // BUG-11 wire 批（契约 1.294 §4.284）：声明尺寸半边/越界都是
    // INVALID_REQUEST（双参同进退 + 1..=16384），在任何 pending 行之前判。
    for (id, width, height) in [
        ("multi-dims-half", json!(640), Value::Null),
        ("multi-dims-zero", json!(0), json!(480)),
        ("multi-dims-over", json!(16385), json!(480)),
    ] {
        let mut entry = json!({
            "dataBase64": "aGVsbG8=",
            "sizeBytes": 5,
            "contentType": "image/jpeg"
        });
        if !width.is_null() {
            entry["width"] = width.clone();
        }
        if !height.is_null() {
            entry["height"] = height.clone();
        }
        let rejected = request(
            &mut client,
            id,
            "messages.attachments.send",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "clientRequestId": id,
                "attachments": [entry],
            }),
        )
        .await;
        assert_eq!(
            rejected["error"]["code"], "INVALID_REQUEST",
            "{id}: {rejected}"
        );
        assert_eq!(rejected["error"]["retryable"], false, "{id}: {rejected}");
    }

    // Mixed forms: any singular key beside the array is INVALID_REQUEST —
    // no upstream line, no pending row.
    let mixed = request(
        &mut client,
        "multi-mixed",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "multi-mixed-1",
            "dataBase64": "aGVsbG8=",
            "sizeBytes": 5,
            "attachments": [
                { "dataBase64": "aGVsbG8=", "sizeBytes": 5 }
            ]
        }),
    )
    .await;
    assert_eq!(mixed["error"]["code"], "INVALID_REQUEST", "{mixed}");
    assert_eq!(mixed["error"]["retryable"], false);

    // Plural with voiceNote: the voice flag is a singular-form face.
    let voiced = request(
        &mut client,
        "multi-voice",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "multi-voice-1",
            "attachments": [
                {
                    "dataBase64": "aGVsbG8=",
                    "sizeBytes": 5,
                    "contentType": "audio/ogg"
                }
            ],
            "voiceNote": true
        }),
    )
    .await;
    assert_eq!(voiced["error"]["code"], "INVALID_REQUEST", "{voiced}");

    // A per-entry payload violation (size mismatch) rejects the whole
    // request with no pending row left behind.
    let bad_entry = request(
        &mut client,
        "multi-bad-entry",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "multi-bad-1",
            "attachments": [
                {
                    "dataBase64": "aGVsbG8=",
                    "sizeBytes": 4,
                    "contentType": "text/plain"
                }
            ]
        }),
    )
    .await;
    assert_eq!(bad_entry["error"]["code"], "INVALID_REQUEST", "{bad_entry}");

    // Exactly one upstream line landed (the successful plural send) and none
    // of the rejected requests left a row behind.
    assert_eq!(attachment_lines().len(), 1);
    let listed = request(
        &mut client,
        "list-final",
        "messages.list",
        json!({ "accountId": account_id, "conversationId": conversation_id, "limit": 50 }),
    )
    .await;
    let rows = listed["result"]["items"].as_array().unwrap();
    for rejected_id in [
        "multi-mixed-1",
        "multi-voice-1",
        "multi-bad-1",
        "multi-dims-half",
        "multi-dims-zero",
        "multi-dims-over",
    ] {
        assert!(
            rows.iter().all(|row| row["clientRequestId"] != rejected_id),
            "a rejected request leaves no row: {rejected_id}"
        );
    }

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.149 (§4.147): the GIF marker rides the send face verbatim —
/// the fixture engine's send log carries the `;gif=true` data-URI parameter
/// byte-for-byte on the flagged entries and nothing on the unflagged ones
/// (the engine maps the parameter to the official `Flags.GIF=8` bit), the
/// sent MessageRecord and the stored row both project `isGif` for the
/// sender's own bubble, and a top-level `gif` beside the plural array is
/// INVALID_REQUEST before any pending row exists (the plural face carries
/// per-entry `gif` instead).
#[tokio::test]
async fn gif_flag_send_rides_the_data_uri_verbatim() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [77_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GifFlag" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();
    let listed = request(
        &mut client,
        "conversations-1",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 10 }),
    )
    .await;
    let conversation_id = listed["result"]["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let attachment_lines = || {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| params.get("attachments").is_some())
            .collect::<Vec<_>>()
    };

    // The flagged singular send: the engine receives the verbatim parameter
    // and the response descriptor projects isGif.
    let sent = request(
        &mut client,
        "gif-send",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "gif-send-1",
            "dataBase64": "YXR0YWNobWVudCBieXRlcw==",
            "sizeBytes": 16,
            "filename": "tenor.gif",
            "contentType": "image/gif",
            "gif": true
        }),
    )
    .await;
    assert_eq!(sent["result"]["attachments"][0]["isGif"], true, "{sent}");
    let lines = attachment_lines();
    assert_eq!(lines.len(), 1, "one upstream send: {lines:?}");
    assert_eq!(
        lines[0]["attachments"][0].as_str().unwrap(),
        "data:image/gif;gif=true;filename=tenor.gif;base64,YXR0YWNobWVudCBieXRlcw=="
    );

    // The stored row carries the flag to the desktop's list face.
    let listed = request(
        &mut client,
        "list-gif",
        "messages.list",
        json!({ "accountId": account_id, "conversationId": conversation_id, "limit": 50 }),
    )
    .await;
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["clientRequestId"] == "gif-send-1")
        .expect("the gif row is listed");
    assert_eq!(row["attachments"][0]["isGif"], true);

    // The unflagged send stays byte-identical to the pre-1.149 frame: no
    // parameter, `isGif` false.
    let sent = request(
        &mut client,
        "plain-send",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "gif-send-2",
            "dataBase64": "aGVsbG8=",
            "sizeBytes": 5,
            "filename": "notes.txt",
            "contentType": "text/plain"
        }),
    )
    .await;
    assert_eq!(sent["result"]["attachments"][0]["isGif"], false, "{sent}");
    let lines = attachment_lines();
    assert_eq!(lines.len(), 2, "one upstream send per request: {lines:?}");
    assert_eq!(
        lines[1]["attachments"][0].as_str().unwrap(),
        "data:text/plain;filename=notes.txt;base64,aGVsbG8="
    );

    // The plural face: the flag rides per entry only — the flagged entry's
    // URI carries it, the plain entry's stays verbatim, and each descriptor
    // mirrors its own entry in array order.
    let sent = request(
        &mut client,
        "gif-multi",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "gif-send-3",
            "attachments": [
                {
                    "dataBase64": "YXR0YWNobWVudCBieXRlcw==",
                    "sizeBytes": 16,
                    "filename": "clip.mp4",
                    "contentType": "video/mp4",
                    "gif": true
                },
                {
                    "dataBase64": "aGVsbG8=",
                    "sizeBytes": 5,
                    "filename": "notes.txt",
                    "contentType": "text/plain"
                }
            ]
        }),
    )
    .await;
    let descriptors = sent["result"]["attachments"].as_array().unwrap();
    assert_eq!(descriptors.len(), 2);
    assert_eq!(descriptors[0]["isGif"], true);
    assert_eq!(descriptors[1]["isGif"], false);
    let lines = attachment_lines();
    assert_eq!(lines.len(), 3, "one upstream send per request: {lines:?}");
    let upstream = lines[2]["attachments"].as_array().unwrap();
    assert_eq!(upstream.len(), 2);
    assert_eq!(
        upstream[0].as_str().unwrap(),
        "data:video/mp4;gif=true;filename=clip.mp4;base64,YXR0YWNobWVudCBieXRlcw=="
    );
    assert_eq!(
        upstream[1].as_str().unwrap(),
        "data:text/plain;filename=notes.txt;base64,aGVsbG8="
    );

    // A top-level `gif` beside the array is a singular-form key: the same
    // deterministic INVALID_REQUEST the voiceNote/viewOnce markers answer,
    // with no upstream line and no row left behind.
    let mixed = request(
        &mut client,
        "gif-mixed",
        "messages.attachments.send",
        json!({
            "accountId": account_id,
            "conversationId": conversation_id,
            "clientRequestId": "gif-send-4",
            "attachments": [
                { "dataBase64": "aGVsbG8=", "sizeBytes": 5 }
            ],
            "gif": true
        }),
    )
    .await;
    assert_eq!(mixed["error"]["code"], "INVALID_REQUEST", "{mixed}");
    assert_eq!(mixed["error"]["retryable"], false);
    assert_eq!(attachment_lines().len(), 3);
    let listed = request(
        &mut client,
        "list-final",
        "messages.list",
        json!({ "accountId": account_id, "conversationId": conversation_id, "limit": 50 }),
    )
    .await;
    let rows = listed["result"]["items"].as_array().unwrap();
    assert!(
        rows.iter()
            .all(|row| row["clientRequestId"] != "gif-send-4"),
        "the rejected request leaves no row"
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.64 (§4.57): the groups.revokeInvites face. The handshake
/// advertises the method plus the `group-invite-revoke` capability; the
/// fail-closed ladder (unknown conversation, direct addressing, shape
/// violations) answers before any upstream write; and a fully valid request
/// rides into the honest engine-face refusal — the engine's updateGroup
/// carries the expiration family only (its compat §5 batch boundary), so the
/// member-family write answers CAPABILITY_UNAVAILABLE (retryable=false) with
/// nothing dispatched.
#[tokio::test]
async fn groups_revoke_invites_round_trip_and_guards() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [57_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    // The handshake carries the new face before anything else runs.
    let (_challenge, handshake) = authenticate_capture(&mut client, &secret).await;
    let capabilities = handshake["result"]["capabilities"].as_array().unwrap();
    for advertised in ["groups.revokeInvites", "group-invite-revoke"] {
        assert!(
            capabilities
                .iter()
                .any(|value| value.as_str() == Some(advertised)),
            "capabilities must advertise {advertised}: {capabilities:?}"
        );
    }

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-GroupRevoke" }),
    )
    .await;
    let finished = request(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let account_id = finished["result"]["id"].as_str().unwrap().to_string();

    // Sync so the fixture group row exists, then read its conversation id.
    let _ = request(
        &mut client,
        "contacts-sync",
        "contacts.sync",
        json!({ "accountId": account_id }),
    )
    .await;
    let listed = request(
        &mut client,
        "conversations-list",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["title"] == "Fixture Group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture group row must exist");

    // The refusal ladder, each before any upstream write.
    let unknown = request(
        &mut client,
        "revoke-unknown",
        "groups.revokeInvites",
        json!({
            "accountId": account_id,
            "conversationId": "no-such-conversation",
            "members": ["+15555550101"]
        }),
    )
    .await;
    assert_eq!(unknown["error"]["code"], "CONVERSATION_NOT_FOUND");
    assert_eq!(unknown["error"]["retryable"], false);
    let bad_params = request(
        &mut client,
        "revoke-bad-params",
        "groups.revokeInvites",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "members": ["+15555550101"],
            "unexpected": true
        }),
    )
    .await;
    assert_eq!(bad_params["error"]["code"], "INVALID_REQUEST");
    let empty_members = request(
        &mut client,
        "revoke-empty",
        "groups.revokeInvites",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "members": []
        }),
    )
    .await;
    assert_eq!(empty_members["error"]["code"], "INVALID_REQUEST");
    let direct_setup = request(
        &mut client,
        "revoke-direct-setup",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "contact",
            "peerKey": "+15555550102",
            "text": "direct guard",
            "clientRequestId": "group-revoke-0"
        }),
    )
    .await;
    let direct_conversation = direct_setup["result"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();
    let direct = request(
        &mut client,
        "revoke-direct",
        "groups.revokeInvites",
        json!({
            "accountId": account_id,
            "conversationId": direct_conversation,
            "members": ["+15555550102"]
        }),
    )
    .await;
    assert_eq!(direct["error"]["code"], "INVALID_REQUEST");

    let send_log_path = temp
        .path()
        .join("signal-data")
        .join(".fixture-send-log.jsonl");
    let revoke_writes = || -> Vec<Value> {
        fs::read_to_string(&send_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|params| params.get("removeMembers").is_some())
            .collect()
    };

    // A fully valid request rides past the ladder into the honest refusal:
    // the member-family updateGroup is the engine's compat §5 batch boundary,
    // so the face answers CAPABILITY_UNAVAILABLE and nothing is dispatched.
    let refused = request(
        &mut client,
        "revoke-group",
        "groups.revokeInvites",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation,
            "members": ["+15555550101"],
            "operationId": "revoke-op-1"
        }),
    )
    .await;
    assert_eq!(
        refused["error"]["code"], "CAPABILITY_UNAVAILABLE",
        "{refused}"
    );
    assert_eq!(refused["error"]["retryable"], false);
    assert!(
        revoke_writes().is_empty(),
        "a refused revoke never reaches the engine: {:?}",
        revoke_writes()
    );

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.150 (§4.149): the engine's voice-waveform pair rides the live
/// row verbatim — a voice descriptor carries the fixed 100-byte base64
/// waveform and the float-second duration byte-for-byte (the connector never
/// decodes or re-encodes), a plain attachment beside it in the same
/// dataMessage carries neither key (absent keys stay absent, the two faces
/// stay independent), and the store round-trip preserves both.
#[tokio::test]
async fn voice_waveform_pair_rides_the_live_row_verbatim() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [31_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;

    // The engine's fixed 100-byte waveform shape (bytes 0..=99, 136 base64
    // chars) — pinned whole so a re-encode or trim can never slip through.
    let waveform_100b = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw==";
    assert_eq!(waveform_100b.len(), 136);

    // Stage one envelope carrying a voice attachment and a plain image in
    // the same dataMessage, delivered in the finishLink receive burst.
    let extra_receives = temp
        .path()
        .join("signal-data")
        .join(".fixture-extra-receives.json");
    fs::create_dir_all(temp.path().join("signal-data")).unwrap();
    fs::write(
        &extra_receives,
        json!([
            {
                "source": "+15555550101",
                "timestamp": 60,
                "dataMessage": {
                    "message": "two attachments",
                    "attachments": [
                        {
                            "id": "att-voice",
                            "contentType": "audio/aac",
                            "size": 2048,
                            "isVoiceNote": true,
                            "waveform": waveform_100b,
                            "duration": 3.7
                        },
                        {
                            "id": "att-image",
                            "contentType": "image/png",
                            "size": 12
                        }
                    ]
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Voice-Waveform" }),
    )
    .await;
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let mut finished: Option<Value> = None;
    let mut upserted: Option<Value> = None;
    timeout(Duration::from_secs(5), async {
        while finished.is_none() || upserted.is_none() {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                finished = Some(frame);
                continue;
            }
            if frame.get("event").and_then(Value::as_str) == Some("message.upserted")
                && frame["data"]["sentAt"] == 60
            {
                upserted = Some(frame);
            }
        }
    })
    .await
    .expect("link finish must deliver the two-attachment receive");
    let account_id = finished.unwrap()["result"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let upserted = upserted.unwrap();
    let conversation_id = upserted["data"]["conversationId"]
        .as_str()
        .unwrap()
        .to_string();

    // The upsert event and the messages.list row are the same projection:
    // the voice descriptor carries the pair verbatim, the image descriptor
    // never grows the keys.
    let face = &upserted["data"]["attachments"];
    assert_eq!(face[0]["id"], "att-voice");
    assert_eq!(face[0]["isVoiceNote"], true);
    assert_eq!(face[0]["waveform"], waveform_100b, "{face}");
    assert_eq!(face[0]["duration"], 3.7, "{face}");
    assert_eq!(face[1]["id"], "att-image");
    assert_eq!(face[1]["isVoiceNote"], false);
    assert!(
        face[1].get("waveform").is_none(),
        "absent keys stay absent: {face}"
    );
    assert!(
        face[1].get("duration").is_none(),
        "absent keys stay absent: {face}"
    );

    let listed = request(
        &mut client,
        "list-1",
        "messages.list",
        json!({ "accountId": account_id, "conversationId": conversation_id, "limit": 50 }),
    )
    .await;
    let row = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["sentAt"] == 60)
        .expect("the two-attachment row is stored");
    let descriptors = &row["attachments"];
    assert_eq!(descriptors.as_array().unwrap().len(), 2);
    let voice = &descriptors[0];
    assert_eq!(voice["id"], "att-voice");
    assert_eq!(voice["isVoiceNote"], true);
    assert_eq!(voice["waveform"], waveform_100b, "{voice}");
    assert_eq!(voice["duration"], 3.7, "{voice}");
    let image = &descriptors[1];
    assert_eq!(image["id"], "att-image");
    assert_eq!(image["isVoiceNote"], false);
    assert!(image.get("waveform").is_none(), "{image}");
    assert!(image.get("duration").is_none(), "{image}");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// Contract 1.190 (§4.190 ②+⑤) — the group dead-letter fix and the ledger
/// faces, end to end through a real connector process and the fake engine:
/// a real `messages.sendText` round trip creates the GROUP's outgoing row,
/// a group member's DELIVERED receipt envelope (whose own direct
/// conversation holds no such row — the exact pre-1.190 dead-letter shape)
/// finds it through the account-level sentAt find, the host lane observes
/// `message.statusChanged` plus the additive `message.receiptsChanged`, and
/// the `messages.receipts` read face serves the stamped per-recipient
/// ledger. The receipt rides the extra-receives marker with the typing send
/// as the flush trigger.
#[tokio::test]
async fn group_receipt_finds_the_group_row_and_serves_the_ledger() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [77_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;
    let started = request(&mut client, "start", "runtime.start", json!({})).await;
    let engine_pid = started["result"]["pid"].as_u64().unwrap() as u32;
    let link = request(
        &mut client,
        "link-start",
        "link.start",
        json!({ "deviceName": "KT-Group-Receipt" }),
    )
    .await;
    send_request_frame(
        &mut client,
        "link-finish",
        "link.finish",
        json!({ "linkSessionId": link["result"]["linkSessionId"] }),
    )
    .await;
    let mut account_id = String::new();
    timeout(Duration::from_secs(5), async {
        loop {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("link-finish") {
                account_id = frame["result"]["id"].as_str().unwrap().to_string();
                return;
            }
        }
    })
    .await
    .expect("the link burst answers the account id");

    // The fixture links with a group conversation; the listing answers its
    // opaque id (the listing runs before the receipt marker exists, so no
    // premature flush).
    let listed = request(
        &mut client,
        "list-groups",
        "conversations.list",
        json!({ "accountId": account_id, "limit": 50 }),
    )
    .await;
    let group_conversation_id = listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "group")
        .map(|row| row["id"].as_str().unwrap().to_string())
        .expect("the fixture links with a group conversation");

    // The group send whose receipt the member will return.
    let sent = request(
        &mut client,
        "send-group",
        "messages.sendText",
        json!({
            "accountId": account_id,
            "kind": "group",
            "peerKey": "ZmFrZS1ncm91cC0x",
            "text": "group receipt probe",
            "clientRequestId": "grp-receipt-1"
        }),
    )
    .await;
    assert_eq!(sent["result"]["status"], "sent");
    let sent_at = sent["result"]["sentAt"].as_u64().expect("the row's stamp");
    let message_id = sent["result"]["id"].as_str().unwrap().to_string();

    // The roster member's DELIVERED receipt: the envelope's own timestamp is
    // the arrival stamp (contract 1.32). The member's own direct
    // conversation exists (the fixture peer materializes at link) but holds
    // no row at the group's sentAt — the exact pre-1.190 dead-letter shape
    // the account-level find fixes; the roster the link-time sync captured
    // carries the member, so the qualification gate passes.
    fs::write(
        temp.path()
            .join("signal-data")
            .join(".fixture-extra-receives.json"),
        json!([{
            "source": "+15555550101",
            "timestamp": sent_at + 1000,
            "receiptMessage": {
                "isDelivery": true,
                "timestamp": [sent_at]
            }
        }])
        .to_string(),
    )
    .unwrap();
    let mut interleaved = Vec::new();
    send_request_frame(
        &mut client,
        "typing-flush",
        "presence.setTypingMessage",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "stop": true
        }),
    )
    .await;
    let typing_reply = timeout(Duration::from_secs(5), async {
        loop {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").and_then(Value::as_str) == Some("typing-flush") {
                return frame;
            }
            interleaved.push(frame);
        }
    })
    .await
    .expect("the typing flush answers");
    assert!(
        typing_reply.get("result").is_some(),
        "the typing flush must succeed: {typing_reply:?}"
    );

    // The receipt notification precedes the typing reply on the wire, but
    // the connector ingests it asynchronously — the events may trail the
    // reply. Keep collecting (bounded quiet window) until the fold's faces
    // arrive.
    timeout(Duration::from_secs(5), async {
        loop {
            let frame: Value =
                serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
            if frame.get("requestId").is_none() {
                interleaved.push(frame);
                let status = interleaved.iter().any(|frame| {
                    frame.get("event").and_then(Value::as_str) == Some("message.statusChanged")
                        && frame["data"]["messageId"] == json!(message_id)
                        && frame["data"]["status"] == "delivered"
                });
                let ledger = interleaved.iter().any(|frame| {
                    frame.get("event").and_then(Value::as_str) == Some("message.receiptsChanged")
                        && frame["data"]["messageId"] == json!(message_id)
                });
                if status && ledger {
                    return;
                }
            }
        }
    })
    .await
    .expect("the receipt fold's events ride the host lane");

    let status = interleaved
        .iter()
        .find(|frame| {
            frame.get("event").and_then(Value::as_str) == Some("message.statusChanged")
                && frame["data"]["messageId"] == json!(message_id)
                && frame["data"]["status"] == "delivered"
        })
        .unwrap_or_else(|| panic!("no delivered transition; interleaved: {interleaved:?}"));
    assert_eq!(status["data"]["deliveredAt"], json!(sent_at + 1000));

    let ledger_event = interleaved
        .iter()
        .find(|frame| frame.get("event").and_then(Value::as_str) == Some("message.receiptsChanged"))
        .expect("the per-recipient ledger event rides the host lane");
    assert_eq!(ledger_event["data"]["messageId"], json!(message_id));
    let receipts = ledger_event["data"]["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["recipient"], "+15555550101");
    assert_eq!(receipts[0]["deliveredAt"], json!(sent_at + 1000));

    // The read face serves the same ledger through the wire method.
    let read = request(
        &mut client,
        "read-receipts",
        "messages.receipts",
        json!({
            "accountId": account_id,
            "conversationId": group_conversation_id,
            "messageId": message_id
        }),
    )
    .await;
    let items = read["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{read}");
    assert_eq!(items[0]["recipient"], "+15555550101");
    assert_eq!(items[0]["deliveredAt"], json!(sent_at + 1000));
    assert!(items[0].get("readAt").is_none(), "absent tiers stay absent");

    drop(client);
    wait_for_process_exit(engine_pid).await;
    assert_clean_exit(&mut connector).await;
}

/// 契约 1.283（§4.267）events.list 的 wire 面：冷启动 → reset、带 token 续读 →
/// 不 reset、旧代际 → tokenMismatch、越界游标 → aheadOfLog，以及四类畸形参数
/// 在宿主面 fail-closed（不是被静默忽略）。
#[tokio::test]
async fn events_list_answers_the_ledger_cursor_face_over_the_wire() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = temp.path().join("connector.sock");
    let secret_file = temp.path().join("bootstrap.secret");
    let secret = [41_u8; 32];
    write_secret_file(&secret_file, &secret);

    let mut connector = spawn_connector(temp.path(), &endpoint, &secret_file);
    wait_for_path(&endpoint).await;
    let stream = UnixStream::connect(&endpoint).await.unwrap();
    let mut client = Framed::new(stream, LinesCodec::new());
    authenticate(&mut client, &secret).await;

    // A bare request is a cold start: a reset that carries no events and names
    // the token the caller must present from now on.
    let cold = request(&mut client, "events-cold", "events.list", json!({})).await;
    assert!(cold.get("error").is_none(), "{cold}");
    let result = &cold["result"];
    assert_eq!(result["reset"], json!(true));
    assert_eq!(result["resetReason"], json!("coldStart"));
    assert_eq!(result["trimmedThroughSeq"], json!(0));
    assert_eq!(result["events"], json!([]));
    assert_eq!(result["nextAfterSeq"], json!(0));
    assert_eq!(result["truncated"], json!(false));
    let token = result["token"].as_str().expect("token").to_string();
    assert_eq!(token.len(), 32, "one 16-byte generation stamp");

    // The same generation resumes: no reset, an empty page, and the cursor
    // stays where it was.
    let resumed = request(
        &mut client,
        "events-resume",
        "events.list",
        json!({ "afterSeq": 0, "token": token, "limit": 10 }),
    )
    .await;
    assert_eq!(resumed["result"]["reset"], json!(false), "{resumed}");
    assert!(resumed["result"].get("resetReason").is_none());
    assert_eq!(resumed["result"]["events"], json!([]));
    assert_eq!(resumed["result"]["nextAfterSeq"], json!(0));

    // A token this ledger never minted means its generation rotated.
    let stale = request(
        &mut client,
        "events-stale",
        "events.list",
        json!({ "afterSeq": 0, "token": "00000000000000000000000000000000" }),
    )
    .await;
    assert_eq!(stale["result"]["reset"], json!(true));
    assert_eq!(stale["result"]["resetReason"], json!("tokenMismatch"));
    assert_eq!(stale["result"]["events"], json!([]));

    // A cursor ahead of every assigned seq belongs to a ledger that is gone.
    let ahead = request(
        &mut client,
        "events-ahead",
        "events.list",
        json!({ "afterSeq": 9, "token": token }),
    )
    .await;
    assert_eq!(ahead["result"]["reset"], json!(true));
    assert_eq!(ahead["result"]["resetReason"], json!("aheadOfLog"));

    // Malformed cursors fail closed at the host face.
    let oversized = "f".repeat(129);
    for (id, params) in [
        ("events-negative", json!({ "afterSeq": -1 })),
        ("events-zero-limit", json!({ "limit": 0 })),
        ("events-over-limit", json!({ "limit": 501 })),
        ("events-long-token", json!({ "token": oversized })),
        ("events-unknown-key", json!({ "since": 1 })),
    ] {
        let rejected = request(&mut client, id, "events.list", params).await;
        assert_eq!(
            rejected["error"]["code"],
            json!("INVALID_REQUEST"),
            "request {id} must fail closed: {rejected}"
        );
    }

    drop(client);
    assert_clean_exit(&mut connector).await;
}
