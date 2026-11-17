// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 0 safety net (docs/optimization-plan.md, 2026-08-25): machine-checked
//! consistency between `schemas/connector-api-v1.schema.json` and the code, so
//! contract drift fails the test suite instead of shipping silently.
//!
//! Code-side sets are extracted mechanically where a stable source exists:
//!
//! - methods: `PHASE2_CAPABILITIES` (src/lib.rs:35) plus `"handshake"`, which is
//!   handled before capability dispatch (src/host.rs:307). Every schema method
//!   must also appear as a dispatch literal in src/host.rs.
//! - events: every `HostEvent::new("<name>", ...)` literal in src/ (the wire
//!   serializer is the emission boundary).
//! - error codes: every `ApiError::new("<CODE>", ...)` literal in src/.
//! - numeric bounds: every schema length/numeric constraint the code also
//!   enforces through a named constant (optimization-plan A8; this is the
//!   gate that keeps A5-class drift — schema 128 vs code 256 — from
//!   recurring). Bounds without a natural code-constant or schema
//!   representation are inventoried with reasons on the bounds test below
//!   (optimization-plan §6.4 M3.4).
//!
//! Known drift is encoded in the explicit allowlists below, each with a reason
//! and the phase that resolves it. Any drift outside an allowlist fails.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use kt_signal_connector::PHASE2_CAPABILITIES;
use kt_signal_connector::engine::{
    MAX_ATTACHMENT_BLUR_HASH_CHARS, MAX_INBOUND_ATTACHMENTS, MAX_RECEIVE_ID_CHARS,
    MAX_SYNC_CALL_ID_CHARS, MAX_SYNC_CALL_LINK_KEY_CHARS, MAX_SYNC_DELETE_GROUP_MESSAGES,
    MAX_SYNC_DELETE_GROUPS, MAX_SYNC_IDENTITY_KEY_CHARS,
};
use kt_signal_connector::history_attachment::MAX_PLAINTEXT_BYTES;
use kt_signal_connector::protocol::MAX_REQUEST_ID_BYTES;
use kt_signal_connector::service::{
    CALL_GROUP_MASTER_KEY_B64_CHARS, CALL_LINK_ROOM_ID_B64_CHARS, CALL_LINK_ROOT_KEY_B64_MAX_CHARS,
    GROUP_CHANGED_MAX_CHANGES, GROUP_DESCRIPTION_MAX_BYTES, GROUP_MEMBER_LABEL_MAX_BYTES,
    GROUP_NAME_MAX_BYTES, IDENTITY_PEER_KEY_MAX_CHARS, IDENTITY_SAFETY_NUMBER_MAX_CHARS,
    MARK_RECEIPT_MESSAGE_IDS_LIMIT, MAX_ALIAS_BYTES, MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENT_CONTENT_TYPE_BYTES, MAX_ATTACHMENT_DIMENSION_PX, MAX_ATTACHMENT_DIMENSION_ROWS,
    MAX_ATTACHMENT_FILENAME_BYTES, MAX_ATTACHMENT_ID_BYTES, MAX_AVATAR_DATA_URI_CHARS,
    MAX_CALL_LINK_KEY_CHARS, MAX_CHAT_FOLDER_BATCH, MAX_CHAT_FOLDER_ID_CHARS,
    MAX_DELETE_FOR_ME_MESSAGES, MAX_DEVICE_NAME_BYTES, MAX_EMOJI_BYTES, MAX_GROUP_MEMBER_ID_CHARS,
    MAX_GROUP_MEMBERS, MAX_LOCATOR_FIELD_CHARS, MAX_LOCATOR_HASH_CHARS,
    MAX_NOTIFICATION_PROFILE_BATCH, MAX_NOTIFICATION_PROFILE_ID_CHARS, MAX_OPAQUE_ID_BYTES,
    MAX_PIN_CONVERSATION_ID_CHARS, MAX_PREVIEW_DESCRIPTION_BYTES, MAX_PREVIEW_IMAGE_DATA_URI_CHARS,
    MAX_PREVIEW_TITLE_BYTES, MAX_PREVIEW_URL_BYTES, MAX_PROFILE_ABOUT_BYTES,
    MAX_PROFILE_NAME_BYTES, MAX_SEND_MENTIONS, MAX_SNAPSHOT_DIR_BYTES, MAX_STICKER_EMOJI_CHARS,
    MAX_STICKER_PACK_ID_CHARS, MAX_STICKER_PACK_KEY_CHARS, MAX_STORY_DISTRIBUTION_ID_CHARS,
    MAX_STORY_LIST_BATCH, MAX_STORY_LIST_ID_CHARS, MAX_STORY_PREVIEW_TITLE_BYTES,
    MAX_STORY_PREVIEW_URL_CHARS, MAX_TEXT_BYTES, PHONE_LOOKUP_MAX_ENTRIES,
    REPORT_SPAM_MESSAGE_IDS_LIMIT, STICKER_PACK_BROWSE_ID_HEX_CHARS,
    STICKER_PACK_SYNC_KEY_B64_CHARS, USERNAME_LOOKUP_ENTRY_MAX_CHARS, USERNAME_LOOKUP_MAX_ENTRIES,
    USERNAME_MAX_WIRE_CHARS,
};
use kt_signal_connector::store::{
    EVENT_PAGE_MAX_LIMIT, EVENT_TOKEN_MAX_CHARS, MAX_MESSAGE_RECEIPT_RECIPIENTS, MAX_PAGE_LIMIT,
};

/// Events the code emits but the schema event enum does not declare. Currently
/// none: `runtime.resourcePressure` (emitted by the RSS sampler bridge,
/// src/host.rs) was registered in the schema by optimization-plan Phase 1,
/// recording existing behavior rather than changing the protocol.
const EVENT_CODE_ONLY_ALLOWLIST: &[&str] = &[];

/// Events the schema declares but the code never emits. Currently none:
/// `message.statusChanged` gained a producer in optimization-plan Phase 2
/// (send completion paths in src/service.rs) and is emitted like every other
/// event, so it is covered by the plain set diff.
const EVENT_SCHEMA_ONLY_ALLOWLIST: &[&str] = &[];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn schema() -> Value {
    let path = repo_root().join("schemas/connector-api-v1.schema.json");
    let raw = fs::read_to_string(&path).expect("schema file must be readable");
    serde_json::from_str(&raw).expect("schema file must be valid JSON")
}

fn schema_enum(pointer: &str) -> BTreeSet<String> {
    schema()
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("schema must declare an enum at {pointer}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("schema enum entries must be strings")
                .to_string()
        })
        .collect()
}

fn schema_methods() -> BTreeSet<String> {
    schema_enum("/$defs/request/properties/method/enum")
}

fn schema_events() -> BTreeSet<String> {
    schema_enum("/$defs/event/properties/event/enum")
}

fn schema_error_codes() -> BTreeSet<String> {
    schema_enum("/$defs/error/properties/code/enum")
}

/// All Rust sources under src/, as (relative path, content) pairs. Test-only
/// `#[cfg(test)]` modules are part of the crate's code and are scanned too:
/// a literal that only a unit test uses is still a defined code/event name.
fn sources() -> Vec<(String, String)> {
    let src = repo_root().join("src");
    let mut entries: Vec<(String, String)> = fs::read_dir(&src)
        .expect("src/ must be readable")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&path).unwrap(),
            )
        })
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "src/ must contain Rust sources");
    entries
}

/// Extract the string literal in the first argument position of every
/// `Constructor::new("literal", ...)` call site, tolerating line breaks
/// between the opening parenthesis and the literal.
fn first_string_literals(sources: &[(String, String)], constructor: &str) -> BTreeSet<String> {
    let marker = format!("{constructor}::new(");
    let mut found = BTreeSet::new();
    for (_name, content) in sources {
        let mut rest = content.as_str();
        while let Some(at) = rest.find(&marker) {
            rest = &rest[at + marker.len()..];
            let trimmed = rest.trim_start();
            let Some(literal) = trimmed.strip_prefix('"') else {
                continue;
            };
            let Some(end) = literal.find('"') else {
                continue;
            };
            found.insert(literal[..end].to_string());
            rest = &literal[end..];
        }
    }
    found
}

fn code_events() -> BTreeSet<String> {
    first_string_literals(&sources(), "HostEvent")
}

fn code_error_codes() -> BTreeSet<String> {
    first_string_literals(&sources(), "ApiError")
        .into_iter()
        .filter(|literal| {
            !literal.is_empty()
                && literal
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .collect()
}

#[test]
fn schema_methods_match_code_methods() {
    let schema_methods = schema_methods();

    // Code-side method list: the advertised capability list (src/lib.rs:32-35)
    // plus "handshake", which is answered before capability dispatch
    // (src/host.rs:307).
    let mut code_methods: BTreeSet<String> = PHASE2_CAPABILITIES
        .iter()
        .map(|method| (*method).to_string())
        .collect();
    code_methods.insert("handshake".to_string());

    let schema_only: Vec<_> = schema_methods.difference(&code_methods).collect();
    let code_only: Vec<_> = code_methods.difference(&schema_methods).collect();
    assert!(
        schema_only.is_empty() && code_only.is_empty(),
        "method drift: schema-only {schema_only:?}, code-only {code_only:?}"
    );

    // Every schema method must be dispatched by the host: it appears as a
    // string literal in src/host.rs.
    let host = sources()
        .into_iter()
        .find(|(name, _)| name == "host.rs")
        .expect("src/host.rs must exist")
        .1;
    for method in &schema_methods {
        assert!(
            host.contains(&format!("\"{method}\"")),
            "schema method {method} has no dispatch literal in src/host.rs"
        );
    }
}

#[test]
fn schema_error_codes_match_code_error_codes() {
    let schema_codes = schema_error_codes();
    let code_codes = code_error_codes();
    assert!(
        !code_codes.is_empty(),
        "error-code scan found no ApiError::new literals; the scanner is broken"
    );

    let schema_only: Vec<_> = schema_codes.difference(&code_codes).collect();
    let code_only: Vec<_> = code_codes.difference(&schema_codes).collect();
    assert!(
        schema_only.is_empty() && code_only.is_empty(),
        "error-code drift: schema-only {schema_only:?}, code-only {code_only:?}"
    );
}

#[test]
fn schema_events_match_emitted_events_within_allowlist() {
    let schema_events = schema_events();
    let emitted = code_events();
    assert!(
        !emitted.is_empty(),
        "event scan found no HostEvent::new literals; the scanner is broken"
    );

    let allowlisted_code_only: BTreeSet<&str> = EVENT_CODE_ONLY_ALLOWLIST.iter().copied().collect();
    let allowlisted_schema_only: BTreeSet<&str> =
        EVENT_SCHEMA_ONLY_ALLOWLIST.iter().copied().collect();

    let code_only: BTreeSet<&str> = emitted
        .iter()
        .map(String::as_str)
        .filter(|event| !schema_events.contains(*event))
        .collect();
    let schema_only: BTreeSet<&str> = schema_events
        .iter()
        .map(String::as_str)
        .filter(|event| !emitted.contains(*event))
        .collect();

    assert_eq!(
        code_only, allowlisted_code_only,
        "code emits events outside the schema and the allowlist (or an allowlisted \
         drift was fixed — remove its entry): {code_only:?}"
    );
    assert_eq!(
        schema_only, allowlisted_schema_only,
        "schema declares events the code never emits, outside the allowlist (or an \
         allowlisted drift was fixed — remove its entry): {schema_only:?}"
    );
}

/// The integer a schema constraint declares at `pointer` under `key`
/// (`maxLength`, `maximum`, ...). A missing constraint panics: every bound
/// listed below is part of the host contract and must stay declared.
fn schema_bound(pointer: &str, key: &str) -> u64 {
    schema()
        .pointer(pointer)
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("schema must declare {key} at {pointer}"))
}

/// Numeric bounds the schema declares and the code enforces through a named
/// constant must be equal (A8). The schema is the host-facing contract, the
/// constants are the connector's enforcement; either side drifting changes
/// what hosts may send versus what the connector accepts. This is the gate
/// that would have caught A5 (schema attachmentId maxLength 128 while the
/// code enforced 256).
///
/// Pairs cover every code constant that enforces a schema constraint. Every
/// remaining numeric bound was re-evaluated item by item (optimization-plan
/// §6.4 M3.4) and stays outside the diff for a stated reason — either the
/// code enforces it by a different mechanism than a named constant, or it
/// has no schema representation at all:
///
/// Schema-only bounds without an enforcing code constant:
/// - cursor/before `maxLength` 256: cursors fail closed by decode and key
///   binding (`Store::decode_*_cursor`), never by length; a length constant
///   would not be the enforcement, so pairing it would be fabricated.
/// - error message `maxLength` 256: messages are short code-authored
///   literals; no constant governs them.
/// - proxyGroupId `maxLength` 128: unknown ids fail closed by launch-plan
///   lookup (`PROXY_GROUP_NOT_FOUND`); launcher ids additionally obey the
///   tighter 32-byte grammar at startup (src/groups.rs), which is a
///   launcher-input rule, not a wire-bound constant.
/// - `minLength`/`minimum` 1 and pid/rssBytes representation bounds:
///   inherent shape constraints enforced structurally (required fields,
///   u64/u32 types); no named constant exists to pair.
///
/// Code-only bounds without a schema representation (internal capacity —
/// gated by behavior tests per optimization-plan §6.4 M3.5, not by pairs):
/// - receive queue budgets (256 items / 2 MiB global, 64 items / 512 KiB per
///   account since contract 1.196's internal companion) and internal channel
///   capacities: in-process queues, not wire contracts.
/// - host admission (128 global / 32 per account / 8 MiB aggregate) and
///   per-method dispatch lanes: connection-local admission control.
/// - inbound text projections (4 KiB preview / 128 KiB persisted body),
///   retention (2000 rows/conversation, 256 delete operations): store-side
///   bounds.
/// - RSS pressure policy (512/420 MiB over 3/2 samples, src/resource.rs):
///   operational thresholds pinned by
///   `default_rss_policy_matches_the_documented_budget`.
/// - proxy-group ceiling 8 (src/groups.rs) and the per-engine account
///   ceiling 8 (M3.3, `MAX_ACCOUNTS_PER_ENGINE`): launcher/store policy with
///   no natural schema numeric hook; pinned by
///   `group_count_is_hard_capped_at_eight_including_default` and
///   `eighth_account_links_but_a_ninth_is_refused_at_the_ceiling`.
/// - sticker browse result bounds (contract 1.36, §4.32):
///   `MAX_STICKER_MANIFEST_TITLE_CHARS` / `MAX_STICKER_MANIFEST_AUTHOR_CHARS`
///   (256) and `MAX_STICKER_MANIFEST_ENTRIES` (1024), plus
///   `MAX_STICKER_IMAGE_BASE64_CHARS` (409600) — the schema's `result` is a
///   free-form object, so these live on the engine-result projection
///   (`manifest_from_engine` / `image_from_engine`) and are pinned by the
///   §4.32 integration test.
/// - the pinned-list entry cap (contract 1.36, §4.33,
///   `MAX_PINNED_CONVERSATIONS` = 128): same free-form-result situation,
///   enforced in `pinned_conversations_result` and pinned by the §4.33
///   integration test.
/// - the sticker-pack sync list cap (contract 1.37, §4.34,
///   `MAX_STICKER_PACK_SYNCS` = 256): same free-form-result situation,
///   enforced in `sticker_pack_syncs_result` and pinned by the §4.34
///   integration test.
/// - the group roster cap (contract 1.40, §4.39, `MAX_GROUP_MEMBERS` = 1001)
///   and the roster address cap (`MAX_GROUP_MEMBER_ID_CHARS` = 128): on the
///   §4.39 sync/read faces the schema's `result` is a free-form object, so
///   the bounds live on the sync capture (`group_extra_json`,
///   src/supervisor.rs) and the read projection (`project_group_roster`,
///   src/service.rs), pinned by the §4.39 unit and integration tests; the
///   §4.44 group-management write face (contract 1.45) mirrors both caps in
///   the schema and is pinned by the pairs below.
/// - the blocked-list entry cap (contract 1.46, §4.45,
///   `MAX_BLOCKED_CONVERSATIONS` = 256): same free-form-result situation,
///   enforced in `blocked_conversations_result` and pinned by the §4.45 unit
///   and integration tests; the §4.47 setBlocked result face reuses the same
///   projection verbatim.
/// - the §4.47 avatar result-face bound (contract 1.48,
///   `MAX_AVATAR_DATA_URI_CHARS` = 13,981,080): a coarse result-side guard
///   enforced in `avatar_from_engine` on the engine result (the schema's
///   `result` is a free-form object, so there is no schema numeric hook);
///   the precise decoded budget is the decode + `byteSize` cross-check,
///   pinned by the §4.47 unit and integration tests.
/// - the §4.45 avatar budget (`MAX_AVATAR_BYTES` = 10 MiB decoded): the code
///   bound is on the decoded size, which the schema can only approximate —
///   the data-URI `maxLength` 13981080 is the padded-base64 encoding of the
///   ceiling plus a fixed prefix margin, not the enforcement itself, so
///   pairing it would be fabricated; pinned by the §4.45 unit tests.
/// - the §4.45 universal-timer face (contract 1.46): `expireSeconds`
///   maximum 4294967295 is enforced structurally by the `u32` type at params
///   deserialization (same situation as `stickerPackSetSyncParams.position`);
///   the schema `maximum` mirrors the type.
/// - the §4.46 backup-export caps (contract 1.47): the artifact caps
///   (`MAX_ARTIFACT_LINE_BYTES` 1 MiB / `MAX_ARTIFACT_LINES` 4M /
///   `MAX_ARTIFACT_TOTAL_BYTES` 2 GiB / `MAX_ARTIFACT_BODY_BYTES` 128 KiB)
///   bind the connector's own artifact build against the engine's §10.2
///   gate — there is no params-side schema number to pair them with (the
///   result mirrors the engine honestly). The wire-side bounds that exist —
///   `backupsExportFileReadChunkParams.offset` `minimum` 0 (a `u64`, checked
///   by the sequential-offset rule, not by a constant) and the `file` enum
///   {metadata, main} (structural, enforced by the two-value match before
///   the filesystem is touched) — are enforced by mechanism, not by a named
///   constant. The chunk ceiling (`CHUNK_BYTES` 262_144) is pinned by the
///   §4.46 integration test's `chunkBytes` assertion.
/// - the §4.67 story recipient-array cap (contract 1.76,
///   `MAX_STORY_RECIPIENTS` = 1001): the schema `maxItems` mirrors the
///   §4.39 roster ceiling, but the pairing stays inventory-side like the
///   story send's sibling faces — the array is the caller-computed
///   expansion forwarded verbatim, the prepare ladder owns the cap, and
///   the §4.67 unit tests pin both sides.
/// - the §4.78 chat-folder list cap (contract 1.95,
///   `MAX_CHAT_FOLDERS` = 64): the schema's `result` is a free-form object,
///   so the cap lives on the engine-result projection
///   (`chat_folder_syncs_result`) and is pinned by the §4.78 unit and
///   integration tests; the write-batch and identity bounds that do have a
///   schema hook are pinned by the pairs below.
/// - the §4.117 engine-notification event faces (contract 1.134): the
///   subject-id bounds (`group.terminated` groupId / terminator /
///   `contact.profileUpdated` aci at maxLength 128/64) ride the receive-id
///   discipline (`MAX_RECEIVE_ID_CHARS`) and the groupUpdated editor bound,
///   pinned inventory-side like the story.received sibling event faces; the
///   `conversation.stateChanged` conversations array carries no connector
///   cap on purpose — the engine's own 256-entry batch cap and overflow
///   tail marker govern the wire, and the connector never trims (the F
///   red line), pinned by the §4.117 unit and integration tests.
#[test]
fn schema_numeric_bounds_match_code_constants() {
    let pairs: &[(&str, &str, u64)] = &[
        ("/$defs/requestId", "maxLength", MAX_REQUEST_ID_BYTES as u64),
        // Contract 1.291 (§4.277 B): the migration status code is clamped to the
        // same bound the connector enforces before it writes the face.
        (
            "/$defs/storeMigration/properties/code",
            "maxLength",
            kt_signal_connector::pool::STORE_MIGRATION_CODE_MAX_CHARS as u64,
        ),
        ("/$defs/opaqueId", "maxLength", MAX_OPAQUE_ID_BYTES as u64),
        (
            "/$defs/linkStartParams/properties/deviceName",
            "maxLength",
            MAX_DEVICE_NAME_BYTES as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/text",
            "maxLength",
            MAX_TEXT_BYTES as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/peerKey",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/peerTitle",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        (
            "/$defs/contactsListParams/properties/query",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        (
            "/$defs/groupsGetParams/properties/groupKey",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        (
            "/$defs/contactsSetLocalAliasParams/properties/peerKey",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        (
            "/$defs/contactsSetLocalAliasParams/properties/alias",
            "maxLength",
            MAX_ALIAS_BYTES as u64,
        ),
        (
            "/$defs/messagesSendReactionParams/properties/emoji",
            "maxLength",
            MAX_EMOJI_BYTES as u64,
        ),
        (
            "/$defs/messagesAttachmentsOpenParams/properties/attachmentId",
            "maxLength",
            MAX_ATTACHMENT_ID_BYTES as u64,
        ),
        (
            "/$defs/messagesSendAttachmentParams/properties/dataBase64",
            "maxLength",
            (4 * MAX_ATTACHMENT_BYTES.div_ceil(3)) as u64,
        ),
        (
            "/$defs/messagesSendAttachmentParams/properties/sizeBytes",
            "maximum",
            MAX_ATTACHMENT_BYTES as u64,
        ),
        (
            "/$defs/messagesSendAttachmentParams/properties/filename",
            "maxLength",
            MAX_ATTACHMENT_FILENAME_BYTES as u64,
        ),
        (
            "/$defs/messagesSendAttachmentParams/properties/contentType",
            "maxLength",
            MAX_ATTACHMENT_CONTENT_TYPE_BYTES as u64,
        ),
        (
            "/$defs/messagesSendAttachmentParams/properties/text",
            "maxLength",
            MAX_TEXT_BYTES as u64,
        ),
        // §4.127 blur placeholder (contract 1.137): the singular key and the
        // plural per-entry key share the receive face's own bound — one
        // constant, both directions.
        (
            "/$defs/messagesSendAttachmentParams/properties/blurHash",
            "maxLength",
            MAX_ATTACHMENT_BLUR_HASH_CHARS as u64,
        ),
        (
            "/$defs/messagesSendAttachmentEntry/properties/blurHash",
            "maxLength",
            MAX_ATTACHMENT_BLUR_HASH_CHARS as u64,
        ),
        // §4.126 link-preview entry bounds (the §5.10 family, now declared
        // in the schema together with the 1.137 date key).
        (
            "/$defs/messagesSendTextParams/properties/previews/items/properties/url",
            "maxLength",
            MAX_PREVIEW_URL_BYTES as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/previews/items/properties/title",
            "maxLength",
            MAX_PREVIEW_TITLE_BYTES as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/previews/items/properties/description",
            "maxLength",
            MAX_PREVIEW_DESCRIPTION_BYTES as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/previews/items/properties/imageDataUri",
            "maxLength",
            MAX_PREVIEW_IMAGE_DATA_URI_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStickerParams/properties/packId",
            "maxLength",
            MAX_STICKER_PACK_ID_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStickerParams/properties/packKey",
            "maxLength",
            MAX_STICKER_PACK_KEY_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStickerParams/properties/emoji",
            "maxLength",
            MAX_STICKER_EMOJI_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStickerParams/properties/image/properties/dataBase64",
            "maxLength",
            (4 * MAX_ATTACHMENT_BYTES.div_ceil(3)) as u64,
        ),
        (
            "/$defs/messagesSendStickerParams/properties/image/properties/sizeBytes",
            "maximum",
            MAX_ATTACHMENT_BYTES as u64,
        ),
        // Sticker pack browsing (contract 1.36, §4.32): the browse-face pack
        // id is exactly the official 32-hex form (both minLength and
        // maxLength pinned to the constant); title/author carry the KT
        // 256-char bound; the manifest entry cap is the schema maxItems.
        (
            "/$defs/stickerPackManifestParams/properties/packId",
            "maxLength",
            STICKER_PACK_BROWSE_ID_HEX_CHARS as u64,
        ),
        (
            "/$defs/stickerPackImageParams/properties/packId",
            "maxLength",
            STICKER_PACK_BROWSE_ID_HEX_CHARS as u64,
        ),
        (
            "/$defs/conversationsSetPinnedParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        // Conversation avatar + blocked write (contract 1.48, §4.47): both
        // faces share the pinned face's 256-char conversation bound (the
        // getAvatar reference and the setBlocked reference).
        (
            "/$defs/conversationsGetAvatarParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        (
            "/$defs/conversationsSetBlockedParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        // Group management (contract 1.45, §4.44): the schema mirrors every
        // bound the service enforces — the addressing pair, the string
        // bounds, the emoji grapheme budget, and the roster caps on the
        // member arrays (the six arrays share one service loop, so one
        // maxItems and one items pin stand for all six).
        (
            "/$defs/groupsUpdateParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        (
            "/$defs/groupsQuitParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/groupName",
            "maxLength",
            GROUP_NAME_MAX_BYTES as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/groupDescription",
            "maxLength",
            GROUP_DESCRIPTION_MAX_BYTES as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/memberLabel",
            "maxLength",
            GROUP_MEMBER_LABEL_MAX_BYTES as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/memberLabelEmoji",
            "maxLength",
            MAX_EMOJI_BYTES as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/addMembers",
            "maxItems",
            MAX_GROUP_MEMBERS as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/removeMembers",
            "maxItems",
            MAX_GROUP_MEMBERS as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/addMembers/items",
            "maxLength",
            MAX_GROUP_MEMBER_ID_CHARS as u64,
        ),
        // Join-request approval (contract 1.58, §4.53): the candidate set
        // rides the §4.39 roster bounds verbatim (the schema mirrors every
        // bound the prepare checks enforce).
        (
            "/$defs/groupsApproveJoinRequestsParams/properties/members",
            "maxItems",
            MAX_GROUP_MEMBERS as u64,
        ),
        (
            "/$defs/groupsApproveJoinRequestsParams/properties/members/items",
            "maxLength",
            MAX_GROUP_MEMBER_ID_CHARS as u64,
        ),
        // Invite revocation (contract 1.64, §4.57): the same §4.39 roster
        // bounds verbatim.
        (
            "/$defs/groupsRevokeInvitesParams/properties/members",
            "maxItems",
            MAX_GROUP_MEMBERS as u64,
        ),
        (
            "/$defs/groupsRevokeInvitesParams/properties/members/items",
            "maxLength",
            MAX_GROUP_MEMBER_ID_CHARS as u64,
        ),
        // The group.changed change-list cap (contract 1.100, §4.81 D3): the
        // parse-side truncate bound the event data mirrors. (These allOf
        // indices shifted +1 when contract 1.158 §4.156 inserted the
        // story.deleteCandidate branch at allOf/12.)
        (
            "/$defs/event/allOf/15/then/properties/data/properties/changes",
            "maxItems",
            GROUP_CHANGED_MAX_CHANGES as u64,
        ),
        // Delete-for-me sync (contract 1.102, §4.83): the event data mirrors
        // the parse-side bounds — the group cap, the per-group entry cap,
        // and the author id bound (the receive-id family).
        (
            "/$defs/event/allOf/16/then/properties/data/properties/deletes",
            "maxItems",
            MAX_SYNC_DELETE_GROUPS as u64,
        ),
        (
            "/$defs/event/allOf/16/then/properties/data/properties/deletes/items/properties/messages",
            "maxItems",
            MAX_SYNC_DELETE_GROUP_MESSAGES as u64,
        ),
        (
            "/$defs/event/allOf/16/then/properties/data/properties/deletes/items/properties/messages/items/properties/author",
            "maxLength",
            MAX_RECEIVE_ID_CHARS as u64,
        ),
        // Contract 1.196 (§4.196): the attachment arm shares the message
        // arm's 256-entry batch ceiling (the engine's projection cap is the
        // same value).
        (
            "/$defs/event/allOf/16/then/properties/data/properties/attachmentDeletes",
            "maxItems",
            MAX_SYNC_DELETE_GROUP_MESSAGES as u64,
        ),
        // Verified sync (contract 1.103, §4.84): the destination mirrors the
        // receive-id bound (the parse gates the UUID shape verbatim) and the
        // hex identity key mirrors its own bound (the parse drops an
        // over-bound key whole — never a truncated fingerprint).
        (
            "/$defs/event/allOf/17/then/properties/data/properties/destinationUuid",
            "maxLength",
            MAX_RECEIVE_ID_CHARS as u64,
        ),
        (
            "/$defs/event/allOf/17/then/properties/data/properties/identityKey",
            "maxLength",
            MAX_SYNC_IDENTITY_KEY_CHARS as u64,
        ),
        // Receipts ledger (contract 1.190, §4.190): the recipient key mirrors
        // the receive-id bound (the envelope source passes it verbatim) and
        // the ledger array mirrors the roster ceiling (the ledger's own
        // recipient cap, the store's MAX_MESSAGE_RECEIPT_RECIPIENTS). The
        // arm sits at allOf/33: receive.decryptionError (§4.163) and
        // engine.initialSyncComplete landed arms ahead of it, so the
        // positional pointer moved from the historical allOf/32.
        (
            "/$defs/event/allOf/35/then/properties/data/properties/receipts/items/properties/recipient",
            "maxLength",
            MAX_RECEIVE_ID_CHARS as u64,
        ),
        (
            "/$defs/event/allOf/35/then/properties/data/properties/receipts",
            "maxItems",
            MAX_MESSAGE_RECEIPT_RECIPIENTS as u64,
        ),
        // Backfill settle face (contract 1.193, §4.193): the entry array
        // mirrors the parse bound (§4.175's MAX_INBOUND_ATTACHMENTS — one
        // entry per remote attachment position).
        (
            "/$defs/event/allOf/37/then/properties/data/properties/attachments",
            "maxItems",
            MAX_INBOUND_ATTACHMENTS as u64,
        ),
        // Call-event sync (contract 1.104, §4.85): the decimal call id
        // mirrors its own bound (the parse also demands all-ASCII digits);
        // the conversation identity rides the shared opaqueId def, so no
        // inline pairing exists to pin.
        (
            "/$defs/event/allOf/18/then/properties/data/properties/callId",
            "maxLength",
            MAX_SYNC_CALL_ID_CHARS as u64,
        ),
        // Call-link update (contract 1.106, §4.87): both base64 keys mirror
        // their own bound — the root key drops the record whole over it, the
        // admin key drops per-key (never a truncated call-link address).
        (
            "/$defs/event/allOf/21/then/properties/data/properties/rootKey",
            "maxLength",
            MAX_SYNC_CALL_LINK_KEY_CHARS as u64,
        ),
        (
            "/$defs/event/allOf/21/then/properties/data/properties/adminKey",
            "maxLength",
            MAX_SYNC_CALL_LINK_KEY_CHARS as u64,
        ),
        // The device-name/PNI registration ids mirror the parse's u32 range
        // gate (the std bound the parse enforces through try_from).
        (
            "/$defs/event/allOf/24/then/properties/data/properties/deviceId",
            "maximum",
            u32::MAX as u64,
        ),
        (
            "/$defs/event/allOf/26/then/properties/data/properties/registrationId",
            "maximum",
            u32::MAX as u64,
        ),
        // Account settings (contract 1.46, §4.45): the profile text budgets
        // mirror the official desktop ProfileEditor; the emoji label reuses
        // the repo-wide bound. The avatar budget (10 MiB decoded) is a
        // code-side constant without an exact schema length (the data-URI
        // prefix varies; the schema carries only a coarse maxLength margin) —
        // inventoried below. The universal-timer u32 face and the blocked-list
        // entry cap are enforced structurally / on the free-form result and
        // are inventoried below as well.
        (
            "/$defs/accountsSetProfileParams/properties/givenName",
            "maxLength",
            MAX_PROFILE_NAME_BYTES as u64,
        ),
        (
            "/$defs/accountsSetProfileParams/properties/familyName",
            "maxLength",
            MAX_PROFILE_NAME_BYTES as u64,
        ),
        (
            "/$defs/accountsSetProfileParams/properties/about",
            "maxLength",
            MAX_PROFILE_ABOUT_BYTES as u64,
        ),
        (
            "/$defs/accountsSetProfileParams/properties/emoji",
            "maxLength",
            MAX_EMOJI_BYTES as u64,
        ),
        (
            "/$defs/groupsUpdateParams/properties/removeMembers/items",
            "maxLength",
            MAX_GROUP_MEMBER_ID_CHARS as u64,
        ),
        // Sticker pack sync (contract 1.37, §4.34): the pack id is the §4.32
        // browse-face 32-hex shape; the pack key when present is exactly the
        // 44-character padded base64 of 32 bytes.
        (
            "/$defs/stickerPackSetSyncParams/properties/packId",
            "maxLength",
            STICKER_PACK_BROWSE_ID_HEX_CHARS as u64,
        ),
        (
            "/$defs/stickerPackSetSyncParams/properties/packKey",
            "maxLength",
            STICKER_PACK_SYNC_KEY_B64_CHARS as u64,
        ),
        (
            "/$defs/conversationsListParams/properties/limit",
            "maximum",
            MAX_PAGE_LIMIT as u64,
        ),
        (
            "/$defs/messagesListParams/properties/limit",
            "maximum",
            MAX_PAGE_LIMIT as u64,
        ),
        (
            "/$defs/contactsListParams/properties/limit",
            "maximum",
            MAX_PAGE_LIMIT as u64,
        ),
        (
            "/$defs/messagesSendTextParams/properties/mentions",
            "maxItems",
            MAX_SEND_MENTIONS as u64,
        ),
        (
            "/$defs/messagesMarkReadParams/properties/messageIds",
            "maxItems",
            MARK_RECEIPT_MESSAGE_IDS_LIMIT as u64,
        ),
        (
            "/$defs/messagesMarkViewedParams/properties/messageIds",
            "maxItems",
            MARK_RECEIPT_MESSAGE_IDS_LIMIT as u64,
        ),
        // Report spam (contract 1.49, §4.48): the addressing pair and the
        // per-id list bounds mirror the prepare ladder's constants.
        (
            "/$defs/messagesReportSpamParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        (
            "/$defs/messagesReportSpamParams/properties/messageIds",
            "maxItems",
            REPORT_SPAM_MESSAGE_IDS_LIMIT as u64,
        ),
        (
            "/$defs/messagesReportSpamParams/properties/messageIds/items",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        // Username faces (contract 1.59, §4.55): the lookup batch cap and
        // per-entry frame bound pair with the service-ladder constants; the
        // setUsername wire bound mirrors the pinned libsignal 3..32 window
        // (the grammar itself — charset, discriminator forms — is shape
        // validation below the wire bound and is pinned by unit tests).
        (
            "/$defs/accountsSetUsernameParams/properties/username",
            "maxLength",
            USERNAME_MAX_WIRE_CHARS as u64,
        ),
        (
            "/$defs/usernameLookupParams/properties/usernames",
            "maxItems",
            USERNAME_LOOKUP_MAX_ENTRIES as u64,
        ),
        (
            "/$defs/usernameLookupParams/properties/usernames/items",
            "maxLength",
            USERNAME_LOOKUP_ENTRY_MAX_CHARS as u64,
        ),
        // Phone lookup (contract 1.164, §4.162): the batch cap mirrors the
        // engine's own frame bound through the service-ladder constant. The
        // per-entry shape is the E.164 grammar (pattern + minLength/
        // maxLength 8..16 in the schema) enforced by the regex-semantics
        // gate, mechanism-not-constant — no pair (the cursor maxLength
        // inventory reason).
        (
            "/$defs/phoneLookupParams/properties/numbers",
            "maxItems",
            PHONE_LOOKUP_MAX_ENTRIES as u64,
        ),
        // Safety-number faces (contract 1.68, §4.61): both faces share the
        // pinned face's 256-char conversation bound; the caller-echoed
        // verification string carries the IDENTITY_SAFETY_NUMBER_MAX_CHARS
        // wire bound (the grammar itself is the upstream's parse, not a
        // connector-enforced shape).
        (
            "/$defs/identitiesGetParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        (
            "/$defs/identitiesVerifyParams/properties/conversationId",
            "maxLength",
            MAX_PIN_CONVERSATION_ID_CHARS as u64,
        ),
        (
            "/$defs/identitiesVerifyParams/properties/safetyNumber",
            "maxLength",
            IDENTITY_SAFETY_NUMBER_MAX_CHARS as u64,
        ),
        // Stories send (contract 1.76, §4.67): the body/preview bounds and
        // the per-recipient id bound mirror the prepare-ladder constants
        // (the recipient-array cap mirrors the §4.39 roster ceiling but
        // stays inventory-side — see the note below).
        (
            "/$defs/messagesSendStoryParams/properties/message",
            "maxLength",
            MAX_TEXT_BYTES as u64,
        ),
        (
            "/$defs/messagesSendStoryParams/properties/distributionListId",
            "maxLength",
            MAX_STORY_DISTRIBUTION_ID_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStoryParams/properties/previewImage",
            "maxLength",
            MAX_AVATAR_DATA_URI_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStoryParams/properties/recipients/items",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        // Story link-preview metadata (contract 1.91, §4.74): the url/title
        // budgets mirror the prepare-ladder constants; the url's
        // `pattern` (^https://) is the official isValidLink posture and is
        // structural (no constant to pair).
        (
            "/$defs/messagesSendStoryParams/properties/previewUrl",
            "maxLength",
            MAX_STORY_PREVIEW_URL_CHARS as u64,
        ),
        (
            "/$defs/messagesSendStoryParams/properties/previewTitle",
            "maxLength",
            MAX_STORY_PREVIEW_TITLE_BYTES as u64,
        ),
        // Story viewed receipt (contract 1.85, §4.70): the story-author
        // bound mirrors the story recipients' per-entry bound (the receipt's
        // single recipient address); storySentAt's minimum 1 is a structural
        // shape rule (the officially meaningless zero marker), no constant.
        (
            "/$defs/storiesMarkViewedParams/properties/storyAuthor",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        // Story reaction send (contract 1.94, §4.77): same story-author
        // bound, and the reaction emoji rides the shared 32-byte cap.
        (
            "/$defs/storiesSendReactionParams/properties/storyAuthor",
            "maxLength",
            MAX_OPAQUE_ID_BYTES as u64,
        ),
        (
            "/$defs/storiesSendReactionParams/properties/emoji",
            "maxLength",
            MAX_EMOJI_BYTES as u64,
        ),
        // Official-desktop snapshot import (contract 1.78, §4.68): the
        // caller-chosen directory path is shape-gated by the connector
        // (absolute, 1..4096 bytes) before any engine traffic — the connector
        // never dereferences it. The account id rides the shared opaqueId
        // `$ref`, whose bound is already paired above — no second pair.
        (
            "/$defs/backupsImportSnapshotParams/properties/snapshotDir",
            "maxLength",
            MAX_SNAPSHOT_DIR_BYTES as u64,
        ),
        // Story-anchored attachment byte faces (contract 1.86, §4.71): the
        // caller-supplied pointer's landing id rides the attachmentId bound;
        // the declared size's ceiling is the transit chain's own constant;
        // and the §4.54 locator-ingest caps mirror onto the caller-supplied
        // strings (the cdnNumber/uploadTimestamp/type bounds are structural
        // u32/u64 serde gates, no constants).
        (
            "/$defs/storyAttachmentPointerParams/properties/id",
            "maxLength",
            MAX_ATTACHMENT_ID_BYTES as u64,
        ),
        (
            "/$defs/storyAttachmentPointerParams/properties/size",
            "maximum",
            MAX_PLAINTEXT_BYTES,
        ),
        (
            "/$defs/storyLocatorParams/properties/key",
            "maxLength",
            MAX_LOCATOR_FIELD_CHARS as u64,
        ),
        (
            "/$defs/storyLocatorParams/properties/cdnKey",
            "maxLength",
            MAX_LOCATOR_FIELD_CHARS as u64,
        ),
        (
            "/$defs/storyLocatorParams/properties/digest",
            "maxLength",
            MAX_LOCATOR_FIELD_CHARS as u64,
        ),
        (
            "/$defs/storyLocatorParams/properties/plaintextHash",
            "maxLength",
            MAX_LOCATOR_HASH_CHARS as u64,
        ),
        (
            "/$defs/storyOpenAttachmentParams/properties/attachmentId",
            "maxLength",
            MAX_ATTACHMENT_ID_BYTES as u64,
        ),
        // Call-link credential material faces (contract 1.88, §4.73): the
        // padded-base64 wire bounds of the engine's fixed byte shapes —
        // rootKey's widest legal form is the 21-byte V1 (28 chars; the 16-byte
        // V0 is 24), roomId and groupId are 32-byte fixed (44 chars). The
        // exact decoded byte length is the prepare ladder's own gate (trim +
        // canonical decode + 16/21 or 32), pinned by unit tests; the schema
        // maxLength only bounds absurd input alongside the constant.
        (
            "/$defs/callsLinkPresentationParams/properties/rootKey",
            "maxLength",
            CALL_LINK_ROOT_KEY_B64_MAX_CHARS as u64,
        ),
        (
            "/$defs/callsCreateLinkAuthParams/properties/rootKey",
            "maxLength",
            CALL_LINK_ROOT_KEY_B64_MAX_CHARS as u64,
        ),
        (
            "/$defs/callsCreateLinkAuthParams/properties/roomId",
            "maxLength",
            CALL_LINK_ROOM_ID_B64_CHARS as u64,
        ),
        (
            "/$defs/callsGroupProofParams/properties/groupId",
            "maxLength",
            CALL_GROUP_MASTER_KEY_B64_CHARS as u64,
        ),
        (
            "/$defs/callsGroupMembersParams/properties/groupId",
            "maxLength",
            CALL_GROUP_MASTER_KEY_B64_CHARS as u64,
        ),
        // Chat-folder sync (contract 1.95, §4.78): the write-batch caps (both
        // halves) and the per-identity bound mirror the prepare ladder; the
        // read-side list cap stays inventory-side (free-form result, see the
        // note above).
        (
            "/$defs/chatFoldersSetRecordsParams/properties/records",
            "maxItems",
            MAX_CHAT_FOLDER_BATCH as u64,
        ),
        (
            "/$defs/chatFoldersSetRecordsParams/properties/removeIds",
            "maxItems",
            MAX_CHAT_FOLDER_BATCH as u64,
        ),
        (
            "/$defs/chatFoldersSetRecordsParams/properties/records/items/properties/id",
            "maxLength",
            MAX_CHAT_FOLDER_ID_CHARS as u64,
        ),
        (
            "/$defs/chatFoldersSetRecordsParams/properties/removeIds/items",
            "maxLength",
            MAX_CHAT_FOLDER_ID_CHARS as u64,
        ),
        // Notification-profile sync (contract 1.129, §4.110): the §4.78
        // pair set verbatim over the profile identity key.
        (
            "/$defs/notificationProfilesSetRecordsParams/properties/records",
            "maxItems",
            MAX_NOTIFICATION_PROFILE_BATCH as u64,
        ),
        (
            "/$defs/notificationProfilesSetRecordsParams/properties/removeIds",
            "maxItems",
            MAX_NOTIFICATION_PROFILE_BATCH as u64,
        ),
        (
            "/$defs/notificationProfilesSetRecordsParams/properties/records/items/properties/id",
            "maxLength",
            MAX_NOTIFICATION_PROFILE_ID_CHARS as u64,
        ),
        (
            "/$defs/notificationProfilesSetRecordsParams/properties/removeIds/items",
            "maxLength",
            MAX_NOTIFICATION_PROFILE_ID_CHARS as u64,
        ),
        // Story-distribution-list sync (contract 1.130, §4.111): the §4.78
        // pair set verbatim over the `identifier` identity key.
        (
            "/$defs/storyDistributionListsSetRecordsParams/properties/records",
            "maxItems",
            MAX_STORY_LIST_BATCH as u64,
        ),
        (
            "/$defs/storyDistributionListsSetRecordsParams/properties/removeIds",
            "maxItems",
            MAX_STORY_LIST_BATCH as u64,
        ),
        (
            "/$defs/storyDistributionListsSetRecordsParams/properties/records/items/properties/identifier",
            "maxLength",
            MAX_STORY_LIST_ID_CHARS as u64,
        ),
        (
            "/$defs/storyDistributionListsSetRecordsParams/properties/removeIds/items",
            "maxLength",
            MAX_STORY_LIST_ID_CHARS as u64,
        ),
        // Storage call-link faces (contract 1.131, §4.112): the identity
        // and passkey bounds mirror the prepare ladder; the ingest faces
        // are single-parameter reads with no numeric schema hook.
        (
            "/$defs/storageSetCallLinkParams/properties/rootKey",
            "maxLength",
            MAX_CALL_LINK_KEY_CHARS as u64,
        ),
        (
            "/$defs/storageSetCallLinkParams/properties/adminPasskey",
            "maxLength",
            MAX_CALL_LINK_KEY_CHARS as u64,
        ),
        // Message-level delete-for-me (contract 1.197, §4.197): the local
        // row-id list mirrors the engine's single-request ceiling.
        (
            "/$defs/messagesDeleteForMeMessagesParams/properties/messageIds",
            "maxItems",
            MAX_DELETE_FOR_ME_MESSAGES as u64,
        ),
        // Persisted attachment dimensions (contract 1.271, §4.255): the
        // official Attachment.width/height domain and the warm-up row bound.
        (
            "/$defs/messagesSetAttachmentDimensionsParams/properties/attachmentId",
            "maxLength",
            MAX_ATTACHMENT_ID_BYTES as u64,
        ),
        (
            "/$defs/messagesSetAttachmentDimensionsParams/properties/width",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesSetAttachmentDimensionsParams/properties/height",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesListAttachmentDimensionsParams/properties/limit",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_ROWS as u64,
        ),
        // Declared media dimensions on the send family (contract 1.294, §4.284
        // BUG-11 wire 批): the same official Attachment.width/height domain as
        // the persisted face above, on the singular keys, the plural entry keys
        // and the retry face (all three reuse the one constant).
        (
            "/$defs/messagesSendAttachmentParams/properties/width",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesSendAttachmentParams/properties/height",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesSendAttachmentEntry/properties/width",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesSendAttachmentEntry/properties/height",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesRetryAttachmentParams/properties/width",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        (
            "/$defs/messagesRetryAttachmentParams/properties/height",
            "maximum",
            MAX_ATTACHMENT_DIMENSION_PX as u64,
        ),
        // Peer addressing on the safety-number faces (contract 1.281,
        // §4.265): the peerKey wire bound on both faces pairs with the code
        // constant. The UUID/E.164 grammar above/below that bound is the
        // shape gate (uuid_shaped / is_e164_phone_number_shape), pinned by
        // the §4.265 unit tests and mirrored by the schema's anyOf patterns
        // in the structural test below.
        (
            "/$defs/identitiesGetParams/properties/peerKey",
            "maxLength",
            IDENTITY_PEER_KEY_MAX_CHARS as u64,
        ),
        (
            "/$defs/identitiesVerifyParams/properties/peerKey",
            "maxLength",
            IDENTITY_PEER_KEY_MAX_CHARS as u64,
        ),
        // 契约 1.283（§4.267）：events.list 的游标面。token 的代际上界与 page
        // 的 limit 上界都由 store 的命名常量执行，这里锁住两个数不漂移；
        // afterSeq 的 0 下界是集合本身的形状（负游标没有意义），由
        // schema_bound 的 minimum 配对。
        (
            "/$defs/eventsListParams/properties/token",
            "maxLength",
            EVENT_TOKEN_MAX_CHARS as u64,
        ),
        (
            "/$defs/eventsListParams/properties/limit",
            "maximum",
            EVENT_PAGE_MAX_LIMIT as u64,
        ),
        ("/$defs/eventsListParams/properties/afterSeq", "minimum", 0),
    ];
    assert!(!pairs.is_empty());
    for (pointer, key, code) in pairs {
        let declared = schema_bound(pointer, key);
        assert_eq!(
            declared, *code,
            "bound drift at {pointer}.{key}: schema says {declared}, code enforces {code}"
        );
    }
}

/// 契约 1.281（§4.265）结构锁：两张安全码面的寻址恰一（conversationId xor
/// peerKey）写成 oneOf —— verify 面的两个独立 oneOf（地址臂、数字/重置臂）
/// 由 allOf 组合 —— 且 peerKey 的 anyOf 词形只认 ACI UUID 或 E.164（组
/// master key、PNI:/u: 用户名拼写与裸数字都不在这条面上）。词形语义由
/// service 的单测（`identity_peer_addressing_reads_without_a_conversation_and
/// _stamps_by_peer`）逐条对齐，这里锁的是 wire 契约本身不能悄悄退化。
#[test]
fn identity_faces_declare_the_addressing_one_of_and_peer_key_grammar() {
    let schema = schema();
    let get = schema
        .pointer("/$defs/identitiesGetParams")
        .expect("identitiesGetParams must exist");
    assert_eq!(
        get["required"],
        serde_json::json!(["accountId"]),
        "the addressing form is exactly-one, so neither key is required"
    );
    assert_eq!(
        get["oneOf"],
        serde_json::json!([
            { "required": ["conversationId"] },
            { "required": ["peerKey"] },
        ])
    );
    assert_eq!(
        get["properties"]["conversationId"]["maxLength"],
        serde_json::json!(256)
    );

    let verify = schema
        .pointer("/$defs/identitiesVerifyParams")
        .expect("identitiesVerifyParams must exist");
    assert_eq!(verify["required"], serde_json::json!(["accountId"]));
    assert_eq!(
        verify["allOf"],
        serde_json::json!([
            {
                "oneOf": [
                    { "required": ["conversationId"] },
                    { "required": ["peerKey"] },
                ],
            },
            {
                "oneOf": [
                    { "required": ["safetyNumber"] },
                    { "required": ["state"] },
                ],
            },
        ]),
        "two independent exactly-one axes need allOf, not a second oneOf key"
    );

    // The two grammar arms, verbatim: ACI UUID (8-4-4-4-12 hex) or E.164.
    for pointer in [
        "/$defs/identitiesGetParams/properties/peerKey/anyOf",
        "/$defs/identitiesVerifyParams/properties/peerKey/anyOf",
    ] {
        let patterns: Vec<&str> = schema
            .pointer(pointer)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("schema must declare the peerKey grammar at {pointer}"))
            .iter()
            .map(|arm| {
                arm.get("pattern")
                    .and_then(Value::as_str)
                    .expect("each peerKey arm is a pattern")
            })
            .collect();
        assert_eq!(
            patterns,
            vec![
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                "^\\+[0-9]{7,15}$",
            ],
            "the peerKey grammar drifted at {pointer}"
        );
    }
}
/// Contract 1.291 (§4.277 B): the status face is a closed vocabulary on both
/// halves, and the connector's own code is the only source of it. `off` is
/// deliberately absent from the wire enum: an unarmed connector omits the key.
#[test]
fn the_store_migration_face_matches_the_code_vocabulary() {
    use kt_signal_connector::pool::{
        STORE_CODE_CAPABILITY_MISSING, STORE_CODE_INTERRUPTED, STORE_CODE_IO_ERROR,
        STORE_CODE_KEY_INVALID, STORE_CODE_LOCKED, STORE_CODE_REQUIRED, STORE_CODE_TIMEOUT,
        STORE_CODE_VERIFY_FAILED, StoreMigrationState,
    };
    let declared = schema_enum("/$defs/storeMigrationState/enum");
    let emitted: BTreeSet<String> = [
        StoreMigrationState::Pending,
        StoreMigrationState::Migrating,
        StoreMigrationState::Migrated,
        StoreMigrationState::Blocked,
        StoreMigrationState::Failed,
    ]
    .iter()
    .map(|state| state.label().to_string())
    .collect();
    assert_eq!(
        declared, emitted,
        "the wire enum is exactly the states the connector can report"
    );
    assert!(
        !declared.contains("off"),
        "an unarmed connector omits the key; it never sends a sixth word"
    );
    let codes = schema_enum("/$defs/storeMigration/properties/code/enum");
    let known: BTreeSet<String> = [
        STORE_CODE_CAPABILITY_MISSING,
        STORE_CODE_KEY_INVALID,
        STORE_CODE_VERIFY_FAILED,
        STORE_CODE_REQUIRED,
        STORE_CODE_INTERRUPTED,
        STORE_CODE_IO_ERROR,
        STORE_CODE_LOCKED,
        STORE_CODE_TIMEOUT,
    ]
    .iter()
    .map(|code| code.to_string())
    .collect();
    assert_eq!(codes, known, "the code face is closed and connector-owned");
    for state in [
        StoreMigrationState::Off,
        StoreMigrationState::Pending,
        StoreMigrationState::Migrating,
        StoreMigrationState::Migrated,
        StoreMigrationState::Blocked,
        StoreMigrationState::Failed,
    ] {
        let label = state.label();
        assert!(label.len() <= 16, "{label}");
    }
}
