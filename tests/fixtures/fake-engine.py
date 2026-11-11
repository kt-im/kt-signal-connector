#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

import base64
import json
import os
import re
from pathlib import Path
import sys
import threading
import time
import uuid
import zlib


# No-Java guard: the engine binary is native (GraalVM) with no JVM, so the
# connector must not set JAVA_OPTS or forward JAVA_HOME to the child at all.
if os.environ.get("KT_FAKE_EXPECT_NO_JAVA") is not None:
    if os.environ.get("JAVA_OPTS") is not None or os.environ.get("JAVA_HOME") is not None:
        sys.exit(94)


# O1 engine contract handshake fixture. The connector asks a freshly started
# engine who it is (`version`) and which contract revision it implements
# (`engine.protocolCapabilities.contractRevision`). Defaults reproduce the
# pre-handshake engine: a real identity with no stated revision, which the
# connector serves as `legacy`. Tests opt into the other rows:
#   KT_FAKE_ENGINE_CONTRACT_REVISION=<rev>  stated revision (e.g. "1.284")
#   KT_FAKE_ENGINE_NO_CAPABILITIES=1        capabilities answers the upstream
#                                           error class (a pre-face engine)
#   KT_FAKE_ENGINE_VERSION_ERROR=1          version answers an error
#   KT_FAKE_ENGINE_VERSION_DELAY_MS=<n>     version answers after n ms
#                                           (past the 5s probe budget)
ENGINE_VERSION = os.environ.get("KT_FAKE_ENGINE_VERSION") or "0.1.0-fixture"

LINKED_ACCOUNT = "+15555550100"
ACTIVE_LINK_URI = "sgnl://link?uuid=fixture&pub_key=fixture"
# Rotating link attempt fixture (connector contract 1.286, §4.272). A
# rotate-capable engine states its rotate key on the startLink answer, and the
# connector keys rotateLink by it. Modes:
#   (unset) / "1"       rotate-capable: startLink mints an attempt id and
#                       rotateLink answers a fresh code for the same attempt
#   "0" / "off"         a pre-rotate engine: startLink states no attempt and
#                       rotateLink is not implemented
#   "method_not_found"  startLink states the key but rotateLink answers the
#                       JSON-RPC method-not-found class (-32601)
LINK_ROTATE_MODE = (os.environ.get("KT_FAKE_LINK_ROTATE") or "").strip().lower()
# attempt id -> how many slots it has minted
LINK_ATTEMPTS = {}
# every code this fixture minted (finishLink accepts any of them, so the
# dual-slot flow can finish through a rotated slot)
LINK_URIS = {ACTIVE_LINK_URI}
# Connector contract 1.286 (§4.272) commit-face fixture: the engine approves a
# device while a rotation retires the very code the finish was dispatched with.
# A finishLink naming this device parks its answer; the test releases it by
# dropping DEFERRED_FINISH_MARKER in the data dir *after* the retiring rotation
# answered, so the engine's success provably lands with that code already
# Retired. The commit must accept it (not answer LINK_LOST) and journal it.
DEFERRED_FINISH_DEVICE = "[deferred-link-test]"
PENDING_FINISH_IDS = []
WRITE_LOCK = threading.Lock()
# §4.68 snapshot-import fixture: the archive identity the background import
# task projects into the §4.38 NDJSON (one contact recipient + one chat + two
# messages), matching the seed shape tests/history_import.rs lays out.
IMPORT_ALICE_ACI = "6e08f0b6-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
IMPORT_ALICE_E164 = "+15550000001"
# Contract 1.36 pin-sync fixture state: the cloud-order pinned list the
# engine would read from the storage record; setConversationPinned mutates it
# in place so a read-back after a write observes the write.
PINNED_STATE = [
    {"conversationId": "+15555550101", "kind": "contact"},
    {"conversationId": "ZmFrZS1ncm91cC0x", "kind": "group"},
]
# Contract 1.37 sticker-pack sync fixture state: the Storage Service
# StickerPackRecord projection — one installed pack (key + position) and one
# tombstone; setStickerPackSync mutates it in place so a read-back after a
# write observes the write.
PACK_SYNC_STATE = [
    {
        "packId": "abcdef0123456789abcdef0123456789",
        "packKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "position": 0,
        "deletedAtTimestampMs": None,
    },
    {
        "packId": "11111111111111111111111111112222",
        "packKey": None,
        "position": None,
        "deletedAtTimestampMs": 1727000000000,
    },
]
# Contract 1.46 account-settings/blocked fixture state: the blocked list is a
# read-only storage-order constant (the §4.45 batch has no unblock write
# face); the three write faces are dispatch-recorded no-ops.
BLOCKED_STATE = [
    {"conversationId": "+15555550103", "kind": "contact",
     "blockedAtTimestampMs": 1700000000000},
    {"conversationId": "bGVnYWN5LWdyb3VwLTE=", "kind": "legacyGroup"},
]
# Contract 1.116 §4.97 conversation-state fixture state: keyed
# (kind:conversationId) → the three storage-record bits, seeded on first
# touch with the all-default projection (the cloud record's unset bits).
# getConversationState reads it, setConversationState mutates it in place so
# a read-back after a write observes the write. Canonicalization faces are
# mirrored from the engine's storage ladder: a contact reference outside the
# fixture's contacted numbers, or a group reference that is not 32-byte
# standard-base64 master-key material, answers CONVERSATION_NOT_RESOLVED;
# the "[fixture-state-unavailable]" sentinel answers STORAGE_UNAVAILABLE.
CONVERSATION_STATE = {}
CONVERSATION_STATE_KNOWN_CONTACTS = ("+15555550101", "+15555550102", "+15555550103")


def conversation_state_default():
    return {"mutedUntilTimestamp": 0, "archived": False, "markedUnread": False}


def canonical_conversation_reference(kind, conversation_id):
    """The engine's storage canonicalization refusal face (§4.97): a
    reference that cannot key a storage record of the named family answers
    None (the caller turns it into CONVERSATION_NOT_RESOLVED)."""
    if kind == "contact":
        return conversation_id in CONVERSATION_STATE_KNOWN_CONTACTS
    if kind in ("group", "legacyGroup"):
        if kind == "group":
            try:
                decoded = base64.b64decode(conversation_id, validate=True)
            except Exception:
                return False
            return len(decoded) == 32
        return bool(conversation_id)
    return None


# Contract 1.117 §4.98 group invite-link family: the fixture mirrors the
# engine's group_link.rs pure-function face with a minimal proto codec —
# the GroupInviteLink wire shape is field 1 = contentsV1 (nested), whose
# fields are 1 = groupMasterKey (32B) and 2 = inviteLinkPassword. Build =
# the official buildGroupLink shape (proto → standard base64 → websafe →
# https://signal.group/#<code>); parse accepts the three official URL
# forms plus the bare invite code and answers None on every tolerance
# failure (empty/malformed/versionless/short-key/empty-password — the
# engine answers -32603 for the whole family, so the fixture folds them).
LINK_PASSWORD_FORBIDDEN = b"\xad" * 16
LINK_PASSWORD_PREVIEW_FAILED = b"\xfe" * 16
LINK_PASSWORD_JOIN_REQUESTED = b"\xf7" * 16


def _fixture_varint(value):
    out = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def _fixture_parse_varint(buf, pos):
    shift = 0
    value = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _fixture_proto_fields(buf):
    """Decode one length-delimited proto message into {field: bytes} (the
    GroupInviteLink shape carries only length-delimited fields; anything
    else is malformed for this face)."""
    fields = {}
    pos = 0
    while pos < len(buf):
        tag, pos = _fixture_parse_varint(buf, pos)
        if tag & 0x07 != 2:
            raise ValueError("unsupported wire type")
        length, pos = _fixture_parse_varint(buf, pos)
        if pos + length > len(buf):
            raise ValueError("truncated field")
        number = tag >> 3
        if number in fields:
            raise ValueError("duplicate field")
        fields[number] = buf[pos : pos + length]
        pos += length
    return fields


def _fixture_from_web_safe(code):
    restored = code.replace("_", "/").replace("-", "+")
    return restored + "=" * ((-len(restored)) % 4)


def fixture_parse_invite_link(value):
    """Engine parse_invite_link parity: the '#' code segment (or the whole
    trimmed value as the bare invite code) → websafe restore → standard
    base64 → proto → contentsV1 must be present → masterKey exactly 32B,
    password non-empty. Answers None on every tolerance failure."""
    trimmed = value.strip()
    if "#" in trimmed:
        code = trimmed.split("#", 1)[1].strip()
    elif trimmed:
        code = trimmed
    else:
        return None
    try:
        raw = base64.b64decode(_fixture_from_web_safe(code), validate=True)
        link_fields = _fixture_proto_fields(raw)
    except Exception:
        return None
    contents = link_fields.get(1)
    if contents is None:
        return None
    try:
        inner = _fixture_proto_fields(contents)
    except Exception:
        return None
    master_key = inner.get(1)
    password = inner.get(2)
    if master_key is None or len(master_key) != 32 or not password:
        return None
    return master_key, password


def fixture_build_invite_link(master_key, password):
    contents = (
        b"\x0a"
        + _fixture_varint(len(master_key))
        + master_key
        + b"\x12"
        + _fixture_varint(len(password))
        + password
    )
    raw = b"\x0a" + _fixture_varint(len(contents)) + contents
    web_safe = (
        base64.b64encode(raw).decode().replace("/", "_").replace("+", "-").replace("=", "")
    )
    return "https://signal.group/#" + web_safe


# Contract 1.95 chat-folder sync fixture state: the Storage Service
# ChatFolderRecordJson projection in storage order — the full 11-key record
# face the engine projects (id/name/position/booleans/folderType/both
# recipient arrays/deletedAtTimestampMs, the tombstone key always present,
# 0 = live); chatFolders.setRecords mutates it in place so a read-back after
# a write observes the write.
CHAT_FOLDER_STATE = [
    {
        "id": "0d6d50f5-7f9e-4a1b-9c2d-3e4f5a6b7c8d",
        "name": "All chats",
        "position": 0,
        "showOnlyUnread": False,
        "showMutedChats": True,
        "includeAllIndividualChats": True,
        "includeAllGroupChats": True,
        "folderType": "ALL",
        "includedConversationIds": [],
        "excludedConversationIds": [],
        "deletedAtTimestampMs": 0,
    },
    {
        "id": "1a2b3c4d-5e6f-4a1b-8c9d-0e1f2a3b4c5d",
        "name": "Work",
        "position": 1,
        "showOnlyUnread": True,
        "showMutedChats": False,
        "includeAllIndividualChats": False,
        "includeAllGroupChats": False,
        "folderType": "CUSTOM",
        "includedConversationIds": [
            {"conversationId": "6e08f0b6-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "kind": "contact"},
            {"conversationId": "ZmFrZS1ncm91cC0x", "kind": "group"},
            {"conversationId": "bGVnYWN5LWdyb3VwLTE=", "kind": "legacyGroup"},
        ],
        "excludedConversationIds": [
            {"conversationId": "7f19e1c7-2d3e-4f6a-9b0c-1d2e3f4a5b6c", "kind": "contact"}
        ],
        "deletedAtTimestampMs": 0,
    },
]
# Contract 1.129 notification-profile sync fixture state: the Storage Service
# NotificationProfileJson projection in storage order — the engine's read
# face keys (id 32-hex / name / emoji / color / createdAtMs / booleans /
# allowedMembers / schedule keys / tombstone key present only when non-zero);
# notificationProfiles.setRecords mutates it in place so a read-back after a
# write observes the write.
NOTIFICATION_PROFILE_STATE = [
    {
        "id": "a3f1c2d4e5b6478901a2b3c4d5e6f701",
        "name": "Work",
        "color": 4,
        "createdAtMs": 1720000000000,
        "allowAllCalls": False,
        "allowAllMentions": True,
        "allowedMembers": [],
        "scheduleEnabled": False,
        "scheduleDaysEnabled": [],
    },
    {
        "id": "b7e2d3c4f5a6081922b3c4d5e6f70812",
        "name": "Sleep",
        "emoji": "🌙",
        "color": 9,
        "createdAtMs": 1720000100000,
        "allowAllCalls": True,
        "allowAllMentions": False,
        "allowedMembers": [
            {"conversationId": "6e08f0b6-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "kind": "contact"},
        ],
        "scheduleEnabled": True,
        "scheduleStartTime": 1320,
        "scheduleEndTime": 420,
        "scheduleDaysEnabled": [1, 2, 3, 4, 5],
        "deletedAtTimestampMs": 0,
    },
]
# Contract 1.130 story-distribution-list sync fixture state: the Storage
# Service StoryDistributionListRecordJson projection in storage order — the
# engine's read face keys (identifier uuid / name / both member faces /
# deletedAtTimestamp always present / allowsReplies / isBlockList);
# storyDistributionLists.setRecords mutates it in place so a read-back
# after a write observes the write.
STORY_LIST_STATE = [
    {
        "identifier": "00000000-0000-0000-0000-000000000000",
        "name": "My Story",
        "recipientServiceIds": [],
        "recipientServiceIdsBinary": [],
        "deletedAtTimestamp": 0,
        "allowsReplies": True,
        "isBlockList": False,
    },
    {
        "identifier": "d1e2f3a4-b5c6-4718-a93a-4b5c6d7e8f90",
        "name": "Close friends",
        "recipientServiceIds": [
            "6e08f0b6-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
            "PNI:8f7e6d5c-4b3a-4928-8172-63d4e5f60718",
        ],
        "recipientServiceIdsBinary": [
            "bGVnYWN5LWJpbmFyeS0x",
        ],
        "deletedAtTimestamp": 0,
        "allowsReplies": False,
        "isBlockList": False,
    },
]
# Contract 1.131 storage sync fixture state: the call-link projection — the
# engine's {rootKey, adminPasskey, deletedAtTimestampMs} face (keys ride
# null when absent); storage.setCallLink upserts by rootKey in place so a
# read-back after a write observes the write.
CALL_LINK_STATE = [
    {
        "rootKey": "Zml4dHVyZS1jYWxsLWxpbmtcm9vdGtleTE=",
        "adminPasskey": "cGFzc2tleS1ieXRlcy0xNg==",
        "deletedAtTimestampMs": None,
    },
    {
        "rootKey": "Zml4dHVyZS10b21ic3RvbmUtbGluaw==",
        "adminPasskey": None,
        "deletedAtTimestampMs": 1720000600000,
    },
]
# Contract 1.48 §4.47 avatar fixture: a tiny PNG magic payload — the engine
# sniffs the MIME from the magic bytes and answers a data URI plus the
# decoded byte count; getAvatar's sentinel conversationId answers the
# structured avatar error faces.
AVATAR_PNG_BYTES = b"\x89PNG\r\n\x1a\nfixture-avatar"
AVATAR_DATA_URI = (
    "data:image/png;base64," + base64.b64encode(AVATAR_PNG_BYTES).decode()
)
# Contract 1.68 §4.61 safety-number faces: the fixture identity's peer — the
# contacted number the integration test's conversation row resolves to (the
# link-time contacts sync materializes the same number into the store), so
# listIdentities keyed by it answers the identity record and trust keyed by
# it records the write.
FIXTURE_PEER_NUMBER = "+15555550103"


def argument_value(name):
    try:
        return sys.argv[sys.argv.index(name) + 1]
    except (ValueError, IndexError):
        return None


SIGNAL_DATA_DIR = Path(argument_value("--data-dir") or "/tmp/kt-signal-fixture")
SIGNAL_DATA_DIR.mkdir(parents=True, exist_ok=True)

# P1 runtime isolation fixture (contract revision 1.288, §4.274): record the
# single-account guard the connector handed this engine. The connector sets or
# removes the variable explicitly per child; the test reads this probe to pin
# that a pooled engine is never launched without it (and a legacy engine never
# carries one).
try:
    (SIGNAL_DATA_DIR / ".fixture-env.json").write_text(
        json.dumps({"KT_ENGINE_SINGLE_ACCOUNT": os.environ.get("KT_ENGINE_SINGLE_ACCOUNT")})
    )
except OSError:
    pass


def log_pid_line():
    logs_dir = SIGNAL_DATA_DIR / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        with (logs_dir / "engine-stderr.log").open("a") as log:
            log.write("pid=" + str(os.getpid()) + "\n")
    except OSError:
        pass


log_pid_line()
# Phase 4: every group engine shares the connector's environment, so group
# identity can only come from the data directory each engine is launched with.
# A non-default group answers with a distinct number, otherwise two engines
# would both report (and the store would UNIQUE-collide on) +15555550100.
LINKED_ACCOUNT = (
    "+15555550101"
    if str(SIGNAL_DATA_DIR).endswith(str(Path("proxy-groups") / "team-a"))
    else "+15555550100"
)
DELETED_MARKER = SIGNAL_DATA_DIR / ".fixture-account-deleted"
# Commit-face release marker (contract 1.286 §4.272, DEFERRED_FINISH_DEVICE):
# the test drops it after the retiring rotation answered, and the watcher below
# emits the parked finishLink success.
DEFERRED_FINISH_MARKER = SIGNAL_DATA_DIR / ".fixture-release-finish"
# §4.179 unknown-outcome reconciliation probe markers: the answer-shape marker
# (.fixture-lookup-dispatch.json, a verbatim lookupOutgoingDispatch result
# object) and the error marker (.fixture-lookup-error, -32603 face).
LOOKUP_DISPATCH_MARKER = SIGNAL_DATA_DIR / ".fixture-lookup-dispatch.json"
LOOKUP_ERROR_MARKER = SIGNAL_DATA_DIR / ".fixture-lookup-error"
STDERR_MARKER = SIGNAL_DATA_DIR / ".fixture-stderr-websocket-error"
FAIL_USER_STATUS_MARKER = SIGNAL_DATA_DIR / ".fixture-fail-user-status"
FAIL_USER_STATUS_COUNT_MARKER = SIGNAL_DATA_DIR / ".fixture-fail-user-status-count"
AUTH_FAILED_MARKER = SIGNAL_DATA_DIR / ".fixture-auth-failed-user-status"
UNREGISTERED_MARKER = SIGNAL_DATA_DIR / ".fixture-unregistered-user-status"
USERNAME_UNSET_MARKER = SIGNAL_DATA_DIR / ".fixture-username-unset"
SEND_LOG = SIGNAL_DATA_DIR / ".fixture-send-log.jsonl"
DELETE_MODE = os.environ.get("KT_FAKE_DELETE_MODE", "")
# §4.123 test hook: one-shot server-unavailable send answer. A test arms it
# by touching .fixture-send-unavailable-armed in this engine's own data dir
# (test-local, never process-global env); the FIRST send call then answers
# the transport error the engine classifier maps to ServerUnavailable
# ("Bad gateway (ServerUnavailableException)", the §4.80 anchor shape), the
# done marker records the one-shot, and every later send answers normally.
SEND_UNAVAILABLE_ARMED = SIGNAL_DATA_DIR / ".fixture-send-unavailable-armed"
SEND_UNAVAILABLE_DONE = SIGNAL_DATA_DIR / ".fixture-send-unavailable-done"
# Contract 1.143 (§4.139) test hook: one-shot rate-limit send answer. A test
# arms it by touching .fixture-send-ratelimit-armed in this engine's own data
# dir; the FIRST send call then answers the engine's structured rate-limit
# face (-32603 + the §4.80 anchor "(RateLimitExceeded)", the verbatim wire
# shape), the done marker records the one-shot, and every later send answers
# normally.
SEND_RATELIMIT_ARMED = SIGNAL_DATA_DIR / ".fixture-send-ratelimit-armed"
SEND_RATELIMIT_DONE = SIGNAL_DATA_DIR / ".fixture-send-ratelimit-done"
# Contract 1.285 (§4.269) test hook: one-shot dispatch-timeout send answer.
# A test arms it by touching .fixture-send-engine-timeout-armed in this
# engine's own data dir; the FIRST send then answers the engine's real
# -32000 (EngineTimeoutException) face with its promised data, the done
# marker records the one-shot, and every later send answers normally. The
# connector must fold a mutating timeout to the existing unknown outcome.
ENGINE_TIMEOUT_ARMED = SIGNAL_DATA_DIR / ".fixture-send-engine-timeout-armed"
ENGINE_TIMEOUT_DONE = SIGNAL_DATA_DIR / ".fixture-send-engine-timeout-done"
# Contract 1.285 (§4.269) read-only counterpart: the version probe answers
# the same -32000 (EngineTimeoutException) face while this marker exists, so
# a test can prove a READ-ONLY cancellation keeps the structured timeout face
# (ENGINE_TIMEOUT) instead of folding to the unknown outcome.
VERSION_TIMEOUT_MARKER = SIGNAL_DATA_DIR / ".fixture-version-engine-timeout"
ACCOUNT_LINKED = not DELETED_MARKER.exists()

# Multi-account mode (optimization-plan §6.4 M3.3 tests and the soak driver's
# account ladder): each finishLink hands out a fresh number from its own
# range (+1556555xxxx, disjoint from the fixed fixture numbers) and persists
# it, so a group can link up to its account ceiling and engine restarts keep
# reporting every number handed out so far.
MULTI_ACCOUNT = os.environ.get("KT_FAKE_MULTI_ACCOUNT") == "1"
# Per-account pool mode (§4.217): every account engine owns a private
# `--data-dir` under <signal-data>/engines/<accountId>. The number ladder
# must then live on the shared engines/ root — a per-engine log would hand
# +15565550001 to every engine, and the second finishLink would collide on
# the number (the registry answers ACCOUNT_ALREADY_LINKED). A pool engine
# is ONE account (unlike a group engine that reports the whole ladder), so
# the allocated number is also remembered in the engine's own data dir and
# listAccounts answers that one account only.
POOL_ACCOUNT_SHAPE = re.fullmatch(
    r"(?P<root>.*/engines)/[0-9a-fA-F]{32}", str(SIGNAL_DATA_DIR)
)
POOL_ACCOUNT_MODE = POOL_ACCOUNT_SHAPE is not None
LADDER_ACCOUNT_MODE = MULTI_ACCOUNT or POOL_ACCOUNT_MODE
LADDER_DIR = (
    Path(POOL_ACCOUNT_SHAPE.group("root")) if POOL_ACCOUNT_SHAPE else SIGNAL_DATA_DIR
)
ACCOUNT_NUMBERS_LOG = LADDER_DIR / ".fixture-linked-numbers"
OWN_NUMBER_MARKER = SIGNAL_DATA_DIR / ".fixture-own-number"


def own_number():
    if not OWN_NUMBER_MARKER.exists():
        return None
    return OWN_NUMBER_MARKER.read_text().strip() or None


def state_file_number():
    state = SIGNAL_DATA_DIR / "engine-state.json"
    if not state.exists():
        return None
    try:
        data = json.loads(state.read_text())
    except (ValueError, OSError):
        return None
    accounts = data.get("accounts") or []
    if accounts:
        return accounts[0].get("number")
    return None


def linked_multi_numbers():
    if not ACCOUNT_NUMBERS_LOG.exists():
        return []
    return [line.strip() for line in ACCOUNT_NUMBERS_LOG.read_text().splitlines() if line.strip()]


def next_multi_number():
    with WRITE_LOCK:
        numbers = linked_multi_numbers()
        number = f"+1556555{len(numbers) + 1:04d}"
        with ACCOUNT_NUMBERS_LOG.open("a") as log:
            log.write(number + "\n")
    return number


# Contract 1.142 (§4.138): the engine answers each account's own ACI beside
# the number on finishLink and listAccounts. The fixture derives a stable
# dashed lowercase UUID per number (uuid5 over the number itself), so every
# account carries its own identity and the value survives engine restarts.
# KT_FAKE_OMIT_ACCOUNT_ACI=1 covers the honest-absence face: an engine build
# that does not answer the key at all, which the connector must report as
# absence and never paper over with an invented identity.
OMIT_ACCOUNT_ACI = os.environ.get("KT_FAKE_OMIT_ACCOUNT_ACI") == "1"


def account_aci(number):
    if OMIT_ACCOUNT_ACI:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"kt-fake-account-aci:{number}"))


def account_entry(number):
    entry = {"number": number}
    aci = account_aci(number)
    if aci is not None:
        entry["aci"] = aci
    return entry


# Receiving account for receive notifications: the newest multi-account
# number when one exists (so post-link receives land on a linked account and
# the store count matches the link count), otherwise the fixed fixture number.
def receiving_account():
    if POOL_ACCOUNT_MODE:
        return own_number() or LINKED_ACCOUNT
    numbers = linked_multi_numbers()
    return numbers[-1] if MULTI_ACCOUNT and numbers else LINKED_ACCOUNT


# --- Controlled-rate receive injection (optimization-plan §6.4 M3.2) -------
#
# The soak driver cannot reach the engines directly (the connector owns the
# only JSON-RPC channels), so it steers load through a marker file in this
# engine's data directory: `.fixture-load` holding
# {"ratePerMinute": R, "accounts": N}. R is messages per minute per account,
# N the number of simulated receiving accounts (keep N <= 8: receive-driven
# upserts bypass the link ceiling, and the soak models a legal engine).
# Every emission appends one line to `.fixture-load-log.jsonl` so the
# baseline report can count exactly what was injected.
LOAD_MARKER = SIGNAL_DATA_DIR / ".fixture-load"
LOAD_LOG = SIGNAL_DATA_DIR / ".fixture-load-log.jsonl"
LOAD_LOCK = threading.Lock()
LOAD_STATE = {"spec": None, "stop": None}


def read_load_spec():
    try:
        spec = json.loads(LOAD_MARKER.read_text())
        rate = int(spec.get("ratePerMinute", 0))
        accounts = int(spec.get("accounts", 1))
    except (OSError, ValueError, AttributeError):
        return None
    if 0 < rate <= 6000 and 1 <= accounts <= 8:
        return {"rate": rate, "accounts": accounts}
    return None


def engine_load_accounts(count):
    # Per-engine deterministic range (+1557xxxxxxxx, disjoint from the fixed
    # fixture numbers and the multi-account link range) seeded from the data
    # directory: two engines sharing one store never flap one account row
    # between groups.
    seed = zlib.crc32(str(SIGNAL_DATA_DIR).encode()) % 10_000_000
    return [f"+1557{seed:07d}{index:02d}" for index in range(count)]


def run_load_injector(spec, stop):
    accounts = engine_load_accounts(spec["accounts"])
    spacing = 60.0 / (spec["rate"] * len(accounts))
    seq = 0
    last_ts = 0
    while not stop.is_set():
        seq += 1
        account = accounts[(seq - 1) % len(accounts)]
        # Strictly increasing timestamps: the connector dedupes receives on
        # (account, conversation, direction, sent_at, sender), so a fixed
        # timestamp would collapse the whole ladder into one message.
        now_ms = int(time.time() * 1000)
        last_ts = max(now_ms, last_ts + 1)
        emit_json(
            {
                "jsonrpc": "2.0",
                "method": "receive",
                "params": {
                    "account": account,
                    "envelope": {
                        "source": "+15555550102",
                        "timestamp": last_ts,
                        "dataMessage": {"message": f"soak load {seq}"},
                    },
                },
            }
        )
        with LOAD_LOG.open("a") as log:
            log.write(
                json.dumps(
                    {"seq": seq, "account": account, "timestamp": last_ts},
                    separators=(",", ":"),
                )
                + "\n"
            )
        stop.wait(spacing)


def watch_load_marker():
    while True:
        spec = read_load_spec()
        with LOAD_LOCK:
            if spec != LOAD_STATE["spec"]:
                if LOAD_STATE["stop"] is not None:
                    LOAD_STATE["stop"].set()
                stop = None
                if spec is not None:
                    stop = threading.Event()
                    threading.Thread(
                        target=run_load_injector, args=(spec, stop), daemon=True
                    ).start()
                LOAD_STATE["spec"] = spec
                LOAD_STATE["stop"] = stop
        time.sleep(0.5)


threading.Thread(target=watch_load_marker, daemon=True).start()


# Contract 1.38 test hook: runtime envelope injection. The connector owns the
# only JSON-RPC channels (the engine socket is private, ADR 0002), so a test
# cannot call the engine's `emitEnvelope` face directly; it instead writes
# `.fixture-emit-envelopes.json` holding {"envelopes": [...]} into this data
# directory and each envelope is delivered verbatim to the receiving account
# as a `receive` notification. The marker is deleted after delivery so a
# later write injects again.
EMIT_MARKER = SIGNAL_DATA_DIR / ".fixture-emit-envelopes.json"

# Contract 1.134 test hook: raw engine-notification injection. The
# standalone-method lane (receive.emptied / receive.clockskew /
# receive.conversationState) cannot ride the envelope markers, so a test
# writes `.fixture-emit-notifications.json` holding {"notifications": [...]}
# — each entry a full JSON-RPC notification object — into this data
# directory and every entry is emitted verbatim. The marker is deleted after
# delivery so a later write injects again.
NOTIFICATION_MARKER = SIGNAL_DATA_DIR / ".fixture-emit-notifications.json"

# --- flake instrumentation (temporary) ---
_flake_log_path = Path(f"/tmp/kt-fixture-debug-{os.getpid()}.log")


def flake_log(msg):
    try:
        with _flake_log_path.open("a") as handle:
            handle.write(f"{time.time():.6f} pid={os.getpid()} {msg}\n")
    except OSError:
        pass


def watch_emit_marker():
    flake_log("emit-marker watcher started")
    while True:
        try:
            spec = json.loads(EMIT_MARKER.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
            continue
        envelopes = spec.get("envelopes") if isinstance(spec, dict) else None
        if isinstance(envelopes, list) and envelopes:
            account = spec.get("account") or receiving_account()
            flake_log(f"marker consumed: {len(envelopes)} envelopes -> {account}")
            for index, envelope in enumerate(envelopes):
                flake_log(f"emit begin {index} ts={envelope.get('timestamp')}")
                emit_json(
                    {
                        "jsonrpc": "2.0",
                        "method": "receive",
                        "params": {"account": account, "envelope": envelope},
                    }
                )
                flake_log(f"emit done {index} ts={envelope.get('timestamp')}")
            flake_log("marker envelopes emitted")
        try:
            EMIT_MARKER.unlink()
        except OSError:
            pass
        time.sleep(0.05)


threading.Thread(target=watch_emit_marker, daemon=True).start()


def watch_notification_marker():
    flake_log("notification-marker watcher started")
    while True:
        try:
            spec = json.loads(NOTIFICATION_MARKER.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
            continue
        notifications = spec.get("notifications") if isinstance(spec, dict) else None
        if isinstance(notifications, list) and notifications:
            flake_log(f"notification marker consumed: {len(notifications)} entries")
            for notification in notifications:
                if isinstance(notification, dict):
                    emit_json(notification)
            flake_log("notification marker entries emitted")
        try:
            NOTIFICATION_MARKER.unlink()
        except OSError:
            pass
        time.sleep(0.05)


threading.Thread(target=watch_notification_marker, daemon=True).start()


def emit_json(value):
    with WRITE_LOCK:
        print(json.dumps(value, separators=(",", ":")), flush=True)


def emit_stderr_websocket_error():
    # Mimics signal-cli logging a dead receive WebSocket to stderr.
    with WRITE_LOCK:
        print(
            "ERROR WebSocketConnection - WebSocket connection closed unexpectedly",
            file=sys.stderr,
            flush=True,
        )


# Watchdog fixture: with the marker present, report a dead receive WebSocket on
# stderr repeatedly (every 0.5s, delayed so the watchdog has subscribed). The
# loop re-checks the marker so a test can stop further emissions by deleting it;
# each restarted engine process re-reads it at startup.
def emit_stderr_while_marked():
    while STDERR_MARKER.exists():
        time.sleep(0.5)
        if STDERR_MARKER.exists():
            emit_stderr_websocket_error()


if STDERR_MARKER.exists():
    threading.Thread(target=emit_stderr_while_marked, daemon=True).start()


def receive_notification():
    return {
        "jsonrpc": "2.0",
        "method": "receive",
        "params": {
            "account": receiving_account(),
            "envelope": {
                "source": "+15555550101",
                "timestamp": 42,
                "dataMessage": {"message": "private text"},
            },
        },
    }


# Contract 1.27 test hook: `.fixture-extra-receives.json` holds a JSON array
# of raw envelopes. finishLink's receive burst delivers every not-yet-emitted
# entry in order after the default one, and `flush_extra_receives()` re-checks
# the marker on later upstream calls a test controls — sendTyping (via
# presence.setTypingMessage, which changes no conversation state) and
# listContacts — so envelopes appended after link time (e.g. a group reaction
# remove) reach the connector at a chosen point. contacts.sync itself is no
# trigger inside its 60s debounce window: it answers from the cache without
# calling listContacts, so sendTyping is the reliable post-link flush.
EXTRA_RECEIVES_MARKER = SIGNAL_DATA_DIR / ".fixture-extra-receives.json"
EXTRA_RECEIVES_EMITTED = [0]


def pending_extra_receive_notifications():
    if not EXTRA_RECEIVES_MARKER.exists():
        return []
    envelopes = json.loads(EXTRA_RECEIVES_MARKER.read_text())
    if not isinstance(envelopes, list):
        return []
    pending = envelopes[EXTRA_RECEIVES_EMITTED[0]:]
    EXTRA_RECEIVES_EMITTED[0] = len(envelopes)
    return [
        {
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {"account": receiving_account(), "envelope": envelope},
        }
        for envelope in pending
    ]


def flush_extra_receives():
    pending = pending_extra_receive_notifications()
    flake_log(f"extra-receives flush: {len(pending)} pending")
    for notification in pending:
        emit_json(notification)


def emit_receive():
    emit_json(receive_notification())
    flush_extra_receives()


def emit_json_after(value, delay_seconds):
    time.sleep(delay_seconds)
    emit_json(value)


# Commit-face fixture (contract 1.286 §4.272): a finishLink parked by
# DEFERRED_FINISH_DEVICE is released by the test through DEFERRED_FINISH_MARKER
# once the rotation that retired the code has answered. Emitting from this
# watcher, rather than inline, keeps rotateLink served while the finish is in
# flight and makes the engine-success-after-retirement order deterministic.
def watch_deferred_finish_marker():
    while True:
        time.sleep(0.05)
        if not DEFERRED_FINISH_MARKER.exists():
            continue
        try:
            DEFERRED_FINISH_MARKER.unlink()
        except OSError:
            continue
        while PENDING_FINISH_IDS:
            pending_id = PENDING_FINISH_IDS.pop(0)
            emit_json({
                "jsonrpc": "2.0",
                "id": pending_id,
                "result": account_entry(LINKED_ACCOUNT),
            })


threading.Thread(target=watch_deferred_finish_marker, daemon=True).start()


def log_method_line(name):
    logs_dir = SIGNAL_DATA_DIR / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        with (logs_dir / "engine-stderr.log").open("a") as log:
            log.write("method=" + str(name) + "\n")
    except OSError:
        pass


for line in sys.stdin:
    request = json.loads(line)
    request_id = request.get("id")
    method = request.get("method")
    log_method_line(method)
    params = request.get("params") or {}
    emit_receive_after = False

    if method in ("hang", "sendHang"):
        continue
    if method in ("crash", "crashSend"):
        os._exit(17)
    if method == "malformed":
        print("not-json", flush=True)
        continue
    if method == "oversized":
        print("x" * 512, flush=True)
        continue
    if method == "stallStdin":
        # Regression fixture for the stdin writer task (A7): answer this one
        # request, then stop reading stdin for good while staying alive, like
        # a wedged signal-cli whose pipe stays full.
        emit_json({"jsonrpc": "2.0", "id": request_id, "result": {"method": method}})
        time.sleep(3600)
        continue

    # O1 handshake faces. Both are read-only, account-free, zero-network,
    # exactly like the engine's own registration (compat §3).
    if method == "version":
        if VERSION_TIMEOUT_MARKER.exists():
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": "Request timed out and was cancelled by the engine. (EngineTimeoutException)",
                    "data": {
                        "reason": "REQUEST_TIMEOUT",
                        "retryable": False,
                        "timeoutMs": 60000,
                    },
                },
            })
            continue
        if os.environ.get("KT_FAKE_ENGINE_VERSION_ERROR"):
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "fixture: the engine does not carry the version face",
                },
            })
            continue
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"name": "kt-signal-engine", "version": ENGINE_VERSION},
        }
        delay_ms = int(os.environ.get("KT_FAKE_ENGINE_VERSION_DELAY_MS", "0") or "0")
        if delay_ms > 0:
            threading.Thread(
                target=emit_json_after,
                args=(response, delay_ms / 1000),
                daemon=True,
            ).start()
            continue
        emit_json(response)
        continue
    if method == "engine.protocolCapabilities":
        if os.environ.get("KT_FAKE_ENGINE_NO_CAPABILITIES"):
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "fixture: engine predates the self-certification face",
                },
            })
            continue
        payload = {
            "deviceCapabilities": {
                "storage": True,
                "transfer": False,
                "attachmentBackfill": True,
                "spqr": True,
                "profiles_v2": False,
                "usernameChangeSyncMessage": True,
                "versionedExpirationTimer": False,
                "optionalPhoneNumber": False,
            },
            "deviceCapabilitiesUpload": {
                "attachmentBackfill": True,
                "spqr": True,
                "usernameChangeSyncMessage": True,
                "optionalPhoneNumber": False,
            },
            "linkCapabilities": {
                "attachmentBackfill": False,
                "spqr": False,
                "usernameChangeSyncMessage": False,
            },
            "baseline": {
                "presageRev": "fixture",
                "libsignalVersion": "fixture",
                "libsignalCommit": "fixture",
            },
        }
        revision = os.environ.get("KT_FAKE_ENGINE_CONTRACT_REVISION")
        if revision:
            payload["contractRevision"] = revision
        emit_json({"jsonrpc": "2.0", "id": request_id, "result": payload})
        continue

    if method == "armDelayedReceive":
        # Regression fixture for the stdin writer task (A7): emit a receive
        # notification after a delay without reading anything else from stdin,
        # so a test can prove the actor keeps pumping stdout while the stdin
        # writer is parked on a full pipe.
        threading.Thread(
            target=emit_json_after,
            args=(receive_notification(), max(params.get("delayMs", 0), 0) / 1000),
            daemon=True,
        ).start()
        result = {"method": method}
    elif method == "startLink":
        result = {"deviceLinkUri": ACTIVE_LINK_URI}
        if LINK_ROTATE_MODE not in ("0", "off"):
            attempt = "lk-fixture-%d" % (len(LINK_ATTEMPTS) + 1)
            LINK_ATTEMPTS[attempt] = 1
            result["linkAttemptId"] = attempt
            result["slots"] = [{"deviceLinkUri": ACTIVE_LINK_URI, "slot": 0}]
    elif method == "rotateLink":
        # Contract 1.286 (§4.272): mint a fresh provisioning session for the
        # same attempt. Each rotation answers a new code and its slot number;
        # the connector owns the two-live-slot bound and the commit.
        if LINK_ROTATE_MODE == "method_not_found":
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found: rotateLink"},
            })
            continue
        attempt = params.get("linkAttemptId")
        if LINK_ROTATE_MODE in ("0", "off") or attempt not in LINK_ATTEMPTS:
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "LINK_ATTEMPT_NOT_FOUND"},
            })
            continue
        slot = LINK_ATTEMPTS[attempt]
        LINK_ATTEMPTS[attempt] = slot + 1
        uri = ACTIVE_LINK_URI + "&slot=%d" % slot
        LINK_URIS.add(uri)
        result = {
            "deviceLinkUri": uri,
            "linkAttemptId": attempt,
            "slot": slot,
            "slots": [{"deviceLinkUri": uri, "slot": slot}],
        }
    elif method == "finishLink":
        if params.get("deviceLinkUri") not in LINK_URIS:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "Unknown device link uri."},
            }
            emit_json(response)
            continue
        # Link-finish budget fixture: the engine's own dispatch budget (360 s)
        # is the deadline that fires first in production; the connector's 370 s
        # is the outer backstop. Answer that face on demand so the suite can
        # prove the fold to the link-class unknown outcome without waiting out
        # a real budget.
        if os.environ.get("KT_FAKE_FINISH_ENGINE_TIMEOUT") == "1":
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": "Request timed out and was cancelled by the engine. (EngineTimeoutException)",
                    "data": {
                        "reason": "REQUEST_TIMEOUT",
                        "retryable": False,
                        "timeoutMs": 360000,
                    },
                },
            })
            continue
        # QR B1 (issue #951): the engine's provisioning channel died after
        # the URL handoff — finishLink answers the definite -1 + LINK_LOST.
        if os.environ.get("KT_FAKE_FINISH_LINK_LOST") == "1":
            emit_json({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "LINK_LOST"},
            })
            continue
        if params.get("deviceName") == DEFERRED_FINISH_DEVICE:
            # Park the approval until the test releases it (contract 1.286
            # §4.272): the answer is emitted by the marker watcher, never
            # inline, so rotateLink keeps being served while this finish is in
            # flight and the success lands after the retiring rotation.
            PENDING_FINISH_IDS.append(request_id)
            continue
        if params.get("deviceName") == "[slow-link-test]":
            continue
        if params.get("deviceName") == "[crash-link-test]":
            # Die with the mutating call in flight: the device may or may not
            # have been linked upstream, which is the indeterminate case.
            os._exit(21)
        ACCOUNT_LINKED = True
        DELETED_MARKER.unlink(missing_ok=True)
        # Multi-account mode hands out a fresh number per link; the default
        # mode keeps the fixed fixture number every existing test expects.
        # Contract 1.142 (§4.138): the answer may carry the account's own ACI
        # beside the number (absent under KT_FAKE_OMIT_ACCOUNT_ACI=1).
        number = next_multi_number() if LADDER_ACCOUNT_MODE else LINKED_ACCOUNT
        if POOL_ACCOUNT_MODE:
            OWN_NUMBER_MARKER.write_text(number + "\n")
            registry = SIGNAL_DATA_DIR / "engine-state.json"
            registry.write_text(json.dumps({
                "version": 2,
                "accounts": [{
                    "number": number,
                    "dir": "accounts/lk-fixture",
                }],
            }))
        result = account_entry(number)
        emit_receive_after = True
    elif method == "listAccounts":
        if POOL_ACCOUNT_MODE:
            number = own_number() or state_file_number()
            result = (
                [account_entry(number)]
                if ACCOUNT_LINKED and number is not None
                else []
            )
        elif MULTI_ACCOUNT:
            result = [account_entry(number) for number in linked_multi_numbers()]
        else:
            result = [account_entry(LINKED_ACCOUNT)] if ACCOUNT_LINKED else []
    elif method == "listContacts":
        # Batch I retry hook: one-shot -32603, consumed by the first call.
        # The background-sync worker's single silent retry is exercisable
        # without wedging the engine or touching the read shape.
        fail_once = SIGNAL_DATA_DIR / ".fixture-list-contacts-fail-once"
        if fail_once.exists():
            fail_once.unlink(missing_ok=True)
            emit_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": "Internal error"},
                }
            )
            continue
        # Contract 1.27 hook: deliver extra receives appended to the marker
        # after link time before answering. Only reached outside the
        # contacts-sync debounce window.
        flush_extra_receives()
        result = [
            {
                "number": LINKED_ACCOUNT,
                "profile": {"givenName": "Test", "familyName": "User"},
            },
            {
                "number": "+15555550101",
                "name": "Alice Contact",
                "profile": {"givenName": "Alice", "familyName": "Example"},
            },
            {
                "number": "+15555550102",
                "profile": {"givenName": "Bob"},
            },
        ]
    elif method == "listGroups":
        # Member shape mirrors the pinned 0.14.8 JsonGroupMember record
        # (number, uuid, isAdmin — NON_NULL omissions included), so the §4.39
        # roster capture and projection run against the real wire shape.
        # isTerminated rides the JsonGroup record the same way (the §4.50
        # verified read source); KT_FAKE_TERMINATED_GROUPS lists the group
        # ids that answer it true, so the sync-capture path is exercisable.
        # requestingMembers rides the JsonGroup too (ListGroupsCommand's
        # resolveJsonMembers(group.requestingMembers()), the §4.53 verified
        # read source): KT_FAKE_REQUESTING_GROUPS carries
        # <groupId>=<comma-separated member addresses> entries, so the
        # approval fold is exercisable against a real JsonGroupMemberAddress
        # shape (number-only entries, the NON_NULL omission real single-
        # device candidates carry). pendingMembers rides the same record the
        # same way (resolveJsonMembers(group.pendingMembers()), the §4.57
        # verified read source): KT_FAKE_PENDING_GROUPS carries
        # <groupId>=<comma-separated member addresses> entries, so the
        # invite-revoke fold and the groups.get pendingMembers projection
        # are exercisable against the same shape. The upstream projects no
        # inviter metadata on a pending entry (no addedByUserId — the
        # recorded §4.57 projection difference), so none is faked.
        # Member labels ride the JsonGroupMember record the same way
        # (labelEmoji/label, both @JsonInclude(NON_NULL), the §4.60 verified
        # read source): KT_FAKE_LABELED_GROUPS lists the group ids whose
        # members answer with the fixture label pair, so the sync-capture
        # path is exercisable; unlisted groups keep the label-less shape.
        terminated_ids = {
            value.strip()
            for value in os.environ.get("KT_FAKE_TERMINATED_GROUPS", "").split(",")
            if value.strip()
        }
        requesting: dict[str, list[str]] = {}
        for entry in os.environ.get("KT_FAKE_REQUESTING_GROUPS", "").split(";"):
            if "=" not in entry:
                continue
            group_id, _, addresses = entry.partition("=")
            requesting[group_id.strip()] = [
                address.strip() for address in addresses.split(",") if address.strip()
            ]
        pending: dict[str, list[str]] = {}
        for entry in os.environ.get("KT_FAKE_PENDING_GROUPS", "").split(";"):
            if "=" not in entry:
                continue
            group_id, _, addresses = entry.partition("=")
            pending[group_id.strip()] = [
                address.strip() for address in addresses.split(",") if address.strip()
            ]
        labeled_ids = {
            value.strip()
            for value in os.environ.get("KT_FAKE_LABELED_GROUPS", "").split(",")
            if value.strip()
        }
        # KT_FAKE_ANNOUNCEMENT_GROUPS: group ids whose JsonGroup answers the
        # announcements-only flag true (contract 1.181, §4.181 — the engine's
        # real face carries the flag verbatim; unlisted groups keep the key
        # absent so the pre-1.181 byte-identical face stays exercisable).
        announcement_ids = {
            value.strip()
            for value in os.environ.get("KT_FAKE_ANNOUNCEMENT_GROUPS", "").split(",")
            if value.strip()
        }
        # KT_FAKE_ROLE_GROUPS=<groupId>=<comma numbers>: those groups' members
        # ride the engine's GV2 role word — ADMINISTRATOR for the listed
        # numbers, DEFAULT for the rest — instead of the legacy uuid/isAdmin
        # marks, the 1.181 capture's real engine wire shape.
        role_admins: dict[str, set[str]] = {}
        for entry in os.environ.get("KT_FAKE_ROLE_GROUPS", "").split(";"):
            if "=" not in entry:
                continue
            group_id, _, numbers = entry.partition("=")
            role_admins[group_id.strip()] = {
                number.strip() for number in numbers.split(",") if number.strip()
            }
        fixture_members = [
            {"number": LINKED_ACCOUNT},
            {
                "number": "+15555550101",
                "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                "isAdmin": True,
            },
        ]
        if "ZmFrZS1ncm91cC0x" in labeled_ids:
            fixture_members[0]["label"] = "Ops"
            fixture_members[1]["labelEmoji"] = "🛠️"
            fixture_members[1]["label"] = "Builders"
        if "ZmFrZS1ncm91cC0x" in role_admins:
            admins = role_admins["ZmFrZS1ncm91cC0x"]
            fixture_members = [
                {
                    "number": member["number"],
                    "role": "ADMINISTRATOR"
                    if member["number"] in admins
                    else "DEFAULT",
                }
                for member in fixture_members
            ]
        result = [
            {
                "id": "ZmFrZS1ncm91cC0x",
                "name": "Fixture Group",
                "isMember": True,
                "isTerminated": "ZmFrZS1ncm91cC0x" in terminated_ids,
                "requestingMembers": [
                    {"number": address} for address in requesting.get("ZmFrZS1ncm91cC0x", [])
                ],
                "pendingMembers": [
                    {"number": address} for address in pending.get("ZmFrZS1ncm91cC0x", [])
                ],
                "members": fixture_members,
            },
            {
                "id": "bm90LWEtbWVtYmVy",
                "name": "Former Group",
                "isMember": False,
                "members": [],
            },
        ]
        # §4.167 resync definitive-negative: the marker answers an empty
        # listing — the engine knows no groups at all — so the "group absent
        # from a successful single-group listing" arm is exercisable against
        # the real wire shape (a filtered query that drops its subject).
        if (SIGNAL_DATA_DIR / ".fixture-groups-empty").exists():
            result = []
        elif "ZmFrZS1ncm91cC0x" in announcement_ids and result:
            result[0]["announcementsOnly"] = True
    elif method == "deleteLocalAccountData":
        if DELETE_MODE == "crash_after_delete_once" and DELETED_MARKER.exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "delete was dispatched twice"},
            }
            emit_json(response)
            continue
        if DELETE_MODE == "hold":
            # Relink-gate fixture: hold the delete open in a background
            # thread (the real engine dispatches each request independently,
            # so later link calls must still be read) until the test creates
            # the release marker. The account stays listable meanwhile.
            running = SIGNAL_DATA_DIR / ".fixture-delete-running"
            release = SIGNAL_DATA_DIR / ".fixture-delete-release"
            running.touch()
            held_account = params.get("account")

            def release_delete(
                running=running,
                release=release,
                account=held_account,
                response={"jsonrpc": "2.0", "id": request_id, "result": {}},
            ):
                global ACCOUNT_LINKED
                while not release.exists():
                    time.sleep(0.02)
                ACCOUNT_LINKED = False
                if POOL_ACCOUNT_MODE:
                    number = own_number()
                    if number is not None:
                        with WRITE_LOCK:
                            numbers = [
                                entry
                                for entry in linked_multi_numbers()
                                if entry != number
                            ]
                            ACCOUNT_NUMBERS_LOG.write_text(
                                "\n".join(numbers) + ("\n" if numbers else ""),
                            )
                    OWN_NUMBER_MARKER.unlink(missing_ok=True)
                elif MULTI_ACCOUNT:
                    # The multi-account list is the persisted numbers log;
                    # deleting an account removes it from the engine's list
                    # exactly like the real engine's registry removal.
                    with WRITE_LOCK:
                        numbers = [
                            number
                            for number in linked_multi_numbers()
                            if number != account
                        ]
                        ACCOUNT_NUMBERS_LOG.write_text(
                            "\n".join(numbers) + ("\n" if numbers else "")
                        )
                DELETED_MARKER.touch()
                running.unlink(missing_ok=True)
                emit_json(response)

            threading.Thread(target=release_delete, daemon=True).start()
            continue
        ACCOUNT_LINKED = False
        if POOL_ACCOUNT_MODE:
            number = own_number()
            if number is not None:
                with WRITE_LOCK:
                    numbers = [
                        entry
                        for entry in linked_multi_numbers()
                        if entry != number
                    ]
                    ACCOUNT_NUMBERS_LOG.write_text(
                        "\n".join(numbers) + ("\n" if numbers else ""),
                    )
            OWN_NUMBER_MARKER.unlink(missing_ok=True)
        elif MULTI_ACCOUNT:
            with WRITE_LOCK:
                numbers = [
                    number
                    for number in linked_multi_numbers()
                    if number != params.get("account")
                ]
                ACCOUNT_NUMBERS_LOG.write_text("\n".join(numbers) + ("\n" if numbers else ""))
        DELETED_MARKER.touch()
        if DELETE_MODE == "crash_after_delete_once":
            os._exit(19)
        result = {}
    elif method == "lookupOutgoingDispatch":
        # §4.179 unknown-outcome reconciliation probe: the connector's startup
        # pass asks whether the engine's own ledger holds the dispatched row.
        # Record the exact params (asserting the row's addressing — account /
        # recipient|groupId / sentTimestamp / toleranceMs); answer shape is
        # marker-driven so a test can arm dispatched=true / dispatched=false /
        # error faces per row set. Default = the honest never-dispatched face.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if LOOKUP_ERROR_MARKER.exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        if LOOKUP_DISPATCH_MARKER.exists():
            result = json.loads(LOOKUP_DISPATCH_MARKER.read_text())
        else:
            result = {"dispatched": False}
    elif method == "getConfiguration":
        # §4.190 receipt-gate fetch: the connector's startup pass mirrors the
        # account's readReceipts flag. The real engine answers the six-key
        # account-configuration face (AccountRecord truth, proto3 defaults
        # when no storage state, phoneNumberSharingMode key-absent when
        # unset); the fixture answers the gate's one consumed key off
        # KT_FAKE_READ_RECEIPTS (default false — the proto default),
        # key-verbatim, no marker file needed.
        result = {
            "readReceipts": os.environ.get("KT_FAKE_READ_RECEIPTS") == "1",
            "typingIndicators": False,
            "linkPreviews": False,
            "unlistedPhoneNumber": False,
            "storiesDisabled": False,
        }
    elif method == "send":
        # Record the exact JSON-RPC params so tests can assert what the
        # connector dispatched upstream (e.g. quoteTimestamp/quoteAuthor).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # §4.154 (contract 1.156) one-shot parse-gate answer: the marker
        # `.fixture-send-rejected` answers the plain -32603 face the real
        # engine's fail-closed send parse answers for every storyReply
        # value-domain violation (single-sided presence, empty author,
        # zero/negative/fractional timestamp) — the gates themselves are
        # the real engine's, which the fixture deliberately does not
        # re-implement.
        if (SIGNAL_DATA_DIR / ".fixture-send-rejected").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        # Contract 1.285 §4.269 one-shot dispatch-timeout answer: the real
        # engine's -32000 (EngineTimeoutException) face with its promised
        # data. A mutating send that receives it may already have been
        # written, so the connector must fold it to the existing unknown
        # outcome — the row settles unknown, never failed, no auto retry.
        if ENGINE_TIMEOUT_ARMED.exists() and not ENGINE_TIMEOUT_DONE.exists():
            ENGINE_TIMEOUT_DONE.touch()
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": "Request timed out and was cancelled by the engine. (EngineTimeoutException)",
                    "data": {
                        "reason": "REQUEST_TIMEOUT",
                        "retryable": False,
                        "timeoutMs": 60000,
                    },
                },
            }
            emit_json(response)
            continue
        # §4.123 one-shot server-unavailable answer (transport error shape
        # the engine classifier maps to ServerUnavailable), armed per test
        # through this data dir's marker file.
        if SEND_UNAVAILABLE_ARMED.exists() and not SEND_UNAVAILABLE_DONE.exists():
            SEND_UNAVAILABLE_DONE.touch()
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -3,
                    "message": "Failed to send message: Bad gateway (ServerUnavailableException)",
                },
            }
            emit_json(response)
            continue
        if SEND_RATELIMIT_ARMED.exists() and not SEND_RATELIMIT_DONE.exists():
            SEND_RATELIMIT_DONE.touch()
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "Failed to send message: Rate limited. (RateLimitExceeded)",
                },
            }
            emit_json(response)
            continue
        result = {"timestamp": 99, "results": []}
        # Contract 1.35 test hook: a sticker send whose pack id is all-f
        # crashes with the mutating call in flight — the send may or may not
        # have reached the server, which is the indeterminate case
        # (engine-exit path).
        if (params.get("sticker") or {}).get("packId") == "ffffffff":
            os._exit(23)
    elif method == "remoteDelete":
        # Same dispatch-recording discipline as `send`: the exact upstream
        # params, so tests can assert targetTimestamp/recipient/groupId.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # Slow answer: the result lands after a short connector request
        # timeout, so the mutating outcome is indeterminate (timeout path).
        if params.get("targetTimestamp") == 350:
            response = {"jsonrpc": "2.0", "id": request_id, "result": {}}
            threading.Thread(
                target=emit_json_after,
                args=(response, 0.35),
                daemon=True,
            ).start()
            continue
        # One-shot crash with the mutating call in flight: the delete may or
        # may not have reached the server, which is the indeterminate case
        # (engine-exit path).
        if params.get("targetTimestamp") == 421:
            os._exit(23)
        result = {}
    elif method == "sendReaction":
        # Same dispatch-recording discipline as `send`: the exact upstream
        # params, so tests can assert targetAuthor/targetTimestamp/remove.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # Slow answer: the result lands after a short connector request
        # timeout, so the mutating outcome is indeterminate (timeout path).
        if params.get("targetTimestamp") == 351:
            response = {"jsonrpc": "2.0", "id": request_id, "result": {}}
            threading.Thread(
                target=emit_json_after,
                args=(response, 0.35),
                daemon=True,
            ).start()
            continue
        # One-shot crash with the mutating call in flight: the reaction may
        # or may not have reached the server, which is the indeterminate
        # case (engine-exit path).
        if params.get("targetTimestamp") == 423:
            os._exit(23)
        result = {}
    elif method == "sendStoryReaction":
        # §4.151 story-reaction send (contract 1.152, engine 4822e99): the
        # engine's sendStoryReaction wire mirror — the official reactToStory
        # alignment (Reaction + StoryContext dual anchor, place-only). Same
        # dispatch-recording discipline as `send`: the exact upstream
        # params, so tests assert the {account, storyAuthor, storyTimestamp,
        # emoji} contract byte-for-byte (the send-family discipline). The
        # account gate rides the same engine-state registry (an unregistered
        # account answers the plain -32603, the engine's unknown-account
        # face). The marker `.fixture-story-reaction-rejected` answers the
        # engine's parse/identity/profileSharing gate face (-32603) — the
        # value domain gates are the real engine's fail-closed parse, which
        # the fixture deliberately does not re-implement. Success answers
        # `{}` (the engine's empty success object). §4.157 (contract 1.159)
        # the group leg's additive answer face: groupId present (absent =
        # the pre-1.159 no-group shape) adds {group: {groupId, timestamp}} —
        # the engine fake discipline (group present = the group face, the
        # group id echoed and the group leg's own timestamp; the real
        # engine's group state and member resolution stay unreachable to
        # the fake).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        story_account = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    story_account = entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            story_account = None
        if story_account is None or (
            SIGNAL_DATA_DIR / ".fixture-story-reaction-rejected"
        ).exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        result = {}
        if params.get("groupId") is not None:
            result["group"] = {
                "groupId": params["groupId"],
                "timestamp": int(time.time() * 1000),
            }
    elif method == "deleteStoryForEveryone":
        # §4.152 story delete-for-everyone fan-out (contract 1.153, engine
        # 7320393): the engine's deleteStoryForEveryone wire mirror — the
        # official sendDeleteForEveryone alignment (per-recipient DOE legs
        # over the story channel + the exactly-once self-sync). Same
        # dispatch-recording discipline as `send`: the exact upstream
        # params, so tests assert the {account, targetTimestamp,
        # updatedStoryRecipients[, recipients]} contract byte-for-byte (the
        # send-family discipline). The account gate rides the same
        # engine-state registry (an unregistered account answers the plain
        # -32603, the engine's unknown-account face). The marker
        # `.fixture-story-delete-rejected` answers the engine's parse gate
        # face (-32603) — the value-domain gates (the timestamp domain, the
        # recipients entry shapes and the rejected single-string form, the
        # updatedStoryRecipients member shapes) are the real engine's
        # fail-closed parse, which the fixture deliberately does not
        # re-implement. Success answers a pinned {timestamp} (the DOE
        # envelope ts; the real engine answers the new deletion's own
        # Signal timestamp).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        delete_account = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    delete_account = entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            delete_account = None
        if delete_account is None or (
            SIGNAL_DATA_DIR / ".fixture-story-delete-rejected"
        ).exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        result = {"timestamp": 1727000999999}
    elif method in ("sendPinMessage", "sendUnpinMessage", "sendAdminDelete"):
        # Contract 1.33 pin family: same dispatch-recording discipline as
        # `send`: the exact upstream params, so tests can assert
        # targetAuthor/targetTimestamp/pinDurationSeconds/groupId.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # Slow answer: the result lands after a short connector request
        # timeout, so the mutating outcome is indeterminate (timeout path).
        if method == "sendPinMessage" and params.get("targetTimestamp") == 352:
            response = {"jsonrpc": "2.0", "id": request_id, "result": {}}
            threading.Thread(
                target=emit_json_after,
                args=(response, 0.35),
                daemon=True,
            ).start()
            continue
        # One-shot crash with the mutating call in flight: the pin may or may
        # not have reached the server, which is the indeterminate case
        # (engine-exit path).
        if method == "sendPinMessage" and params.get("targetTimestamp") == 424:
            os._exit(23)
        result = {}
    elif method in ("sendDeliveryReceipt", "sendReadReceipt", "sendViewedReceipt"):
        # Contract 1.34 receipt face: same dispatch-recording discipline as
        # `send`: the exact upstream params, so tests can assert the
        # {account, recipient (single author), timestamps} contract.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # One-shot crash with the mutating call in flight: the receipt may or
        # may not have reached the server, which is the indeterminate case
        # (engine-exit path). Sentinel 425 keeps the sentinel space disjoint
        # from remoteDelete 421 / reaction 423 / pin 424.
        if 425 in (params.get("timestamps") or []):
            os._exit(23)
        # §4.119 stopgap gate: `.fixture-fail-receipt` answers a definite
        # upstream rejection for the receipt faces (the stale-timestamp
        # rejection the supervisor failure debounce rides), after the
        # dispatch log line — the log records the attempt, the error is the
        # outcome.
        if (SIGNAL_DATA_DIR / ".fixture-fail-receipt").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "RECEIPT_TIMESTAMP_REJECTED"},
            }
            emit_json(response)
            continue
        result = {}
    elif method == "sendViewOnceOpen":
        # Contract 1.38 view-once open face: same dispatch-recording
        # discipline as `send`: the exact upstream params, so tests can assert
        # the {account, senderAci, timestamp} contract.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # One-shot crash with the mutating call in flight: the open sync may
        # or may not have reached the server, which is the indeterminate case
        # (engine-exit path). Sentinel 426 keeps the sentinel space disjoint
        # from remoteDelete 421 / reaction 423 / pin 424 / receipt 425.
        if params.get("timestamp") == 426:
            os._exit(23)
        result = {}
    elif method == "deleteForMeConversation":
        # Contract 1.118 §4.99 delete-for-me upstream leg: same
        # dispatch-recording discipline as `send`: the exact upstream
        # params, so tests can assert the {account, kind, conversationId,
        # localOnly?/mostRecentMessages?} contract. Fail-closed param gate
        # mirrors the engine's -32603 face (the deterministic refusal the
        # connector's receipt-class degradation folds into `unknown`).
        account = params.get("account")
        kind = params.get("kind")
        conversation_id = params.get("conversationId")
        local_only = params.get("localOnly")
        most_recent = params.get("mostRecentMessages")
        non_expiring = params.get("mostRecentNonExpiringMessages")

        def _entries_ok(entries):
            if entries is None:
                return True
            if not isinstance(entries, list) or len(entries) > 5:
                return False
            for entry in entries:
                if not isinstance(entry, dict):
                    return False
                author = entry.get("author")
                timestamp = entry.get("timestamp")
                if not isinstance(author, str) or not author:
                    return False
                if not isinstance(timestamp, int) or timestamp <= 0:
                    return False
            return True

        shape_ok = (
            isinstance(account, str)
            and bool(account)
            and kind in ("contact", "group")
            and isinstance(conversation_id, str)
            and bool(conversation_id)
            and _entries_ok(most_recent)
            and _entries_ok(non_expiring)
        )
        if local_only is not None and not isinstance(local_only, bool):
            shape_ok = False
        if local_only and (most_recent or non_expiring):
            shape_ok = False
        if not local_only and (not most_recent or not (
                isinstance(most_recent, list) and 1 <= len(most_recent) <= 5)):
            shape_ok = False
        if not shape_ok:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "invalid deleteForMeConversation params"},
            }
            emit_json(response)
            continue
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # One-shot crash with the mutating call in flight: the sync message
        # may or may not have reached the other devices, which is the
        # indeterminate case (engine-exit path). Sentinel timestamp 427
        # keeps the sentinel space disjoint from remoteDelete 421 /
        # reaction 423 / pin 424 / receipt 425 / view-once 426.
        if any(
            entry.get("timestamp") == 427 for entry in (most_recent or [])
        ):
            os._exit(23)
        result = {"status": "sent"}
    elif method == "deleteForMeMessages":
        # Contract 1.197 §4.197 message-level delete-for-me upstream leg:
        # same dispatch-recording discipline as its conversation twin, so
        # tests can assert the {account, kind, conversationId, entries}
        # contract. Fail-closed param gate mirrors the engine's -32603 face.
        account = params.get("account")
        kind = params.get("kind")
        conversation_id = params.get("conversationId")
        entries = params.get("entries")
        shape_ok = (
            isinstance(account, str)
            and bool(account)
            and kind in ("contact", "group")
            and isinstance(conversation_id, str)
            and bool(conversation_id)
            and isinstance(entries, list)
            and 1 <= len(entries) <= 256
        )
        if shape_ok:
            for entry in entries:
                if not isinstance(entry, dict):
                    shape_ok = False
                    break
                author = entry.get("author")
                timestamp = entry.get("timestamp")
                if not isinstance(author, str) or not author:
                    shape_ok = False
                    break
                if not isinstance(timestamp, int) or timestamp <= 0:
                    shape_ok = False
                    break
        if not shape_ok:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "invalid deleteForMeMessages params"},
            }
            emit_json(response)
            continue
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        result = {"status": "sent"}
    elif method == "getStickerPackManifest":
        # Contract 1.36 browse face: deterministic manifest keyed by pack id.
        # Sentinel packId ffffffffffffffffffffffffffffffff answers a
        # structured key-invalid error; 0000... answers a retryable fetch
        # failure; 1111... answers a codeless error (the degradation path);
        # anything else returns the fixture manifest (2 stickers + cover).
        if params.get("packId") == "f" * 32:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STICKER_PACK_KEY_INVALID"},
            }
            emit_json(response)
            continue
        if params.get("packId") == "0" * 32:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STICKER_PACK_FETCH_FAILED"},
            }
            emit_json(response)
            continue
        if params.get("packId") == "1" * 32:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "fixture malformed"},
            }
            emit_json(response)
            continue
        result = {
            "title": "Fixture Pack",
            "author": "KT Fixture",
            "cover": {"id": 1, "emoji": "🎉", "contentType": "image/webp"},
            "stickers": [
                {"id": 1, "emoji": "🎉", "contentType": "image/webp"},
                {"id": 2, "emoji": "🚀", "contentType": "image/png"},
            ],
            "stickerCount": 2,
        }
    elif method == "getStickerImage":
        # Contract 1.36 browse face: a small deterministic base64 payload.
        # Sentinels mirror the manifest error mapping; stickerId 413 answers
        # STICKER_IMAGE_TOO_LARGE.
        if params.get("packId") == "f" * 32:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STICKER_PACK_KEY_INVALID"},
            }
            emit_json(response)
            continue
        if params.get("stickerId") == 404:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STICKER_PACK_MALFORMED"},
            }
            emit_json(response)
            continue
        if params.get("stickerId") == 413:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STICKER_IMAGE_TOO_LARGE"},
            }
            emit_json(response)
            continue
        payload = base64.b64encode(b"fixture-bytes").decode()
        result = {"dataBase64": payload, "contentType": "image/webp", "size": 13}
    elif method == "getPinnedConversations":
        # Contract 1.36 pin sync read: the cloud order as a fixture constant.
        result = {"pinned": list(PINNED_STATE)}
    elif method == "setConversationPinned":
        # Contract 1.36 pin sync write: record the exact upstream params
        # (tests assert the resolved conversationId/kind/pinned), apply the
        # write to the fixture pin state, answer the post-write cloud state.
        # Peer-key sentinels (locally resolvable, so the connector forwards
        # them): +15555550998 answers a structured STORAGE_UNAVAILABLE,
        # +15555550997 answers CONVERSATION_NOT_RESOLVED, +15555550999
        # crashes with the mutating call in flight.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        conversation_id = params.get("conversationId")
        if conversation_id == "+15555550998":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if conversation_id == "+15555550997":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "CONVERSATION_NOT_RESOLVED"},
            }
            emit_json(response)
            continue
        if conversation_id == "+15555550999":
            os._exit(29)
        pinned = [entry for entry in PINNED_STATE if entry["conversationId"] != conversation_id]
        if params.get("pinned"):
            pinned.insert(0, {"conversationId": conversation_id, "kind": params.get("kind")})
        PINNED_STATE[:] = pinned
        result = {"pinned": list(PINNED_STATE)}
    elif method == "getStickerPackSyncs":
        # Contract 1.37 sticker-pack sync read: the record projection as a
        # fixture constant (one installed pack + one tombstone).
        result = {"packs": list(PACK_SYNC_STATE)}
    elif method == "setStickerPackSync":
        # Contract 1.37 sticker-pack sync write: record the exact upstream
        # params (tests assert the resolved account/packId/packKey/position/
        # installed contract), apply the write to the fixture record state,
        # answer the post-write cloud state. Pack-id sentinels: "f"*32
        # answers a structured STORAGE_UNAVAILABLE, "0"*32 answers
        # STORAGE_READ_FAILED, "1"*32 crashes with the mutating call in
        # flight (os._exit(30); disjoint from the pin-sync 29 and the
        # sticker-send 23 paths).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        pack_id = params.get("packId")
        if pack_id == "f" * 32:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if pack_id == "0" * 32:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_READ_FAILED"},
            }
            emit_json(response)
            continue
        if pack_id == "1" * 32:
            os._exit(30)
        packs = [entry for entry in PACK_SYNC_STATE if entry["packId"] != pack_id]
        if params.get("installed"):
            # Engine contract: an install carries the key (the connector
            # validated it) and the optional position; the tombstone clears.
            packs.insert(
                0,
                {
                    "packId": pack_id,
                    "packKey": params.get("packKey"),
                    "position": params.get("position"),
                    "deletedAtTimestampMs": None,
                },
            )
        else:
            # An uninstall ignores packKey/position entirely and writes the
            # tombstone with the engine clock.
            packs.append(
                {
                    "packId": pack_id,
                    "packKey": None,
                    "position": None,
                    "deletedAtTimestampMs": int(time.time() * 1000),
                }
            )
        PACK_SYNC_STATE[:] = packs
        result = {"packs": list(PACK_SYNC_STATE)}
    elif method == "chatFolders.list":
        # Contract 1.95 chat-folder sync read: the storage-order record
        # projection as a fixture constant (one ALL folder + one CUSTOM
        # folder with the three-kind recipient arrays). Account gate mirrors
        # the engine (-32603 on an unregistered account). Markers the driving
        # test writes steer the structured storage ladder:
        # `.fixture-chat-folder-read-failed` answers STORAGE_READ_FAILED,
        # `.fixture-chat-folder-unavailable` answers STORAGE_UNAVAILABLE.
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-chat-folder-read-failed").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_READ_FAILED"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-chat-folder-unavailable").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        result = {"folders": list(CHAT_FOLDER_STATE)}
    elif method == "chatFolders.setRecords":
        # Contract 1.95 chat-folder sync write: record the exact upstream
        # params (tests assert the resolved account and the verbatim
        # records/removeIds contract), apply the official upload semantics —
        # upsert by id in place, removeIds out of the set — and answer the
        # post-write cloud state. Account gate mirrors the engine (-32603 on
        # an unregistered account); the structured ladder steers from
        # markers: `.fixture-chat-folder-write-failed` answers
        # STORAGE_WRITE_FAILED, `.fixture-chat-folder-read-failed` answers
        # STORAGE_READ_FAILED (the engine reads before it writes),
        # `.fixture-chat-folder-unavailable` answers STORAGE_UNAVAILABLE.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        marker_errors = (
            (".fixture-chat-folder-write-failed", "STORAGE_WRITE_FAILED"),
            (".fixture-chat-folder-read-failed", "STORAGE_READ_FAILED"),
            (".fixture-chat-folder-unavailable", "STORAGE_UNAVAILABLE"),
        )
        for marker, code in marker_errors:
            if (SIGNAL_DATA_DIR / marker).exists():
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": code},
                }
                emit_json(response)
                continue
        # The mutating-crash sentinel (record id magic; exit 31 = the shared
        # mutating-in-flight crash code, disjoint from every other face by
        # trigger): the connector must answer SEND_OUTCOME_UNKNOWN and never
        # retry.
        if any(
            isinstance(record, dict)
            and record.get("id") == "cede0000-0000-4000-8000-000000000031"
            for record in params.get("records") or []
        ):
            os._exit(31)
        # The engine's strict record grammar (parse_folder): every record
        # must carry the eight required keys with the right shapes — id (uuid
        # string), name (string), position (u64), the four booleans, and the
        # folderType word — else the engine answers -32603. Optional: the two
        # recipient arrays and deletedAtTimestampMs.
        def _folder_shape_ok(record):
            if not isinstance(record, dict):
                return False
            try:
                uuid.UUID(str(record.get("id")))
            except (ValueError, AttributeError, TypeError):
                return False
            if not isinstance(record.get("name"), str):
                return False
            if not isinstance(record.get("position"), int) or isinstance(
                record.get("position"), bool
            ):
                return False
            for key in (
                "showOnlyUnread",
                "showMutedChats",
                "includeAllIndividualChats",
                "includeAllGroupChats",
            ):
                if not isinstance(record.get(key), bool):
                    return False
            if record.get("folderType") not in ("UNKNOWN", "ALL", "CUSTOM"):
                return False
            return True

        records = params.get("records") or []
        if any(not _folder_shape_ok(record) for record in records):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        with WRITE_LOCK:
            folders = [
                entry
                for entry in CHAT_FOLDER_STATE
                if entry["id"] not in set(params.get("removeIds") or [])
            ]
            for record in params.get("records") or []:
                record = json.loads(json.dumps(record))
                for index, entry in enumerate(folders):
                    if entry["id"] == record["id"]:
                        folders[index] = record
                        break
                else:
                    folders.append(record)
            CHAT_FOLDER_STATE[:] = folders
        result = {"folders": list(CHAT_FOLDER_STATE)}
    elif method == "notificationProfiles.list":
        # Contract 1.129 notification-profile sync read: the storage-order
        # record projection as a fixture constant (one schedule-less profile
        # + one scheduled profile with an allowed member). Account gate
        # mirrors the engine (-32603 on an unregistered account). Markers
        # the driving test writes steer the structured storage ladder:
        # `.fixture-profile-read-failed` answers STORAGE_READ_FAILED,
        # `.fixture-profile-unavailable` answers STORAGE_UNAVAILABLE.
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-profile-read-failed").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_READ_FAILED"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-profile-unavailable").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        result = {"profiles": list(NOTIFICATION_PROFILE_STATE)}
    elif method == "notificationProfiles.setRecords":
        # Contract 1.129 notification-profile sync write: record the exact
        # upstream params (tests assert the resolved account and the
        # verbatim records/removeIds contract), apply the official upload
        # semantics — upsert by id in place, removeIds out of the set — and
        # answer the post-write cloud state. Account gate mirrors the
        # engine (-32603 on an unregistered account); the structured ladder
        # steers from markers: `.fixture-profile-write-failed` answers
        # STORAGE_WRITE_FAILED, `.fixture-profile-read-failed` answers
        # STORAGE_READ_FAILED (the engine reads before it writes),
        # `.fixture-profile-unavailable` answers STORAGE_UNAVAILABLE.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        marker_errors = (
            (".fixture-profile-write-failed", "STORAGE_WRITE_FAILED"),
            (".fixture-profile-read-failed", "STORAGE_READ_FAILED"),
            (".fixture-profile-unavailable", "STORAGE_UNAVAILABLE"),
        )
        for marker, code in marker_errors:
            if (SIGNAL_DATA_DIR / marker).exists():
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": code},
                }
                emit_json(response)
                continue
        # The mutating-crash sentinel (record id magic; exit 31 = the shared
        # mutating-in-flight crash code, disjoint from every other face by
        # trigger): the connector must answer SEND_OUTCOME_UNKNOWN and never
        # retry.
        if any(
            isinstance(record, dict)
            and record.get("id") == "cede000000000000400080000000000032"
            for record in params.get("records") or []
        ):
            os._exit(31)
        # The engine's strict record grammar (parse_profile): every record
        # must carry the required keys with the right shapes — id (32-char
        # lowercase hex), name (non-empty string), color/createdAtMs (u64),
        # the three booleans, allowedMembers (entries {conversationId,
        # kind}), scheduleEnabled — else the engine answers -32603.
        # Optional: emoji, scheduleStartTime/scheduleEndTime (u32 or
        # absent), scheduleDaysEnabled (1..=7), deletedAtTimestampMs (u64
        # or absent).
        def _profile_shape_ok(record):
            if not isinstance(record, dict):
                return False
            profile_id = record.get("id")
            if (
                not isinstance(profile_id, str)
                or len(profile_id) != 32
                or any(char not in "0123456789abcdef" for char in profile_id)
            ):
                return False
            if not isinstance(record.get("name"), str) or not record.get("name"):
                return False
            for key in ("color", "createdAtMs"):
                value = record.get(key)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    return False
            for key in ("allowAllCalls", "allowAllMentions", "scheduleEnabled"):
                if not isinstance(record.get(key), bool):
                    return False
            members = record.get("allowedMembers")
            if not isinstance(members, list):
                return False
            for member in members:
                if not isinstance(member, dict):
                    return False
                if not isinstance(member.get("conversationId"), str):
                    return False
                if member.get("kind") not in ("contact", "group", "legacyGroup"):
                    return False
            days = record.get("scheduleDaysEnabled")
            if days is not None:
                if not isinstance(days, list):
                    return False
                for day in days:
                    if not isinstance(day, int) or isinstance(day, bool):
                        return False
                    if not 1 <= day <= 7:
                        return False
            return True

        records = params.get("records") or []
        if any(not _profile_shape_ok(record) for record in records):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        with WRITE_LOCK:
            profiles = [
                entry
                for entry in NOTIFICATION_PROFILE_STATE
                if entry["id"] not in set(params.get("removeIds") or [])
            ]
            for record in params.get("records") or []:
                record = json.loads(json.dumps(record))
                for index, entry in enumerate(profiles):
                    if entry["id"] == record["id"]:
                        profiles[index] = record
                        break
                else:
                    profiles.append(record)
            NOTIFICATION_PROFILE_STATE[:] = profiles
        result = {"profiles": list(NOTIFICATION_PROFILE_STATE)}
    elif method == "storyDistributionLists.list":
        # Contract 1.130 story-distribution-list sync read: the storage-order
        # record projection as a fixture constant (My Story = the all-zero
        # uuid, no special case + one custom list carrying both member
        # faces). Account gate mirrors the engine (-32603 on an unregistered
        # account). Markers the driving test writes steer the structured
        # storage ladder: `.fixture-story-list-read-failed` answers
        # STORAGE_READ_FAILED, `.fixture-story-list-unavailable` answers
        # STORAGE_UNAVAILABLE.
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-story-list-read-failed").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_READ_FAILED"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-story-list-unavailable").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        result = {"lists": list(STORY_LIST_STATE)}
    elif method == "storyDistributionLists.setRecords":
        # Contract 1.130 story-distribution-list sync write: record the
        # exact upstream params (tests assert the resolved account and the
        # verbatim records/removeIds contract), apply the official upload
        # semantics — upsert by identifier in place, removeIds out of the
        # set — and answer the post-write cloud state. Account gate mirrors
        # the engine (-32603 on an unregistered account); the structured
        # ladder steers from markers: `.fixture-story-list-write-failed`
        # answers STORAGE_WRITE_FAILED, `.fixture-story-list-read-failed`
        # answers STORAGE_READ_FAILED (the engine reads before it writes),
        # `.fixture-story-list-unavailable` answers STORAGE_UNAVAILABLE.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        marker_errors = (
            (".fixture-story-list-write-failed", "STORAGE_WRITE_FAILED"),
            (".fixture-story-list-read-failed", "STORAGE_READ_FAILED"),
            (".fixture-story-list-unavailable", "STORAGE_UNAVAILABLE"),
        )
        for marker, code in marker_errors:
            if (SIGNAL_DATA_DIR / marker).exists():
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": code},
                }
                emit_json(response)
                continue
        # The mutating-crash sentinel (identifier magic; exit 31 = the
        # shared mutating-in-flight crash code, disjoint from every other
        # face by trigger): the connector must answer SEND_OUTCOME_UNKNOWN
        # and never retry.
        if any(
            isinstance(record, dict)
            and record.get("identifier") == "cede0000-0000-4000-8000-000000000033"
            for record in params.get("records") or []
        ):
            os._exit(31)
        # The engine's strict record grammar (parse_story_list): every
        # record must carry the required keys with the right shapes —
        # identifier (uuid string), name (string; empty is the official
        # tombstone posture), recipientServiceIds (string array),
        # allowsReplies / isBlockList (booleans) — else the engine answers
        # -32603. Optional: deletedAtTimestamp (u64 or absent),
        # recipientServiceIdsBinary (string array or absent).
        def _story_list_shape_ok(record):
            if not isinstance(record, dict):
                return False
            try:
                uuid.UUID(str(record.get("identifier")))
            except (ValueError, AttributeError, TypeError):
                return False
            if not isinstance(record.get("name"), str):
                return False
            for key in ("recipientServiceIds", "recipientServiceIdsBinary"):
                value = record.get(key)
                if value is not None and not (
                    isinstance(value, list)
                    and all(isinstance(item, str) for item in value)
                ):
                    return False
            for key in ("allowsReplies", "isBlockList"):
                if not isinstance(record.get(key), bool):
                    return False
            stamp = record.get("deletedAtTimestamp")
            if stamp is not None and (
                not isinstance(stamp, int) or isinstance(stamp, bool) or stamp < 0
            ):
                return False
            return True

        records = params.get("records") or []
        if any(not _story_list_shape_ok(record) for record in records):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        with WRITE_LOCK:
            lists = [
                entry
                for entry in STORY_LIST_STATE
                if entry["identifier"] not in set(params.get("removeIds") or [])
            ]
            for record in params.get("records") or []:
                record = json.loads(json.dumps(record))
                for index, entry in enumerate(lists):
                    if entry["identifier"] == record["identifier"]:
                        lists[index] = record
                        break
                else:
                    lists.append(record)
            STORY_LIST_STATE[:] = lists
        result = {"lists": list(STORY_LIST_STATE)}
    elif method in ("storage.mergeContacts", "storage.importGroups"):
        # Contract 1.131 storage ingest reads: the engine's own camelCase
        # summary tallies (non-zero here so the pass-through test pins the
        # verbatim key face). Account gate mirrors the engine (-32603 on an
        # unregistered account); the structured ladder steers from markers:
        # `.fixture-storage-sync-read-failed` answers STORAGE_READ_FAILED,
        # `.fixture-storage-sync-unavailable` answers STORAGE_UNAVAILABLE.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        for marker, code in (
            (".fixture-storage-sync-read-failed", "STORAGE_READ_FAILED"),
            (".fixture-storage-sync-unavailable", "STORAGE_UNAVAILABLE"),
        ):
            if (SIGNAL_DATA_DIR / marker).exists():
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": code},
                }
                emit_json(response)
                continue
        if method == "storage.mergeContacts":
            result = {
                "recordsRead": 12,
                "skipped": 1,
                "identitiesNew": 3,
                "identitiesReplaced": 0,
                "profileKeysSet": 2,
                "contactsCreated": 4,
                "trustStatesSynced": 5,
            }
        else:
            result = {"recordsRead": 7, "imported": 5, "alreadyKnown": 1, "failed": 1}
    elif method == "storage.getCallLinks":
        # Contract 1.131 call-link read: the projection as a fixture
        # constant (one live link with an admin passkey + one tombstoned
        # link without). Account gate and markers as the ingest reads.
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        for marker, code in (
            (".fixture-storage-sync-read-failed", "STORAGE_READ_FAILED"),
            (".fixture-storage-sync-unavailable", "STORAGE_UNAVAILABLE"),
        ):
            if (SIGNAL_DATA_DIR / marker).exists():
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": code},
                }
                emit_json(response)
                continue
        result = {"callLinks": list(CALL_LINK_STATE)}
    elif method == "storage.setCallLink":
        # Contract 1.131 call-link write: record the exact upstream params
        # (tests assert the resolved account, the verbatim rootKey, and the
        # arms-only-when-present contract), upsert by rootKey in place, and
        # answer the post-write cloud state. Markers:
        # `.fixture-storage-sync-write-failed` answers STORAGE_WRITE_FAILED,
        # `.fixture-storage-sync-read-failed` answers STORAGE_READ_FAILED
        # (the engine reads before it writes),
        # `.fixture-storage-sync-unavailable` answers STORAGE_UNAVAILABLE.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            numbers = {
                entry.get("number")
                for entry in state.get("accounts") or []
            }
        except (OSError, ValueError, AttributeError):
            numbers = set()
        if params.get("account") not in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        for marker, code in (
            (".fixture-storage-sync-write-failed", "STORAGE_WRITE_FAILED"),
            (".fixture-storage-sync-read-failed", "STORAGE_READ_FAILED"),
            (".fixture-storage-sync-unavailable", "STORAGE_UNAVAILABLE"),
        ):
            if (SIGNAL_DATA_DIR / marker).exists():
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": code},
                }
                emit_json(response)
                continue
        # The mutating-crash sentinel (rootKey magic; exit 31 = the shared
        # mutating-in-flight crash code, disjoint from every other face by
        # trigger): the connector must answer SEND_OUTCOME_UNKNOWN and never
        # retry.
        if params.get("rootKey") == "Zml4dHVyZS1jcmFzaC0zMg==":
            os._exit(31)
        with WRITE_LOCK:
            links = [
                entry
                for entry in CALL_LINK_STATE
                if entry["rootKey"] != params.get("rootKey")
            ]
            links.append(
                {
                    "rootKey": params.get("rootKey"),
                    "adminPasskey": params.get("adminPasskey"),
                    "deletedAtTimestampMs": params.get("deletedAtTimestampMs"),
                }
            )
            CALL_LINK_STATE[:] = links
        result = {"callLinks": list(CALL_LINK_STATE)}
    elif method == "setAccountConfiguration":
        # Contract 1.46 §4.45 account settings write: record the exact
        # upstream params (tests assert only the provided keys appear — the
        # partial-write contract) and answer the engine's bare success. No
        # free-text param exists on this face, so the STORAGE_* sentinels ride
        # the pin/sticker/profile faces; the shared UpstreamCode mapping is
        # already integration-proven there. The 1.120 §4.101 linkPreviews bit
        # is type-gated like the engine's own bool fields: a non-boolean is a
        # shape failure (-32603), never a silent store.
        if "linkPreviews" in params and not isinstance(params.get("linkPreviews"), bool):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        result = {}
    elif method == "setProfile":
        # Contract 1.46 §4.45 profile write: record the exact upstream
        # params (tests assert the text-face full-write forwarding and the
        # avatar tri-state). Sentinels: about "[fixture-storage-*]" answers a
        # structured storage error (disjoint codes), givenName
        # "[fixture-crash-profile]" crashes with the mutating call in flight
        # (os._exit(31); disjoint from 25/29/30).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        about = params.get("about")
        if about == "[fixture-storage-unavailable]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if about == "[fixture-storage-read-failed]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_READ_FAILED"},
            }
            emit_json(response)
            continue
        if about == "[fixture-storage-write-failed]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_WRITE_FAILED"},
            }
            emit_json(response)
            continue
        if params.get("givenName") == "[fixture-crash-profile]":
            os._exit(31)
        result = {}
    elif method == "setUniversalExpireTimer":
        # Contract 1.46 §4.45 universal timer write: record the exact
        # upstream params (tests assert the expirationInSeconds key). The max
        # legal u32 value is the in-flight crash magic (os._exit(31)), the
        # 1.42 timer-face discipline with a value the per-conversation face
        # cannot carry (i32 ceiling).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if params.get("expirationInSeconds") == 4294967295:
            os._exit(31)
        result = {}
    elif method == "updateAccount":
        # Contract 1.59 §4.55 username write: record the exact upstream
        # params (tests assert the username / deleteUsername key). Sentinels
        # (grammar-legal so they pass the connector's local shape gate):
        # username "fixture_username_taken.01" answers the upstream
        # InvalidUsernameException face (-1 "Invalid username: ...");
        # "fixture_crash_username.31" crashes with the mutating call in
        # flight (os._exit(31); disjoint from 25/29/30). The set path answers
        # the upstream write-back shape {username, usernameLink}; the delete
        # path answers {} (no result body upstream).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        username = params.get("username")
        if username == "fixture_username_taken.01":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "Invalid username: Username is malformed or already taken",
                },
            }
            emit_json(response)
            continue
        if username == "fixture_crash_username.31":
            os._exit(31)
        if "deleteUsername" in params:
            result = {}
        else:
            result = {
                "username": username,
                "usernameLink": "https://signal.me/username/fixture-link",
            }
    elif method == "getUsername":
        # Contract 1.74 §4.65: the kt-engine username read route. Record the
        # exact upstream params (tests assert the resolved account key). The
        # unset marker answers the both-keys-absent never-set shape; the
        # default answers the set shape (the same link the updateAccount
        # write-back carries).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if USERNAME_UNSET_MARKER.exists():
            result = {}
        else:
            result = {
                "username": "fixture_user.01",
                "usernameLink": "https://signal.me/username/fixture-link",
            }
    elif method == "engine.deviceCapabilities":
        # Contract 1.100 §4.81 D5: the device-face registration probe. Record
        # the exact upstream params (the test asserts the resolved account key
        # and that the connector strips it from the host answer). The fixture
        # answers the registered shape with the four official upload bits —
        # the pinned DEVICE_CAPABILITIES_UPLOAD mirror the engine's own
        # capabilities face projects (fake/real same-code-path, getUsername
        # precedent).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        result = {
            "account": params.get("account"),
            "registered": True,
            "capabilities": {
                "attachmentBackfill": False,
                "spqr": True,
                "usernameChangeSyncMessage": True,
                "optionalPhoneNumber": False,
            },
        }
    elif method == "getDevices":
        # Contract 1.122 §4.103: the device-list read. Record the exact
        # upstream params (the test asserts the resolved account key). The
        # fixture answers three entries: the nameless primary (deviceId 1, all
        # optional server fields present), a linked device carrying only
        # deviceId+name (the absent-optional-keys face), and a ghost entry
        # whose deviceId is a string — the malformed-entry shape the
        # connector's drop rule must never project.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        result = {
            "devices": [
                {
                    "deviceId": 1,
                    "name": None,
                    "registrationId": 111,
                    "lastSeenMs": 1728000000000,
                    "createdAtCiphertext": "Zml4dHVyZS1jcmVk",
                },
                {"deviceId": 2, "name": "KT-Desktop"},
                {"deviceId": "3", "name": "ghost"},
            ]
        }
    elif method == "unlinkDevice":
        # Contract 1.122 §4.103: the server-side unlink write. Record the
        # exact upstream params (the test asserts the resolved account and the
        # deviceId). Sentinels (grammar-legal, they pass the connector's local
        # shape gate): deviceId 4294967295 answers the server-rejection face
        # (-1 DEVICES_FAILED, data.status 409); 4294967294 crashes with the
        # mutating call in flight (os._exit(31), the 1.42 timer-face
        # discipline) — the unknown-outcome shape; anything else succeeds.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        device_id = params.get("deviceId")
        if device_id == 4294967295:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "DEVICES_FAILED",
                    "data": {"status": 409},
                },
            }
            emit_json(response)
            continue
        if device_id == 4294967294:
            os._exit(31)
        result = {}
    elif method == "usernameLookup":
        # Contract 1.74 §4.65: the kt-engine lookup route — the same top-level
        # array contract as the getUserStatus --username face (first entry
        # registered with username+uuid, the rest the unregistered face; the
        # ratelimit sentinel answers the plain upstream error). The engine
        # record carries no `number` key — that key is the pinned
        # getUserStatus face's alone.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if "[fixture-username-ratelimited]" in params.get("usernames", []):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "fixture usernameLookup failure"},
            }
            emit_json(response)
            continue
        entries = []
        for index, name in enumerate(params.get("usernames", [])):
            if index == 0:
                entries.append(
                    {
                        "recipient": name,
                        "username": name,
                        "uuid": "00000000-0000-0000-0000-00000000000" + str(index % 10),
                        "isRegistered": True,
                    }
                )
            else:
                entries.append({"recipient": name, "isRegistered": False})
        result = entries
    elif method == "phoneLookup":
        # Contract 1.164 §4.162: the kt-engine CDSI lookup route — the same
        # top-level array contract as the usernameLookup face (first entry
        # the registered hit face with both service ids, the rest the
        # pre-degraded unregistered face; the connector re-keys nothing).
        # Sentinels mirror the engine's structured read faces (code -1 + the
        # literal in the message): "+15550000001" answers PHONE_RATE_LIMITED
        # with the promised {retryAfterSeconds} backoff fact,
        # "+15550000002" answers PHONE_SERVER_FAILED, "+15550000003" answers
        # PHONE_INVALID (the engine's own E.164 grammar refusal — a drift-net
        # face here, the connector mirrors the grammar locally). The exact
        # upstream params ride SEND_LOG (tests assert the resolved account
        # and the numbers verbatim); the answer itself is a memory
        # projection — nothing is written to any store.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        numbers = params.get("numbers", [])
        if "+15550000001" in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "PHONE_RATE_LIMITED",
                    "data": {"retryAfterSeconds": 42},
                },
            }
            emit_json(response)
            continue
        if "+15550000002" in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "PHONE_SERVER_FAILED"},
            }
            emit_json(response)
            continue
        if "+15550000003" in numbers:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "PHONE_INVALID"},
            }
            emit_json(response)
            continue
        entries = []
        for index, number in enumerate(numbers):
            if index == 0:
                entries.append(
                    {
                        "number": number,
                        "aci": "00000000-0000-0000-0000-00000000000" + str(index % 10),
                        "pni": "00000000-0000-0000-0000-00000000001" + str(index % 10),
                        "isRegistered": True,
                    }
                )
            else:
                entries.append({"number": number, "isRegistered": False})
        result = entries
    elif method == "usernameReserve":
        # Contract 1.75 §4.66: the kt-engine username write face, hop one.
        # Record the exact upstream params (tests assert the resolved account
        # + username keys). Sentinels mirror the engine's structured server
        # codes (code -1 + the literal in the message):
        # "fixture_username_taken.01" answers USERNAME_TAKEN;
        # "fixture_username_ratelimited.01" answers USERNAME_RATE_LIMITED;
        # "fixture_crash_username.31" crashes with the mutating call in
        # flight (os._exit(31); the JVM updateAccount twin never fires in
        # kt-engine mode). Bare nicknames adopt the .07 discriminator (the
        # engine's fake first-candidate discipline); full names echo.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        username = params.get("username") or ""
        if username == "fixture_username_taken.01":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "USERNAME_TAKEN"},
            }
            emit_json(response)
            continue
        if username == "fixture_username_ratelimited.01":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "USERNAME_RATE_LIMITED"},
            }
            emit_json(response)
            continue
        if username == "fixture_crash_username.31":
            os._exit(31)
        adopted = username if "." in username else username + ".07"
        result = {
            "username": adopted,
            "usernameHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }
    elif method == "usernameConfirm":
        # Contract 1.75 §4.66: hop two — proof + link land the reservation.
        # "fixture_username_gone.01" answers USERNAME_RESERVATION_GONE (the
        # torn two-hop face). Success answers the write-back shape
        # {username, usernameLink}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        username = params.get("username") or ""
        if username == "fixture_username_gone.01":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "USERNAME_RESERVATION_GONE"},
            }
            emit_json(response)
            continue
        result = {
            "username": username,
            "usernameLink": "https://signal.me/username/fixture-link",
        }
    elif method == "usernameDelete":
        # Contract 1.75 §4.66: the delete hop — server DELETE + storage clear,
        # idempotent. No result body (the JVM delete path's shape).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        result = {}
    elif method == "sendStory":
        # Contract 1.76 §4.67: the kt-engine story send face. Record the
        # exact upstream params (tests assert the resolved account, the
        # message/recipients keys, and the omitted-by-default option keys).
        # Sentinel: message "fixture_story_crash.31" crashes with the
        # mutating call in flight (os._exit(31), the usernameReserve
        # discipline; disjoint from the JVM send magic). Success answers the
        # upstream write shape {timestamp, results} — the fake answers an
        # empty per-recipient list (the honest offline face; the real engine
        # lists one success entry per recipient).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # §4.154 (contract 1.156) one-shot parse-gate answer: the marker
        # `.fixture-story-send-rejected` answers the plain -32603 face the
        # real engine's fail-closed parse answers for the two-leg value
        # domain (message/attachment co-presence, a text-leg key on the
        # attachment leg, an empty attachment, the bare no-payload frame) —
        # the gates themselves are the real engine's, which the fixture
        # deliberately does not re-implement.
        if (SIGNAL_DATA_DIR / ".fixture-story-send-rejected").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        if params.get("message") == "fixture_story_crash.31":
            os._exit(31)
        result = {
            "timestamp": int(time.time() * 1000),
            "results": [],
        }
        # §4.159 (contract 1.161) the media pointer answer faces, mirroring
        # the engine fake's stub discipline: the stub face is metadata-only
        # (id constant empty, contentType the generic word, the three
        # booleans false) + a locator{cdnKey fake-story-attachment,
        # cdnNumber 3, uploadTimestamp stub moment} — no key/digest crypto
        # material is invented (宁缺勿错), caption rides in-cap-out (the
        # documented caption-through-the-pointer shape). The roster leg
        # (attachment riding, recipients non-empty) answers the top-level
        # key; the group leg answers group.fileAttachment — the mixed
        # audience's two uploads are independent stubs (the real legs'
        # pointers are distinct objects, the split-key fact). The text leg
        # answers neither key (absent = never serialized).
        def fixture_story_pointer():
            pointer = {
                "id": "",
                "contentType": "application/octet-stream",
                "isVoiceNote": False,
                "isBorderless": False,
                "isGif": False,
                "locator": {
                    "cdnKey": "fake-story-attachment",
                    "cdnNumber": 3,
                    "uploadTimestamp": int(time.time() * 1000),
                },
            }
            caption = params.get("caption")
            if caption is not None:
                pointer["caption"] = caption
            return pointer

        media_leg = params.get("attachment") is not None
        if media_leg and params.get("recipients"):
            result["fileAttachment"] = fixture_story_pointer()
        # §4.155 (contract 1.157) the group audience leg's additive answer
        # face: group present (absent = the pre-1.157 no-group shape) adds
        # {groupId, timestamp} — the single leg shares the batch timestamp,
        # the mixed audience answers the official +1 offset (the real
        # engine's group state and member resolution stay unreachable to
        # the fake, the send-fake discipline).
        if params.get("group") is not None:
            result["group"] = {
                "groupId": params["group"],
                "timestamp": result["timestamp"]
                + (1 if params.get("recipients") else 0),
            }
            if media_leg:
                result["group"]["fileAttachment"] = fixture_story_pointer()
    elif method == "getBlockedConversations":
        # Contract 1.46 §4.45 blocked read: the storage-order projection as a
        # fixture constant (one contact + one legacy group). Read face, no
        # sentinel input exists on this face — the STORAGE_* passthrough is
        # integration-proven on the sibling faces (getStickerPackSyncs
        # precedent).
        result = {"blocked": list(BLOCKED_STATE)}
    elif method == "listIdentities":
        # Contract 1.68 §4.61 safety-number read: the pinned face answers a
        # JSON array of JsonIdentity records. Read face, no SEND_LOG dispatch
        # recording (read-lane discipline, listContacts precedent). The
        # number param keys the read; the fixture answers the contacted
        # peer's identity record (the contacts fixture's number) or an empty
        # array for any other recipient — the honest no-identity-yet state
        # (never exchanged messages).
        number = params.get("number")
        if number == FIXTURE_PEER_NUMBER:
            result = [{
                "number": FIXTURE_PEER_NUMBER,
                "uuid": "99999999-9999-9999-9999-999999999999",
                "fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "safetyNumber": "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890",
                "scannableSafetyNumber": "AQIDBAUGBwgJCgsMDQ4PEA==",
                "trustLevel": "TRUSTED_UNVERIFIED",
                "addedTimestamp": 1727000000000,
            }]
        else:
            result = []
    elif method == "trust":
        # Contract 1.68 §4.61 verify write: record the exact upstream params
        # (tests assert the resolved recipient + the echoed verification
        # digits), answer the pinned face's empty success object. The
        # verifiedSafetyNumber grammar is the upstream's IdentityVerification
        # Code.parse: the fixture mirrors only the digits-stripped 60-digit
        # form — anything else is the upstream's definite UserError (-1), the
        # honest mismatch face. No crash sentinel: the trust outcome is
        # deterministic upstream (parse-or-apply), the unknown-outcome drill
        # is carried by the sibling mutating faces (25/29/30/31/32/33).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # 契约 §4.223 两臂：verifiedSafetyNumber（比对闸）或 state="default"
        # （sendAnyway 信任重置，引擎 (None, Some("default")) 臂，无比对）。
        # 两臂恰一——同置/双缺/词表外 state 是引擎的 fail-closed 面，fixture
        # 逐字回 -1。
        state = params.get("state")
        verified = params.get("verifiedSafetyNumber")
        digits = (verified or "").replace(" ", "")
        if state is not None:
            ok = state == "default" and verified is None
        else:
            ok = digits == "123456789012345678901234567890123456789012345678901234567890"
        if not ok:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "User input error (UserErrorException)"},
            }
            emit_json(response)
            continue
        result = {}
    elif method == "getAvatar":
        # Contract 1.48 §4.47 avatar download: read face, no SEND_LOG
        # dispatch recording (read-lane discipline, listContacts precedent).
        # Sentinel conversationIds answer the structured avatar error faces:
        # +15555550991 → AVATAR_UNAVAILABLE (the honest no-avatar),
        # +15555550992 → AVATAR_FETCH_FAILED, +15555550993 →
        # AVATAR_TOO_LARGE — the 509xx sentinel family, disjoint from every
        # other face's magic. They stay legal wire shapes on purpose: the
        # sentinel reaches this face as the conversation row's peer reference,
        # and the direct peerKey face only admits an ACI UUID or an E.164
        # number (§4.253 词形闸), so a bracketed token could never be
        # materialized into a conversation in the first place.
        conversation_id = params.get("conversationId")
        if conversation_id == "+15555550991":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "AVATAR_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if conversation_id == "+15555550992":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "AVATAR_FETCH_FAILED"},
            }
            emit_json(response)
            continue
        if conversation_id == "+15555550993":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "AVATAR_TOO_LARGE"},
            }
            emit_json(response)
            continue
        result = {"dataUri": AVATAR_DATA_URI, "size": len(AVATAR_PNG_BYTES)}
    elif method == "getConversationState":
        # Contract 1.116 §4.97 state read: the storage ladder's canonical
        # refusal face first (unknown record family reference →
        # CONVERSATION_NOT_RESOLVED, the engine's ConversationNotResolved),
        # then the three-bit projection — an unseeded (kind, id) reads as the
        # all-default record (the cloud record's unset bits). Sentinel
        # conversationId "[fixture-state-unavailable]" answers
        # STORAGE_UNAVAILABLE (the storage-outage face; disjoint from every
        # other face's magic). Read face, no SEND_LOG dispatch recording
        # (read-lane discipline, listContacts precedent).
        account = params.get("account")
        kind = params.get("kind")
        conversation_id = params.get("conversationId")
        if not account or kind not in ("contact", "group", "legacyGroup") or not conversation_id:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "invalid getConversationState params"},
            }
            emit_json(response)
            continue
        if conversation_id == "[fixture-state-unavailable]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if not canonical_conversation_reference(kind, conversation_id):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "CONVERSATION_NOT_RESOLVED"},
            }
            emit_json(response)
            continue
        key = f"{kind}:{conversation_id}"
        state = dict(CONVERSATION_STATE.get(key, conversation_state_default()))
        result = {
            "mutedUntilTimestamp": state["mutedUntilTimestamp"],
            "archived": state["archived"],
            "markedUnread": state["markedUnread"],
        }
    elif method == "setConversationBlocked":
        # Contract 1.48 §4.47 blocked write: record the exact upstream params
        # (tests assert the resolved conversationId/kind/blocked contract),
        # apply the write to the fixture blocked state, answer the post-write
        # full list. ConversationId sentinels (the 509xx E.164 family — the
        # value arrives as the row's peer reference, and the direct peerKey
        # face only admits an ACI UUID or a phone number, §4.253 词形闸):
        # +15555550994 answers STORAGE_UNAVAILABLE, +15555550995 answers
        # CONVERSATION_NOT_RESOLVED, +15555550996 crashes with the mutating
        # call in flight (os._exit(32); disjoint from 25/29/30/31).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        conversation_id = params.get("conversationId")
        if conversation_id == "+15555550994":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if conversation_id == "+15555550995":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "CONVERSATION_NOT_RESOLVED"},
            }
            emit_json(response)
            continue
        if conversation_id == "+15555550996":
            os._exit(32)
        conversation_id = params.get("conversationId")
        kind = params.get("kind")
        blocked = [entry for entry in BLOCKED_STATE if entry["conversationId"] != conversation_id]
        if params.get("blocked"):
            blocked.append({"conversationId": conversation_id, "kind": kind})
        BLOCKED_STATE[:] = blocked
        result = {"blocked": list(BLOCKED_STATE)}
    elif method == "setConversationState":
        # Contract 1.116 §4.97 state write: record the exact upstream params
        # (tests assert the resolved reference + the only-present-flags
        # partial-write contract), apply the write over the fixture state,
        # answer the post-write three-bit projection. Parameter discipline
        # mirrors the engine face verbatim: mutedUntilTimestamp must be a
        # number, archived/markedUnread booleans, at least one flag present —
        # anything else is the -32603 parameter face. Sentinels mirror the
        # read face: "[fixture-state-unavailable]" answers STORAGE_UNAVAILABLE;
        # the canonicalization refusal answers CONVERSATION_NOT_RESOLVED. No
        # crash sentinel: the sibling mutating faces carry the unknown-outcome
        # drills (25/29/30/31/32/33).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        kind = params.get("kind")
        conversation_id = params.get("conversationId")
        if not params.get("account") or kind not in (
            "contact",
            "group",
            "legacyGroup",
        ) or not conversation_id:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "invalid setConversationState params"},
            }
            emit_json(response)
            continue
        muted_until = params.get("mutedUntilTimestamp")
        archived = params.get("archived")
        marked_unread = params.get("markedUnread")
        if muted_until is None and archived is None and marked_unread is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "no write intent"},
            }
            emit_json(response)
            continue
        # JSON true/false are ints in Python — gate the bool leak first.
        if muted_until is not None and (
            isinstance(muted_until, bool) or not isinstance(muted_until, int)
        ):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "invalid mutedUntilTimestamp"},
            }
            emit_json(response)
            continue
        if (archived is not None and not isinstance(archived, bool)) or (
            marked_unread is not None and not isinstance(marked_unread, bool)
        ):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "invalid boolean flag"},
            }
            emit_json(response)
            continue
        if conversation_id == "[fixture-state-unavailable]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        if not canonical_conversation_reference(kind, conversation_id):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "CONVERSATION_NOT_RESOLVED"},
            }
            emit_json(response)
            continue
        key = f"{kind}:{conversation_id}"
        state = dict(CONVERSATION_STATE.get(key, conversation_state_default()))
        if muted_until is not None:
            state["mutedUntilTimestamp"] = muted_until
        if archived is not None:
            state["archived"] = archived
        if marked_unread is not None:
            state["markedUnread"] = marked_unread
        CONVERSATION_STATE[key] = state
        result = {
            "mutedUntilTimestamp": state["mutedUntilTimestamp"],
            "archived": state["archived"],
            "markedUnread": state["markedUnread"],
        }
    elif method == "sendCallMessage":
        # Contract 1.50 §4.48 call-signaling outbound face: record the exact
        # upstream params (tests assert the resolved recipient + verbatim
        # payload), answer the engine's {timestamp} envelope. The engine
        # parses no signaling content and neither does this fixture — the
        # data string ships as-is. Sentinel payloads: "[fixture-call-crash]"
        # crashes with the mutating call in flight (os._exit(33); disjoint
        # from 25/29/30/31/32).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # Contract 1.82 group arm (the negotiated engine face): `group` and
        # `recipient` are mutually exclusive — a malformed envelope answers
        # the engine's -32603 parameter face and is never dispatched.
        if bool(params.get("group")) == bool(params.get("recipient")):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "sendCallMessage requires exactly one of group, recipient",
                },
            }
            emit_json(response)
            continue
        if params.get("data") == "[fixture-call-crash]":
            os._exit(33)
        result = {"timestamp": 1727000000000}
    elif method == "sendGroupCallUpdate":
        # Contract 1.127 §4.108: the group-call era update route. Same
        # dispatch-recording discipline as `send`: the exact upstream params
        # land in SEND_LOG (the test asserts the resolved account, the group
        # master key, and the era string). Sentinels: eraId
        # "[fixture-crash-gcu]" crashes with the mutating call in flight
        # (os._exit(49); disjoint from 25/29/30/31/32/33/34/35/36/37/46/47/48).
        # Success answers the engine's empty body.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if params.get("eraId") == "[fixture-crash-gcu]":
            os._exit(49)
        result = {}
    elif method == "updateContact":
        # Same dispatch-recording discipline as `send`: the exact upstream
        # params, so tests can assert the single-string recipient contract.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # One-shot crash with the mutating call in flight: the rename may or
        # may not have reached the server, which is the indeterminate case
        # (engine-exit path). The same magic rides the timer route's max legal
        # `expiration` value (contract 1.42 §4.41 unknown-outcome drill).
        if params.get("name") == "[fixture-crash-alias]":
            os._exit(25)
        if params.get("expiration") == 2147483647:
            os._exit(25)
        result = {}
    elif method == "setExpirationTimer":
        # Contract 1.42 §4.41: the engine-face timer route. Same
        # dispatch-recording discipline as `updateContact` so tests can assert
        # the seconds-keyed payload, and the same in-flight crash magic on the
        # max legal value.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if params.get("expirationInSeconds") == 2147483647:
            os._exit(25)
        result = {}
    elif method == "createGroup":
        # Contract 1.126 §4.107: the new-group route (the official
        # createGroupV2 posture). Same dispatch-recording discipline: the
        # exact upstream params (the test asserts the resolved account, the
        # title, and the optional roster; the avatar data URI is
        # digest-summarized before logging — the createGroup/migrateGroup
        # "zero avatar bytes in the dispatch log" discipline the engine
        # pins). Sentinels (grammar-legal, they pass the connector's local
        # shape gate): title "[fixture-crash-create]" crashes with the
        # mutating call in flight (os._exit(48); disjoint from
        # 25/29/30/31/32/33/34/35/36/37/46/47); title
        # "[fixture-reject-create]" answers the server-rejection face
        # (-1 GROUP_CREATE_FAILED, data.status 400). Success answers the
        # create result shape {groupId: new master key base64, revision: 0}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                logged = json.loads(json.dumps(params))
                if isinstance(logged.get("avatar"), str):
                    logged["avatar"] = "[avatar data uri: %d bytes]" % len(logged["avatar"])
                log.write(json.dumps(logged, separators=(",", ":")) + "\n")
        if params.get("title") == "[fixture-crash-create]":
            os._exit(48)
        if params.get("title") == "[fixture-reject-create]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_CREATE_FAILED",
                    "data": {"status": 400},
                },
            }
            emit_json(response)
            continue
        result = {
            "groupId": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
            "revision": 0,
        }
    elif method == "migrateGroup":
        # Contract 1.123 §4.104: the GV1→GV2 migration route. Same
        # dispatch-recording discipline: the exact upstream params (the test
        # asserts the resolved account, the legacy groupId, and the member
        # roster; the avatar data URI is digest-summarized before logging —
        # the createGroup/migrateGroup "zero avatar bytes in the dispatch
        # log" discipline the engine pins). Sentinels (grammar-legal, they
        # pass the connector's local shape gate): title
        # "[fixture-crash-migrate]" crashes with the mutating call in flight
        # (os._exit(31); the 1.42 timer-face discipline); legacy groupId
        # Zml4dHVyZS1taWdyYXRpb24tZmFpbA== answers the server-rejection face
        # (-1 GROUP_MIGRATION_FAILED, data.status 409). Success answers the
        # migration result shape {groupId: new master key base64, revision}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                logged = json.loads(json.dumps(params))
                if isinstance(logged.get("avatar"), str):
                    logged["avatar"] = "[avatar data uri: %d bytes]" % len(logged["avatar"])
                log.write(json.dumps(logged, separators=(",", ":")) + "\n")
        if params.get("title") == "[fixture-crash-migrate]":
            os._exit(31)
        if params.get("groupId") == "Zml4dHVyZS1taWdyYXRpb24tZmFpbA==":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_MIGRATION_FAILED",
                    "data": {"status": 409},
                },
            }
            emit_json(response)
            continue
        result = {
            "groupId": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
            "revision": 0,
        }
    elif method == "sendContact":
        # Contract 1.124 §4.105: the contact-card send route (the 1:1 and
        # group legs share the engine face; recipient/groupId exactly one —
        # the sendCallMessage discipline). Same dispatch-recording
        # discipline as `send`: the exact upstream params land in SEND_LOG,
        # with the contact.avatar data URI digest-summarized before logging
        # (the createGroup/migrateGroup "zero avatar bytes in the dispatch
        # log" discipline the engine pins; the rest of the card is the
        # caller's own text data and rides verbatim). Sentinel: organization
        # "[fixture-crash-contact]" crashes with the mutating call in flight
        # (os._exit(46); disjoint from 25/29/30/31/32/33/34). Success
        # answers the send shape {timestamp}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                logged = json.loads(json.dumps(params))
                if isinstance(logged.get("contact"), dict) and isinstance(
                    logged["contact"].get("avatar"), str
                ):
                    logged["contact"]["avatar"] = "[avatar data uri: %d bytes]" % len(
                        logged["contact"]["avatar"]
                    )
                log.write(json.dumps(logged, separators=(",", ":")) + "\n")
        if bool(params.get("recipient")) == bool(params.get("groupId")):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "sendContact requires exactly one of recipient, groupId",
                },
            }
            emit_json(response)
            continue
        contact = params.get("contact") or {}
        if contact.get("organization") == "[fixture-crash-contact]":
            os._exit(46)
        result = {"timestamp": 1727000000000}
    elif method == "sendPollCreate":
        # Contract 1.125 §4.106: the poll-create route (group-only; groupId
        # mandatory — a missing/undecodable one is the engine's -32603
        # parameter face). Same dispatch-recording discipline as `send`:
        # the exact upstream params land in SEND_LOG. Sentinel: question
        # "[fixture-crash-poll]" crashes with the mutating call in flight
        # (os._exit(47); disjoint from 25/29/30/31/32/33/34/46). Success
        # answers the empty poll result {}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        group = params.get("groupId")
        if not isinstance(group, str) or not group:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "sendPollCreate requires a groupId",
                },
            }
            emit_json(response)
            continue
        if params.get("question") == "[fixture-crash-poll]":
            os._exit(47)
        result = {}
    elif method == "sendPollVote":
        # Contract 1.125 §4.106: the poll-vote route (group-only). Same
        # dispatch-recording discipline; success answers {}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        group = params.get("groupId")
        if not isinstance(group, str) or not group:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "sendPollVote requires a groupId",
                },
            }
            emit_json(response)
            continue
        result = {}
    elif method == "sendPollTerminate":
        # Contract 1.125 §4.106: the poll-terminate route (group-only).
        # Same dispatch-recording discipline; success answers {}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        group = params.get("groupId")
        if not isinstance(group, str) or not group:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "sendPollTerminate requires a groupId",
                },
            }
            emit_json(response)
            continue
        result = {}
    elif method == "updateGroup":
        # Contract 1.45 §4.44: the group-management write route. Same
        # dispatch-recording discipline as `send`/`updateContact`: the exact
        # upstream params land in SEND_LOG so tests assert the change-set keys
        # verbatim. The alias crash magic gets a group twin: the crash fires
        # with the change in flight — the indeterminate case (engine-exit
        # path). Success answers the updateGroup result shape (a timestamp
        # plus the per-recipient fan-out list).
        #
        # 2026-10-06 group-timer batch (engine main @ 216a4c7 parity): the
        # `expiration` route is the engine face's updateGroup {expiration}
        # form. Its crash magic is the timer twin "[fixture-crash-group-timer]"
        # (os._exit(34); disjoint from 25/29/30/31/32/33), and the
        # server-rejection faces mirror the engine's GROUP_UPDATE_FAILED data
        # mapping: groupId "[fixture-group-forbidden]" answers data.status=403
        # (non-admin), "[fixture-group-conflict]" answers data.status=409
        # (revision race). Contract 1.115 §4.96: the sentinels answer on
        # every updateGroup route (the wired groups.update face rides
        # title/member/link-access/avatar changes, never `expiration`).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if params.get("name") == "[fixture-crash-group]":
            os._exit(25)
        if params.get("expiration") is not None and params.get("groupId") == "[fixture-crash-group-timer]":
            os._exit(34)
        if params.get("groupId") == "[fixture-group-forbidden]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_UPDATE_FAILED",
                    "data": {"status": 403},
                },
            }
            emit_json(response)
            continue
        if params.get("groupId") == "[fixture-group-conflict]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_UPDATE_FAILED",
                    "data": {"status": 409},
                },
            }
            emit_json(response)
            continue
        # Contract 1.58 §4.53: the join-request approval rides updateGroup's
        # member family (the fold already emptied everything but requesting
        # members). Contract 1.64 §4.57: the invite revocation rides the
        # same updateGroup route's removeMembers family (the fold already
        # emptied everything but pending invitees). The sentinel group ids
        # answer the upstream non-admin refusal (the GroupsV2 user error →
        # UPSTREAM_ERROR family); the crash sentinels ride the
        # members/removeMembers array and crash with the mutating call in
        # flight (os._exit(36)/os._exit(37); disjoint from
        # 25/29/30/31/32/33/34/35 and from each other).
        if params.get("groupId") == "[fixture-approve-forbidden]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "UserErrorException: Failed to send group update",
                },
            }
            emit_json(response)
            continue
        if params.get("groupId") == "[fixture-approve-crash]" and (
            params.get("members") or params.get("removeMembers")
        ):
            os._exit(36)
        if params.get("groupId") == "[fixture-revoke-forbidden]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "UserErrorException: Failed to send group update",
                },
            }
            emit_json(response)
            continue
        if params.get("groupId") == "[fixture-revoke-crash]" and (
            params.get("members") or params.get("removeMembers")
        ):
            os._exit(37)
        result = {"timestamp": 99, "results": []}
    elif method == "leaveGroup":
        # Contract 1.45 §4.44 / contract 1.115 §4.96: the wired groups.quit
        # route — the engine's method name for the upstream quit write (the
        # engine face never carried a `quitGroup` literal). Same recording
        # discipline; the magic group id answers the upstream user error a
        # last-admin quit produces (the deterministic UPSTREAM_ERROR face),
        # every other id leaves cleanly with the engine's {status: "left"}.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if params.get("groupId") == "ZmFhaWwtZ3JvdXAtMg==":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "UserErrorException: Last group admin"},
            }
            emit_json(response)
            continue
        result = {"status": "left"}
    elif method == "terminateGroup":
        # Contract 1.52 §4.50: the group-termination write route. Same
        # recording discipline as updateGroup/quitGroup: the exact upstream
        # params land in SEND_LOG so tests assert the {account, groupId}
        # payload verbatim. Sentinel magics (disjoint from the quit-fail
        # group): the forbidden group id answers the upstream non-admin
        # refusal (GroupSendingNotAllowedException user error →
        # UPSTREAM_ERROR family), "[fixture-terminate-crash]" rides the
        # groupId and crashes with the mutating call in flight
        # (os._exit(35); disjoint from 25/29/30/31/32/33/34) — the
        # indeterminate case. Success answers the SendGroupMessageResults
        # shape (a timestamp plus the per-recipient fan-out list).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if params.get("groupId") == "[fixture-terminate-forbidden]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "UserErrorException: Failed to terminate group: "
                    "GroupSendingNotAllowedException",
                },
            }
            emit_json(response)
            continue
        if params.get("groupId") == "[fixture-terminate-crash]":
            os._exit(35)
        result = {"timestamp": 99, "results": []}
    elif method == "reportSpam":
        # Contract 1.49 §4.48: the report write route. Same recording
        # discipline as `send`: the exact upstream params land in SEND_LOG so
        # tests assert the {account, targetAci, serverGuids} payload verbatim.
        # Sentinel magic on the serverGuid values: `guid-crash` exits with the
        # report in flight (the indeterminate case), `guid-reject-all` answers
        # the structured per-batch refusal (the engine's whole-batch-rejected
        # shape), and `guid-partial` rides back as one server-rejected entry
        # (status 400) inside an otherwise successful batch — the per-id
        # failure shape.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        guids = params.get("serverGuids") or []
        if "guid-crash" in guids:
            os._exit(25)
        if "guid-reject-all" in guids:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "REPORT_SPAM_FAILED"},
            }
            emit_json(response)
            continue
        reported = len(guids)
        failures = [{"serverGuid": "guid-partial", "status": 400}] if "guid-partial" in guids else []
        result = {"reported": reported, "failures": failures}
    elif method == "sendTyping":
        # Contract 1.27 hook: deliver extra receives appended to the marker
        # after link time before answering. Typing indicators change no
        # conversation state, so this is the clean post-link flush trigger.
        flush_extra_receives()
        # Same dispatch-recording discipline as `send`: the exact upstream
        # params, so tests can assert the recipient array / groupId / explicit
        # stop boolean contract.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        # One-shot crash with the mutating call in flight (the magic peer
        # +15555550999): the indicator may or may not have reached the
        # server, which is the indeterminate case (engine-exit path).
        if "+15555550999" in (params.get("recipient") or []):
            os._exit(27)
        result = {}
    elif method == "emitReceive":
        result = {"method": method}
    elif method == "emitGroupUpdated":
        # 2026-10-06 group-timer batch: inject the engine's `groupUpdated`
        # projection verbatim (kt-signal-engine main @ 216a4c7, compat §4) —
        # one receive notification whose envelope carries `groupUpdated`
        # {groupId, revision, expireTimerSeconds, editor?} instead of a
        # message body. Params mirror the projection keys; absent keys take
        # the fixture group / revision 1 / off defaults, so the common case
        # needs no params at all.
        result = {"method": method}
    elif method == "emitStderr":
        emit_stderr_websocket_error()
        result = {"method": method}
    elif method == "backup.export":
        # §4.46 export-task face: the engine reads the connector's artifact
        # from the registered account directory, fail-closed on the start
        # ladder (account registered → artifact present → first line parses).
        # The directory comes from this process's own registry, exactly what
        # the real engine reads.
        registry = SIGNAL_DATA_DIR / "engine-state.json"
        account_dir = None
        try:
            state = json.loads(registry.read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    account_dir = SIGNAL_DATA_DIR / entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            account_dir = None
        if account_dir is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        artifact = account_dir / "backup-export-input.ndjson"
        if not artifact.is_file() or artifact.stat().st_size == 0:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "BACKUP_ARTIFACT_MISSING"},
            }
            emit_json(response)
            continue
        lines = artifact.read_text().splitlines()
        first = json.loads(lines[0]) if lines else None
        if not isinstance(first, dict) or first.get("type") != "account":
            artifact.unlink(missing_ok=True)
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "BACKUP_ARTIFACT_INVALID"},
            }
            emit_json(response)
            continue
        given_name = first.get("givenName") or ""
        # Export-task sentinels ride the account line's givenName — the one
        # field the connector's builder derives from store data, so a seeded
        # display name steers the failure ladder without a second channel.
        if given_name == "[fixture-artifact-missing]":
            artifact.unlink(missing_ok=True)
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "BACKUP_ARTIFACT_MISSING"},
            }
            emit_json(response)
            continue
        if given_name == "[fixture-artifact-invalid]":
            artifact.write_text("not-json\n")
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "BACKUP_ARTIFACT_INVALID"},
            }
            emit_json(response)
            continue
        if given_name == "[fixture-crash-backup]":
            os._exit(33)
        if given_name == "[fixture-snapshot-exists]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "BACKUP_SNAPSHOT_EXISTS"},
            }
            emit_json(response)
            continue
        if given_name == "[fixture-io-failed]":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "BACKUP_IO_FAILED"},
            }
            emit_json(response)
            continue
        # The happy path: the task runs in the background — writes the §5
        # snapshot shape (metadata + main under SignalBackups/signal-backup-
        # <ts>), then deletes the transitional artifact on leaving running
        # (§10.2), and `started` is answered immediately. A
        # `.fixture-backup-running` marker holds the task in `running` for
        # exportStatus polls until the task finishes.
        running_marker = SIGNAL_DATA_DIR / ".fixture-backup-running"
        running_marker.touch()

        def run_backup_task(account_dir=account_dir, running_marker=running_marker):
            time.sleep(0.2)
            snapshot = account_dir / (
                "SignalBackups/signal-backup-"
                + time.strftime("%Y-%m-%d-%H-%M-%S", time.gmtime())
            )
            snapshot.mkdir(parents=True, exist_ok=True)
            (snapshot / "metadata").write_bytes(b"fixture-snapshot-metadata")
            (snapshot / "main").write_bytes(b"fixture-snapshot-main-bytes-0123456789")
            artifact.unlink(missing_ok=True)
            running_marker.unlink(missing_ok=True)

        threading.Thread(target=run_backup_task, daemon=True).start()
        result = {"status": "started"}
    elif method == "backup.exportStatus":
        # §4.46 status face: the task registry is process memory, mirrored by
        # the `.fixture-backup-running` marker; snapshots are listed from disk
        # (name + main size, newest first, ≤ 32). Keys are honest-absence —
        # `lines`/`frames`/`snapshot`/`error` only when they have a referent.
        running_marker = SIGNAL_DATA_DIR / ".fixture-backup-running"
        account_dir = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    account_dir = SIGNAL_DATA_DIR / entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            account_dir = None
        if account_dir is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        snapshot_root = account_dir / "SignalBackups"
        names = []
        if snapshot_root.is_dir():
            for entry in sorted(snapshot_root.iterdir(), reverse=True):
                if entry.is_dir() and entry.name.startswith("signal-backup-") and not entry.name.endswith("-tmp"):
                    names.append(entry.name)
        names = names[:32]
        snapshots = []
        for name in names:
            main = snapshot_root / name / "main"
            snapshots.append({
                "name": name,
                "mainBytes": main.stat().st_size if main.is_file() else 0,
            })
        artifact = account_dir / "backup-export-input.ndjson"
        if running_marker.exists():
            result = {
                "state": "running",
                "artifactPresent": artifact.is_file(),
            }
        elif snapshots:
            newest = snapshots[0]
            result = {
                "state": "completed",
                "artifactPresent": False,
                "finishedAtMs": int(time.time() * 1000),
                "snapshot": dict(newest),
                "snapshots": snapshots,
            }
        else:
            result = {
                "state": "idle",
                "artifactPresent": False,
                "snapshots": snapshots,
            }
    elif method == "backup.importSnapshot":
        # §4.68 snapshot-import face: the engine consumes the caller-chosen
        # official snapshot directory. The directory string is the steering
        # channel — sentinel substrings pick the structured-error ladder; the
        # happy path answers `started` immediately and a background thread
        # writes the §4.38 NDJSON archive, with a `.fixture-import-running`
        # marker holding the status polls in `running` (the export pattern).
        snapshot_dir = params.get("snapshotDir") or ""
        account_dir = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    account_dir = SIGNAL_DATA_DIR / entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            account_dir = None
        if account_dir is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        import_error = None
        if "[fixture-snapshot-missing]" in snapshot_dir:
            import_error = "BACKUP_SNAPSHOT_MISSING"
        elif "[fixture-snapshot-metadata-invalid]" in snapshot_dir:
            import_error = "BACKUP_SNAPSHOT_METADATA_INVALID"
        elif "[fixture-snapshot-key-mismatch]" in snapshot_dir:
            import_error = "BACKUP_SNAPSHOT_KEY_MISMATCH"
        elif "[fixture-io-failed]" in snapshot_dir:
            import_error = "BACKUP_SNAPSHOT_IO_FAILED"
        elif "[fixture-import-running]" in snapshot_dir:
            import_error = "BACKUP_IMPORT_ALREADY_RUNNING"
        if import_error is not None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": import_error},
            }
            emit_json(response)
            continue

        def run_import_task(account_dir=account_dir, snapshot_dir=snapshot_dir, running_marker=None):
            time.sleep(0.2)
            if "[fixture-import-fails-later]" in snapshot_dir:
                (SIGNAL_DATA_DIR / ".fixture-import-failed").touch()
            else:
                recipient = (
                    '{"type":"recipient","id":1,"kind":"contact","name":"Alice Import",'
                    '"aci":"' + IMPORT_ALICE_ACI + '","e164":"' + IMPORT_ALICE_E164 + '"}'
                )
                chat = '{"type":"chat","id":10,"recipientId":1}'
                incoming = (
                    '{"type":"message","chatId":10,"authorId":1,"dateSent":1000,'
                    '"direction":"incoming","text":"archived hello"}'
                )
                outgoing = (
                    '{"type":"message","chatId":10,"authorId":1,"dateSent":2000,'
                    '"direction":"outgoing","text":"archived reply"}'
                )
                (account_dir / "history-import.ndjson").write_text(
                    recipient + "\n" + chat + "\n" + incoming + "\n" + outgoing + "\n"
                )
            if running_marker is not None:
                running_marker.unlink(missing_ok=True)

        running_marker = SIGNAL_DATA_DIR / ".fixture-import-running"
        running_marker.touch()
        threading.Thread(
            target=run_import_task, kwargs={"running_marker": running_marker}, daemon=True
        ).start()
        result = {"status": "started"}
    elif method == "backup.importSnapshotStatus":
        # §4.68 status face: the import-task registry is process memory,
        # mirrored by the `.fixture-import-running` / `.fixture-import-failed`
        # markers; `ndjsonPresent` is the archive's disk truth and the counts
        # mirror the fixture archive's fixed shape (4 projected rows, 5 frames
        # including the BackupInfo meta-frame).
        account_dir = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    account_dir = SIGNAL_DATA_DIR / entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            account_dir = None
        if account_dir is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        archive = account_dir / "history-import.ndjson"
        ndjson_present = archive.is_file() and archive.stat().st_size > 0
        if (SIGNAL_DATA_DIR / ".fixture-import-running").exists():
            result = {"state": "running", "ndjsonPresent": ndjson_present}
        elif (SIGNAL_DATA_DIR / ".fixture-import-failed").exists():
            result = {
                "state": "failed",
                "ndjsonPresent": ndjson_present,
                "error": "fixture import failed",
            }
        elif ndjson_present:
            result = {
                "state": "completed",
                "ndjsonPresent": True,
                "finishedAtMs": int(time.time() * 1000),
                "lines": 4,
                "frames": 5,
            }
        else:
            result = {"state": "idle", "ndjsonPresent": False}
    elif method == "transfer.downloadStatus":
        # §4.38 progress face (contract 1.53): the real engine answers from an
        # in-process per-account download snapshot. The fixture mirrors that
        # shape from marker files in the signal data dir —
        # `.fixture-transfer-running` (present = a download is in flight) and
        # `.fixture-transfer-bytes` ("<read> [<total>]", total optional), both
        # written by the driving test. Absent markers answer {present: false},
        # the honest no-download answer. §4.146 failure face (contract 1.148):
        # `.fixture-transfer-error` carries the engine's short failure code —
        # its presence is the terminal failed snapshot (the code rides
        # verbatim; the connector gates the shape) and wins over the running
        # marker, and it persists until the fixture engine restart clears the
        # markers.
        result = {"present": False}
        error_marker = SIGNAL_DATA_DIR / ".fixture-transfer-error"
        running_marker = SIGNAL_DATA_DIR / ".fixture-transfer-running"
        bytes_marker = SIGNAL_DATA_DIR / ".fixture-transfer-bytes"
        if error_marker.exists():
            try:
                code = error_marker.read_text().strip()
            except OSError:
                code = ""
            result = {"present": True, "errorCode": code}
        elif running_marker.exists():
            try:
                parts = bytes_marker.read_text().split()
                bytes_read = max(int(parts[0]), 0)
            except (OSError, ValueError, IndexError):
                parts = []
                bytes_read = 0
            result = {"present": True, "bytesRead": bytes_read}
            if len(parts) > 1:
                result["bytesTotal"] = max(int(parts[1]), 0)
    elif method == "history.importCancel":
        # §4.146 cancel face (contract 1.148): the frozen engine contract —
        # params {account}, result {"cancelled": bool} where true means a live
        # download was aborted. The fixture mirrors it from the transfer
        # markers: `.fixture-transfer-running` present = a download in flight,
        # aborted now (both progress markers removed, true); absent = nothing
        # live to cancel (false). A terminal error snapshot is not a live
        # download — it survives a cancel, like the engine's (it persists
        # until the next engine start).
        # B4 delete-cancel fixture: record which account the connector asked
        # to cancel, so a test can prove the delete targets only its own
        # account (`.fixture-import-cancel-log`, one number per line). The
        # marker semantics below stay unchanged.
        with WRITE_LOCK:
            with (SIGNAL_DATA_DIR / ".fixture-import-cancel-log").open("a") as log:
                log.write(str(params.get("account", "")) + "\n")
        running_marker = SIGNAL_DATA_DIR / ".fixture-transfer-running"
        bytes_marker = SIGNAL_DATA_DIR / ".fixture-transfer-bytes"
        if running_marker.exists():
            for marker in (running_marker, bytes_marker):
                try:
                    marker.unlink()
                except FileNotFoundError:
                    pass
            result = {"cancelled": True}
        else:
            result = {"cancelled": False}
    elif method == "backups.restoreFromCloud":
        # §4.69 cloud-restore start face (contract 1.83): the negotiated wire
        # mirror of the engine's KT-extension method — the params face is only
        # {account}, the happy path answers {"status": "started"} (the whole
        # chain runs in the engine's background), and the seven-family
        # structured-error ladder steers from markers the driving test writes:
        # `.fixture-cloud-restore-running` present = the engine's atomic
        # re-entry gate (BACKUP_RUNNING, no detail); `.fixture-cloud-restore-error`
        # carries a family sentinel — NOT_PROVISIONED / AUTH / TRANSPORT /
        # DOWNLOAD / DECRYPT / EXPORT — mapped onto the BACKUP_* code, where
        # the four message-carrying families additionally carry data.detail
        # (the engine's CloudRestoreError::rpc_code table; the three state
        # families answer content-free).
        #
        # §4.69 consumption batch (contract 1.84): the happy path also runs
        # the background chain the connector's consumption watcher watches —
        # after a short delay it either writes the NDJSON product
        # `history-import-cloud.ndjson` into the account directory and clears
        # the cloud-status snapshot (the engine's success-clear discipline),
        # or — steered by markers — stalls forever (`.fixture-cloud-restore-stall`,
        # the driving test owns the status face) or flips the snapshot to the
        # failed phase (`.fixture-cloud-restore-fails-later`).
        cloud_error = None
        error_marker = SIGNAL_DATA_DIR / ".fixture-cloud-restore-error"
        if (SIGNAL_DATA_DIR / ".fixture-cloud-restore-running").exists():
            cloud_error = "BACKUP_RUNNING"
        elif error_marker.exists():
            sentinel = error_marker.read_text().strip()
            cloud_error = {
                "NOT_PROVISIONED": "BACKUP_NOT_PROVISIONED",
                "AUTH": "BACKUP_AUTH_FAILED",
                "TRANSPORT": "BACKUP_TRANSPORT_FAILED",
                "DOWNLOAD": "BACKUP_DOWNLOAD_FAILED",
                "DECRYPT": "BACKUP_DECRYPT_FAILED",
                "EXPORT": "BACKUP_EXPORT_FAILED",
            }.get(sentinel)
        cloud_account_dir = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    cloud_account_dir = SIGNAL_DATA_DIR / entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            cloud_account_dir = None
        if cloud_account_dir is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        if cloud_error is not None:
            response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -1, "message": cloud_error}}
            if cloud_error in (
                "BACKUP_TRANSPORT_FAILED",
                "BACKUP_DOWNLOAD_FAILED",
                "BACKUP_DECRYPT_FAILED",
                "BACKUP_EXPORT_FAILED",
            ):
                response["error"]["data"] = {"detail": f"fixture {cloud_error}"}
            emit_json(response)
            continue

        def run_cloud_restore_task(account_dir=cloud_account_dir):
            time.sleep(0.2)
            status_marker = SIGNAL_DATA_DIR / ".fixture-cloud-status"
            if (SIGNAL_DATA_DIR / ".fixture-cloud-restore-stall").exists():
                return
            if (SIGNAL_DATA_DIR / ".fixture-cloud-restore-fails-later").exists():
                status_marker.write_text("failed 4096 BACKUP_DOWNLOAD_FAILED")
                return
            recipient = (
                '{"type":"recipient","id":2,"kind":"contact","name":"Cloud Import",'
                '"aci":"' + IMPORT_ALICE_ACI + '","e164":"' + IMPORT_ALICE_E164 + '"}'
            )
            chat = '{"type":"chat","id":20,"recipientId":2}'
            incoming = (
                '{"type":"message","chatId":20,"authorId":2,"dateSent":5000,'
                '"direction":"incoming","text":"cloud archived hello"}'
            )
            outgoing = (
                '{"type":"message","chatId":20,"authorId":2,"dateSent":6000,'
                '"direction":"outgoing","text":"cloud archived reply"}'
            )
            (account_dir / "history-import-cloud.ndjson").write_text(
                recipient + "\n" + chat + "\n" + incoming + "\n" + outgoing + "\n"
            )
            status_marker.unlink(missing_ok=True)

        threading.Thread(target=run_cloud_restore_task, daemon=True).start()
        result = {"status": "started"}
    elif method == "backups.cloudStatus":
        # §4.69 cloud-status face (contract 1.83): the progress snapshot is
        # engine-process memory; the fixture mirrors the three negotiated
        # states from `.fixture-cloud-status` ("<phase> <read> [<total|code>]",
        # written by the driving test) — absent/empty answers {present: false},
        # `downloading <read> [total]` carries the byte counts (total absent =
        # the honest-uncertainty form, never a fake 0), and
        # `failed <read> <code>` carries the structured errorCode.
        result = {"present": False}
        status_marker = SIGNAL_DATA_DIR / ".fixture-cloud-status"
        if status_marker.exists():
            parts = status_marker.read_text().split()
            if len(parts) >= 2 and parts[0] in ("downloading", "failed"):
                result = {
                    "present": True,
                    "phase": parts[0],
                    "bytesRead": max(int(parts[1]), 0),
                }
                if len(parts) > 2:
                    if parts[0] == "downloading":
                        result["bytesTotal"] = max(int(parts[2]), 0)
                    else:
                        result["errorCode"] = parts[2]
    elif method == "backups.uploadToCloud":
        # §4.72 cloud-upload start face (contract 1.87, engine
        # cloud-backup-contract §6.2): the negotiated wire mirror of the
        # engine's KT-extension method — the params face is only {account},
        # the happy path answers {"status": "started"} (the whole chain runs
        # in the engine's background), and the eight-family structured-error
        # ladder steers from markers the driving test writes:
        # `.fixture-cloud-upload-running` present = the engine's process-wide
        # single-slot re-entry gate (BACKUP_UPLOAD_ALREADY_RUNNING, no
        # detail); `.fixture-cloud-upload-error` carries a family sentinel —
        # AUTH / NOT_PROVISIONED / ARTIFACT_MISSING / ARTIFACT_INVALID /
        # TRANSPORT / UPLOAD / IO — mapped onto the BACKUP_* code, where the
        # three message-carrying families (TRANSPORT/UPLOAD/IO, the engine's
        # detail() Some set) additionally carry data.detail and the five
        # state families answer content-free. Without a steering marker the
        # arm mirrors the engine's start artifact gate honestly: the
        # §10.2 input artifact (`backup-export-input.ndjson`) must exist in
        # the account directory — the connector builds it ahead of the
        # start call, so a happy path through the real connector always
        # lands it and its absence answers BACKUP_ARTIFACT_MISSING.
        upload_error = None
        upload_error_marker = SIGNAL_DATA_DIR / ".fixture-cloud-upload-error"
        if (SIGNAL_DATA_DIR / ".fixture-cloud-upload-running").exists():
            upload_error = "BACKUP_UPLOAD_ALREADY_RUNNING"
        elif upload_error_marker.exists():
            sentinel = upload_error_marker.read_text().strip()
            upload_error = {
                "AUTH": "BACKUP_AUTH_FAILED",
                "NOT_PROVISIONED": "BACKUP_NOT_PROVISIONED",
                "ARTIFACT_MISSING": "BACKUP_ARTIFACT_MISSING",
                "ARTIFACT_INVALID": "BACKUP_ARTIFACT_INVALID",
                "TRANSPORT": "BACKUP_TRANSPORT_FAILED",
                "UPLOAD": "BACKUP_UPLOAD_FAILED",
                "IO": "BACKUP_IO_FAILED",
            }.get(sentinel)
        upload_account_dir = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    upload_account_dir = SIGNAL_DATA_DIR / entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            upload_account_dir = None
        if upload_account_dir is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "account is not registered"},
            }
            emit_json(response)
            continue
        if upload_error is None and not (
            upload_account_dir / "backup-export-input.ndjson"
        ).is_file():
            upload_error = "BACKUP_ARTIFACT_MISSING"
        if upload_error is not None:
            response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -1, "message": upload_error}}
            if upload_error in (
                "BACKUP_TRANSPORT_FAILED",
                "BACKUP_UPLOAD_FAILED",
                "BACKUP_IO_FAILED",
            ):
                response["error"]["data"] = {"detail": f"fixture {upload_error}"}
            emit_json(response)
            continue
        result = {"status": "started"}
    elif method == "backups.uploadStatus":
        # §4.72 cloud-upload status face (contract 1.87): the progress
        # snapshot is engine-process memory (a process-wide single slot);
        # the fixture mirrors the negotiated states from
        # `.fixture-cloud-upload-status` ("<phase> <read> [<total|code>]",
        # written by the driving test) — absent/empty answers
        # {present: false}, `exporting 0` carries the zero-count assembly
        # face, `uploading <read> [total]` carries the block counts (total
        # absent = the honest-uncertainty form, never a fake 0), and
        # `failed <read> <code>` carries the structured errorCode.
        result = {"present": False}
        upload_status_marker = SIGNAL_DATA_DIR / ".fixture-cloud-upload-status"
        if upload_status_marker.exists():
            parts = upload_status_marker.read_text().split()
            if len(parts) >= 2 and parts[0] in ("exporting", "uploading", "failed"):
                result = {
                    "present": True,
                    "phase": parts[0],
                    "bytesRead": max(int(parts[1]), 0),
                }
                if len(parts) > 2:
                    if parts[0] == "uploading":
                        result["bytesTotal"] = max(int(parts[2]), 0)
                    elif parts[0] == "failed":
                        result["errorCode"] = parts[2]
    elif method in (
        "calls.linkPresentation",
        "calls.createLinkAuth",
        "calls.groupProof",
        "calls.groupMembers",
        "calls.endorsementsPublicKey",
    ):
        # §4.73 call-link credential material faces (contract 1.88, engine
        # a3ae39b): the negotiated wire mirror of the engine's five
        # KT-extension methods — the account-scoped four gate the account
        # (engine-state registry, else -32603) and their material shapes
        # fail-closed -32603 (rootKey standard b64 16/21 B, roomId/groupId
        # 32 B — the engine's own parameter gates), endorsementsPublicKey
        # takes no fields and never fails here. The structured ladder steers
        # from markers the driving test writes:
        # `.fixture-call-cred-failed` answers CALL_CREDENTIALS_FAILED —
        # "status <N>" content carries error.data.status (the honest HTTP
        # pass-through), anything else answers data {} (the engine's
        # no-status form); `.fixture-call-cred-unavailable` answers
        # CALL_CREDENTIALS_UNAVAILABLE. Happy paths answer the fake shape
        # stubs (fixed placeholder bytes/proof/members — stub bytes are NOT
        # valid zk material, they only pin the contract shape, the engine
        # fake discipline): presentation/params are the standard base64 of
        # fixed byte strings, proof is a fixed token, members one entry.
        def _call_cred_error():
            failed_marker = SIGNAL_DATA_DIR / ".fixture-call-cred-failed"
            if failed_marker.exists():
                text = failed_marker.read_text().strip()
                data = {}
                if text.startswith("status "):
                    try:
                        data["status"] = max(int(text.split()[1]), 0)
                    except (ValueError, IndexError):
                        pass
                return {"code": -1, "message": "CALL_CREDENTIALS_FAILED", "data": data}
            if (SIGNAL_DATA_DIR / ".fixture-call-cred-unavailable").exists():
                return {"code": -1, "message": "CALL_CREDENTIALS_UNAVAILABLE"}
            return None

        def _b64_fixed(tag):
            return base64.b64encode(bytes([0xF0 ^ tag]) * 16).decode()

        if method != "calls.endorsementsPublicKey":
            cred_account = None
            try:
                state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
                for entry in state.get("accounts") or []:
                    if entry.get("number") == params.get("account"):
                        cred_account = entry["dir"]
                        break
            except (OSError, ValueError, KeyError, AttributeError):
                cred_account = None
            if cred_account is None:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": "account is not registered"},
                }
                emit_json(response)
                continue

            def _decode_exact(value, lengths):
                try:
                    raw = base64.b64decode(value.strip(), validate=True)
                except Exception:
                    return False
                return len(raw) in lengths

            if method in ("calls.linkPresentation", "calls.createLinkAuth"):
                if not _decode_exact(params.get("rootKey") or "", (16, 21)):
                    response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32603, "message": "Internal error"},
                    }
                    emit_json(response)
                    continue
            if method == "calls.createLinkAuth" and not _decode_exact(
                params.get("roomId") or "", (32,)
            ):
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": "Internal error"},
                }
                emit_json(response)
                continue
            if method in ("calls.groupProof", "calls.groupMembers") and not _decode_exact(
                params.get("groupId") or "", (32,)
            ):
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": "Internal error"},
                }
                emit_json(response)
                continue

        cred_error = _call_cred_error()
        if cred_error is not None:
            response = {"jsonrpc": "2.0", "id": request_id, "error": cred_error}
            emit_json(response)
            continue
        result = {
            "calls.linkPresentation": {"presentation": _b64_fixed(1)},
            "calls.createLinkAuth": {
                "presentation": _b64_fixed(2),
                "callLinkPublicParams": _b64_fixed(3),
            },
            "calls.groupProof": {"proof": "fixture-group-proof-token"},
            "calls.groupMembers": {
                "members": [
                    {
                        "uuid": "ae45f0d7-9c15-4e0a-9bf5-6cb610e1f2a3",
                        "userIdCipherText": _b64_fixed(4),
                    }
                ]
            },
            "calls.endorsementsPublicKey": {"endorsementPublicKey": _b64_fixed(5)},
        }[method]
    elif method == "calls.relays":
        # §4.143 call-relay configuration proxy (contract 1.145, engine
        # e2f2e6d): the engine's calls.relays wire mirror. No dispatch
        # record (the engine's networked read faces never log). The
        # account gate rides the same engine-state registry (an
        # unregistered account answers the plain -32603, the engine's
        # unknown-account face). The marker ladder drives the three
        # contract faces the driving test pins, each the engine's own
        # semantics verbatim:
        # `.fixture-call-relays-unbound` answers the engine's 401/403
        # unbound message word for word (the USER_UNBOUND_MESSAGE the
        # connector's §4.17 matcher folds into ACCOUNT_UNLINKED);
        # `.fixture-call-relays-empty` answers the no-cache empty state
        # (relays [] + stale, fetchedAtMs/expiresAtMs keys absent — the
        # engine's no-null discipline); `.fixture-call-relays-refresh-
        # failed` answers the empty state carrying lastError (the honest
        # refresh-failure face). The default happy shape carries every
        # optional relay field (urls/urlsWithIps/hostname/ttl) plus the
        # freshness pair — stub TURN material, NOT valid credentials (the
        # engine fake discipline).
        relay_account = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    relay_account = entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            relay_account = None
        if relay_account is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-call-relays-unbound").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "Failed to send message: Authorization failed! (AuthorizationFailedException)",
                },
            }
            emit_json(response)
            continue
        relay_account_value = params.get("account")
        if (SIGNAL_DATA_DIR / ".fixture-call-relays-empty").exists():
            result = {"account": relay_account_value, "relays": [], "stale": True}
        elif (SIGNAL_DATA_DIR / ".fixture-call-relays-refresh-failed").exists():
            result = {
                "account": relay_account_value,
                "relays": [],
                "stale": True,
                "lastError": "http 500",
            }
        else:
            result = {
                "account": relay_account_value,
                "relays": [
                    {
                        "username": "fixture-relay-user",
                        "password": "fixture-relay-pass",
                        "urls": ["turn:turn.example.org:80?transport=tcp"],
                        "urlsWithIps": ["1.2.3.4:3478"],
                        "hostname": "turn.example.org",
                        "ttl": 86400,
                    }
                ],
                "fetchedAtMs": 1_000,
                "expiresAtMs": 86_501_000,
                "stale": False,
            }
    elif method == "sendCallEvent":
        # §4.150 call-event cross-device sync (contract 1.151, engine
        # 6d56660): the engine's sendCallEvent wire mirror — the
        # SyncMessage.callEvent=19 self-send face. Same dispatch-recording
        # discipline as `send`: the exact upstream params, so tests assert
        # the {account, type, direction, event, conversationId, callId?,
        # timestamp?} contract byte-for-byte (the callEvent fields are
        # record metadata, kept verbatim — the send-family discipline). The
        # account gate rides the same engine-state registry (an
        # unregistered account answers the plain -32603, the engine's
        # unknown-account face). The marker `.fixture-call-event-rejected`
        # answers the engine's parse-gate face (-32603) — the three word
        # lists, the per-leg conversation shapes, the callId domain, and
        # the per-leg callId requirement are the real engine's fail-closed
        # parse gate, which the fixture deliberately does not re-implement.
        # Success answers {timestamp}: the caller's value when present, the
        # envelope moment when absent (three legs, same answer shape — the
        # send-family stub discipline).
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        event_account = None
        try:
            state = json.loads((SIGNAL_DATA_DIR / "engine-state.json").read_text())
            for entry in state.get("accounts") or []:
                if entry.get("number") == params.get("account"):
                    event_account = entry["dir"]
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            event_account = None
        if event_account is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        if (SIGNAL_DATA_DIR / ".fixture-call-event-rejected").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        result = {"timestamp": params.get("timestamp", 1_000)}
    elif method == "generateInviteLinkPassword":
        # Contract 1.117 §4.98: the account-less material face. No dispatch
        # record (the engine's material faces never log), no account: 16
        # CSPRNG bytes as standard base64 — the official
        # GROUP_INVITE_LINK_PASSWORD_LENGTH shape.
        result = {"password": base64.b64encode(os.urandom(16)).decode()}
    elif method == "buildInviteLink":
        # Contract 1.117 §4.98: the build face, read side, no dispatch
        # record. Engine-parity parameter gates: groupId standard base64 of
        # exactly 32 bytes, password (when present) standard base64 decoding
        # to a non-empty byte string — anything else answers -32603. The
        # explicit-password arm is pure construction (a real proto link, the
        # engine fake/real shared code path); the password-absent arm
        # mirrors the engine fake's no-group-state face —
        # GROUP_INVITE_LINK_UNAVAILABLE with no data. The
        # LINK_PASSWORD_FORBIDDEN bytes answer the same code's data.status
        # face (the server-rejection channel).
        try:
            master_key = base64.b64decode(params.get("groupId") or "", validate=True)
            password_raw = params.get("password")
            password_bytes = (
                None
                if password_raw is None
                else base64.b64decode(password_raw, validate=True)
            )
        except Exception:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        if len(master_key) != 32 or password_bytes == b"":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        if password_bytes == LINK_PASSWORD_FORBIDDEN:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_INVITE_LINK_UNAVAILABLE",
                    "data": {"status": 403},
                },
            }
            emit_json(response)
            continue
        if password_bytes is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "GROUP_INVITE_LINK_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        result = {"inviteLink": fixture_build_invite_link(master_key, password_bytes)}
    elif method == "parseInviteLink":
        # Contract 1.117 §4.98: the account-less pure-parse face. Every
        # tolerance failure (empty, bad base64, bad proto, versionless,
        # short key, empty password) answers -32603 — the engine folds the
        # whole parse family there.
        parsed_link = fixture_parse_invite_link(params.get("inviteLink") or "")
        if parsed_link is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        master_key, link_password = parsed_link
        result = {
            "groupId": base64.b64encode(master_key).decode(),
            "password": base64.b64encode(link_password).decode(),
        }
    elif method == "previewGroupViaLink":
        # Contract 1.117 §4.98: the pre-join read face, no dispatch record.
        # The `.fixture-invite-link-unavailable` marker answers
        # STORAGE_UNAVAILABLE for all four account-scoped faces. Parse
        # failure answers -32603; the LINK_PASSWORD_PREVIEW_FAILED bytes
        # answer GROUP_INVITE_LINK_PREVIEW_FAILED with data.status (the
        # server-rejection channel); the happy path answers the full
        # 8-key projection (both optional profile keys present).
        if (SIGNAL_DATA_DIR / ".fixture-invite-link-unavailable").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        parsed_link = fixture_parse_invite_link(params.get("inviteLink") or "")
        if parsed_link is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        master_key, link_password = parsed_link
        if link_password == LINK_PASSWORD_PREVIEW_FAILED:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_INVITE_LINK_PREVIEW_FAILED",
                    "data": {"status": 404},
                },
            }
            emit_json(response)
            continue
        result = {
            "groupId": base64.b64encode(master_key).decode(),
            "memberCount": 12,
            "revision": 7,
            "addFromInviteLink": "ANY",
            "approvalRequired": False,
            "pendingAdminApproval": False,
            "name": "Fixture Link Group",
            "description": "previewed through the invite link",
        }
    elif method == "joinGroupViaLink":
        # Contract 1.117 §4.98: the join write face — the engine appends
        # the dispatch record BEFORE the parse (a refused write still
        # records its dispatch), so the fixture logs first. The
        # LINK_PASSWORD_PREVIEW_FAILED bytes answer the GROUP_UPDATE_FAILED
        # data.status face; the LINK_PASSWORD_JOIN_REQUESTED bytes answer
        # the approval-gate verb; every other parseable link joins.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if (SIGNAL_DATA_DIR / ".fixture-invite-link-unavailable").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        parsed_link = fixture_parse_invite_link(params.get("inviteLink") or "")
        if parsed_link is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        _, link_password = parsed_link
        if link_password == LINK_PASSWORD_PREVIEW_FAILED:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_UPDATE_FAILED",
                    "data": {"status": 403},
                },
            }
            emit_json(response)
            continue
        status = (
            "requested" if link_password == LINK_PASSWORD_JOIN_REQUESTED else "joined"
        )
        result = {"status": status}
    elif method == "cancelJoinRequest":
        # Contract 1.117 §4.98: the withdrawal write face — the same
        # record-before-parse discipline as the join; the
        # LINK_PASSWORD_PREVIEW_FAILED bytes answer GROUP_UPDATE_FAILED
        # data.status=409; every other parseable link cancels.
        with WRITE_LOCK:
            with SEND_LOG.open("a") as log:
                log.write(json.dumps(params, separators=(",", ":")) + "\n")
        if (SIGNAL_DATA_DIR / ".fixture-invite-link-unavailable").exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "STORAGE_UNAVAILABLE"},
            }
            emit_json(response)
            continue
        parsed_link = fixture_parse_invite_link(params.get("inviteLink") or "")
        if parsed_link is None:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
            emit_json(response)
            continue
        _, link_password = parsed_link
        if link_password == LINK_PASSWORD_PREVIEW_FAILED:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": "GROUP_UPDATE_FAILED",
                    "data": {"status": 409},
                },
            }
            emit_json(response)
            continue
        result = {"status": "cancelled"}
    elif method == "getUserStatus":
        if AUTH_FAILED_MARKER.exists():
            # Contract 1.21: the account holder unlinked this device. The
            # real upstream wraps AuthorizationFailedException in an
            # UnexpectedErrorException (-32603) with this message shape.
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": "Failed to send message: Authorization failed! (AuthorizationFailedException)",
                },
            }
            emit_json(response)
            continue
        if UNREGISTERED_MARKER.exists():
            # Post-mortem unlink form (contract 1.21 §4.17, C2 widening):
            # after the first authorization failure signal-cli persists
            # registered=false and every later account-scoped command fails
            # LOCALLY with UserErrorException "User <account> is not
            # registered." (USER_ERROR = -1) before any network call — the
            # 0-17 ms instant-failure form. Must classify as Unauthorized
            # exactly like the live form above.
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -1,
                    "message": f"User {LINKED_ACCOUNT} is not registered.",
                },
            }
            emit_json(response)
            continue
        if FAIL_USER_STATUS_MARKER.exists():
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -1, "message": "fixture getUserStatus failure"},
            }
            emit_json(response)
            continue
        # Count-based failure: fail the next N getUserStatus calls, then recover.
        if FAIL_USER_STATUS_COUNT_MARKER.exists():
            try:
                remaining = int(FAIL_USER_STATUS_COUNT_MARKER.read_text().strip() or "0")
            except ValueError:
                remaining = 0
            if remaining > 0:
                FAIL_USER_STATUS_COUNT_MARKER.write_text(str(remaining - 1))
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -1, "message": "fixture getUserStatus counted failure"},
                }
                emit_json(response)
                continue
        if params.get("usernames") is not None:
            # Contract 1.59 §4.55 username lookup: the --username face answers
            # a top-level array of JsonUserStatus records. First entry
            # resolves registered (with number+username+uuid), the rest are
            # the unregistered face; a rate-limit sentinel entry answers the
            # upstream CDSI RateLimitException mapping (-1, retryAfter
            # message).
            if "[fixture-username-ratelimited]" in params["usernames"]:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -1,
                        "message": "Rate limit exceeded; try again after 30 seconds (RateLimitException)",
                    },
                }
                emit_json(response)
                continue
            entries = []
            for index, name in enumerate(params["usernames"]):
                if index == 0:
                    entries.append(
                        {
                            "recipient": name,
                            "number": "+15551230001",
                            "username": name,
                            "uuid": "00000000-0000-0000-0000-00000000000" + str(index % 10),
                            "isRegistered": True,
                        }
                    )
                else:
                    entries.append({"recipient": name, "isRegistered": False})
            result = entries
        else:
            result = {"isRegistered": True}
    else:
        result = {"method": method}

    response = {"jsonrpc": "2.0", "id": request_id, "result": result}
    if method == "send" and params.get("message") == "[slow-host-test]":
        threading.Thread(
            target=emit_json_after,
            args=(response, 0.35),
            daemon=True,
        ).start()
        continue
    if method == "slowRead":
        # Slow read answer (same 0.35s cadence as the mutating slow family):
        # the result lands after a short connector request timeout, so the
        # read-only outcome is a deadline Timeout and the late answer must be
        # dropped as an unknown id, never misattributed to a later request.
        threading.Thread(
            target=emit_json_after,
            args=(response, 0.35),
            daemon=True,
        ).start()
        continue
    emit_json(response)

    if method == "duplicate":
        emit_json(response)
    if method == "emitReceive" or emit_receive_after:
        emit_receive()
    if method == "emitGroupUpdated":
        # The emitReceive twin for the groupUpdated projection: emitted after
        # the response, same receive-notification channel.
        update = {
            "groupId": params.get("groupId") or "ZmFrZS1ncm91cC0x",
            "revision": params.get("revision", 1),
            "expireTimerSeconds": params.get("expireTimerSeconds", 0),
        }
        if "editor" in params and params.get("editor") is not None:
            update["editor"] = params.get("editor")
        emit_json({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "account": receiving_account(),
                "envelope": {
                    "timestamp": int(time.time() * 1000),
                    "groupUpdated": update,
                },
            },
        })
    if method == "emitEnvelope":
        # Contract 1.15 test hook: inject arbitrary envelope receives so a
        # test can exercise reaction / remote-delete / typing / edit /
        # attachment-metadata normalization end to end through a real engine
        # process. The envelope is passed through verbatim; `envelopes`
        # (array form) emits each in order after the response.
        envelopes = params.get("envelopes")
        if not isinstance(envelopes, list):
            envelopes = [params.get("envelope") or {}]
        account = params.get("account") or receiving_account()
        result = {"method": method, "emitted": len(envelopes)}

        def emit_envelopes(account=account, envelopes=envelopes):
            for envelope in envelopes:
                emit_json({
                    "jsonrpc": "2.0",
                    "method": "receive",
                    "params": {"account": account, "envelope": envelope},
                })

        threading.Thread(target=emit_envelopes, daemon=True).start()
