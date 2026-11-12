// SPDX-License-Identifier: AGPL-3.0-only

//! Single source of truth for the host method surface (optimization-plan
//! §5.2 B1). One row per method carries every classification the connector
//! makes about it; dispatch-lane admission (`host.rs`), the metrics label
//! (`metrics.rs`), and the advertised capability list (`lib.rs`) all derive
//! from this table. Adding a method is one row here plus its host dispatch
//! arm and schema entry — not four parallel classification lists.

/// Dispatch lane that bounds a method's concurrency
/// (`host::HostDispatchLimits`): one semaphore set per account, plus a
/// connector-wide backstop per lane (ADR 0005).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lane {
    Control,
    Read,
    Send,
}

/// One table row: `(name, lane, account-scoped mutating, metrics class)`.
///
/// `account-scoped mutating` marks the mutating methods that serialize on
/// the per-account mutex and sit behind the delete drain barrier (`host.rs`
/// `acquire`); the metrics class is a fixed label from
/// `metrics::METHOD_CLASSES`, never the raw method string.
pub type MethodRow = (&'static str, Lane, bool, &'static str);

pub const METHODS: &[MethodRow] = &[
    ("runtime.status", Lane::Control, false, "control"),
    ("runtime.start", Lane::Control, false, "control"),
    ("runtime.stop", Lane::Control, false, "control"),
    // D4 所有权执行面(阶段1 批1-5c):本地编排(不透传上游),Control 车道
    // ——隔离/休眠都是破坏性收敛动作,与 runtime.stop 同级同格。
    ("ownership.quarantineSlot", Lane::Control, false, "control"),
    ("ownership.hibernateSlot", Lane::Control, false, "control"),
    ("accounts.list", Lane::Control, false, "accounts"),
    ("accounts.deleteLocalData", Lane::Control, true, "accounts"),
    // Account settings writes (contract 1.46, §4.45): the three storage-record
    // write faces — reaction-class write-lane mutex and delete barrier, no
    // local persistence; advertised through `account-settings`.
    ("accounts.setExpireTimer", Lane::Send, true, "accounts"),
    ("accounts.setProfile", Lane::Send, true, "accounts"),
    ("accounts.updateConfiguration", Lane::Send, true, "accounts"),
    ("link.start", Lane::Control, false, "link"),
    // `link.finish` never takes a global lane: `host.rs` routes it to the
    // bounded per-group wait lane (ADR 0001 R3) before the table's lane
    // would apply, so its Control entry only documents the fallback shape.
    ("link.finish", Lane::Control, false, "link"),
    // Rotating link attempt (contract 1.286, §4.272): one bounded engine call
    // on the attempt's own engine, no local persistence beyond the in-memory
    // slot table. The pre-dispatch gate answers LINK_ATTEMPT_NOT_FOUND /
    // INVALID_REQUEST / LINK_EXPIRED without touching the engine, and an
    // engine without the rotate face answers NOT_SUPPORTED.
    ("link.rotate", Lane::Control, false, "link"),
    ("link.cancel", Lane::Control, false, "link"),
    ("conversations.list", Lane::Read, false, "read"),
    // Blocked-conversations read (contract 1.46, §4.45): a bounded
    // cloud-backed read of the storage records' blocked bits — read lane, no
    // local persistence; advertised through `blocked-conversations`.
    ("conversations.getBlocked", Lane::Read, false, "read"),
    // Avatar download (contract 1.48, §4.47): the engine downloads,
    // decrypts, and sniffs the conversation avatar — one bounded read-only
    // call, no mutation, no local persistence; advertised through
    // `avatar-fetch`.
    ("conversations.getAvatar", Lane::Read, false, "read"),
    ("messages.list", Lane::Read, false, "read"),
    // Persisted attachment dimensions, read half (contract revision 1.271,
    // §4.255): one bounded store-only projection of the conversation's
    // `attachments_json` width/height faces — no upstream traffic, no
    // mutation, no unread side effect (the §4.76 adjacentMedia posture).
    // This is the desktop's open-conversation warm-up: it answers the sizes
    // the official model always has (Attachment.width/height) so every media
    // box is laid out from data before the first scroll. Advertised through
    // `attachment-dimensions`.
    (
        "messages.listAttachmentDimensions",
        Lane::Read,
        false,
        "read",
    ),
    // Persisted attachment dimensions, write half (contract revision 1.271,
    // §4.255): the desktop's own measurement (the official
    // VisualAttachment.dom.ts width/height capture) lands in the row's
    // descriptor face. A local store write on the send lane — the
    // conversations.saveDraft class (account-scoped mutex and delete barrier,
    // zero engine frames, zero upstream traffic); idempotent, so a replay of
    // the same pair answers updated=false instead of rewriting the row.
    ("messages.setAttachmentDimensions", Lane::Send, true, "send"),
    // Adjacent visual-media probe (contract 1.93, §4.76): a bounded
    // store-only read over one conversation's media-bearing rows — no
    // upstream traffic, no mutation; advertised through
    // `message-adjacent-media`.
    ("messages.adjacentMedia", Lane::Read, false, "read"),
    ("messages.getText", Lane::Read, false, "read"),
    // Per-recipient receipt ledger read (contract 1.190, §4.190): a bounded
    // store-only read over one message's ledger rows — no upstream traffic,
    // no mutation; the desktop's per-recipient checkmark face.
    ("messages.receipts", Lane::Read, false, "read"),
    // Orphan-sweep probe (contract 1.172, §4.172): the single-row read-only
    // face behind the desktop's unsettled-row sweep — the same ledger row
    // the retry face addresses, answered with its settled state; no
    // mutation, no upstream traffic.
    ("messages.getByClientRequestId", Lane::Read, false, "read"),
    // Account-wide store search (contract 1.30): a bounded read over the
    // local database only — no upstream traffic, no mutation.
    ("messages.search", Lane::Read, false, "read"),
    ("messages.sendText", Lane::Send, true, "send"),
    // Same-row retry of a definitively failed send (contract 1.31): mutating,
    // send-lane, upstream traffic — the same class as the original send.
    ("messages.retryText", Lane::Send, true, "send"),
    ("messages.attachments.send", Lane::Send, true, "send"),
    // In-place attachment retry (contract 1.278, §4.262; dataBase64/sizeBytes
    // optional = 1.279, §4.263; plural payload rebuild = 1.280, §4.264):
    // mutating, send-lane upstream traffic — the same class as the original
    // send, because the retry really re-uploads the bytes (caller-supplied for a
    // singular row, or the persisted payload group) and settles the SAME row in
    // the shape the original used.
    ("messages.attachments.retry", Lane::Send, true, "send"),
    // Sticker send (contract 1.35): mutating, send-lane upstream traffic —
    // the §4.12 attachment class verbatim, same-account mutex and delete
    // barrier included; advertised through `send-sticker`.
    ("messages.sendSticker", Lane::Send, true, "send"),
    // Contact-card send (contract revision 1.124, §4.105): mutating,
    // send-lane upstream traffic — the reaction class verbatim, same-account
    // mutex and delete barrier included; advertised through `send-contact`.
    ("messages.sendContact", Lane::Send, true, "send"),
    // Poll send batch (contract revision 1.125, §4.106): the three
    // group-only poll faces — mutating, send-lane upstream traffic, the
    // remoteDelete answer discipline (an indeterminate outcome answers the
    // explicit `{"status":"unknown"}`, never an automatic retry);
    // advertised through `polls`.
    ("messages.sendPollCreate", Lane::Send, true, "send"),
    ("messages.sendPollVote", Lane::Send, true, "send"),
    ("messages.sendPollTerminate", Lane::Send, true, "send"),
    ("messages.edit", Lane::Send, true, "send"),
    ("messages.remoteDelete", Lane::Send, true, "send"),
    ("messages.sendReaction", Lane::Send, true, "send"),
    // Pin family (contract 1.33): mutating, send-lane upstream traffic — the
    // reaction class verbatim, same-account mutex and delete barrier included.
    ("messages.sendPinMessage", Lane::Send, true, "send"),
    ("messages.sendUnpinMessage", Lane::Send, true, "send"),
    ("messages.sendAdminDelete", Lane::Send, true, "send"),
    // Outbound receipt face (contract 1.34): mutating, send-lane upstream
    // traffic — the reaction class again; the receipt send failure never
    // fails the request, but the write-lane mutex and delete drain barrier
    // still serialize it against sends on the same account.
    ("messages.markRead", Lane::Send, true, "send"),
    ("messages.markViewed", Lane::Send, true, "send"),
    // Outbound read/viewed SELF-SYNC faces (contract 1.108, §4.89): the
    // engine markRead/markViewed SyncMessage channel — independent of the
    // readReceipts-gated peer receipt face, same receipt-class discipline,
    // so the same lane and mutex classification applies.
    ("messages.syncRead", Lane::Send, true, "send"),
    ("messages.syncViewed", Lane::Send, true, "send"),
    // Delete-for-me SELF-SYNC upstream leg (contract 1.118, §4.99): the
    // conversation-level delete-for-me sync the official desktop sends when
    // a conversation is cleared — receipt-class, same lane and mutex
    // classification as the syncRead/syncViewed pair; advertised through
    // `delete-for-me`.
    ("messages.deleteForMe", Lane::Send, true, "send"),
    // Message-level delete-for-me SELF-SYNC upstream leg (contract 1.197,
    // §4.197): the official messageDeletes sender, one engine
    // `deleteForMeMessages` call per batch — receipt-class, same lane and
    // mutex classification as the conversation twin; advertised through
    // `delete-for-me`.
    ("messages.deleteForMeMessages", Lane::Send, true, "send"),
    // View-once faces (contract 1.38): the bare open-sync passthrough and
    // the burn trigger are both receipt-class — mutating, send-lane upstream
    // traffic under the reaction-class write-lane mutex and delete barrier;
    // an upstream failure degrades {status: unknown} and is never retried.
    ("messages.sendViewOnceOpen", Lane::Send, true, "send"),
    ("messages.markViewOnceOpened", Lane::Send, true, "send"),
    // Media ingest (ADR 0004): the chunked streaming triple rides the READ
    // lane — one bounded chunk per call, no mutation, no upstream traffic.
    // The one-shot base64 reader (`messages.attachments.get`, contract 1.10
    // PoC) was retired with contract 1.20; the chunked triple is the only
    // inbound-attachment channel.
    ("messages.attachments.open", Lane::Read, false, "read"),
    ("messages.attachments.readChunk", Lane::Read, false, "read"),
    (
        "messages.attachments.closeHandle",
        Lane::Read,
        false,
        "read",
    ),
    // `contacts.sync` rides the READ lane: a slow sync must not squeeze the
    // control lane (runtime.status/start keep answering). The desktop
    // client's requestScheduler.ts keeps its own lane limits as a
    // hand-maintained mirror of host.rs CONTROL/READ/SEND_CONCURRENCY — a
    // lane or capacity change on either side must move both sides in
    // lockstep (optimization-plan §5.2 B2; desktop-side realignment is a
    // separate batch).
    ("contacts.sync", Lane::Read, true, "contacts"),
    ("contacts.list", Lane::Read, false, "contacts"),
    ("groups.get", Lane::Read, false, "contacts"),
    // Groups in common (contract 1.181, §4.181): the contact-details panel's
    // groups-in-common answer over the §4.39 captured rosters — a pure
    // local-cache read beside groups.get, no engine traffic, no writes.
    ("groups.common", Lane::Read, false, "contacts"),
    ("contacts.setLocalAlias", Lane::Send, true, "send"),
    ("presence.setTypingMessage", Lane::Send, true, "send"),
    // Sticker pack browsing (contract 1.36, §4.32): anonymous CDN traffic
    // through the engine — no account, no mutation, no local state, so the
    // READ lane and the read metrics class; the connector passes pack
    // identity through and never touches key material beyond the parameter.
    ("stickerPacks.getManifest", Lane::Read, false, "read"),
    ("stickerPacks.getImage", Lane::Read, false, "read"),
    // Conversation pin sync (contract 1.36, §4.33): getPinnedConversations is
    // a bounded cloud-backed read; setConversationPinned is the mutating
    // storage-service write — reaction-class write-lane mutex and delete
    // barrier, no local persistence on either side.
    ("conversations.getPinned", Lane::Read, false, "read"),
    ("conversations.setPinned", Lane::Send, true, "send"),
    // Conversation blocked-bit write (contract 1.48, §4.47): mutating,
    // send-lane upstream traffic — the §4.33 pin-write class verbatim,
    // same-account mutex and delete barrier included; the result is the
    // post-write cloud blocked list read back, not a local echo; advertised
    // through `blocked-write`.
    ("conversations.setBlocked", Lane::Send, true, "send"),
    // Conversation draft stamp (contract 1.138, §4.130): mutating local
    // state on the send lane — the history.importRetry class (a local write
    // with no upstream call, the reaction-class same-account mutex and
    // delete barrier included). The engine stays out of the path: the stamp
    // is the whole draft record (the desktop keeps draft text in its own
    // safeStorage), and the refreshed summary rides conversation.changed.
    ("conversations.saveDraft", Lane::Send, true, "send"),
    ("conversations.clearDraft", Lane::Send, true, "send"),
    // Conversation state trio (contract 1.116, §4.97): get is a bounded
    // cloud-backed read of the storage records' mute/archive/unread bits;
    // set is the mutating storage-service partial write — reaction-class
    // write-lane mutex and delete barrier, no local persistence on either
    // side; advertised through `conversation-state`.
    ("conversations.getState", Lane::Read, false, "read"),
    ("conversations.setState", Lane::Send, true, "send"),
    // Sticker pack sync (contract 1.37, §4.34): getSyncs is a bounded
    // cloud-backed read of the account's StickerPackRecord set; setSync is
    // the mutating storage-service write — reaction-class write-lane mutex
    // and delete barrier, no local persistence on either side (unlike the
    // anonymous §4.32 browse face, these are account-scoped).
    ("stickerPacks.getSyncs", Lane::Read, false, "read"),
    ("stickerPacks.setSync", Lane::Send, true, "send"),
    // Link-time history import status (contract revision 1.39, §4.38): a
    // store-only read over the import ledger and the archive presence signal
    // — no engine call, no network, no mutation. The desktop polls it while
    // the state is `running`; there is deliberately no push event. Since
    // contract revision 1.53 a `running` state may carry the `progress`
    // object (the engine's transfer-download byte snapshot — one bounded
    // read-only call — or the connector's own import pass); every other
    // state stays store/disk-only.
    ("history.importStatus", Lane::Read, false, "read"),
    // Link-time history import manual retry (contract revision 1.53, §4.38):
    // clears the account's `failed` ledger row and re-arms the orchestration
    // (the archive on disk returns to `pending` for the sweep/watcher).
    // Mutating, send lane behind the reaction-class write-lane mutex and
    // delete drain barrier — same account-mutating class as backups.export;
    // no upstream traffic. Advertised through the existing `history-import`
    // tag (no new capability bit).
    ("history.importRetry", Lane::Send, true, "accounts"),
    // Link-time history import cancel (contract revision 1.148, §4.146): the
    // desktop's cancel-sync face — aborts a live pass and arms the in-process
    // cancel marker without unbinding. Mutating local state on the send lane
    // behind the reaction-class write-lane mutex and delete drain barrier —
    // the history.importRetry class verbatim; the one upstream call (the
    // frozen engine `history.importCancel`) is best-effort read-of-outcome,
    // never retried, never failing the call. Advertised through the existing
    // `history-import` tag (no new capability bit, the 1.53 precedent).
    ("history.importCancel", Lane::Send, true, "accounts"),
    // History attachment download (contract revision 1.57, §4.38 step 3):
    // the transit-CDN byte chain behind an imported pointer face — mutating
    // (it lands a file in the governed media directory), send lane behind the
    // reaction-class write-lane mutex and delete barrier, same class as
    // importRetry. Advertised through the existing `history-import` tag (no
    // new capability bit, the 1.53 precedent).
    ("history.attachmentDownload", Lane::Send, true, "send"),
    // Live attachment download (contract revision 1.61, §4.54): the same
    // transit-CDN chain behind the live-receive/import locator ladder,
    // addressed by attachmentIndex. Mutating (it lands a file in the
    // governed media directory), send lane behind the reaction-class
    // write-lane mutex and delete barrier — the 1.57 class verbatim.
    // Advertised through the `attachment-download` tag (the §4.38
    // faces keep their no-new-bit discipline; this one widens the audience
    // beyond the history-import desktops) — the one advertisement gated on
    // runtime state since contract 1.98: the handshake omits the tag unless
    // the media table is armed.
    ("attachments.download", Lane::Send, true, "send"),
    // Attachment backfill request (contract revision 1.175, §4.175): the
    // request half of the official backfill loop — receipt-class fire-and-
    // forget posture, control lane (no payload delivery).
    (
        "attachments.requestBackfill",
        Lane::Control,
        false,
        "control",
    ),
    // Disappearing-message timer set (contract revision 1.42, §4.41):
    // mutating, send-lane upstream traffic — the reaction class verbatim,
    // same-account mutex and delete barrier included. Direct conversations
    // route setExpirationTimer/updateContact by mode; groups route the
    // updateGroup expiration write since contract 1.45 (§4.44).
    ("conversations.setExpireTimer", Lane::Send, true, "send"),
    // Group management writes (contract revision 1.45, §4.44): mutating,
    // send-lane upstream traffic — the setExpireTimer class verbatim,
    // same-account mutex and delete barrier included; advertised through
    // `group-management`. No local row is written by the send path; group
    // state converges through the group-update receive projection.
    ("groups.update", Lane::Send, true, "send"),
    ("groups.quit", Lane::Send, true, "send"),
    // Group termination (contract revision 1.52, §4.50): mutating, send-lane
    // upstream traffic — the groups class verbatim, same-account mutex and
    // delete barrier included; advertised through `group-terminate`. Zero
    // local writes: the terminated state converges through the group-update
    // receive projection.
    ("groups.terminate", Lane::Send, true, "send"),
    // Group join-request approval (contract revision 1.58, §4.53): mutating,
    // send-lane upstream traffic — the groups class verbatim, same-account
    // mutex and delete barrier included; advertised through
    // `group-join-approve`. The write itself is the pinned upstream's
    // `updateGroup` faces (approve = the `members` family, refuse = the
    // `removeMembers` family), with the candidate set the caller names
    // intersected against the engine's own requesting-members read before
    // anything goes upstream, so the member/remove-member arrays can never
    // carry a non-requesting address (the "add stranger" / "remove member"
    // mis-target faces fail closed at the connector). Zero local writes: the
    // roster converges through contacts.sync like every group row.
    ("groups.approveJoinRequests", Lane::Send, true, "send"),
    // Group invite revocation (contract revision 1.64, §4.57): mutating,
    // send-lane upstream traffic — the groups class verbatim, same-account
    // mutex and delete barrier included; advertised through
    // `group-invite-revoke`. The write is the pinned upstream's updateGroup
    // `removeMembers` family — entries that are pending members ride
    // `revokeInvitedMembers` (GroupHelper.updateGroupV2:763-764) — with the
    // candidate set the caller names intersected against the engine's own
    // pending-members read before anything goes upstream, so the array can
    // never carry a non-pending address (a full member or a requesting
    // candidate never rides the revoke write; the mis-target faces fail
    // closed at the connector). Zero local writes: the roster converges
    // through contacts.sync like every group row.
    ("groups.revokeInvites", Lane::Send, true, "send"),
    // Group invite-link family (contract revision 1.117, §4.98): the
    // engine's link material and parse faces are account-less reads (the
    // password is pure CSPRNG, the parse is pure proto decoding — the
    // sticker-browse class), build and preview are account-scoped reads
    // (the build's default arm reads the server group state; explicit
    // password is pure construction), and join/cancel are the mutating
    // upstream writes — the groups class verbatim, same-account mutex and
    // delete barrier included. Zero local writes on every face: the
    // membership state converges through contacts.sync. The link and
    // password bytes are single-pass material — they ride the call they
    // were asked for and are never logged or persisted connector-side.
    (
        "groups.generateInviteLinkPassword",
        Lane::Read,
        false,
        "read",
    ),
    ("groups.buildInviteLink", Lane::Read, false, "read"),
    ("groups.parseInviteLink", Lane::Read, false, "read"),
    ("groups.previewViaLink", Lane::Read, false, "read"),
    ("groups.joinViaLink", Lane::Send, true, "send"),
    ("groups.cancelJoinRequest", Lane::Send, true, "send"),
    // Group migration (contract revision 1.123, §4.104): mutating, send-lane
    // upstream traffic — the groups class verbatim, same-account mutex and
    // delete barrier included; advertised through the existing
    // `group-management` tag, widened in place (the 1.82 precedent — the
    // migration is the group life cycle's own GV1→GV2 face). The engine
    // derives the new GV2 master key and answers {groupId, revision}; its
    // already-migrated fallback probe (the official
    // hasV1GroupBeenMigrated semantic) presents as the same honest answer.
    // Zero local writes: the migrated group converges through contacts.sync
    // like every group row.
    ("groups.migrate", Lane::Send, true, "send"),
    // Group create (contract revision 1.126, §4.107): mutating, send-lane
    // upstream traffic — the groups class verbatim, same-account mutex and
    // delete barrier included; advertised through the existing
    // `group-management` tag, widened in place (the 1.82 precedent — the
    // create is the group life cycle's own first face). The engine derives
    // the new group master key and answers {groupId, revision} (the
    // official createGroupV2 posture). Zero local writes: the new group
    // converges through contacts.sync like every group row.
    ("groups.create", Lane::Send, true, "send"),
    // Android local-backup export (contract revision 1.47, §4.46): the
    // engine's background export task is account-mutating state, so the
    // start face rides the send lane behind the reaction-class write-lane
    // mutex and delete barrier; the status poll and the media-three-chain
    // file face are bounded reads. Advertised through `backup-export`.
    ("backups.export", Lane::Send, true, "accounts"),
    // Plaintext chat export (contract revision 1.132, §4.115): the S1
    // 「明文不过引擎」 face — the connector projects its own store into a
    // plaintext JSONL artifact engine-free (zero network requests; the
    // build itself never calls the engine, and the start slot's only engine
    // touch is the best-effort read-only exportStatus slot poll). The start
    // face is account-mutating local state (the
    // connector-local per-account task slot, shared with the encrypted
    // export in the start direction), so it rides the send lane behind the
    // reaction-class write-lane mutex and delete barrier — the
    // backups.export class verbatim; the status poll and the file
    // three-chain are the unchanged §4.46 reads. Advertised through the
    // existing `backup-export` tag, widened in place (the 1.87 upload
    // precedent — no new capability bit).
    ("backups.exportPlaintext", Lane::Send, true, "accounts"),
    ("backups.exportStatus", Lane::Read, false, "read"),
    ("backups.exportFile.open", Lane::Read, false, "read"),
    ("backups.exportFile.readChunk", Lane::Read, false, "read"),
    ("backups.exportFile.closeHandle", Lane::Read, false, "read"),
    // Official-desktop snapshot import (contract revision 1.78, §4.68): the
    // engine consumes an official Signal Desktop snapshot directory and
    // produces the §4.38 archive. The start face is account-mutating state
    // (the engine's own per-account import gate), so it rides the send lane
    // behind the reaction-class write-lane mutex and delete barrier — the
    // backups.export class verbatim; the status poll is a bounded read.
    // Advertised through the existing `history-import` tag (no new capability
    // bit: the face's entire output is the history-import archive and
    // ledger).
    ("backups.importSnapshot", Lane::Send, true, "accounts"),
    ("backups.importSnapshotStatus", Lane::Read, false, "read"),
    // Cloud-backup restore passthrough (contract revision 1.83, §4.69):
    // the engine's cloud restore runs entirely in its background (credentials
    // → zkgroup → chat gRPC → CDN → decrypt → NDJSON), so the start face is
    // account-mutating engine state — send lane behind the reaction-class
    // write-lane mutex and delete barrier, the backups.export class verbatim;
    // the status poll is a bounded read over the engine's progress snapshot.
    // Advertised through the existing `history-import` tag (no new capability
    // bit: the restore's entire output is the history-import NDJSON chain).
    ("backups.restoreFromCloud", Lane::Send, true, "accounts"),
    ("backups.cloudStatus", Lane::Read, false, "read"),
    // Cloud-backup upload passthrough (contract revision 1.87, §4.72): the
    // outbound half of cloud backup. The start face first (re)builds the
    // §10.2 transitional artifact with the §4.46 machine — connector-local
    // store + filesystem work — then forwards to the engine, whose whole
    // chain (assembly → credentials → zkgroup → form gRPC → cdn3 TUS
    // single POST → refresh_backup) runs in its background: account-
    // mutating engine state, so send lane behind the reaction-class
    // write-lane mutex and delete barrier, the §4.69 restore class
    // verbatim; the status poll is a bounded read over the engine's
    // process-wide single-slot progress snapshot. Advertised through the
    // existing `backup-export` tag, widened in place (the 1.82
    // call-signaling precedent — the upload's entire input is the
    // backup-export artifact chain); KT-extension, no upstream counterpart.
    ("backups.uploadToCloud", Lane::Send, true, "accounts"),
    ("backups.uploadStatus", Lane::Read, false, "read"),
    // Report spam (contract revision 1.49, §4.48): mutating, send-lane
    // upstream traffic — the groups class verbatim, same-account mutex and
    // delete barrier included; advertised through `report-spam`. Zero local
    // writes: the report is an upstream protocol action only.
    ("messages.reportSpam", Lane::Send, true, "send"),
    // Call signaling (contract revision 1.51, §4.49): the send face is
    // mutating send-lane upstream traffic — the reaction class verbatim,
    // same-account mutex and delete barrier included; the signaling payload
    // is shape-gated (type enum / callId / opaque payload) and forwarded
    // byte-for-byte, never interpreted. The state face is a store-only
    // read: the connector is a signaling pipe, the call state machine
    // lives in the desktop + calling sidecar (the honest near-empty
    // registry). Advertised through `call-signaling`.
    ("calls.sendSignal", Lane::Send, true, "send"),
    // Group call update (contract revision 1.127, §4.108): mutating,
    // send-lane upstream traffic — the reaction class verbatim, same-account
    // mutex and delete barrier included; advertised through the existing
    // `call-signaling` tag, widened in place (the 1.82/1.88 precedent — the
    // group-call update is the same signaling pipe's group-era face). The
    // conversation row must resolve to a group kind before anything travels
    // (group call signaling has no direct form — 1:1 signaling rides
    // calls.sendSignal), and the engine's DataMessage.groupCallUpdate
    // fan-out carries the era id.
    ("calls.sendGroupCallUpdate", Lane::Send, true, "send"),
    ("calls.getState", Lane::Read, false, "read"),
    // Username write (contract revision 1.59, §4.55): mutating, send-lane
    // upstream traffic — the account-settings class verbatim, same-account
    // mutex and delete barrier included. The upstream face is the pinned
    // signal-cli `updateAccount` JSON-RPC command (0.14.8
    // UpdateAccountCommand.java:42-71): `username` and `deleteUsername` are
    // mutually exclusive keys (at least one required — fail-closed locally),
    // the reserve→confirm sequence is upstream-internal, and the result is
    // the `{username, usernameLink}` projection (read back after the write).
    // Zero local persistence; advertised through `username`.
    ("accounts.setUsername", Lane::Send, true, "accounts"),
    // Username read (contract revision 1.59, §4.55): a bounded read of the
    // account's own username/link straight from the upstream `updateAccount`
    // result shape — read lane, no mutation, no local persistence.
    ("accounts.getUsername", Lane::Read, false, "read"),
    // Device-capability registration read (contract revision 1.100, §4.81):
    // the idempotent device-face registration probe — a read-lane call that
    // still serializes on the account mutex (the contacts.sync precedent:
    // the upstream face is a PUT), no local persistence. The result strips
    // the engine's bare `account` identity before it crosses the connector.
    ("accounts.deviceCapabilities", Lane::Read, true, "accounts"),
    // Device-plane faces (contract revision 1.122, §4.103, capability
    // device-management): getDevices is the bounded device-list read — one
    // GET v1/devices projection with engine-side device-name decryption, read
    // lane, non-mutating, no local persistence; unlinkDevice is the mutating
    // upstream DELETE v1/devices/{id} — the groups class verbatim,
    // same-account mutex and delete barrier included. The unlink's
    // indeterminate outcome face answers SEND_OUTCOME_UNKNOWN and is never
    // retried.
    ("accounts.getDevices", Lane::Read, false, "read"),
    // Login-window sync projection (contract revision 1.286, §4.281): the
    // engine's pure-read `getSyncState` passthrough — {contacts, storage,
    // profile, sinceMs} behind the closed phase vocabulary shape gate. Read
    // lane, non-mutating, no local persistence: this is the desktop gate's
    // bounded polling fallback (SIGNAL-STAGE1 §二 P-B-3), so a repeated call
    // must answer the same face and never serialize on the account mutex.
    ("accounts.getSyncState", Lane::Read, false, "read"),
    ("accounts.unlinkDevice", Lane::Send, true, "accounts"),
    // Username lookup (contract revision 1.59, §4.55): upstream `getUserStatus
    // --username` passthrough (0.14.8 GetUserStatusCommand.java:41,69) — one
    // bounded cloud read, no mutation, no local state; the candidate bounds
    // mirror the username shape rules.
    ("username.lookup", Lane::Read, false, "read"),
    // Phone lookup (contract revision 1.164, §4.162): the engine's
    // `phoneLookup` CDSI read (engine d088a59) — one bounded cloud batch
    // (1..20 full E.164 numbers, the engine's own frame grammar mirrored
    // fail-closed), no mutation, no local state; the results are a memory
    // projection only (the number→account local mapping stays the contacts
    // sync chain's — zero rows land in the connector store).
    ("phone.lookup", Lane::Read, false, "read"),
    // Message-request response faces (contract revision 1.63, §4.56): the
    // pinned upstream's native `sendMessageRequestResponse` sync face —
    // accept/decline over the multi-device MessageRequestResponse sync
    // message. Mutating, send-lane upstream traffic — the reaction class
    // verbatim, same-account mutex and delete barrier included; advertised
    // through `message-requests`. Zero local writes: the request state
    // converges through the §4.56 receive projection (an MRR envelope on the
    // account stamps the contact row's accepted flag; the official desktop
    // derives request state locally the same way). An upstream decline for a
    // single contact rides the two-step ladder when the account cannot share
    // its profile with the peer (the share-off write fails with the upstream
    // UNREGISTERED_FAILURE user error); the ladder is internal — the host
    // sees one method and one outcome.
    ("conversations.acceptRequest", Lane::Send, true, "send"),
    ("conversations.declineRequest", Lane::Send, true, "send"),
    // Conversation-level report (contract revision 1.266, §4.250): the
    // official reportSpam / blockAndReportSpam thunks — the MRR sync word
    // plus the §4.48 report face over the guid ladder, one host method.
    // Mutating, send-lane upstream traffic — the reaction class verbatim,
    // same-account mutex and delete barrier included; advertised through
    // the existing `report-spam` tag, widened in place (the 1.82/1.88
    // precedent). Direct conversations only (the official group report
    // resolves the added-by sender first — no data plane, honest refusal).
    ("conversations.reportSpam", Lane::Send, true, "send"),
    // Safety-number read (contract revision 1.68, §4.61; peer arm 1.281,
    // §4.265): the pinned upstream's native `listIdentities` JSON-RPC read
    // (0.14.8 jsonrpc.rs:121-126; ListIdentitiesCommand.java:23 — a
    // JsonRpcLocalCommand, so the JSON-RPC projection is native) — one
    // bounded read keyed by the addressed peer reference (a 1:1 conversation
    // id, or the peer's own ACI UUID / E.164 with no conversation row
    // needed), no mutation, no local persistence; advertised through
    // `safety-number`.
    ("identities.get", Lane::Read, false, "read"),
    // Safety-number verify write (contract revision 1.68, §4.61): the
    // pinned upstream's native `trust` JSON-RPC face (0.14.8
    // jsonrpc.rs:374-381) in its verifiedSafetyNumber form — the official
    // desktop's "Mark as verified" semantic (the digits the user just
    // compared travel back as the confirmation). Mutating, send-lane
    // upstream traffic — the reaction class verbatim, same-account mutex
    // and delete barrier included; the testing-only trustAllKnownKeys mode
    // is never sent. The official toggle's clear-verification half has no
    // pinned JSON-RPC projection and stays out of the contract. One local
    // write on success (1.260, §4.244): the addressed peer's trust stamp —
    // by conversation row on the `conversationId` arm, by peer key on the
    // `peerKey` arm (1.281, §4.265, where no conversation row is required at
    // all) — so the read face converges without a second round trip.
    ("identities.verify", Lane::Send, true, "send"),
    // Stories faces (contract revision 1.76, §4.67): `messages.sendStory` is
    // mutating send-lane upstream traffic — the reaction class verbatim,
    // same-account mutex and delete barrier included (rowless: no pending
    // row, no conversation addressing). The stories-disabled toggle is the
    // connector's own receive gate — local store only, no engine frame, but
    // still an account-state write, so setDisabled rides the send lane
    // behind the same-account mutex and delete barrier (the setLocalAlias
    // precedent) and getDisabled is a bounded store read; both answer from
    // the local store alone. Advertised through `stories`.
    ("messages.sendStory", Lane::Send, true, "send"),
    ("stories.setDisabled", Lane::Send, true, "send"),
    ("stories.getDisabled", Lane::Read, false, "read"),
    // Story viewed receipt (contract revision 1.85, §4.70): the send leg of
    // the story viewed-receipt chain — mutating, send-lane upstream traffic,
    // the messages.markViewed receipt class verbatim (best-effort, failures
    // degrade to `unknown`, nothing retries), with the §4.29 row selection
    // replaced by the story anchor (storyAuthor + storySentAt). The upstream
    // face is the engine's own `sendViewedReceipt`, so no capability seam.
    // Advertised through the existing
    // `stories` tag (widened in place, the 1.82 call-signaling precedent).
    ("stories.markViewed", Lane::Send, true, "send"),
    // Story reaction send (contract 1.152, §4.151): the §4.150 call-event
    // proxy posture on the stories family — the connector-side registration
    // of the engine's `sendStoryReaction` (engine 4822e99, the official
    // reactToStory alignment, the Reaction + StoryContext dual anchor). A
    // pure send-lane proxy: account resolution, the mutating forward, the
    // engine's `{}` answer and error faces through untouched — the
    // author/emoji/timestamp value domain, the author resolution, and the
    // identity-reject/profileSharing gates are the engine's fail-closed
    // parse, never re-gated or re-keyed here; `remove: true` is the
    // connector's one local refusal (the official reaction is place-only,
    // remove:false hardcoded). Mutating: an indeterminate outcome answers
    // SEND_OUTCOME_UNKNOWN and is never retried. Replaces the §4.77
    // constant CAPABILITY_UNAVAILABLE arm (the engine face has landed).
    // Advertised through the existing `stories` tag (widened in place, the
    // 1.82 call-signaling precedent).
    ("stories.sendReaction", Lane::Send, true, "send"),
    // Story delete-for-everyone fan-out (contract 1.153, §4.152): the
    // connector-side registration of the engine's `deleteStoryForEveryone`
    // (engine 7320393, the official sendDeleteForEveryone alignment) — the
    // §4.150 proxy posture on the stories family. A pure send-lane proxy:
    // account resolution, the mutating forward, the engine's `{timestamp}`
    // answer and error faces through untouched — the timestamp domain, the
    // recipients entries (absent/null = the empty batch, the single-string
    // form refused), and the updatedStoryRecipients member shapes are the
    // engine's fail-closed parse, never re-gated or re-keyed here. Mutating:
    // an indeterminate outcome answers SEND_OUTCOME_UNKNOWN and is never
    // retried (an unknown delete outcome may already sit in the recipients'
    // story fan-out). Rowless: no local write, no event. Advertised through
    // the existing `stories` tag (widened in place, the 1.82 precedent).
    ("stories.deleteForEveryone", Lane::Send, true, "send"),
    // Story-anchored attachment byte faces (contract revision 1.86, §4.71):
    // the story byte channel — stories land in no conversation row (§4.67),
    // so the row-anchored `attachments.download` can never address one and
    // the caller supplies the pointer face its story event carried.
    // downloadAttachment is mutating send-lane local work (it lands a file
    // in the governed media directory) — the 1.57/1.61 download class
    // verbatim: reaction-class write-lane mutex and delete drain barrier,
    // every download/verify failure terminal, never auto-retried. The chain
    // is pure connector (transit-CDN GET + the §4.38 step-3 crypto), zero
    // engine involvement. openAttachment
    // is the messages.attachments.open class verbatim (read lane, handle
    // mint over the already-landed file, no engine touch); chunk read and
    // close ride the existing handle faces unchanged. Advertised through
    // the existing `stories` tag (widened in place, the 1.82
    // call-signaling precedent).
    ("stories.downloadAttachment", Lane::Send, true, "send"),
    ("stories.openAttachment", Lane::Read, false, "read"),
    // Call-link credential material faces (contract revision 1.88, §4.73):
    // pure engine passthrough — the material in, the credential bytes out,
    // zero logic, zero parsing, zero logging (the engine a3ae39b batch owns
    // the whole zkgroup chain; the credential/presentation bytes are never
    // logged or persisted anywhere). Every face is a bounded read: no local
    // state changes, no message send — the conversations.getAvatar class
    // (network possible inside one engine call, read lane, non-mutating).
    // createLinkAuth's server-side POST is credential issuance with no
    // user-visible state change; endorsementsPublicKey is a constant
    // derivation, no account at all. Advertised through the existing
    // `call-signaling` tag, widened in place (the 1.82 precedent — the
    // faces are the signaling pipeline's own material supply). kt-engine
    // only (KT-extension methods a stock signal-cli does not carry).
    ("calls.linkPresentation", Lane::Read, false, "read"),
    ("calls.createLinkAuth", Lane::Read, false, "read"),
    ("calls.groupProof", Lane::Read, false, "read"),
    ("calls.groupMembers", Lane::Read, false, "read"),
    ("calls.endorsementsPublicKey", Lane::Read, false, "read"),
    // Call-relay configuration proxy (contract revision 1.145, §4.143): the
    // connector-side registration of the engine's `calls.relays` — the
    // authenticated GET /v2/calling/relays ICE/TURN read the desktop's
    // calling chain dials with (the relays data flows engine → connector →
    // desktop → calling sidecar). A pure proxy: account resolution, the
    // read-lane forward, the engine's answer through untouched — the
    // connector owns no TTL, no cache, no polling (the engine's
    // official-same-shape cache and the pull-on-demand face cover all of
    // it), and the error face is the engine's verbatim (the plain -32603
    // unknown-account face, the 401/403 unbound message through the §4.17
    // matcher). Advertised through the existing `call-signaling` tag,
    // widened in place (the 1.82/1.88/1.127 precedent — the relays are the
    // call chain's own connection material). KT-extension, no upstream
    // connector-side counterpart.
    ("calls.relays", Lane::Read, false, "read"),
    // Call-event self-sync proxy (contract revision 1.151, §4.150): the
    // connector-side registration of the engine's `sendCallEvent` — the
    // SyncMessage.callEvent=19 self-send that mirrors one call-history
    // state transition to the account's own devices (the official
    // updateRemoteCallHistory/getDeleteCallEvent alignment). A pure
    // send-lane proxy: account resolution, the mutating forward, the
    // engine's {timestamp} answer and error faces through untouched — the
    // three word lists, the per-leg conversation shapes, the callId
    // domain, and the direct/group callId requirement are the engine's
    // fail-closed parse gate (engine 6d56660), never re-gated or re-keyed
    // here. The event source wiring (one call per local transition) lives
    // in the calling sidecar (queued); desktop consumption is queued.
    // Advertised through the existing `call-signaling` tag, widened in
    // place (the 1.82/1.88/1.127/1.145 precedent — the call-event sync is
    // the call chain's own history face). KT-extension, no upstream
    // connector-side counterpart.
    ("calls.sendCallEvent", Lane::Send, true, "send"),
    // Chat-folder sync (contract 1.95, §4.78): chatFolders.list is a bounded
    // cloud-backed read of the account's ChatFolderRecord set;
    // chatFolders.setRecords is the mutating storage-service write —
    // reaction-class write-lane mutex and delete barrier, no local
    // persistence on either side (records cross verbatim; the connector
    // neither interprets nor re-keys them). KT-extension, no upstream
    // counterpart; advertised through `chat-folders`.
    ("chatFolders.list", Lane::Read, false, "read"),
    ("chatFolders.setRecords", Lane::Send, true, "send"),
    // Notification-profile sync (contract revision 1.129, §4.110):
    // notificationProfiles.list is a bounded cloud-backed read of the
    // account's NotificationProfile set; notificationProfiles.setRecords is
    // the mutating storage-service write — reaction-class write-lane mutex
    // and delete barrier, no local persistence on either side (records cross
    // verbatim; the connector neither interprets nor re-keys them).
    // KT-extension, no upstream counterpart; advertised through
    // `notification-profiles`.
    ("notificationProfiles.list", Lane::Read, false, "read"),
    ("notificationProfiles.setRecords", Lane::Send, true, "send"),
    // Story-distribution-list sync (contract revision 1.130, §4.111): the
    // stories surface's own audience-management sync pipe — list is a
    // bounded cloud-backed read of the account's StoryDistributionList
    // set; setRecords is the mutating storage-service write —
    // reaction-class write-lane mutex and delete barrier, no local
    // persistence on either side. KT-extension, no upstream counterpart;
    // advertised through the existing `stories` tag, widened in place (the
    // 1.82 no-new-bit discipline — the distribution lists are the story
    // audience the §4.67 send faces address).
    ("storyDistributionLists.list", Lane::Read, false, "read"),
    (
        "storyDistributionLists.setRecords",
        Lane::Send,
        true,
        "send",
    ),
    // Storage merge/import/call-link faces (contract revision 1.131,
    // §4.112): storage.mergeContacts / storage.importGroups are the
    // engine-local Storage Service ingest reads — the contacts.sync class
    // (read lane, account-scoped mutating: the ingest lands engine state,
    // so the same-account mutex and delete barrier serialize it; metrics
    // contacts). storage.getCallLinks is the bounded cloud read;
    // storage.setCallLink is the mutating storage-service write — the
    // reaction class verbatim, unknown outcome answers SEND_OUTCOME_UNKNOWN
    // and is never retried. KT-extension, no upstream counterpart;
    // advertised through `storage-sync`.
    ("storage.mergeContacts", Lane::Read, true, "contacts"),
    ("storage.importGroups", Lane::Read, true, "contacts"),
    ("storage.getCallLinks", Lane::Read, false, "read"),
    ("storage.setCallLink", Lane::Send, true, "send"),
    // Read-only runtime diagnostic face (contract 1.97, §4.79): one payload
    // answering the whole chain — connector/engine versions plus the
    // engine's self-certification baseline, per-group data-dir and
    // occupancy-lock status, the bounded recent-error ring, the reused
    // connectivity surfaces, and the declared Signal service-plane probes.
    // Control lane like runtime.status; never
    // mutating; the implementation is entirely in `doctor`.
    ("runtime.doctor", Lane::Control, false, "control"),
    // Durable change-ledger read face (contract revision 1.283, §4.267): one
    // bounded, token-stamped page of thin events plus the reset verdict. Read
    // lane — the page reads on the store's read pool, never the writer, and
    // the reset is a decision, not a mutation. Added to the table so the
    // handshake advertises it: a host that cannot see the capability would
    // fall back to polling every list face.
    ("events.list", Lane::Read, false, "read"),
];

fn spec(method: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|row| row.0 == method)
}

/// Dispatch lane for one method; an unknown method takes the control lane
/// (the pre-table fallback behavior).
pub fn lane(method: &str) -> Lane {
    spec(method).map_or(Lane::Control, |row| row.1)
}

/// Whether the method is mutating and account-scoped (per-account mutex plus
/// delete drain barrier in `host.rs`); unknown methods are not.
pub fn is_account_scoped_mutating(method: &str) -> bool {
    spec(method).is_some_and(|row| row.2)
}

/// Fixed metrics label; unknown methods classify as `"unknown"` (plan §8).
pub fn metrics_class(method: &str) -> &'static str {
    spec(method).map_or("unknown", |row| row.3)
}

/// Method names in table order; the advertised capability list
/// (`crate::PHASE2_CAPABILITIES`) derives from this, so the two cannot drift
/// apart.
pub const METHOD_NAMES: [&str; METHODS.len()] = {
    let mut names = [""; METHODS.len()];
    let mut index = 0;
    while index < METHODS.len() {
        names[index] = METHODS[index].0;
        index += 1;
    }
    names
};

/// The §4.54 live attachment-download tag — the one feature capability the
/// handshake advertisement gates on runtime state (contract revision 1.98):
/// media download is real only when the launcher armed media ingest and the
/// group's media table exists, so a runtime without it must not advertise
/// the tag. A desktop that sees it absent renders attachment pills
/// metadata-only — the honest unavailable path — instead of calling a face
/// that answers `CAPABILITY_UNAVAILABLE` for every download.
pub const ATTACHMENT_DOWNLOAD_CAPABILITY: &str = "attachment-download";

/// Feature capability tags that ride the handshake `capabilities` array
/// beyond the method-name list (contract revision 1.34): `send-receipts`
/// marks the outbound receipt face — `messages.markRead` /
/// `messages.markViewed` plus the auto delivery receipt — as present, and
/// `send-sticker` (contract revision 1.35) marks `messages.sendSticker` plus
/// the sticker receive projection as present. `sticker-pack-browse` and
/// `conversation-pin-sync` (contract revision 1.36) mark the two browse/sync
/// faces of §4.32/§4.33, `sticker-pack-sync` (contract revision 1.37)
/// marks the §4.34 account-scoped pack install face, `view-once`
/// (contract revision 1.38) marks the §4.36/§4.37 view-once send, open-sync
/// and burn faces, `history-import` (contract revision 1.39) marks the
/// §4.38 link-time import status face — widened in place by revision 1.53
/// (the `running` `progress` object plus the `history.importRetry` manual
/// retry face; no new capability bit, so a 1.39-aware desktop keeps gating
/// on the same tag) and by revision 1.57 (the `history.attachmentDownload`
/// transit byte chain; the same no-new-bit discipline) and by revision 1.78
/// (the `backups.importSnapshot` / `backups.importSnapshotStatus`
/// official-desktop snapshot import faces — the face's entire output is the
/// history-import archive and ledger) and by revision 1.83 (the
/// `backups.restoreFromCloud` / `backups.cloudStatus` cloud-backup restore
/// passthrough — the restore's entire output is again the history-import
/// NDJSON chain) —
/// `disappearing-messages`
/// (contract revision 1.42) marks the §4.41 receive metadata, timer-notice
/// and bounded-sweep faces plus `conversations.setExpireTimer`, and
/// `group-management` (contract revision 1.45) marks the §4.44 group write
/// face (`groups.update` / `groups.quit` / the group route of
/// `conversations.setExpireTimer`) — desktops gate the new surface on this
/// tag so an old connector answers a clean capability gap instead of
/// `METHOD_NOT_ALLOWED`. `account-settings` and `blocked-conversations`
/// (contract revision 1.46) mark the §4.45 account-record write faces and
/// the blocked-list read face, and `backup-export` (contract revision 1.47)
/// marks the §4.46 Android local-backup export face (`backups.export`,
/// `backups.exportStatus`, the `backups.exportFile` three-chain), widened in
/// place by revision 1.87 (the §4.72 cloud-backup upload faces
/// `backups.uploadToCloud` / `backups.uploadStatus` — the upload's entire
/// input is the backup-export artifact chain; the 1.82 call-signaling
/// no-new-bit discipline) and by revision 1.132 (the §4.115 plaintext chat
/// export face `backups.exportPlaintext` plus the `exportStatus` additive
/// `kind` field and the `exportFile.open` third `file` value — the
/// connector-local store projection; the same no-new-bit discipline);
/// `avatar-fetch` / `blocked-write` (contract revision 1.48) mark the §4.47
/// avatar download and blocked-bit write faces; `report-spam` (contract
/// revision 1.49) marks the §4.48 report face (`messages.reportSpam` plus
/// the row-level serverGuid persistence); `call-signaling` (contract
/// revision 1.51, widened in place by 1.82, by 1.88, by 1.127, by
/// 1.145, by 1.151, and by 1.155) marks
/// the §4.49
/// call signaling faces (`calls.sendSignal` — the 1:1 and, since 1.82, the
/// group-addressed route — plus the `call.incoming` and `call.groupIncoming`
/// events) and, since 1.88, the §4.73 call-link credential material faces
/// (`calls.linkPresentation` / `calls.createLinkAuth` / `calls.groupProof` /
/// `calls.groupMembers` / `calls.endorsementsPublicKey` — the signaling
/// pipeline's own material supply) and, since 1.127, the §4.108 group-call
/// update write (`calls.sendGroupCallUpdate` — the same pipe's group-era
/// face; the same no-new-bit discipline) and, since 1.145, the §4.143
/// call-relay configuration proxy (`calls.relays` — the desktop calling
/// chain's ICE/TURN connection material, the engine's own cache and
/// freshness story proxied untouched) and, since 1.151, the §4.150
/// call-event self-sync proxy (`calls.sendCallEvent` — the call chain's
/// own cross-device history face, the engine's SyncMessage.callEvent=19
/// self-send with the full parameter gate proxied verbatim) and, since
/// 1.155, the §4.85 raw identity leg (the `call.historyEvent` record's
/// optional `peerId` — the projection's raw conversation identity riding
/// verbatim, the desktop's ad-hoc ledger join key, `call.logEvent`'s
/// wire-additive twin);
/// `group-terminate` (contract revision 1.52) marks the §4.50 termination face
/// (`groups.terminate`); `group-join-approve` (contract revision 1.58) marks
/// the §4.53 join-request approval face (`groups.approveJoinRequests`);
/// `attachment-download` (contract revision 1.61) marks the §4.54 live
/// attachment download face (`attachments.download`); `message-adjacent-media`
/// (contract revision 1.93) marks the §4.76 adjacent visual-media probe
/// (`messages.adjacentMedia` — the store-only read behind the desktop
/// lightbox's cross-message navigation); `username` (contract
/// revision 1.59) marks the §4.55 username faces (`accounts.setUsername`,
/// `accounts.getUsername`, `username.lookup`); `message-requests`
/// (contract revision 1.63) marks the §4.56 message-request response faces
/// (`conversations.acceptRequest` / `conversations.declineRequest` over the
/// pinned upstream's native `sendMessageRequestResponse` sync face);
/// `group-invite-revoke` (contract revision 1.64) marks the §4.57
/// group-invites face (`groups.get` `pendingMembers` read half +
/// `groups.revokeInvites` write half) — one capability for one protocol
/// action's read and write halves, the 1.53-appendix discipline the 1.62
/// read face recorded; and `safety-number` (contract revision 1.68) marks
/// the §4.61 safety-number faces (`identities.get` read over the pinned
/// upstream's native `listIdentities` projection plus the `identities.verify`
/// write over its native `trust` verifiedSafetyNumber form — one capability,
/// read and write halves together, the 1.53 appendix discipline); and
/// `stories` (contract revision 1.76) marks the §4.67 stories faces
/// (`messages.sendStory` over the kt-engine `sendStory` face plus the
/// `stories.setDisabled` / `stories.getDisabled` local toggle — the receive
/// gate mirror of the official `getStoriesBlocked` leg — and the transient
/// `story.received` event), widened in place by revision 1.85 (the
/// `stories.markViewed` story-anchored viewed receipt — the send leg of the
/// story viewed-receipt chain — plus the transient `story.viewed` event;
/// the 1.82 call-signaling no-new-bit discipline) and by revision 1.86 (the
/// `stories.downloadAttachment` / `stories.openAttachment` story-anchored
/// attachment byte faces — the caller-supplied pointer channel with its
/// fail-closed shape gate, plus the handle mint over the landed file; the
/// same no-new-bit discipline) and by revision 1.94 (the
/// `stories.sendReaction` story-anchored reaction send plus the `viewedAt`
/// projection key on message rows and `message.statusChanged`; the same
/// no-new-bit discipline) and by revision 1.152 (the §4.151 conversion of
/// `stories.sendReaction` to the engine passthrough — the §4.150 proxy
/// posture on the stories family, the §4.77 constant-reject arm retired;
/// the same no-new-bit discipline) and by revision 1.153 (the §4.152
/// `stories.deleteForEveryone` story delete fan-out — the §4.150 proxy
/// posture registering the engine's `deleteStoryForEveryone`, the
/// per-recipient DOE legs plus the exactly-once self-sync; the same
/// no-new-bit discipline) and by revision 1.154 (the §4.153 transient
/// story-receive faces — the `story.reaction` / `story.deleted` /
/// `story.recipientUpdate` events over the engine's story S4/S5 batch
/// projections, the story.received transient discipline: no rows, no
/// self-heal, the stories-disabled gate on incoming story material only;
/// the same no-new-bit discipline) and by revision 1.157 (the §4.155 group
/// audience leg on the `messages.sendStory` face — the engine's group
/// story batch (engine `ffab2a8`), the official `StoryMessage.group`
/// GroupContextV2 alignment: the engine groupId riding the frame verbatim
/// as a raw value, the recipients empty batch riding only with the group
/// leg (the engine's audience-at-least-one-domain gate mirrored) and
/// keeping its refusal without it, and the additive
/// `group:{groupId,timestamp}` answer face passing the projection through;
/// the same no-new-bit discipline) and by revision 1.158 (the §4.156
/// group story receive 翻案 — the reaction + storyReply co-presence
/// routing the story face on the group leg exactly as on the 1:1 leg
/// (the official group-channel wire's always-present storyContext), the
/// conservative isStory-carrying group DOE leg, the new transient
/// `story.deleteCandidate` candidacy event over the group-DOE true buffer
/// miss, and the stories-disabled gate realigned onto the reaction (the
/// official stories-blocked whole-envelope drop); the same no-new-bit
/// discipline) and by revision 1.161 (the §4.159 media-story pointer
/// answer faces on the `messages.sendStory` face — the engine's
/// sendStory pointer batch (engine `941c091`), the official sender-holds-
/// the-upload-pointer fact face: the engine answer's `fileAttachment`
/// (the roster leg) and `group.fileAttachment` (the group leg, the mixed
/// audience's two independent uploads being distinct objects) pass the
/// projection through as raw values, untyped and unshaped — the pointer
/// face is the engine projection's product and stays opaque transit for
/// the desktop's own read-back chain (zero CDN resolution, zero pointer
/// consumption); absent stays absent, every pre-1.161 answer reads
/// byte-identically; the same no-new-bit discipline) and by revision 1.185
/// (the §4.185 media-story caption leg on the `messages.sendStory` face —
/// the engine's sendStory caption batch (engine `48e69a2`), the official
/// `AttachmentPointer.caption=11` alignment: the optional host `caption`
/// key riding the engine frame verbatim on the 1.156 attachment transit
/// class — no connector leg gate, no byte gate, the engine's documented
/// parse owning the whole value domain (empty, over the official 64 KiB
/// MAX_BODY_ATTACHMENT_BYTE_LENGTH budget, or riding without the attachment
/// leg answer its plain -32603); absence never becomes a key, every
/// pre-1.185 frame reads byte-identically; the same no-new-bit
/// discipline) and by revision
/// 1.160 (the §4.158 own-story sync
/// transcript — the engine's `syncMessage.sentMessage.storyMessage`
/// projection riding home as the outgoing row face the desktop's
/// message-upserted story intercept consumes (isStory + storyMessage,
/// direction outgoing), zero rows and zero store writes (the §4.67 story
/// posture), the stories-disabled gate on the official pre-split
/// `getStoriesBlocked` leg, and the bounded story face forwarding
/// verbatim; the same no-new-bit discipline) and by revision 1.159 (the §4.157 group leg on the
/// `stories.sendReaction` face — the engine's group story-reaction batch
/// (engine `a6c0520`), the official ordinary-group-channel alignment: the
/// optional host `group` key riding onto the engine frame's `groupId` key
/// verbatim as a raw value (the engine's fail-closed parse owning the
/// whole value domain), the `remove:true` local refusal keeping its face
/// ahead of the group key on both legs, and the additive
/// `group:{groupId,timestamp}` answer passing through untouched; the same
/// no-new-bit discipline) and by revision 1.156 (the §4.154
/// story-reply and media-story send legs on the existing send faces — the
/// `messages.sendText` storyReply context keys riding the send frame
/// verbatim, the engine's storyContext parse owning the pair discipline and
/// the value domain, plus the `messages.sendStory` `attachment` media-story
/// leg (engine 7e3652e), the data URI verbatim transit with the upload and
/// cap gates its own; wire-additive optional keys, the same no-new-bit
/// discipline) and by revision 1.130 (the
/// `storyDistributionLists.list` / `storyDistributionLists.setRecords`
/// story-audience sync faces — the §4.78 sync-face pair over the story
/// distribution lists the §4.67 send faces address; the same no-new-bit
/// discipline), and `chat-folders` (contract revision 1.95)
/// marks the §4.78 chat-folder sync faces (`chatFolders.list` read over the
/// account's ChatFolderRecord set plus the `chatFolders.setRecords`
/// storage-service write — one capability for the read and write halves,
/// the 1.36/1.37 sync-face discipline); and `notification-profiles`
/// (contract revision 1.129) marks the §4.110 notification-profile sync
/// faces (`notificationProfiles.list` read over the account's
/// NotificationProfile set plus the `notificationProfiles.setRecords`
/// storage-service write — one capability for the read and write halves,
/// the 1.53 appendix discipline); and `storage-sync` (contract revision
/// 1.131) marks the §4.112 storage merge/import/call-link faces
/// (`storage.mergeContacts` / `storage.importGroups` engine-local ingest
/// reads plus `storage.getCallLinks` cloud read and `storage.setCallLink`
/// write — one capability for the whole storage-sync family, the 1.53
/// appendix discipline); and `conversation-state` (contract
/// revision 1.116) marks the §4.97 conversation-state faces
/// (`conversations.getState` read over the storage records'
/// mutedUntilTimestamp/archived/markedUnread bits plus `conversations.setState`
/// partial write — one capability for the read and write halves, the 1.53
/// appendix discipline); and `group-invite-links` (contract revision 1.117)
/// marks the §4.98 group invite-link faces (`groups.generateInviteLinkPassword`
/// / `groups.buildInviteLink` / `groups.parseInviteLink` material-and-parse
/// reads plus `groups.previewViaLink` preview read and the
/// `groups.joinViaLink` / `groups.cancelJoinRequest` join-family writes — one
/// capability for the whole link life cycle, the 1.53 appendix discipline),
/// widened in place by revision 1.123 (the `groups.migrate` GV1→GV2
/// migration write) and again by revision 1.126 (the `groups.create`
/// new-group write — the create is the group life cycle's own first face;
/// the same no-new-bit discipline); and `device-management` (contract revision
/// 1.122) marks the §4.103
/// device-plane faces (`accounts.getDevices` — the bounded device-list read
/// with engine-side device-name decryption — plus the `accounts.unlinkDevice`
/// server-side unlink write; one capability for the read and write halves,
/// the 1.53 appendix discipline); and `send-contact` (contract revision
/// 1.124) marks the §4.105 contact-card send face (`messages.sendContact` —
/// the official DataMessage.contact single-entry face, the conversation
/// row's kind deciding the 1:1 / group leg); and `polls` (contract revision
/// 1.125) marks the §4.106 poll send faces (`messages.sendPollCreate` /
/// `messages.sendPollVote` / `messages.sendPollTerminate` — the official
/// PollCreateSchema/PollVoteSchema content gate, group-conversation legs
/// exclusively); and `phone-lookup` (contract revision 1.164) marks the
/// §4.162 phone-number lookup face (`phone.lookup` — the engine's
/// `phoneLookup` CDSI batch reader, engine d088a59, the desktop D-batch
/// find-by-phone-number supply; the desktop gates its entry on the tag, so
/// an older connector keeps the entry rendered away, never a
/// `METHOD_NOT_ALLOWED` surprise). They never
/// join [`METHOD_NAMES`]: the schema request-frame method enum and the
/// dispatch table describe real methods only — desktops gate a new surface on
/// its tag so an old connector answers a clean capability gap instead of
/// `METHOD_NOT_ALLOWED`.
/// `METHOD_NOT_ALLOWED`.
///
/// Contract revision 1.98: `attachment-download` is the one tag whose
/// advertisement is conditional — [`crate::advertised_capabilities`] filters
/// it out unless the runtime's media ingest is armed, because the media
/// faces behind it answer `CAPABILITY_UNAVAILABLE` for every call otherwise.
/// Since contract 1.121 (§4.102) the effective decision is the launcher's
/// own: the registry passes `--media-ingest` through verbatim, so the flag
/// alone is the whole truth and the handshake advertises exactly the faces
/// the runtime can serve. The constant stays in this table so the tag
/// inherits the table-order advertisement when the gate is open.
pub const FEATURE_CAPABILITIES: &[&str] = &[
    "send-receipts",
    "send-sticker",
    "sticker-pack-browse",
    "conversation-pin-sync",
    "sticker-pack-sync",
    "view-once",
    "history-import",
    "disappearing-messages",
    "group-management",
    "account-settings",
    "blocked-conversations",
    "backup-export",
    "avatar-fetch",
    "blocked-write",
    "report-spam",
    "call-signaling",
    "group-terminate",
    "group-join-approve",
    "group-invite-revoke",
    ATTACHMENT_DOWNLOAD_CAPABILITY,
    "message-adjacent-media",
    "username",
    "message-requests",
    "safety-number",
    "stories",
    "chat-folders",
    "notification-profiles",
    "conversation-state",
    "group-invite-links",
    "device-management",
    "send-contact",
    "polls",
    "delete-for-me",
    "storage-sync",
    "phone-lookup",
    "attachment-dimensions",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatch contract the table must keep serving (`host.rs`
    /// `acquire`): the exact read-lane and account-scoped mutating sets, and
    /// the control fallback for unknown methods.
    #[test]
    fn lane_and_mutating_sets_match_the_dispatch_contract() {
        let read_lane = [
            "conversations.list",
            "conversations.getBlocked",
            "conversations.getAvatar",
            "messages.list",
            "messages.listAttachmentDimensions",
            "messages.adjacentMedia",
            "messages.getText",
            "messages.receipts",
            "messages.getByClientRequestId",
            "messages.search",
            "messages.attachments.open",
            "messages.attachments.readChunk",
            "messages.attachments.closeHandle",
            "contacts.sync",
            "contacts.list",
            "groups.get",
            "groups.common",
            "accounts.deviceCapabilities",
            "accounts.getDevices",
            "accounts.getSyncState",
            "stickerPacks.getManifest",
            "stickerPacks.getImage",
            "conversations.getPinned",
            "stickerPacks.getSyncs",
            "conversations.getState",
            "history.importStatus",
            "backups.exportStatus",
            "backups.exportFile.open",
            "backups.exportFile.readChunk",
            "backups.exportFile.closeHandle",
            "backups.importSnapshotStatus",
            "backups.cloudStatus",
            "backups.uploadStatus",
            "calls.getState",
            "accounts.getUsername",
            "username.lookup",
            "phone.lookup",
            "identities.get",
            "events.list",
            "stories.getDisabled",
            "stories.openAttachment",
            "calls.linkPresentation",
            "calls.createLinkAuth",
            "calls.groupProof",
            "calls.groupMembers",
            "calls.endorsementsPublicKey",
            "calls.relays",
            "chatFolders.list",
            "notificationProfiles.list",
            "storyDistributionLists.list",
            "storage.mergeContacts",
            "storage.importGroups",
            "storage.getCallLinks",
            "groups.generateInviteLinkPassword",
            "groups.buildInviteLink",
            "groups.parseInviteLink",
            "groups.previewViaLink",
        ];
        let send_lane = [
            "messages.sendText",
            "accounts.setExpireTimer",
            "accounts.setProfile",
            "accounts.updateConfiguration",
            "accounts.unlinkDevice",
            "messages.retryText",
            "messages.attachments.send",
            "messages.attachments.retry",
            "messages.sendSticker",
            "messages.sendContact",
            "messages.sendPollCreate",
            "messages.sendPollVote",
            "messages.sendPollTerminate",
            "messages.edit",
            "messages.remoteDelete",
            "messages.sendReaction",
            "messages.sendPinMessage",
            "messages.sendUnpinMessage",
            "messages.sendAdminDelete",
            "messages.markRead",
            "messages.markViewed",
            "messages.syncRead",
            "messages.syncViewed",
            "messages.sendViewOnceOpen",
            "messages.markViewOnceOpened",
            "contacts.setLocalAlias",
            "presence.setTypingMessage",
            "conversations.setPinned",
            "conversations.setBlocked",
            "conversations.saveDraft",
            "conversations.clearDraft",
            "conversations.setState",
            "conversations.setExpireTimer",
            "groups.update",
            "groups.quit",
            "groups.terminate",
            "groups.approveJoinRequests",
            "groups.revokeInvites",
            "groups.joinViaLink",
            "groups.cancelJoinRequest",
            "groups.migrate",
            "groups.create",
            "messages.reportSpam",
            "stickerPacks.setSync",
            "backups.export",
            "backups.exportPlaintext",
            "backups.importSnapshot",
            "backups.restoreFromCloud",
            "backups.uploadToCloud",
            "history.importRetry",
            "history.importCancel",
            "history.attachmentDownload",
            "attachments.download",
            "calls.sendSignal",
            "calls.sendGroupCallUpdate",
            "calls.sendCallEvent",
            "accounts.setUsername",
            "conversations.acceptRequest",
            "conversations.declineRequest",
            "conversations.reportSpam",
            "identities.verify",
            "messages.sendStory",
            "stories.setDisabled",
            "stories.markViewed",
            "stories.sendReaction",
            "stories.deleteForEveryone",
            "stories.downloadAttachment",
            "chatFolders.setRecords",
            "notificationProfiles.setRecords",
            "storyDistributionLists.setRecords",
            "storage.setCallLink",
            "messages.deleteForMe",
            "messages.deleteForMeMessages",
            "messages.setAttachmentDimensions",
        ];
        let mutating = [
            "messages.sendText",
            "accounts.setExpireTimer",
            "accounts.setProfile",
            "accounts.updateConfiguration",
            "messages.retryText",
            "messages.attachments.send",
            "messages.attachments.retry",
            "messages.sendSticker",
            "messages.sendContact",
            "messages.sendPollCreate",
            "messages.sendPollVote",
            "messages.sendPollTerminate",
            "messages.edit",
            "messages.remoteDelete",
            "messages.sendReaction",
            "messages.sendPinMessage",
            "messages.sendUnpinMessage",
            "messages.sendAdminDelete",
            "messages.markRead",
            "messages.markViewed",
            "messages.syncRead",
            "messages.syncViewed",
            "messages.sendViewOnceOpen",
            "messages.markViewOnceOpened",
            "contacts.sync",
            "accounts.deviceCapabilities",
            "accounts.unlinkDevice",
            "storage.mergeContacts",
            "storage.importGroups",
            "contacts.setLocalAlias",
            "presence.setTypingMessage",
            "accounts.deleteLocalData",
            "conversations.setPinned",
            "conversations.setBlocked",
            "conversations.saveDraft",
            "conversations.clearDraft",
            "conversations.setState",
            "conversations.setExpireTimer",
            "groups.update",
            "groups.quit",
            "groups.terminate",
            "groups.approveJoinRequests",
            "groups.revokeInvites",
            "groups.joinViaLink",
            "groups.cancelJoinRequest",
            "groups.migrate",
            "groups.create",
            "messages.reportSpam",
            "stickerPacks.setSync",
            "backups.export",
            "backups.exportPlaintext",
            "backups.importSnapshot",
            "backups.restoreFromCloud",
            "backups.uploadToCloud",
            "history.importRetry",
            "history.importCancel",
            "history.attachmentDownload",
            "attachments.download",
            "calls.sendSignal",
            "calls.sendGroupCallUpdate",
            "calls.sendCallEvent",
            "accounts.setUsername",
            "conversations.acceptRequest",
            "conversations.declineRequest",
            "conversations.reportSpam",
            "identities.verify",
            "messages.sendStory",
            "stories.setDisabled",
            "stories.markViewed",
            "stories.sendReaction",
            "stories.deleteForEveryone",
            "stories.downloadAttachment",
            "chatFolders.setRecords",
            "notificationProfiles.setRecords",
            "storyDistributionLists.setRecords",
            "storage.setCallLink",
            "messages.deleteForMe",
            "messages.deleteForMeMessages",
            "messages.setAttachmentDimensions",
        ];
        for (name, row_lane, row_mutating, _) in METHODS {
            let expected_lane = if read_lane.contains(name) {
                Lane::Read
            } else if send_lane.contains(name) {
                Lane::Send
            } else {
                Lane::Control
            };
            assert_eq!(*row_lane, expected_lane, "lane for {name}");
            assert_eq!(
                *row_mutating,
                mutating.contains(name),
                "mutating classification for {name}"
            );
        }
        assert_eq!(lane("anything.else"), Lane::Control);
        assert!(!is_account_scoped_mutating("anything.else"));
    }

    /// Cross-table consistency: the capability list, the metrics labels, and
    /// the classification rows cannot drift apart.
    #[test]
    fn capabilities_and_metrics_labels_derive_from_the_table() {
        // The advertised method list is exactly the table; the handshake
        // payload appends the feature tags after it (contract revision 1.34:
        // `send-receipts`). An armed runtime advertises the full table.
        assert_eq!(crate::PHASE2_CAPABILITIES, METHOD_NAMES.as_slice());
        assert_eq!(
            crate::advertised_capabilities(true)[..METHOD_NAMES.len()],
            METHOD_NAMES[..]
        );
        assert_eq!(
            &crate::advertised_capabilities(true)[METHOD_NAMES.len()..],
            FEATURE_CAPABILITIES
        );
        let names: Vec<_> = METHODS.iter().map(|row| row.0).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(names.len(), unique.len(), "duplicate method row");
        for (_, _, _, class) in METHODS {
            assert!(
                crate::metrics::METHOD_CLASSES.contains(class),
                "metrics class {class} is not a known series"
            );
        }
        assert_eq!(metrics_class("anything.else"), "unknown");
    }

    /// Contract revision 1.98: the `attachment-download` tag is the one
    /// advertisement the runtime state gates. Without the armed media table
    /// the tag is absent — every other feature tag keeps its table position —
    /// and with it armed the payload is the full pre-1.98 advertisement.
    #[test]
    fn attachment_download_capability_tracks_the_media_ingest_gate() {
        let unarmed = crate::advertised_capabilities(false);
        assert!(
            !unarmed.contains(&ATTACHMENT_DOWNLOAD_CAPABILITY),
            "an unarmed runtime must not advertise attachment-download: {unarmed:?}"
        );
        let armed = crate::advertised_capabilities(true);
        assert!(
            armed.contains(&ATTACHMENT_DOWNLOAD_CAPABILITY),
            "an armed runtime advertises attachment-download: {armed:?}"
        );
        // The gate only removes the one tag; the rest of the table — method
        // names first, then the remaining feature tags in table order — is
        // byte-identical between the two payloads.
        let without_tag: Vec<_> = armed
            .iter()
            .copied()
            .filter(|capability| *capability != ATTACHMENT_DOWNLOAD_CAPABILITY)
            .collect();
        assert_eq!(unarmed, without_tag);
    }
}
