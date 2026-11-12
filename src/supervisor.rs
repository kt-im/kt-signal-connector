// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep};

use crate::engine::{
    CallClass, EngineConfig, EngineError, EngineEvent, EngineHandle, EngineState, EngineStatus,
    NormalizedReceive, QueuedReceive, ReceiveIngress, WATCHDOG_LIVENESS_BACKOFF_CAP, event_channel,
    receive_channel,
};
use crate::event_publisher::EventPublisher;
use crate::groups::MAX_ACCOUNTS_PER_ENGINE;
use crate::link::now_ms;
use crate::media::{MediaGovernor, MediaHandleTable};
use crate::protocol::ApiError;
use crate::service::{
    AccountDeviceCapabilities, AccountUsername, AccountsDeviceCapabilitiesParams,
    AccountsGetDevicesParams, AccountsGetUsernameParams, AccountsSetExpireTimerParams,
    AccountsSetProfileParams, AccountsSetUsernameParams, AccountsUnlinkDeviceParams,
    AccountsUpdateConfigurationParams, AttachmentSendTarget, AvatarDownload, BlockedConversations,
    CallLinkSyncs, CallsSendGroupCallUpdateParams, CallsSendSignalParams, ChatFolderSyncs,
    ChatFoldersListParams, ChatFoldersSetRecordsParams, CommonGroupsDetails, ConnectorService,
    ContactsSyncOutcome, ConversationState, ConversationsGetAvatarParams,
    ConversationsGetBlockedParams, ConversationsGetPinnedParams, ConversationsGetStateParams,
    ConversationsReportSpamParams, ConversationsReportSpamResult, ConversationsSetBlockedParams,
    ConversationsSetExpireTimerParams, ConversationsSetExpireTimerResult,
    ConversationsSetPinnedParams, ConversationsSetStateParams, DeviceList,
    GROUP_MEMBER_LABEL_EMOJI_MAX_BYTES, GROUP_MEMBER_LABEL_SERVER_MAX_BYTES, GroupDetails,
    GroupInviteLink, GroupInviteLinkParse, GroupInviteLinkPassword, GroupInviteLinkPreview,
    GroupsApproveJoinRequestsParams, GroupsBuildInviteLinkParams, GroupsCancelJoinRequestParams,
    GroupsCreateParams, GroupsCreateResult, GroupsInviteLinkPasswordParams,
    GroupsJoinViaLinkParams, GroupsMigrateParams, GroupsMigrateResult, GroupsParseInviteLinkParams,
    GroupsPreviewViaLinkParams, GroupsQuitParams, GroupsRevokeInvitesParams, GroupsTerminateParams,
    GroupsUpdateParams, HistoryAttachmentDownloadView, HostSideEvent, IdentitiesGetParams,
    IdentitiesVerifyParams, IdentityRead, IdentityVerifyOutcome, ImportGroupsSummary,
    MAX_AVATAR_DATA_URI_CHARS, MAX_GROUP_MEMBER_ID_CHARS, MAX_GROUP_MEMBERS, MAX_STORY_RECIPIENTS,
    MediaChunkView, MediaCloseView, MediaIngest, MediaOpenView, MergeContactsSummary,
    MessageRequestOutcome, MessageRequestParams, MessagesDeleteForMeMessagesParams,
    MessagesDeleteForMeParams, MessagesReportSpamParams, MessagesSendContactParams,
    MessagesSendPollCreateParams, MessagesSendPollTerminateParams, MessagesSendPollVoteParams,
    MessagesSendStickerParams, MessagesSendStoryParams, NotificationProfileSyncs,
    NotificationProfilesListParams, NotificationProfilesSetRecordsParams, PeerTarget,
    PhoneLookupEntry, PhoneLookupParams, PhoneLookupResult, PinnedConversations,
    PreparedHistoryDownload, PreparedSend, ReportSpamFailure, ReportSpamResult, SendTarget,
    SendTextMentionParams, SendTextPreviewParams, SendTextStyleParams, ServiceError,
    StickerManifestEntry, StickerPackGetSyncsParams, StickerPackImage, StickerPackImageParams,
    StickerPackManifest, StickerPackManifestParams, StickerPackSetSyncParams, StickerPackSyncs,
    StorageGetCallLinksParams, StorageIngestParams, StorageSetCallLinkParams, StoriesDisabled,
    StoriesGetDisabledParams, StoriesMarkViewedParams, StoriesSendReactionParams,
    StoriesSetDisabledParams, StoryDistributionListSyncs, StoryDistributionListsListParams,
    StoryDistributionListsSetRecordsParams, StorySendGroupFace, StorySendRecipientResult,
    StorySendResult, StorySendSuccess, UsernameLookupEntry, UsernameLookupParams,
    UsernameLookupResult, account_device_capabilities_from_engine, account_limit_error,
    blocked_conversations_result, call_link_syncs_result, chat_folder_syncs_result,
    conversation_state_from_engine, device_list_from_engine, group_create_result_from_engine,
    group_invite_join_status_from_engine, group_invite_link_parse_from_engine,
    group_invite_link_password_from_engine, group_invite_link_preview_from_engine,
    group_migrate_result_from_engine, identities_addressing, identities_verify_intent,
    identity_from_engine, identity_verify_stamp_word, import_groups_summary_from_engine,
    merge_contacts_summary_from_engine, notification_profile_syncs_result,
    pinned_conversations_result, sticker_pack_syncs_result, store_adjacent_media,
    store_get_group_with_requesting, store_get_message_text, store_list_contacts,
    store_list_conversations, store_list_messages, store_search_messages,
    story_distribution_lists_result, validate_account_delete_operation_id,
};
use crate::store::{
    AccountDeletePlan, AccountSummary, ContactSummary, ConversationSummary, EXPIRE_SWEEP_BATCH,
    MessageRecord, Page, Store, StoreError, SyncedContact,
};

/// Phone-approval wait for `finishLink`. Pinned above both deadlines it must
/// never pre-empt: the engine's own finish dispatch budget (360 s) and the
/// desktop's link wait (330 s). A connector that answered first would turn a
/// link the engine may still commit into a client-side failure — and re-running
/// `finishLink` claims a second device slot. When this budget does expire the
/// answer is therefore the link-class unknown outcome (the desktop's adopt
/// path), never a retryable `UPSTREAM_TIMEOUT`.
const LINK_FINISH_TIMEOUT: Duration = Duration::from_secs(370);
const RECEIVE_STORE_RETRY_MIN: Duration = Duration::from_millis(100);
const RECEIVE_STORE_RETRY_MAX: Duration = Duration::from_secs(5);
const WATCHDOG_PING_TIMEOUT: Duration = Duration::from_secs(15);
/// Consecutive receive-liveness ping failures that escalate to a real restart.
/// One timeout is noise (a slow tick can starve a read-only call); two in a
/// row mean the receive path is not answering and throttling must not turn
/// that into "wait for the next window forever".
const WATCHDOG_MAX_PING_FAILURES: u32 = 2;
/// Budget for the per-tick engine account cross-check (`listAccounts`): only
/// an account the engine itself lists may serve as a liveness probe. A short
/// budget keeps the tick responsive; when it expires the tick falls back to
/// the connector-known candidates, so a slow engine never silently disables
/// liveness (that would weaken the restart boundary, not tighten it).
const WATCHDOG_ACCOUNT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
/// Candidate accounts one tick probes before giving up. A legal group holds at
/// most `MAX_ACCOUNTS_PER_ENGINE`, so this only bounds a pathological store.
/// Continuing past a refusal is only ever justified by the engine's *fast*
/// plain upstream error (an unknown account answers -32603 in milliseconds);
/// a timeout or any engine-level variant stops the series. Whatever the cap
/// leaves unprobed is reached on a later tick, because the refused prefix is
/// excluded as it is walked.
const WATCHDOG_PING_ATTEMPT_LIMIT: usize = MAX_ACCOUNTS_PER_ENGINE;
/// How long a `getUserStatus` refusal keeps an account out of the liveness
/// candidate set. The exclusion stops a per-tick -32603 series, but it must
/// not blind liveness for the engine's whole lifetime: after this window the
/// account is probed again, and a refusal that was actually transient heals
/// without an engine restart.
const WATCHDOG_PING_REFUSAL_TTL: Duration = Duration::from_secs(10 * 60);
/// Rows one retention transaction may delete, keeping each one short.
const RETENTION_BATCH_MESSAGES: u32 = 2_000;
/// Breathing room between retention batches so receives and host requests get
/// the store lock while a large history is being pruned.
const RETENTION_BATCH_PAUSE: Duration = Duration::from_millis(50);
/// Settle time before a group's first expire sweep after start (§4.41): the
/// handshake must not share its few-second budget with a store pass.
const EXPIRE_SWEEP_STARTUP_SETTLE: Duration = Duration::from_secs(5);
/// Capacity of the auto delivery-receipt queue (contract revision 1.34):
/// bounded, lossy by design — a full queue drops the job, never the receive.
const DELIVERY_RECEIPT_QUEUE_CAP: usize = 512;
/// §4.244 verified 探针窗帽（Z25 根因批）：单引用 listIdentities 读每窗
/// 最多行数——hidden 回写纯面帽 16 同款纪律，余行留下一窗（60s 节流），
/// 有界自熄。
const VERIFIED_PROBE_WINDOW_CAP: usize = 16;

/// Batch X · S6①: the stale-avatar refetch queue cap. Profile-change and
/// group-avatar-change events are rare by protocol construction (the engine's
/// profile-key idempotence gate and the group change batches bound them); the
/// cap absorbs a storm without unbounded growth, and a full queue drops the
/// refetch kick lossily (the desktop's own on-demand pull is the convergence
/// backstop).
const AVATAR_REFRESH_QUEUE_CAP: usize = 32;
/// 契约 1.270（§4.254 · 批 Z14）：单轮头像 backfill 的目标帽——contacts
/// sync 落库后一轮扫描最多入队的缓存缺席 direct 行数。有界纪律沿用
/// avatar-refresh 队列（lossy try_send，满即弃；对端无头像的负答由
/// UNAVAILABLE 幂等清位承载，下一轮 sync 前不重复触发）。
const AVATAR_BACKFILL_CAP: usize = 24;

/// §4.163 contacts.sync wall-clock budget: the whole face — engine resolve,
/// the two read-only listings, and the store upsert transaction — must answer
/// inside it or the request folds to the retryable timeout face. Without a
/// budget the desktop's "正在同步联系人与群组" empty state could hang forever
/// on a wedged leg (a starved service lock, a store stall); the cache
/// short-circuit above it stays budget-free (local store only).
const CONTACTS_SYNC_BUDGET: Duration = Duration::from_secs(120);

/// Batch I background sync: capacity of the engine-completion kick queue.
/// Bounded and lossy by design (AGENTS.md bounded-queue rule) — a full queue
/// drops the kick, never blocks the engine-event watcher. The 60 s marker
/// inside the sync folds duplicate kicks, and the desktop gate remains the
/// fallback when a kick is dropped.
const BACKGROUND_SYNC_QUEUE_CAP: usize = 8;

/// Batch I background sync: one silent retry after a failed pass. A short
/// settle keeps a wedged engine from being hammered; after the retry the next
/// completion event (or the desktop gate) converges.
const BACKGROUND_SYNC_RETRY_DELAY: Duration = Duration::from_secs(2);

/// §4.123 outbox drain cadence: the periodic sweep runs at most this often
/// per group. The cadence is deliberately slow — the queue's own schedule
/// (190 ms exponential → 15-minute cap) is what paces retries; the tick only
/// bounds how late a due row can be noticed when every other wake source is
/// lost (a dropped drain notification, a clock anomaly). A pass that sees
/// due-later rows sleeps until the earliest due instant instead of the full
/// tick, so a fresh 190 ms schedule drains within the same second-series the
/// official queue would have used, not 15 s later.
const OUTBOX_TICK: Duration = Duration::from_secs(15);
/// Floor on the due-time wake: a just-scheduled row is never re-scanned
/// sooner than this, so a pass that schedules +190 ms cannot busy-loop.
const OUTBOX_DUE_WAKE_MIN: Duration = Duration::from_millis(50);
/// Hard claim batch per drain pass (AGENTS.md bounded-queue rule): at most
/// this many rows leave the queue per pass per group, so one drain can never
/// monopolize the store lock or the engine's send queue.
const OUTBOX_CLAIM_BATCH: u32 = 16;

/// §4.179 unknown-outcome reconciliation: settle beat before the first probe
/// round — the fresh engine's own startup work (and the link-time inline
/// sync) lands first, same discipline as the contacts-resync settle delay.
const UNKNOWN_RECONCILE_SETTLE_DELAY: Duration = Duration::from_secs(2);
/// §4.179 unknown-outcome reconciliation: rows per probe round. A full batch
/// loops straight into the next (the query is drained oldest-first and the
/// settles are guarded), so this bounds the per-round engine probe series,
/// not the backlog (the batch ceiling below bounds the pass).
const UNKNOWN_RECONCILE_BATCH: u32 = 64;
/// §4.179 unknown-outcome reconciliation: hard pass ceiling in batches
/// (4096 rows — a backlog beyond this is a runaway somewhere else; the pass
/// exits warn-only and the next engine landing continues).
const UNKNOWN_RECONCILE_MAX_BATCHES: u32 = 64;
/// §4.179 unknown-outcome reconciliation: the engine lookup tolerance, pinned
/// to the engine face's hard cap (`lookupOutgoingDispatch` 1..=60000). Recall
/// over precision: the unknown row's sent_at is the PREPARE-time stamp while
/// the engine row's ts is the dispatch envelope timestamp (per-account
/// queueing + any attachment upload in between); a tight window would
/// re-strand genuinely dispatched rows — the exact dead state §4.179 heals.
const UNKNOWN_RECONCILE_TOLERANCE_MS: u64 = 60_000;

/// §4.119 receipt-failure debounce: after one conversation's receipt face
/// records a failure, another trigger of the same (account, conversation,
/// face) key inside this window answers `unknown` without touching the
/// engine. The upstream rejects stale receipt timestamps, so a rapid re-trigger
/// of a failing face is pure replay pressure; the window narrows how often a
/// failing face re-attempts without retrying anything (the desktop's next
/// deliberate trigger after the window is a fresh request, never an automatic
/// retry — the AGENTS.md red line stays intact).
const RECEIPT_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
/// Hard cap on the debounce map (AGENTS.md bounded-maps rule): expired
/// entries prune on every touch, and a pathological burst of distinct
/// failing conversations past the cap is refused insertion (those
/// conversations keep hitting the engine, never an unbounded map).
const RECEIPT_FAILURE_MAP_CAP: usize = 4_096;

/// §4.167 group-history resync TTL: the official lazy group update window —
/// `waitThenMaybeUpdateGroup` skips the fetch when the group was fetched
/// within five minutes (`FIVE_MINUTES`, groups.preload.ts:3057/:3074-3082),
/// so opening a conversation can never hammer the upstream. The connector
/// stamps the attempt on a successful refresh only; a failed refresh clears
/// the stamp (official `setLastSuccessfulGroupFetch(id, undefined)` on
/// failure, :3094) so the next open retries immediately — which is what
/// makes a boot-window miss self-heal without any manual `contacts.sync`.
const GROUP_RESYNC_TTL_MS: u64 = 5 * 60_000;
/// Hard cap on the resync throttle map (AGENTS.md bounded-maps rule): expired
/// entries prune on every touch and insertion is refused past the cap — a
/// pathological burst of distinct group reads past the cap keeps reaching
/// the engine, never an unbounded map (the receipt debounce's own cap
/// direction).
const GROUP_RESYNC_MAP_CAP: usize = 512;

/// One queued auto delivery receipt (contract revision 1.34, §4.29): after an
/// incoming dataMessage row lands, the connector best-effort tells the engine
/// to send the official delivery receipt to its author. Fully silent: failures
/// change nothing, and there is no retry.
#[derive(Clone, Debug)]
struct DeliveryReceiptJob {
    account: String,
    recipient: String,
    timestamp: u64,
}

/// What raised a restart request. Drives whether ping recovery may clear a
/// pending restart: the REST ping says nothing about the receive WebSocket,
/// so only an executed restart clears a stderr-sourced pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestartSource {
    Stderr,
    Ping,
    /// The child process exited on its own (SIGKILL, crash, pipe failure).
    /// The pre-pool watchdog only reacted to stderr/ping evidence and left a
    /// silently dead engine parked until the next runtime.start; per-account
    /// slots need the F3/§6.3 semantics (restart radius = one account), so an
    /// observed terminal engine arms the same bounded restart lane.
    Crash,
}

impl std::fmt::Display for RestartSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestartSource::Stderr => write!(f, "stderr"),
            RestartSource::Ping => write!(f, "ping"),
            RestartSource::Crash => write!(f, "crash"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingRestart {
    source: RestartSource,
    reason: &'static str,
    /// Earliest instant the deferred restart may execute. Armed once and
    /// never pushed later by fresh triggers: a fault that keeps reporting
    /// gets its restart at the first eligible tick instead of "one window
    /// from now" forever.
    due_at: Instant,
    /// Receive-evidence counter value at the moment this pending was armed.
    /// A delivered envelope afterwards proves the receive path itself is
    /// alive and cancels the restart; a successful REST ping cannot, because
    /// `getUserStatus` does not touch the receive WebSocket.
    evidence: u64,
}

/// One failure episode: restarts performed since the first trigger, and the
/// last trigger time. A trigger-free gap longer than the anti-storm window
/// (watchdog_min_restart_interval) resets the schedule, so only one fresh
/// "immediate" restart can begin per window — a fault that keeps reporting
/// inside the window stays on the bounded liveness backoff instead.
#[derive(Default)]
struct WatchdogEpisode {
    restarts: u32,
    last_trigger: Option<Instant>,
}

/// One liveness-ping candidate: the opaque store row id — the only account
/// identity the watchdog ever logs — beside the signal number, which rides
/// into engine call params and nowhere else.
#[derive(Clone, Debug)]
struct WatchdogPingTarget {
    account_id: String,
    number: String,
}

/// Per-engine-instance liveness-probe verdicts. Neither set is ever written
/// back to the store: deleting or reconciling a stale row is a separate
/// concern, the watchdog only stops using it as proof of liveness.
#[derive(Default)]
struct WatchdogProbeVerdicts {
    /// Store rows a successful `listAccounts` answer did not include: the
    /// engine does not serve them, so a ping would only earn its plain
    /// -32603 in milliseconds.
    engine_absent: HashSet<String>,
    /// Store rows `getUserStatus` refused with a plain upstream error while
    /// another candidate answered right after: attributed to the account,
    /// never to the engine (an engine-wide fault refuses every candidate).
    /// Each entry carries the instant the exclusion expires
    /// (`WATCHDOG_PING_REFUSAL_TTL`), so a transient refusal heals on its own.
    ping_refused: HashMap<String, Instant>,
    /// Engine instance these verdicts belong to. A new pid clears both sets:
    /// the restarted engine may serve the account again.
    pid: Option<u32>,
}

impl WatchdogProbeVerdicts {
    /// Scope the verdicts to the current engine instance and drop expired
    /// refusals. Called once per tick, before the candidate set is built.
    fn for_engine(&mut self, pid: Option<u32>) {
        if self.pid != pid {
            self.engine_absent.clear();
            self.ping_refused.clear();
            self.pid = pid;
        }
        let now = Instant::now();
        self.ping_refused.retain(|_, until| now < *until);
    }

    /// Whether this account is currently excluded after a refused probe.
    fn refuses(&self, account_id: &str) -> bool {
        self.ping_refused.contains_key(account_id)
    }

    /// Exclude an account after a refused probe. Answers true when this is a
    /// fresh exclusion (the caller logs and counts it once).
    fn refuse(&mut self, account_id: &str) -> bool {
        let fresh = !self.ping_refused.contains_key(account_id);
        self.ping_refused.insert(
            account_id.to_string(),
            Instant::now() + WATCHDOG_PING_REFUSAL_TTL,
        );
        fresh
    }
}

/// What one tick's probe series proved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchdogPingOutcome {
    /// A verified candidate answered: the engine serves at least one account,
    /// so any plain upstream refusal before it was that account's face.
    Answered,
    /// The engine answered `Unauthorized`: the credential is dead but the
    /// engine itself is alive (contract 1.21), never a restart cause.
    Unauthorized,
    /// No candidate answered. An engine-level error ended the series, or the
    /// caller's evidence rule still decides between an account-scoped skip
    /// and the pre-existing failure accounting.
    Failed,
}

/// The liveness plan of one watchdog tick.
enum WatchdogPingPlan {
    /// A link flow is in flight: pinging or restarting is unsafe (existing
    /// gate, unchanged, not an account-availability skip).
    LinkFlow,
    /// No engine-confirmed account to probe this tick. Skipped, never
    /// counted as a liveness failure.
    NoTarget(WatchdogPingSkip),
    /// Ordered, engine-confirmed candidates (bounded by
    /// `WATCHDOG_PING_ATTEMPT_LIMIT`).
    Probe(Vec<WatchdogPingTarget>),
}

/// Why a tick had no probe target, for the structured skip line.
struct WatchdogPingSkip {
    reason: &'static str,
    known_accounts: usize,
    excluded_accounts: usize,
    engine_verified: bool,
}

/// Backoff before the next restart of one failure episode. `restarts` counts
/// the restarts already executed in the episode: the first is immediate, then
/// `base`, `2 * base`, `4 * base`, … capped at `cap`. A zero base
/// (integration-test launchers) keeps every restart immediate; a capped
/// schedule still retries forever while triggers keep arriving.
fn watchdog_restart_backoff(base: Duration, restarts: u32, cap: Duration) -> Duration {
    if restarts == 0 || base.is_zero() {
        return Duration::ZERO;
    }
    let shift = restarts.saturating_sub(1).min(16);
    base.saturating_mul(1u32 << shift).min(cap)
}

/// Record a deferred restart without ever loosening the one already armed:
/// stderr outranks ping (a receive-fatal stderr trigger is the stronger
/// signal), and among equal sources the earlier deadline wins, so a stream of
/// triggers cannot postpone a live fault. A replacement keeps the earliest
/// receive-evidence snapshot: an envelope delivered between two triggers must
/// still cancel the pending on the next tick.
/// Returns true when this trigger actually armed or tightened the entry.
fn arm_pending_restart(pending: &mut Option<PendingRestart>, candidate: PendingRestart) -> bool {
    let replace = match *pending {
        None => true,
        Some(existing) => match (existing.source, candidate.source) {
            (RestartSource::Stderr, RestartSource::Ping) => false,
            (RestartSource::Ping, RestartSource::Stderr) => true,
            _ => candidate.due_at < existing.due_at,
        },
    };
    if !replace {
        return false;
    }
    let evidence = (*pending).map_or(candidate.evidence, |existing| {
        existing.evidence.min(candidate.evidence)
    });
    *pending = Some(PendingRestart {
        evidence,
        ..candidate
    });
    true
}

/// The engine's own account list as a number set, or `None` when the engine
/// could not answer (or answered a shape that is not an array). Unverified
/// is deliberately NOT the same as "no accounts": the caller must never
/// skip liveness on a failed cross-check.
async fn engine_account_numbers(engine: &EngineHandle) -> Option<HashSet<String>> {
    let result = engine
        .call_with_timeout(
            "listAccounts",
            json!({}),
            CallClass::ReadOnly,
            WATCHDOG_ACCOUNT_VERIFY_TIMEOUT,
        )
        .await
        .ok()?;
    result.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| {
                item.get("number")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect()
    })
}

/// Whether a `getUserStatus` failure can be the *account's* face rather than
/// the engine's: an account the engine does not serve earns its plain JSON-RPC
/// internal error (-32603). The numeric code is the only stable discriminator
/// — the message text of that face is not part of the pinned contract — and it
/// is honoured only for `-32603`; every other upstream code, and every other
/// variant (timeout, backpressure, protocol, exit, not-running, the §4.80
/// transport families), is engine-scoped and keeps the pre-existing failure
/// accounting. Even a `-32603` is attributed to the account only under the
/// caller's evidence rule (another candidate answers, or every candidate is
/// refused and the engine never fails at the transport level).
fn account_scoped_engine_error(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::Upstream {
            code: Some(-32603),
            ..
        }
    )
}

/// Exclude accounts whose `getUserStatus` the engine refused, counting and
/// logging each fresh exclusion exactly once. The rows stay in the store:
/// the watchdog only stops treating them as proof of liveness.
fn exclude_refused_ping_targets(
    verdicts: &mut WatchdogProbeVerdicts,
    refused: &[(String, &'static str)],
    candidates: usize,
) {
    for (account_id, error_class) in refused {
        if verdicts.refuse(account_id) {
            crate::metrics::record_watchdog_ping_target_skipped();
            tracing::info!(
                account_id = %account_id,
                error_class = *error_class,
                candidates,
                "watchdog ping target excluded: the engine refused the account"
            );
        }
    }
}

/// The §4.119 receipt-failure debounce key: one account, one conversation,
/// one receipt face (`sendReadReceipt` / `sendViewedReceipt`). The NUL
/// separator keeps the three opaque ids unambiguous.
fn receipt_failure_key(account_id: &str, conversation_id: &str, method: &str) -> String {
    format!("{account_id}\u{0}{conversation_id}\u{0}{method}")
}

/// Contract 1.197 (§4.197, D4): the delete answer. A recorded deletion adds
/// the content-free receipt under `deleted`; an account already gone (or
/// deleted by a pre-1.197 binary) keeps the historical empty object.
fn account_delete_result(receipt: Option<crate::store::AccountDeleteReceipt>) -> Value {
    match receipt {
        Some(receipt) => json!({ "deleted": receipt }),
        None => json!({}),
    }
}

/// One proxy group's supervised runtime: its own engine slot, watchdog,
/// receive pipeline and link state, over the shared per-profile store
/// (ADR 0001 R4/R5). The group id is the opaque wire identity; the proxy
/// endpoint stays inside the launcher-provided config.
fn link_cancelled_error() -> ServiceError {
    ServiceError::Api(ApiError::new(
        "LINK_CANCELLED",
        "link session was cancelled",
        false,
    ))
}

/// O1: dispose of an engine the contract handshake refused (or could not
/// verify). The child is killed directly — a wedged engine (the probe-timeout
/// case) would otherwise hold the graceful-shutdown budget for nothing, and a
/// mismatched one has no state worth a graceful exit.
async fn refuse_started_engine(engine: &EngineHandle, error: &EngineError) {
    if let Err(kill_error) = engine.force_kill().await {
        tracing::warn!(
            error_class = ?kill_error.kind(),
            "engine refused by the contract handshake could not be killed directly"
        );
    }
    tracing::warn!(
        error_class = error.class(),
        "engine refused by the contract handshake; killed before any account work"
    );
}

/// The engine's method-not-found class (contract 1.286, §4.272): JSON-RPC
/// `-32601`, or the pinned engine's embedded `MethodNotFound` cause literal.
/// `link.rotate` folds it into the host's NOT_SUPPORTED instead of leaking an
/// upstream protocol error for a capability the engine simply does not carry.
fn engine_method_missing(error: &EngineError) -> bool {
    match error {
        EngineError::Upstream {
            code: Some(-32601), ..
        } => true,
        EngineError::Upstream {
            cause: Some(cause), ..
        } => matches!(cause.as_str(), "(MethodNotFound)" | "(MethodNotFoundError)"),
        _ => false,
    }
}

/// The one in-flight `link.finish` wait of this group (per-group wait lane,
/// implementation-plan §6.1). The watch channel is the cancellation signal:
/// `link.cancel` flips it and the finish call stops waiting at once without
/// touching the shared engine.
struct ActiveLinkFinish {
    link_session_id: String,
    cancel: watch::Sender<bool>,
}

pub struct RuntimeSupervisor {
    config: EngineConfig,
    /// Opaque group id (launcher-defined, ADR 0001 R1). Appears on the wire
    /// and in logs; the group's proxy endpoint never does. For a per-account
    /// engine slot this stays the account's *proxy group* (the immutable store
    /// binding); the slot identity is `preferred_account_id` beside it.
    pub(crate) group_id: String,
    /// The pre-provisioned opaque account id of a per-account engine slot
    /// (engine-pool design §5.3). `None` for every legacy group supervisor —
    /// the pre-pool behavior is retained byte for byte. When present, the
    /// first account commit (finishLink or the listAccounts sync) inserts the
    /// row under this id, and log lines carry it so a pool's per-account
    /// lines are attributable without naming a number.
    preferred_account_id: Option<String>,
    /// Successful engine restarts since process start (watchdog recoveries).
    /// Exposed through the pool's per-account status face; never persisted.
    restart_count: Arc<AtomicU64>,
    /// Contract 1.275/1.292: the terminal unlink latch of a **per-account**
    /// engine slot. The account holder unlinked this device upstream (the
    /// engine classified the 401 and the account-unlink watcher persisted
    /// `device_unlinked`): the credential is permanently dead, so the slot's
    /// engine is stopped, no watchdog restart may re-spawn it, and no wake or
    /// `runtime.start` may start it. Only a fresh link clears it.
    ///
    /// A legacy group supervisor never latches: its engine serves every account
    /// of the group, so stopping it for one dead credential would take the
    /// healthy accounts down with it (`note_device_unlinked` is a no-op there).
    device_unlinked: AtomicBool,
    engine: Mutex<Option<EngineHandle>>,
    /// O1 engine contract handshake state: the verdict of the last engine
    /// landing (doctor/metrics read it) plus the latched fault that refuses
    /// every later start for the life of this process. A mismatch is never
    /// self-healing — the same binary answers the same revision on restart —
    /// so the latch is what keeps the watchdog and `runtime.start` from
    /// burning the launcher's restart budget on it.
    engine_contract: Mutex<crate::engine_contract::EngineContractState>,
    service: Arc<Mutex<ConnectorService>>,
    /// Shared store handle for the store-only paths (retention, reads) that
    /// run on the blocking pool without the service lock.
    store: Arc<Store>,
    /// Media ingest backing (ADR 0004) when the launcher passed
    /// `--media-ingest`; drives the retention trigger and exists iff the
    /// service's own backing exists. Never held; `MediaGovernor` is a plain
    /// data-dir handle.
    media: Option<MediaIngest>,
    active_link_finish: Mutex<Option<ActiveLinkFinish>>,
    events: broadcast::Sender<EngineEvent>,
    host_events: broadcast::Sender<HostSideEvent>,
    receive_ingress: ReceiveIngress,
    receive_worker: JoinHandle<()>,
    /// Receive-evidence counter (one bump per envelope the engine delivered to
    /// this group's receive lane). The receive-liveness watchdog uses it as
    /// the only positive proof the receive WebSocket is alive: the REST ping
    /// cannot see that channel, so a delivered envelope — not a successful
    /// `getUserStatus` — is what cancels a pending restart.
    receive_evidence: Arc<AtomicU64>,
    /// Receive-liveness watchdog; never held across an await.
    watchdog: StdMutex<Option<JoinHandle<()>>>,
    /// Engine-event watcher: device-unlinked accounts (contract 1.21) plus
    /// the account-domain transient-notification lane (contract 1.134,
    /// §4.117); never held across an await.
    account_unlink_worker: JoinHandle<()>,
    /// One-shot history retention pass; never held across an await.
    retention: StdMutex<Option<JoinHandle<()>>>,
    /// One-shot media governor pass (ADR 0004: once per process start);
    /// never held across an await.
    media_governor_pass: StdMutex<Option<JoinHandle<()>>>,
    /// The contacts/groups re-sync pass armed by every engine landing (boot
    /// start or watchdog recovery); never held across an await. The running
    /// flag, not the handle slot, is what keeps one pass at a time — each
    /// landing may arm a fresh pass, and the 60 s cache folds a restart storm
    /// into read-only no-ops (the official afterAuthSocketConnect posture:
    /// run the sync chain on every authenticated connection).
    contacts_resync: StdMutex<Option<JoinHandle<()>>>,
    contacts_resync_running: Arc<AtomicBool>,
    /// Receiver of the bounded background-sync kicks (engine completion
    /// events); `Some` until `spawn_background_sync_worker` takes it. The
    /// queue exists in `new` because the engine-event watcher holds the
    /// sender, but the worker is spawned by the registry once the supervisor
    /// sits behind its `Arc`.
    background_sync_rx: StdMutex<Option<mpsc::Receiver<String>>>,
    /// The background-sync worker; never held across an await.
    background_sync_worker: StdMutex<Option<JoinHandle<()>>>,
    /// Link-time history import single flight (contract revision 1.39,
    /// §4.38): at most one import per group at a time — claimed by the
    /// `link.finish` watcher or the startup sweep, released when the import
    /// (plus its retention convergence) finishes. Shared with the spawned
    /// tasks, which outlive any borrow of `self`.
    history_import_running: Arc<AtomicBool>,
    /// Which account holds the import slot right now (contract 1.53): the
    /// `processing` stage of `history.importStatus` must name the polled
    /// account, not just "the group is busy" — a crashed run's stale
    /// `running` row on a second account must not borrow another account's
    /// live pass as its progress. Set/cleared inside the same claim/release
    /// window as the single-flight flag.
    history_import_holder: Arc<StdMutex<Option<String>>>,
    /// The cooperative cancel flag for the run that holds the slot (contract
    /// revision 1.148, §4.146): `history.importCancel` flips it when the
    /// holder names the cancelled account, the run checks it between archive
    /// lines, and every claim resets it first so a stale flag can never kill
    /// the next account's pass. One flag per group (the slot is
    /// single-flight); never held across an await.
    history_import_abort: Arc<AtomicBool>,
    /// The process-lifetime cancel registry (contract revision 1.148,
    /// §4.146): accounts whose link-time import the desktop cancelled. At
    /// most one entry per linked account (bounded by the account ceiling);
    /// the link watcher exits on it, the eligibility probe refuses it, the
    /// status face answers `unavailable`/`cancelled` from it, and an explicit
    /// `history.importRetry` clears it (an explicit user intent supersedes
    /// the cancel). Deliberately not persisted: a connector restart is a new
    /// intent (the §4.69 recovery-hole posture).
    history_import_cancels: Arc<StdMutex<HashSet<String>>>,
    /// Disappearing-message sweep single flight (contract revision 1.42,
    /// §4.41): at most one sweep pass per group at a time, shared with the
    /// periodic task.
    expire_sweep_running: Arc<AtomicBool>,
    /// The periodic expire sweeper; never held across an await.
    expire_sweeper: StdMutex<Option<JoinHandle<()>>>,
    /// Receiver of the bounded auto delivery-receipt queue; `Some` until
    /// `spawn_delivery_receipt_worker` takes it. The queue itself is created
    /// in `new` (the persistence loop holds the sender), but the worker can
    /// only be spawned once the supervisor sits behind its `Arc`.
    delivery_receipt_rx: StdMutex<Option<mpsc::Receiver<DeliveryReceiptJob>>>,
    /// The delivery-receipt worker; never held across an await.
    delivery_receipt_worker: StdMutex<Option<JoinHandle<()>>>,
    /// Batch X · S6①: the bounded avatar-refresh queue's receiver, taken by
    /// `spawn_avatar_refresh_worker` (the queue itself is created in `new`;
    /// the persistence loop holds the sender). Bounded and lossy — a full
    /// queue drops the refetch kick, never the receive (the next profile
    /// change or the desktop's own on-demand pull converges).
    avatar_refresh_rx: StdMutex<Option<mpsc::Receiver<(String, String)>>>,
    /// 契约 1.270（§4.254 · 批 Z14）：头像 backfill kick 用的队列发送端
    /// clone（队列本体在 `new` 创建；persistence loop 持原版发送端，本
    /// 字段供 contacts-sync 落库后的 backfill 臂 try_send，lossy 同纪律）。
    avatar_backfill_tx: mpsc::Sender<(String, String)>,
    /// The avatar-refresh worker; never held across an await.
    avatar_refresh_worker: StdMutex<Option<JoinHandle<()>>>,
    /// §4.123 outbox drain: the receiver side of the lossy drain-kick channel
    /// (cap 1 — a send that finds it full means a pass is already pending),
    /// taken by `spawn_outbox_worker`; and the single worker slot. The
    /// channel's sender stays on the supervisor for the engine-landed hooks.
    outbox_drain_rx: StdMutex<Option<mpsc::Receiver<()>>>,
    outbox_drain_tx: mpsc::Sender<()>,
    outbox_worker: StdMutex<Option<JoinHandle<()>>>,
    /// unix ms of last listContacts title enrich (throttle hot list path)
    last_title_enrich_ms: AtomicU64,
    /// The §4.46 backup file three-chain: `Some` when the launcher armed the
    /// backup-export capability. Process-wide like the media table (the
    /// registry hands every group the same `Arc` — `readChunk`/`closeHandle`
    /// carry no accountId, so handle resolution must not depend on routing).
    backup_handles: Option<Arc<crate::backup_export::BackupFileHandleTable>>,
    /// Per-account skip counters from the most recent successful artifact
    /// build; published after `build_artifact` writes the artifact, merged
    /// into `backups.exportStatus` answers. Content-free numbers only.
    backup_counters: StdMutex<HashMap<String, crate::backup_export::SkipCounters>>,
    /// Per-account plaintext export task slots (contract revision 1.132,
    /// §4.115): connector-local and in-memory like the engine's own task
    /// registry — a restart reads idle while the on-disk artifacts stay
    /// listed. Shared with the spawned build tasks, which outlive any borrow
    /// of `self`.
    plaintext_tasks: Arc<crate::backup_export::PlaintextTaskRegistry>,
    /// §4.119 receipt-failure debounce: (account, conversation, receipt face)
    /// keys whose last engine attempt failed, valued by the failure instant.
    /// In-memory, process-local, pruned on every touch, hard-capped. The
    /// std clock keeps `duration_since` saturating — a backwards wall-clock
    /// jump reads as "just failed", never a panic.
    receipt_failures: StdMutex<HashMap<String, std::time::Instant>>,
    /// §4.167 single-group resync throttle: (account, group) → last
    /// successful refresh stamp (epoch ms). Success-only stamps — a failed
    /// refresh removes its entry so the next conversation open retries
    /// immediately. Bounded like the receipt debounce; never held across an
    /// await.
    group_resync_stamps: StdMutex<HashMap<(String, String), u64>>,
    /// P0 engine-orphan sweep state: whose slots this supervisor watches and
    /// the repeat-detection memory for them (see
    /// `parent::plan_engine_sweep`). Set only by the pool owner — a legacy
    /// group supervisor never runs the sweep, and a supervisor without a
    /// setting is byte-for-byte its pre-sweep self.
    orphan_sweep: StdMutex<Option<OrphanSweepScope>>,
    /// The slot table the sweep classifies against (set by the pool owner on
    /// the one supervisor that was armed). Kept as a weak-free `Arc` because
    /// the pool owns its supervisors: ownership here would be a cycle, so the
    /// pool clears it when it stops.
    sweep_owner: StdMutex<Option<Arc<crate::registry::SweepOwner>>>,
    /// Contract 1.291 (§4.277 C): the store gate this supervisor consults
    /// before it spawns an engine on a path the pool did not open itself -
    /// the watchdog's crash restart, and any future start face. Installed by
    /// the per-account pool; a legacy group supervisor has none and answers
    /// exactly as it always has.
    start_gate: StdMutex<Option<Arc<dyn EngineStartGate>>>,
}

/// A pre-spawn admission check owned by the engine pool (contract 1.291,
/// §4.277 C). The gate is what stops a **crash restart** from opening a store
/// the store migrator still owns: the watchdog recovers an engine without the
/// pool asking, so the decision has to live at the spawn, not at the caller.
///
/// `Ok(())` = spawn now. `Err(code)` = not now, with a closed literal naming
/// the lifecycle state for the caller's log and the host face.
pub trait EngineStartGate: Send + Sync {
    fn admit_engine_start(&self) -> futures_util::future::BoxFuture<'_, Result<(), &'static str>>;
}

/// What the watchdog's orphan-engine pass watches: one scope per process (the
/// engine pool), because every slot engine is discovered by the same data
/// directory and must not be swept twice by two watchdog clocks.
pub(crate) struct OrphanSweepScope {
    pub(crate) signal_data_dir: PathBuf,
    pub(crate) memory: crate::parent::SweepMemory,
}

impl OrphanSweepScope {
    pub(crate) fn new(signal_data_dir: PathBuf) -> Self {
        Self {
            signal_data_dir,
            memory: crate::parent::SweepMemory::default(),
        }
    }
}

impl RuntimeSupervisor {
    pub fn new(
        config: EngineConfig,
        store: Arc<Store>,
        group_id: String,
        media_handles: Option<Arc<MediaHandleTable>>,
    ) -> Self {
        Self::with_backup_handles(config, store, group_id, media_handles, None)
    }

    /// Launcher entry carrying the §4.46 backup-handle table: `Some` arms the
    /// backup-export capability (every group receives the same process-wide
    /// table — see `backup_handles`). `new` is the media-only compatibility
    /// form the tests use.
    pub fn with_backup_handles(
        config: EngineConfig,
        store: Arc<Store>,
        group_id: String,
        media_handles: Option<Arc<MediaHandleTable>>,
        backup_handles: Option<Arc<crate::backup_export::BackupFileHandleTable>>,
    ) -> Self {
        Self::with_media_root(
            config,
            store,
            group_id,
            media_handles,
            backup_handles,
            None,
            None,
        )
    }

    /// Launcher entry for a per-account engine slot (engine-pool design
    /// §3.3/§8): the media namespace stays connector-owned at
    /// `<signal-data>/media/<accountId>/attachments` even though the engine
    /// data directory is now the account slot's own
    /// `<signal-data>/engines/<accountId>`. Passing `None` keeps the legacy
    /// root (the group's data directory) byte for byte. The engine log file
    /// is the engine's own concern and follows the data directory
    /// (`<data-dir>/logs/engine-stderr.log`), which is exactly what makes the
    /// per-account logs disjoint.
    #[allow(clippy::too_many_arguments)]
    pub fn with_media_root(
        config: EngineConfig,
        store: Arc<Store>,
        group_id: String,
        media_handles: Option<Arc<MediaHandleTable>>,
        backup_handles: Option<Arc<crate::backup_export::BackupFileHandleTable>>,
        media_root: Option<PathBuf>,
        preferred_account_id: Option<String>,
    ) -> Self {
        let (events, _) = event_channel();
        let (host_events, _) = broadcast::channel(1024);
        // Media ingest is armed only when the launcher passed both the
        // `--media-ingest` flag and the shared handle table; anything else
        // keeps the service on the pre-PoC capability-unavailable shape.
        let media = if config.media_ingest {
            let root = media_root.unwrap_or_else(|| config.data_dir.clone());
            media_handles.map(|handles| MediaIngest::new(root, handles))
        } else {
            None
        };
        if config.media_ingest && media.is_none() {
            tracing::warn!(
                "media ingest flag is set without a handle table; media methods stay unavailable"
            );
        }
        let service = Arc::new(Mutex::new(ConnectorService::with_media_and_account(
            Arc::clone(&store),
            media.clone(),
            preferred_account_id.clone(),
        )));
        let (receive_ingress, receive_rx) = receive_channel();
        // Auto delivery receipts (contract revision 1.34): the persistence
        // loop queues one job per landed incoming dataMessage; the worker
        // spawned later by the registry drains it. Bounded and lossy — a full
        // queue drops the receipt job, never the receive.
        let (delivery_receipt_tx, delivery_receipt_rx) =
            mpsc::channel::<DeliveryReceiptJob>(DELIVERY_RECEIPT_QUEUE_CAP);
        // Batch X · S6①: the stale-avatar refetch queue the persistence loop
        // feeds (profile change / group avatar change targets, resolved and
        // invalidated under the service lock by the service's
        // stale_avatar_targets); the worker spawned later by the registry
        // drains it through the getAvatar read lane. Bounded and lossy.
        let (avatar_refresh_tx, avatar_refresh_rx) =
            mpsc::channel::<(String, String)>(AVATAR_REFRESH_QUEUE_CAP);
        // 契约 1.270（§4.254 · 批 Z14）：backfill kick 的发送端 clone——原版
        // 发送端 move 进 persistence loop，本 clone 存 supervisor 字段供
        // contacts-sync 落库后的 backfill 臂 try_send（lossy 同纪律）。
        let avatar_backfill_tx = avatar_refresh_tx.clone();
        // §4.123 outbox drain: the cap-1 lossy kick channel the engine-landed
        // hooks send on; the worker (spawned later by the registry) owns the
        // receiver and otherwise paces itself on the due schedules + tick.
        let (outbox_drain_tx, outbox_drain_rx) = mpsc::channel(1);
        // Batch I: the engine's completion notifications (storagePull /
        // initialSyncComplete) kick the ordinary contacts/groups sync from the
        // background. Bounded and lossy; the worker is spawned by the registry
        // (a supervisor is not behind its `Arc` yet inside `new`).
        let (background_sync_tx, background_sync_rx) =
            mpsc::channel::<String>(BACKGROUND_SYNC_QUEUE_CAP);
        // Receive-path survival evidence for the watchdog: bumped by the
        // persistence loop for every envelope the engine actually delivers to
        // this group's receive lane (see the field doc).
        let receive_evidence = Arc::new(AtomicU64::new(0));
        let receive_worker = tokio::spawn(receive_persistence_loop(
            receive_rx,
            service.clone(),
            Arc::clone(&store),
            host_events.clone(),
            group_id.clone(),
            media.as_ref().map(|media| media.governor().clone()),
            delivery_receipt_tx,
            avatar_refresh_tx,
            Arc::clone(&receive_evidence),
        ));
        // Contract 1.21: authorization failures observed on this group's
        // engine mark the dead account in the shared store and surface it on
        // the host lane (account.changed). Contract 1.134 §4.117: the same
        // watcher is the account-domain transient-notification lane's
        // consumer (receive.emptied / receive.clockskew /
        // receive.conversationState → their host frames).
        let account_unlink_worker = tokio::spawn(engine_event_watch_loop(
            events.subscribe(),
            service.clone(),
            Arc::clone(&store),
            host_events.clone(),
            background_sync_tx,
        ));
        Self {
            config,
            group_id,
            preferred_account_id,
            restart_count: Arc::new(AtomicU64::new(0)),
            device_unlinked: AtomicBool::new(false),
            engine: Mutex::new(None),
            engine_contract: Mutex::new(crate::engine_contract::EngineContractState::default()),
            service,
            store,
            media,
            active_link_finish: Mutex::new(None),
            events,
            host_events,
            receive_ingress,
            receive_worker,
            receive_evidence,
            account_unlink_worker,
            watchdog: StdMutex::new(None),
            retention: StdMutex::new(None),
            media_governor_pass: StdMutex::new(None),
            contacts_resync: StdMutex::new(None),
            contacts_resync_running: Arc::new(AtomicBool::new(false)),
            background_sync_rx: StdMutex::new(Some(background_sync_rx)),
            background_sync_worker: StdMutex::new(None),
            history_import_running: Arc::new(AtomicBool::new(false)),
            history_import_holder: Arc::new(StdMutex::new(None)),
            history_import_abort: Arc::new(AtomicBool::new(false)),
            history_import_cancels: Arc::new(StdMutex::new(HashSet::new())),
            expire_sweep_running: Arc::new(AtomicBool::new(false)),
            expire_sweeper: StdMutex::new(None),
            delivery_receipt_rx: StdMutex::new(Some(delivery_receipt_rx)),
            delivery_receipt_worker: StdMutex::new(None),
            avatar_refresh_rx: StdMutex::new(Some(avatar_refresh_rx)),
            avatar_backfill_tx,
            avatar_refresh_worker: StdMutex::new(None),
            outbox_drain_rx: StdMutex::new(Some(outbox_drain_rx)),
            outbox_drain_tx,
            outbox_worker: StdMutex::new(None),
            last_title_enrich_ms: AtomicU64::new(0),
            backup_handles,
            backup_counters: StdMutex::new(HashMap::new()),
            plaintext_tasks: Arc::new(crate::backup_export::PlaintextTaskRegistry::new()),
            receipt_failures: StdMutex::new(HashMap::new()),
            group_resync_stamps: StdMutex::new(HashMap::new()),
            orphan_sweep: StdMutex::new(None),
            start_gate: StdMutex::new(None),
            sweep_owner: StdMutex::new(None),
        }
    }

    /// Arm the P0 orphan-engine sweep on this supervisor (called once by the
    /// engine pool, right after the slot exists). Before this call the
    /// watchdog runs its pre-sweep loop byte for byte.
    pub(crate) fn arm_orphan_sweep(
        &self,
        signal_data_dir: PathBuf,
        owner: Arc<crate::registry::SweepOwner>,
    ) {
        if let Ok(mut scope) = self.orphan_sweep.lock() {
            *scope = Some(OrphanSweepScope::new(signal_data_dir));
        }
        if let Ok(mut slot) = self.sweep_owner.lock() {
            *slot = Some(owner);
        }
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// The pre-provisioned opaque account id of a per-account slot, or `None`
    /// for a legacy group supervisor.
    pub fn account_id(&self) -> Option<&str> {
        self.preferred_account_id.as_deref()
    }

    /// Successful watchdog restarts of this slot's engine since process
    /// start. The per-account status face exposes it as `restarts`.
    pub fn restart_count(&self) -> u64 {
        self.restart_count.load(Ordering::Relaxed)
    }

    /// Whether this slot sits in the terminal "the account holder unlinked
    /// this device" state (contract 1.275/1.292). Always `false` for a legacy
    /// group supervisor: the group engine is shared, so one dead account's
    /// terminal state is not a slot state there.
    pub fn is_device_unlinked(&self) -> bool {
        self.preferred_account_id.is_some() && self.device_unlinked.load(Ordering::Acquire)
    }

    /// Latch the terminal unlink without touching the engine: every start face
    /// answers `ACCOUNT_UNLINKED` (retryable=false) from here on. Returns true
    /// when this call latched it. A legacy group supervisor is never latched.
    pub fn note_device_unlinked(&self) -> bool {
        if self.preferred_account_id.is_none() {
            return false;
        }
        let fresh = !self.device_unlinked.swap(true, Ordering::AcqRel);
        if fresh {
            tracing::warn!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                "account device was unlinked upstream; this slot is parked until a re-link"
            );
        }
        fresh
    }

    /// The terminal handling of an observed unlink: latch the state and stop
    /// the engine process. Idempotent by construction (the shutdown is a no-op
    /// with no engine), so every caller that discovers the terminal state -
    /// the account.changed lane, the watchdog, a wake - enforces the same
    /// invariant: no engine outlives a dead credential. Returns `true` when the
    /// slot is terminal, `false` for a legacy group supervisor, which is never
    /// retired.
    pub async fn retire_device_unlinked(&self) -> bool {
        if self.preferred_account_id.is_none() {
            return false;
        }
        self.note_device_unlinked();
        // The engine process must not outlive the dead credential: nothing it
        // could still do is attributable to a linked device, and leaving it
        // resident is exactly the "engine and slot hang forever" shape. With no
        // engine there is nothing to stop (and nothing to log): the latch alone
        // keeps every later start refused.
        if self.engine.lock().await.is_none() {
            return true;
        }
        match self.shutdown_within(None).await {
            Ok(()) => tracing::warn!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                "account engine stopped: the device was unlinked upstream and cannot be revived by a restart"
            ),
            Err(error) => tracing::warn!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                error_class = error.class(),
                "account engine did not stop cleanly after the terminal unlink"
            ),
        }
        true
    }

    /// Clear the terminal unlink latch: a fresh link (or its commit) is the one
    /// answer that may replace a terminal unlink (contract 1.275). The engine
    /// stays cold; the ordinary wake path starts it again.
    pub fn clear_device_unlinked(self: &Arc<Self>) {
        if !self.device_unlinked.swap(false, Ordering::AcqRel) {
            return;
        }
        tracing::info!(
            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
            group_id = %self.group_id,
            "terminal device unlink cleared: a fresh link owns this slot again"
        );
        // The watchdog owns the restart lane; a terminal retire parked it, so a
        // slot that may serve traffic again gets its liveness loop back.
        self.spawn_watchdog();
    }

    /// Abort this slot's watchdog task (idempotent). The terminal unlink parks
    /// the restart lane from another task; `clear_device_unlinked` respawns it.
    pub fn stop_watchdog(&self) {
        if let Ok(mut slot) = self.watchdog.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
    }

    /// The engine-start refusal for a terminal unlink. Consulted by every start
    /// face **before** any other gate, so a device the holder already unlinked
    /// never spawns an engine that can only answer 401.
    fn terminal_unlink_guard(&self) -> Result<(), EngineError> {
        let Some(account_id) = self.preferred_account_id.as_deref() else {
            return Ok(());
        };
        if !self.account_is_device_unlinked(account_id) {
            return Ok(());
        }
        self.note_device_unlinked();
        tracing::warn!(
            account_id = %account_id,
            group_id = %self.group_id,
            "engine start refused: the account holder unlinked this device; the slot needs a re-link"
        );
        Err(EngineError::Unauthorized)
    }

    /// Whether the shared store's row for `account_id` carries the terminal
    /// `device_unlinked` state. The store is the authority across connector
    /// restarts (the in-memory latch is not): a fresh process rediscovers the
    /// slot cold and must answer the same terminal refusal.
    pub(crate) fn account_is_device_unlinked(&self, account_id: &str) -> bool {
        self.is_device_unlinked()
            || self
                .store
                .account_summary(account_id)
                .ok()
                .flatten()
                .is_some_and(|row| row.state == "device_unlinked")
    }

    /// The media namespace root this supervisor writes under, when the media
    /// path is armed. Per-account slots point at the connector root
    /// (`<signal-data>`) so media stays outside the engine data directory;
    /// legacy groups keep their data-dir root. Test-only visibility: the pool
    /// tests pin the two shapes.
    #[cfg(test)]
    pub(crate) fn media_root(&self) -> Option<&Path> {
        self.media
            .as_ref()
            .map(|media| media.governor().data_dir().as_path())
    }

    /// Shared service handle. The registry uses it for cross-group routing
    /// lookups and account counts over the single shared store.
    pub(crate) fn service(&self) -> &Arc<Mutex<ConnectorService>> {
        &self.service
    }

    /// The shared store handle (contract revision 1.282, §4.266): the
    /// registry keeps one for the process-wide store health face, so the
    /// doctor and the metrics line can read schema version, integrity, file
    /// sizes and snapshot state without going through a group engine.
    pub(crate) fn store(&self) -> Arc<Store> {
        Arc::clone(&self.store)
    }

    /// Whether the media-download capability is genuinely armed for this
    /// group: the media table exists — the launcher passed `--media-ingest`
    /// AND the shared handle table arrived — which is the exact gate every
    /// media method answers before anything else. The registry reads it for
    /// the handshake `attachment-download` advertisement (contract revision
    /// 1.98): an unarmed group must not advertise a tag whose faces answer
    /// `CAPABILITY_UNAVAILABLE` for every call.
    pub(crate) fn media_ingest_armed(&self) -> bool {
        self.media.is_some()
    }

    /// Spawn the receive-liveness watchdog (idempotent). Detects a silently dead
    /// receive path — signal-cli stays alive but its server WebSocket is gone —
    /// via stderr error lines and periodic read-only pings, then restarts the engine.
    /// Abort the long-lived background tasks that a process-lifetime
    /// supervisor would otherwise keep forever. Only a dynamic account slot
    /// being discarded (link rollback / account delete) calls this; legacy
    /// supervisors live for the process, and their tasks must keep running
    /// across `runtime.stop`/start.
    pub fn stop_background_tasks(&self) {
        if let Ok(mut slot) = self.watchdog.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        for task in [
            &self.retention,
            &self.media_governor_pass,
            &self.contacts_resync,
            &self.expire_sweeper,
            &self.delivery_receipt_worker,
            &self.outbox_worker,
        ] {
            if let Ok(mut slot) = task.lock()
                && let Some(handle) = slot.take()
            {
                handle.abort();
            }
        }
        self.receive_worker.abort();
        self.account_unlink_worker.abort();
    }

    pub fn spawn_watchdog(self: &Arc<Self>) {
        let Ok(mut slot) = self.watchdog.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let supervisor = Arc::clone(self);
        *slot = Some(tokio::spawn(supervisor.watchdog_loop()));
    }

    /// Apply history retention once per process start (idempotent).
    ///
    /// It runs in the background rather than on the startup path because the
    /// host only waits a few seconds for the handshake, and it takes the store
    /// lock one bounded batch at a time because inbound receives need that same
    /// lock. It does not repeat on a timer: nothing here is time-critical, and a
    /// long-lived process simply defers the rest to the next start.
    pub fn spawn_history_retention(self: &Arc<Self>) {
        let Ok(mut slot) = self.retention.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let store = Arc::clone(&self.store);
        *slot = Some(tokio::spawn(async move {
            let now = crate::link::now_ms();
            let mut removed = 0_u64;
            loop {
                // Each batch runs on the blocking pool: rusqlite is
                // synchronous and must never occupy a tokio worker thread.
                let outcome = tokio::task::spawn_blocking({
                    let store = Arc::clone(&store);
                    move || store.prune_history(now, RETENTION_BATCH_MESSAGES)
                })
                .await
                .unwrap_or(Err(StoreError::Unavailable(None)));
                match outcome {
                    Ok(outcome) => {
                        removed += outcome.messages_deleted;
                        if outcome.messages_deleted < u64::from(RETENTION_BATCH_MESSAGES) {
                            break;
                        }
                        sleep(RETENTION_BATCH_PAUSE).await;
                    }
                    // Storage trouble surfaces on the paths the host is waiting
                    // on; retention leaves the rest for the next start.
                    Err(error) => {
                        tracing::warn!(
                            error_class = error.class(),
                            "history retention stopped: store unavailable"
                        );
                        break;
                    }
                }
            }
            if removed > 0 {
                tracing::info!(removed, "history retention removed expired messages");
            }
            // Phase 3: the one-time plaintext migration backup has its own
            // 7-day retention budget, pruned through this same once-per-start
            // batch pass.
            match tokio::task::spawn_blocking(move || store.prune_expired_plaintext_backup(now))
                .await
                .unwrap_or(Err(StoreError::Unavailable(None)))
            {
                Ok(true) => tracing::info!("expired plaintext store backup removed"),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    error_class = error.class(),
                    "plaintext store backup cleanup failed"
                ),
            }
        }));
    }

    /// Spawn the disappearing-message sweeper (contract 1.42, §4.41;
    /// idempotent). One periodic task per group: after a short startup settle
    /// it runs one full drain (bounded batches back to back), then sweeps on
    /// the configured cadence. Store work runs on the blocking pool; each
    /// pass is single-flight (`expire_sweep_running`) so a long drain never
    /// overlaps the next tick. A conversation with no timer state costs
    /// nothing: the partial index makes the "nothing due" probe a point query.
    pub fn spawn_expire_sweeper(self: &Arc<Self>) {
        let Ok(mut slot) = self.expire_sweeper.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let supervisor = Arc::clone(self);
        *slot = Some(tokio::spawn(async move {
            sleep(EXPIRE_SWEEP_STARTUP_SETTLE).await;
            loop {
                supervisor.run_expire_sweep_pass().await;
                sleep(supervisor.config.expire_sweep_interval).await;
            }
        }));
    }

    /// One sweep drain: bounded delete batches back to back until a batch
    /// comes back under the cap (or the store fails), emitting one batched
    /// `message.expired` event per touched conversation. Failures leave the
    /// rest for the next tick and never take the sweeper down.
    async fn run_expire_sweep_pass(&self) {
        if self.expire_sweep_running.swap(true, Ordering::Relaxed) {
            return;
        }
        let result = self.expire_sweep_batches().await;
        self.expire_sweep_running.store(false, Ordering::Relaxed);
        if let Err(error) = result {
            tracing::warn!(
                error_class = error.class(),
                "expire sweep stopped: store unavailable"
            );
        }
    }

    async fn expire_sweep_batches(&self) -> Result<(), StoreError> {
        loop {
            let groups = tokio::task::spawn_blocking({
                let store = Arc::clone(&self.store);
                move || store.sweep_expired_messages(crate::link::now_ms(), EXPIRE_SWEEP_BATCH)
            })
            .await
            .unwrap_or(Err(StoreError::Unavailable(None)))?;
            // The cap bounds deleted rows, not conversations: a full batch is
            // total ids across the returned groups (one group may hold the
            // whole batch), so a backed-up drain keeps going immediately.
            let deleted: usize = groups.iter().map(|group| group.message_ids.len()).sum();
            let full_batch = deleted >= EXPIRE_SWEEP_BATCH as usize;
            for group in groups {
                let account_id = group.account_id.clone();
                let event = HostSideEvent::MessageExpired {
                    account_id: group.account_id,
                    conversation_id: group.conversation_id,
                    message_ids: group.message_ids,
                };
                let epoch = self
                    .store
                    .account_engine_epoch(&account_id)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                let publisher =
                    EventPublisher::new(Arc::clone(&self.store), self.host_events.clone());
                if let Err(error) =
                    publisher.publish(epoch, Some(&account_id), "message.expired", event)
                {
                    tracing::warn!(?error, "durable event publish failed");
                }
            }
            if !full_batch {
                return Ok(());
            }
            sleep(RETENTION_BATCH_PAUSE).await;
        }
    }

    /// One media governor pass per process start (ADR 0004 trigger
    /// discipline; idempotent). Media retention is per engine data directory,
    /// so — unlike the store-wide history retention — every proxy group's
    /// supervisor runs its own pass, and the receive pipeline repeats it
    /// after every [`crate::media::GOVERNOR_INBOUND_MESSAGE_INTERVAL`]
    /// inbound messages.
    pub fn spawn_media_governor(self: &Arc<Self>) {
        let Some(governor) = self.media.as_ref().map(|media| media.governor().clone()) else {
            return;
        };
        let Ok(mut slot) = self.media_governor_pass.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        *slot = Some(run_media_governor_pass(governor));
    }

    /// Take the queued auto delivery-receipt receiver and spawn its one
    /// worker (contract revision 1.34, idempotent). Spawned by the registry —
    /// not in `new`, which runs before the supervisor sits behind its
    /// `Arc<Self>` — and the worker re-resolves `running_engine()` per job
    /// because a pre-cloned engine handle would go stale across watchdog
    /// restarts. Fully silent: every failure (runtime down, engine error,
    /// unknown outcome) is dropped; nothing is retried.
    pub fn spawn_delivery_receipt_worker(self: &Arc<Self>) {
        let Some(receiver) = self
            .delivery_receipt_rx
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        else {
            return;
        };
        let supervisor = Arc::clone(self);
        let worker = tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some(job) = receiver.recv().await {
                let Ok(engine) = supervisor.running_engine().await else {
                    continue;
                };
                let _ = engine
                    .call(
                        "sendDeliveryReceipt",
                        json!({
                            "account": job.account,
                            "recipient": job.recipient,
                            "timestamps": [job.timestamp],
                        }),
                        CallClass::Mutating,
                    )
                    .await;
            }
        });
        if let Ok(mut slot) = self.delivery_receipt_worker.lock() {
            *slot = Some(worker);
        }
    }

    /// Batch X · S6① (S6 头像生命周期 ① 失效重拉时机): take the bounded
    /// avatar-refresh queue and drain it — one (account, conversation) kick
    /// per profile-change / group-avatar-change face, refetched through the
    /// exact read lane the desktop's `conversations.getAvatar` uses (the
    /// §4.47 prepare face, the read-only engine call, the result-face gate,
    /// the service commit gate) so the cache converges through one writer
    /// discipline. Lossy end to end: an unreachable engine or a full queue
    /// drops the kick (the desktop's on-demand pull is the backstop), an
    /// honest UNAVAILABLE clears the entry idempotently (the L2
    /// negative-chain discipline), and a committed byte set pushes the
    /// refreshed summary so open windows repaint without a re-read.
    pub fn spawn_avatar_refresh_worker(self: &Arc<Self>) {
        let Some(receiver) = self
            .avatar_refresh_rx
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        else {
            return;
        };
        let supervisor = Arc::clone(self);
        let worker = tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some((account_id, conversation_id)) = receiver.recv().await {
                supervisor
                    .refresh_conversation_avatar(&account_id, &conversation_id)
                    .await;
            }
        });
        if let Ok(mut slot) = self.avatar_refresh_worker.lock() {
            *slot = Some(worker);
        }
    }

    /// Batch X · S6①: one background avatar refetch — the getAvatar lane
    /// minus the IPC boundary (the phases of the desktop-facing
    /// `get_avatar` above, verbatim order). Never logs bytes or identities
    /// (§4.47); every failure face is a content-free warn at most.
    async fn refresh_conversation_avatar(&self, account_id: &str, conversation_id: &str) {
        let Ok(engine) = self.running_engine().await else {
            return;
        };
        let upstream = {
            let service = self.service.lock().await;
            match service.prepare_conversations_get_avatar(account_id, conversation_id) {
                Ok(upstream) => upstream,
                Err(_) => return,
            }
        };
        match engine
            .call("getAvatar", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => {
                let Ok(download) = avatar_from_engine(&result) else {
                    return;
                };
                let service = self.service.lock().await;
                let committed = service
                    .commit_conversation_avatar(
                        account_id,
                        conversation_id,
                        &download.data_uri,
                        download.byte_size,
                    )
                    .is_ok();
                if committed
                    && let Ok(Some(conversation)) =
                        self.store.conversation_summary(account_id, conversation_id)
                {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(conversation));
                }
            }
            Err(EngineError::UpstreamCode {
                code: "AVATAR_UNAVAILABLE",
                ..
            }) => {
                // The honest no-avatar answer (peer/group has none or the
                // profile key went missing): the idempotent clear keeps the
                // projection absent, and the changed push lets any open
                // window drop the stale bytes in the same pass.
                let service = self.service.lock().await;
                let _ = service.clear_conversation_avatar(account_id, conversation_id);
                if let Ok(Some(conversation)) =
                    self.store.conversation_summary(account_id, conversation_id)
                {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(conversation));
                }
            }
            Err(_) => {
                // Transient (FETCH_FAILED / TOO_LARGE / lifecycle): nothing
                // cached either way (the clear already ran), the next
                // profile change or the desktop's own pull retries.
            }
        }
    }

    /// 契约 1.270（§4.254 · 批 Z14 · S6 头像生命周期⑦）：contacts sync 落
    /// 库后的一轮 backfill——扫缓存缺席的 direct 行（有界
    /// AVATAR_BACKFILL_CAP），逐条经既有 avatar-refresh 队列入队，worker
    /// 端走 getAvatar 读 lane 全链（prepare → 引擎只读调用 → 结果闸 →
    /// service commit 闸 → ConversationChanged 推送）。lossy：队满即弃
    /// （桌面按需拉取是兜底）；UNAVAILABLE 负答由既有幂等清位承载。群行
    /// 不入目标集（群头像走 GroupChanged 事件 kick）。
    async fn kick_avatar_backfill(&self, account_id: &str) {
        let targets = {
            let store = Arc::clone(&self.store);
            let account_id = account_id.to_string();
            tokio::task::spawn_blocking(move || {
                store.avatar_backfill_targets(&account_id, AVATAR_BACKFILL_CAP as u32)
            })
            .await
            .ok()
            .and_then(|result| result.ok())
        };
        let Some(targets) = targets else {
            return;
        };
        if targets.is_empty() {
            return;
        }
        for conversation_id in targets {
            let _ = self
                .avatar_backfill_tx
                .try_send((account_id.to_string(), conversation_id));
        }
    }

    /// Take the §4.123 drain-kick receiver and spawn the single outbox worker
    /// (idempotent, same discipline as `spawn_delivery_receipt_worker`).
    ///
    /// Every pass re-resolves `running_engine()` — a pre-cloned handle goes
    /// stale across watchdog restarts, and the whole point of the queue is to
    /// outlive them. Wake sources: a pass-computed due instant (the schedule
    /// itself), the cap-1 drain kick (engine landed: `start` or
    /// `restart_engine` — the official online-event re-dispatch, hook-for-
    /// hook), and the tick cap. All bounded: at most `OUTBOX_CLAIM_BATCH`
    /// rows leave the queue per pass, and each row's attempt budget lives in
    /// the store face.
    pub fn spawn_outbox_worker(self: &Arc<Self>) {
        let Some(drain) = self
            .outbox_drain_rx
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        else {
            return;
        };
        let Ok(mut slot) = self.outbox_worker.lock() else {
            return;
        };
        if slot.is_some() {
            // A worker is already running (a second spawn after a receiver
            // take race): drop the spare receiver, keep one drain loop.
            return;
        }
        let supervisor = Arc::clone(self);
        *slot = Some(tokio::spawn(async move {
            supervisor.outbox_loop(drain).await;
        }));
    }

    /// The engine-landed immediate-drain kick (§4.123): lossy and bounded —
    /// a full kick channel means a pass is already pending, which is exactly
    /// the semantics the hooks want.
    pub(crate) fn notify_outbox_drain(&self) {
        let _ = self.outbox_drain_tx.try_send(());
    }

    async fn outbox_loop(self: Arc<Self>, mut drain: mpsc::Receiver<()>) {
        loop {
            if let Err(error) = self.outbox_pass().await {
                tracing::warn!(error_class = error.class(), "outbox drain pass failed");
            }
            // Sleep until the earliest schedule still standing (bounded by
            // the tick, floored so a just-scheduled near beat cannot
            // busy-loop), the next drain kick, or the tick itself when the
            // queue is empty.
            let due_at = blocking_service({
                let store = Arc::clone(&self.store);
                move || store.next_retry_due_at().map_err(ServiceError::Store)
            })
            .await
            .ok()
            .flatten();
            let wake = match due_at {
                Some(due_at) => {
                    let now = crate::link::now_ms();
                    Duration::from_millis(due_at.saturating_sub(now))
                        .max(OUTBOX_DUE_WAKE_MIN)
                        .min(OUTBOX_TICK)
                }
                None => OUTBOX_TICK,
            };
            tokio::select! {
                _ = drain.recv() => {}
                _ = sleep(wake) => {}
            }
        }
    }

    /// One drain pass: claim a bounded batch of due retries (the store face
    /// kills window-dead entries and wins the atomic failed→pending flip per
    /// row), rebuild each send from its persisted row, and re-drive it
    /// through the ordinary `dispatch_prepared` funnel — so settlement,
    /// events, and the next schedule all flow exactly the paths a manual
    /// retry uses. An offline engine (NotRunning) aborts the pass BEFORE any
    /// claim: rows stay queued and wait for recovery, which is the official
    /// "offline is not failure" semantics. Per-claim failures are warn-only
    /// and never abort the batch.
    async fn outbox_pass(&self) -> Result<(), ServiceError> {
        let engine = self.running_engine().await?;
        let store = Arc::clone(&self.store);
        let claims = blocking_service(move || {
            store
                .claim_due_retries(crate::link::now_ms(), OUTBOX_CLAIM_BATCH)
                .map_err(ServiceError::Store)
        })
        .await?;
        for claim in claims {
            let prepared = {
                let service = self.service.lock().await;
                match service.prepare_outbox_retry_text(&claim) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        tracing::warn!(
                            error_class = error.class(),
                            "outbox retry claim dropped before dispatch"
                        );
                        continue;
                    }
                }
            };
            if let Err(error) = self.dispatch_prepared(&engine, prepared).await {
                tracing::warn!(error_class = error.class(), "outbox retry dispatch failed");
            }
        }
        Ok(())
    }

    /// One best-effort contacts/groups re-sync per linked account of this
    /// group on every engine landing (boot start or watchdog recovery).
    ///
    /// Batch I aligns this with the official `afterAuthSocketConnect` posture
    /// (`upstream/Signal-Desktop/ts/background.preload.ts:1829-1948`): the
    /// sync chain runs from the background service on every authenticated
    /// connection, not from a UI/RPC trigger. The sync is what materializes
    /// the contract-1.14 conversation skeletons, so an account linked before
    /// that revision — or whose inline link-time sync failed — would
    /// otherwise surface conversations only message by message. It runs in
    /// the background (the host handshake path never waits on the engine) and
    /// the 60-second cache inside the sync folds repeat starts into read-only
    /// no-ops. The running flag keeps one pass at a time; a landing that
    /// arrives while a pass is still running is not double-armed — the
    /// engine's own completion events (and, failing those, the desktop gate)
    /// are the convergence path for that window.
    fn spawn_contacts_resync(&self) {
        let Ok(engine_slot) = self.engine.try_lock() else {
            return;
        };
        let Some(engine) = engine_slot
            .as_ref()
            .filter(|engine| !engine.is_terminal())
            .cloned()
        else {
            return;
        };
        drop(engine_slot);
        self.spawn_contacts_resync_with(engine);
    }

    fn spawn_contacts_resync_with(&self, engine: EngineHandle) {
        if self.contacts_resync_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(mut slot) = self.contacts_resync.lock() else {
            self.contacts_resync_running.store(false, Ordering::Release);
            return;
        };
        let service = Arc::clone(&self.service);
        let group_id = self.group_id.clone();
        let host_events = self.host_events.clone();
        let running = Arc::clone(&self.contacts_resync_running);
        *slot = Some(tokio::spawn(async move {
            // Every early return and panic unwinds through this guard, so one
            // failed landing can never wedge the lane for later ones.
            struct RunningGuard(Arc<AtomicBool>);
            impl Drop for RunningGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _guard = RunningGuard(running);
            // Let the fresh engine settle and any link-time inline sync land
            // first; the 60-second cache then folds the overlap into a no-op.
            sleep(Duration::from_secs(2)).await;
            let accounts = match service.lock().await.list_accounts_in_group(&group_id) {
                Ok(accounts) => accounts,
                Err(error) => {
                    tracing::warn!(
                        error_class = error.class(),
                        "startup contacts resync account listing failed"
                    );
                    return;
                }
            };
            for account in accounts {
                if let Err(error) =
                    sync_contacts_with(&service, &engine, &account.id, &host_events).await
                {
                    tracing::warn!(
                        error_class = error.class(),
                        account_id = %account.id,
                        "startup contacts resync failed"
                    );
                }
            }
        }));
    }

    /// Take the bounded background-sync receiver and spawn its single worker
    /// (idempotent, the delivery-receipt worker's discipline).
    ///
    /// Batch I: the engine's own completion notifications (`storagePull`
    /// both-ok, `initialSyncComplete` manifest-ok) are consumed from the same
    /// broadcast stream whose host frames ride to the desktop, and each kick
    /// runs the ordinary [`RuntimeSupervisor::sync_contacts`] face. The
    /// desktop's manual `contacts.sync` and this worker therefore share one
    /// implementation — the 60 s marker, the 120 s budget, and the one
    /// all-or-nothing upsert transaction — so the two paths cannot drift.
    ///
    /// Failures are host-silent: one retry after
    /// [`BACKGROUND_SYNC_RETRY_DELAY`], then the next completion event or the
    /// desktop gate converges. The worker re-resolves `running_engine()` per
    /// kick, so a watchdog restart never leaves it on a stale handle.
    pub fn spawn_background_sync_worker(self: &Arc<Self>) {
        let Some(receiver) = self
            .background_sync_rx
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        else {
            return;
        };
        let Ok(mut slot) = self.background_sync_worker.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let supervisor = Arc::clone(self);
        *slot = Some(tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some(account_id) = receiver.recv().await {
                match supervisor.sync_contacts(&account_id).await {
                    Ok(outcome) => tracing::info!(
                        account_id = %account_id,
                        contact_count = outcome.contact_count,
                        group_count = outcome.group_count,
                        synced_at = outcome.synced_at,
                        "background contacts sync completed"
                    ),
                    Err(error) => {
                        tracing::warn!(
                            error_class = error.class(),
                            account_id = %account_id,
                            "background contacts sync failed; retrying once"
                        );
                        sleep(BACKGROUND_SYNC_RETRY_DELAY).await;
                        if let Err(error) = supervisor.sync_contacts(&account_id).await {
                            tracing::warn!(
                                error_class = error.class(),
                                account_id = %account_id,
                                "background contacts sync retry failed; the next completion event or the desktop gate converges"
                            );
                        }
                    }
                }
            }
        }));
    }

    // -------------------------------------------------------------------------
    // Link-time history import (contract revision 1.39, §4.38): the kt-engine
    // backup5 archive face. The engine downloads and decrypts in the
    // background after `link.finish`; the connector watches for the file
    // (plus a once-per-start sweep for restarts-in-between) and imports one
    // account at a time under the bounded-batch discipline. The status face
    // is store-only and never touches the engine.
    // -------------------------------------------------------------------------

    /// Once-per-start sweep: import any group account whose archive exists
    /// but has no completed row — the connector may have restarted between
    /// link and import, or a previous attempt failed. Settles first so the
    /// fresh engine's own startup work lands, then imports one account at a
    /// time (the group's single slot).
    fn spawn_history_import_pass(&self) {
        let store = Arc::clone(&self.store);
        let group_id = self.group_id.clone();
        let data_dir = self.config.data_dir.clone();
        let running = Arc::clone(&self.history_import_running);
        let holder = Arc::clone(&self.history_import_holder);
        let abort = Arc::clone(&self.history_import_abort);
        let cancels = Arc::clone(&self.history_import_cancels);
        tokio::spawn(async move {
            // Let the fresh engine settle and any link-time inline sync land
            // before the first import pass claims store batches.
            sleep(Duration::from_secs(5)).await;
            let accounts = match tokio::task::spawn_blocking({
                let store = Arc::clone(&store);
                let group_id = group_id.clone();
                move || store.list_accounts_in_group(&group_id)
            })
            .await
            {
                Ok(Ok(accounts)) => accounts,
                _ => {
                    tracing::warn!("history import sweep account listing failed");
                    return;
                }
            };
            for account in accounts {
                let probe = tokio::task::spawn_blocking({
                    let store = Arc::clone(&store);
                    let data_dir = data_dir.clone();
                    let cancels = Arc::clone(&cancels);
                    let account_id = account.id.clone();
                    move || probe_history_import(&store, &data_dir, &account_id, &cancels)
                })
                .await
                .unwrap_or(HistoryImportProbe::Done);
                let HistoryImportProbe::Ready(job) = probe else {
                    continue;
                };
                // A busy slot skips this account: the next start (or the link
                // watcher's tick for freshly linked accounts) retries.
                let _ = claim_and_run_history_import(
                    Arc::clone(&running),
                    Arc::clone(&holder),
                    Arc::clone(&abort),
                    Arc::clone(&store),
                    job,
                )
                .await;
            }
        });
    }

    // -------------------------------------------------------------------------
    // Unknown-outcome reconciliation (contract revision 1.179, §4.179): the
    // engine's own thread_messages store is the local truth of "the engine
    // really dispatched this" (its outgoing rows land only AFTER a dispatch
    // call returns success), exposed through the read-only engine
    // `lookupOutgoingDispatch` face. When an engine lands Running, this pass
    // asks it, row by row, about this group's unsettled outgoing rows
    // (status='unknown' — the §4.172 anti-double-delivery residue an engine
    // restart window leaves behind) and settles each with a guarded store
    // write: dispatched → sent (sent_at kept), not-found → failed (provably
    // never sent, so the §4.172 retryText gate re-opens with zero
    // double-delivery risk). Warn-only everywhere: an engine error leaves
    // the row unknown (without the engine's truth nothing is claimed) and
    // never blocks startup.
    // -------------------------------------------------------------------------

    /// Arm the startup reconciliation pass. Best-effort and idempotent: the
    /// settles are guarded (`WHERE status='unknown'`), so a re-run — a
    /// watchdog-recovered engine, a later start — converges to no-ops over
    /// already-settled rows and never stomps a concurrently rearmed retry.
    async fn spawn_unknown_outcome_reconcile(&self) {
        // O1 note: this used `try_lock`, so an engine mutex that happened to
        // be held at landing time (the contacts-resync pass grabs it in the
        // same instant) silently skipped the ONLY reconciliation arming until
        // the next engine landing. Awaiting the lock costs nothing here — the
        // caller has already released its own guard — and keeps the pass from
        // being a scheduling race.
        let engine_slot = self.engine.lock().await;
        let Some(engine) = engine_slot
            .as_ref()
            .filter(|engine| !engine.is_terminal())
            .cloned()
        else {
            return;
        };
        drop(engine_slot);
        let service = Arc::clone(&self.service);
        let store = Arc::clone(&self.store);
        let group_id = self.group_id.clone();
        let host_events = self.host_events.clone();
        tokio::spawn(async move {
            // Let the fresh engine settle first (its own startup work and the
            // link-time inline sync land; the contacts-resync settle beat).
            sleep(UNKNOWN_RECONCILE_SETTLE_DELAY).await;
            for _ in 0..UNKNOWN_RECONCILE_MAX_BATCHES {
                let batch = match blocking_service({
                    let store = Arc::clone(&store);
                    let group_id = group_id.clone();
                    move || {
                        store
                            .unsettled_unknown_outgoing_sends(&group_id, UNKNOWN_RECONCILE_BATCH)
                            .map_err(ServiceError::Store)
                    }
                })
                .await
                {
                    Ok(batch) => batch,
                    Err(error) => {
                        tracing::warn!(
                            error_class = error.class(),
                            "unknown-outcome reconciliation backlog query failed"
                        );
                        return;
                    }
                };
                if batch.is_empty() {
                    return;
                }
                let drained = (batch.len() as u32) < UNKNOWN_RECONCILE_BATCH;
                for row in batch {
                    // The row's own conversation addressing, the same
                    // `set_upstream_target` semantics the original send used:
                    // direct = recipient peer_key, group = groupId master key.
                    let mut params = json!({
                        "account": row.signal_account,
                        "sentTimestamp": row.sent_at,
                        // The engine's hard tolerance cap: recall over
                        // precision — the unknown row's sent_at is the
                        // prepare-time stamp while the engine row's ts is the
                        // dispatch envelope timestamp (queueing + any
                        // attachment upload in between); §4.179 records the
                        // trade-off.
                        "toleranceMs": UNKNOWN_RECONCILE_TOLERANCE_MS,
                    });
                    if row.conversation_kind == "group" {
                        params["groupId"] = json!(row.peer_key);
                    } else {
                        params["recipient"] = json!(row.peer_key);
                    }
                    let answer = engine
                        .call("lookupOutgoingDispatch", params, CallClass::ReadOnly)
                        .await;
                    let dispatched = match answer {
                        Ok(result) => match result.get("dispatched").and_then(Value::as_bool) {
                            Some(dispatched) => dispatched,
                            None => {
                                tracing::warn!(
                                    "unknown-outcome reconciliation answer lost its dispatched face; row stays unknown"
                                );
                                continue;
                            }
                        },
                        // The engine died or the call never landed: without
                        // the engine's truth nothing is claimed — the row
                        // stays unknown and the next engine landing re-runs.
                        Err(EngineError::NotRunning | EngineError::Exited) => {
                            tracing::warn!(
                                "engine left before the unknown-outcome reconciliation drained; the next landing re-runs"
                            );
                            return;
                        }
                        Err(error) => {
                            // Per-row failure (unregistered account,
                            // unresolvable peer, transport): warn and keep
                            // draining the rest of the batch.
                            tracing::warn!(
                                error_class = ServiceError::from(error).class(),
                                "unknown-outcome reconciliation probe failed; row stays unknown"
                            );
                            continue;
                        }
                    };
                    let events = {
                        let service = service.lock().await;
                        service.settle_reconciled_unknown(&row.id, dispatched)
                    };
                    match events {
                        Ok(events) => {
                            for event in events {
                                let _ = host_events.send(event);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                error_class = error.class(),
                                "unknown-outcome reconciliation settle failed; row stays unknown"
                            );
                        }
                    }
                }
                if drained {
                    return;
                }
            }
            tracing::warn!(
                "unknown-outcome reconciliation pass hit its batch ceiling; the next engine landing continues"
            );
        });
    }

    /// §4.190 ⑥: fetch each account's configuration once per engine landing
    /// and mirror the readReceipts flag onto the account row — the receipt
    /// gate's local input (the official `shouldDropReceipt` privacy
    /// symmetry; the engine's `getConfiguration` is the truth source, the
    /// §4.87 sync and the §4.45 write face are the incremental writers).
    /// Best-effort and idempotent: an engine that never answers leaves the
    /// flag at its previous value (never-answered stays the honest unknown,
    /// which the gate reads as off — the official falsy parity), a transport
    /// error warns and moves on, and nothing here blocks startup. The
    /// settle delay lets the fresh engine finish its own startup work first
    /// (the contacts-resync and reconcile beats).
    fn spawn_configuration_gate_sync(&self) {
        let Ok(engine_slot) = self.engine.try_lock() else {
            return;
        };
        let Some(engine) = engine_slot
            .as_ref()
            .filter(|engine| !engine.is_terminal())
            .cloned()
        else {
            return;
        };
        drop(engine_slot);
        let store = Arc::clone(&self.store);
        let group_id = self.group_id.clone();
        tokio::spawn(async move {
            sleep(UNKNOWN_RECONCILE_SETTLE_DELAY).await;
            let accounts = match blocking_service({
                let store = Arc::clone(&store);
                let group_id = group_id.clone();
                move || {
                    store
                        .list_accounts_in_group(&group_id)
                        .map_err(ServiceError::Store)
                }
            })
            .await
            {
                Ok(accounts) => accounts,
                Err(error) => {
                    tracing::warn!(
                        error_class = error.class(),
                        "configuration gate sync could not list accounts"
                    );
                    return;
                }
            };
            for summary in accounts {
                // The summary masks the address; the engine wants the real
                // one, so the row answers it (the same account_by_id walk the
                // control plane's fallback runs).
                let Ok(Some(account)) = store.account_by_id(&summary.id) else {
                    continue;
                };
                let answer = engine
                    .call(
                        "getConfiguration",
                        json!({ "account": account.signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await;
                match answer {
                    Ok(result) => {
                        let read_receipts = result.get("readReceipts").and_then(Value::as_bool);
                        if let Err(error) =
                            store.set_account_read_receipts(&account.id, read_receipts)
                        {
                            tracing::warn!(
                                error_class = ServiceError::Store(error).class(),
                                "configuration gate sync mirror write failed"
                            );
                        }
                    }
                    Err(EngineError::NotRunning | EngineError::Exited) => return,
                    Err(error) => {
                        tracing::warn!(
                            error_class = ServiceError::from(error).class(),
                            "configuration gate sync probe failed; the flag keeps its last answer"
                        );
                    }
                }
            }
        });
    }

    /// After a `link.finish`, watch for the archive the engine is
    /// downloading in the background (§4.38): poll every few seconds for at
    /// most [`crate::history_import::LINK_WAIT_MS`], import when the file
    /// appears. A busy group slot retries on the next tick. Best-effort: the
    /// import never fails the link flow.
    fn spawn_history_import_watch(&self, account_id: String) {
        let store = Arc::clone(&self.store);
        let data_dir = self.config.data_dir.clone();
        let running = Arc::clone(&self.history_import_running);
        let holder = Arc::clone(&self.history_import_holder);
        let abort = Arc::clone(&self.history_import_abort);
        let cancels = Arc::clone(&self.history_import_cancels);
        tokio::spawn(async move {
            let deadline =
                Instant::now() + Duration::from_millis(crate::history_import::LINK_WAIT_MS);
            loop {
                if Instant::now() >= deadline {
                    tracing::info!(
                        account_id = %account_id,
                        "history archive did not appear within the link-time window"
                    );
                    return;
                }
                sleep(Duration::from_secs(5)).await;
                let probe = tokio::task::spawn_blocking({
                    let store = Arc::clone(&store);
                    let data_dir = data_dir.clone();
                    let cancels = Arc::clone(&cancels);
                    let account_id = account_id.clone();
                    move || probe_history_import(&store, &data_dir, &account_id, &cancels)
                })
                .await
                .unwrap_or(HistoryImportProbe::Done);
                match probe {
                    HistoryImportProbe::Waiting => continue,
                    HistoryImportProbe::Done => return,
                    HistoryImportProbe::Ready(job) => {
                        if claim_and_run_history_import(
                            Arc::clone(&running),
                            Arc::clone(&holder),
                            Arc::clone(&abort),
                            Arc::clone(&store),
                            job,
                        )
                        .await
                        {
                            return;
                        }
                        // Slot busy: the next tick retries.
                    }
                }
            }
        });
    }

    /// Whether the group's import slot is held by THIS account's run (the
    /// `processing` stage must not borrow another account's live pass — the
    /// group slot is single-flight but a crashed run's stale `running` row on
    /// a second account is not a live pass, contract 1.53).
    fn history_import_pass_active_for(&self, account_id: &str) -> bool {
        self.history_import_running.load(Ordering::Acquire)
            && self
                .history_import_holder
                .lock()
                .map(|holder| holder.as_deref() == Some(account_id))
                .unwrap_or(false)
    }

    /// history.importStatus (contract revision 1.39, §4.38): the honest
    /// minimal projection the desktop polls — store-first, never the network.
    /// Since contract 1.53 a `running` row also consults the engine's
    /// transfer-download snapshot (one bounded read-only call) so the
    /// Download stage can report byte progress. Since contract 1.148 (§4.146)
    /// a wait-window `pending` with no archive consults the same snapshot
    /// once: the engine's failure terminal state resolves the wait at once
    /// (`no_archive` onto the existing NO_ARCHIVE information class, any
    /// other code onto an immediately-landed persisted failed row) instead of
    /// hanging `pending` until the window expires. Since contract 1.166
    /// (§4.164) that same consult also projects the snapshot's live
    /// downloading face onto the pending answer — the same `progress` object
    /// the running face carries, failure terminal keeping priority — so the
    /// desktop watches the real transfer across the whole wait window instead
    /// of static copy; every other state is store/disk-only exactly as
    /// before.
    pub async fn history_import_status(&self, account_id: String) -> Result<Value, ServiceError> {
        let store = Arc::clone(&self.store);
        let data_dir = self.config.data_dir.clone();
        let cancels = Arc::clone(&self.history_import_cancels);
        let row_account_id = account_id.clone();
        let (mut status, signal_account) = blocking_service(move || {
            // The engine face is consulted only where it can change the
            // answer: a `running` row (byte progress) and a wait-window
            // `pending` (failure consumption plus the live download face,
            // §4.164). The projection's consult flag names the second: a
            // disk-`pending` (archive present, the sweep or watcher about to
            // claim it) never consults — a stale terminal snapshot must not
            // land a failed row beside an archive the connector is about to
            // import, nor decorate it with stale progress. Every other
            // state is already terminal or store/disk-derived.
            let (status, consult_engine) =
                history_import_status_projection(&store, &data_dir, &cancels, &row_account_id)?;
            let signal_account = match (status["state"].as_str(), consult_engine) {
                (Some("running"), _) | (Some("pending"), true) => store
                    .account_by_id(&row_account_id)
                    .ok()
                    .flatten()
                    .map(|account| account.signal_account),
                _ => None,
            };
            Ok((status, signal_account))
        })
        .await?;
        // Download-stage progress: only while the row says `running`, and
        // only if this group's engine is answering. A down engine reads as no
        // snapshot — the projection stays honest without the bytes rather
        // than guessing a state the store does not hold. When the engine
        // answers "no download in flight" but this group's own NDJSON import
        // pass holds the slot, the stage is `processing` (the official
        // Process stage renders copy, not numbers). Neither signal present:
        // the pre-1.53 shape, no progress invented.
        if status["state"] == "running" {
            let mut downloading = None;
            if let Some(signal_account) = signal_account.as_deref()
                && let Ok(engine) = self.running_engine().await
                && let Ok(snapshot) = engine
                    .call(
                        "transfer.downloadStatus",
                        json!({ "account": signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await
                && let Some(progress) = import_progress_from_engine_snapshot(&snapshot)
            {
                downloading = Some(progress);
            }
            let stage = compose_import_progress(
                downloading,
                self.history_import_pass_active_for(&account_id),
            );
            if let (Some(progress), Some(object)) = (stage, status.as_object_mut()) {
                object.insert("progress".to_owned(), progress);
            }
        }
        // Failure consumption (contract 1.148, §4.146) with the live-face
        // projection (contract 1.166, §4.164) riding the same single bounded
        // consult: a wait-window `pending` reads the engine's snapshot once.
        // A terminal `errorCode` keeps priority — `no_archive` is the
        // existing information class (the phone transferred nothing — never
        // a failed row), any other code lands an honest persisted failed row
        // through one atomic insert-or-ignore and renders it (the code rides
        // verbatim: the engine owns the word list, the connector adds no
        // semantics). A snapshot without a consumable code is the live
        // transfer: the same `progress` face the running state carries, so
        // the desktop sees the real state across the whole wait window. A
        // down engine, a malformed code, a malformed byte shape, or an
        // absent snapshot keeps the honest bare pending — no progress
        // invented.
        if status["state"] == "pending"
            && let Some(signal_account) = signal_account
            && let Ok(engine) = self.running_engine().await
            && let Ok(snapshot) = engine
                .call(
                    "transfer.downloadStatus",
                    json!({ "account": signal_account }),
                    CallClass::ReadOnly,
                )
                .await
        {
            if let Some(code) = engine_import_failure_code(&snapshot) {
                if code == IMPORT_FAILURE_NO_ARCHIVE {
                    status = json!({
                        "accountId": account_id,
                        "state": "unavailable",
                        "reason": "no-archive",
                    });
                } else {
                    let store = Arc::clone(&self.store);
                    let row_account_id = account_id.clone();
                    let code = code.to_string();
                    let row = blocking_service(move || {
                        store
                            .land_history_import_failure(
                                &row_account_id,
                                &code,
                                crate::link::now_ms(),
                            )
                            .map_err(ServiceError::from)
                    })
                    .await?;
                    status = serde_json::to_value(row)
                        .map_err(|_| ServiceError::Store(StoreError::Unavailable(None)))?;
                }
            } else if let Some(progress) = import_progress_from_engine_snapshot(&snapshot)
                && let Some(object) = status.as_object_mut()
            {
                object.insert("progress".to_owned(), progress);
            }
        }
        Ok(status)
    }

    /// history.importCancel (contract revision 1.148, §4.146): the desktop's
    /// cancel-sync stops the import without unbinding. The marker registers
    /// first (the link watcher exits on its next tick, the eligibility probe
    /// refuses the account, the status face answers
    /// `unavailable`/`cancelled`), a live pass for THIS account gets its
    /// cooperative abort flag flipped and its still-`running` row flipped to
    /// `failed`/`cancelled` through the conditional store write (never
    /// regressing a completed row, never spending the attempt budget), and
    /// the frozen engine contract (`history.importCancel {account}` →
    /// `{"cancelled": bool}`) rides out best-effort: an engine error of any
    /// flavor answers `cancelled: false` and never retries — the
    /// connector-side half has already taken effect, and the unknown-outcome
    /// red line forbids guessing. Idempotent in every state.
    pub async fn history_import_cancel(&self, account_id: String) -> Result<Value, ServiceError> {
        let store = Arc::clone(&self.store);
        let cancels = Arc::clone(&self.history_import_cancels);
        let abort = Arc::clone(&self.history_import_abort);
        let holder = Arc::clone(&self.history_import_holder);
        let row_account_id = account_id.clone();
        let signal_account = blocking_service(move || {
            let account = store
                .account_by_id(&row_account_id)?
                .ok_or(ServiceError::Store(StoreError::AccountNotFound))?;
            if let Ok(mut set) = cancels.lock() {
                set.insert(row_account_id.clone());
            }
            // Only THIS account's live pass gets the abort flag: the holder
            // names the slot's owner (contract 1.53), and the flag resets at
            // every claim, so a stale flag can never kill the next pass.
            let live = holder
                .lock()
                .map(|slot| slot.as_deref() == Some(row_account_id.as_str()))
                .unwrap_or(false);
            if live {
                abort.store(true, Ordering::Release);
            }
            // The immediate ledger answer while the aborted pass winds down.
            // The `WHERE state='running'` guard is the race discipline: a
            // pass that already completed never regresses.
            let _ = store.cancel_running_history_import(&row_account_id, crate::link::now_ms());
            Ok(account.signal_account)
        })
        .await?;
        let mut cancelled = false;
        if let Ok(engine) = self.running_engine().await {
            cancelled = engine
                .call(
                    "history.importCancel",
                    json!({ "account": signal_account }),
                    CallClass::Mutating,
                )
                .await
                .ok()
                .and_then(|result| result.get("cancelled").and_then(Value::as_bool))
                .unwrap_or(false);
        }
        // The post-cancel state the desktop would read from importStatus: the
        // row's truth when one survived, else the marker's
        // `unavailable`/`cancelled` — never `pending` after a cancel.
        let store = Arc::clone(&self.store);
        let row_account_id = account_id.clone();
        let state = blocking_service(move || {
            Ok(match store.history_import_row(&row_account_id)? {
                Some(row) => row.state,
                None => "unavailable".to_owned(),
            })
        })
        .await?;
        Ok(json!({
            "accountId": account_id,
            "cancelled": cancelled,
            "state": state,
        }))
    }

    /// history.importRetry (contract revision 1.53, §4.38): clear the
    /// account's `failed` import row and re-arm the orchestration — the
    /// archive on disk returns to `pending` and the sweep (next engine start)
    /// or the link watcher (fresh spawn) picks it up. Mutating face: the
    /// account-scoped write-lane mutex and delete drain barrier serialize it
    /// against every other account mutation (host `acquire`); the store work
    /// runs on the blocking pool. A non-`failed` row is NOT_RETRYABLE; no
    /// archive on the engine face is NO_ARCHIVE. Since contract 1.148
    /// (§4.146) a successful re-arm also clears the cancel marker: an
    /// explicit retry is the user intent that supersedes the cancel.
    pub async fn history_import_retry(&self, account_id: String) -> Result<Value, ServiceError> {
        let store = Arc::clone(&self.store);
        let data_dir = self.config.data_dir.clone();
        let row_account_id = account_id.clone();
        let result = blocking_service(move || {
            history_import_retry_projection(&store, &data_dir, &row_account_id)
        })
        .await?;
        if result.get("armed").and_then(Value::as_bool) == Some(true)
            && let Ok(mut set) = self.history_import_cancels.lock()
        {
            set.remove(&account_id);
        }
        Ok(result)
    }

    /// history.attachmentDownload (contract revision 1.57, §4.38 step 3):
    /// walk one stored transit pointer face end to end — stream the CDN body
    /// to a temp file under hard byte bounds, gate the ciphertext layer
    /// (terminal HMAC + whole-body SHA-256 `digest`), decrypt
    /// (AES-256-CBC / PKCS7 / log-pad trim), gate the plaintext hash, and
    /// atomically land the plaintext where `messages.attachments.open`
    /// resolves it. Mutating, send lane behind the reaction-class write-lane
    /// mutex and delete barrier (like importRetry). Every download/verify
    /// failure is terminal — no auto-retry (§4.38 honest degradation; a retry
    /// is the caller's fresh call). Local-IO failures keep the established
    /// retryable UPSTREAM_ERROR face.
    pub async fn history_attachment_download(
        &self,
        params: crate::service::HistoryAttachmentDownloadParams,
    ) -> Result<Value, ServiceError> {
        self.run_attachment_download_chain(|service| {
            service.prepare_history_attachment_download(
                &params.account_id,
                &params.conversation_id,
                &params.message_id,
                &params.attachment_id,
            )
        })
        .await
    }

    /// attachments.download (contract revision 1.61, §4.54): the §4.54
    /// addressing face onto the same chain as
    /// [`Self::history_attachment_download`] — the prepare half resolves the
    /// descriptor positionally and walks the live/import locator ladder, the
    /// network and crypto halves are the 1.57 machine unchanged. Mutating,
    /// send lane behind the reaction-class write-lane mutex and delete
    /// barrier; every download/verify failure terminal; idempotent on an
    /// already-present file.
    pub async fn attachment_download(
        &self,
        params: crate::service::AttachmentDownloadParams,
    ) -> Result<Value, ServiceError> {
        self.run_attachment_download_chain(|service| {
            service.prepare_attachment_download(
                &params.account_id,
                &params.conversation_id,
                &params.message_id,
                params.attachment_index,
            )
        })
        .await
    }

    /// attachments.requestBackfill (contract revision 1.175, §4.175): the
    /// request half of the official attachment-backfill loop. The
    /// deterministic prepare runs inside the service lock (id ladder, row
    /// resolution, the official target triple), then the engine's
    /// `requestAttachmentBackfill` fires on the send lane. The answer is the
    /// receipt-class posture: `sent` when the engine confirmed the write,
    /// `unknown` when the engine is unreachable or refused — the desktop
    /// treats either as fire-and-forget (its bounded retry loop re-asks the
    /// download; a duplicate request the primary already answered is
    /// harmless, the official #pendingRequests de-dup posture). The
    /// response itself arrives asynchronously as the
    /// `syncMessage.attachmentBackfillResponse` consume arm and merges the
    /// fresh pointers into the row's live-locator column.
    pub async fn request_attachment_backfill(
        &self,
        params: crate::service::AttachmentBackfillRequestParams,
    ) -> Result<&'static str, ServiceError> {
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_request_attachment_backfill(&params)?
        };
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(_) => return Ok("unknown"),
        };
        match engine
            .call("requestAttachmentBackfill", prepared, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(_) => Ok("unknown"),
        }
    }

    /// stories.downloadAttachment (contract revision 1.86, §4.71): the
    /// story-anchored face onto the same chain as
    /// [`Self::attachment_download`] — the prepare half gates the
    /// caller-supplied pointer's wire shape (the §4.54 ingest caps mirrored)
    /// and stages the landing, the network and crypto halves are the 1.57
    /// machine unchanged with the `TransitFace::build` crypto-shape decode
    /// still ahead of any network traffic. Mutating, send lane behind the
    /// reaction-class write-lane mutex and delete barrier; every
    /// download/verify failure terminal; idempotent on an already-present
    /// file.
    pub async fn story_attachment_download(
        &self,
        params: crate::service::StoryAttachmentDownloadParams,
    ) -> Result<Value, ServiceError> {
        self.run_attachment_download_chain(|service| {
            service.prepare_story_attachment_download(&params)
        })
        .await
    }

    /// stories.openAttachment (contract revision 1.86, §4.71): the handle
    /// mint over an already-landed story attachment — the
    /// [`Self::open_media`] machine without the row addressing (stories
    /// land in no conversation row). Read lane, no engine touch.
    pub async fn story_open_attachment(
        &self,
        params: crate::service::StoryOpenAttachmentParams,
    ) -> Result<MediaOpenView, ServiceError> {
        self.service
            .lock()
            .await
            .open_story_attachment_handle(&params.account_id, &params.attachment_id)
    }

    /// The shared download chain: the deterministic prepare half runs inside
    /// the service lock, the streaming network half runs on the supervisor
    /// (§4.38 step 3 machine verbatim).
    async fn run_attachment_download_chain(
        &self,
        prepare: impl FnOnce(
            &crate::service::ConnectorService,
        ) -> Result<crate::service::PreparedHistoryDownload, ServiceError>,
    ) -> Result<Value, ServiceError> {
        // The staged, locally-verified inputs: capability gate, id ladder,
        // descriptor index, pointer face, destination paths. Everything
        // deterministic answers here, before any network traffic.
        let prepared = prepare(&*self.service.lock().await)?;
        let (locator, descriptor_size, target, temp_path, plaintext_path) = match prepared {
            // Idempotent dedup: the file already exists (an earlier call or
            // the engine's own live download). The measured size is the
            // honest answer; the CDN is never re-asked.
            PreparedHistoryDownload::AlreadyPresent { size_bytes } => {
                return Ok(
                    serde_json::to_value(HistoryAttachmentDownloadView { size_bytes })
                        .unwrap_or(Value::Null),
                );
            }
            PreparedHistoryDownload::Ready {
                locator,
                descriptor_size,
                target,
                temp_path,
                plaintext_path,
            } => (locator, descriptor_size, target, temp_path, plaintext_path),
        };
        // Fail-closed pointer decode (official gate parity): the face's
        // key/cdn/integrity/size fields, the URL assembly, and the body
        // bounds — before the sink opens. Cheap, but the locator strings
        // (bounded) move into a scoped thread anyway so nothing borrows
        // across the await below.
        let cdn_base_override = self.config.history_cdn_base.clone();
        let face = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    crate::history_attachment::TransitFace::build(
                        &locator,
                        descriptor_size,
                        cdn_base_override.as_deref(),
                    )
                })
                .join()
                .unwrap_or(Err(crate::history_attachment::DownloadFailure::Io))
        })
        .map_err(map_download_failure)?;
        let body_max = face.body_max_bytes();
        let url = face.url.clone();

        // Stream the body. The service lock is released for the network half
        // (the media chain answers stay serialized at dispatch; the temp
        // names are unique so two chains cannot collide). The launcher's
        // SOCKS route from the process environment (contract revision 1.98,
        // §4.38 step 3) rides this client too: the CDN GET shares the exact
        // route the engine's own transport takes.
        let env_proxy = std::env::var(crate::doctor::SOCKS_PROXY_ENV).ok();
        let client = attachment_download_client(env_proxy.as_deref())?;
        let response = client.get(&url).send().await.map_err(|_| {
            map_download_failure(crate::history_attachment::DownloadFailure::Network)
        })?;
        if !response.status().is_success() {
            return Err(map_download_failure(
                crate::history_attachment::DownloadFailure::Http(response.status().as_u16()),
            ));
        }
        let mut sink = crate::history_attachment::BodySink::create(&temp_path, body_max)
            .map_err(map_download_failure)?;
        sink.set_mac_key(&face.mac_key);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
            let chunk = chunk.map_err(|_| {
                map_download_failure(crate::history_attachment::DownloadFailure::Network)
            })?;
            sink.push(&chunk).map_err(|failure| {
                cleanup_temp(&temp_path);
                map_download_failure(failure)
            })?;
        }
        let finished = sink.finish().map_err(|failure| {
            cleanup_temp(&temp_path);
            map_download_failure(failure)
        })?;
        // Ciphertext gates: terminal HMAC, then the whole-body digest face.
        finished.verify_ciphertext(&face).map_err(|failure| {
            cleanup_temp(&temp_path);
            map_download_failure(failure)
        })?;
        // The decrypt pass is blocking file work — off the async workers.
        let decrypt = {
            let temp_path = temp_path.clone();
            let plaintext_path = plaintext_path.clone();
            let face = face.clone();
            tokio::task::spawn_blocking(move || {
                crate::history_attachment::decrypt_to_file(&temp_path, &plaintext_path, &face)
            })
            .await
            .unwrap_or(Err(crate::history_attachment::DownloadFailure::Io))
        };
        let size_bytes = decrypt.map_err(|failure| {
            cleanup_temp(&temp_path);
            cleanup_temp(&plaintext_path);
            map_download_failure(failure)
        })?;
        // Land the plaintext atomically; the ciphertext temp never outlives
        // the chain, win or lose.
        std::fs::remove_file(&temp_path).map_err(|_| ServiceError::Io)?;
        std::fs::rename(&plaintext_path, &target).map_err(|_| {
            cleanup_temp(&plaintext_path);
            ServiceError::Io
        })?;
        Ok(
            serde_json::to_value(HistoryAttachmentDownloadView { size_bytes })
                .unwrap_or(Value::Null),
        )
    }

    pub fn subscribe_engine(&self) -> broadcast::Receiver<EngineEvent> {
        self.events.subscribe()
    }
    pub fn subscribe_host(&self) -> broadcast::Receiver<HostSideEvent> {
        self.host_events.subscribe()
    }

    pub async fn status(&self) -> EngineStatus {
        self.engine
            .lock()
            .await
            .as_ref()
            .map(EngineHandle::status)
            .unwrap_or(EngineStatus {
                state: EngineState::Stopped,
                pid: None,
                rss_bytes: None,
                resource_pressure: false,
            })
    }

    /// The read-only per-group snapshot the `runtime.doctor` face (§4.79)
    /// consumes: the launcher-config identity plus the supervised engine
    /// status and a live engine handle when one exists. Read-only by
    /// contract — it never starts, stops, or writes anything; the doctor's
    /// engine method probes ride the handle's read-only call path.
    pub(crate) async fn doctor_face(&self) -> crate::doctor::DoctorGroupFace {
        // The credentials probe target first — the same any-account-of-this-
        // group rule the watchdog ping uses, taken before the engine mutex so
        // the store read never holds it across SQLite I/O. The number rides
        // only into the engine call params — it never enters the report.
        let probe_account = self
            .service
            .lock()
            .await
            .any_signal_account_number_in_group(&self.group_id)
            .ok()
            .flatten();
        let contract = self.engine_contract_state().await;
        let slot = self.engine.lock().await;
        let live = slot.as_ref().filter(|engine| !engine.is_terminal());
        crate::doctor::DoctorGroupFace {
            data_dir: self.config.data_dir.clone(),
            status: slot
                .as_ref()
                .map(EngineHandle::status)
                .unwrap_or(EngineStatus {
                    state: EngineState::Stopped,
                    pid: None,
                    rss_bytes: None,
                    resource_pressure: false,
                }),
            engine: live.cloned(),
            probe_account,
            contract,
        }
    }

    /// Install the pool's admission gate (contract 1.291, §4.277 C). Every
    /// `start` on a path the pool did not open itself - above all the watchdog's
    /// crash restart - then asks this gate before spawning an engine.
    pub fn set_start_gate(&self, gate: Arc<dyn EngineStartGate>) {
        *self
            .start_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(gate);
    }

    fn start_gate(&self) -> Option<Arc<dyn EngineStartGate>> {
        self.start_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Refuse this spawn when the pool's gate does, and say why in the log
    /// channel with the closed literal (never a path, never key material).
    async fn admit_start(&self) -> Result<(), EngineError> {
        let Some(gate) = self.start_gate() else {
            return Ok(());
        };
        match gate.admit_engine_start().await {
            Ok(()) => Ok(()),
            Err(code) => {
                tracing::warn!(
                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                    group_id = %self.group_id,
                    store_gate = code,
                    "engine start deferred by the store gate; this account keeps no engine until the pass lands"
                );
                Err(EngineError::StoreDeferred { code })
            }
        }
    }

    /// Start this slot's engine, consulting the pool's store gate first. The
    /// terminal unlink is judged **before** every other gate (contract 1.275):
    /// a store migration is never run for a device that cannot be served.
    pub async fn start(&self) -> Result<EngineStatus, EngineError> {
        self.terminal_unlink_guard()?;
        self.admit_start().await?;
        self.start_after_store_gate().await
    }

    /// Start this slot's engine for a caller that has **just cleared the store
    /// gate itself** (the pool's migration pass, and the pool's own gated
    /// paths). Using this from anywhere else would re-open the bypass the gate
    /// exists to close, so it is deliberately a separate, named entry point.
    pub async fn start_after_store_gate(&self) -> Result<EngineStatus, EngineError> {
        // A caller that cleared the store gate itself (the pool's wake and
        // migration pass) still may not revive a credential the account holder
        // already unlinked: the slot is terminal until a fresh link lands.
        self.terminal_unlink_guard()?;
        let mut slot = self.engine.lock().await;
        if let Some(fault) = self.latched_contract_fault().await {
            tracing::warn!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                engine_version = fault.engine_version.as_deref().unwrap_or("unknown"),
                contract_reason = fault.reason.as_str(),
                "engine start refused: the contract mismatch is latched for this process"
            );
            return Err(EngineError::ContractMismatch(fault));
        }
        if let Some(engine) = slot.as_ref()
            && !engine.is_terminal()
        {
            return Err(EngineError::Backpressure);
        }
        let engine = EngineHandle::start(
            self.config.clone(),
            self.events.clone(),
            self.receive_ingress.clone(),
        )
        .await?;
        // O1: the handshake is the gate in front of every account-shaped
        // side effect. A refused engine is killed here and never lands in the
        // slot, so no resync/import/reconcile pass can run against it.
        if let Err(error) = self.admit_engine(&engine).await {
            refuse_started_engine(&engine, &error).await;
            return Err(error);
        }
        let status = engine.status();
        *slot = Some(engine);
        drop(slot);
        if status.state == EngineState::Running {
            self.spawn_contacts_resync();
            self.spawn_history_import_pass();
            // §4.179: the engine landed — reconcile this group's unsettled
            // unknown-outcome rows against the engine's own dispatch ledger
            // (best-effort, idempotent, warn-only).
            self.spawn_unknown_outcome_reconcile().await;
            // §4.190 ⑥: the engine landed — fetch each account's
            // configuration and mirror the readReceipts gate flag
            // (best-effort, idempotent, warn-only).
            self.spawn_configuration_gate_sync();
            // §4.123: engine landed — the offline queue drains now instead of
            // waiting out the tick (the official online-event re-dispatch).
            self.notify_outbox_drain();
        }
        Ok(status)
    }

    pub async fn stop(&self) -> Result<EngineStatus, EngineError> {
        let engine = self
            .engine
            .lock()
            .await
            .take()
            .ok_or(EngineError::NotRunning)?;
        self.service.lock().await.clear_link();
        *self.active_link_finish.lock().await = None;
        engine.shutdown().await?;
        Ok(EngineStatus {
            state: EngineState::Stopped,
            pid: None,
            rss_bytes: None,
            resource_pressure: false,
        })
    }

    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.shutdown_within(None).await
    }

    /// Bounded graceful stop (engine-pool F7): the caller's remaining global
    /// budget replaces the engine's own grace when it is smaller. On expiry
    /// the child is **force-killed** while this function still owns the
    /// handle — dropping the outer future instead would leave the child alive
    /// behind the actor's own handle clone.
    pub async fn shutdown_within(&self, budget: Option<Duration>) -> Result<(), EngineError> {
        let engine = self.engine.lock().await.take();
        self.service.lock().await.clear_link();
        *self.active_link_finish.lock().await = None;
        let Some(engine) = engine else {
            return Ok(());
        };
        let Some(budget) = budget else {
            return engine.shutdown().await;
        };
        match tokio::time::timeout(budget, engine.shutdown()).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                    group_id = %self.group_id,
                    budget_ms = budget.as_millis().min(u64::MAX as u128) as u64,
                    "engine shutdown exceeded the pool budget; killing the engine process"
                );
                if let Err(error) = engine.force_kill().await {
                    tracing::warn!(
                        account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                        error_class = ?error.kind(),
                        "engine force kill failed"
                    );
                }
                Ok(())
            }
        }
    }

    async fn running_engine(&self) -> Result<EngineHandle, EngineError> {
        self.engine
            .lock()
            .await
            .as_ref()
            .filter(|engine| !engine.is_terminal())
            .cloned()
            .ok_or(EngineError::NotRunning)
    }

    /// The latched O1 contract fault, if this slot has refused an engine.
    pub(crate) async fn latched_contract_fault(
        &self,
    ) -> Option<crate::engine_contract::EngineContractFault> {
        self.engine_contract.lock().await.fault.clone()
    }

    /// The whole handshake state (doctor/metrics): last served verdict or the
    /// latched fault.
    pub(crate) async fn engine_contract_state(
        &self,
    ) -> crate::engine_contract::EngineContractState {
        self.engine_contract.lock().await.clone()
    }

    /// O1: run the contract handshake for a freshly spawned engine and record
    /// its verdict. The caller owns the engine and must refuse it on error:
    /// nothing account-shaped may run against an engine this gate did not
    /// admit.
    ///
    /// Unconditional by design: there is no environment switch that skips the
    /// gate. A production env bypass is a drift hole (the one deployment that
    /// sets it serves an unverified engine forever), so debugging goes through
    /// the fake engine's own fixture parameters instead.
    async fn admit_engine(&self, engine: &EngineHandle) -> Result<(), EngineError> {
        match crate::engine_contract::verify(engine).await {
            Ok(report) => {
                crate::metrics::record_engine_contract(&report);
                if report.status == crate::engine_contract::CONTRACT_STATUS_LEGACY {
                    tracing::warn!(
                        account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                        group_id = %self.group_id,
                        engine_name = %report.engine_name,
                        engine_version = %report.engine_version,
                        "engine contract handshake: the engine states no contract revision; served in legacy mode"
                    );
                } else {
                    tracing::info!(
                        account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                        group_id = %self.group_id,
                        engine_name = %report.engine_name,
                        engine_version = %report.engine_version,
                        engine_contract_revision = report
                            .contract_revision
                            .as_deref()
                            .unwrap_or("-"),
                        "engine contract handshake: revision in range"
                    );
                }
                *self.engine_contract.lock().await = crate::engine_contract::EngineContractState {
                    report: Some(report),
                    fault: None,
                };
                Ok(())
            }
            Err(crate::engine_contract::EngineContractError::Unavailable) => {
                // Retryable: the engine is alive enough to have been spawned
                // but did not answer the handshake inside the budget. This is
                // a startup failure, not a contract refusal — the watchdog may
                // try again.
                crate::metrics::record_engine_contract_probe_failure();
                tracing::warn!(
                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                    group_id = %self.group_id,
                    budget_ms = crate::engine_contract::ENGINE_CONTRACT_PROBE_TIMEOUT
                        .as_millis()
                        .min(u64::MAX as u128) as u64,
                    "engine contract handshake did not complete; the start stays retryable"
                );
                Err(EngineError::StartFailed)
            }
            Err(crate::engine_contract::EngineContractError::Mismatch(fault)) => {
                crate::metrics::record_engine_contract_mismatch(&fault);
                // The launcher's only byte-stable channel: the same fixed line
                // shape the store's fatal classes use. Emitted once, at the
                // moment the fault is latched.
                let line = fault.fatal_line();
                tracing::error!(
                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                    group_id = %self.group_id,
                    engine_name = fault.engine_name.as_deref().unwrap_or("unknown"),
                    engine_version = fault.engine_version.as_deref().unwrap_or("unknown"),
                    engine_contract_revision = fault.contract_revision.as_deref().unwrap_or("-"),
                    contract_reason = fault.reason.as_str(),
                    supported = crate::engine_contract::SUPPORTED_ENGINE_CONTRACT_RANGE,
                    "engine contract mismatch; the engine is not served and the fault is latched"
                );
                eprintln!("{line}");
                *self.engine_contract.lock().await = crate::engine_contract::EngineContractState {
                    report: None,
                    fault: Some(fault.clone()),
                };
                Err(EngineError::ContractMismatch(fault))
            }
        }
    }

    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>, ServiceError> {
        // Prefer live signal-cli numbers of THIS group's engine. On engine error fall
        // back to this group's store rows so a flaky listAccounts after link does not
        // hard-fail the host. When the engine is healthy and returns an empty list, do
        // NOT surface store-only "ghost" ready accounts from a partial/failed link.
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(_) => {
                let rows = self
                    .service
                    .lock()
                    .await
                    .list_accounts_in_group(&self.group_id)?;
                return Ok(self.stale_slot_accounts(rows));
            }
        };
        // Contract 1.142 (§4.138): each entry may carry the engine's own-ACI
        // report beside the number; the face rides when the engine answers it
        // and stays absent otherwise — the connector never invents one from
        // the opaque local row id.
        let numbers = match engine
            .call("listAccounts", json!({}), CallClass::ReadOnly)
            .await
        {
            Ok(result) => result
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| {
                            let number = item.get("number")?.as_str()?;
                            // Contract 1.194 (§4.194): the engine's own-profile
                            // capabilities projection. Only the backfill bit the
                            // desktop gate consumes rides; absent/ill-typed =
                            // absent (honest unknown, never folded to false).
                            let capabilities = item
                                .get("capabilities")
                                .and_then(|caps| caps.get("attachmentBackfill"))
                                .and_then(Value::as_bool)
                                .map(|attachment_backfill| crate::store::AccountCapabilities {
                                    attachment_backfill,
                                });
                            Some((
                                number.to_string(),
                                item.get("aci").and_then(Value::as_str).map(str::to_string),
                                capabilities,
                            ))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            Err(_) => {
                let rows = self
                    .service
                    .lock()
                    .await
                    .list_accounts_in_group(&self.group_id)?;
                return Ok(self.stale_slot_accounts(rows));
            }
        };
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        // Keep listAccounts fast: do not call listContacts here (blocks the single
        // signal-cli queue and starves conversations.list / startLink).
        // Profile names are filled on finish_link.
        let accounts = self
            .service
            .lock()
            .await
            .sync_accounts_from_numbers_with_capabilities_and_id(
                &numbers,
                &self.group_id,
                self.preferred_account_id.as_deref(),
            )?;
        let accounts = self.live_slot_accounts(accounts);
        // Contract 1.170 (§4.170): the ACI was just (re)written for these
        // accounts — fold each number-keyed memo shell into the canonical
        // ACI-keyed row and announce it.
        self.backfill_memo_identities(&accounts).await;
        let _ = engine;
        Ok(accounts)
    }

    /// Whether this slot currently owns a non-expired link session. The
    /// pool's abandoned-link reaper uses it to tell a merely idle slot from a
    /// half-finished link that will never be committed.
    pub async fn has_pending_link(&self) -> bool {
        self.service.lock().await.has_pending_link()
    }

    /// Store-only account rows for this slot (the registry's degraded answer
    /// when the engine misses the global listing deadline). Scoped exactly
    /// like [`Self::list_accounts`]: a per-account slot answers its own row
    /// only.
    pub async fn list_local_accounts(&self) -> Result<Vec<AccountSummary>, ServiceError> {
        let rows = self
            .service
            .lock()
            .await
            .list_accounts_in_group(&self.group_id)?;
        Ok(self.stale_slot_accounts(rows))
    }

    /// A legacy group supervisor returns every row of its group (the pre-pool
    /// behavior). A per-account slot answers only its own pre-provisioned
    /// account: the shared store holds both legacy and dynamic accounts, and a
    /// dynamic engine's listAccounts must never surface another engine's
    /// account as if this engine served it.
    fn slot_accounts(&self, accounts: Vec<AccountSummary>) -> Vec<AccountSummary> {
        match self.preferred_account_id.as_deref() {
            Some(preferred) => accounts
                .into_iter()
                .filter(|account| account.id == preferred)
                .collect(),
            None => accounts,
        }
    }

    /// Live inventory projection: non-terminal rows carry inventory evidence;
    /// a terminal row rides only when its stored origin is an upstream/engine
    /// answer. Legacy rows with no origin are downgraded to cache/unknown.
    fn live_slot_accounts(&self, accounts: Vec<AccountSummary>) -> Vec<AccountSummary> {
        let mut accounts = self.slot_accounts(accounts);
        for account in &mut accounts {
            apply_live_account_evidence(account);
        }
        accounts
    }

    /// Store-only projection when the engine cannot answer: every row is
    /// cache evidence, and a persisted terminal unlink is downgraded to
    /// `unknown` until a live engine/upstream answer proves it. This is the
    /// guard that stops "engine down" from rendering as "phone unlinked".
    fn stale_slot_accounts(&self, accounts: Vec<AccountSummary>) -> Vec<AccountSummary> {
        let mut accounts = self.slot_accounts(accounts);
        for account in &mut accounts {
            apply_stale_account_evidence(account);
        }
        accounts
    }

    /// Contract 1.170 (§4.170): fold each freshly-ACI'd account's number-keyed
    /// memo shell into the canonical ACI-keyed row (§4.170) and announce the
    /// canonical summary. Best-effort at the seam — a store hiccup degrades
    /// to a warn and the next sync retries (the fold is idempotent).
    async fn backfill_memo_identities(&self, accounts: &[AccountSummary]) {
        for account in accounts {
            let store = Arc::clone(&self.store);
            let account_id = account.id.clone();
            let folded = blocking_service(move || {
                store
                    .normalize_memo_identity(&account_id)
                    .map_err(ServiceError::from)
            })
            .await;
            match folded {
                Ok(Some(summary)) => {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(summary));
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    error_class = error.class(),
                    account_id = %account.id,
                    "memo identity backfill failed; the next sync retries"
                ),
            }
        }
    }

    /// Resolve a human-readable profile label for the local linked account.
    /// Never logs the phone number.
    async fn fetch_self_display_name(
        &self,
        engine: &crate::engine::EngineHandle,
        number: &str,
    ) -> Option<String> {
        if let Ok(result) = engine
            .call(
                "listContacts",
                json!({
                    "account": number,
                    "recipient": [number],
                }),
                CallClass::ReadOnly,
            )
            .await
            && let Some(name) = display_name_from_contacts(&result, number)
        {
            return Some(name);
        }
        if let Ok(result) = engine
            .call(
                "listContacts",
                json!({
                    "account": number,
                    "allRecipients": true,
                }),
                CallClass::ReadOnly,
            )
            .await
            && let Some(name) = display_name_from_contacts(&result, number)
        {
            return Some(name);
        }
        None
    }

    pub async fn start_link(&self, device_name: String) -> Result<Value, ServiceError> {
        self.start_link_with_attempt(device_name, None).await
    }

    /// The pooled entry: the registry mints the connector attempt id before
    /// provisioning the slot, so the slot lease and the host-facing
    /// `linkAttemptId` are the same owner. `None` keeps the legacy
    /// service-minted id exactly as before.
    pub async fn start_link_with_attempt(
        &self,
        device_name: String,
        connector_attempt_id: Option<String>,
    ) -> Result<Value, ServiceError> {
        self.service.lock().await.ensure_link_available()?;
        // Per-engine account ceiling (optimization-plan §6.4 M3.3): refuse
        // before the engine mints a QR, so no one scans a code that can never
        // finish. A store failure propagates as its own error class.
        if self
            .service
            .lock()
            .await
            .group_at_account_ceiling(&self.group_id)?
        {
            return Err(account_limit_error(&self.group_id));
        }
        let engine = self.running_engine().await?;
        let result = engine
            .call("startLink", json!({}), CallClass::ReadOnly)
            .await?;
        let device_link_uri = result
            .get("deviceLinkUri")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ServiceError::Api(ApiError::new(
                    "UPSTREAM_PROTOCOL_ERROR",
                    "startLink response missing deviceLinkUri",
                    true,
                ))
            })?
            .to_string();
        // Contract 1.286 (§4.272): an engine that minted a rotate key states
        // it on the startLink answer. Its absence is the capability verdict —
        // `link.rotate` then answers NOT_SUPPORTED and this single slot is
        // the whole attempt, exactly like the pre-rotate wire.
        let engine_attempt_id = result
            .get("linkAttemptId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|attempt| !attempt.is_empty())
            .map(str::to_string);
        let mut result = self.service.lock().await.begin_link_with_identities(
            device_name,
            device_link_uri,
            engine_attempt_id,
            connector_attempt_id,
        )?;
        // The wire result echoes the selected group (implementation-plan §4.4);
        // this supervisor IS the selected group.
        result["proxyGroup"] = json!(self.group_id);
        tracing::info!(
            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
            group_id = %self.group_id,
            "link session started"
        );
        Ok(result)
    }

    /// `link.rotate` (contract 1.286, §4.272): mint a fresh provisioning
    /// session — a new slot — for the same link attempt on the engine's own
    /// rotate face. The attempt's oldest live slot is retired when a third code
    /// would go live, so at most two codes are ever scannable at once.
    ///
    /// Degradation is explicit rather than incidental. An engine that predates
    /// the rotate face never states a rotate key on its `startLink` answer, so
    /// the attempt has none and the connector answers NOT_SUPPORTED without
    /// touching the engine — the single slot keeps working exactly like the
    /// pre-rotate wire. An engine that *does* state a key but answers the
    /// method as unknown (JSON-RPC -32601 / the `MethodNotFound` cause class)
    /// folds into the same NOT_SUPPORTED answer.
    pub async fn rotate_link(&self, link_attempt_id: String) -> Result<Value, ServiceError> {
        // Session judgment first: an unknown, committed, or expired attempt is
        // a definite answer that does not depend on engine liveness.
        let engine_attempt_id = self.service.lock().await.begin_rotate(&link_attempt_id)?;
        let Some(engine_attempt_id) = engine_attempt_id else {
            tracing::info!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                "link rotate refused: the engine states no rotate key"
            );
            return Err(Self::link_rotate_not_supported_error());
        };
        let engine = self.running_engine().await?;
        let upstream = engine
            .call(
                "rotateLink",
                json!({ "linkAttemptId": engine_attempt_id }),
                CallClass::ReadOnly,
            )
            .await;
        let payload = match upstream {
            Ok(payload) => payload,
            Err(error) if engine_method_missing(&error) => {
                tracing::info!(
                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                    group_id = %self.group_id,
                    "link rotate refused: the engine does not carry the method"
                );
                return Err(Self::link_rotate_not_supported_error());
            }
            Err(error) => return Err(ServiceError::Engine(error)),
        };
        let device_link_uri = payload
            .get("deviceLinkUri")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| {
                ServiceError::Api(ApiError::new(
                    "UPSTREAM_PROTOCOL_ERROR",
                    "rotateLink response missing deviceLinkUri",
                    true,
                ))
            })?
            .to_string();
        let outcome = self.service.lock().await.attach_rotated_slot(
            &link_attempt_id,
            device_link_uri,
            now_ms(),
        )?;
        if let Some(retired) = outcome.retired {
            tracing::info!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                retired_slot = retired,
                "link slot retired by rotation"
            );
        }
        tracing::info!(
            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
            group_id = %self.group_id,
            slot = outcome.slot,
            "link slot rotated"
        );
        // The new slot's own session id rides the answer beside the contract's
        // {deviceLinkUri, slot, slots}: link.finish/link.cancel address a slot
        // by its linkSessionId, and the contract's slots entries carry only the
        // code and the number.
        Ok(json!({
            "linkAttemptId": outcome.link_attempt_id,
            "linkSessionId": outcome.link_session_id,
            "deviceLinkUri": outcome.device_link_uri,
            "slot": outcome.slot,
            "slots": outcome.slots,
            "expiresAt": outcome.expires_at_ms,
            "proxyGroup": self.group_id,
        }))
    }

    /// The rotate degradation answer: this engine cannot mint a second code
    /// for an attempt. Not retryable — the remedy is a fresh `link.start`.
    fn link_rotate_not_supported_error() -> ServiceError {
        ServiceError::Api(ApiError::new(
            "NOT_SUPPORTED",
            "the engine does not support link rotation; start a new link instead",
            false,
        ))
    }

    /// The answer a budget-expired `finishLink` gets: the link-class unknown
    /// outcome, never a definite retryable timeout. The call is mutating and
    /// was in flight when the budget expired, so the phone may already have
    /// approved the device and the engine may have committed the link; the
    /// remedy is the caller's adopt path (`accounts.list`), not a re-run.
    fn link_finish_timeout_error() -> ServiceError {
        ServiceError::Api(ApiError::new(
            "LINK_OUTCOME_UNKNOWN",
            "finishLink exceeded the link budget; the phone may have approved the device, \
             so adopt from the account list instead of retrying",
            false,
        ))
    }

    pub async fn finish_link(
        &self,
        link_session_id: String,
    ) -> Result<AccountSummary, ServiceError> {
        // [link-stage] BUG-5 取证：connector 侧同一时钟从 link.finish 受理起算，
        // 与 registry 的 slot-promote 行同窗口（仅日志，零行为变更）。
        let link_stage_started = std::time::Instant::now();
        let cancel = {
            let mut active = self.active_link_finish.lock().await;
            if active.is_some() {
                return Err(ServiceError::Api(ApiError::new(
                    "LINK_IN_PROGRESS",
                    "a link finish request is already active",
                    false,
                )));
            }
            let (cancel_tx, cancel_rx) = watch::channel(false);
            *active = Some(ActiveLinkFinish {
                link_session_id: link_session_id.clone(),
                cancel: cancel_tx,
            });
            cancel_rx
        };
        // Lost-finish replay (contract 1.276 §4.260, widened by 1.286 §4.272):
        // an attempt that already committed answers the same account from any
        // of its codes instead of asking the phone again or minting a second
        // binding. Rotation never commits, so this arm also covers a rotate
        // that retired the code the host is retrying with. The lane taken
        // above is released before the answer leaves.
        match self
            .service
            .lock()
            .await
            .replay_link_commit(&link_session_id)
        {
            Ok(Some(account)) => {
                self.clear_link_finish(&link_session_id).await;
                tracing::info!(
                    account_id = %account.id,
                    "link finish replayed the committed attempt"
                );
                return Ok(account);
            }
            Ok(None) => {}
            Err(error) => {
                self.clear_link_finish(&link_session_id).await;
                return Err(error);
            }
        }
        // Session state is judged before the engine is resolved (QR B1): a
        // lost/expired/unknown session is a definite answer that does not
        // depend on engine liveness, so a terminal or missing engine must not
        // downgrade it to RUNTIME_NOT_RUNNING. Every pre-dispatch refusal
        // below clears the finish lane it just took.
        let credentials = self
            .service
            .lock()
            .await
            .peek_link_for_finish(&link_session_id);
        let (device_name, device_link_uri) = match credentials {
            Ok(credentials) => credentials,
            Err(error) => {
                self.clear_link_finish(&link_session_id).await;
                return Err(error);
            }
        };
        // Per-engine account ceiling (M3.3): refuse before the engine is
        // resolved and before the mutating finishLink is dispatched, so the
        // phone is never asked to approve a link the connector would then
        // have to reject at commit time. Session errors (LINK_LOST/
        // LINK_NOT_FOUND/LINK_EXPIRED) keep precedence.
        // Bind the store answer before matching: a match scrutinee's
        // temporary guard would stay alive through the arms, and the refusal
        // arm takes the service lock again (a same-mutex deadlock).
        let ceiling = self
            .service
            .lock()
            .await
            .group_at_account_ceiling(&self.group_id);
        match ceiling {
            Ok(true) => {
                // The refused QR can never commit while the group stays full,
                // so the session is spent: dropping it keeps
                // has_pending_link false (the watchdog is not suppressed for
                // its TTL) and lets the next link.start mint a fresh QR
                // instead of answering LINK_IN_PROGRESS. It is dropped while
                // this lane still excludes a concurrent finish, so no one can
                // peek the session between the drop and the lane release.
                self.service
                    .lock()
                    .await
                    .discard_link_session(&link_session_id);
                // Clear the lane before the refusal leaves, exactly like the
                // peek and pin arms: a lane left taken would answer every
                // later finish with LINK_IN_PROGRESS and keep the watchdog
                // suppressed for good.
                self.clear_link_finish(&link_session_id).await;
                return Err(account_limit_error(&self.group_id));
            }
            Ok(false) => {}
            Err(error) => {
                self.clear_link_finish(&link_session_id).await;
                return Err(error);
            }
        }

        // A live engine is only needed to dispatch finishLink, so it is
        // resolved after the session judgment (a terminal/missing engine must
        // not downgrade a lost session's definite LINK_LOST) and after the
        // store-only ceiling refusal. This arm clears its own lane too: the
        // finish never started, so nothing may stay suppressed.
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(error) => {
                self.clear_link_finish(&link_session_id).await;
                return Err(error.into());
            }
        };

        // The finish budget outlives the advertised QR lifetime
        // (`LINK_SESSION_TTL`): an approval that lands while `finishLink` is
        // in flight must still be commitable, or the engine links a device
        // that the commit then refuses with LINK_EXPIRED. The pin extends only
        // the in-memory session deadline; the QR's advertised `expiresAt`
        // stays what it was. It runs only once every pre-dispatch refusal is
        // past, so a refusal never stretches a dead QR's deadline.
        if let Err(error) = self
            .service
            .lock()
            .await
            .pin_link_for_finish(&link_session_id, LINK_FINISH_TIMEOUT)
        {
            self.clear_link_finish(&link_session_id).await;
            return Err(error);
        }

        let upstream = engine
            .call_with_timeout_or_cancel(
                "finishLink",
                json!({
                    "deviceLinkUri": device_link_uri,
                    "deviceName": device_name,
                }),
                CallClass::Mutating,
                LINK_FINISH_TIMEOUT,
                cancel,
            )
            .await;
        let still_current = self.clear_link_finish(&link_session_id).await;
        if !still_current {
            return Err(link_cancelled_error());
        }

        let result = match upstream {
            Ok(Some(value)) => value,
            // `link.cancel` (or a stop/shutdown) abandoned the wait. The
            // engine may still complete the link; the pinned JSON-RPC face has
            // no cancel verb, so the honest answer is the cancellation, and
            // any late engine-side link surfaces through the next
            // accounts.list sync as a real link (the phone approved it).
            Ok(None) => return Err(link_cancelled_error()),
            // The budget expired with the mutating call still in flight: the
            // phone may have approved the device and the engine may have
            // committed the link. A definite timeout would invite a blind
            // re-run (a second device slot), so the honest answer is the
            // link-class unknown outcome — the desktop reconciles it through
            // the account list (adopt).
            Err(EngineError::Timeout) => return Err(Self::link_finish_timeout_error()),
            // finishLink is Mutating, so this means the call was in flight when
            // the engine died: the phone may already have linked the device.
            // Retrying would claim a second device slot, so the host has to
            // reconcile against the account list instead.
            Err(EngineError::UnknownOutcome) => {
                return Err(ServiceError::Api(ApiError::new(
                    "LINK_OUTCOME_UNKNOWN",
                    "finishLink outcome is unknown; check linked devices before retrying",
                    false,
                )));
            }
            // QR B1 (issue #951): the engine's provisioning channel is dead.
            // The finish lane was already cleared above (clear_link_finish),
            // so mark the service session lost and keep it addressable: the
            // next link.start replaces it, has_pending_link stops suppressing
            // the watchdog, and any later finish for this id answers the
            // definite LINK_LOST rather than LINK_NOT_FOUND.
            Err(EngineError::UpstreamCode {
                code: "LINK_LOST",
                data,
            }) => {
                let marked = self.service.lock().await.mark_link_lost(&link_session_id);
                if !marked {
                    tracing::warn!(
                        account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                        group_id = %self.group_id,
                        "engine reported LINK_LOST for a session this service no longer owns"
                    );
                }
                return Err(ServiceError::Engine(EngineError::UpstreamCode {
                    code: "LINK_LOST",
                    data,
                }));
            }
            Err(error) => return Err(ServiceError::Engine(error)),
        };
        // [link-stage] 引擎 finishLink 返回 = link 已在引擎侧注册完成。手机确认
        // 与 provisioning 的等待都包含在本段内；该行与桌面 scan-confirmed 行的
        // 时间差就是这段等待（仅日志，零行为变更）。
        crate::link_stage::line(
            "link-register",
            link_stage_started.elapsed(),
            &link_session_id,
            self.preferred_account_id.as_deref(),
            "engine finishLink returned",
        );
        let number = result
            .get("number")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ServiceError::Api(ApiError::new(
                    "UPSTREAM_PROTOCOL_ERROR",
                    "finishLink response missing number",
                    true,
                ))
            })?;
        let aci = result.get("aci").and_then(Value::as_str);
        let mut account = {
            let mut service = self.service.lock().await;
            service.complete_link_session_with_id(
                &link_session_id,
                number,
                &self.group_id,
                aci,
                self.preferred_account_id.as_deref(),
            )?
        };
        // Contract 1.170 (§4.170): the finish answer may have just written the
        // account's first ACI — fold the number-keyed memo shell and announce
        // the canonical row before the account-changed event rides.
        self.backfill_memo_identities(std::slice::from_ref(&account))
            .await;
        if let Some(summary) = self
            .store
            .account_summary(&account.id)
            .map_err(ServiceError::from)?
        {
            account = summary;
        }
        // Refresh profile display name right after link (best-effort).
        if let Ok(engine) = self.running_engine().await
            && let Some(name) = self.fetch_self_display_name(&engine, number).await
            && let Ok(updated) = self
                .service
                .lock()
                .await
                .set_account_display_name(&account.id, Some(name.as_str()))
        {
            account = updated;
        }
        // Best-effort initial contacts/groups sync right after link: signal-cli
        // has already pulled them from the primary device, so this only reads
        // them into the local cache. A failure must not fail the link flow.
        if let Err(error) = self.sync_contacts(&account.id).await {
            tracing::warn!(
                error_class = error.class(),
                account_id = %account.id,
                "initial contacts sync after link failed"
            );
        }
        // §4.38: the engine starts the backup5 archive download in the
        // background when finishLink returns; watch for the file and import.
        // Best-effort — a watcher failure never fails the link flow.
        self.spawn_history_import_watch(account.id.clone());
        let _ = self
            .host_events
            .send(HostSideEvent::AccountChanged(account.clone()));
        tracing::info!(account_id = %account.id, "link finished");
        Ok(account)
    }

    /// Clear the active finish lane only when it still names this session.
    /// False means `link.cancel` (or stop/shutdown) already took it.
    async fn clear_link_finish(&self, link_session_id: &str) -> bool {
        let mut active = self.active_link_finish.lock().await;
        if active
            .as_ref()
            .is_some_and(|finish| finish.link_session_id == link_session_id)
        {
            *active = None;
            true
        } else {
            false
        }
    }

    pub async fn cancel_link(&self, link_session_id: String) -> Result<Value, ServiceError> {
        // [KT 适配] The pinned engine has no link-cancel verb: `finishLink` is
        // a mutating call already dispatched to the engine and cannot be
        // withdrawn. Cancellation is therefore local and immediate — the wait
        // is abandoned (the engine call is removed from the pending map and
        // its late answer ignored), the link session is cleared, and the
        // shared engine keeps running. Restarting the group engine here (the
        // pre-B3 behavior) disconnected every other account in the group for
        // a cancellation that concerns one link session; audit §9.10 item 4.
        let cancelled_in_flight = {
            let mut active = self.active_link_finish.lock().await;
            match active.as_ref() {
                Some(finish) if finish.link_session_id == link_session_id => {
                    let finish = active.take().expect("checked above");
                    let _ = finish.cancel.send(true);
                    true
                }
                _ => false,
            }
        };
        let result = self.service.lock().await.cancel_link(&link_session_id);
        if cancelled_in_flight {
            tracing::info!("link finish wait abandoned; the group engine keeps running");
        }
        result
    }

    /// Shared engine restart: shut the current engine down and start a fresh one.
    /// `EngineHandle::shutdown` is internally bounded (total timeout, then a
    /// direct child kill), so a watchdog restart cannot hang here even when the
    /// old engine's actor is parked on receive backpressure.
    async fn restart_engine(&self) -> Result<(), EngineError> {
        // Contract 1.275: a terminal unlink is not a crash. No restart can
        // revive a credential the account holder revoked, so the watchdog lane
        // stops here instead of re-spawning an engine whose only answer is 401.
        self.terminal_unlink_guard()?;
        // Contract 1.291 (§4.277 C): the watchdog recovers an engine without
        // the pool asking, so this is where a crash restart could open a store
        // the migrator still owns. Ask the gate **before** the old handle is
        // taken, so a refusal never costs a live engine.
        self.admit_start().await?;
        let mut slot = self.engine.lock().await;
        if let Some(fault) = self.latched_contract_fault().await {
            tracing::warn!(
                account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                group_id = %self.group_id,
                engine_version = fault.engine_version.as_deref().unwrap_or("unknown"),
                contract_reason = fault.reason.as_str(),
                "engine restart refused: the contract mismatch is latched for this process"
            );
            return Err(EngineError::ContractMismatch(fault));
        }
        if let Some(engine) = slot.take() {
            engine.shutdown().await?;
        }
        let engine = EngineHandle::start(
            self.config.clone(),
            self.events.clone(),
            self.receive_ingress.clone(),
        )
        .await?;
        // O1: a watchdog recovery re-earns the handshake verdict — the engine
        // binary may have been replaced between restarts, and a mismatch here
        // latches exactly like a fresh start does.
        if let Err(error) = self.admit_engine(&engine).await {
            refuse_started_engine(&engine, &error).await;
            return Err(error);
        }
        let status = engine.status();
        self.restart_count.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
            group_id = %self.group_id,
            pid = status.pid.unwrap_or(0),
            restarts = self.restart_count(),
            "engine restarted"
        );
        let fresh = engine.clone();
        *slot = Some(engine);
        drop(slot);
        self.spawn_contacts_resync_with(fresh);
        self.spawn_history_import_pass();
        if status.state == EngineState::Running {
            // §4.179: every engine landing re-arms the reconciliation — a
            // watchdog recovery (or link-cancel restart) is exactly the
            // window that leaves unknown-outcome rows behind, so limiting
            // the pass to `start()` would strand them until the next manual
            // start. Best-effort, idempotent, warn-only.
            self.spawn_unknown_outcome_reconcile().await;
        }
        // §4.190 ⑥: a fresh engine (watchdog recovery included) re-fetches
        // the accounts' configuration — the readReceipts gate flag converges
        // on every landing.
        self.spawn_configuration_gate_sync();
        // §4.123: a fresh engine (watchdog recovery included) drains the
        // offline queue immediately — the official online-event re-dispatch.
        self.notify_outbox_drain();
        Ok(())
    }

    /// The pid this supervisor currently believes its engine owns (never a
    /// terminal handle's stale pid) — the owner-exclusion face the orphan
    /// sweep consumes.
    pub(crate) async fn owned_engine_pid(&self) -> Option<u32> {
        self.engine
            .lock()
            .await
            .as_ref()
            .filter(|engine| !engine.is_terminal())
            .and_then(|engine| engine.status().pid)
    }

    async fn sweep_owner_facts(
        self: &Arc<Self>,
    ) -> Option<Vec<(String, crate::parent::SlotFacts)>> {
        let owner = self
            .sweep_owner
            .lock()
            .ok()
            .and_then(|owner| owner.as_ref().map(Arc::clone))?;
        Some(owner.facts().await)
    }

    /// P0 orphan-engine sweep (watchdog cadence). On Unix only: it reads the
    /// host process table, classifies the engines that name this data
    /// directory, and terminates only the ones that are unambiguously orphaned
    /// (see `parent::plan_engine_sweep` for the full decision table). Every
    /// signal is preceded by a log line with the pid and the fixed reason
    /// literal, and no number, path, or account material ever enters it.
    ///
    /// The pass is a no-op unless a scope was armed (the pool owner), so a
    /// legacy group supervisor keeps its pre-sweep behavior exactly.
    async fn orphan_engine_sweep(&self, facts: &[(String, crate::parent::SlotFacts)]) {
        #[cfg(not(unix))]
        {
            let _ = facts;
        }
        #[cfg(unix)]
        {
            let Some(data_dir) = self
                .orphan_sweep
                .lock()
                .ok()
                .and_then(|scope| scope.as_ref().map(|scope| scope.signal_data_dir.clone()))
            else {
                return;
            };
            let rows = match tokio::task::spawn_blocking(crate::parent::scan_processes).await {
                Ok(rows) => rows,
                Err(_) => return,
            };
            let self_pid = std::process::id();
            let plan = match self.orphan_sweep.lock() {
                Ok(mut scope) => {
                    let Some(scope) = scope.as_mut() else {
                        return;
                    };
                    crate::parent::plan_engine_sweep(
                        &rows,
                        &data_dir,
                        facts,
                        self_pid,
                        &mut scope.memory,
                        true,
                    )
                }
                Err(_) => return,
            };
            for (pid, ppid) in &plan.foreign {
                tracing::warn!(
                    pid,
                    ppid,
                    "engine names this data directory but is not an orphan; recording only"
                );
            }
            for (pid, slot) in &plan.pending {
                tracing::info!(
                    pid,
                    slot,
                    "engine orphan candidate recorded; re-checking on the next sweep"
                );
            }
            if plan.kill.is_empty() {
                return;
            }
            let owned: Vec<u32> = facts
                .iter()
                .filter_map(|(_, facts)| facts.owned_pid)
                .collect();
            for kill in plan.kill {
                let reason = match kill.reason {
                    crate::parent::SlotVerdict::OrphanUnprovisioned => "orphan_unprovisioned",
                    _ => "orphan_engine",
                };
                // Last gate, right before the signal: re-read the pid's argv
                // and ask the kernel who its parent is now. A pid that no
                // longer names this slot, or whose parent is this process, is
                // never signalled.
                let data_dir = data_dir.clone();
                let pid = kill.pid;
                let slot = kill.slot.clone();
                let gate = tokio::task::spawn_blocking(move || {
                    let still_targets = crate::parent::still_targets(pid, &data_dir, Some(&slot));
                    let child_of_self = crate::parent::parent_of(pid) == Some(std::process::id());
                    (still_targets, child_of_self)
                })
                .await
                .unwrap_or((false, false));
                let (still_targets, child_of_self) = gate;
                if !still_targets
                    || !crate::parent::may_kill_orphan(pid, self_pid, &owned, Some(child_of_self))
                {
                    tracing::warn!(
                        pid,
                        slot = %kill.slot,
                        reason,
                        "orphan engine re-check refused the kill; recording only"
                    );
                    continue;
                }
                tracing::warn!(
                    pid,
                    slot = %kill.slot,
                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                    reason,
                    "terminating an orphaned engine that holds this data directory"
                );
                let outcome = tokio::task::spawn_blocking(move || {
                    crate::parent::terminate_pid(pid, Duration::from_secs(3))
                })
                .await
                .unwrap_or(crate::parent::TerminatedPid::Refused);
                tracing::warn!(
                    pid,
                    slot = %kill.slot,
                    reason,
                    outcome = ?outcome,
                    "orphan engine termination finished"
                );
            }
        }
    }

    async fn watchdog_loop(self: Arc<Self>) {
        let mut ticker = interval(self.config.watchdog_interval.max(Duration::from_millis(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // stderr subscription follows the current engine instance (tracked by pid).
        let mut stderr_rx: Option<broadcast::Receiver<String>> = None;
        let mut stderr_pid: Option<u32> = None;
        let mut ping_failures = 0u32;
        let mut last_restart: Option<Instant> = None;
        // A restart request that arrived inside the backoff window. It must
        // not be dropped: a dead receive WebSocket produces no further stderr
        // lines, and the REST ping (getUserStatus) does not cover the receive
        // channel at all — a known structural blind spot. The pending retry is
        // the only backstop for "can send but cannot receive", so it carries
        // its own deadline and is never discarded by an episode budget.
        let mut pending: Option<PendingRestart> = None;
        // Failure episode: restarts executed so far and the last trigger
        // time. Each executed restart doubles the next backoff (capped), which
        // bounds restart churn while keeping a persistently dead receive path
        // retried instead of silently abandoned.
        let mut episode = WatchdogEpisode::default();
        // Liveness-probe verdicts for the current engine instance: store
        // rows the engine does not serve. Per instance, cleared on restart.
        let mut verdicts = WatchdogProbeVerdicts::default();
        // P0 orphan-engine sweep clock: its own cadence (independent of the
        // watchdog's, so a tightened test watchdog cannot turn the sweep into
        // a hot loop) and only while a scope is armed.
        let mut sweep_clock = interval(crate::parent::ENGINE_SWEEP_INTERVAL);
        sweep_clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
        sweep_clock.tick().await;
        loop {
            let engine = self.engine.lock().await.clone();
            let current_pid = engine.as_ref().and_then(|e| e.status().pid);
            if current_pid != stderr_pid {
                stderr_rx = engine
                    .as_ref()
                    .filter(|e| !e.is_terminal())
                    .map(EngineHandle::subscribe_stderr);
                stderr_pid = current_pid;
            }
            tokio::select! {
                line = recv_stderr_line(stderr_rx.as_mut()) => {
                    match line {
                        Some(line) => match classify_engine_stderr(&line) {
                            EngineStderrClass::ReceiveFatal => {
                                if self
                                    .watchdog_request_restart(
                                        &mut last_restart,
                                        &mut pending,
                                        &mut episode,
                                        RestartSource::Stderr,
                                        "receive WebSocket error on stderr",
                                    )
                                    .await
                                {
                                    ping_failures = 0;
                                    stderr_rx = None;
                                    stderr_pid = None;
                                }
                            }
                            EngineStderrClass::NetworkPath => {
                                tracing::info!(
                                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                                    line = %line,
                                    "engine stderr: network egress declared"
                                );
                            }
                            EngineStderrClass::Diagnostic => {
                                tracing::debug!(
                                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                                    line = %line,
                                    "engine stderr"
                                );
                            }
                        },
                        None => {
                            stderr_rx = None;
                            stderr_pid = None;
                        }
                    }
                }
                _ = sweep_clock.tick() => {
                    // The pool owner arms exactly one scope on one supervisor;
                    // without it this supervisor has no slots to attribute and
                    // the pass is a no-op rather than a scan.
                    let armed = self
                        .orphan_sweep
                        .lock()
                        .map(|scope| scope.is_some())
                        .unwrap_or(false);
                    if armed
                        && let Some(facts) = self.sweep_owner_facts().await
                    {
                        self.orphan_engine_sweep(&facts).await;
                    }
                }
                _ = ticker.tick() => {
                    // Contract 1.275: a terminal unlink is not a liveness fault
                    // and nothing about it is retryable. The slot is parked
                    // (engine stopped, every start face answers ACCOUNT_UNLINKED)
                    // until a fresh link clears it, so this tick judges nothing
                    // and must not arm a restart of a dead credential.
                    if self.is_device_unlinked() {
                        pending = None;
                        ping_failures = 0;
                        continue;
                    }
                    // Receive-path survival evidence cancels a pending
                    // restart: an envelope actually delivered over the
                    // engine's receive lane proves the WebSocket is alive,
                    // which no REST ping can. This is the only positive
                    // signal allowed to clear a liveness pending besides an
                    // executed restart itself.
                    if let Some(armed) = pending
                        && self.receive_evidence.load(Ordering::Relaxed) > armed.evidence
                    {
                        tracing::info!(
                            reason = armed.reason,
                            source = %armed.source,
                            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                            group_id = %self.group_id,
                            episode_restarts = episode.restarts,
                            "watchdog pending restart cleared: receive path delivered an envelope"
                        );
                        pending = None;
                        ping_failures = 0;
                    }
                    // Episode reset (anti-storm window): only a trigger-free
                    // gap longer than watchdog_min_restart_interval restores
                    // the immediate restart. Retries inside an episode are
                    // paced by the seconds-scale liveness backoff instead.
                    if pending.is_none()
                        && let Some(last_trigger) = episode.last_trigger
                        && last_trigger.elapsed() > self.config.watchdog_min_restart_interval
                    {
                        episode = WatchdogEpisode::default();
                    }
                    // Process exit (engine-pool F3/§6.3): a terminal child
                    // is a restart trigger of its own. Arming through the
                    // same lane keeps the anti-storm backoff and link-flow
                    // suppression; the deferred block below executes it.
                    if self.preferred_account_id.is_some()
                        && engine.as_ref().is_some_and(EngineHandle::is_terminal)
                        && pending.is_none()
                    {
                        let _ = self
                            .watchdog_request_restart(
                                &mut last_restart,
                                &mut pending,
                                &mut episode,
                                RestartSource::Crash,
                                "engine process exited",
                            )
                            .await;
                    }
                    // A deferred restart fires when its own deadline passes.
                    // It is never dropped by an episode budget: a dead
                    // receive path must not stay dead because earlier
                    // restarts happened to miss. While a link flow is active
                    // it stays pending (restarting would invalidate an
                    // in-flight deviceLinkUri) and fires once the flow ends.
                    if let Some(deferred) = pending
                        && Instant::now() >= deferred.due_at
                        && !self.link_flow_active().await
                    {
                        tracing::warn!(
                            reason = deferred.reason,
                            source = %deferred.source,
                            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                            group_id = %self.group_id,
                            episode_restarts = episode.restarts,
                            "watchdog restarting the engine (backoff elapsed)"
                        );
                        match self.restart_engine().await {
                            Ok(()) => {
                                crate::metrics::record_watchdog_restart();
                                last_restart = Some(Instant::now());
                                episode.restarts = episode.restarts.saturating_add(1);
                                pending = None;
                                ping_failures = 0;
                                stderr_rx = None;
                                stderr_pid = None;
                            }
                            Err(EngineError::ContractMismatch(fault)) => {
                                // O1: not retryable by construction. Clear the
                                // backstop instead of re-arming it — the latch
                                // already refuses every later attempt.
                                pending = None;
                                tracing::error!(
                                    reason = deferred.reason,
                                    source = %deferred.source,
                                    account_id = self
                                        .preferred_account_id
                                        .as_deref()
                                        .unwrap_or("-"),
                                    group_id = %self.group_id,
                                    engine_version = fault
                                        .engine_version
                                        .as_deref()
                                        .unwrap_or("unknown"),
                                    contract_reason = fault.reason.as_str(),
                                    "watchdog recovery refused: engine contract mismatch is not self-healing"
                                );
                            }
                            Err(error) => {
                                // Keep the backstop armed: dropping it here
                                // would recreate the "fault hangs forever"
                                // shape this deadline exists to prevent.
                                let retry_in = self
                                    .config
                                    .watchdog_interval
                                    .max(Duration::from_millis(1));
                                pending = Some(PendingRestart {
                                    due_at: Instant::now() + retry_in,
                                    ..deferred
                                });
                                crate::metrics::record_watchdog_restart_failed();
                                tracing::warn!(
                                    reason = deferred.reason,
                                    source = %deferred.source,
                                    account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
                                    group_id = %self.group_id,
                                    error = %error,
                                    retry_in_ms =
                                        retry_in.as_millis().min(u64::MAX as u128) as u64,
                                    "watchdog deferred restart failed; retrying"
                                );
                            }
                        }
                        // The cloned handle belongs to the engine that was
                        // just replaced (or whose restart failed): never ping
                        // it, start a fresh loop iteration on the new slot.
                        continue;
                    }
                    let Some(engine) = engine.filter(|e| !e.is_terminal()) else {
                        continue;
                    };
                    // Probe verdicts are facts about one engine instance.
                    verdicts.for_engine(current_pid);
                    let targets = match self.watchdog_ping_plan(&engine, &mut verdicts).await {
                        WatchdogPingPlan::LinkFlow => continue,
                        WatchdogPingPlan::NoTarget(skip) => {
                            // No engine-confirmed account means liveness is
                            // unobservable this tick, not that it failed.
                            // Pinging an account the engine does not serve
                            // would only earn its -32603 and restart a
                            // healthy engine (the stale-row incident).
                            crate::metrics::record_watchdog_liveness_tick_skipped();
                            tracing::info!(
                                reason = skip.reason,
                                known_accounts = skip.known_accounts,
                                excluded_accounts = skip.excluded_accounts,
                                engine_verified = skip.engine_verified,
                                "watchdog liveness skipped: no engine-confirmed ping target"
                            );
                            // A skipped tick judged nothing, so it must not
                            // add failure evidence: the threshold stays
                            // "two consecutive failed pings".
                            ping_failures = 0;
                            continue;
                        }
                        WatchdogPingPlan::Probe(targets) => targets,
                    };
                    // Probe the verified candidates in order. The engine's
                    // plain -32603 is its unknown-account face; a refusal is
                    // attributed to the account only under evidence — another
                    // candidate answers, or every attempted candidate is
                    // refused and the engine never fails at the transport
                    // level. Anything else (timeout, backpressure, protocol,
                    // exit, another upstream code) is engine-scoped and keeps
                    // the pre-existing failure accounting.
                    let mut refused: Vec<(String, &'static str)> = Vec::new();
                    let mut failed_class: Option<&'static str> = None;
                    let mut outcome = WatchdogPingOutcome::Failed;
                    for target in &targets {
                        let number = &target.number;
                        let ping = engine
                            .call_with_timeout(
                                "getUserStatus",
                                json!({
                                    "account": number,
                                    "recipient": [number],
                                }),
                                CallClass::ReadOnly,
                                WATCHDOG_PING_TIMEOUT,
                            )
                            .await;
                        match ping {
                            Ok(_) => {
                                outcome = WatchdogPingOutcome::Answered;
                                break;
                            }
                            Err(EngineError::Unauthorized) => {
                                outcome = WatchdogPingOutcome::Unauthorized;
                                break;
                            }
                            Err(error) if account_scoped_engine_error(&error) => {
                                failed_class = Some(error.class());
                                refused.push((target.account_id.clone(), error.class()));
                            }
                            Err(error) => {
                                failed_class = Some(error.class());
                                break;
                            }
                        }
                    }
                    match outcome {
                        WatchdogPingOutcome::Answered => {
                            // A later candidate answered, so every plain
                            // upstream refusal before it was that account's
                            // face, not the engine's: exclude those
                            // accounts from liveness for this engine
                            // instance.
                            exclude_refused_ping_targets(
                                &mut verdicts,
                                &refused,
                                targets.len(),
                            );
                            // A successful REST ping decays the failure
                            // counter only. It must NOT clear a pending
                            // restart: getUserStatus does not touch the
                            // receive WebSocket, and clearing on a single
                            // success was exactly the "REST looks fine while
                            // receive is dead" loop that kept engines down.
                            // Only delivered envelope evidence (above) or an
                            // executed restart can clear a pending.
                            ping_failures = 0;
                        }
                        WatchdogPingOutcome::Unauthorized => {
                            // Contract 1.21: the ping target's device was
                            // unlinked by the account holder. The credential
                            // is dead and no restart can resurrect it; the
                            // account-unauthorized event has already marked
                            // the account. Counting this as a ping failure
                            // would only churn bounded restarts forever.
                            ping_failures = 0;
                            // Contract 1.275: the credential is dead, so the
                            // slot parks itself from the ping lane as well (a
                            // no-op for a legacy group engine). This is the
                            // backstop for a slot whose account.changed lane
                            // was missed (a connector restart, a lagged
                            // receiver): without it the engine would sit
                            // resident forever behind a dead credential.
                            if self.preferred_account_id.is_some() {
                                self.retire_device_unlinked().await;
                                stderr_rx = None;
                                stderr_pid = None;
                            }
                        }
                        WatchdogPingOutcome::Failed
                            if !refused.is_empty() && refused.len() == targets.len() =>
                        {
                            // Every attempted candidate answered with the
                            // engine's account-scoped face: the engine is
                            // answering, it just does not serve these
                            // accounts (the stale-row incident). Exclude
                            // them and skip the tick instead of counting a
                            // liveness failure; the next tick walks on to
                            // whatever the attempt cap left unprobed.
                            exclude_refused_ping_targets(
                                &mut verdicts,
                                &refused,
                                targets.len(),
                            );
                            crate::metrics::record_watchdog_liveness_tick_skipped();
                            tracing::info!(
                                reason = "allCandidatesRefused",
                                candidates = targets.len(),
                                "watchdog liveness skipped: the engine refused every candidate"
                            );
                            ping_failures = 0;
                        }
                        WatchdogPingOutcome::Failed => {
                            // An engine-level error ended the series: keep
                            // the pre-existing failure accounting (and its
                            // restart boundary) intact.
                            ping_failures += 1;
                            tracing::debug!(
                                error_class = failed_class.unwrap_or("unknown"),
                                ping_failures,
                                candidates = targets.len(),
                                refused_accounts = refused.len(),
                                "watchdog liveness ping failed"
                            );
                            if ping_failures >= WATCHDOG_MAX_PING_FAILURES
                                && self
                                    .watchdog_request_restart(
                                        &mut last_restart,
                                        &mut pending,
                                        &mut episode,
                                        RestartSource::Ping,
                                        "receive liveness ping failed repeatedly",
                                    )
                                    .await
                            {
                                ping_failures = 0;
                                stderr_rx = None;
                                stderr_pid = None;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn link_flow_active(&self) -> bool {
        self.active_link_finish.lock().await.is_some()
            || self.service.lock().await.has_pending_link()
    }

    /// Resolve this tick's liveness-ping plan.
    ///
    /// A ping only proves something about the receive path when the engine
    /// actually serves the account: an unknown account earns the engine's
    /// plain -32603 in milliseconds, and counting that as a liveness failure
    /// restarted healthy engines once per anti-storm window (the stale-row
    /// incident). So the candidate set is the connector's group rows
    /// intersected with the engine's own `listAccounts` answer; rows the
    /// engine does not list are excluded (and counted) instead of pinged.
    ///
    /// When the cross-check cannot run, the connector-known candidates are
    /// used — except the rows the last successful cross-check already proved
    /// absent, which stay excluded for this engine instance. An engine that
    /// cannot answer `listAccounts` is exactly what the ping threshold exists
    /// for, and silently skipping liveness would weaken that boundary rather
    /// than tighten it.
    async fn watchdog_ping_plan(
        &self,
        engine: &EngineHandle,
        verdicts: &mut WatchdogProbeVerdicts,
    ) -> WatchdogPingPlan {
        if self.active_link_finish.lock().await.is_some() {
            return WatchdogPingPlan::LinkFlow;
        }
        let rows = {
            let service = self.service.lock().await;
            if service.has_pending_link() {
                return WatchdogPingPlan::LinkFlow;
            }
            // Never hold the service lock across an engine call: the store
            // read is the only thing this lock is for.
            match service.signal_account_candidates_in_group(&self.group_id) {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::warn!(
                        error_class = error.class(),
                        "watchdog ping candidate listing failed"
                    );
                    return WatchdogPingPlan::NoTarget(WatchdogPingSkip {
                        reason: "candidateListingFailed",
                        known_accounts: 0,
                        excluded_accounts: 0,
                        engine_verified: false,
                    });
                }
            }
        };
        if rows.is_empty() {
            return WatchdogPingPlan::NoTarget(WatchdogPingSkip {
                reason: "noAccounts",
                known_accounts: 0,
                excluded_accounts: 0,
                engine_verified: false,
            });
        }
        // The engine's own account list is the only authority on which
        // accounts this engine serves.
        let verified = engine_account_numbers(engine).await;
        let mut targets = Vec::new();
        let mut excluded_accounts = 0usize;
        let mut confirmed_accounts = 0usize;
        for row in &rows {
            // Contract 1.275: `device_unlinked` is a terminal verdict, never a
            // silent `engineAbsent` exclusion. The pre-fix shape read "the
            // engine no longer lists it" as "nothing to ping" and left the
            // engine process and the slot resident forever. The terminal state
            // is judged exactly where an exclusion would happen, so a healthy
            // engine's ping path costs no extra store read: a slot whose own
            // account is terminal is retired here (a legacy group engine keeps
            // serving its healthy accounts, so it is only named, never stopped).
            let absent = match &verified {
                Some(numbers) => !numbers.contains(&row.signal_account),
                None => verdicts.engine_absent.contains(&row.id),
            };
            if absent && self.account_is_device_unlinked(&row.id) {
                if self.preferred_account_id.as_deref() == Some(row.id.as_str()) {
                    // A per-account slot serves exactly this account: terminal
                    // means the whole slot is terminal, so it is retired and
                    // this tick has nothing left to probe.
                    self.retire_device_unlinked().await;
                    return WatchdogPingPlan::NoTarget(WatchdogPingSkip {
                        reason: "deviceUnlinked",
                        known_accounts: rows.len(),
                        excluded_accounts: rows.len(),
                        engine_verified: verified.is_some(),
                    });
                }
                // Legacy group engine: one dead account never stops the engine
                // its healthy siblings share. The exclusion is *named* here
                // instead of hiding behind `engineAbsent`, and the row stays out
                // of the probe set for this engine instance.
                if verdicts.engine_absent.insert(row.id.clone()) {
                    crate::metrics::record_watchdog_ping_target_skipped();
                    tracing::info!(
                        account_id = %row.id,
                        reason = "deviceUnlinked",
                        "watchdog ping target excluded: the account holder unlinked this device"
                    );
                }
                excluded_accounts += 1;
                continue;
            }
            if verified.is_some() {
                if absent {
                    // Record once per engine instance; the exclusion itself
                    // applies on every later tick.
                    if verdicts.engine_absent.insert(row.id.clone()) {
                        crate::metrics::record_watchdog_ping_target_skipped();
                        tracing::info!(
                            account_id = %row.id,
                            reason = "engineAbsent",
                            "watchdog ping target excluded: the engine does not list the account"
                        );
                    }
                    excluded_accounts += 1;
                    continue;
                }
                // The engine lists it now (re-link, or an earlier refusal
                // that did not reproduce): it is not absent any more.
                confirmed_accounts += 1;
                verdicts.engine_absent.remove(&row.id);
            } else if verdicts.engine_absent.contains(&row.id) {
                // A failed cross-check does not erase what the last
                // successful one proved: the row stays out of the fallback
                // candidate set for this engine instance.
                excluded_accounts += 1;
                continue;
            }
            if verdicts.refuses(&row.id) {
                excluded_accounts += 1;
                continue;
            }
            targets.push(WatchdogPingTarget {
                account_id: row.id.clone(),
                number: row.signal_account.clone(),
            });
        }
        if verified.is_none() {
            tracing::debug!(
                known_accounts = rows.len(),
                excluded_accounts,
                "watchdog account verification unavailable; probing connector-known candidates"
            );
        }
        if targets.is_empty() {
            let reason = if verified.is_none() {
                "allCandidatesExcluded"
            } else if confirmed_accounts == 0 {
                "noEngineConfirmedAccount"
            } else {
                "allConfirmedCandidatesExcluded"
            };
            return WatchdogPingPlan::NoTarget(WatchdogPingSkip {
                reason,
                known_accounts: rows.len(),
                excluded_accounts,
                engine_verified: verified.is_some(),
            });
        }
        if targets.len() > WATCHDOG_PING_ATTEMPT_LIMIT {
            tracing::debug!(
                candidates = targets.len(),
                attempt_limit = WATCHDOG_PING_ATTEMPT_LIMIT,
                "watchdog ping candidate series capped"
            );
            targets.truncate(WATCHDOG_PING_ATTEMPT_LIMIT);
        }
        WatchdogPingPlan::Probe(targets)
    }

    /// Handle a watchdog restart trigger. Executes immediately unless a link
    /// flow is active (suppressed: restarting would invalidate an in-flight
    /// deviceLinkUri) or the backoff window is still open — in which case the
    /// request is armed as pending with a fixed deadline instead of being
    /// dropped. The window doubles per executed restart inside one episode
    /// (capped), so churn stays bounded while a persistent fault keeps getting
    /// retried. Any executed restart also satisfies an outstanding pending
    /// request. Returns true only when a restart happened now. Logs carry no
    /// phone numbers.
    async fn watchdog_request_restart(
        &self,
        last_restart: &mut Option<Instant>,
        pending: &mut Option<PendingRestart>,
        episode: &mut WatchdogEpisode,
        source: RestartSource,
        reason: &'static str,
    ) -> bool {
        // Contract 1.275: the terminal unlink outranks every restart source. A
        // dead credential is not a liveness fault, and the engine the watchdog
        // would re-spawn can only answer 401 again — so the slot parks itself
        // instead of burning the restart budget.
        if let Some(account_id) = self.preferred_account_id.as_deref()
            && self.account_is_device_unlinked(account_id)
        {
            if self.note_device_unlinked() {
                tracing::warn!(
                    reason,
                    source = %source,
                    account_id = %account_id,
                    group_id = %self.group_id,
                    "watchdog restart refused: the account holder unlinked this device; the slot needs a re-link"
                );
            }
            // Any deferred restart of the dead credential is dropped, not
            // re-armed: nothing about this account is retryable.
            *pending = None;
            // Park the slot as well: a dead or wedged handle must not stay as
            // this slot's engine behind a credential nothing can serve.
            let _ = self.retire_device_unlinked().await;
            return false;
        }
        // O1: a latched contract mismatch is terminal for this process — no
        // watchdog tick may re-spawn the same refused engine.
        if let Some(fault) = self.latched_contract_fault().await {
            tracing::warn!(
                reason,
                source = %source,
                engine_version = fault.engine_version.as_deref().unwrap_or("unknown"),
                contract_reason = fault.reason.as_str(),
                "watchdog restart refused: the engine contract mismatch is latched"
            );
            return false;
        }
        // A trigger-free gap longer than the anti-storm window starts a fresh
        // episode with the fast (immediate) path restored.
        if let Some(last_trigger) = episode.last_trigger
            && last_trigger.elapsed() > self.config.watchdog_min_restart_interval
        {
            episode.restarts = 0;
        }
        episode.last_trigger = Some(Instant::now());

        if self.link_flow_active().await {
            crate::metrics::record_watchdog_restart_suppressed();
            tracing::warn!(
                reason,
                source = %source,
                "watchdog restart suppressed: link in progress"
            );
            return false;
        }
        // Receive-liveness retries use their own seconds-scale base. The
        // five-minute watchdog_min_restart_interval is the anti-storm window
        // (episode reset), never the retry pace: using it here left users
        // "connected once every five minutes" during a dead receive path.
        let backoff = watchdog_restart_backoff(
            self.config.watchdog_liveness_backoff_base,
            episode.restarts,
            WATCHDOG_LIVENESS_BACKOFF_CAP,
        );
        let now = Instant::now();
        if let Some(last) = *last_restart {
            let due_at = last + backoff;
            if now < due_at {
                let armed = arm_pending_restart(
                    pending,
                    PendingRestart {
                        source,
                        reason,
                        due_at,
                        evidence: self.receive_evidence.load(Ordering::Relaxed),
                    },
                );
                let retry_in_ms = (due_at - now).as_millis().min(u64::MAX as u128) as u64;
                if armed {
                    crate::metrics::record_watchdog_restart_deferred();
                    tracing::warn!(
                        reason,
                        source = %source,
                        episode_restarts = episode.restarts,
                        backoff_ms = backoff.as_millis().min(u64::MAX as u128) as u64,
                        retry_in_ms,
                        "watchdog restart throttled; recorded as pending"
                    );
                } else {
                    // The same fault is already armed with an earlier (or
                    // higher-priority) deadline; do not spam the log every
                    // tick while the window is open.
                    tracing::debug!(
                        reason,
                        source = %source,
                        episode_restarts = episode.restarts,
                        retry_in_ms,
                        "watchdog restart already pending; deadline unchanged"
                    );
                }
                return false;
            }
        }
        let label = if episode.restarts == 0 {
            "initial"
        } else {
            "backoff-elapsed"
        };
        tracing::warn!(
            %label,
            reason,
            source = %source,
            account_id = self.preferred_account_id.as_deref().unwrap_or("-"),
            group_id = %self.group_id,
            episode_restarts = episode.restarts,
            "watchdog restarting the engine"
        );
        match self.restart_engine().await {
            Ok(()) => {
                crate::metrics::record_watchdog_restart();
                *last_restart = Some(Instant::now());
                episode.restarts = episode.restarts.saturating_add(1);
                *pending = None;
                true
            }
            Err(error) => {
                // Not a restart: keep the previous last_restart so the next
                // trigger retries, and surface the failure instead of
                // returning silently.
                crate::metrics::record_watchdog_restart_failed();
                tracing::warn!(
                    reason,
                    source = %source,
                    error = %error,
                    "watchdog restart failed; the next trigger retries"
                );
                false
            }
        }
    }

    /// Clear one local Signal account (desktop exit). Not remote primary unregister.
    /// Local rows are removed only after signal-cli confirms success. Unknown outcomes
    /// are surfaced without an automatic retry or local state loss.
    pub async fn delete_local_account(
        &self,
        account_id: String,
        operation_id: Option<String>,
    ) -> Result<Value, ServiceError> {
        if let Some(operation_id) = operation_id.as_deref() {
            validate_account_delete_operation_id(operation_id)?;
        }
        let (number, reconcile_first) = match operation_id.as_deref() {
            Some(operation_id) => {
                // Bind the plan before matching: the lock guard borrowed by the
                // prepare call would otherwise live for the whole match, and the
                // Completed arm re-locks below.
                let plan = self
                    .service
                    .lock()
                    .await
                    .prepare_account_delete(&account_id, operation_id)?;
                match plan {
                    // Idempotent replay of an already-completed delete: the
                    // account session is long gone, so any straggler media
                    // handles from before are released here too.
                    AccountDeletePlan::Completed => {
                        self.clear_account_delete_residue(&account_id).await;
                        // A replay is also the repair point for a crash
                        // between the row transaction and the backup scrub.
                        let _ = self.finish_account_delete_residue_async(&account_id).await;
                        return Ok(account_delete_result(
                            self.store
                                .account_delete_receipt(&account_id)
                                .ok()
                                .flatten(),
                        ));
                    }
                    AccountDeletePlan::Dispatch {
                        signal_account,
                        reconcile_first,
                    } => (signal_account, reconcile_first),
                }
            }
            None => {
                // Bind the number before matching: the temporary service
                // guard would otherwise live for the whole match and the
                // absent arm's cleanup re-locks the service (self-deadlock).
                let number = self
                    .service
                    .lock()
                    .await
                    .account_signal_number_optional(&account_id)?;
                match number {
                    Some(number) => (number, false),
                    None => {
                        self.clear_account_delete_residue(&account_id).await;
                        let _ = self.finish_account_delete_residue_async(&account_id).await;
                        return Ok(account_delete_result(
                            self.store
                                .account_delete_receipt(&account_id)
                                .ok()
                                .flatten(),
                        ));
                    }
                }
            }
        };
        let engine = self.running_engine().await?;
        // [KT 适配] §9.10 item 6: cancel this account's engine-side tasks
        // before the destructive delete. The pinned engine exposes exactly one
        // account-task cancel face, `history.importCancel {account}` — it
        // aborts the in-flight transfer-archive download and a live
        // cloud-backup restore (kt-signal-engine `docs/jsonrpc-compat.md:202`).
        // `backup.export`, `backup.importSnapshot` and `backups.uploadToCloud`
        // have no cancel verb in that contract, and inventing one is
        // forbidden; for those the engine's own account removal is the stop
        // (their next disk touch fails), while the connector releases every
        // local handle below. Best-effort: a cancel failure never blocks the
        // user's delete.
        if let Err(error) = self.history_import_cancel(account_id.clone()).await {
            tracing::warn!(
                error_class = error.class(),
                "account task cancel before local-data delete failed; delete proceeds"
            );
        }
        if reconcile_first && !signal_account_present(&engine, &number).await? {
            let receipt = {
                let mut service = self.service.lock().await;
                let receipt = service
                    .complete_account_delete_recorded(&account_id, operation_id.as_deref())?;
                service.clear_media_for_account(&account_id);
                receipt
            };
            let receipt = match receipt {
                Some(receipt) => self
                    .finish_account_delete_residue_async(&account_id)
                    .await
                    .or(Some(receipt)),
                None => None,
            };
            self.clear_account_delete_files(&account_id);
            return Ok(account_delete_result(receipt));
        }
        match engine
            .call_with_timeout(
                "deleteLocalAccountData",
                json!({
                    "account": number,
                    "ignoreRegistered": true,
                }),
                CallClass::Mutating,
                Duration::from_secs(60),
            )
            .await
        {
            Ok(_) => {}
            Err(EngineError::UnknownOutcome) => {
                if let Some(operation_id) = operation_id.as_deref() {
                    let _ = self
                        .service
                        .lock()
                        .await
                        .mark_account_delete_unknown(operation_id);
                }
                return Err(ServiceError::Api(ApiError::new(
                    "ACCOUNT_DELETE_OUTCOME_UNKNOWN",
                    "local account deletion has an unknown outcome",
                    false,
                )));
            }
            Err(error) => return Err(ServiceError::Engine(error)),
        }
        let receipt = {
            let mut service = self.service.lock().await;
            let receipt =
                service.complete_account_delete_recorded(&account_id, operation_id.as_deref())?;
            // ADR 0004 gate 3: a chunk-stream handle cannot outlive the
            // account session it was opened from — media and §4.46 backup
            // file streams alike.
            service.clear_media_for_account(&account_id);
            receipt
        };
        // §4.197: the store rows are gone; scrub the account out of the
        // plaintext migration backup (outside the service lock — VACUUM can
        // take a moment and nothing here needs the service).
        let receipt = match receipt {
            Some(receipt) => self
                .finish_account_delete_residue_async(&account_id)
                .await
                .or(Some(receipt)),
            None => None,
        };
        self.clear_account_delete_files(&account_id);
        Ok(account_delete_result(receipt))
    }

    /// Contract 1.197 (§4.197, D4): release every connector-owned handle or
    /// file that outlives the account row. Engine-owned media and the engine
    /// account directory are removed by the engine's own
    /// `deleteLocalAccountData` (the connector never reaches into that tree);
    /// this clears the connector's handles and its `state-dir` products.
    async fn clear_account_delete_residue(&self, account_id: &str) {
        self.service
            .lock()
            .await
            .clear_media_for_account(account_id);
        self.clear_account_delete_files(account_id);
    }

    /// The plaintext-backup scrub runs `VACUUM`; keep it off the async
    /// runtime's thread. Returns `None` when no receipt exists.
    async fn finish_account_delete_residue_async(
        &self,
        account_id: &str,
    ) -> Option<crate::store::AccountDeleteReceipt> {
        let store = Arc::clone(&self.store);
        let account_id = account_id.to_string();
        match tokio::task::spawn_blocking(move || store.finish_account_delete_residue(&account_id))
            .await
        {
            Ok(Ok(receipt)) => receipt,
            _ => None,
        }
    }

    fn clear_account_delete_files(&self, account_id: &str) {
        if let Some(handles) = self.backup_handles.as_ref() {
            handles.clear_account(account_id);
        }
        // §4.115: the plaintext task record and its artifact directory die
        // with the account session too — an export product never outlives it.
        self.plaintext_tasks.clear(account_id);
        crate::backup_export::clear_plaintext_artifacts(self.store.state_dir(), account_id);
        // In-memory, per-account caches: none may outlive the account.
        self.backup_counters
            .lock()
            .expect("backup counters mutex")
            .remove(account_id);
        let receipt_prefix = format!("{account_id}\u{0}");
        self.receipt_failures
            .lock()
            .expect("receipt failure mutex")
            .retain(|key, _| !key.starts_with(&receipt_prefix));
        self.group_resync_stamps
            .lock()
            .expect("group resync stamp mutex")
            .retain(|(account, _group), _| account != account_id);
        self.history_import_cancels
            .lock()
            .expect("history import cancel mutex")
            .remove(account_id);
    }

    pub async fn list_conversations(
        &self,
        account_id: String,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<Page<ConversationSummary>, ServiceError> {
        // Best-effort title enrich only when masks remain or a fresh direct
        // row still owes its §4.58 factor probe — and at most every 60s so
        // poll/UI refresh does not hammer listContacts on the single engine
        // queue.
        let _ = self.enrich_conversation_faces_throttled(&account_id).await;
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            store_list_conversations(&store, &account_id, limit, cursor.as_deref())
        })
        .await
    }

    /// Resolve human titles for direct chats still showing mask_address(peer)
    /// and, on the same one listContacts round trip, stamp the §4.58
    /// message-request factor trio. Throttled to at most one engine call per
    /// 60s; the call fires only when a mask remains or a fresh direct row has
    /// never been probed, so a fully-enriched account costs no engine traffic.
    async fn enrich_conversation_faces_throttled(
        &self,
        account_id: &str,
    ) -> Result<(), ServiceError> {
        let (peers, mrr_missing, trust_missing) = tokio::task::spawn_blocking({
            let store = Arc::clone(&self.store);
            let account_id = account_id.to_string();
            move || {
                let peers = store.list_direct_peers_needing_title(&account_id)?;
                // The §4.58 probe only widens the trigger: a page with masks
                // to resolve fires anyway, so the count is read only when the
                // title fast path would otherwise skip the engine call. The
                // counter itself only owes rows whose derivation can flip on
                // a stamp (data window without outgoing rows), so the probe
                // never wakes for rows the window weight already settles.
                let mrr_missing = if peers.is_empty() {
                    store.count_direct_conversations_without_mrr_factors(&account_id)?
                } else {
                    0
                };
                // Contract 1.260 (§4.244): the verified probe only widens the
                // trigger further — read when the title and factor fast paths
                // would both otherwise skip the engine call (one full
                // `listIdentities` read stamps the whole account, so the
                // count self-extinguishes after one pass).
                let trust_missing = if peers.is_empty() && mrr_missing == 0 {
                    store.count_direct_conversations_without_identity_verified(&account_id)?
                } else {
                    0
                };
                Ok((peers, mrr_missing, trust_missing))
            }
        })
        .await
        .unwrap_or(Err(StoreError::Unavailable(None)))?;
        if peers.is_empty() && mrr_missing == 0 && trust_missing == 0 {
            return Ok(());
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = self.last_title_enrich_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 60_000 {
            return Ok(());
        }
        self.last_title_enrich_ms.store(now_ms, Ordering::Relaxed);
        let engine = {
            let guard = self.engine.lock().await;
            guard
                .clone()
                .ok_or(ServiceError::Engine(EngineError::NotRunning))?
        };
        let number = self
            .service
            .lock()
            .await
            .account_signal_number(account_id)?;
        let result = engine
            .call(
                "listContacts",
                json!({
                    "account": number,
                    "allRecipients": true,
                }),
                CallClass::ReadOnly,
            )
            .await
            .map_err(ServiceError::Engine)?;
        let items = result.as_array().cloned().unwrap_or_default();
        // The row updates are store-only; they run batched on the blocking
        // pool without the service lock.
        let write_backs = tokio::task::spawn_blocking({
            let store = Arc::clone(&self.store);
            let account_id = account_id.to_string();
            let items = items.clone();
            move || {
                for (peer_key, _title) in peers {
                    if let Some(name) = find_contact_display_name(&items, &peer_key) {
                        let _ = store.set_conversation_title_for_peer(
                            &account_id,
                            "direct",
                            &peer_key,
                            &name,
                        );
                    }
                }
                // Contract 1.65 (§4.58): the factor stamp rides the same
                // answer. Every engine contact with a direct conversation row
                // gets exactly the flags the engine exposed; an item without
                // any of the three (the kt-engine read face today) stamps the
                // probed-absent `{}` so the probe never re-fires for that
                // row. Per-item failures are warn-silent by the same
                // discipline as the title pass — one bad stamp never fails
                // the list that triggered the enrich.
                for item in &items {
                    let Some(peer_key) = contact_item_peer_key(item) else {
                        continue;
                    };
                    let factors = mrr_factors_stamp(item);
                    let _ = store.set_conversation_mrr_factors_for_peer(
                        &account_id,
                        peer_key,
                        &factors,
                    );
                }
                // 契约 1.268（§4.252 · 批 Z12 · S16）：回写目标的变化检测
                // rides the same blocking pass（store 读共用线程池）。
                hidden_write_back_targets(&items, &|uuid| {
                    store
                        .conversation_hidden_bit(&account_id, uuid)
                        .unwrap_or(None)
                })
            }
        })
        .await
        .map_err(|_| StoreError::Unavailable(None))?;
        // Contract 1.260 (§4.244): the verified storage-consumption leg —
        // Z25 根因修复（2026-10-25，台账 §29.118）：引擎 listIdentities 面
        // 是单引用窄读（engine compat §3/§5 行：number 必填，账号全量清单
        // 形态不提供）。本臂原发 {account} 缺 number，引擎按契约恒
        // -32603（duration_ms=0），? 把整条 enrich 中断：verified 戳永不落
        // → 触发计数永不自熄 → 60s internal_error 无限循环（活体事故实
        // 证）。改为对欠戳行逐行单引用读 {account, number: peer_key}：
        // 有界（VERIFIED_PROBE_WINDOW_CAP/窗，hidden 回写纯面帽同款），
        // 自熄语义逐字保留——读到词行落词戳（uuid/number 双拼写同前），
        // 读成功而无 identity（官方 SafetyNumberNotReady 态，非错误）落该
        // 行 probed-absent {}；引擎错误行保持 NULL 下一窗重试（60s 节流即
        // 窗内退避，绝不窗内重试轰炸引擎）。store 写单趟 blocking 池，逐行
        // best-effort（一行失败不炸本窗——title-pass 纪律）。
        let owed_peers = tokio::task::spawn_blocking({
            let store = Arc::clone(&self.store);
            let account_id = account_id.to_string();
            move || {
                store.direct_peers_without_identity_verified(&account_id, VERIFIED_PROBE_WINDOW_CAP)
            }
        })
        .await
        .map_err(|_| StoreError::Unavailable(None))??;
        // (owed peer key, stamp keys, word) 收集在 await 循环，store 写单趟。
        let mut probed: Vec<(String, Vec<String>, Option<String>)> = Vec::new();
        for peer_key in owed_peers {
            let identities = engine
                .call(
                    "listIdentities",
                    json!({
                        "account": number,
                        "number": peer_key,
                    }),
                    CallClass::ReadOnly,
                )
                .await;
            let entries = match identities {
                Ok(value) => value.as_array().cloned().unwrap_or_default(),
                Err(error) => {
                    tracing::warn!(
                        kind = "identity_verified_probe",
                        class = error.class(),
                        "engine listIdentities read failed; the row stays owed for the next window",
                    );
                    continue;
                }
            };
            let word = entries.iter().find_map(|entry| {
                let word = entry.get("trustLevel").and_then(Value::as_str)?;
                IDENTITY_TRUST_WORDS
                    .contains(&word)
                    .then(|| word.to_string())
            });
            // 词戳双拼写同前（uuid/e164 各落己行形，row key 随创建捕获拼
            // 写）；无词 = probed-absent，只落欠戳行本身（单引用读答不出
            // 的拼写无从落）。
            let mut keys = vec![peer_key.clone()];
            if word.is_some() {
                for entry in &entries {
                    for key in ["uuid", "number"] {
                        if let Some(spelling) = entry
                            .get(key)
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|spelling| {
                                !spelling.is_empty() && !keys.iter().any(|k| k == spelling)
                            })
                        {
                            keys.push(spelling.to_string());
                        }
                    }
                }
            }
            probed.push((peer_key, keys, word));
        }
        let _ = tokio::task::spawn_blocking({
            let store = Arc::clone(&self.store);
            let account_id = account_id.to_string();
            move || {
                for (owed_peer, keys, word) in &probed {
                    let Some(word) = word else {
                        let _ = store.stamp_identity_verified_absent_peer(&account_id, owed_peer);
                        continue;
                    };
                    for key in keys {
                        let _ = store.set_conversation_identity_verified_for_peer(
                            &account_id,
                            key,
                            word,
                        );
                    }
                }
            }
        })
        .await;
        // 引擎存储回写（两仓契约的 connector 半）：有界/轮（纯面帽 16），
        // best-effort warn-only——丢失的回写让引擎读臂暂退批 W 反演近似，
        // 下一次 hidden 变化自然再火，绝不阻断 enrich。uuid = 引擎
        // allRecipients 条目的 ServiceId 串；号码键行无 uuid 永不收集。
        for (peer_aci, hidden) in &write_backs {
            let upstream = json!({
                "account": number,
                "peerAci": peer_aci,
                "hidden": hidden,
            });
            if let Err(error) = engine
                .call("setConversationHidden", upstream, CallClass::ReadOnly)
                .await
            {
                tracing::warn!(
                    kind = "conversation_hidden_write_back",
                    class = error.class(),
                    "engine hidden write-back skipped; the read arms keep the batch-W approximation",
                );
            }
        }
        Ok(())
    }

    /// messages.setAttachmentDimensions (contract revision 1.271, §4.255): a
    /// local store write on the send lane — the conversations.saveDraft class
    /// (mutating, account-scoped mutex and delete barrier, no engine frame, no
    /// upstream traffic). The lane/mutex classification lives in the method
    /// table; this wrapper only hands the work to the blocking pool.
    pub async fn set_attachment_dimensions(
        &self,
        params: crate::service::MessagesSetAttachmentDimensionsParams,
    ) -> Result<crate::service::AttachmentDimensionsWriteResult, ServiceError> {
        let store = Arc::clone(&self.store);
        blocking_service(move || crate::service::store_set_attachment_dimensions(&store, &params))
            .await
    }

    /// messages.listAttachmentDimensions (contract revision 1.271, §4.255): a
    /// bounded store-only read on the read lane — no upstream traffic, no
    /// mutation, and no unread side effect (the §4.76 adjacentMedia posture).
    pub async fn list_attachment_dimensions(
        &self,
        params: crate::service::MessagesListAttachmentDimensionsParams,
    ) -> Result<crate::service::AttachmentDimensionsListResult, ServiceError> {
        let store = Arc::clone(&self.store);
        blocking_service(move || crate::service::store_list_attachment_dimensions(&store, &params))
            .await
    }

    pub async fn list_messages(
        &self,
        account_id: String,
        conversation_id: String,
        limit: u32,
        before: Option<String>,
    ) -> Result<Page<MessageRecord>, ServiceError> {
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            store_list_messages(
                &store,
                &account_id,
                &conversation_id,
                limit,
                before.as_deref(),
            )
        })
        .await
    }

    /// 契约 1.204（M4b）：以锚点为中心取窗（store-only 读面，与
    /// messages.list 同车道纪律——不经 service 锁）。
    pub async fn list_messages_around(
        &self,
        account_id: String,
        conversation_id: String,
        anchor_message_id: Option<String>,
        limit: u32,
    ) -> Result<Option<Page<MessageRecord>>, ServiceError> {
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            if store.account_by_id(&account_id)?.is_none() {
                return Err(crate::store::StoreError::AccountNotFound.into());
            }
            match anchor_message_id {
                Some(anchor) => Ok(Some(store.list_messages_around(
                    &account_id,
                    &conversation_id,
                    &anchor,
                    limit,
                )?)),
                None => Ok(store.list_messages_around_oldest_unread(
                    &account_id,
                    &conversation_id,
                    limit,
                )?),
            }
        })
        .await
    }

    pub async fn list_adjacent_media(
        &self,
        account_id: String,
        conversation_id: String,
        anchor_message_id: String,
        direction: crate::store::AdjacentMediaDirection,
        limit: u32,
    ) -> Result<Vec<MessageRecord>, ServiceError> {
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            store_adjacent_media(
                &store,
                &account_id,
                &conversation_id,
                &anchor_message_id,
                direction,
                limit,
            )
        })
        .await
    }

    pub async fn search_messages(
        &self,
        account_id: String,
        query: String,
        limit: u32,
        cursor: Option<String>,
        conversation_id: Option<String>,
    ) -> Result<Page<MessageRecord>, ServiceError> {
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            store_search_messages(
                &store,
                &account_id,
                &query,
                limit,
                cursor.as_deref(),
                conversation_id.as_deref(),
            )
        })
        .await
    }

    pub async fn get_message_text(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<crate::service::MessageText, ServiceError> {
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            store_get_message_text(&store, &account_id, &conversation_id, &message_id)
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_text(
        &self,
        account_id: String,
        target: SendTarget,
        text: String,
        client_request_id: String,
        quote_message_id: Option<String>,
        previews: Option<Vec<SendTextPreviewParams>>,
        mentions: Option<Vec<SendTextMentionParams>>,
        text_styles: Option<Vec<SendTextStyleParams>>,
        story_reply_author: Option<String>,
        story_reply_timestamp: Option<Value>,
    ) -> Result<MessageRecord, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            match &target {
                SendTarget::Conversation(conversation_id) => service.prepare_send_text(
                    &account_id,
                    conversation_id,
                    &text,
                    &client_request_id,
                    quote_message_id.as_deref(),
                    previews,
                    mentions,
                    text_styles,
                    story_reply_author,
                    story_reply_timestamp,
                )?,
                SendTarget::Peer {
                    kind,
                    peer_key,
                    peer_title,
                } => service.prepare_send_text_to_peer(
                    &account_id,
                    &PeerTarget {
                        kind,
                        peer_key,
                        peer_title: peer_title.as_deref(),
                    },
                    &text,
                    &client_request_id,
                    quote_message_id.as_deref(),
                    previews,
                    mentions,
                    text_styles,
                    story_reply_author,
                    story_reply_timestamp,
                )?,
            }
        };
        self.dispatch_prepared(&engine, prepared).await
    }

    /// messages.getByClientRequestId (contract 1.172, §4.172): the read-only
    /// orphan-sweep probe — the service lock guards the in-memory projection
    /// state, so this reads under the lock like the retry face; no engine
    /// touch, no mutation.
    pub async fn get_message_by_client_request(
        &self,
        account_id: String,
        conversation_id: String,
        client_request_id: String,
    ) -> Result<MessageRecord, ServiceError> {
        let service = self.service.lock().await;
        service.get_message_by_client_request(&account_id, &conversation_id, &client_request_id)
    }

    /// messages.receipts (contract 1.190, §4.190 ⑤): the per-recipient
    /// receipt ledger read — local store only, under the service lock like
    /// every read face; no engine touch, no mutation.
    pub async fn get_message_receipts(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<Vec<crate::store::RecipientReceiptRow>, ServiceError> {
        let service = self.service.lock().await;
        service.get_message_receipts(&account_id, &conversation_id, &message_id)
    }

    /// Retry one definitively-failed outgoing text in place (contract 1.31,
    /// implementation-plan §4.26, replay semantics §4.172). Same settlement
    /// path as `send_text` — the
    /// pending row rearmed by `prepare_retry_text` keeps its original id, so
    /// success / unknown / failure all complete the SAME row the desktop
    /// bubble renders and no superseded duplicate row can appear.
    pub async fn retry_text(
        &self,
        account_id: String,
        conversation_id: String,
        client_request_id: String,
    ) -> Result<MessageRecord, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_retry_text(&account_id, &conversation_id, &client_request_id)?
        };
        self.dispatch_prepared(&engine, prepared).await
    }

    /// §4.173: count the engine `send` reply's per-recipient `results` array
    /// (the group send shape: `{recipientNumber, success:{timestamp}}` /
    /// `{recipientNumber, failure:{type}}` entries) into success/failure
    /// totals. `None` — no array, an empty array, or no recognizable entry —
    /// keeps the row on the pre-1.173 shape (no outcomes face; direct sends
    /// always land here).
    fn send_outcomes_from_reply(result: &Value) -> Option<crate::store::MessageSendOutcomes> {
        let entries = result.get("results")?.as_array()?;
        let mut counted = crate::store::MessageSendOutcomes {
            succeeded: 0,
            failed: 0,
            deleted_for_everyone_send_status: None,
        };
        for entry in entries {
            if entry.get("success").is_some() {
                counted.succeeded = counted.succeeded.saturating_add(1);
            } else if entry.get("failure").is_some() {
                counted.failed = counted.failed.saturating_add(1);
            }
        }
        (counted.succeeded > 0 || counted.failed > 0).then_some(counted)
    }

    /// §4.190 ⑦ (the optional arm): expand the same `results` array into
    /// per-recipient Sent/Failed ledger seeds — the §4.173 counts
    /// de-aggregated, the official `sendStateByConversationId` posture
    /// (every addressed recipient starts at Sent,
    /// MessageReceipts.preload.ts:462-490). `None` when the reply carried no
    /// recognizable array (the direct-send shape: single recipient, the row
    /// status is the whole story — no seeds); entries without a usable
    /// recipient identity skip individually; the batch is bounded at 256,
    /// the receipt faces' own ceiling.
    fn send_receipt_seeds_from_reply(result: &Value) -> Option<Vec<crate::store::SendReceiptSeed>> {
        let entries = result.get("results")?.as_array()?;
        let mut seeds = Vec::new();
        for entry in entries.iter().take(256) {
            let Some(recipient) = entry
                .get("recipientNumber")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if entry.get("success").is_some() {
                seeds.push(crate::store::SendReceiptSeed {
                    recipient: recipient.to_string(),
                    succeeded: true,
                });
            } else if entry.get("failure").is_some() || entry.get("error").is_some() {
                seeds.push(crate::store::SendReceiptSeed {
                    recipient: recipient.to_string(),
                    succeeded: false,
                });
            }
        }
        (!seeds.is_empty()).then_some(seeds)
    }

    /// 契约 1.274：把 remoteDelete 的逐收件人 results 展开为
    /// deletedForEveryoneSendStatus（success=true / failure=false）。
    fn deleted_for_everyone_send_status_from_reply(
        result: &Value,
    ) -> std::collections::BTreeMap<String, bool> {
        let mut status = std::collections::BTreeMap::new();
        for seed in Self::send_receipt_seeds_from_reply(result).unwrap_or_default() {
            status.insert(seed.recipient, seed.succeeded);
        }
        status
    }

    async fn dispatch_prepared(
        &self,
        engine: &EngineHandle,
        prepared: PreparedSend,
    ) -> Result<MessageRecord, ServiceError> {
        match prepared {
            PreparedSend::Existing(message) => Ok(*message),
            PreparedSend::Dispatch {
                pending_id,
                account_id,
                conversation_id,
                params,
                pending_sent_at,
            } => match engine.call("send", params, CallClass::Mutating).await {
                Ok(result) => {
                    let sent_at = result
                        .get("timestamp")
                        .and_then(Value::as_u64)
                        .unwrap_or(pending_sent_at);
                    // §4.173: the reply's per-recipient `results` array (the
                    // group send shape) counted into success/failure totals.
                    // Absent on direct sends (single recipient — the row
                    // status is the whole story) and on any shape-hostile
                    // array, which degrade to the pre-1.173 behavior.
                    // §4.190 ⑦: the same array expands into per-recipient
                    // Sent/Failed ledger seeds beside the counts.
                    let outcomes = Self::send_outcomes_from_reply(&result);
                    let seeds = Self::send_receipt_seeds_from_reply(&result);
                    if outcomes
                        .as_ref()
                        .is_some_and(|counted| counted.succeeded == 0)
                    {
                        // Every recipient failed: nothing was delivered, so
                        // the row settles definitively failed (retryable —
                        // nobody got it, a resend carries no duplicate risk)
                        // and the answer reports GROUP_SEND_FAILED.
                        let events = self
                            .service
                            .lock()
                            .await
                            .complete_send_failed_group_outcomes(
                                &pending_id,
                                outcomes
                                    .as_ref()
                                    .expect("guarded by the succeeded == 0 check"),
                                seeds.as_deref().unwrap_or(&[]),
                            )?;
                        for event in events {
                            let _ = self.host_events.send(event);
                        }
                        return Err(ServiceError::Api(ApiError::new(
                            "GROUP_SEND_FAILED",
                            "send failed for every recipient",
                            true,
                        )));
                    }
                    let (message, events) =
                        self.service.lock().await.complete_send_success_seeded(
                            &pending_id,
                            &account_id,
                            &conversation_id,
                            sent_at,
                            outcomes.as_ref(),
                            seeds.as_deref().unwrap_or(&[]),
                        )?;
                    for event in events {
                        let _ = self.host_events.send(event);
                    }
                    Ok(message)
                }
                Err(EngineError::UnknownOutcome) => {
                    let events = self
                        .service
                        .lock()
                        .await
                        .complete_send_unknown(&pending_id)?;
                    for event in events {
                        let _ = self.host_events.send(event);
                    }
                    Err(ServiceError::Api(ApiError::new(
                        "SEND_OUTCOME_UNKNOWN",
                        "mutating request has an unknown outcome",
                        false,
                    )))
                }
                Err(error) => {
                    // §4.123: the funnel settles classified — a
                    // definitive-error answer in an automatic-retry arm also
                    // arms the bounded queue schedule in the same guarded
                    // write (the transport family on the curve beat, the
                    // rate-limit family on the Retry-After beat), and kicks
                    // the drain so the beat is honored at its own pace
                    // instead of the tick's; every other class (and the
                    // unknown outcome above, which never reaches this arm)
                    // settles plain.
                    let events = self
                        .service
                        .lock()
                        .await
                        .complete_send_failed_for_engine(&pending_id, &error)?;
                    for event in events {
                        let _ = self.host_events.send(event);
                    }
                    if ConnectorService::auto_retry_schedule(&error)
                        != crate::store::SendRetrySchedule::None
                    {
                        self.notify_outbox_drain();
                    }
                    Err(ServiceError::Engine(error))
                }
            },
        }
    }

    /// messages.sendStory (contract revision 1.76, §4.67): one bounded story
    /// text out through the engine's `sendStory` face (engine compat §3
    /// send batch). Stories live outside every conversation — no local row,
    /// no `clientRequestId`, no pending settlement: prepare under the
    /// service lock, one mutating call, and the answer is the upstream
    /// truth projected (`story_from_engine`). An indeterminate mutating
    /// outcome answers SEND_OUTCOME_UNKNOWN and is never retried (the §5
    /// send discipline, rowless variant — there is no pending row to
    /// settle, and a story is idempotent upstream by its own timestamp).
    /// Contract 1.157 (§4.155): the group audience leg rides the same one
    /// mutating call — the engine answers its additive `group` face and the
    /// projection passes it through (absent stays absent); a group-leg
    /// refusal rides the structured ladder, its non-allowlisted `SEND_*`
    /// literals degrading to the plain UPSTREAM_ERROR exactly like every
    /// upstream code the host contract does not declare. Contract 1.161
    /// (§4.159): the engine's media-upload pointer faces ride the answer
    /// verbatim on both legs (the top-level `fileAttachment` for the roster
    /// leg, `group.fileAttachment` for the group leg) — raw-value transit,
    /// zero CDN resolution, zero pointer consumption; the desktop's own
    /// read-back chain is the downstream consumer batch.
    pub async fn send_story(
        &self,
        params: MessagesSendStoryParams,
    ) -> Result<StorySendResult, ServiceError> {
        let engine = self.running_engine().await?;
        let frame = {
            let service = self.service.lock().await;
            service.prepare_send_story(&params)?
        };
        match engine.call("sendStory", frame, CallClass::Mutating).await {
            Ok(result) => story_from_engine(&result),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// stories.setDisabled (contract revision 1.76, §4.67): the account's
    /// stories-disabled toggle — the receive-gate mirror of the official
    /// `getStoriesBlocked` leg. Local store only (no engine frame exists):
    /// validation + account pin under the
    /// service lock, then the meta-KV write on the blocking pool. The
    /// result is the stored truth, not an echo of the request.
    pub async fn set_stories_disabled(
        &self,
        params: StoriesSetDisabledParams,
    ) -> Result<StoriesDisabled, ServiceError> {
        {
            let service = self.service.lock().await;
            service.prepare_stories_set_disabled(&params)?;
        }
        let store = Arc::clone(&self.store);
        let account_id = params.account_id;
        let disabled = params.disabled;
        blocking_service(move || {
            store.set_stories_disabled(&account_id, disabled)?;
            Ok(StoriesDisabled { disabled })
        })
        .await
    }

    /// stories.getDisabled (contract revision 1.76, §4.67): the same local
    /// toggle, read side — an account with no stored state answers the
    /// official default (stories enabled).
    pub async fn get_stories_disabled(
        &self,
        params: StoriesGetDisabledParams,
    ) -> Result<StoriesDisabled, ServiceError> {
        {
            let service = self.service.lock().await;
            service.prepare_stories_get_disabled(&params)?;
        }
        let store = Arc::clone(&self.store);
        let account_id = params.account_id;
        blocking_service(move || {
            Ok(StoriesDisabled {
                disabled: store.stories_disabled(&account_id)?,
            })
        })
        .await
    }

    /// stories.markViewed (contract revision 1.85, §4.70): the story-anchored
    /// viewed receipt — the `messages.markViewed` receipt class verbatim
    /// (best-effort, `{status: sent|unknown}`, any upstream failure
    /// degrades and nothing retries) with the §4.29 row selection replaced
    /// by the story anchor frame. One mutating `sendViewedReceipt` call
    /// upstream (the author is a single recipient, one timestamp per frame —
    /// there is no fan-out: a story receipt names exactly one story).
    pub async fn send_story_viewed(
        &self,
        params: StoriesMarkViewedParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let frame = {
            let service = self.service.lock().await;
            service.prepare_story_mark_viewed(&params)?
        };
        match engine
            .call("sendViewedReceipt", frame, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            // Receipt-class degradation: the pin-family discipline — a
            // definite upstream error, transport trouble, or an unknown
            // outcome only degrades the answer; nothing is ever retried
            // (AGENTS.md).
            Err(_) => Ok("unknown"),
        }
    }

    /// stories.sendReaction (contract 1.152, §4.151; the group leg contract
    /// 1.159, §4.157): the story-anchored reaction send — the §4.150
    /// call-event proxy posture on the stories family. The account
    /// resolution rides the service prepare, the engine's `sendStoryReaction`
    /// crosses as its own mutating call (the official reactToStory
    /// alignment, the Reaction + StoryContext dual anchor), the success
    /// answer (`{}` on the 1:1 leg, additive `{group:{groupId,timestamp}}`
    /// on the group leg, engine `a6c0520`) passes through untouched, and
    /// the error face is the engine's verbatim through the structured
    /// ladder: the plain -32603 parse/identity/profileSharing faces and the
    /// group leg's decode/-1-word structured faces degrade to UPSTREAM_ERROR,
    /// the §4.17 unbound matcher still applies, and the connector adds no
    /// gate of its own (the engine parse owns the value domain). Mutating
    /// class: a timeout answers SEND_OUTCOME_UNKNOWN and is never retried —
    /// an unknown reaction outcome may already sit in the author's or the
    /// group's fan-out.
    pub async fn send_story_reaction(
        &self,
        params: StoriesSendReactionParams,
    ) -> Result<Value, ServiceError> {
        let frame = {
            let service = self.service.lock().await;
            service.prepare_story_send_reaction(&params)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("sendStoryReaction", frame, CallClass::Mutating)
            .await
            .map_err(ServiceError::from)
    }

    /// stories.deleteForEveryone (contract 1.153, §4.152): the
    /// story-anchored delete fan-out — the §4.150 call-event proxy posture
    /// on the stories family. The account resolution rides the service
    /// prepare, the engine's `deleteStoryForEveryone` crosses as its own
    /// mutating call (the official sendDeleteStoryForEveryone alignment:
    /// the per-recipient DOE legs over the story channel plus the
    /// exactly-once self-sync), the success `{timestamp}` answer (the DOE
    /// envelope ts) passes through untouched, and the error face is the
    /// engine's verbatim through the structured ladder: the plain -32603
    /// parse/unknown-account faces degrade to UPSTREAM_ERROR, the §4.17
    /// unbound matcher still applies, and the connector adds no gate of its
    /// own (the engine 7320393 fail-closed parse owns the timestamp domain,
    /// the recipients entries, and the updatedStoryRecipients shapes).
    /// Mutating class: a timeout answers SEND_OUTCOME_UNKNOWN and is never
    /// retried — an unknown delete outcome may already sit in the
    /// recipients' story fan-out.
    pub async fn send_story_delete_for_everyone(
        &self,
        params: crate::service::StoriesDeleteForEveryoneParams,
    ) -> Result<Value, ServiceError> {
        let frame = {
            let service = self.service.lock().await;
            service.prepare_story_delete_for_everyone(&params)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("deleteStoryForEveryone", frame, CallClass::Mutating)
            .await
            .map_err(ServiceError::from)
    }

    /// Send one attachment (optionally with a caption) — implementation-plan
    /// §4.12. Identical settlement path to `send_text`: local prepare under
    /// the service lock, upstream mutating `send` call, pending row settled
    /// on confirmation / unknown outcome / failure with the same event
    /// emission and no-auto-retry discipline.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_attachment(
        &self,
        account_id: String,
        target: SendTarget,
        client_request_id: String,
        data_base64: String,
        size_bytes: u64,
        filename: Option<String>,
        content_type: Option<String>,
        text: Option<String>,
        quote_message_id: Option<String>,
        voice_note: bool,
        view_once: bool,
        blur_hash: Option<String>,
        gif: bool,
    ) -> Result<MessageRecord, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            let attachment_target = match &target {
                SendTarget::Conversation(conversation_id) => {
                    AttachmentSendTarget::Conversation(conversation_id)
                }
                SendTarget::Peer {
                    kind,
                    peer_key,
                    peer_title,
                } => AttachmentSendTarget::Peer(PeerTarget {
                    kind,
                    peer_key,
                    peer_title: peer_title.as_deref(),
                }),
            };
            service.prepare_send_attachment(
                &account_id,
                &attachment_target,
                &client_request_id,
                &data_base64,
                size_bytes,
                filename.as_deref(),
                content_type.as_deref(),
                text.as_deref(),
                quote_message_id.as_deref(),
                voice_note,
                view_once,
                blur_hash.as_deref(),
                gif,
            )?
        };
        self.dispatch_prepared(&engine, prepared).await
    }

    /// Retry one definitively-failed outgoing attachment in place (contract
    /// revision 1.278, §4.262; bytes optional = 1.279, §4.263; plural rebuild =
    /// 1.280, §4.264): the §4.12 settlement path unchanged — local rearm + face
    /// rewrite under the service lock, one upstream mutating `send` call
    /// carrying the caller's bytes when supplied (else the original payload group
    /// persisted at first send, rebuilt entry by entry), then the shared
    /// completion, which settles the SAME row id the desktop bubble renders. No
    /// second row, no new clientRequestId.
    #[allow(clippy::too_many_arguments)]
    pub async fn retry_attachment(
        &self,
        account_id: String,
        target: SendTarget,
        client_request_id: String,
        data_base64: Option<String>,
        size_bytes: Option<u64>,
        filename: Option<String>,
        content_type: Option<String>,
        text: Option<String>,
        quote_message_id: Option<String>,
        voice_note: bool,
        view_once: bool,
        blur_hash: Option<String>,
        gif: bool,
    ) -> Result<MessageRecord, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            let attachment_target = match &target {
                SendTarget::Conversation(conversation_id) => {
                    AttachmentSendTarget::Conversation(conversation_id)
                }
                SendTarget::Peer {
                    kind,
                    peer_key,
                    peer_title,
                } => AttachmentSendTarget::Peer(PeerTarget {
                    kind,
                    peer_key,
                    peer_title: peer_title.as_deref(),
                }),
            };
            service.prepare_retry_attachment(
                &account_id,
                &attachment_target,
                &client_request_id,
                data_base64.as_deref(),
                size_bytes,
                filename.as_deref(),
                content_type.as_deref(),
                text.as_deref(),
                quote_message_id.as_deref(),
                voice_note,
                view_once,
                blur_hash.as_deref(),
                gif,
            )?
        };
        self.dispatch_prepared(&engine, prepared).await
    }

    /// Send one message carrying several attachments (contract revision
    /// 1.66, §4.59). Identical settlement path to `send_attachment`: local
    /// prepare under the service lock, one upstream mutating `send` call
    /// whose array-typed `attachments` carries every entry, pending row
    /// settled with the same no-auto-retry discipline.
    pub async fn send_attachments_multi(
        &self,
        account_id: String,
        target: SendTarget,
        client_request_id: String,
        entries: Vec<crate::service::MessagesSendAttachmentEntry>,
        text: Option<String>,
        quote_message_id: Option<String>,
    ) -> Result<MessageRecord, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            let attachment_target = match &target {
                SendTarget::Conversation(conversation_id) => {
                    AttachmentSendTarget::Conversation(conversation_id)
                }
                SendTarget::Peer {
                    kind,
                    peer_key,
                    peer_title,
                } => AttachmentSendTarget::Peer(PeerTarget {
                    kind,
                    peer_key,
                    peer_title: peer_title.as_deref(),
                }),
            };
            service.prepare_send_attachment_multi(
                &account_id,
                &attachment_target,
                &client_request_id,
                &entries,
                text.as_deref(),
                quote_message_id.as_deref(),
            )?
        };
        self.dispatch_prepared(&engine, prepared).await
    }

    /// messages.sendViewOnceOpen (contract revision 1.38, §4.36): the bare
    /// engine `sendViewOnceOpen` passthrough under receipt-class discipline —
    /// account resolution still fails deterministically, but every upstream
    /// failure (engine down, method absent, unknown outcome) degrades to
    /// `{status: "unknown"}` and nothing is ever retried (AGENTS.md).
    pub async fn send_view_once_open(
        &self,
        params: crate::service::MessagesSendViewOnceOpenParams,
    ) -> Result<&'static str, ServiceError> {
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_send_view_once_open(&params)?
        };
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(_) => return Ok("unknown"),
        };
        match engine
            .call("sendViewOnceOpen", prepared, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(_) => Ok("unknown"),
        }
    }

    /// messages.markViewOnceOpened (contract revision 1.38, §4.37): the
    /// desktop's single view-once trigger point. The burn already ran inside
    /// prepare (it never depends on upstream); this method emits the one
    /// `message.viewOnceOpened` event the transition earned, then runs the
    /// official upstream pair — `sendViewedReceipt` to the author, then
    /// `sendViewOnceOpen` — in order under receipt-class discipline: any
    /// failure degrades the answer to `unknown`, and nothing is ever retried.
    /// A replay (already burned) skips the fan-out and answers a trivial
    /// `sent` no-op.
    pub async fn mark_view_once_opened(
        &self,
        params: crate::service::MessagesMarkViewOnceOpenedParams,
    ) -> Result<&'static str, ServiceError> {
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_mark_view_once_opened(&params)?
        };
        for event in prepared.events {
            let _ = self.host_events.send(event);
        }
        if prepared.receipt_recipient.is_none() && prepared.open_sender_aci.is_none() {
            return Ok("sent");
        }
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(_) => return Ok("unknown"),
        };
        let mut all_confirmed = true;
        if let Some(recipient) = &prepared.receipt_recipient {
            let params = json!({
                "account": prepared.account_signal,
                "recipient": recipient,
                "timestamps": [prepared.timestamp],
            });
            match engine
                .call("sendViewedReceipt", params, CallClass::Mutating)
                .await
            {
                Ok(_) => {}
                Err(_) => all_confirmed = false,
            }
        }
        if let Some(sender_aci) = &prepared.open_sender_aci {
            let params = json!({
                "account": prepared.account_signal,
                "senderAci": sender_aci,
                "timestamp": prepared.timestamp,
            });
            match engine
                .call("sendViewOnceOpen", params, CallClass::Mutating)
                .await
            {
                Ok(_) => {}
                Err(_) => all_confirmed = false,
            }
        }
        Ok(if all_confirmed { "sent" } else { "unknown" })
    }

    /// messages.sendSticker (contract revision 1.35, §4.31; quote face 1.37,
    /// §4.35): the §4.12 attachment shape end to end — local prepare under
    /// the service lock (addressing resolved like `messages.attachments.send`,
    /// exactly one form; the optional quote resolved through the shared
    /// ladder before the pending row), upstream `send` with the `sticker`
    /// object via the shared `dispatch_prepared` settlement (success completes
    /// the pending row with the upstream timestamp; an unknown mutating
    /// outcome answers SEND_OUTCOME_UNKNOWN and is never retried).
    pub async fn send_sticker(
        &self,
        params: MessagesSendStickerParams,
    ) -> Result<MessageRecord, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            let MessagesSendStickerParams {
                account_id,
                conversation_id,
                kind,
                peer_key,
                peer_title,
                client_request_id,
                pack_id,
                pack_key,
                sticker_id,
                emoji,
                image,
                quote_message_id,
            } = params;
            let target = match (&conversation_id, &kind, &peer_key, &peer_title) {
                (Some(conversation_id), None, None, None) => {
                    AttachmentSendTarget::Conversation(conversation_id)
                }
                (None, Some(kind), Some(peer_key), peer_title) => {
                    AttachmentSendTarget::Peer(PeerTarget {
                        kind,
                        peer_key,
                        peer_title: peer_title.as_deref(),
                    })
                }
                _ => {
                    return Err(ServiceError::Api(ApiError::new(
                        "INVALID_REQUEST",
                        "exactly one of conversationId or kind+peerKey must be provided",
                        false,
                    )));
                }
            };
            service.prepare_send_sticker(
                &account_id,
                &target,
                &client_request_id,
                &pack_id,
                &pack_key,
                sticker_id,
                emoji.as_deref(),
                &image,
                quote_message_id.as_deref(),
            )?
        };
        self.dispatch_prepared(&engine, prepared).await
    }

    /// stickerPacks.getManifest (contract revision 1.36, §4.32): bounds
    /// validation under the service lock, then the read-only engine call —
    /// anonymous CDN work engine-side, no account context, nothing
    /// persisted. A timeout answers the ordinary retryable UPSTREAM_TIMEOUT
    /// (a read provably took no effect), and structured engine errors
    /// (STICKER_*) surface through the §4.32 mapping.
    pub async fn get_sticker_pack_manifest(
        &self,
        params: StickerPackManifestParams,
    ) -> Result<StickerPackManifest, ServiceError> {
        let engine = self.running_engine().await?;
        {
            let service = self.service.lock().await;
            service.prepare_sticker_pack_manifest(&params)?;
        }
        let result = engine
            .call(
                "getStickerPackManifest",
                json!({
                    "packId": params.pack_id,
                    "packKey": params.pack_key,
                }),
                CallClass::ReadOnly,
            )
            .await?;
        manifest_from_engine(&result)
    }

    /// stickerPacks.getImage (contract revision 1.36, §4.32): the same
    /// shape as the manifest face with the decrypted sticker bytes as the
    /// result — base64 pass-through, `size` cross-checked against the
    /// engine's declared byte count so a mismatching result fails as a
    /// protocol error instead of shipping a truncated image.
    pub async fn get_sticker_image(
        &self,
        params: StickerPackImageParams,
    ) -> Result<StickerPackImage, ServiceError> {
        let engine = self.running_engine().await?;
        {
            let service = self.service.lock().await;
            service.prepare_sticker_pack_image(&params)?;
        }
        let result = engine
            .call(
                "getStickerImage",
                json!({
                    "packId": params.pack_id,
                    "packKey": params.pack_key,
                    "stickerId": params.sticker_id,
                }),
                CallClass::ReadOnly,
            )
            .await?;
        image_from_engine(&result)
    }

    /// conversations.getPinned (contract revision 1.36, §4.33): account
    /// resolution then the read-only engine call; the pinned list projects
    /// straight from the engine result with the KT entry cap (§4.33).
    pub async fn get_pinned_conversations(
        &self,
        params: ConversationsGetPinnedParams,
    ) -> Result<PinnedConversations, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_get_pinned(&params.account_id)?
        };
        let result = engine
            .call("getPinnedConversations", upstream, CallClass::ReadOnly)
            .await?;
        Ok(pinned_conversations_result(
            result
                .get("pinned")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// conversations.setPinned (contract revision 1.36, §4.33): bounds +
    /// resolution under the service lock, then the mutating engine call —
    /// reaction-class discipline: an unknown outcome answers
    /// SEND_OUTCOME_UNKNOWN and is never retried; the success result is the
    /// post-write cloud state read back, not a local echo.
    pub async fn set_conversation_pinned(
        &self,
        params: ConversationsSetPinnedParams,
    ) -> Result<PinnedConversations, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_set_pinned(
                &params.account_id,
                &params.conversation_id,
                &params.kind,
                params.pinned,
            )?
        };
        match engine
            .call("setConversationPinned", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => Ok(pinned_conversations_result(
                result
                    .get("pinned")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            )),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.setExpireTimer (contract revision 1.42, §4.41): bounds +
    /// resolution + the mode-shaped upstream payload under the service lock,
    /// then the mutating engine call — reaction-class discipline, an unknown
    /// outcome answers SEND_OUTCOME_UNKNOWN and is never retried. On a
    /// definite success the conversation's local mirror row updates and the
    /// refreshed summary rides conversation.changed, so every window sees the
    /// new timer without a re-read; the upstream timer state stays the source
    /// of truth. The direct route is the engine's `setExpirationTimer`; a
    /// group rides `updateGroup` — same-value no-ops are upstream semantics,
    /// the passthrough never pre-checks.
    pub async fn set_conversation_expire_timer(
        &self,
        params: ConversationsSetExpireTimerParams,
    ) -> Result<ConversationsSetExpireTimerResult, ServiceError> {
        let engine = self.running_engine().await?;
        let (method, upstream, seconds) = {
            let service = self.service.lock().await;
            service.prepare_conversations_set_expire_timer(
                &params.account_id,
                &params.conversation_id,
                params.expire_seconds,
            )?
        };
        match engine.call(method, upstream, CallClass::Mutating).await {
            Ok(_) => {
                // Local mirror best-effort: the upstream write is the state;
                // a mirror failure only costs the next event its freshness.
                if self
                    .store
                    .set_conversation_expire_timer(
                        &params.account_id,
                        &params.conversation_id,
                        seconds,
                    )
                    .unwrap_or(false)
                    && let Some(conversation) = self
                        .store
                        .conversation_summary(&params.account_id, &params.conversation_id)?
                {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(conversation));
                }
                Ok(ConversationsSetExpireTimerResult {
                    expire_timer_seconds: seconds,
                })
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.update (contract revision 1.45, §4.44, capability
    /// group-management; the engine write face wired by contract 1.115,
    /// §4.96): full local validation + resolution under the service lock,
    /// then the mutating `updateGroup` call — reaction-class discipline with
    /// the timer face's unknown-outcome honesty: an indeterminate answer is
    /// the SEND_OUTCOME_UNKNOWN error and is never retried. The engine's
    /// deny faces (unknown account/group, non-member, server user errors)
    /// are deterministic refusals: UPSTREAM_ERROR with retryable=false — a
    /// bare replay fails the same way. Zero local writes: the group row
    /// converges through the receive projection when the change's own
    /// group-update envelope lands.
    pub async fn update_group(
        &self,
        params: GroupsUpdateParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_update(&params)?
        };
        match engine
            .call("updateGroup", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.quit (contract revision 1.45, §4.44, capability
    /// group-management; the engine write face wired by contract 1.115,
    /// §4.96): resolution under the service lock, then the mutating
    /// `leaveGroup` call — the engine's method name for the upstream quit
    /// write — under the same unknown-outcome discipline as groups.update,
    /// with the same deterministic deny face (a non-member or last-admin
    /// quit is UPSTREAM_ERROR retryable=false). The local conversation row
    /// is kept; non-member state is upstream convergence.
    pub async fn quit_group(&self, params: GroupsQuitParams) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_quit(&params)?
        };
        match engine
            .call("leaveGroup", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.terminate (contract revision 1.52, §4.50, capability
    /// group-terminate): resolution under the service lock, then the
    /// mutating `terminateGroup` call — the same unknown-outcome discipline
    /// as groups.update/groups.quit. Zero local writes: the terminated state
    /// converges through the receive projection when the change's own
    /// group-update envelope lands.
    pub async fn terminate_group(
        &self,
        params: GroupsTerminateParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_terminate(&params)?
        };
        match engine
            .call("terminateGroup", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.approveJoinRequests (contract revision 1.58, §4.53, capability
    /// group-join-approve): the safety fold, then the mutating upstream
    /// write. The pinned upstream weaves approval into the updateGroup
    /// member semantics (`GroupHelper.updateGroupV2`: `members` entries
    /// that are requesting members ride `approveJoinRequestMembers`,
    /// `removeMembers` entries that are requesting members ride
    /// `refuseJoinRequestMembers` — every other entry is an add/remove
    /// member change), so the connector folds the caller's candidates
    /// against the engine's own requesting-members read
    /// (`listGroups {account, groupId}` → JsonGroup.requestingMembers)
    /// before anything goes upstream: only candidates the engine itself
    /// reports as requesting can ever ride the member arrays, so the
    /// "add a stranger" / "remove a member" mis-target faces of the shared
    /// arrays fail closed here instead of upstream. A fully-stale candidate
    /// set (the fold empties it) answers
    /// `JOIN_REQUEST_NO_LONGER_PENDING` (retryable) — the request was
    /// resolved elsewhere (another admin acted, the candidate withdrew); a
    /// read face that cannot answer (engine refuses the group read) fails
    /// closed with that refusal. The write is the groups.terminate
    /// discipline verbatim: one mutating `updateGroup` call, a definite
    /// success answers `{"status": "sent"}`, an indeterminate outcome
    /// answers SEND_OUTCOME_UNKNOWN and is never retried. Zero local
    /// writes: the roster converges through contacts.sync.
    pub async fn approve_join_requests(
        &self,
        params: GroupsApproveJoinRequestsParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let (group_id, members, approve) = {
            let service = self.service.lock().await;
            service.prepare_groups_approve_join_requests(&params)?
        };
        let number = self
            .service
            .lock()
            .await
            .account_signal_number(&params.account_id)?;
        // The engine's own read of who is still requesting membership (the
        // §4.50-verified listGroups read source; a single-group read keeps
        // the fold O(requesting) and the traffic bounded).
        let listed = engine
            .call(
                "listGroups",
                json!({ "account": number, "groupId": [group_id.clone()] }),
                CallClass::ReadOnly,
            )
            .await
            .map_err(ServiceError::Engine)?;
        let requesting: std::collections::HashSet<String> = requesting_member_identities(&listed);
        // The fold: the caller's candidates survive only while the engine
        // still reports them requesting. A requesting entry carries either
        // or both of its number/uuid identities (the JsonGroupMemberAddress
        // NON_NULL omissions), so both ride the same identity set and the
        // caller may name the candidate by either (the connector-wide
        // first-wins address ladder). Nothing else can ride the arrays.
        let folded: Vec<String> = fold_join_request_candidates(members, &requesting);
        if folded.is_empty() {
            return Err(ServiceError::Api(ApiError::new(
                "JOIN_REQUEST_NO_LONGER_PENDING",
                "no candidate is still requesting membership (already approved, refused, or withdrawn)",
                true,
            )));
        }
        // The upstream write: the requesting-survivor set rides exactly the
        // one member family its approve bit names, every other change key
        // absent — the upstream reads absence as "no change" (§4.44).
        let mut upstream = json!({
            "account": number,
            "groupId": group_id,
        });
        if let Some(object) = upstream.as_object_mut() {
            object.insert(
                if approve { "members" } else { "removeMembers" }.to_string(),
                json!(folded),
            );
        }
        match engine
            .call("updateGroup", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.revokeInvites (contract revision 1.64, §4.57, capability
    /// group-invite-revoke): the safety fold, then the mutating upstream
    /// write. The pinned upstream weaves invite revocation into the
    /// updateGroup removeMembers semantics (`GroupHelper.updateGroupV2`:
    /// `removeMembers` entries that are pending members ride
    /// `revokeInvitedMembers` — :760-764 — while entries that are full
    /// members ride the member removal and entries that are requesting
    /// members ride `refuseJoinRequestMembers`; the three-way discrimination
    /// is upstream's), so the connector folds the caller's candidates
    /// against the engine's own pending-members read
    /// (`listGroups {account, groupId}` → JsonGroup.pendingMembers) before
    /// anything goes upstream: only candidates the engine itself reports as
    /// pending invitees can ever ride the `removeMembers` array, so the
    /// "remove a member" / "refuse a request" mis-target faces of the
    /// shared array fail closed here instead of upstream. A fully-stale
    /// candidate set (the fold empties it) answers
    /// `INVITE_NO_LONGER_PENDING` (retryable) — the invite was resolved
    /// elsewhere (another admin revoked it, the invitee joined); a read
    /// face that cannot answer (engine refuses the group read) fails closed
    /// with that refusal. The write is the groups.terminate discipline
    /// verbatim: one mutating `updateGroup` call, a definite success
    /// answers `{"status": "sent"}`, an indeterminate outcome answers
    /// SEND_OUTCOME_UNKNOWN and is never retried. Zero local writes: the
    /// roster converges through contacts.sync.
    pub async fn revoke_invites(
        &self,
        params: GroupsRevokeInvitesParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let (group_id, members) = {
            let service = self.service.lock().await;
            service.prepare_groups_revoke_invites(&params)?
        };
        let number = self
            .service
            .lock()
            .await
            .account_signal_number(&params.account_id)?;
        // The engine's own read of who is still a pending invitee (the same
        // listGroups read source the groups.get pendingMembers face
        // projects; a single-group read keeps the fold O(pending) and the
        // traffic bounded).
        let listed = engine
            .call(
                "listGroups",
                json!({ "account": number, "groupId": [group_id.clone()] }),
                CallClass::ReadOnly,
            )
            .await
            .map_err(ServiceError::Engine)?;
        let pending: std::collections::HashSet<String> = pending_member_identities(&listed);
        // The fold: the caller's candidates survive only while the engine
        // still reports them pending invitees. A pending entry carries
        // either or both of its number/uuid identities (the
        // JsonGroupMemberAddress NON_NULL omissions), so both ride the same
        // identity set and the caller may name the candidate by either (the
        // connector-wide first-wins address ladder). Nothing else can ride
        // the array — a full member or a requesting candidate in the
        // candidate set drops here, never into the upstream write.
        let folded: Vec<String> = fold_invite_candidates(members, &pending);
        if folded.is_empty() {
            return Err(ServiceError::Api(ApiError::new(
                "INVITE_NO_LONGER_PENDING",
                "no candidate is still a pending invitee (already revoked, joined, or withdrawn)",
                true,
            )));
        }
        // The upstream write: the pending-survivor set rides exactly the
        // `removeMembers` family, every other change key absent — the
        // upstream reads absence as "no change" (§4.44).
        let upstream = json!({
            "account": number,
            "groupId": group_id,
            "removeMembers": folded,
        });
        match engine
            .call("updateGroup", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// messages.reportSpam (contract revision 1.49, §4.48, capability
    /// report-spam): resolution and row reads under the service lock, then
    /// the mutating `reportSpam` call — the groups face's unknown-outcome
    /// discipline (a lost answer is the SEND_OUTCOME_UNKNOWN error and is
    /// never retried). The confirmed result projects the engine's
    /// `{reported, failures}` back onto the caller's message ids; rows
    /// without a serverGuid never reached upstream and answer as failures.
    pub async fn report_spam(
        &self,
        params: MessagesReportSpamParams,
    ) -> Result<ReportSpamResult, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_report_spam(&params)?
        };
        match engine
            .call("reportSpam", prepared.upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => {
                let reported = result
                    .get("reported")
                    .and_then(Value::as_u64)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?;
                let answered = result
                    .get("failures")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?;
                // The engine answers failures by serverGuid with an optional
                // status (absent on transport failures — never invented as 0).
                let answered_by_guid = answered
                    .iter()
                    .filter_map(|entry| {
                        let guid = entry.get("serverGuid")?.as_str()?;
                        Some((guid, entry.get("status").and_then(Value::as_u64)))
                    })
                    .collect::<Vec<_>>();
                let mut failures = prepared
                    .pairs
                    .iter()
                    .filter_map(|(message_id, guid)| {
                        answered_by_guid
                            .iter()
                            .find(|(answered_guid, _)| answered_guid == guid)
                            .map(|(_, code)| ReportSpamFailure {
                                message_id: message_id.clone(),
                                code: *code,
                            })
                    })
                    .collect::<Vec<_>>();
                // Rows without a persisted serverGuid never reached upstream
                // (sent rows, history imports, unknown ids) — honest per-id
                // failures with no code, not a dropped or failed request.
                for message_id in &params.message_ids {
                    if !prepared.pairs.iter().any(|(id, _)| id == message_id) {
                        failures.push(ReportSpamFailure {
                            message_id: message_id.clone(),
                            code: None,
                        });
                    }
                }
                Ok(ReportSpamResult { reported, failures })
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// `conversations.reportSpam` (contract revision 1.266, §4.250,
    /// capability report-spam): the conversation-level report — the official
    /// `reportSpam` / `blockAndReportSpam` thunks
    /// (state/ducks/conversations.preload.ts:3862-3922 / :3924-3990), in
    /// the official order: (1) the MRR sync face — the pinned native
    /// `sendMessageRequestResponse` upstream carrying the SPAM /
    /// BLOCK_AND_SPAM word (the official `syncMessageRequestResponse`
    /// argument); (2) the LOCAL landing on the upstream answer — the same
    /// §4.239/§1.258 action-arm shape (rows behind the official
    /// didResponseChange / didSpamChange / didBlockChange gates, the
    /// authoritative factor stamp, the blocked-family mask stamp, the
    /// row-then-summary push); (3) the report itself — the engine
    /// `reportSpam` call over the §4.250 guid ladder
    /// (`addReportSpamJob`'s server face), honestly skipped when the ladder
    /// found nothing reportable. Unknown outcomes answer SEND_OUTCOME_UNKNOWN
    /// and are never retried (the reaction class). Landing legs are
    /// warn-only best-effort: the upstream answer is the primary face
    /// (§4.239 discipline).
    pub async fn report_conversation_spam(
        &self,
        params: ConversationsReportSpamParams,
    ) -> Result<ConversationsReportSpamResult, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_conversations_report_spam(&params)?
        };
        if let Err(EngineError::UnknownOutcome) = engine
            .call(
                "sendMessageRequestResponse",
                prepared.mrr_upstream,
                CallClass::Mutating,
            )
            .await
        {
            return Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            )));
        }
        let response_type = if params.block {
            crate::service::MRR_RESPONSE_TYPE_BLOCK_AND_SPAM
        } else {
            crate::service::MRR_RESPONSE_TYPE_SPAM
        };
        {
            let store = Arc::clone(&self.store);
            let account_id = params.account_id.clone();
            let conversation_id = params.conversation_id.clone();
            match blocking_service(move || {
                crate::service::land_local_report_response(
                    &store,
                    &account_id,
                    &conversation_id,
                    response_type,
                )
            })
            .await
            {
                Ok(events) => {
                    // Row-then-summary order (§4.226): rows ride ahead of
                    // the changed push so one pass renders both faces.
                    for event in events {
                        let _ = self.host_events.send(event);
                    }
                }
                Err(error) => tracing::warn!(
                    kind = "message_request_report_landing",
                    class = error.class(),
                    "report landed no local face; the upstream answer stands"
                ),
            }
        }
        // The report itself (official addReportSpamJob): skipped when the
        // ladder found no reportable rows — the honest empty-job face.
        let reported = match prepared.report_upstream {
            Some(upstream) => {
                match engine
                    .call("reportSpam", upstream, CallClass::Mutating)
                    .await
                {
                    Ok(result) => result
                        .get("reported")
                        .and_then(Value::as_u64)
                        .ok_or(ServiceError::Engine(EngineError::Protocol))?,
                    Err(EngineError::UnknownOutcome) => {
                        return Err(ServiceError::Api(ApiError::new(
                            "SEND_OUTCOME_UNKNOWN",
                            "mutating request has an unknown outcome",
                            false,
                        )));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            None => 0,
        };
        Ok(ConversationsReportSpamResult {
            status: "reported",
            reported,
        })
    }

    /// stickerPacks.getSyncs (contract revision 1.37, §4.34): account
    /// resolution then the read-only engine call; the record list projects
    /// straight from the engine result with the KT entry cap (§4.34).
    pub async fn get_sticker_pack_syncs(
        &self,
        params: StickerPackGetSyncsParams,
    ) -> Result<StickerPackSyncs, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_sticker_pack_get_syncs(&params.account_id)?
        };
        let result = engine
            .call("getStickerPackSyncs", upstream, CallClass::ReadOnly)
            .await?;
        Ok(sticker_pack_syncs_result(
            result
                .get("packs")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// stickerPacks.setSync (contract revision 1.37, §4.34): bounds under the
    /// service lock, then the mutating engine call — reaction-class
    /// discipline: an unknown outcome answers SEND_OUTCOME_UNKNOWN and is
    /// never retried; the success result is the post-write cloud state read
    /// back, not a local echo.
    pub async fn set_sticker_pack_sync(
        &self,
        params: StickerPackSetSyncParams,
    ) -> Result<StickerPackSyncs, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_sticker_pack_set_sync(
                &params.account_id,
                &params.pack_id,
                params.pack_key.as_deref(),
                params.installed,
                params.position,
            )?
        };
        match engine
            .call("setStickerPackSync", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => Ok(sticker_pack_syncs_result(
                result
                    .get("packs")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            )),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// chatFolders.list (contract revision 1.95, §4.78): bounds and account
    /// resolution under the service lock, then the read-only engine call;
    /// the folder list projects straight from the engine result with the KT
    /// entry cap, record bodies verbatim.
    pub async fn chat_folders_list(
        &self,
        params: ChatFoldersListParams,
    ) -> Result<ChatFolderSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_chat_folders_list(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        let result = engine
            .call("chatFolders.list", upstream, CallClass::ReadOnly)
            .await?;
        Ok(chat_folder_syncs_result(
            result
                .get("folders")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// chatFolders.setRecords (contract revision 1.95, §4.78): bounds under
    /// the service lock, then the mutating engine call — reaction-class
    /// discipline: an unknown outcome answers SEND_OUTCOME_UNKNOWN and is
    /// never retried; the success result is the post-write cloud state read
    /// back, not a local echo.
    pub async fn chat_folders_set_records(
        &self,
        params: ChatFoldersSetRecordsParams,
    ) -> Result<ChatFolderSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_chat_folders_set_records(
                &params.account_id,
                params.records.as_deref().unwrap_or(&[]),
                params.remove_ids.as_deref().unwrap_or(&[]),
            )?
        };
        let engine = self.running_engine().await?;
        match engine
            .call("chatFolders.setRecords", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => Ok(chat_folder_syncs_result(
                result
                    .get("folders")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            )),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// notificationProfiles.list (contract revision 1.129, §4.110): the
    /// §4.78 read shape — bounds and account resolution under the service
    /// lock, then the read-only engine call; the profile list projects
    /// straight from the engine result with the KT entry cap, record bodies
    /// verbatim.
    pub async fn notification_profiles_list(
        &self,
        params: NotificationProfilesListParams,
    ) -> Result<NotificationProfileSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_notification_profiles_list(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        let result = engine
            .call("notificationProfiles.list", upstream, CallClass::ReadOnly)
            .await?;
        Ok(notification_profile_syncs_result(
            result
                .get("profiles")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// notificationProfiles.setRecords (contract revision 1.129, §4.110):
    /// the §4.78 write shape — bounds under the service lock, then the
    /// mutating engine call with the reaction-class unknown-outcome
    /// discipline; the success result is the post-write cloud state read
    /// back, not a local echo.
    pub async fn notification_profiles_set_records(
        &self,
        params: NotificationProfilesSetRecordsParams,
    ) -> Result<NotificationProfileSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_notification_profiles_set_records(
                &params.account_id,
                params.records.as_deref().unwrap_or(&[]),
                params.remove_ids.as_deref().unwrap_or(&[]),
            )?
        };
        let engine = self.running_engine().await?;
        match engine
            .call(
                "notificationProfiles.setRecords",
                upstream,
                CallClass::Mutating,
            )
            .await
        {
            Ok(result) => Ok(notification_profile_syncs_result(
                result
                    .get("profiles")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            )),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// storyDistributionLists.list (contract revision 1.130, §4.111): the
    /// §4.78 read shape — bounds and account resolution under the service
    /// lock, then the read-only engine call; the list projects straight
    /// from the engine result with the KT entry cap, record bodies
    /// verbatim.
    pub async fn story_distribution_lists_list(
        &self,
        params: StoryDistributionListsListParams,
    ) -> Result<StoryDistributionListSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_story_distribution_lists_list(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        let result = engine
            .call("storyDistributionLists.list", upstream, CallClass::ReadOnly)
            .await?;
        Ok(story_distribution_lists_result(
            result
                .get("lists")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// storyDistributionLists.setRecords (contract revision 1.130,
    /// §4.111): the §4.78 write shape — bounds under the service lock, then
    /// the mutating engine call with the reaction-class unknown-outcome
    /// discipline; the success result is the post-write cloud state read
    /// back, not a local echo.
    pub async fn story_distribution_lists_set_records(
        &self,
        params: StoryDistributionListsSetRecordsParams,
    ) -> Result<StoryDistributionListSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_story_distribution_lists_set_records(
                &params.account_id,
                params.records.as_deref().unwrap_or(&[]),
                params.remove_ids.as_deref().unwrap_or(&[]),
            )?
        };
        let engine = self.running_engine().await?;
        match engine
            .call(
                "storyDistributionLists.setRecords",
                upstream,
                CallClass::Mutating,
            )
            .await
        {
            Ok(result) => Ok(story_distribution_lists_result(
                result
                    .get("lists")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            )),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// storage.mergeContacts (contract revision 1.131, §4.112): the
    /// engine-local ingest read — account resolution under the service
    /// lock, then the read-only engine call; the summary tallies ride
    /// verbatim (the contacts.sync class: the ingest lands engine state, so
    /// the account mutex serializes it).
    pub async fn storage_merge_contacts(
        &self,
        params: StorageIngestParams,
    ) -> Result<MergeContactsSummary, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_storage_ingest_read(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        let result = engine
            .call("storage.mergeContacts", upstream, CallClass::ReadOnly)
            .await?;
        merge_contacts_summary_from_engine(result)
    }

    /// storage.importGroups (contract revision 1.131, §4.112): the
    /// mergeContacts class verbatim — the manifest GROUPV2 ingest read, the
    /// summary tallies ride verbatim.
    pub async fn storage_import_groups(
        &self,
        params: StorageIngestParams,
    ) -> Result<ImportGroupsSummary, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_storage_ingest_read(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        let result = engine
            .call("storage.importGroups", upstream, CallClass::ReadOnly)
            .await?;
        import_groups_summary_from_engine(result)
    }

    /// storage.getCallLinks (contract revision 1.131, §4.112): the bounded
    /// cloud read — the link list projects straight from the engine result
    /// with the KT entry cap, entry bodies verbatim.
    pub async fn storage_get_call_links(
        &self,
        params: StorageGetCallLinksParams,
    ) -> Result<CallLinkSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_storage_ingest_read(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        let result = engine
            .call("storage.getCallLinks", upstream, CallClass::ReadOnly)
            .await?;
        Ok(call_link_syncs_result(
            result
                .get("callLinks")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// storage.setCallLink (contract revision 1.131, §4.112): the intent
    /// gates under the service lock, then the mutating engine call — the
    /// reaction-class unknown-outcome discipline; the success result is the
    /// post-write cloud state read back, not a local echo.
    pub async fn storage_set_call_link(
        &self,
        params: StorageSetCallLinkParams,
    ) -> Result<CallLinkSyncs, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_storage_set_call_link(&params)?
        };
        let engine = self.running_engine().await?;
        match engine
            .call("storage.setCallLink", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => Ok(call_link_syncs_result(
                result
                    .get("callLinks")
                    .and_then(Value::as_array)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            )),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// accounts.updateConfiguration (contract revision 1.46, §4.45,
    /// capability account-settings): bounds under the service lock, then the
    /// mutating engine call — reaction-class discipline: an unknown outcome
    /// answers SEND_OUTCOME_UNKNOWN and is never retried. The result is the
    /// definite-success ack, not state: the settings live upstream and the
    /// desktop re-reads them through its own channel. §4.190 (contract
    /// 1.190 ⑥): a definite-success `readReceipts` write mirrors the flag
    /// onto the account row — the receipt gate's local input (the §4.87
    /// sync arm and the startup `getConfiguration` fetch are the other two
    /// writers; a failed or unknown write mirrors nothing).
    pub async fn update_account_configuration(
        &self,
        params: AccountsUpdateConfigurationParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_update_configuration(&params)?
        };
        match engine
            .call("setAccountConfiguration", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => {
                if let Some(read_receipts) = params.read_receipts
                    && let Err(error) = self
                        .store
                        .set_account_read_receipts(&params.account_id, Some(read_receipts))
                {
                    tracing::warn!(
                        error_class = ServiceError::Store(error).class(),
                        "readReceipts mirror write failed; the startup fetch re-converges it"
                    );
                }
                Ok("saved")
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// accounts.setProfile (contract revision 1.46, §4.45, capability
    /// account-settings): bounds + the avatar tri-state under the service
    /// lock, then the mutating engine call — the reaction-class discipline
    /// verbatim. Zero local writes: the profile lives upstream.
    pub async fn set_profile(
        &self,
        params: AccountsSetProfileParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_set_profile(&params)?
        };
        match engine
            .call("setProfile", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("saved"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// accounts.setExpireTimer (contract revision 1.46, §4.45, capability
    /// account-settings): account resolution under the service lock, then the
    /// mutating engine call — the reaction-class discipline verbatim. Zero
    /// local writes: the universal timer lives upstream, other devices
    /// converge through storage sync.
    pub async fn set_account_expire_timer(
        &self,
        params: AccountsSetExpireTimerParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_set_expire_timer(&params.account_id, params.expire_seconds)?
        };
        match engine
            .call("setUniversalExpireTimer", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("saved"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.getBlocked (contract revision 1.46, §4.45, capability
    /// blocked-conversations): account resolution then the read-only engine
    /// call; the blocked list projects straight from the engine result with
    /// the KT entry cap (§4.45).
    pub async fn get_blocked_conversations(
        &self,
        params: ConversationsGetBlockedParams,
    ) -> Result<BlockedConversations, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_get_blocked(&params.account_id)?
        };
        let result = engine
            .call("getBlockedConversations", upstream, CallClass::ReadOnly)
            .await?;
        Ok(blocked_conversations_result(
            result
                .get("blocked")
                .and_then(Value::as_array)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        ))
    }

    /// accounts.deviceCapabilities (contract revision 1.100, §4.81): account
    /// resolution then the read-only engine call — the idempotent device-face
    /// registration (the official registerCapabilities endpoint, PUT — the
    /// engine folds every failure into the plain -32603, the connector adds
    /// no matcher of its own) — and the projection that strips the engine's
    /// bare `account` identity before it crosses the connector.
    pub async fn get_device_capabilities(
        &self,
        params: AccountsDeviceCapabilitiesParams,
    ) -> Result<AccountDeviceCapabilities, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_device_capabilities(&params.account_id)?
        };
        let result = engine
            .call("engine.deviceCapabilities", upstream, CallClass::ReadOnly)
            .await?;
        account_device_capabilities_from_engine(&result)
    }

    /// accounts.getDevices (contract revision 1.122, §4.103, capability
    /// device-management): account resolution then the read-only engine call —
    /// the GET v1/devices projection with the engine-side device-name
    /// decryption — and the bounded projection (the 32-entry cap, the
    /// malformed-entry drops, the id-0 fail-closed refusal). Nothing persists,
    /// nothing logs.
    pub async fn get_devices(
        &self,
        params: AccountsGetDevicesParams,
    ) -> Result<DeviceList, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_get_devices(&params.account_id)?
        };
        let result = engine
            .call("getDevices", upstream, CallClass::ReadOnly)
            .await?;
        device_list_from_engine(&result)
    }

    /// accounts.unlinkDevice (contract revision 1.122, §4.103, capability
    /// device-management): the server-side unlink — the engine DELETE
    /// v1/devices/{id}, the official unlink endpoint; the server owns the
    /// authorization (a primary unlinks any linked device, a linked device
    /// unlinks only itself, and the over-reach/primary-delete refusals surface
    /// as DEVICES_FAILED with the engine's `data.status?`). A mutating call
    /// whose outcome can be lost in transport: `EngineError::UnknownOutcome`
    /// folds to SEND_OUTCOME_UNKNOWN (retryable=false — the AGENTS.md red
    /// line, never auto-retried) through the global into_api face.
    pub async fn unlink_device(
        &self,
        params: AccountsUnlinkDeviceParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_unlink_device(&params.account_id, params.device_id)?
        };
        engine
            .call("unlinkDevice", upstream, CallClass::Mutating)
            .await?;
        Ok("unlinked")
    }

    /// groups.create (contract revision 1.126, §4.107, capability
    /// group-management): the new-group upstream leg — the engine
    /// `createGroup` face (the official createGroupV2): the engine derives
    /// the new group master key and answers {groupId, revision}. A mutating
    /// upstream write: the indeterminate outcome folds to
    /// SEND_OUTCOME_UNKNOWN (retryable=false) through the global into_api
    /// face and is never retried — a create whose delivery is unknown may
    /// already have created the group server-side. Zero local writes: the
    /// new group converges through contacts.sync like every group row.
    pub async fn create_group(
        &self,
        params: GroupsCreateParams,
    ) -> Result<GroupsCreateResult, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_create(&params)?
        };
        let result = engine
            .call("createGroup", upstream, CallClass::Mutating)
            .await?;
        group_create_result_from_engine(&result)
    }

    /// groups.migrate (contract revision 1.123, §4.104, capability
    /// group-management): the GV1→GV2 migration upstream leg — the engine
    /// `migrateGroup` face (the official initiateMigrationToGroupV2): the
    /// engine derives the new GV2 master key and answers {groupId, revision},
    /// with the already-migrated fallback probe presenting as the same honest
    /// answer. A mutating upstream write: the indeterminate outcome folds to
    /// SEND_OUTCOME_UNKNOWN (retryable=false) through the global into_api
    /// face and is never retried — a migration whose delivery is unknown may
    /// already have created the GV2 group server-side. Zero local writes.
    pub async fn migrate_group(
        &self,
        params: GroupsMigrateParams,
    ) -> Result<GroupsMigrateResult, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_migrate(&params)?
        };
        let result = engine
            .call("migrateGroup", upstream, CallClass::Mutating)
            .await?;
        group_migrate_result_from_engine(&result)
    }

    /// messages.sendContact (contract revision 1.124, §4.105, capability
    /// send-contact): the shape gate + resolution under the service lock,
    /// then the mutating engine `sendContact` call — the reaction-class
    /// discipline verbatim (same-account mutex, delete barrier, an unknown
    /// outcome answers SEND_OUTCOME_UNKNOWN and is never retried — a card
    /// whose delivery is unknown may already sit in the recipients'
    /// timelines). The conversation kind decides the leg (direct recipient /
    /// group groupId, the calls.sendSignal addressing precedent). The
    /// result is the engine's send timestamp, echoed as `{sentAt}` — the
    /// send ack, not message state (the connector keeps no send rows for
    /// the face).
    pub async fn send_contact(
        &self,
        params: MessagesSendContactParams,
    ) -> Result<Value, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_messages_send_contact(&params)?
        };
        match engine
            .call("sendContact", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => {
                let sent_at = result
                    .get("timestamp")
                    .and_then(Value::as_u64)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?;
                Ok(json!({ "sentAt": sent_at }))
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// messages.sendPollCreate (contract revision 1.125, §4.106, capability
    /// polls): the shape gate + resolution under the service lock, then the
    /// mutating engine `sendPollCreate` call — the remoteDelete answer
    /// discipline (a definite success answers the explicit `sent`, an
    /// indeterminate outcome the explicit `unknown`, a definite error
    /// propagates; nothing retries). The upstream result body is empty —
    /// the poll's identity is the send timestamp the receive projection
    /// converges.
    pub async fn send_poll_create(
        &self,
        params: MessagesSendPollCreateParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_messages_send_poll_create(&params)?
        };
        match engine
            .call("sendPollCreate", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// messages.sendPollVote (contract revision 1.125, §4.106): the
    /// `sendPollCreate` discipline verbatim against the engine's
    /// group-only `sendPollVote` face (the anchor + selection gates ride
    /// the prepare; an empty optionIndexes array is the legal clear-vote
    /// and answers the same `sent`).
    pub async fn send_poll_vote(
        &self,
        params: MessagesSendPollVoteParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_messages_send_poll_vote(&params)?
        };
        match engine
            .call("sendPollVote", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// messages.sendPollTerminate (contract revision 1.125, §4.106): the
    /// `sendPollCreate` discipline verbatim against the engine's
    /// group-only `sendPollTerminate` face.
    pub async fn send_poll_terminate(
        &self,
        params: MessagesSendPollTerminateParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_messages_send_poll_terminate(&params)?
        };
        match engine
            .call("sendPollTerminate", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.getAvatar (contract revision 1.48, §4.47, capability
    /// avatar-fetch): resolution under the service lock, then the read-only
    /// engine call — a download touches no account state. The result
    /// projects through the avatar face's bound and byte-count cross-check
    /// (`avatar_from_engine`). Contract 1.217 (§29.2 · L2 接线批，剩余项①
    /// 落库闸): the success arm commits the bytes into the
    /// `conversation_avatars` cache through the service commit gate
    /// (best-effort — a failed cache write never pollutes the
    /// already-successful Read lane, the answer still ships, and the absent
    /// cache stays the honest uncached face); the engine's honest
    /// `AVATAR_UNAVAILABLE` arm (peer/group never set an avatar, or the
    /// server folded a 403/404) idempotently clears a stale cache row so a
    /// removed avatar stops projecting. Transient `AVATAR_FETCH_FAILED` and
    /// capacity `AVATAR_TOO_LARGE` touch neither arm — cached bytes stay
    /// valid. Bytes are never logged (§4.47 discipline).
    pub async fn get_avatar(
        &self,
        params: ConversationsGetAvatarParams,
    ) -> Result<AvatarDownload, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_get_avatar(&params.account_id, &params.conversation_id)?
        };
        let result = match engine
            .call("getAvatar", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                // §29.2① 失效半：上游诚实「无头像」（engine avatar.rs 折叠
                // 语义，含服务器 403/404）→ 幂等清缓存防陈旧（best-effort，
                // 清失败不遮蔽上游答案面，下次拉取自愈）；瞬态 FETCH_FAILED /
                // TOO_LARGE / 协议与生命周期族不触缓存，原样上抛。
                if matches!(
                    &error,
                    EngineError::UpstreamCode {
                        code: "AVATAR_UNAVAILABLE",
                        ..
                    }
                ) {
                    let service = self.service.lock().await;
                    let _ = service
                        .clear_conversation_avatar(&params.account_id, &params.conversation_id);
                }
                return Err(error.into());
            }
        };
        let download = avatar_from_engine(&result)?;
        // §29.2① 落库半：result-face 门禁已在 avatar_from_engine 过闸，这里
        // 经 service 提交闸（二次门禁重放 + wire 顺序 ladder + upsert
        // latest-wins）把字节送进缓存——下次 list/summary/conversation.changed
        // 投影即携 avatarUrl。缓存写失败不污染已成功的 Read lane（字节照答），
        // 缺席缓存保持诚实的「未缓存」面；字节从不入日志（§4.47）。
        {
            let service = self.service.lock().await;
            let _ = service.commit_conversation_avatar(
                &params.account_id,
                &params.conversation_id,
                &download.data_uri,
                download.byte_size,
            );
        }
        Ok(download)
    }

    /// accounts.setUsername (contract revision 1.59, §4.55; the kt-engine
    /// write face opened with contract 1.75, §4.66): the two-hop
    /// orchestration — `usernameReserve` then `usernameConfirm`, each a
    /// separate mutating call under the groups face's unknown-outcome
    /// discipline (an indeterminate hop stops the chain: the reservation
    /// itself carries no user-visible effect server-side, and a torn
    /// two-hop converges through getUsername / the engine's storage sync).
    /// The confirmed result projects the write-back `{username,
    /// usernameLink}` on the set path — the adopted candidate wins (a bare
    /// nickname's discriminator is the server's pick) — and `{username:
    /// null}` on the delete path (the upstream writes no result body
    /// there). Structured engine codes (USERNAME_TAKEN /
    /// USERNAME_RESERVATION_GONE / USERNAME_RATE_LIMITED /
    /// USERNAME_SERVER_FAILED, and the STORAGE_* honest partial-success
    /// family when the server confirmed but the storage write failed) map
    /// through the connector's allowlist (`into_api`).
    pub async fn set_username(
        &self,
        params: AccountsSetUsernameParams,
    ) -> Result<AccountUsername, ServiceError> {
        let engine = self.running_engine().await?;
        let (upstream, account_key) = {
            let service = self.service.lock().await;
            let upstream = service.prepare_accounts_set_username(&params)?;
            let account_key = upstream["account"].clone();
            (upstream, account_key)
        };
        // Delete hop: usernameDelete {account} → {} (idempotent — the
        // engine deletes server-side and clears the storage record).
        if params.delete_username {
            return match engine
                .call("usernameDelete", upstream, CallClass::Mutating)
                .await
            {
                Ok(_) => Ok(AccountUsername {
                    username: None,
                    username_link: None,
                }),
                Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                    "SEND_OUTCOME_UNKNOWN",
                    "mutating request has an unknown outcome",
                    false,
                ))),
                Err(error) => Err(error.into()),
            };
        }
        // Set path, two hops under the same unknown-outcome discipline:
        // reserve (candidate + hash, no user-visible server effect)
        // adopts the candidate, confirm (proof + link) lands it.
        let reserved = match engine
            .call("usernameReserve", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => result,
            Err(EngineError::UnknownOutcome) => {
                return Err(ServiceError::Api(ApiError::new(
                    "SEND_OUTCOME_UNKNOWN",
                    "mutating request has an unknown outcome",
                    false,
                )));
            }
            Err(error) => return Err(error.into()),
        };
        let confirm = json!({
            "account": account_key,
            "username": reserved
                .get("username")
                .and_then(Value::as_str)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            "usernameHash": reserved
                .get("usernameHash")
                .and_then(Value::as_str)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
        });
        match engine
            .call("usernameConfirm", confirm, CallClass::Mutating)
            .await
        {
            Ok(result) => {
                let username = result
                    .get("username")
                    .and_then(Value::as_str)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?
                    .to_string();
                Ok(AccountUsername {
                    username: Some(username),
                    username_link: result
                        .get("usernameLink")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// accounts.getUsername (contract revision 1.59, §4.55; the kt-engine
    /// read face opened with contract 1.74, §4.65): a read-only engine
    /// `getUsername` call projects the `{username?, usernameLink?}` storage
    /// truth (both keys absent = unset — the honest never-set answer, not an
    /// error).
    pub async fn get_username(
        &self,
        params: AccountsGetUsernameParams,
    ) -> Result<AccountUsername, ServiceError> {
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_accounts_get_username(&params.account_id)?
        };
        let engine = self.running_engine().await?;
        match engine
            .call("getUsername", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => Ok(AccountUsername {
                username: result
                    .get("username")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                username_link: result
                    .get("usernameLink")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// username.lookup (contract revision 1.59, §4.55; the kt-engine face
    /// opened with contract 1.74, §4.65): resolution under the service lock,
    /// then the read-only `usernameLookup` engine call (same server
    /// lookups). The upstream answer
    /// is a top-level array; the connector projects it entry-for-entry — a
    /// missing field is a protocol face, not a silently-dropped item.
    pub async fn lookup_usernames(
        &self,
        params: UsernameLookupParams,
    ) -> Result<UsernameLookupResult, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_username_lookup(&params)?
        };
        let result = engine
            .call("usernameLookup", upstream, CallClass::ReadOnly)
            .await?;
        let entries = result
            .as_array()
            .ok_or(ServiceError::Engine(EngineError::Protocol))?;
        Ok(UsernameLookupResult {
            results: entries
                .iter()
                .map(|entry| {
                    Ok(UsernameLookupEntry {
                        recipient: entry
                            .get("recipient")
                            .and_then(Value::as_str)
                            .ok_or(ServiceError::Engine(EngineError::Protocol))?
                            .to_string(),
                        number: entry
                            .get("number")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        username: entry
                            .get("username")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        uuid: entry
                            .get("uuid")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        is_registered: entry
                            .get("isRegistered")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    })
                })
                .collect::<Result<Vec<_>, ServiceError>>()?,
        })
    }

    /// phone.lookup (contract revision 1.164, §4.162): resolution under the
    /// service lock, then the read-only `phoneLookup` engine call (the CDSI
    /// batch, engine d088a59 — connector wire `phone.lookup`, engine method
    /// camelCase, the username chain's naming posture). The upstream answer
    /// is a top-level array projected entry-for-entry — the keys ride the
    /// engine's names verbatim (`number`/`aci`/`pni`/`isRegistered`, absent
    /// service ids absent, a miss pre-degraded `{number, isRegistered:
    /// false}`), a missing `number` is a protocol face, not a silently
    /// dropped item, and the projection answers from memory alone: nothing
    /// lands in the connector store. The three structured error faces
    /// (PHONE_INVALID / PHONE_RATE_LIMITED + data.retryAfterSeconds /
    /// PHONE_SERVER_FAILED) ride the engine's literals through the global
    /// mapping; the plain -32603 unknown-account face stays UPSTREAM_ERROR.
    pub async fn lookup_phones(
        &self,
        params: PhoneLookupParams,
    ) -> Result<PhoneLookupResult, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_phone_lookup(&params)?
        };
        let result = engine
            .call("phoneLookup", upstream, CallClass::ReadOnly)
            .await?;
        let entries = result
            .as_array()
            .ok_or(ServiceError::Engine(EngineError::Protocol))?;
        Ok(PhoneLookupResult {
            entries: entries
                .iter()
                .map(|entry| {
                    Ok(PhoneLookupEntry {
                        number: entry
                            .get("number")
                            .and_then(Value::as_str)
                            .ok_or(ServiceError::Engine(EngineError::Protocol))?
                            .to_string(),
                        aci: entry.get("aci").and_then(Value::as_str).map(str::to_string),
                        pni: entry.get("pni").and_then(Value::as_str).map(str::to_string),
                        is_registered: entry
                            .get("isRegistered")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    })
                })
                .collect::<Result<Vec<_>, ServiceError>>()?,
        })
    }

    /// identities.get (contract revision 1.68, §4.61; peer arm added by
    /// contract revision 1.281, §4.265, capability safety-number): addressing
    /// decode first (`conversationId` xor `peerKey` — a params-shape gate that
    /// must not depend on runtime state), then resolution under the service
    /// lock, then the read-only pinned `listIdentities` call narrowed to the
    /// addressed peer reference. The upstream answer is the JSON array of
    /// `JsonIdentity` records; the projection is the §4.61 ladder (empty →
    /// `identity` null, malformed record → protocol defect). The peer arm
    /// resolves no conversation: the account identity store is read directly
    /// by the peer reference, so a peer with no direct thread is readable.
    pub async fn get_identity(
        &self,
        params: IdentitiesGetParams,
    ) -> Result<IdentityRead, ServiceError> {
        // 契约 §4.265：寻址形状（恰一）先于运行时状态 fail-closed——双缺 /
        // 同置与 peerKey 词形都在任何 engine 调用之前拒。
        let target = identities_addressing(
            params.conversation_id.as_deref(),
            params.peer_key.as_deref(),
        )
        .map_err(ServiceError::Api)?;
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_identities_get_for_target(&params.account_id, &target)?
        };
        let result = engine
            .call("listIdentities", upstream, CallClass::ReadOnly)
            .await?;
        identity_from_engine(&result)
    }

    /// identities.verify (contract revision 1.68, §4.61; peer arm added by
    /// contract revision 1.281, §4.265, capability safety-number): addressing
    /// decode, resolution under the service lock, then the mutating
    /// `trust` call (both arms: `verifiedSafetyNumber` or the §4.223
    /// `state` reset) — the reaction-class discipline verbatim (an
    /// indeterminate outcome answers SEND_OUTCOME_UNKNOWN and is never
    /// retried: the trust write may already have landed). The engine answers
    /// an empty result object on success (the command writes no JSON output),
    /// so the result is the plain `{status: "verified"}` confirmation; the
    /// upstream mismatch UserError folds into the plain UPSTREAM_ERROR like
    /// every account-domain method. The peer arm addresses the account
    /// identity store directly — no conversation row is resolved or required,
    /// and the write-through stamp lands on the peer's direct row when one
    /// exists (a peer with no row simply has no local projection to stamp).
    pub async fn verify_identity(
        &self,
        params: IdentitiesVerifyParams,
    ) -> Result<IdentityVerifyOutcome, ServiceError> {
        // 契约 §4.265：寻址两臂先解码（同读面，形状先于运行时状态）。
        let target = identities_addressing(
            params.conversation_id.as_deref(),
            params.peer_key.as_deref(),
        )
        .map_err(ServiceError::Api)?;
        // 契约 §4.223：两臂恰一路由（双臂/双缺 fail-closed 同 engine）。
        // 解码与写穿词各是 service 层的单点纯函数——supervisor 只做装配，
        // 两臂语义与单测同源。
        let intent =
            identities_verify_intent(params.safety_number.as_deref(), params.state.as_deref())
                .map_err(ServiceError::Api)?;
        // Contract 1.260 (§4.244): the write-through stamp word — the
        // official `#_setVerified` arm writes the protocol store AND lands
        // the record (`DataWriter.updateConversation`), so the projection
        // the render reads is the deterministic post-image of the write.
        // Verified arm → TRUSTED_VERIFIED (the engine trust
        // verifiedSafetyNumber post-image); trust-reset arm (state "default",
        // the official DEFAULT write) → TRUSTED_UNVERIFIED (first-use trust
        // restored, the word the next `listIdentities` read answers).
        let stamp_word = identity_verify_stamp_word(&intent);
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_identities_verify_for_target(&params.account_id, &target, &intent)?
        };
        match engine.call("trust", upstream, CallClass::Mutating).await {
            Ok(_) => {
                {
                    let service = self.service.lock().await;
                    let _ =
                        service.stamp_identity_verified(&params.account_id, &target, stamp_word);
                }
                Ok(IdentityVerifyOutcome { status: "verified" })
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.setBlocked (contract revision 1.48, §4.47, capability
    /// blocked-write): bounds + resolution under the service lock, then the
    /// mutating engine call — reaction-class discipline: an unknown outcome
    /// answers SEND_OUTCOME_UNKNOWN and is never retried; the success result
    /// is the post-write cloud blocked list read back, not a local echo.
    pub async fn set_conversation_blocked(
        &self,
        params: ConversationsSetBlockedParams,
    ) -> Result<BlockedConversations, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_set_blocked(
                &params.account_id,
                &params.conversation_id,
                &params.kind,
                params.blocked,
            )?
        };
        match engine
            .call("setConversationBlocked", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => {
                let blocked = blocked_conversations_result(
                    result
                        .get("blocked")
                        .and_then(Value::as_array)
                        .ok_or(ServiceError::Engine(EngineError::Protocol))?,
                );
                // 契约 1.253（§4.239）：BLOCK 行的先态门在盖章前读——官方
                // blockConversation → applyMessageRequestResponse 的
                // didBlockChange = hasBlock(response) ≠ isBlocked()（先态），
                // 已屏蔽会话的重复 block 不铸行。§4.47 是 KT 所有屏蔽路径
                // （请求区/信息页/头部菜单）的同一写面，官方对位全部走
                // blockConversation thunk（ConversationDetails.dom.tsx:779 同
                // 一出口），全局落行 = 官方同构。params.blocked=false 是官方
                // 素 unblock（unblock() 更新块清单，不经
                // applyMessageRequestResponse，UNBLOCK 行只由「被屏蔽会话的
                // accept」铸造）——不落行，记档对照。落行 warn-only（§4.226
                // 纪律：云应答是主面，行只是持久回声）。
                let prior_blocked = self
                    .store
                    .conversation_summary(&params.account_id, &params.conversation_id)
                    .ok()
                    .flatten()
                    .is_some_and(|summary| summary.blocked);
                // Contract 1.138 (§4.131): the local mirror follows the
                // upstream write — the direct row's factor stamp carries the
                // blocked bit (a group row stamps nothing, §4.45 pull stays
                // the group authority) and the refreshed summary rides
                // conversation.changed, so the masking window and every other
                // window converge without a re-read. Best-effort like the
                // expire-timer mirror: a mirror failure only costs the next
                // event its freshness, the cloud answer stays the face.
                let stamped = self
                    .store
                    .set_conversation_blocked_factor(
                        &params.account_id,
                        &params.conversation_id,
                        params.blocked,
                    )
                    .unwrap_or(false);
                // 契约 1.258（§4.56 动作臂盖章 · 批 X · S7①）：官方
                // blockConversation thunk = applyMessageRequestResponse(BLOCK)
                //（ducks/conversations.preload.ts:4073-4127），无条件写
                // messageRequestResponseType = BLOCK 成员
                //（models/conversations.preload.ts:2638-2640）——§4.47 是 KT
                // 全部屏蔽路径的同一写面，§4.56 因子随同一臂盖章（accepted=
                // false + 原始成员 BLOCK=3）。direct 限定（store 闸，官方
                // 请求语义不落群行）；params.blocked=false 是官方素 unblock
                //（applyMessageRequestResponse 不运行），不盖章记档。best-
                // effort：失败降镜像/读面收敛。
                if params.blocked
                    && let Err(error) = self.store.set_conversation_accept_response_factor(
                        &params.account_id,
                        &params.conversation_id,
                        false,
                        crate::service::MRR_RESPONSE_TYPE_BLOCK,
                    )
                {
                    tracing::warn!(
                        kind = "message_request_factor",
                        class = error.class(),
                        "block stamped no request factor; the mirror path converges"
                    );
                }
                if stamped
                    && let Some(conversation) = self
                        .store
                        .conversation_summary(&params.account_id, &params.conversation_id)
                        .ok()
                        .flatten()
                {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(conversation));
                }
                if params.blocked && !prior_blocked {
                    let store = Arc::clone(&self.store);
                    let account_id = params.account_id.clone();
                    let conversation_id = params.conversation_id.clone();
                    match blocking_service(move || {
                        crate::service::store_land_message_request_row(
                            &store,
                            &account_id,
                            &conversation_id,
                            crate::service::MrrRowEvent::Block,
                        )
                    })
                    .await
                    {
                        Ok(Some(row_event)) => {
                            let _ = self.host_events.send(row_event);
                            // A group row stamps nothing (the §4.131 store
                            // posture) — the row's own changed push keeps the
                            // list window convergent all the same.
                            if !stamped
                                && let Some(conversation) = self
                                    .store
                                    .conversation_summary(
                                        &params.account_id,
                                        &params.conversation_id,
                                    )
                                    .ok()
                                    .flatten()
                            {
                                let _ = self
                                    .host_events
                                    .send(HostSideEvent::ConversationChanged(conversation));
                            }
                        }
                        Ok(None) => {}
                        Err(error) => tracing::warn!(
                            kind = "message_request_row",
                            class = error.class(),
                            "block landed no timeline row; the upstream answer stands"
                        ),
                    }
                }
                Ok(blocked)
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.saveDraft (contract 1.138, §4.130): the local draft
    /// stamp — bounds, resolution, and the timestamp-only write in one
    /// blocking-lane call over the shared store, no engine and no upstream
    /// (the `history.importRetry` lane shape; the account-scoped mutating
    /// mutex and delete barrier apply through the host `acquire`). The
    /// refreshed summary rides conversation.changed so every window sees the
    /// new draft clock without a re-read.
    pub async fn save_conversation_draft(
        &self,
        params: crate::service::ConversationsSaveDraftParams,
    ) -> Result<&'static str, ServiceError> {
        let store = Arc::clone(&self.store);
        let summary = blocking_service(move || {
            crate::service::store_save_conversation_draft(
                &store,
                &params.account_id,
                &params.conversation_id,
                params.draft_timestamp,
            )
        })
        .await?;
        let _ = self
            .host_events
            .send(HostSideEvent::ConversationChanged(summary));
        Ok("saved")
    }

    /// conversations.clearDraft (contract 1.138, §4.130): the stamp is the
    /// whole draft record, so the clear is the save's inverse on the same
    /// local lane — idempotent (a conversation with no draft still answers
    /// `saved`→`cleared`), and the refreshed summary rides
    /// conversation.changed.
    pub async fn clear_conversation_draft(
        &self,
        params: crate::service::ConversationsClearDraftParams,
    ) -> Result<&'static str, ServiceError> {
        let store = Arc::clone(&self.store);
        let summary = blocking_service(move || {
            crate::service::store_clear_conversation_draft(
                &store,
                &params.account_id,
                &params.conversation_id,
            )
        })
        .await?;
        let _ = self
            .host_events
            .send(HostSideEvent::ConversationChanged(summary));
        Ok("cleared")
    }

    /// conversations.getState (contract revision 1.116, §4.97, capability
    /// conversation-state): bounds + resolution under the service lock, then
    /// the read-only engine call — the three cloud bits read back, all keys
    /// always present (0/false = unset bit). The connector persists nothing:
    /// the cloud record is the whole state.
    pub async fn get_conversation_state(
        &self,
        params: ConversationsGetStateParams,
    ) -> Result<ConversationState, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_get_state(
                &params.account_id,
                &params.conversation_id,
                &params.kind,
            )?
        };
        match engine
            .call("getConversationState", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => conversation_state_from_engine(&result),
            // The bare -32603 face (an account the engine no longer holds, a
            // malformed parameter the typed ladder cannot produce) is a
            // deterministic refusal — retryable=false, the 1.115 discipline.
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.setState (contract revision 1.116, §4.97, capability
    /// conversation-state): bounds + resolution under the service lock, then
    /// the mutating engine call — the reaction-class discipline verbatim (an
    /// indeterminate outcome answers SEND_OUTCOME_UNKNOWN and is never
    /// retried: the storage write may already have landed). Only the flags
    /// the caller sent travel (the engine's partial-write grammar); the
    /// success result is the post-write projection read back, not a local
    /// echo. Zero local writes: the cloud record is the whole state.
    pub async fn set_conversation_state(
        &self,
        params: ConversationsSetStateParams,
    ) -> Result<ConversationState, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_set_state(
                &params.account_id,
                &params.conversation_id,
                &params.kind,
                params.muted_until_timestamp,
                params.archived,
                params.marked_unread,
            )?
        };
        match engine
            .call("setConversationState", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => conversation_state_from_engine(&result),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            // The bare -32603 face rejects the parameters before any write
            // lands — a deterministic refusal, retryable=false (the 1.115
            // groups discipline).
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.generateInviteLinkPassword (contract revision 1.117, §4.98,
    /// capability group-invite-links): the account-less material face —
    /// 16 CSPRNG bytes as standard base64, the official
    /// GROUP_INVITE_LINK_PASSWORD_LENGTH. No dispatch record engine-side
    /// (the material faces never log), and the bytes are single-pass:
    /// they ride this answer and are never logged or persisted
    /// connector-side.
    pub async fn generate_group_invite_link_password(
        &self,
        _params: GroupsInviteLinkPasswordParams,
    ) -> Result<GroupInviteLinkPassword, ServiceError> {
        let engine = self.running_engine().await?;
        let result = engine
            .call("generateInviteLinkPassword", json!({}), CallClass::ReadOnly)
            .await?;
        group_invite_link_password_from_engine(&result)
    }

    /// groups.buildInviteLink (contract revision 1.117, §4.98, capability
    /// group-invite-links): group resolution under the service lock, then
    /// the read-only `buildInviteLink {account, groupId, password?}` — the
    /// explicit-password arm is pure construction, the default arm reads
    /// the server group state (a link the group has not enabled answers
    /// GROUP_INVITE_LINK_UNAVAILABLE). Read lane, non-mutating; the link
    /// and password bytes are single-pass material.
    pub async fn build_group_invite_link(
        &self,
        params: GroupsBuildInviteLinkParams,
    ) -> Result<GroupInviteLink, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_build_invite_link(
                &params.account_id,
                &params.conversation_id,
                params.password.as_deref(),
            )?
        };
        match engine
            .call("buildInviteLink", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => {
                let invite_link = result
                    .get("inviteLink")
                    .and_then(Value::as_str)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?;
                Ok(GroupInviteLink {
                    invite_link: invite_link.to_string(),
                })
            }
            // The bare -32603 face (an account the engine no longer holds,
            // a malformed parameter the typed ladder cannot produce) is a
            // deterministic refusal — retryable=false, the 1.115
            // discipline; the structured link families
            // (GROUP_INVITE_LINK_UNAVAILABLE, STORAGE_UNAVAILABLE) map
            // through the allowlist channels.
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.parseInviteLink (contract revision 1.117, §4.98, capability
    /// group-invite-links): the account-less pure-parse face — the engine
    /// decodes the official `https://signal.group/#<websafe>` shape (the
    /// three URL forms and the bare invite code) to its master key +
    /// password bytes; a malformed link is the engine's -32603 face, the
    /// deterministic UPSTREAM_ERROR refusal. The decoded bytes are
    /// single-pass material.
    pub async fn parse_group_invite_link(
        &self,
        params: GroupsParseInviteLinkParams,
    ) -> Result<GroupInviteLinkParse, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_parse_invite_link(&params.invite_link)?
        };
        match engine
            .call("parseInviteLink", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => group_invite_link_parse_from_engine(&result),
            // The bare -32603 parse gate (a malformed link the engine's
            // tolerance ladder refuses before anything goes upstream) is a
            // deterministic refusal — retryable=false, a replay fails the
            // same way.
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.previewViaLink (contract revision 1.117, §4.98, capability
    /// group-invite-links): bounds + account resolution under the service
    /// lock, then the read-only `previewGroupViaLink {account, inviteLink}`
    /// — the engine's pre-join projection (the link's group without
    /// membership). Read lane; a server refusal answers
    /// GROUP_INVITE_LINK_PREVIEW_FAILED with data.status? verbatim.
    pub async fn preview_group_via_link(
        &self,
        params: GroupsPreviewViaLinkParams,
    ) -> Result<GroupInviteLinkPreview, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_link_addressed_face(&params.account_id, &params.invite_link)?
        };
        match engine
            .call("previewGroupViaLink", upstream, CallClass::ReadOnly)
            .await
        {
            Ok(result) => group_invite_link_preview_from_engine(&result),
            // The bare -32603 face (a malformed link, an account the
            // engine no longer holds) is a deterministic refusal —
            // retryable=false; the structured faces
            // (GROUP_INVITE_LINK_PREVIEW_FAILED, STORAGE_UNAVAILABLE) map
            // through the allowlist channels.
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.joinViaLink (contract revision 1.117, §4.98, capability
    /// group-invite-links): bounds + account resolution under the service
    /// lock, then the mutating `joinGroupViaLink {account, inviteLink}` —
    /// the reaction-class discipline with the timer face's unknown-outcome
    /// honesty (an indeterminate answer is SEND_OUTCOME_UNKNOWN and is
    /// never retried; the join may already have landed). The status verb
    /// distinguishes the definite member add (`joined`) from the approval
    /// gate's request (`requested`); a server rejection answers
    /// GROUP_UPDATE_FAILED with data.status? verbatim (the 1.115 channel).
    /// Zero local writes: the roster converges through contacts.sync.
    pub async fn join_group_via_link(
        &self,
        params: GroupsJoinViaLinkParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_link_addressed_face(&params.account_id, &params.invite_link)?
        };
        match engine
            .call("joinGroupViaLink", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => group_invite_join_status_from_engine(&result),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            // The bare -32603 face (a malformed link the engine's parse
            // gate refuses before anything goes upstream) is a
            // deterministic refusal — retryable=false.
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// groups.cancelJoinRequest (contract revision 1.117, §4.98, capability
    /// group-invite-links): the join write's withdrawal twin — the same
    /// link-addressed ladder, the same reaction-class discipline, the
    /// same `{"status": "cancelled"}` definite success. Zero local
    /// writes: the roster converges through contacts.sync.
    pub async fn cancel_join_request(
        &self,
        params: GroupsCancelJoinRequestParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_groups_link_addressed_face(&params.account_id, &params.invite_link)?
        };
        match engine
            .call("cancelJoinRequest", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("cancelled"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(EngineError::Upstream { .. }) => Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "engine returned an error",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// conversations.acceptRequest (contract revision 1.63, §4.56, capability
    /// message-requests): bounds + resolution under the service lock, then
    /// the mutating upstream `sendMessageRequestResponse {type: accept}` —
    /// the pinned native face. Reaction-class discipline: an unknown outcome
    /// answers SEND_OUTCOME_UNKNOWN and is never retried. Zero local writes:
    /// the request state converges through the §4.56 receive projection.
    pub async fn accept_message_request(
        &self,
        params: MessageRequestParams,
    ) -> Result<MessageRequestOutcome, ServiceError> {
        self.message_request_request(params, "accept", "accepted")
            .await
    }

    /// conversations.declineRequest (contract revision 1.63, §4.56,
    /// capability message-requests): the delete variant — the same bare
    /// upstream face with `type: delete`, the official decline (delete-the-
    /// conversation) sync semantics. The pinned JSON-RPC face answers an
    /// empty result object on success and folds every per-recipient failure
    /// (ResolveHelper/SyncHelper, incl. the profile-sharing-off write's
    /// UnregisteredRecipientException path) into a USER_ERROR -1 with no
    /// structured marker, so no per-failure ladder is attempted here — the
    /// connector maps the error class honestly (UPSTREAM_ERROR) and never
    /// composes a second upstream write onto one host method (the official
    /// block-and-delete twin stays the desktop's explicit
    /// conversations.setBlocked composition). Unknown outcomes are terminal.
    pub async fn decline_message_request(
        &self,
        params: MessageRequestParams,
    ) -> Result<MessageRequestOutcome, ServiceError> {
        self.message_request_request(params, "delete", "declined")
            .await
    }

    /// The shared §4.56 body: prepare under the service lock, stamp the
    /// upstream `type`, one mutating engine call, unknown-outcome mapping.
    async fn message_request_request(
        &self,
        params: MessageRequestParams,
        request_type: &str,
        status: &'static str,
    ) -> Result<MessageRequestOutcome, ServiceError> {
        let engine = self.running_engine().await?;
        let mut upstream = {
            let service = self.service.lock().await;
            service.prepare_conversations_message_request(
                &params.account_id,
                &params.conversation_id,
            )?
        };
        if let Some(object) = upstream.as_object_mut() {
            object.insert("type".to_string(), json!(request_type));
        }
        match engine
            .call("sendMessageRequestResponse", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => {
                // 契约 1.253（§4.239）：LOCAL 动作臂的时间线系统行——官方次序
                // 是「先本地落行（LOCAL 源），再上行 sync」（ducks/
                // conversations.preload.ts:3779-3787
                // syncMessageRequestResponse），上行已答 = 官方动作已定局，
                // 本臂补本地持久行。accept 的事件词按官方 didUnblock 映射
                // （applyMessageRequestResponse:2600-2607：被屏蔽会话的
                // accept = UNBLOCK 行）；delete = 官方 DELETE——上游即删会话
                // 语义，官方 DELETE 臂不铸行（:2616-2638 只铸 ACCEPT/BLOCK/
                // SPAM 三臂），落行无渲染面，诚实不落（记档对照）。落行
                // warn-only：行只是持久回声，动作应答是主面（§4.226 纪律）。
                if request_type == "accept" {
                    let store = Arc::clone(&self.store);
                    let account_id = params.account_id.clone();
                    let conversation_id = params.conversation_id.clone();
                    match blocking_service(move || {
                        crate::service::store_land_message_request_row(
                            &store,
                            &account_id,
                            &conversation_id,
                            crate::service::MrrRowEvent::Accept,
                        )
                    })
                    .await
                    {
                        Ok(Some(row_event)) => {
                            let _ = self.host_events.send(row_event);
                            // The list face rides the refreshed summary (the
                            // row is the conversation's new last message): the
                            // changed push follows the row (§4.239 row-then-
                            // summary order), read AFTER the insert so it
                            // never predates the row.
                            if let Ok(Some(conversation)) = self
                                .store
                                .conversation_summary(&params.account_id, &params.conversation_id)
                            {
                                let _ = self
                                    .host_events
                                    .send(HostSideEvent::ConversationChanged(conversation));
                            }
                        }
                        Ok(None) => {}
                        Err(error) => tracing::warn!(
                            kind = "message_request_row",
                            class = error.class(),
                            "accept landed no timeline row; the action answer stands"
                        ),
                    }
                }
                // 契约 1.258（§4.56 动作臂盖章 · 批 X · S7①）：动作设备即真相
                // 源——官方动作次序「先本地落行/盖章、再上行 sync」
                //（ducks/conversations.preload.ts:3779-3787），sync 只发对端
                // 设备、动作臂永不经镜像回流盖章，§4.239 批记档的「本机
                // accept 后因子不经镜像回流、重载后 accepted 派生回落窗口
                // 权重」窗口由此闭合：accept → ACCEPT 位 true + 原始成员 1，
                // decline → DELETE 成员 2（官方 deleteConversation thunk 的
                // DELETE stamp 同源，models/conversations.preload.ts:2638-2640
                // 无条件写）。§4.58 存储闸直连同款写面（direct 限定，官方
                // 请求语义不落群行）；best-effort——盖章失败降下次镜像/读面
                // 收敛，动作应答仍是主面。
                {
                    let accepted = request_type == "accept";
                    let member = if accepted {
                        crate::service::MRR_RESPONSE_TYPE_ACCEPT
                    } else {
                        crate::service::MRR_RESPONSE_TYPE_DELETE
                    };
                    match self.store.set_conversation_accept_response_factor(
                        &params.account_id,
                        &params.conversation_id,
                        accepted,
                        member,
                    ) {
                        Ok(_) => {
                            if let Ok(Some(conversation)) = self
                                .store
                                .conversation_summary(&params.account_id, &params.conversation_id)
                            {
                                let _ = self
                                    .host_events
                                    .send(HostSideEvent::ConversationChanged(conversation));
                            }
                        }
                        Err(error) => tracing::warn!(
                            kind = "message_request_factor",
                            class = error.class(),
                            "action stamped no request factor; the mirror path converges"
                        ),
                    }
                }
                Ok(MessageRequestOutcome { status })
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// calls.sendSignal (contract revision 1.53, §4.49, capability
    /// call-signaling): the shape gate + resolution under the service lock,
    /// then the mutating engine `sendCallMessage` call — the reaction-class
    /// discipline verbatim (same-account mutex, delete barrier, an unknown
    /// outcome answers SEND_OUTCOME_UNKNOWN and is never retried). The
    /// signaling envelope travels byte-for-byte: the connector neither
    /// parses nor logs the payload. Legacy busy/hangup frames without a
    /// payload route the engine's `legacy` bare-frame face (contract 1.53);
    /// `urgency` rides through when present. The result is the engine's
    /// envelope timestamp, echoed as `{sentAt}` — the send ack, not call
    /// state (the connector keeps none).
    pub async fn send_call_signal(
        &self,
        params: CallsSendSignalParams,
    ) -> Result<Value, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_calls_send_signal(
                &params.account_id,
                &params.conversation_id,
                &params.signal_type,
                params.call_id,
                params.payload.as_deref(),
                params.urgency.as_deref(),
                params.hangup_type.as_deref(),
                params.destination_device_id,
            )?
        };
        match engine
            .call("sendCallMessage", upstream, CallClass::Mutating)
            .await
        {
            Ok(result) => {
                let sent_at = result
                    .get("timestamp")
                    .and_then(Value::as_u64)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?;
                Ok(json!({ "sentAt": sent_at }))
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// calls.getState (contract revision 1.50, §4.48, capability
    /// call-signaling): a store-only read — no engine call, no network, no
    /// mutation (the `history.importStatus` class). The connector's call
    /// registry is the honest empty state: the connector is the signaling
    /// pipe between the engine's transport and the desktop + calling
    /// sidecar's RingRTC state machine, not a state owner.
    pub async fn call_state(&self, account_id: String) -> Result<Value, ServiceError> {
        let service = self.service.lock().await;
        let state = service.prepare_calls_get_state(&account_id)?;
        Ok(serde_json::to_value(state).unwrap_or(Value::Null))
    }

    /// calls.sendGroupCallUpdate (contract revision 1.127, §4.108,
    /// capability call-signaling): the group-call era update — the engine
    /// `sendGroupCallUpdate` face (the official DataMessage.groupCallUpdate
    /// group fan-out). A mutating upstream write: the indeterminate outcome
    /// folds to SEND_OUTCOME_UNKNOWN (retryable=false) and is never retried
    /// — an era update whose delivery is unknown may already sit in the
    /// group's call state. The definite success answers the explicit
    /// `{"status":"sent"}` — the engine's own body is empty, the update's
    /// identity is the era string itself.
    pub async fn send_group_call_update(
        &self,
        params: CallsSendGroupCallUpdateParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_calls_send_group_call_update(&params)?
        };
        match engine
            .call("sendGroupCallUpdate", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "mutating request has an unknown outcome",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// calls.linkPresentation (contract revision 1.88, §4.73, capability
    /// call-signaling widened in place): pure engine material passthrough —
    /// the shape gate + account resolution ride the service prepare under
    /// the service lock, then the engine's KT-extension method answers the
    /// presentation bytes, forwarded verbatim. The connector parses nothing,
    /// logs nothing, caches nothing: the credential bytes cross this process
    /// exactly once, engine → host (the engine compat §5 zero-persistence
    /// discipline mirrored at the pipe). Read-only engine class: a timeout
    /// answers UPSTREAM_TIMEOUT (retryable), never the mutating unknown
    /// outcome. The faces are KT-extension engine methods (the §4.69
    /// ladder).
    pub async fn calls_link_presentation(
        &self,
        account_id: &str,
        root_key: &str,
    ) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_calls_link_presentation(account_id, root_key)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("calls.linkPresentation", params, CallClass::ReadOnly)
            .await
            .map_err(ServiceError::from)
    }

    /// calls.createLinkAuth (contract revision 1.88, §4.73): the create-auth
    /// two-shot passthrough — the same discipline as `calls_link_presentation`
    /// with the roomId gate added. The engine runs both shots (the
    /// create-auth POST → redeem → present + public params) inside the one
    /// RPC; the server-side POST is credential issuance with no user-visible
    /// state change, so the face stays read-only.
    pub async fn calls_create_link_auth(
        &self,
        account_id: &str,
        root_key: &str,
        room_id: &str,
    ) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_calls_create_link_auth(account_id, root_key, room_id)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("calls.createLinkAuth", params, CallClass::ReadOnly)
            .await
            .map_err(ServiceError::from)
    }

    /// calls.groupProof (contract revision 1.88, §4.73): the membership
    /// proof passthrough — `calls_link_presentation`'s discipline with the
    /// 32-byte group master key gate (the engine's decode_group_id shape).
    pub async fn calls_group_proof(
        &self,
        account_id: &str,
        group_id: &str,
    ) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_calls_group_proof(account_id, group_id)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("calls.groupProof", params, CallClass::ReadOnly)
            .await
            .map_err(ServiceError::from)
    }

    /// calls.groupMembers (contract revision 1.88, §4.73): the member
    /// cipher-text material passthrough — the `calls_group_proof` discipline
    /// verbatim against the engine's groupMembers face; the ACI-keyed
    /// material never touches a connector log or store.
    pub async fn calls_group_members(
        &self,
        account_id: &str,
        group_id: &str,
    ) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_calls_group_members(account_id, group_id)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("calls.groupMembers", params, CallClass::ReadOnly)
            .await
            .map_err(ServiceError::from)
    }

    /// calls.endorsementsPublicKey (contract revision 1.88, §4.73): the
    /// constant-derivation passthrough — no account, no material input, no
    /// network; the engine derives from its pinned legacy ServerPublicParams
    /// and the bytes pass through (a KT-extension engine method).
    pub async fn calls_endorsements_public_key(&self) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_calls_endorsements_public_key()?
        };
        let engine = self.running_engine().await?;
        engine
            .call("calls.endorsementsPublicKey", params, CallClass::ReadOnly)
            .await
            .map_err(ServiceError::from)
    }

    /// calls.relays (contract revision 1.145, §4.143): the call-relay
    /// proxy — the §4.73 material-passthrough discipline with no material:
    /// the account resolution rides the service prepare, the read-only
    /// engine call may touch the network inside the one call (the
    /// `conversations.getAvatar` read class), and the engine's answer —
    /// the official-same-shape relay list with its own freshness face —
    /// passes through untouched. The error face is the engine's verbatim:
    /// the plain -32603 unknown-account face degrades through the
    /// structured ladder, and the 401/403 unbound message trips the
    /// existing §4.17 authorization matcher (the connector adds no
    /// matcher of its own). Read-only engine class: a timeout answers
    /// UPSTREAM_TIMEOUT (retryable), never the mutating unknown outcome.
    pub async fn calls_relays(&self, account_id: &str) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_calls_relays(account_id)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("calls.relays", params, CallClass::ReadOnly)
            .await
            .map_err(ServiceError::from)
    }

    /// calls.sendCallEvent (contract revision 1.151, §4.150): the call-event
    /// self-sync proxy — the §4.143 relays posture on the send lane. The
    /// account resolution rides the service prepare, the
    /// SyncMessage.callEvent=19 self-send crosses as the engine's own
    /// mutating call, the success `{timestamp}` answer passes through
    /// untouched, and the error face is the engine's verbatim through the
    /// structured ladder: the plain -32603 parse/unknown-account faces
    /// degrade to UPSTREAM_ERROR, the §4.17 unbound matcher still applies,
    /// and the connector adds no gate of its own (the engine 6d56660
    /// fail-closed parse owns the word lists, the conversation shapes, the
    /// callId domain, and the per-leg callId requirement). Mutating engine
    /// class: a timeout answers SEND_OUTCOME_UNKNOWN and is never retried —
    /// an unknown sync outcome may already sit in the self-device fan-out.
    pub async fn send_call_event(
        &self,
        params: crate::service::CallsSendCallEventParams,
    ) -> Result<Value, ServiceError> {
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_send_call_event(&params)?
        };
        let engine = self.running_engine().await?;
        engine
            .call("sendCallEvent", prepared, CallClass::Mutating)
            .await
            .map_err(ServiceError::from)
    }

    /// "Delete for everyone" for one own sent message: local prepare under
    /// the service lock, upstream `remoteDelete` without it, then the
    /// contract-1.273 local tombstone completion on confirmation. Indeterminate
    /// outcomes still answer `{"status":"unknown"}` and never auto-retry.
    pub async fn remote_delete(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_remote_delete(&account_id, &conversation_id, &message_id)?
        };
        let outcome = engine
            .call("remoteDelete", prepared.params, CallClass::Mutating)
            .await;
        // 契约 §4.224：结算删除失败态——成功清旗标；未知/失败落旗标+时刻
        // （持久化，重启后桌面仍可见「删除失败可重试」）。结果本身不自动重试
        // （unknown_outcome 纪律）。
        {
            let service = self.service.lock().await;
            let failed = outcome.is_err();
            let _ = service.set_message_delete_failed(&account_id, &message_id, failed);
        }
        match outcome {
            Ok(result) => {
                // 契约 1.273 + 1.274：上行确认后落本地墓碑，并持久化逐收件人
                // 删除状态。部分失败保留 success=true 的条目，同时置 failed。
                let send_status = Self::deleted_for_everyone_send_status_from_reply(&result);
                let failed = send_status.values().any(|succeeded| !succeeded);
                let completed = {
                    let service = self.service.lock().await;
                    service.complete_remote_delete(
                        &prepared.account_id,
                        &prepared.conversation_id,
                        &prepared.message_id,
                        prepared.target_sent_at,
                        send_status,
                        failed,
                    )?
                };
                if let Some((record, summary)) = completed {
                    let _ = self.host_events.send(HostSideEvent::MessageStatusChanged {
                        account_id: record.account_id,
                        message_id: record.id,
                        status: record.status,
                        delivered_at: None,
                        read_at: None,
                        viewed_at: None,
                    });
                    if let Some(summary) = summary {
                        let _ = self
                            .host_events
                            .send(HostSideEvent::ConversationChanged(summary));
                    }
                }
                Ok("deleted")
            }
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// Best-effort reaction add/remove for one message with a resolvable
    /// protocol identity (contract revision 1.7): local prepare under the
    /// service lock, upstream `sendReaction` call without it — the same shape
    /// as `send_text` and `remote_delete`. No local row is created or changed
    /// and no event is emitted; an indeterminate mutating outcome maps to the
    /// explicit `{"status":"unknown"}` response, never to an automatic retry.
    pub async fn send_reaction(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
        emoji: String,
        remove: bool,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_send_reaction(
                &account_id,
                &conversation_id,
                &message_id,
                &emoji,
                remove,
            )?
        };
        match engine
            .call("sendReaction", prepared.params, CallClass::Mutating)
            .await
        {
            Ok(_) => {
                // Confirmed upstream: persist the own reaction and push the
                // conversation refresh so pills survive the app's optimistic
                // window (the same event the receive path uses for reactions).
                let summary = {
                    let service = self.service.lock().await;
                    service.complete_send_reaction(
                        &prepared.account_id,
                        &prepared.conversation_id,
                        &prepared.emoji,
                        prepared.remove,
                        prepared.target_sent_at,
                    )?
                };
                if let Some(summary) = summary {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(summary));
                }
                Ok("sent")
            }
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// Best-effort pin for one message with a resolvable protocol identity
    /// (contract revision 1.33): the reaction shape end to end — local
    /// prepare under the service lock, upstream `sendPinMessage` call without
    /// it. On confirmation the derived per-conversation pinned state is
    /// written (a newer pin replaces the older one; the expiry is connector
    /// clock computed) and the conversation refresh rides the host lane, so a
    /// reloaded window renders the pin bar without replaying events. An
    /// indeterminate mutating outcome answers `{"status":"unknown"}` and is
    /// never retried automatically.
    pub async fn send_pin_message(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
        pin_duration_seconds: Option<u32>,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_send_pin_message(
                &account_id,
                &conversation_id,
                &message_id,
                pin_duration_seconds,
            )?
        };
        match engine
            .call("sendPinMessage", prepared.params, CallClass::Mutating)
            .await
        {
            Ok(_) => {
                let summary = {
                    let service = self.service.lock().await;
                    service.complete_send_pin_message(
                        &prepared.account_id,
                        &prepared.conversation_id,
                        &prepared.target_author,
                        prepared.target_sent_at,
                        prepared.pin_duration_seconds,
                    )?
                };
                if let Some(summary) = summary {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(summary));
                }
                Ok("sent")
            }
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// Best-effort unpin (contract revision 1.33): the pin shape without the
    /// duration. On confirmation the local pinned state clears only when it
    /// still points at the (author, timestamp) this unpin names, and the
    /// conversation refresh rides the host lane.
    pub async fn send_unpin_message(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_send_unpin_message(&account_id, &conversation_id, &message_id)?
        };
        match engine
            .call("sendUnpinMessage", prepared.params, CallClass::Mutating)
            .await
        {
            Ok(_) => {
                let summary = {
                    let service = self.service.lock().await;
                    service.complete_send_unpin_message(
                        &prepared.account_id,
                        &prepared.conversation_id,
                        &prepared.target_author,
                        prepared.target_sent_at,
                    )?
                };
                if let Some(summary) = summary {
                    let _ = self
                        .host_events
                        .send(HostSideEvent::ConversationChanged(summary));
                }
                Ok("sent")
            }
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// Best-effort group admin delete (contract revision 1.33): the pin
    /// addressing, group conversations only, with no admin-eligibility
    /// pre-check — the server is the authority and its rejection surfaces as
    /// the upstream error. The local row is left unchanged on success (the
    /// remoteDelete boundary, §4.5): the authoritative tombstone converges
    /// through the row-marker projection when the echo arrives.
    pub async fn send_admin_delete(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_send_admin_delete(&account_id, &conversation_id, &message_id)?
        };
        match engine
            .call("sendAdminDelete", prepared.params, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// Outbound read receipt (contract revision 1.34, §4.29): the pin-family
    /// shape with a fan-out instead of a single call — one engine
    /// `sendReadReceipt` per author group, results aggregated. A receipt-call
    /// failure never fails the request: any failure (including an unknown
    /// outcome) only degrades the answer to `{"status":"unknown"}`, and
    /// nothing is ever retried automatically.
    ///
    /// Contract revision 1.216 (§4.216): `read_message_id` is the optional
    /// message-granular read target — the service advances the conversation
    /// watermark to that row's `sent_at` (validated: a foreign or unknown
    /// target fails the request with INVALID_REQUEST before any fan-out).
    /// Absent keeps the whole-conversation advance byte-identically.
    pub async fn send_read_receipt(
        &self,
        account_id: String,
        conversation_id: String,
        message_ids: Option<Vec<String>>,
        read_message_id: Option<String>,
    ) -> Result<&'static str, ServiceError> {
        self.send_receipt(
            account_id,
            conversation_id,
            message_ids,
            read_message_id,
            "sendReadReceipt",
        )
        .await
    }

    /// Outbound viewed receipt (contract revision 1.34): identical fan-out,
    /// upstream `sendViewedReceipt`.
    pub async fn send_viewed_receipt(
        &self,
        account_id: String,
        conversation_id: String,
        message_ids: Option<Vec<String>>,
    ) -> Result<&'static str, ServiceError> {
        self.send_receipt(
            account_id,
            conversation_id,
            message_ids,
            // The viewed face has no read-position target: §4.216 is the
            // read legs' contract only.
            None,
            "sendViewedReceipt",
        )
        .await
    }

    /// Shared mark-read/mark-viewed body: prepare (selection + author
    /// grouping) under the service lock, one mutating engine call per author
    /// group without it. markViewed first-stamps the selected rows' local
    /// `viewed_at` (§4.77) before any fan-out — the stamp is the request's
    /// own local effect, not a receipt consequence, so it lands even when
    /// the group list is empty and survives an upstream failure. markRead
    /// carries the §4.163 issuance ledger instead: the `read_receipt_sent_at`
    /// stamp lands ONLY after a confirmed fan-out (a failed or unknown send
    /// stamps nothing, so the next deliberate trigger re-supplies the batch),
    /// and on the empty-group path (a group conversation's authors are
    /// unresolvable upstream — those rows will never ride) — best-effort,
    /// never overriding the send's own answer. Zero groups is the trivial
    /// `sent` no-op; the per-author params are exactly the engine contract
    /// `{account, recipient, timestamps}` — recipient is the single author,
    /// timestamps ascend (the engine chunks 100 per envelope).
    ///
    /// §4.119 failure debounce: a failed face records its (account,
    /// conversation, face) key, and another trigger of the same key inside
    /// [`RECEIPT_FAILURE_COOLDOWN`] answers `unknown` before any engine or
    /// store work — the upstream rejection of a conversation's stale
    /// timestamps cannot be replayed at trigger frequency. Nothing is ever
    /// retried: the desktop's next deliberate trigger after the window is a
    /// fresh request (AGENTS.md).
    async fn send_receipt(
        &self,
        account_id: String,
        conversation_id: String,
        message_ids: Option<Vec<String>>,
        read_message_id: Option<String>,
        method: &'static str,
    ) -> Result<&'static str, ServiceError> {
        let failure_key = receipt_failure_key(&account_id, &conversation_id, method);
        if self.receipt_failure_pending(&failure_key, std::time::Instant::now()) {
            return Ok("unknown");
        }
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            let prepared = match method {
                "sendReadReceipt" => service.prepare_mark_read(
                    &account_id,
                    &conversation_id,
                    message_ids,
                    read_message_id.as_deref(),
                )?,
                _ => service.prepare_mark_viewed(&account_id, &conversation_id, message_ids)?,
            };
            if method == "sendViewedReceipt" {
                service.complete_mark_viewed(&prepared)?;
            }
            prepared
        };
        if prepared.groups.is_empty() {
            // The §4.163 ledger still closes the selection on the no-fan-out
            // path: those rows can never ride upstream, so leaving the ledger
            // open would reselect them on every trigger. Best-effort — a
            // store hiccup costs one more reselection, never the answer.
            if method == "sendReadReceipt"
                && let Err(error) = self.service.lock().await.complete_mark_read(&prepared)
            {
                tracing::warn!(
                    error_class = error.class(),
                    "read receipt ledger stamp failed"
                );
            }
            return Ok("sent");
        }
        let mut all_confirmed = true;
        for group in &prepared.groups {
            let params = json!({
                "account": prepared.account_signal,
                "recipient": group.recipient,
                "timestamps": group.timestamps,
            });
            match engine.call(method, params, CallClass::Mutating).await {
                Ok(_) => {}
                // Any failure — definite upstream error, transport trouble,
                // or an unknown outcome — degrades to `unknown` and is never
                // propagated: a receipt is best-effort, and an unknown
                // outcome must not be retried (AGENTS.md).
                Err(_) => all_confirmed = false,
            }
        }
        if !all_confirmed {
            self.note_receipt_failure(&failure_key, std::time::Instant::now());
        } else if method == "sendReadReceipt" {
            // §4.163: the ledger closes on a CONFIRMED fan-out only. A store
            // hiccup here never overrides the send's own answer — the worst
            // case is one more reselection on the next trigger.
            if let Err(error) = self.service.lock().await.complete_mark_read(&prepared) {
                tracing::warn!(
                    error_class = error.class(),
                    "read receipt ledger stamp failed"
                );
            }
        }
        Ok(if all_confirmed { "sent" } else { "unknown" })
    }

    /// The §4.119 debounce verdict for one key: `true` while the key sits
    /// inside its cooldown after a recorded failure; an expired entry is
    /// dropped on the way out.
    fn receipt_failure_pending(&self, key: &str, now: std::time::Instant) -> bool {
        let mut failures = self
            .receipt_failures
            .lock()
            .expect("receipt failures mutex");
        match failures.get(key).copied() {
            Some(failed_at) if now.duration_since(failed_at) < RECEIPT_FAILURE_COOLDOWN => true,
            _ => {
                failures.remove(key);
                false
            }
        }
    }

    /// Records a face failure at `now`, pruning expired entries first and
    /// refusing insertion past the hard cap — the map stays bounded
    /// (AGENTS.md), and a refused insertion only means that conversation
    /// keeps reaching the engine.
    fn note_receipt_failure(&self, key: &str, now: std::time::Instant) {
        let mut failures = self
            .receipt_failures
            .lock()
            .expect("receipt failures mutex");
        failures.retain(|_, failed_at| now.duration_since(*failed_at) < RECEIPT_FAILURE_COOLDOWN);
        if failures.len() >= RECEIPT_FAILURE_MAP_CAP {
            return;
        }
        failures.insert(key.to_string(), now);
    }

    /// Outbound read SELF-SYNC (contract revision 1.108, §4.89): the same
    /// selection and receipt-class answer as `send_read_receipt`, but the
    /// upstream face is the engine's `markRead` — SyncMessage.read to the
    /// account's own devices — not the peer-facing `sendReadReceipt`. The
    /// two channels are independent protocol faces (the official
    /// markConversationRead.preload.ts:252 note); the sync leg is what makes
    /// the account's OTHER devices show the read state, and it is not gated
    /// by the account's readReceipts configuration flag. The prepared group
    /// (direct conversations only, one author) maps to the engine's entry
    /// list `{account, reads: [{sender, timestamp}...]}` — one engine call,
    /// the engine chunking 100 entries per envelope internally.
    pub async fn send_sync_read_receipt(
        &self,
        account_id: String,
        conversation_id: String,
        message_ids: Option<Vec<String>>,
        read_message_id: Option<String>,
    ) -> Result<&'static str, ServiceError> {
        self.send_sync_receipt(
            account_id,
            conversation_id,
            message_ids,
            read_message_id,
            "markRead",
        )
        .await
    }

    /// Outbound viewed SELF-SYNC (contract revision 1.108, §4.89): identical
    /// shape, engine `markViewed` (`{account, viewed: [...]}`), with the
    /// same local `viewed_at` first-stamp discipline as the peer-faced
    /// markViewed.
    pub async fn send_sync_viewed_receipt(
        &self,
        account_id: String,
        conversation_id: String,
        message_ids: Option<Vec<String>>,
    ) -> Result<&'static str, ServiceError> {
        self.send_sync_receipt(
            account_id,
            conversation_id,
            message_ids,
            // The viewed self-sync has no read-position target.
            None,
            "markViewed",
        )
        .await
    }

    /// messages.deleteForMe (contract revision 1.118, §4.99, capability
    /// delete-for-me): the conversation-level delete-for-me upstream leg —
    /// the engine `deleteForMeConversation` face (the official
    /// deleteConversation sync, the full-clear arm and the local-only arm
    /// verbatim). Receipt-class like the sync read/viewed pair: any engine
    /// call failure degrades to `{status: "unknown"}` and is never retried
    /// — the sync message may already ride the self-send lane. Zero local
    /// writes (the §4.89 discipline): the §4.83 receive mirror stays the
    /// inbound channel; this face is the outbound leg only.
    pub async fn delete_for_me(
        &self,
        params: MessagesDeleteForMeParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_messages_delete_for_me(&params)?
        };
        match engine
            .call("deleteForMeConversation", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            // Same receipt-class degradation as the peer-faced fan-out: any
            // failure — including the engine's pre-flight refusal — answers
            // `unknown` and is never retried.
            Err(_) => Ok("unknown"),
        }
    }

    /// messages.deleteForMeMessages (contract revision 1.197, §4.197,
    /// capability delete-for-me): the message-level delete-for-me upstream
    /// leg — the engine `deleteForMeMessages` face (the official
    /// `getDeleteForMeSyncMessage` messageDeletes sender). The connector
    /// resolves the desktop's local row ids into the official
    /// `(author, sentTimestamp)` entries itself (`Service::
    /// prepare_messages_delete_for_me_messages`), so no protocol identity
    /// ever crosses the desktop boundary. Receipt-class like the
    /// conversation-level twin: any engine call failure degrades to
    /// `{status: "unknown"}` and is never retried — the sync message may
    /// already ride the self-send lane. Zero local writes (the §4.83
    /// receive mirror stays the inbound channel).
    pub async fn delete_for_me_messages(
        &self,
        params: MessagesDeleteForMeMessagesParams,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let upstream = {
            let service = self.service.lock().await;
            service.prepare_messages_delete_for_me_messages(&params)?
        };
        match engine
            .call("deleteForMeMessages", upstream, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("sent"),
            // Same receipt-class degradation as the conversation-level face:
            // the sync may already be on the self-send lane.
            Err(_) => Ok("unknown"),
        }
    }

    /// Shared sync read/viewed body: the receipt-class twin of
    /// [`Self::send_receipt`] on the self-sync engine faces. Prepare and the
    /// `viewed_at` first-stamp are byte-identical (the local stamp is the
    /// request's own effect and survives any upstream failure); only the
    /// engine method and params shape differ — `{account, reads|viewed:
    /// [{sender, timestamp}...]}` carries the author inside each entry, so
    /// the whole group rides ONE call (the direct-conversation selection has
    /// exactly one resolvable author). The same aggregation, degradation,
    /// and never-retry discipline applies.
    async fn send_sync_receipt(
        &self,
        account_id: String,
        conversation_id: String,
        message_ids: Option<Vec<String>>,
        read_message_id: Option<String>,
        method: &'static str,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            let prepared = match method {
                "markRead" => service.prepare_sync_read(
                    &account_id,
                    &conversation_id,
                    message_ids,
                    read_message_id.as_deref(),
                )?,
                _ => service.prepare_sync_viewed(&account_id, &conversation_id, message_ids)?,
            };
            if method == "markViewed" {
                service.complete_mark_viewed(&prepared)?;
            }
            prepared
        };
        if prepared.groups.is_empty() {
            return Ok("sent");
        }
        let mut all_confirmed = true;
        for group in &prepared.groups {
            let list_key = if method == "markRead" {
                "reads"
            } else {
                "viewed"
            };
            let entries: Vec<Value> = group
                .timestamps
                .iter()
                .map(|timestamp| json!({ "sender": group.recipient, "timestamp": timestamp }))
                .collect();
            let params = json!({
                "account": prepared.account_signal,
                list_key: entries,
            });
            match engine.call(method, params, CallClass::Mutating).await {
                Ok(_) => {}
                // Same receipt-class discipline as the peer-faced fan-out:
                // any failure degrades to `unknown` and is never retried.
                Err(_) => all_confirmed = false,
            }
        }
        Ok(if all_confirmed { "sent" } else { "unknown" })
    }

    /// messages.edit (contract revision 1.15): retarget one previously sent
    /// message's body via the engine's native `editMessage` wire method
    /// (contract 1.105 migration — the signal-cli-era `send` + `editTimestamp`
    /// call dispatched a brand-new message on the kt-engine, which has no
    /// `editTimestamp` parameter). Local prepare (row resolution, text bounds)
    /// under the service lock, upstream mutating call without it; on confirmed
    /// success the local row is rewritten and the updated record returned
    /// (`Some(record)`); an indeterminate outcome maps to `Ok(None)` with the
    /// local row unchanged — never an automatic retry.
    pub async fn edit_message(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
        text: String,
    ) -> Result<Option<MessageRecord>, ServiceError> {
        let engine = self.running_engine().await?;
        let prepared = {
            let service = self.service.lock().await;
            service.prepare_edit(&account_id, &conversation_id, &message_id, &text)?
        };
        match engine
            .call("editMessage", prepared.params, CallClass::Mutating)
            .await
        {
            Ok(_) => {
                let service = self.service.lock().await;
                Ok(service.complete_edit_success(
                    &prepared.account_id,
                    &prepared.conversation_id,
                    &prepared.message_id,
                    &prepared.text,
                )?)
            }
            Err(EngineError::UnknownOutcome) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Media ingest (ADR 0004, contract revision 1.17): open a chunk stream
    /// for one already-downloaded attachment. Pure local resolution — the
    /// engine is not consulted, the upstream whole-file base64
    /// `getAttachment` read is never used, and a not-downloaded or
    /// governor-deleted file answers UPSTREAM_ERROR exactly as before.
    pub async fn open_media(
        &self,
        params: crate::service::MessagesAttachmentsOpenParams,
    ) -> Result<MediaOpenView, ServiceError> {
        self.service.lock().await.open_media_handle(
            &params.account_id,
            &params.conversation_id,
            &params.message_id,
            &params.attachment_id,
        )
    }

    /// Media ingest: one sequential chunk from a live handle. The handle
    /// table is process-wide, so this answers identically no matter which
    /// group's supervisor the registry routed it through.
    pub async fn read_media_chunk(
        &self,
        media_handle: String,
        offset: u64,
    ) -> Result<MediaChunkView, ServiceError> {
        self.service
            .lock()
            .await
            .read_media_chunk(&media_handle, offset)
    }

    /// Media ingest: explicit early release; idempotent, TTL is the backstop.
    pub async fn close_media_handle(
        &self,
        media_handle: String,
    ) -> Result<MediaCloseView, ServiceError> {
        self.service.lock().await.close_media_handle(&media_handle)
    }

    // ---------------------------------------------------------------------
    // Android local-backup export (contract revision 1.47, §4.46,
    // capability backup-export).
    // ---------------------------------------------------------------------

    fn backup_handles(
        &self,
    ) -> Result<Arc<crate::backup_export::BackupFileHandleTable>, ServiceError> {
        self.backup_handles.clone().ok_or_else(|| {
            ServiceError::Api(ApiError::new(
                "CAPABILITY_UNAVAILABLE",
                "backup export is not enabled for this connector",
                false,
            ))
        })
    }

    /// backups.export: build (or rebuild) the transitional artifact locally,
    /// run the connector's snapshot cleanup, then start the engine's export
    /// task. The artifact build and the snapshot walk are pure filesystem +
    /// store work and run on the blocking pool; the engine call is Mutating,
    /// so an indeterminate outcome answers SEND_OUTCOME_UNKNOWN — the task
    /// may already be writing a snapshot, and restarting it automatically
    /// could race the running one. On any pre-engine failure the artifact is
    /// either absent (never built) or removed by `build_artifact` itself, so
    /// the engine never sees a stale one.
    pub async fn export_local_backup(&self, account_id: &str) -> Result<Value, ServiceError> {
        self.backup_handles()?;
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        let store = Arc::clone(&self.store);
        let data_dir = self.config.data_dir.clone();
        let account = account_id.to_string();
        let counters = tokio::task::spawn_blocking({
            let signal_account = signal_account.clone();
            move || {
                crate::backup_export::build_artifact(&store, &data_dir, &account, &signal_account)
            }
        })
        .await
        .map_err(|_| ServiceError::Store(StoreError::Unavailable(None)))?
        .map_err(ServiceError::from)?;
        let account_dir =
            crate::history_import::engine_account_dir(&self.config.data_dir, &signal_account)
                .ok_or(ServiceError::from(
                    crate::backup_export::BuildError::NoEngineDirectory,
                ))?;
        crate::backup_export::prepare_snapshots_for_export(&account_dir);
        self.backup_counters
            .lock()
            .expect("backup counters mutex")
            .insert(account_id.to_string(), counters);
        let engine = self.running_engine().await?;
        match engine
            .call(
                "backup.export",
                json!({ "account": signal_account }),
                CallClass::Mutating,
            )
            .await
        {
            Ok(value) => {
                if value.get("status").and_then(Value::as_str) == Some("started") {
                    Ok(json!({ "status": "started" }))
                } else {
                    Err(ServiceError::Api(ApiError::new(
                        "UPSTREAM_PROTOCOL_ERROR",
                        "backup.export answered without a started status",
                        true,
                    )))
                }
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "backup.export outcome is unknown; poll backups.exportStatus",
                false,
            ))),
            Err(error) => Err(error.into()),
        }
    }

    /// backups.exportPlaintext (contract revision 1.132, §4.115): build the
    /// plaintext JSONL artifact connector-locally — engine-free (red line 1:
    /// no network request, no engine call; the artifact is a pure store
    /// projection). The start gates share one task slot per account across
    /// the family: a plaintext build already running answers
    /// BACKUP_PLAINTEXT_ALREADY_RUNNING, and an engine export whose status
    /// reads running answers BACKUP_EXPORT_ALREADY_RUNNING — both
    /// retryable=false (poll, never retry). The build runs on the blocking
    /// pool behind a spawned settle-watch; the face answers `started`
    /// immediately and the desktop polls `backups.exportStatus`, where the
    /// additive `kind` field discriminates the family.
    pub async fn export_plaintext(
        self: &Arc<Self>,
        account_id: &str,
    ) -> Result<Value, ServiceError> {
        self.backup_handles()?;
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        // Forward gate against the engine's encrypted export: a read-only
        // poll. An engine that is down, or an indeterminate read, proves no
        // running task — the task registry is engine-process memory (§10.4)
        // — so the build proceeds; only a definite `running` blocks.
        if let Ok(engine) = self.running_engine().await
            && let Ok(status) = engine
                .call(
                    "backup.exportStatus",
                    json!({ "account": signal_account }),
                    CallClass::ReadOnly,
                )
                .await
            && status.get("state").and_then(Value::as_str) == Some("running")
        {
            return Err(ServiceError::Api(ApiError::new(
                "BACKUP_EXPORT_ALREADY_RUNNING",
                "an encrypted backup export is already running for this account; poll backups.exportStatus",
                false,
            )));
        }
        let started_at_ms = crate::link::now_ms();
        if !self.plaintext_tasks.begin(account_id, started_at_ms) {
            return Err(ServiceError::Api(ApiError::new(
                "BACKUP_PLAINTEXT_ALREADY_RUNNING",
                "a plaintext export is already running for this account; poll backups.exportStatus",
                false,
            )));
        }
        let store = Arc::clone(&self.store);
        let account = account_id.to_string();
        let build = tokio::task::spawn_blocking(move || {
            crate::backup_export::build_plaintext_artifact(&store, &account, &signal_account)
        });
        let tasks = Arc::clone(&self.plaintext_tasks);
        let account = account_id.to_string();
        tokio::spawn(async move {
            match build.await {
                Ok(Ok(outcome)) => {
                    tasks.complete(&account, crate::link::now_ms(), &outcome);
                }
                Ok(Err(error)) => {
                    let class = crate::backup_export::plaintext_error_class(&error);
                    tracing::warn!(error_class = class, "plaintext export build failed");
                    tasks.fail(&account, crate::link::now_ms(), class);
                }
                // JoinError: the blocking build panicked — settle the slot so
                // it never sticks `running` (the class is content-free).
                Err(_) => {
                    tasks.fail(
                        &account,
                        crate::link::now_ms(),
                        crate::backup_export::PLAINTEXT_PANIC_ERROR_CLASS,
                    );
                }
            }
        });
        Ok(json!({ "status": "started" }))
    }

    /// backups.exportStatus: poll the engine read-only and project the
    /// answer — the upstream `account` echo is stripped (the raw number never
    /// crosses the host boundary, §4.46), `accountId` rides in its place,
    /// and the connector's own skip counters merge in after a successful
    /// build. Since revision 1.132 (§4.115) the answer carries the additive
    /// `kind` field naming which product family owns the latest task:
    /// `plaintext_jsonl` when the connector-local plaintext task is the
    /// latest started (startedAtMs wins the comparison), `backup` when the
    /// engine's encrypted task does, absent when no task has ever run
    /// (honest absence). Read-only, so an unknown outcome degrades honestly
    /// to the same shape as an idle engine rather than inventing a state.
    pub async fn export_backup_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        self.backup_handles()?;
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        let upstream = match self.running_engine().await {
            Ok(engine) => Some(
                engine
                    .call(
                        "backup.exportStatus",
                        json!({ "account": signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await,
            ),
            // Engine down (or the read raced a crash): the snapshots live on
            // disk — report the store-side projection rather than failing the
            // poll. Read-only, so this is honest, not a guess.
            Err(_) => None,
        };
        let plaintext_task = self.plaintext_tasks.latest(account_id);
        match upstream {
            Some(Ok(result)) => {
                let engine_started_ms = result
                    .get("startedAtMs")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if let Some(task) =
                    plaintext_task.filter(|task| task.started_at_ms >= engine_started_ms)
                {
                    let data_dir = self.config.data_dir.clone();
                    let account = account_id.to_string();
                    return blocking_service(move || {
                        Ok(plaintext_status_projection(
                            &data_dir,
                            &account,
                            &signal_account,
                            task,
                        ))
                    })
                    .await;
                }
                let counters = self
                    .backup_counters
                    .lock()
                    .expect("backup counters mutex")
                    .get(account_id)
                    .copied();
                let mut projected =
                    export_status_projection(account_id, &signal_account, result, counters);
                // The engine's task owns the latest run: name the family
                // unless the engine has never run one (idle = honest
                // absence, §4.115).
                if projected.get("state").and_then(Value::as_str) != Some("idle") {
                    projected["kind"] = json!("backup");
                }
                Ok(projected)
            }
            // Read-only, so an indeterminate outcome degrades to the same
            // disk-truth projection as an engine that is down (§4.46: never
            // invent a task state). A live plaintext task record is the only
            // task memory left on this path and wins the projection.
            Some(Err(EngineError::UnknownOutcome)) | None => {
                let data_dir = self.config.data_dir.clone();
                let account = account_id.to_string();
                blocking_service(move || {
                    Ok(match plaintext_task {
                        Some(task) => {
                            plaintext_status_projection(&data_dir, &account, &signal_account, task)
                        }
                        None => {
                            export_status_idle_projection(&data_dir, &account, &signal_account)?
                        }
                    })
                })
                .await
            }
            Some(Err(error)) => Err(error.into()),
        }
    }

    /// backups.exportFile.open: mint a chunk-stream handle for one fixed file
    /// of the latest export artifact. Pure local resolution — the engine is
    /// not consulted. `metadata`/`main` address the newest encrypted snapshot
    /// directory (its name is the newest one on disk, the same rule the
    /// engine's exportStatus list applies); `plaintext_jsonl` (revision
    /// 1.132, §4.115) addresses the newest plaintext artifact in the
    /// connector's state dir.
    pub async fn export_file_open(
        &self,
        account_id: &str,
        file: &str,
    ) -> Result<Value, ServiceError> {
        let handles = self.backup_handles()?;
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        let store = Arc::clone(&self.store);
        let data_dir = self.config.data_dir.clone();
        let account = account_id.to_string();
        let file = file.to_string();
        blocking_service(move || {
            // The enum gate runs before any filesystem touch; each arm then
            // resolves its own family's latest artifact lazily — a plaintext
            // export never requires an encrypted snapshot to exist, and vice
            // versa.
            let path = match file.as_str() {
                "metadata" | "main" => {
                    let snapshot =
                        export_latest_snapshot(&store, &data_dir, &account, &signal_account)?;
                    snapshot.join(file.as_str())
                }
                // §4.115 (revision 1.132): the additive third enum value
                // addresses the newest plaintext artifact in the connector's
                // state dir — the three-chain mechanics are untouched.
                "plaintext_jsonl" => crate::backup_export::latest_plaintext_artifact(
                    &crate::backup_export::plaintext_export_root(store.state_dir(), &account),
                )
                .ok_or_else(|| {
                    ServiceError::Api(ApiError::new(
                        "BACKUP_SNAPSHOT_MISSING",
                        "the account has no plaintext export artifact yet",
                        false,
                    ))
                })?,
                _ => {
                    return Err(ServiceError::Api(ApiError::new(
                        "INVALID_REQUEST",
                        "file must be \"metadata\", \"main\", or \"plaintext_jsonl\"",
                        false,
                    )));
                }
            };
            let size_bytes = std::fs::metadata(&path)
                .map(|metadata| metadata.len())
                .map_err(|_| {
                    ServiceError::Api(ApiError::new(
                        "BACKUP_SNAPSHOT_MISSING",
                        "the snapshot file is not on disk",
                        false,
                    ))
                })?;
            let file_handle = handles
                .open(&account, path, size_bytes)
                .map_err(map_backup_handle_error)?;
            Ok(json!({
                "fileHandle": file_handle,
                "sizeBytes": size_bytes,
                "chunkBytes": crate::backup_export::CHUNK_BYTES,
            }))
        })
        .await
    }

    /// backups.exportFile.readChunk: one sequential chunk from a live handle.
    /// The handle table is process-wide, so this answers identically no
    /// matter which group's supervisor the registry routed it through.
    pub async fn export_file_read_chunk(
        &self,
        file_handle: &str,
        offset: u64,
    ) -> Result<Value, ServiceError> {
        let handles = self.backup_handles()?;
        crate::service::validate_backup_handle(file_handle)?;
        let chunk = handles
            .read_chunk(file_handle, offset)
            .map_err(map_backup_handle_error)?;
        Ok(json!({
            "dataBase64": crate::backup_export::encode_chunk(&chunk.data),
            "sizeBytes": chunk.data.len() as u64,
            "eof": chunk.eof,
        }))
    }

    /// backups.exportFile.closeHandle: explicit early release; idempotent,
    /// TTL is the backstop.
    pub async fn export_file_close_handle(&self, file_handle: &str) -> Result<Value, ServiceError> {
        self.backup_handles()?;
        crate::service::validate_backup_handle(file_handle)?;
        let handles = self.backup_handles()?;
        Ok(json!({
            "released": handles.close(file_handle),
        }))
    }

    /// backups.importSnapshot (contract revision 1.78, §4.68): forward the
    /// caller-chosen official snapshot directory to the engine's import task,
    /// then arm the consumption watcher. The account resolution rides the
    /// §4.38 faces (capability `history-import` — no new bit); the Mutating
    /// engine call answers SEND_OUTCOME_UNKNOWN on
    /// an indeterminate outcome and never retries — the watcher still spawns so
    /// an import that actually started is observed to its terminal state.
    pub async fn import_local_snapshot(
        self: &Arc<Self>,
        account_id: &str,
        snapshot_dir: &str,
    ) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_import_snapshot(account_id, snapshot_dir)?
        };
        let engine = self.running_engine().await?;
        match engine
            .call("backup.importSnapshot", params, CallClass::Mutating)
            .await
        {
            Ok(value) => {
                if value.get("status").and_then(Value::as_str) == Some("started") {
                    self.spawn_import_snapshot_watcher(account_id);
                    Ok(json!({ "status": "started" }))
                } else {
                    Err(ServiceError::Api(ApiError::new(
                        "UPSTREAM_PROTOCOL_ERROR",
                        "backup.importSnapshot answered without a started status",
                        true,
                    )))
                }
            }
            Err(EngineError::UnknownOutcome) => {
                self.spawn_import_snapshot_watcher(account_id);
                Err(ServiceError::Api(ApiError::new(
                    "SEND_OUTCOME_UNKNOWN",
                    "backup.importSnapshot outcome is unknown; poll backups.importSnapshotStatus",
                    false,
                )))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// backups.importSnapshotStatus (contract revision 1.78, §4.68): poll the
    /// engine read-only and project the answer — the upstream `account` echo
    /// is stripped and `accountId` rides in its place (the §4.46 precedent).
    /// Read-only, so an engine that is down or an indeterminate read degrades
    /// to the disk-truth idle projection rather than inventing a task state.
    /// The face has no store fallback, its whole truth is the engine's import
    /// task.
    pub async fn import_snapshot_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        let upstream = match self.running_engine().await {
            Ok(engine) => Some(
                engine
                    .call(
                        "backup.importSnapshotStatus",
                        json!({ "account": signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await,
            ),
            // Engine down (or the read raced a crash): the produced NDJSON
            // lives on disk — report the disk-truth projection rather than
            // failing the poll. Read-only, so this is honest, not a guess.
            Err(_) => None,
        };
        match upstream {
            Some(Ok(result)) => Ok(import_snapshot_status_from_engine(account_id, result)),
            Some(Err(EngineError::UnknownOutcome)) | None => {
                let data_dir = self.config.data_dir.clone();
                let account = account_id.to_string();
                blocking_service(move || {
                    Ok(import_snapshot_status_idle_projection(
                        &data_dir,
                        &account,
                        &signal_account,
                    ))
                })
                .await
            }
            Some(Err(error)) => Err(error.into()),
        }
    }

    /// backups.restoreFromCloud (contract revision 1.83, §4.69): forward the
    /// cloud-restore start to the engine — the account resolution rides the
    /// §4.68 ladder (capability `history-import` — no new bit), and the
    /// engine runs the whole chain
    /// (credentials 404-bootstrap → zkgroup → chat gRPC → CDN → decrypt →
    /// NDJSON) in its own background. The Mutating engine call answers
    /// SEND_OUTCOME_UNKNOWN on an indeterminate outcome and never retries —
    /// the terminal state is observed through `backups.cloudStatus` (the
    /// engine keeps the failed phase until the next start overwrites). On a
    /// definite start — and on an unknown outcome, which may actually have
    /// started — the consumption watcher spawns (contract revision 1.84,
    /// [`Self::spawn_cloud_restore_watcher`]): the produced
    /// `history-import-cloud.ndjson` is driven through the §4.38 import pass
    /// and rendered through `history.importStatus`.
    pub async fn restore_from_cloud(
        self: &Arc<Self>,
        account_id: &str,
    ) -> Result<Value, ServiceError> {
        let params = {
            let service = self.service.lock().await;
            service.prepare_cloud_restore_account(account_id)?
        };
        let engine = self.running_engine().await?;
        match engine
            .call("backups.restoreFromCloud", params, CallClass::Mutating)
            .await
        {
            Ok(value) => {
                if value.get("status").and_then(Value::as_str) == Some("started") {
                    self.spawn_cloud_restore_watcher(account_id);
                    Ok(json!({ "status": "started" }))
                } else {
                    Err(ServiceError::Api(ApiError::new(
                        "UPSTREAM_PROTOCOL_ERROR",
                        "backups.restoreFromCloud answered without a started status",
                        true,
                    )))
                }
            }
            Err(EngineError::UnknownOutcome) => {
                // The start may actually have taken: the watcher still spawns
                // so a restore that is running is observed to its terminal
                // state (the §4.68 unknown-outcome posture).
                self.spawn_cloud_restore_watcher(account_id);
                Err(ServiceError::Api(ApiError::new(
                    "SEND_OUTCOME_UNKNOWN",
                    "backups.restoreFromCloud outcome is unknown; poll backups.cloudStatus",
                    false,
                )))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// backups.cloudStatus (contract revision 1.83, §4.69): poll the engine's
    /// cloud-restore progress snapshot read-only and mirror it. The snapshot
    /// is engine-process memory (the transfer.downloadStatus discipline), so
    /// an engine that is down or an indeterminate read answers
    /// `{present: false}` — "not observable" is exactly the post-restart
    /// truth, not an invented state. The face has no store fallback, its
    /// whole truth is the engine's restore task.
    pub async fn cloud_backup_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        let upstream = match self.running_engine().await {
            Ok(engine) => Some(
                engine
                    .call(
                        "backups.cloudStatus",
                        json!({ "account": signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await,
            ),
            Err(_) => None,
        };
        match upstream {
            Some(Ok(result)) => cloud_status_from_engine(&result),
            // Read-only: an indeterminate read degrades to the same
            // not-observable answer as a down engine (never a guessed state).
            Some(Err(EngineError::UnknownOutcome)) | None => Ok(json!({ "present": false })),
            Some(Err(error)) => Err(error.into()),
        }
    }

    /// backups.uploadToCloud (contract revision 1.87, §4.72, engine
    /// cloud-backup-contract §6.2/§6.3): the outbound half of cloud backup.
    /// The connector's own chain stage comes first — (re)build the §10.2
    /// transitional artifact (`backup-export-input.ndjson`) in the engine's
    /// per-account data directory with the §4.46 machine verbatim
    /// (write-once, rebuilt before every attempt; a failed build removes
    /// the partial file, so the engine never sees a stale one; the
    /// engine's start gate answers BACKUP_ARTIFACT_MISSING only when this
    /// build never landed) — then the start forwards to the engine, whose
    /// whole chain (assembly thread → credentials with the 404 bootstrap
    /// self-heal → zkgroup → form gRPC → cdn3 TUS single POST →
    /// refresh_backup) runs in its own background. The Mutating engine
    /// call answers SEND_OUTCOME_UNKNOWN on an indeterminate outcome and
    /// never retries — the terminal state is observed through
    /// `backups.uploadStatus` (the engine keeps the failed phase until the
    /// next start overwrites; a retry is the caller's fresh
    /// backups.uploadToCloud — a new form, a new artifact). The
    /// eight-family structured error ladder maps through
    /// `cloud_upload_face_error`: the engine's `CloudUploadError::rpc_code`
    /// single mapping source, with the two per-face divergences (the
    /// transport family's upload text, BACKUP_IO_FAILED retryable=false +
    /// detail) reasserted over the global mapping. Deliberately no
    /// consumption watcher (the upload produces nothing local — a success
    /// leaves no trace), no snapshot caretaker and no skip-counter merge
    /// (both are the export face's own: the upload creates no snapshot and
    /// has no status face to merge counters into).
    pub async fn upload_to_cloud(&self, account_id: &str) -> Result<Value, ServiceError> {
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_cloud_upload_account(account_id)?
        };
        let store = Arc::clone(&self.store);
        let data_dir = self.config.data_dir.clone();
        let account = account_id.to_string();
        tokio::task::spawn_blocking({
            let signal_account = signal_account.clone();
            move || {
                crate::backup_export::build_artifact(&store, &data_dir, &account, &signal_account)
            }
        })
        .await
        .map_err(|_| ServiceError::Store(StoreError::Unavailable(None)))?
        .map_err(ServiceError::from)?;
        let engine = self.running_engine().await?;
        match engine
            .call(
                "backups.uploadToCloud",
                json!({ "account": signal_account }),
                CallClass::Mutating,
            )
            .await
        {
            Ok(value) => {
                if value.get("status").and_then(Value::as_str) == Some("started") {
                    Ok(json!({ "status": "started" }))
                } else {
                    Err(ServiceError::Api(ApiError::new(
                        "UPSTREAM_PROTOCOL_ERROR",
                        "backups.uploadToCloud answered without a started status",
                        true,
                    )))
                }
            }
            Err(EngineError::UnknownOutcome) => Err(ServiceError::Api(ApiError::new(
                "SEND_OUTCOME_UNKNOWN",
                "backups.uploadToCloud outcome is unknown; poll backups.uploadStatus",
                false,
            ))),
            Err(EngineError::UpstreamCode { code, data }) => Err(ServiceError::Api(
                crate::service::cloud_upload_face_error(code, data),
            )),
            Err(error) => Err(error.into()),
        }
    }

    /// backups.uploadStatus (contract revision 1.87, §4.72, engine
    /// cloud-backup-contract §6.2): poll the engine's cloud-upload progress
    /// snapshot read-only and mirror it — the `cloud_backup_status`
    /// discipline verbatim. The snapshot is engine-process memory (a
    /// process-wide single slot), so an engine that is down or an
    /// indeterminate read answers `{present: false}` — "not observable" is
    /// exactly the post-restart truth, not an invented state. The mode
    /// gate sits first (the §4.69 status-face precedent): the face has no
    /// store fallback, its whole truth is the engine's upload task.
    pub async fn cloud_upload_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let signal_account = {
            let service = self.service.lock().await;
            service.prepare_backups_account(account_id)?
        };
        let upstream = match self.running_engine().await {
            Ok(engine) => Some(
                engine
                    .call(
                        "backups.uploadStatus",
                        json!({ "account": signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await,
            ),
            Err(_) => None,
        };
        match upstream {
            Some(Ok(result)) => upload_status_from_engine(&result),
            // Read-only: an indeterminate read degrades to the same
            // not-observable answer as a down engine (never a guessed state).
            Some(Err(EngineError::UnknownOutcome)) | None => Ok(json!({ "present": false })),
            Some(Err(error)) => Err(error.into()),
        }
    }

    /// The §4.68 consumption watcher: poll the engine's import status (~3 s,
    /// 30-minute ceiling) and on a terminal state drive the §4.38 import pass
    /// directly — `completed` constructs the job immediately (bypassing the
    /// link-time probe's completed/attempts gates on purpose: this is an
    /// explicit user request, not a link-time sweep) under the group's
    /// single-flight slot; `failed` or the expired-idle escape lands an honest
    /// failed ledger row with the engine class. `history.importRetry` then
    /// answers NO_ARCHIVE for that row — retry is re-invoking
    /// backups.importSnapshot, the official Retry semantics.
    fn spawn_import_snapshot_watcher(self: &Arc<Self>, account_id: &str) {
        let supervisor = Arc::clone(self);
        let account = account_id.to_string();
        tokio::spawn(async move {
            let started = Instant::now();
            // `completed` observed but the group slot busy: keep polling while
            // the engine still reports it (its task registry is process
            // memory) so a link-time pass holding the slot only delays the
            // claim, never fakes a failure.
            let mut completed_seen = false;
            loop {
                if started.elapsed() >= IMPORT_SNAPSHOT_CEILING {
                    if !completed_seen {
                        land_import_engine_failure(&supervisor.store, &account);
                    }
                    tracing::warn!(
                        account_id = %account,
                        "snapshot import watcher hit its ceiling"
                    );
                    return;
                }
                sleep(IMPORT_SNAPSHOT_POLL).await;
                // A deleted account has no ledger row to land and nothing
                // left to observe — exit quietly.
                let signal_account = match supervisor
                    .service
                    .lock()
                    .await
                    .prepare_backups_account(&account)
                {
                    Ok(number) => number,
                    Err(_) => return,
                };
                let engine = match supervisor.running_engine().await {
                    Ok(engine) => engine,
                    // The task registry is engine-process memory: a down
                    // engine keeps polling within the ceiling in case the
                    // process restarts around it.
                    Err(_) => continue,
                };
                let status = engine
                    .call(
                        "backup.importSnapshotStatus",
                        json!({ "account": signal_account }),
                        CallClass::ReadOnly,
                    )
                    .await;
                match status {
                    Ok(status) => match status.get("state").and_then(Value::as_str) {
                        Some("running") => continue,
                        Some("completed") => {
                            completed_seen = true;
                            let Some(archive) = crate::history_import::archive_path(
                                &supervisor.config.data_dir,
                                &signal_account,
                            ) else {
                                land_import_engine_failure(&supervisor.store, &account);
                                return;
                            };
                            let claimed = claim_and_run_history_import(
                                Arc::clone(&supervisor.history_import_running),
                                Arc::clone(&supervisor.history_import_holder),
                                Arc::clone(&supervisor.history_import_abort),
                                Arc::clone(&supervisor.store),
                                HistoryImportJob {
                                    account_id: account.clone(),
                                    signal_account,
                                    archive,
                                },
                            )
                            .await;
                            if claimed {
                                return;
                            }
                            // Slot busy: the next tick retries while the
                            // engine still reports completed.
                        }
                        Some("failed") => {
                            land_import_engine_failure(&supervisor.store, &account);
                            return;
                        }
                        // Expired-idle escape: the engine restarted and its
                        // task registry lost the run — the import is gone.
                        _ => {
                            land_import_engine_failure(&supervisor.store, &account);
                            return;
                        }
                    },
                    // Read-only: every error flavor reads as "not yet
                    // terminal" — keep polling within the ceiling.
                    Err(_) => continue,
                }
            }
        });
    }

    /// The §4.69 consumption watcher (contract revision 1.84): follow a
    /// started cloud restore and drive the produced
    /// `history-import-cloud.ndjson` through the §4.38 import pass — the
    /// §4.68 watcher pattern on the cloud artifact. The engine's progress
    /// snapshot cannot certify success (`{present: false}` is the same
    /// answer a never-started or restarted engine gives — a success leaves
    /// no trace), so the completion face is the artifact's disk freshness
    /// face: the `(mtime, len)` identity captured at spawn, and only a face
    /// that CHANGES during the watch is the engine's fresh write — a stale
    /// archive from a previous restore is never imported. `cloudStatus`
    /// rides the loop for the failure face (`phase: "failed"`, the
    /// engine's terminal snapshot), with the §4.68 cadence bounding the
    /// watch: ~3 s polls, a 60-minute ceiling (the watched chain includes
    /// the whole CDN download). The artifact-face check precedes the status
    /// check each tick — the engine writes the file strictly before an
    /// export failure maps onto the failed phase, so a landed artifact is
    /// consumed before a late failure observation could clobber a completed
    /// ledger row.
    fn spawn_cloud_restore_watcher(self: &Arc<Self>, account_id: &str) {
        let supervisor = Arc::clone(self);
        let account = account_id.to_string();
        tokio::spawn(async move {
            let started = Instant::now();
            // The freshness baseline, captured before the first sleep: the
            // restore chain cannot have landed its artifact in the moments
            // between the started answer and here, so this face is exactly
            // the stale world the fresh write must differ from. An
            // unresolvable account or a missing registry entry exits
            // quietly — no ledger row was ever claimed, no face promised an
            // import.
            let Ok(signal_account) = supervisor
                .service
                .lock()
                .await
                .prepare_backups_account(&account)
            else {
                return;
            };
            let Some(archive) = crate::history_import::cloud_archive_path(
                &supervisor.config.data_dir,
                &signal_account,
            ) else {
                tracing::warn!(
                    account_id = %account,
                    "cloud restore watcher found no engine registry entry"
                );
                return;
            };
            let baseline = cloud_archive_face(&archive);
            // A fresh face observed while the group slot is busy: keep
            // polling while it persists (the §4.68 completed-seen posture),
            // so a link-time pass holding the slot only delays the claim,
            // never fakes a failure — and never lands one at the ceiling
            // either.
            let mut fresh_seen = false;
            loop {
                if started.elapsed() >= CLOUD_RESTORE_CEILING {
                    // Last-chance disk check: a slow restore whose artifact
                    // landed between ticks still consumes.
                    let landed = if cloud_archive_face(&archive) != baseline
                        && crate::history_import::archive_ready(&archive)
                    {
                        claim_and_run_history_import(
                            Arc::clone(&supervisor.history_import_running),
                            Arc::clone(&supervisor.history_import_holder),
                            Arc::clone(&supervisor.history_import_abort),
                            Arc::clone(&supervisor.store),
                            HistoryImportJob {
                                account_id: account.clone(),
                                signal_account: signal_account.clone(),
                                archive: archive.clone(),
                            },
                        )
                        .await
                    } else {
                        false
                    };
                    if !landed && !fresh_seen {
                        land_import_engine_failure(&supervisor.store, &account);
                    }
                    tracing::warn!(
                        account_id = %account,
                        "cloud restore watcher hit its ceiling"
                    );
                    return;
                }
                sleep(CLOUD_RESTORE_POLL).await;
                // A deleted account has no ledger row to land and nothing
                // left to observe — exit quietly (the §4.68 posture).
                if supervisor
                    .service
                    .lock()
                    .await
                    .prepare_backups_account(&account)
                    .is_err()
                {
                    return;
                }
                // ① The artifact face first: a face off the baseline is the
                // engine's definite success signal.
                if cloud_archive_face(&archive) != baseline {
                    if !crate::history_import::archive_ready(&archive) {
                        // Present but empty: not a produced archive (the
                        // §4.38 ready discipline). Keep watching.
                        continue;
                    }
                    fresh_seen = true;
                    let claimed = claim_and_run_history_import(
                        Arc::clone(&supervisor.history_import_running),
                        Arc::clone(&supervisor.history_import_holder),
                        Arc::clone(&supervisor.history_import_abort),
                        Arc::clone(&supervisor.store),
                        HistoryImportJob {
                            account_id: account.clone(),
                            signal_account: signal_account.clone(),
                            archive: archive.clone(),
                        },
                    )
                    .await;
                    if claimed {
                        return;
                    }
                    // Slot busy: the next tick retries while the fresh face
                    // persists.
                    continue;
                }
                // ② The failure face: a failed phase is the engine's
                // terminal snapshot (it persists until the next start) —
                // land the honest failed ledger row and stop; retry is
                // re-invoking backups.restoreFromCloud, so
                // `history.importRetry` answers NO_ARCHIVE (the §4.68
                // official-Retry semantics). Every other answer —
                // downloading, present:false, a down engine, an unknown
                // read — is "not yet terminal": keep polling within the
                // ceiling.
                let engine = match supervisor.running_engine().await {
                    Ok(engine) => engine,
                    Err(_) => continue,
                };
                let status = engine
                    .call(
                        "backups.cloudStatus",
                        json!({ "account": signal_account.clone() }),
                        CallClass::ReadOnly,
                    )
                    .await;
                if let Ok(status) = status
                    && status.get("phase").and_then(Value::as_str) == Some("failed")
                {
                    land_import_engine_failure(&supervisor.store, &account);
                    return;
                }
            }
        });
    }

    /// Read-only view of the contacts cache; never triggers an upstream call.
    pub async fn list_contacts(
        &self,
        account_id: String,
        query: Option<String>,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<Page<ContactSummary>, ServiceError> {
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            store_list_contacts(
                &store,
                &account_id,
                query.as_deref(),
                limit,
                cursor.as_deref(),
            )
        })
        .await
    }

    /// contacts.setLocalAlias (contract revision 1.10, implementation-plan
    /// §4.9): rename one contact via the mutating upstream `updateContact`.
    /// The alias lives in upstream account data — no local row is written and
    /// no event is emitted; the next contacts.sync brings the new name into
    /// the cache. An indeterminate mutating outcome answers "unknown" and is
    /// never retried automatically.
    pub async fn set_local_alias(
        &self,
        account_id: String,
        peer_key: String,
        alias: String,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let params = {
            let service = self.service.lock().await;
            service.prepare_set_local_alias(&account_id, &peer_key, &alias)?
        };
        match engine
            .call("updateContact", params, CallClass::Mutating)
            .await
        {
            Ok(_) => Ok("updated"),
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// presence.setTypingMessage (contract revision 1.11, implementation-plan
    /// §4.10): fire a typing indicator via the mutating upstream `sendTyping`.
    /// The indicator is ephemeral upstream state — no local row is written and
    /// no event is emitted. An indeterminate mutating outcome answers
    /// "unknown" and is never retried automatically.
    pub async fn set_typing_message(
        &self,
        account_id: String,
        conversation_id: String,
        stop: bool,
    ) -> Result<&'static str, ServiceError> {
        let engine = self.running_engine().await?;
        let params = {
            let service = self.service.lock().await;
            service.prepare_set_typing_message(&account_id, &conversation_id, stop)?
        };
        match engine.call("sendTyping", params, CallClass::Mutating).await {
            Ok(_) => Ok("sent"),
            Err(EngineError::UnknownOutcome) => Ok("unknown"),
            Err(error) => Err(error.into()),
        }
    }

    /// Read-only projection of one group (§4.8): the cached contacts row plus
    /// — contract revision 1.62, §4.53 appendix — the group's live
    /// requesting-members list. The requesting list is deliberately NOT a
    /// sync-captured cache field: the §4.53 fold treats the engine's own
    /// single-group `listGroups` read as the approval truth source (the
    /// candidate set is intersected against it at write time), and the read
    /// face consumes the same source so the list the desktop renders and the
    /// set the approval write folds against can never disagree — a sync
    /// snapshot would be a second, older truth that the write's own
    /// `JOIN_REQUEST_NO_LONGER_PENDING` stale-ladder exists to paper over.
    /// Freshness follows the read call itself (as fresh as opening the group
    /// info page, the official render rhythm), which also lets the desktop's
    /// post-action refresh observe the converged list without waiting for a
    /// contacts.sync (the sync path cannot carry this face: its 60s
    /// short-circuit would keep answering the pre-approval roster). The read
    /// degrades honestly: an engine that is not running, or a `listGroups`
    /// face without the requesting array, answers the cached row without the
    /// key (the desktop renders no approval section) — the cache face the
    /// method has always promised stays intact.
    /// Contract 1.181 (§4.181): the store-only groups-in-common read —
    /// no engine call, no resync (the panel answer derives from the cached
    /// rosters exactly like the official local derivation; staleness is the
    /// regular contacts sync's business, `syncedAt` on each group read the
    /// host's signal).
    pub async fn groups_common(
        &self,
        account_id: String,
        conversation_id: String,
    ) -> Result<CommonGroupsDetails, ServiceError> {
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        blocking_service(move || {
            crate::service::store_groups_common(&store, &account_id, &conversation_id)
        })
        .await
    }

    pub async fn get_group(
        &self,
        account_id: String,
        group_key: String,
    ) -> Result<GroupDetails, ServiceError> {
        // The live halves first (ReadOnly, the §4.53/§4.57 folds' own read):
        // failure degrades to no live keys instead of failing the cached
        // read.
        let requesting = self
            .requesting_members_for_group(&account_id, &group_key)
            .await
            .unwrap_or_default();
        let pending = self
            .pending_members_for_group(&account_id, &group_key)
            .await
            .unwrap_or_default();
        // Store-only read: the service lock guards in-memory state only.
        let store = Arc::clone(&self.store);
        let account = account_id.clone();
        let group = group_key.clone();
        let cached = blocking_service(move || {
            store_get_group_with_requesting(
                &store,
                &account,
                &group,
                requesting.as_deref(),
                pending.as_deref(),
            )
        })
        .await;
        // §4.167: a cache miss or an empty roster triggers the throttled
        // single-group resync — the official lazy group update, with the
        // conversation open itself as the trigger. A terminated row (the
        // §4.50 appendix face, which the definitive-negative arm writes)
        // never re-pulls, and every other answer answers exactly the
        // pre-1.167 read.
        let needs_resync = match &cached {
            Err(ServiceError::Api(api)) if api.code == "GROUP_NOT_FOUND" => true,
            Err(_) => false,
            Ok(details) => {
                !details.is_terminated && details.member_count.is_none_or(|count| count == 0)
            }
        };
        // 【临时诊断探针 · 名册链路】台账 §29.23：groups.get 读形状 +
        // 重同步决策，验证「名册缺席」断点（A 没触发 / B 引擎没回 / C 回填丢）。
        tracing::warn!(
            target: "kt_signal_connector::groupdiag",
            stage = "groups_get_read",
            has_member_count = cached
                .as_ref()
                .map(|details| details.member_count.is_some())
                .unwrap_or(false),
            members_len = cached
                .as_ref()
                .ok()
                .and_then(|details| details.members.as_ref())
                .map(|members| members.len())
                .unwrap_or(0),
            is_group_not_found = matches!(&cached, Err(ServiceError::Api(api)) if api.code == "GROUP_NOT_FOUND"),
            needs_resync,
            "groups.get cached read shape and resync decision"
        );
        if !needs_resync {
            return cached;
        }
        self.get_group_with_resync(&account_id, &group_key, cached)
            .await
    }

    /// §4.167: the throttled single-group resync behind a `groups.get` cache
    /// miss or an empty roster. Official anchor (behavior alignment, zero
    /// code copied): `waitThenMaybeUpdateGroup` (`groups.preload.ts:3058-3101`)
    /// — the conversation open triggers one group fetch under a five-minute
    /// TTL; a failed fetch clears the stamp so the next open retries
    /// immediately (`:3074-3094`); a definitive nonexistent answer folds to
    /// left semantics (`:3772-3777`), which this face records as the §4.50
    /// appendix terminated bit (the connector has no left face; the
    /// terminated presentation disables the composer the same way). Success
    /// backfills the cache row through the passive upsert — the account-wide
    /// sync marker deliberately untouched — and replays the original read;
    /// every failure answers the incoming cache face unchanged.
    async fn get_group_with_resync(
        &self,
        account_id: &str,
        group_key: &str,
        cached: Result<GroupDetails, ServiceError>,
    ) -> Result<GroupDetails, ServiceError> {
        let now_ms = crate::link::now_ms();
        if self.group_resync_throttled(account_id, group_key, now_ms) {
            tracing::warn!(
                target: "kt_signal_connector::groupdiag",
                stage = "group_resync_throttled",
                "group resync suppressed by 5min TTL"
            );
            return cached;
        }
        tracing::warn!(
            target: "kt_signal_connector::groupdiag",
            stage = "group_resync_attempt",
            "group resync calling engine listGroups"
        );
        if !self.note_group_resync_attempt(account_id, group_key, now_ms) {
            return cached;
        }
        match self.refresh_group_from_engine(account_id, group_key).await {
            Ok(GroupResync::Refreshed {
                requesting,
                pending,
            }) => {
                tracing::warn!(
                    target: "kt_signal_connector::groupdiag",
                    stage = "group_resync_refreshed",
                    "engine returned the group; replaying backfilled read"
                );
                let store = Arc::clone(&self.store);
                let account = account_id.to_string();
                let group = group_key.to_string();
                blocking_service(move || {
                    store_get_group_with_requesting(
                        &store,
                        &account,
                        &group,
                        requesting.as_deref(),
                        pending.as_deref(),
                    )
                })
                .await
            }
            Ok(GroupResync::Gone) => {
                if self.mark_group_terminated(account_id, group_key).await? {
                    let store = Arc::clone(&self.store);
                    let account = account_id.to_string();
                    let group = group_key.to_string();
                    blocking_service(move || {
                        store_get_group_with_requesting(&store, &account, &group, None, None)
                    })
                    .await
                } else {
                    cached
                }
            }
            // The engine is not ready or refused the read — never a group
            // negative. The stamp clears (official :3094) so the next open
            // retries immediately, and the cache face above answers byte for
            // byte (the boot-window degrade keeps its exact shape).
            Err(_) => {
                self.clear_group_resync_stamp(account_id, group_key);
                cached
            }
        }
    }

    /// §4.167 throttle read: a successful refresh inside
    /// [`GROUP_RESYNC_TTL_MS`] suppresses the next trigger — the official
    /// `isMoreRecentThan(lastSuccessfulGroupFetch, FIVE_MINUTES)` gate.
    fn group_resync_throttled(&self, account_id: &str, group_key: &str, now_ms: u64) -> bool {
        let stamps = self
            .group_resync_stamps
            .lock()
            .expect("group resync stamps mutex");
        stamps
            .get(&(account_id.to_string(), group_key.to_string()))
            .is_some_and(|stamp| now_ms.saturating_sub(*stamp) < GROUP_RESYNC_TTL_MS)
    }

    /// §4.167 throttle write: prune expired stamps, then record — bounded by
    /// [`GROUP_RESYNC_MAP_CAP`] (AGENTS.md bounded-maps rule); a refused
    /// insertion only means that group keeps reaching the engine (the
    /// receipt debounce's cap direction).
    fn note_group_resync_attempt(&self, account_id: &str, group_key: &str, now_ms: u64) -> bool {
        let mut stamps = self
            .group_resync_stamps
            .lock()
            .expect("group resync stamps mutex");
        stamps.retain(|_, stamp| now_ms.saturating_sub(*stamp) < GROUP_RESYNC_TTL_MS);
        let key = (account_id.to_string(), group_key.to_string());
        if stamps.len() >= GROUP_RESYNC_MAP_CAP && !stamps.contains_key(&key) {
            return false;
        }
        stamps.insert(key, now_ms);
        true
    }

    /// §4.167 failure stamp clear (official `setLastSuccessfulGroupFetch(id,
    /// undefined)`, groups.preload.ts:3094): a failed refresh never
    /// suppresses the next trigger.
    fn clear_group_resync_stamp(&self, account_id: &str, group_key: &str) {
        let mut stamps = self
            .group_resync_stamps
            .lock()
            .expect("group resync stamps mutex");
        stamps.remove(&(account_id.to_string(), group_key.to_string()));
    }

    /// §4.167 definitive-negative stamp: record the §4.50 appendix
    /// terminated face on the group's cache row so the replayed read (and
    /// every later read) carries `isTerminated`, and the resync gate never
    /// re-pulls a terminated row. The conversation must already exist — the
    /// official fold marks the user's existing conversation left; a key no
    /// conversation answers materializes nothing. Returns whether the stamp
    /// was written.
    async fn mark_group_terminated(
        &self,
        account_id: &str,
        group_key: &str,
    ) -> Result<bool, ServiceError> {
        let store = Arc::clone(&self.store);
        let account = account_id.to_string();
        let group = group_key.to_string();
        let title = blocking_service(move || -> Result<Option<String>, ServiceError> {
            // Peer-key addressing, the same ladder groups.get itself uses:
            // the conversation id is the derived stable hash, never the raw
            // key.
            let Some(row) = store.conversation_by_peer(&account, "group", &group)? else {
                return Ok(None);
            };
            store
                .conversation_title(&row.id)
                .map_err(ServiceError::Store)
        })
        .await?;
        let Some(title) = title else {
            return Ok(false);
        };
        let changed = blocking_service({
            let store = Arc::clone(&self.store);
            let account = account_id.to_string();
            let group = group_key.to_string();
            move || {
                let entries = [SyncedContact {
                    kind: "group",
                    peer_key: group.as_str(),
                    title: title.as_str(),
                    // Contract 1.255 (§4.240): the Gone stamp now also
                    // carries the member word — the §4.167 definitive
                    // negative folds to left semantics officially
                    // (groups.preload.ts:3772-3777), so the row reads as
                    // removed at the notification stage while the legacy
                    // isTerminated face stays byte-identical for pre-1.255
                    // consumers (the additive capture discipline).
                    extra: Some(r#"{"isTerminated":true,"isMember":false}"#),
                }];
                store
                    .upsert_passive_contacts(&account, &entries, crate::link::now_ms())
                    .map_err(ServiceError::Store)
            }
        })
        .await?;
        self.emit_passive_changes(account_id, changed).await?;
        Ok(true)
    }

    /// §4.135 semantics for one passive upsert's change set: one
    /// `conversation.changed` per newly materialized skeleton or upgraded
    /// title, summaries read after the commit, replay-silent by
    /// construction.
    async fn emit_passive_changes(
        &self,
        account_id: &str,
        changed: Vec<String>,
    ) -> Result<(), ServiceError> {
        if changed.is_empty() {
            return Ok(());
        }
        let store = Arc::clone(&self.store);
        let account = account_id.to_string();
        let summaries =
            blocking_service(move || -> Result<Vec<ConversationSummary>, ServiceError> {
                Ok(changed
                    .iter()
                    .filter_map(|id| store.conversation_summary(&account, id).transpose())
                    .collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        for summary in summaries {
            let _ = self
                .host_events
                .send(HostSideEvent::ConversationChanged(summary));
        }
        Ok(())
    }

    /// §4.167: one single-group engine listing, filtered the way the
    /// §4.53/§4.57 folds read it (`groupId: [key]`) and searched by id —
    /// never assumed `first()`. `Ok(Refreshed)` carries the same answer's
    /// requesting/pending arrays for the replay; `Ok(Gone)` is the
    /// definitive negative: the engine answered and this group is absent
    /// from the listing, or present with `isMember != true` (the sync
    /// persist's own member gate). `Err` is everything else — an unbound
    /// engine, a refused read, a store write failure — never a group
    /// negative.
    async fn refresh_group_from_engine(
        &self,
        account_id: &str,
        group_key: &str,
    ) -> Result<GroupResync, ServiceError> {
        let engine = self.running_engine().await.map_err(ServiceError::Engine)?;
        let number = self
            .service
            .lock()
            .await
            .account_signal_number(account_id)?;
        let listed = engine
            .call(
                "listGroups",
                json!({ "account": number, "groupId": [group_key] }),
                CallClass::ReadOnly,
            )
            .await
            .map_err(ServiceError::Engine)?;
        let entry = listed.as_array().and_then(|groups| {
            groups
                .iter()
                .find(|group| group.get("id").and_then(Value::as_str) == Some(group_key))
        });
        let Some(entry) = entry else {
            return Ok(GroupResync::Gone);
        };
        if entry.get("isMember").and_then(Value::as_bool) != Some(true) {
            return Ok(GroupResync::Gone);
        }
        // The sync persist's own projection (§4.39 roster capture): the same
        // entry shape, the same title truncation, the same bounded roster.
        let title = entry
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(64).collect::<String>())
            .unwrap_or_else(|| "group".to_string());
        let extra = entry
            .get("members")
            .and_then(Value::as_array)
            .map(|members| group_extra_json(members, entry));
        let changed = blocking_service({
            let store = Arc::clone(&self.store);
            let account = account_id.to_string();
            let group = group_key.to_string();
            let title = title.clone();
            let extra = extra.clone();
            move || {
                let entries = [SyncedContact {
                    kind: "group",
                    peer_key: group.as_str(),
                    title: title.as_str(),
                    extra: extra.as_deref(),
                }];
                store
                    .upsert_passive_contacts(&account, &entries, crate::link::now_ms())
                    .map_err(ServiceError::Store)
            }
        })
        .await?;
        self.emit_passive_changes(account_id, changed).await?;
        Ok(GroupResync::Refreshed {
            requesting: entry
                .get("requestingMembers")
                .and_then(Value::as_array)
                .cloned(),
            pending: entry
                .get("pendingMembers")
                .and_then(Value::as_array)
                .cloned(),
        })
    }

    /// The engine's live requesting-members array for one group (contract
    /// revision 1.62, §4.53 appendix): the same single-group `listGroups`
    /// read the §4.53 fold runs, projected to the raw
    /// `JsonGroup.requestingMembers` entries. `Ok(None)` = the engine
    /// answered without the face (every entry drops, the key stays absent);
    /// `Err` = the engine is not running or refused the read (the caller
    /// degrades the same way). The read does not widen the §4.8 addressing:
    /// the caller still gates on the cached kind='group' row before this
    /// face is worth anything, and `store_get_group_with_requesting` keeps
    /// answering `GROUP_NOT_FOUND` for an unsynced group even when the live
    /// read succeeded.
    async fn requesting_members_for_group(
        &self,
        account_id: &str,
        group_key: &str,
    ) -> Result<Option<Vec<Value>>, ServiceError> {
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(_) => return Ok(None),
        };
        let number = self
            .service
            .lock()
            .await
            .account_signal_number(account_id)?;
        let listed = engine
            .call(
                "listGroups",
                json!({ "account": number, "groupId": [group_key] }),
                CallClass::ReadOnly,
            )
            .await
            .map_err(ServiceError::Engine)?;
        Ok(listed
            .as_array()
            .and_then(|groups| groups.first())
            .and_then(|group| group.get("requestingMembers"))
            .and_then(Value::as_array)
            .cloned())
    }

    /// The engine's live pending-members array for one group (contract
    /// revision 1.64, §4.57): the same single-group `listGroups` read the
    /// §4.57 revoke fold runs, projected to the raw
    /// `JsonGroup.pendingMembers` entries. `Ok(None)` = the engine answered
    /// without the face (every entry drops, the key stays absent); `Err` =
    /// the engine is not running or refused the read (the caller degrades
    /// the same way). The read does not widen the §4.8 addressing: the
    /// caller still gates on the cached kind='group' row before this face is
    /// worth anything, and `store_get_group_with_requesting` keeps answering
    /// `GROUP_NOT_FOUND` for an unsynced group even when the live read
    /// succeeded.
    async fn pending_members_for_group(
        &self,
        account_id: &str,
        group_key: &str,
    ) -> Result<Option<Vec<Value>>, ServiceError> {
        let engine = match self.running_engine().await {
            Ok(engine) => engine,
            Err(_) => return Ok(None),
        };
        let number = self
            .service
            .lock()
            .await
            .account_signal_number(account_id)?;
        let listed = engine
            .call(
                "listGroups",
                json!({ "account": number, "groupId": [group_key] }),
                CallClass::ReadOnly,
            )
            .await
            .map_err(ServiceError::Engine)?;
        Ok(listed
            .as_array()
            .and_then(|groups| groups.first())
            .and_then(|group| group.get("pendingMembers"))
            .and_then(Value::as_array)
            .cloned())
    }

    /// Pull the contacts/groups signal-cli already synced from the primary
    /// device into the local cache. Both calls are ReadOnly on the single engine
    /// queue, so they cannot starve or corrupt mutating sends. A successful
    /// sync less than 60s old short-circuits to the cached counts.
    ///
    /// §4.163 budget: the engine-and-store pass rides one wall-clock budget
    /// ([`CONTACTS_SYNC_BUDGET`]) — any leg that stalls (a starved service
    /// lock, a store stall, a wedged engine call) folds the whole face to the
    /// retryable timeout code instead of hanging the desktop's sync empty
    /// state forever. The budget covers the whole pass, not each engine call:
    /// the hang can sit in any leg.
    pub async fn sync_contacts(
        &self,
        account_id: &str,
    ) -> Result<ContactsSyncOutcome, ServiceError> {
        let now_ms = crate::link::now_ms();
        {
            let service = self.service.lock().await;
            if let Some(synced_at) = service.contacts_synced_at(account_id)?
                && now_ms.saturating_sub(synced_at) < 60_000
            {
                let (contact_count, group_count) = service.count_contacts(account_id)?;
                return Ok(ContactsSyncOutcome {
                    contact_count,
                    group_count,
                    synced_at,
                });
            }
        }
        let outcome = tokio::time::timeout(CONTACTS_SYNC_BUDGET, async {
            let engine = self.running_engine().await?;
            sync_contacts_with(&self.service, &engine, account_id, &self.host_events).await
        })
        .await
        .unwrap_or_else(|_| {
            // The same face an engine read timeout answers (retryable): the
            // caller re-triggers when it chooses; nothing is retried here.
            Err(ServiceError::Api(ApiError::new(
                "UPSTREAM_TIMEOUT",
                "contacts sync exceeded its budget; retry later",
                true,
            )))
        });
        // An empty projection means the engine store was not ready yet; do
        // not let that empty result arm the 60s throttle. The gate retries
        // until the contact attachment has landed.
        if matches!(&outcome, Ok(outcome) if outcome.contact_count == 0) {
            let service = self.service.lock().await;
            let _ = service.store_ref().clear_contacts_synced_at(account_id);
        }
        if outcome.is_ok() {
            // 契约 1.270（§4.254 · 批 Z14）：真实落库（非 60s 节流早退）后
            // 一轮头像 backfill——首轮链接/换机/重启后的冷缓存收敛点。
            self.kick_avatar_backfill(account_id).await;
        }
        outcome
    }
}

/// Shared body of [`RuntimeSupervisor::sync_contacts`] plus the startup
/// re-sync: the read-only engine listing and the single all-or-nothing upsert
/// transaction. Free-standing so the spawned startup pass can run against the
/// engine handle it captured at spawn time. The change-set half of the store
/// write rides the host event lane (§4.135): each newly materialized
/// conversation skeleton or placeholder-title upgrade pushes
/// `conversation.changed` — the §4.122 passive batch's event semantics — so a
/// desktop already rendering the list converges after an engine restart or a
/// fresh link without a refetch; a replayed pull changes nothing and emits
/// nothing.
async fn sync_contacts_with(
    service: &Arc<Mutex<ConnectorService>>,
    engine: &EngineHandle,
    account_id: &str,
    events: &tokio::sync::broadcast::Sender<HostSideEvent>,
) -> Result<ContactsSyncOutcome, ServiceError> {
    let number = service.lock().await.account_signal_number(account_id)?;
    // Contacts registered on the account only (no allRecipients walk).
    let mut contacts_result = engine
        .call(
            "listContacts",
            json!({ "account": number }),
            CallClass::ReadOnly,
        )
        .await
        .map_err(ServiceError::Engine)?;
    let has_unnamed = contacts_result.as_array().is_some_and(|items| {
        !items.is_empty()
            && items.iter().all(|item| {
                item.get("name")
                    .and_then(Value::as_str)
                    .is_none_or(|name| name.trim().is_empty())
            })
    });
    if has_unnamed {
        // A fresh/relinked account can land contacts before any profile
        // material does. Refresh once and re-read the projection instead of
        // leaving every row as 未知联系人 until the next link.
        let _ = engine
            .call(
                "profiles.refreshContacts",
                json!({ "account": number }),
                CallClass::ReadOnly,
            )
            .await;
        if let Ok(refreshed) = engine
            .call(
                "listContacts",
                json!({ "account": number }),
                CallClass::ReadOnly,
            )
            .await
        {
            contacts_result = refreshed;
        }
    }
    let contact_items = contacts_result
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let named = contact_items
        .iter()
        .filter(|item| {
            item.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty())
        })
        .count();
    let profiled = contact_items
        .iter()
        .filter(|item| item.get("profile").is_some())
        .count();
    tracing::warn!(
        contacts = contact_items.len(),
        named,
        profiled,
        "contacts sync engine projection"
    );
    let groups_result = engine
        .call(
            "listGroups",
            json!({ "account": number }),
            CallClass::ReadOnly,
        )
        .await
        .map_err(ServiceError::Engine)?;

    let mut synced: Vec<(String, String, String, Option<String>)> = Vec::new();
    let mut contact_count = 0_u64;
    let mut group_count = 0_u64;
    for item in contacts_result.as_array().cloned().unwrap_or_default() {
        // Prefer the ACI: direct conversation rows are keyed by serviceId on
        // the receive path. Picking the number first materialized a second
        // number-keyed row and left the live ACI row's title masked.
        let peer_key = ["uuid", "number", "numberUuid"]
            .iter()
            .find_map(|field| item.get(field).and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(peer_key) = peer_key else {
            continue;
        };
        // Contract 1.43 (§4.42): the linked account's own entry (the
        // signal-cli "note to self" contact) flows through the same skeleton
        // path as every other contact. Its composed title is the account's
        // own profile name — raw material the desktop replaces with its
        // localized Note to Self label off the summary's `isSelf` marker; the
        // connector ships no copy of its own.
        let title = compose_contact_display_name(&item)
            .unwrap_or_else(|| crate::ids::mask_address(peer_key));
        // Contract 1.176 (§4.176): the raw upstream `JsonContact.username`
        // rides the row's `extra` JSON verbatim (trimmed, bounded) — the
        // desktop's official getTitleNoDefault last-tier material
        // (profileName → number → username). Absent upstream leaves the
        // extra empty, the same informative-keys discipline as the group
        // rows' markers.
        let extra = contact_extra_json(item.get("username").and_then(Value::as_str));
        synced.push(("contact".to_string(), peer_key.to_string(), title, extra));
        contact_count += 1;
    }
    for item in groups_result.as_array().cloned().unwrap_or_default() {
        // Only groups the linked account is still a member of.
        if item.get("isMember").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(peer_key) = item
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let title = item
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(64).collect::<String>())
            .unwrap_or_else(|| "group".to_string());
        let extra = item
            .get("members")
            .and_then(Value::as_array)
            .map(|members| group_extra_json(members, &item));
        synced.push(("group".to_string(), peer_key.to_string(), title, extra));
        group_count += 1;
    }

    let entries: Vec<SyncedContact<'_>> = synced
        .iter()
        .map(|(kind, peer_key, title, extra)| SyncedContact {
            kind: kind.as_str(),
            peer_key: peer_key.as_str(),
            title: title.as_str(),
            extra: extra.as_deref(),
        })
        .collect();
    // One transaction for the whole batch plus the sync marker: the store
    // lock is held once instead of per contact, and a partial sync is
    // never visible (a failed entry rolls back the rows and the marker).
    let now_ms = crate::link::now_ms();
    let changed = service
        .lock()
        .await
        .upsert_synced_contacts(account_id, &entries, now_ms)?;
    // §4.135: the skeleton change set rides `conversation.changed` exactly
    // like the §4.122 passive batch — summaries read after the commit, one
    // event per changed row, replay-silent by construction (the change set
    // is empty when nothing materialized or upgraded).
    let summaries = {
        let service = service.lock().await;
        let store = service.store_ref();
        let mut summaries = Vec::with_capacity(changed.len());
        for conversation_id in changed {
            if let Some(summary) = store.conversation_summary(account_id, &conversation_id)? {
                summaries.push(HostSideEvent::ConversationChanged(summary));
            }
        }
        summaries
    };
    for event in summaries {
        let _ = events.send(event);
    }
    Ok(ContactsSyncOutcome {
        contact_count,
        group_count,
        synced_at: now_ms,
    })
}

/// The requesting-members identity set the §4.53 fold reads: the first group
/// entry's `requestingMembers` array (the pinned JsonGroupMemberAddress
/// shape — each entry carries `number` and/or `uuid`, the NON_NULL
/// omissions a real single-identity candidate has), flattened into the
/// set of address strings. Anything else (an engine without the face, a
/// foreign shape) reads as an empty set — the fold then empties and the
/// write never happens, the honest fail-closed direction.
fn requesting_member_identities(listed: &Value) -> std::collections::HashSet<String> {
    listed
        .as_array()
        .and_then(|groups| groups.first())
        .and_then(|group| group.get("requestingMembers"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_object())
                .flat_map(|object| {
                    ["number", "uuid"].iter().filter_map(|field| {
                        object
                            .get(*field)
                            .and_then(Value::as_str)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The §4.53 fold: the caller's candidates survive only while the engine
/// still reports them requesting (either identity the set carries). The
/// return keeps the caller's order; empty means no candidate is still
/// requesting — the write never goes upstream.
fn fold_join_request_candidates(
    members: Vec<String>,
    requesting: &std::collections::HashSet<String>,
) -> Vec<String> {
    members
        .into_iter()
        .filter(|member| requesting.contains(member))
        .collect()
}

/// The pending-invitees identity set the §4.57 fold reads: the first group
/// entry's `pendingMembers` array (the pinned JsonGroupMemberAddress shape —
/// each entry carries `number` and/or `uuid`, the NON_NULL omissions a real
/// single-identity invitee has), flattened into the set of address strings.
/// Anything else (an engine without the face, a foreign shape) reads as an
/// empty set — the fold then empties and the write never happens, the
/// honest fail-closed direction.
fn pending_member_identities(listed: &Value) -> std::collections::HashSet<String> {
    listed
        .as_array()
        .and_then(|groups| groups.first())
        .and_then(|group| group.get("pendingMembers"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_object())
                .flat_map(|object| {
                    ["number", "uuid"].iter().filter_map(|field| {
                        object
                            .get(*field)
                            .and_then(Value::as_str)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The §4.57 fold: the caller's candidates survive only while the engine
/// still reports them pending invitees (either identity the set carries).
/// The return keeps the caller's order; empty means no candidate is still
/// pending — the write never goes upstream.
fn fold_invite_candidates(
    members: Vec<String>,
    pending: &std::collections::HashSet<String>,
) -> Vec<String> {
    members
        .into_iter()
        .filter(|member| pending.contains(member))
        .collect()
}

/// The cached group row's `extra` JSON (contract revision 1.40, §4.39; the
/// terminated flag added in 1.53, §4.50 appendix; the member label pair added
/// in 1.67, §4.60): the member count the 1.9 sync already recorded, now beside
/// the bounded roster the §4.39 projection reads. Member entries keep the
/// connector-wide first-wins address ladder (`number` before `uuid`); a
/// separate `uuid` key
/// is stored only when the upstream supplied one that differs from `id`.
/// `admin: true` is recorded when the pinned upstream marks the member — its
/// per-member `isAdmin` flag or the group-level `admins` address set
/// (`ListGroupsCommand$JsonGroupMember` / `$JsonGroup`, verified in the
/// 0.14.8 distribution jar); engines without an admin face simply never set
/// it. `labelEmoji` / `label` (contract 1.67, §4.60) are the pinned upstream's
/// per-member label fields (`JsonGroupMember.labelEmoji` / `.label`, both
/// `@JsonInclude(NON_NULL)` — absent keys when the member carries none) passed
/// through verbatim under the upstream's own server budgets: an emoji over 64
/// bytes or a string over 512 bytes (the pinned
/// `GroupsV2Operations` server-side caps; the write face budgets them at
/// `SERVER_EMOJI_BYTE_LIMIT` / `SERVER_STRING_BYTE_LIMIT`) drops the key
/// instead of truncating — a clipped label would render a lie. Engines
/// without a label face simply never set either key; the kt engine projects
/// the same pair natively since contract 1.252 (§4.238), so both runtime
/// faces feed this capture identically. Entries without any
/// address and entries past [`MAX_GROUP_MEMBERS`]
/// drop — a hostile roster can never fail the sync. `isTerminated: true` is
/// recorded when the upstream `JsonGroup` carries it (the §4.50 verified read
/// source; false and absent collapse to absent, the same informative-keys
/// discipline as `admin` — the read projection answers the default false).
/// `description` (contract 1.188, §4.188) is the engine `listGroups` entry's
/// decrypted group description under the write face's own
/// [`crate::service::GROUP_DESCRIPTION_MAX_BYTES`] budget — trimmed,
/// non-empty, and only
/// when it fits whole (the label discipline: an over-budget description
/// drops rather than truncating into a lie); engines without the face (the
/// pinned signal-cli JsonGroup) never set the key, and the captured value
/// is cache material only, never logged. `accessControl` (contract 1.221,
/// §4.231) is the engine listGroups entry's three-arm object, projected arm
/// by arm: only MEMBER / ADMINISTRATOR ride (the official gate words the
/// desktop's canEditGroupInfo / canAddNewMembers / getCanAddLabel read);
/// every other word and every malformed shape drops that arm, and the whole
/// key is absent when no arm survives — unknown, never a lie.
fn group_extra_json(members: &[Value], group: &Value) -> String {
    let admin_ids: std::collections::BTreeSet<String> = group
        .get("admins")
        .and_then(Value::as_array)
        .map(|admins| {
            admins
                .iter()
                .take(MAX_GROUP_MEMBERS)
                .filter_map(|entry| entry.as_object().and_then(member_address_id))
                .collect()
        })
        .unwrap_or_default();
    let roster: Vec<Value> = members
        .iter()
        .take(MAX_GROUP_MEMBERS)
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let id = member_address_id(object)?;
            let uuid = ["uuid"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str))
                .map(str::trim)
                .filter(|value| !value.is_empty() && *value != id)
                .map(|value| {
                    value
                        .chars()
                        .take(MAX_GROUP_MEMBER_ID_CHARS)
                        .collect::<String>()
                });
            let admin = object.get("isAdmin").and_then(Value::as_bool) == Some(true)
                || admin_ids.contains(&id)
                // Contract 1.181 (§4.181): the engine face's GV2 role word —
                // ADMINISTRATOR is the only admin role (DEFAULT and UNKNOWN
                // are member states); the legacy isAdmin/admins reads above
                // stay for the signal-cli JsonGroup face.
                || object.get("role").and_then(Value::as_str) == Some("ADMINISTRATOR");
            let label_emoji = bounded_upstream_label(
                object.get("labelEmoji").and_then(Value::as_str),
                GROUP_MEMBER_LABEL_EMOJI_MAX_BYTES,
            );
            let label = bounded_upstream_label(
                object.get("label").and_then(Value::as_str),
                GROUP_MEMBER_LABEL_SERVER_MAX_BYTES,
            );
            let mut projected = serde_json::Map::with_capacity(5);
            projected.insert("id".to_string(), json!(id));
            if let Some(uuid) = uuid {
                projected.insert("uuid".to_string(), json!(uuid));
            }
            if admin {
                projected.insert("admin".to_string(), json!(true));
            }
            if let Some(label_emoji) = label_emoji {
                projected.insert("labelEmoji".to_string(), json!(label_emoji));
            }
            if let Some(label) = label {
                projected.insert("label".to_string(), json!(label));
            }
            Some(Value::Object(projected))
        })
        .collect();
    let mut extra = serde_json::Map::with_capacity(4);
    extra.insert("memberCount".to_string(), json!(members.len()));
    extra.insert("members".to_string(), Value::Array(roster));
    if group.get("isTerminated").and_then(Value::as_bool) == Some(true) {
        extra.insert("isTerminated".to_string(), json!(true));
    }
    // Contract 1.255 (§4.240): the engine face's member word — captured only
    // when explicitly false, the left/kicked residual the engine's own
    // isMember computation answers for a group this account no longer
    // belongs to. true and absent collapse to no key: the healthy default
    // stays the absent marker, the informative-keys discipline (the
    // isTerminated capture beside it runs the same shape). The read side
    // projects the official removalStage vocabulary from it (store
    // extra_removal_stage); the two markers stay independent words — the
    // official removal-stage and terminated machines never folded.
    if group.get("isMember").and_then(Value::as_bool) == Some(false) {
        extra.insert("isMember".to_string(), json!(false));
    }
    // Contract 1.180 (§4.180): the official link-access word the upstream
    // JsonGroup carries (`addFromInviteLink` — the official
    // buildAccessControlAddFromInviteLinkChange vocabulary the desktop's
    // group-link face derives hasGroupLink/approval from). MEMBER is not a
    // link-join state and UNKNOWN is the engine's unparsed fallback —
    // neither is a display state the official client knows, so both (and
    // every malformed value) collapse to absent: unknown, never a lie.
    // Contract 1.252 (§4.237): the engine's listGroups face — the only
    // runtime — never carries the top-level key; it projects the word
    // inside its accessControl object (P5 b991076), which is also the
    // official client's own read position (GroupLinkManagement.dom.tsx:
    // 46-53 reads conversation.accessControl.addFromInviteLink), so the
    // top-level-only capture stayed absent on every engine-mode sync and
    // the group-link panel sat on its unsynced placeholder forever. When
    // the top-level word is absent the capture falls back to the nested
    // accessControl.addFromInviteLink word under the identical §4.180
    // vocabulary and collapse rules; the top-level word keeps precedence
    // when a face carries both (the pinned signal-cli JsonGroup shape) —
    // a top-level word outside the vocabulary collapses the key and never
    // blends with the nested face.
    let link_access_word = group
        .get("addFromInviteLink")
        .and_then(Value::as_str)
        .or_else(|| {
            group
                .get("accessControl")
                .and_then(|access| access.get("addFromInviteLink"))
                .and_then(Value::as_str)
        });
    if let Some(word) = link_access_word
        && matches!(word, "ANY" | "ADMINISTRATOR" | "UNSATISFIABLE")
    {
        extra.insert("linkAccess".to_string(), json!(word));
    }
    // Contract 1.221 (§4.231): the engine listGroups entry's accessControl
    // object (`{attributes, members, addFromInviteLink, memberLabel}`,
    // engine P5 b991076 — the official ConversationType arms at
    // getConversation.preload.ts:226-228). Only the three gate arms ride,
    // and each only in the official two gate words: MEMBER / ADMINISTRATOR.
    // UNKNOWN/ANY/UNSATISFIABLE and malformed values collapse that arm to
    // absence (unknown, never a lie); the whole key is absent when no arm
    // survives, so pre-1.221 rows stay byte-identical. addFromInviteLink
    // stays on its own linkAccess face above — different vocabulary.
    let mut access_control = serde_json::Map::new();
    if let Some(access) = group.get("accessControl").and_then(Value::as_object) {
        for (key, host) in [
            ("attributes", "attributes"),
            ("members", "members"),
            ("memberLabel", "memberLabel"),
        ] {
            if let Some(word) = access.get(key).and_then(Value::as_str)
                && matches!(word, "MEMBER" | "ADMINISTRATOR")
            {
                access_control.insert(host.to_string(), json!(word));
            }
        }
    }
    if !access_control.is_empty() {
        extra.insert("accessControl".to_string(), Value::Object(access_control));
    }
    // Contract 1.181 (§4.181): the announcements-only flag the upstream
    // JsonGroup carries verbatim (the engine's listGroups always does; the
    // CompositionArea.dom.tsx:1108 `announcementsOnly && !areWeAdmin` banner
    // gate). Stored only when the upstream supplied the key — a legacy face
    // without it keeps the key absent (unknown, never a guessed false).
    if let Some(flag) = group.get("announcementsOnly").and_then(Value::as_bool) {
        extra.insert("announcementsOnly".to_string(), json!(flag));
    }
    // Contract 1.188 (§4.188): the engine's decrypted group description
    // under the write face's own whole-value budget — the label
    // discipline: an over-budget description drops the key rather than
    // truncating into a lie. Engines without the face (the pinned
    // signal-cli JsonGroup) never set the key; the captured value is
    // cache material only, never logged.
    if let Some(description) = group
        .get("description")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| {
            !value.is_empty() && value.len() <= crate::service::GROUP_DESCRIPTION_MAX_BYTES
        })
    {
        extra.insert("description".to_string(), json!(description));
    }
    Value::Object(extra).to_string()
}

/// One upstream roster address with the connector-wide first-wins ladder:
/// `number` before `uuid`, trimmed, non-empty, bounded to the roster id cap.
pub(crate) fn member_address_id(object: &serde_json::Map<String, Value>) -> Option<String> {
    ["number", "uuid"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .chars()
                .take(MAX_GROUP_MEMBER_ID_CHARS)
                .collect::<String>()
        })
}

/// One upstream label field under its server budget (contract 1.67, §4.60):
/// trimmed, non-empty, and only when it fits the budget whole — the key drops
/// otherwise (a truncated label would render a lie, so over-budget values are
/// treated as malformed and dropped individually, the §4.39 hostile-roster
/// discipline).
fn bounded_upstream_label(value: Option<&str>, max_bytes: usize) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= max_bytes)
        .map(str::to_owned)
}

impl Drop for RuntimeSupervisor {
    fn drop(&mut self) {
        self.receive_worker.abort();
        self.account_unlink_worker.abort();
        if let Ok(mut slot) = self.watchdog.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        if let Ok(mut slot) = self.retention.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        if let Ok(mut slot) = self.media_governor_pass.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        if let Ok(mut slot) = self.contacts_resync.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        if let Ok(mut slot) = self.delivery_receipt_worker.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        if let Ok(mut slot) = self.background_sync_worker.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
    }
}

/// §4.167 single-group refresh outcome: backfilled (with the same engine
/// answer's live member faces for the replay) or definitively gone — the
/// engine answered the listing and this group is absent from it or carries
/// `isMember != true`.
enum GroupResync {
    Refreshed {
        requesting: Option<Vec<Value>>,
        pending: Option<Vec<Value>>,
    },
    Gone,
}

/// Run one store-backed call on the blocking pool: rusqlite is synchronous
/// and must never occupy a tokio worker thread. A blocking task that died
/// without a result is a storage failure for the caller; the JoinError detail
/// is never logged.
async fn blocking_service<T>(
    call: impl FnOnce() -> Result<T, ServiceError> + Send + 'static,
) -> Result<T, ServiceError>
where
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(call).await {
        Ok(result) => result,
        Err(_) => Err(ServiceError::Store(StoreError::Unavailable(None))),
    }
}

/// Map one download-chain failure onto the wire codes. Content failures are
/// terminal (a corrupt or expired transit object does not improve on a
/// re-fetch — §4.38 no-auto-retry); only local filesystem work keeps the
/// advisory retryable flag. Log discipline: the failure variants are
/// content-free already — nothing here logs a URL, path, id, or key.
fn map_download_failure(failure: crate::history_attachment::DownloadFailure) -> ServiceError {
    use crate::history_attachment::DownloadFailure as Failure;
    let (code, text, retryable) = match failure {
        Failure::InvalidLocator(reason) => ("INVALID_REQUEST", reason, false),
        Failure::Http(_) => (
            "UPSTREAM_ERROR",
            "the transit CDN refused the attachment request",
            false,
        ),
        Failure::Network => ("UPSTREAM_ERROR", "the transit CDN download failed", false),
        Failure::BodyTooLarge { .. } => (
            "UPSTREAM_ERROR",
            "the attachment body exceeded its declared bounds",
            false,
        ),
        Failure::BadMac => (
            "UPSTREAM_ERROR",
            "the attachment ciphertext failed its integrity check",
            false,
        ),
        Failure::DigestMismatch => (
            "UPSTREAM_ERROR",
            "the attachment ciphertext failed its integrity check",
            false,
        ),
        Failure::BadPadding | Failure::PlaintextTooShort { .. } => (
            "UPSTREAM_ERROR",
            "the attachment could not be decrypted",
            false,
        ),
        Failure::PlaintextHashMismatch => (
            "UPSTREAM_ERROR",
            "the attachment failed its plaintext integrity check",
            false,
        ),
        Failure::Io => ("UPSTREAM_ERROR", "local attachment storage failed", true),
    };
    ServiceError::Api(ApiError::new(code, text, retryable))
}

/// The §4.163 CDN download trust anchor: the vendored Signal production root
/// CA (the same `vendor/certs/production-root-ca.pem` the doctor's strict leg
/// pins). The CDN chains to Signal's private root — it is in neither the
/// webpki set nor any platform keychain, so both earlier trust stories died
/// on the real chain (the compile-time `include_bytes!` makes the anchor
/// non-optional; a parse failure fails the client build like any other).
fn cdn_root_certificate() -> Option<reqwest::Certificate> {
    reqwest::Certificate::from_pem(include_bytes!("../vendor/certs/production-root-ca.pem")).ok()
}

/// The §4.38 step-3 CDN download client: the same connect/total budgets and
/// no-redirect posture the chain has always used, plus the launcher's SOCKS
/// route when the caller passes the `KT_SIGNAL_SOCKS_PROXY` environment
/// value (injected, so both branches stay testable without mutating process
/// state). The value parses through the doctor's tolerant parse — the
/// canonical `host:port`, a `socks5(h)://` prefix normalized away — and
/// rides the client as `socks5h://` (remote DNS), the same `ALL_PROXY`
/// mapping the engine child gets, so a walled or DNS-poisoned network still
/// reaches the transit CDN over the route the engine's own transport takes.
/// A missing or malformed value builds the direct client: byte-for-byte the
/// behavior before the route existed.
///
/// Trust anchors (contract revision 1.165, §4.163; superseding the 1.163
/// platform-store-only posture): the vendored Signal production root CA
/// first — the CDN's real chain terminates at Signal's private root, which
/// neither the webpki set nor any keychain carries, so the 1.163
/// native-roots-only client rejected every clean-network handshake exactly
/// like its webpki predecessor (two dead generations). The platform store
/// stays loaded beneath it (the `rustls-tls-native-roots` feature default —
/// reqwest 0.12.28 assembles custom roots first, then webpki, then the
/// native set; the coarse `tls_built_in_root_certs(false)` would drop the
/// native leg too and that call is deliberately NOT made here): a
/// user-trusted MITM proxy keeps the official-desktop tolerance (Chromium +
/// system store) 1.163 promised. The webpki leg needs no explicit off
/// switch — this dependency is built with `rustls-tls-native-roots` only
/// (no `rustls-tls-webpki-roots`), so that set is not compiled in at all;
/// `tls_built_in_webpki_certs` does not even exist on 0.12.28's builder
/// without that feature (the per-leg toggles are 0.13 API).
fn attachment_download_client(proxy: Option<&str>) -> Result<reqwest::Client, ServiceError> {
    let certificate = cdn_root_certificate().ok_or(ServiceError::Io)?;
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(certificate)
        .connect_timeout(crate::history_attachment::CONNECT_TIMEOUT)
        .timeout(crate::history_attachment::TOTAL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = proxy.and_then(crate::doctor::parse_socks_proxy_env) {
        let socks_url = format!("socks5h://{}:{}", proxy.host, proxy.port);
        builder = builder.proxy(reqwest::Proxy::all(&socks_url).map_err(|_| ServiceError::Io)?);
    }
    builder.build().map_err(|_| ServiceError::Io)
}

/// Best-effort temp cleanup; the download dir stays governed, so a leftover
/// temp only wastes its own bytes.
fn cleanup_temp(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Link-time history import plumbing (contract revision 1.39, §4.38).
// ---------------------------------------------------------------------------

/// One importable account: the identity the blocking import needs to open
/// the engine's archive through the registry.
#[derive(Clone)]
struct HistoryImportJob {
    account_id: String,
    signal_account: String,
    archive: PathBuf,
}

/// What the blocking eligibility probe decided for one account.
enum HistoryImportProbe {
    /// Archive present, no completed row, attempts inside the budget.
    Ready(HistoryImportJob),
    /// No archive on the engine face yet — the link watcher keeps polling.
    Waiting,
    /// Nothing to do: account gone, completed row, or attempt budget spent.
    Done,
}

fn probe_history_import(
    store: &Arc<Store>,
    data_dir: &Path,
    account_id: &str,
    cancels: &StdMutex<HashSet<String>>,
) -> HistoryImportProbe {
    // A cancel marker outranks everything (contract 1.148, §4.146): the
    // link watcher exits on its next tick and the sweep skips the account —
    // no pass is ever claimed again until `history.importRetry` clears the
    // marker. A poisoned lock (a panicking holder) reads as not-cancelled,
    // the pre-1.48 behavior.
    if cancels
        .lock()
        .map(|set| set.contains(account_id))
        .unwrap_or(false)
    {
        return HistoryImportProbe::Done;
    }
    let Ok(Some(account)) = store.account_by_id(account_id) else {
        return HistoryImportProbe::Done;
    };
    let Some(archive) = crate::history_import::archive_path(data_dir, &account.signal_account)
    else {
        // No registry entry for this number: the engine face cannot name an
        // archive path, so there is nothing to watch for.
        return HistoryImportProbe::Done;
    };
    if !crate::history_import::archive_ready(&archive) {
        return HistoryImportProbe::Waiting;
    }
    match store.history_import_row(account_id) {
        // Store trouble must not spin the watcher: treat as nothing-to-do.
        Err(_) => HistoryImportProbe::Done,
        Ok(Some(row)) if row.state == "completed" => HistoryImportProbe::Done,
        Ok(Some(row)) if row.attempts >= crate::history_import::MAX_ATTEMPTS => {
            HistoryImportProbe::Done
        }
        _ => HistoryImportProbe::Ready(HistoryImportJob {
            account_id: account_id.to_string(),
            signal_account: account.signal_account,
            archive,
        }),
    }
}

/// Claim the group's single import slot, run the import on the blocking pool,
/// and converge retention after a completed run (§4.38). `false` means
/// another import holds the slot; the caller retries later. The holder name
/// rides the claim window so `history.importStatus` can attribute the
/// `processing` stage to the polled account (contract 1.53). The cancel flag
/// resets at every claim so a `history.importCancel` abort (contract 1.148,
/// §4.146) can only ever hit the run it names — a stale flag from a previous
/// run never kills the next account's pass.
async fn claim_and_run_history_import(
    running: Arc<AtomicBool>,
    holder: Arc<StdMutex<Option<String>>>,
    abort: Arc<AtomicBool>,
    store: Arc<Store>,
    job: HistoryImportJob,
) -> bool {
    if running
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    abort.store(false, Ordering::Release);
    if let Ok(mut slot) = holder.lock() {
        *slot = Some(job.account_id.clone());
    }
    run_history_import(&store, &job, Arc::clone(&abort)).await;
    if let Ok(mut slot) = holder.lock() {
        *slot = None;
    }
    running.store(false, Ordering::Release);
    true
}

async fn run_history_import(store: &Arc<Store>, job: &HistoryImportJob, abort: Arc<AtomicBool>) {
    let outcome = tokio::task::spawn_blocking({
        let store = Arc::clone(store);
        let job = job.clone();
        move || {
            crate::history_import::run_import(
                &store,
                &job.account_id,
                &job.signal_account,
                &job.archive,
                &abort,
            )
        }
    })
    .await;
    match outcome {
        Ok(Ok(counters)) => {
            tracing::info!(
                account_id = %job.account_id,
                imported = counters.imported,
                skipped_lines = counters.skipped_lines,
                skipped_chats = counters.skipped_chats,
                skipped_messages = counters.skipped_messages,
                "history import completed"
            );
            converge_history_retention(Arc::clone(store)).await;
        }
        Ok(Err(failure)) => {
            tracing::warn!(
                account_id = %job.account_id,
                error_class = failure.class(),
                "history import failed"
            );
        }
        Err(_) => {
            // The blocking task died without landing a terminal state; record
            // an honest failure so the face never shows a phantom `running`.
            let _ = store.complete_history_import(
                &job.account_id,
                "failed",
                &crate::store::ImportCounters::default(),
                Some("internal"),
                crate::link::now_ms(),
            );
            tracing::warn!(account_id = %job.account_id, "history import task died");
        }
    }
}

// ---------------------------------------------------------------------------
// Official-desktop snapshot import plumbing (contract revision 1.78, §4.68).
// ---------------------------------------------------------------------------

/// The §4.68 consumption-watcher cadence: ~3 s polls, a 30-minute ceiling.
const IMPORT_SNAPSHOT_POLL: Duration = Duration::from_secs(3);
const IMPORT_SNAPSHOT_CEILING: Duration = Duration::from_secs(30 * 60);

/// The §4.69 consumption-watcher cadence (contract revision 1.84): the
/// §4.68 watcher's ~3 s polls. The ceiling rides wider than the §4.68
/// import ceiling because the watched chain is the engine's whole restore —
/// credentials, the CDN download of the entire backup, decrypt, export.
const CLOUD_RESTORE_POLL: Duration = Duration::from_secs(3);
const CLOUD_RESTORE_CEILING: Duration = Duration::from_secs(60 * 60);

/// The cloud archive's freshness face: `(modified, len)`, `None` when the
/// file is absent. Equality with the face captured at watcher spawn means
/// "the artifact did not change during the watch" — only a changed face is
/// the engine's fresh write (the write is whole and strictly post-success,
/// engine `src/service/cloud_backup.rs`), so a stale archive from a
/// previous restore is never imported a second time.
fn cloud_archive_face(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Land the watcher's honest failure row: an engine-side task failure, the
/// expired-idle escape, or the ceiling. `begin` upserts the row (an account
/// may never have had a link-time import), `complete` stamps the failed
/// terminal state with the engine class so `history.importStatus` renders it
/// and `history.importRetry` answers NO_ARCHIVE — retry is re-invoking
/// backups.importSnapshot, the official Retry semantics.
fn land_import_engine_failure(store: &Arc<Store>, account_id: &str) {
    let _ = store.begin_history_import(account_id, crate::link::now_ms());
    let _ = store.complete_history_import(
        account_id,
        "failed",
        &crate::store::ImportCounters::default(),
        Some("engine"),
        crate::link::now_ms(),
    );
}

/// The §4.68 status projection: the engine's answer verbatim minus the raw
/// `account` echo, `accountId` riding in its place (the §4.46 precedent).
fn import_snapshot_status_from_engine(account_id: &str, mut result: Value) -> Value {
    if let Some(object) = result.as_object_mut() {
        object.remove("account");
        object.insert("accountId".to_owned(), json!(account_id));
    }
    result
}

/// The disk-truth degradation (the §4.46 posture): an engine that is down or
/// an indeterminate read never invents a task state — idle plus the NDJSON
/// presence the produced archive actually shows.
fn import_snapshot_status_idle_projection(
    data_dir: &Path,
    account_id: &str,
    signal_account: &str,
) -> Value {
    let present = crate::history_import::archive_path(data_dir, signal_account)
        .map(|archive| crate::history_import::archive_ready(&archive))
        .unwrap_or(false);
    json!({ "accountId": account_id, "state": "idle", "ndjsonPresent": present })
}

/// The §4.69 cloudStatus projection: the engine's progress snapshot mirrored
/// through a shape gate (engine output is not trusted input — the
/// transfer.downloadStatus gate posture). `present:false` passes as the bare
/// absent face; a present snapshot must carry the two-value phase
/// (`downloading`/`failed`) and a non-negative integer `bytesRead`, with
/// `bytesTotal`/`errorCode` optional and typed. The answer is rebuilt
/// key-by-key so no unplanned key rides and a `bytesTotal` absence stays an
/// honest absence (never a zero). A malformed present-snapshot face fails
/// UPSTREAM_PROTOCOL_ERROR instead of degrading to `present:false` — a read
/// that delivered junk knows nothing, and `present:false` would claim it does.
fn cloud_status_from_engine(result: &Value) -> Result<Value, ServiceError> {
    if result.get("present") == Some(&Value::Bool(false)) {
        return Ok(json!({ "present": false }));
    }
    let phase = result.get("phase").and_then(Value::as_str);
    let bytes_read = result.get("bytesRead").and_then(Value::as_u64);
    let bytes_total = result.get("bytesTotal").and_then(Value::as_u64);
    let error_code = result.get("errorCode").and_then(Value::as_str);
    let shaped = result.get("present") == Some(&Value::Bool(true))
        && matches!(phase, Some("downloading") | Some("failed"))
        && bytes_read.is_some()
        && result.get("bytesTotal").is_some() == bytes_total.is_some()
        && result.get("errorCode").is_some() == error_code.is_some();
    if !shaped {
        return Err(ServiceError::Api(ApiError::new(
            "UPSTREAM_PROTOCOL_ERROR",
            "backups.cloudStatus answered a malformed snapshot",
            true,
        )));
    }
    let mut payload = serde_json::Map::new();
    payload.insert("present".to_owned(), json!(true));
    payload.insert("phase".to_owned(), json!(phase));
    payload.insert("bytesRead".to_owned(), json!(bytes_read));
    if let Some(total) = bytes_total {
        payload.insert("bytesTotal".to_owned(), json!(total));
    }
    if let Some(code) = error_code {
        payload.insert("errorCode".to_owned(), json!(code));
    }
    Ok(Value::Object(payload))
}

/// The §4.72 uploadStatus projection (contract 1.87, engine
/// cloud-backup-contract §6.2): the engine's progress snapshot mirrored
/// through a shape gate — the `cloud_status_from_engine` posture verbatim
/// (engine output is not trusted input), with the upload three-value phase
/// set: `exporting` (the assembly stage — byte counts carry no semantics
/// there, the engine keeps bytesRead at 0 and the total absent),
/// `uploading` (the uplink stage — block counts valid, the total is the
/// assembled artifact's byte count), `failed` (the terminal failure —
/// errorCode carries the same code table as the start face's error ladder,
/// the snapshot persists until the next start overwrites it).
/// `present:false` passes as the bare absent face (never started /
/// succeeded — a success leaves no trace — / the engine restarted); a
/// `bytesTotal` absence stays an honest absence (never a zero); the answer
/// is rebuilt key-by-key so no unplanned key rides; a malformed
/// present-snapshot face fails UPSTREAM_PROTOCOL_ERROR instead of
/// degrading to `present:false` — a read that delivered junk knows
/// nothing.
fn upload_status_from_engine(result: &Value) -> Result<Value, ServiceError> {
    if result.get("present") == Some(&Value::Bool(false)) {
        return Ok(json!({ "present": false }));
    }
    let phase = result.get("phase").and_then(Value::as_str);
    let bytes_read = result.get("bytesRead").and_then(Value::as_u64);
    let bytes_total = result.get("bytesTotal").and_then(Value::as_u64);
    let error_code = result.get("errorCode").and_then(Value::as_str);
    let shaped = result.get("present") == Some(&Value::Bool(true))
        && matches!(
            phase,
            Some("exporting") | Some("uploading") | Some("failed")
        )
        && bytes_read.is_some()
        && result.get("bytesTotal").is_some() == bytes_total.is_some()
        && result.get("errorCode").is_some() == error_code.is_some();
    if !shaped {
        return Err(ServiceError::Api(ApiError::new(
            "UPSTREAM_PROTOCOL_ERROR",
            "backups.uploadStatus answered a malformed snapshot",
            true,
        )));
    }
    let mut payload = serde_json::Map::new();
    payload.insert("present".to_owned(), json!(true));
    payload.insert("phase".to_owned(), json!(phase));
    payload.insert("bytesRead".to_owned(), json!(bytes_read));
    if let Some(total) = bytes_total {
        payload.insert("bytesTotal".to_owned(), json!(total));
    }
    if let Some(code) = error_code {
        payload.insert("errorCode".to_owned(), json!(code));
    }
    Ok(Value::Object(payload))
}

/// §4.38: one bounded retention pass after a completed import, so the store
/// converges to the per-conversation cap within the same session. Same batch
/// discipline as the once-per-start retention pass.
async fn converge_history_retention(store: Arc<Store>) {
    let now = crate::link::now_ms();
    loop {
        let outcome = tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            move || store.prune_history(now, RETENTION_BATCH_MESSAGES)
        })
        .await
        .unwrap_or(Err(StoreError::Unavailable(None)));
        match outcome {
            Ok(outcome) => {
                if outcome.messages_deleted < u64::from(RETENTION_BATCH_MESSAGES) {
                    return;
                }
                sleep(RETENTION_BATCH_PAUSE).await;
            }
            Err(_) => return,
        }
    }
}

/// The engine's failure code for "the phone transferred nothing" — the
/// existing NO_ARCHIVE information class (contract 1.148, §4.146): an
/// informational face, never a failed row, never budget.
const IMPORT_FAILURE_NO_ARCHIVE: &str = "no_archive";

/// The engine failure-code length cap (contract 1.148, §4.146): anything
/// longer than this is engine output noise, not a code, and is consumed as
/// malformed — the pre-1.48 answer stands.
const MAX_IMPORT_FAILURE_CODE_CHARS: usize = 64;

/// The engine's terminal download-failure code, when the snapshot carries
/// one worth consuming (contract 1.148, §4.146): a non-empty string within
/// [`MAX_IMPORT_FAILURE_CODE_CHARS`]. An absent, empty, or oversized value —
/// or a non-string — is malformed engine output and answers `None`: the
/// pre-1.48 honest face, byte for byte.
fn engine_import_failure_code(snapshot: &Value) -> Option<&str> {
    snapshot
        .get("errorCode")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty() && code.len() <= MAX_IMPORT_FAILURE_CODE_CHARS)
}

/// The `history.importStatus` projection (§4.38). Priority order is the
/// contract's: a persisted ledger row (running/completed/failed) always
/// answers; otherwise the archive presence or the link-time wait window
/// decides between `pending` and `unavailable` — the engine's failure modes
/// are indistinguishable from "the phone had nothing to transfer" and are
/// reported as such, never guessed. Since contract 1.148 (§4.146) a cancel
/// marker with no ledger row answers `unavailable`/`cancelled` ahead of
/// every store/disk branch: the account was cancelled, and no pending face
/// may resurrect it until a retry clears the marker. The boolean in the
/// answer is the consult face: `true` only for the wait-window `pending`
/// branch — the one state whose answer the engine's snapshot can still
/// change (the §4.146 failure consumption and, since §4.164, the live
/// download face). A row answers with `false` (the caller consults for
/// `running` byte progress by state, never by this flag) and every
/// store/disk-derived answer with `false`.
fn history_import_status_projection(
    store: &Arc<Store>,
    data_dir: &Path,
    cancels: &StdMutex<HashSet<String>>,
    account_id: &str,
) -> Result<(Value, bool), ServiceError> {
    let account = store
        .account_by_id(account_id)?
        .ok_or(ServiceError::Store(StoreError::AccountNotFound))?;
    if let Some(row) = store.history_import_row(account_id)? {
        let status = serde_json::to_value(row)
            .map_err(|_| ServiceError::Store(StoreError::Unavailable(None)))?;
        return Ok((status, false));
    }
    let cancelled = cancels
        .lock()
        .map(|set| set.contains(account_id))
        .unwrap_or(false);
    if cancelled {
        return Ok((
            json!({
                "accountId": account_id,
                "state": "unavailable",
                "reason": "cancelled",
            }),
            false,
        ));
    }
    let on_disk = crate::history_import::archive_path(data_dir, &account.signal_account)
        .map(|path| crate::history_import::archive_ready(&path))
        .unwrap_or(false);
    if on_disk {
        // Archive present, no run has claimed it yet: the sweep or the link
        // watcher picks it up within seconds.
        return Ok((
            json!({ "accountId": account_id, "state": "pending" }),
            false,
        ));
    }
    let linked_at = store
        .account_summary(account_id)?
        .and_then(|summary| summary.linked_at);
    let inside_window = linked_at.is_some_and(|linked_at| {
        crate::link::now_ms().saturating_sub(linked_at) < crate::history_import::LINK_WAIT_MS
    });
    if inside_window {
        return Ok((json!({ "accountId": account_id, "state": "pending" }), true));
    }
    Ok((
        json!({
            "accountId": account_id,
            "state": "unavailable",
            "reason": "no-archive",
        }),
        false,
    ))
}

/// The contract 1.53 `progress` object the desktop gets while
/// `state === "running"`: `downloading` (byte progress from the engine's
/// transfer snapshot) or `processing` (the connector's own NDJSON import pass
/// — the official Process stage renders copy, not numbers, so no byte fields
/// ride this shape). `None` means the caller's projection stays without
/// `progress` — the honest "nothing observable" answer, never a guess.
///
/// Byte fields ride together or not at all (the contract's two brothers):
/// the engine only reports both when it read a content-length, so a snapshot
/// with a total presents `bytesTransferred` + `bytesTotal`, and one without
/// presents `stage` only.
///
/// Shape gate (`transfer.downloadStatus` is engine output, not trusted
/// input): `present` must be a true boolean and `bytesRead` a non-negative
/// integer within u64; `bytesTotal`, when present, the same; when both ride,
/// `bytesRead <= bytesTotal` must hold. A malformed snapshot drops the
/// `progress` object entirely — the state projection is never sacrificed for
/// a malformed ornament ("better to omit than to get it wrong"). Since
/// contract 1.148 (§4.146) a snapshot carrying `errorCode` is the engine's
/// terminal failure face — it never renders `downloading` byte progress;
/// the failure-consumption face owns the answer.
fn import_progress_from_engine_snapshot(snapshot: &Value) -> Option<Value> {
    if snapshot.get("present") != Some(&Value::Bool(true)) {
        return None;
    }
    if snapshot.get("errorCode").is_some() {
        return None;
    }
    let bytes_read = snapshot.get("bytesRead").and_then(Value::as_u64);
    let bytes_total = snapshot.get("bytesTotal").and_then(Value::as_u64);
    // A present-but-malformed byte field kills the object (better to omit
    // than to get it wrong); transferred > total is unrenderable the same way.
    if snapshot.get("bytesRead").is_some() && bytes_read.is_none() {
        return None;
    }
    if snapshot.get("bytesTotal").is_some() && bytes_total.is_none() {
        return None;
    }
    if let (Some(read), Some(total)) = (bytes_read, bytes_total)
        && read > total
    {
        return None;
    }
    let mut progress = serde_json::Map::new();
    progress.insert("stage".to_owned(), json!("downloading"));
    if let (Some(read), Some(total)) = (bytes_read, bytes_total) {
        progress.insert("bytesTransferred".to_owned(), json!(read));
        progress.insert("bytesTotal".to_owned(), json!(total));
    }
    Some(Value::Object(progress))
}

/// The `running`-state progress composition (contract 1.53): the engine's
/// download snapshot wins (stage downloading), else an active connector
/// import pass answers stage processing, else the pre-1.53 shape — no
/// progress invented.
fn compose_import_progress(downloading: Option<Value>, import_pass_active: bool) -> Option<Value> {
    if downloading.is_some() {
        return downloading;
    }
    if import_pass_active {
        return Some(json!({ "stage": "processing" }));
    }
    None
}

/// The `history.importRetry` service (contract revision 1.53, §4.38): the
/// state ladder answers before anything else — a non-`failed` row (or a
/// `running` row's absence of a re-armable state) is NOT_RETRYABLE; a failed
/// row (or a failed-engine-download face with no row at all) re-arms only
/// when the archive is still on the engine face, else NO_ARCHIVE. Success is
/// the re-armed answer `{armed: true, state: "pending"}`.
fn history_import_retry_projection(
    store: &Arc<Store>,
    data_dir: &Path,
    account_id: &str,
) -> Result<Value, ServiceError> {
    let account = store
        .account_by_id(account_id)?
        .ok_or(ServiceError::Store(StoreError::AccountNotFound))?;
    let on_disk = crate::history_import::archive_path(data_dir, &account.signal_account)
        .map(|path| crate::history_import::archive_ready(&path))
        .unwrap_or(false);
    let row = store.history_import_row(account_id)?;
    match row.as_ref().map(|row| row.state.as_str()) {
        // A failed row with its archive still on disk: clear and re-arm.
        Some("failed") if on_disk => {
            store.clear_failed_history_import(account_id)?;
            Ok(json!({ "armed": true, "state": "pending" }))
        }
        // A failed row whose archive is gone: nothing to re-import.
        Some("failed") => Err(ServiceError::Api(ApiError::new(
            "NO_ARCHIVE",
            "the transfer archive is no longer on the engine face",
            false,
        ))),
        // Completed/running rows are not retryable by definition (completed
        // is the consumption marker; running belongs to the live pass).
        Some(_) => Err(ServiceError::Api(ApiError::new(
            "NOT_RETRYABLE",
            "the import is not in a failed state",
            false,
        ))),
        // No row: the archive face decides. An archive that never completed a
        // run (the engine's best-effort download failed, or the connector
        // died mid-run leaving no row) re-arms when the file is there;
        // otherwise there is nothing to retry — the honest NO_ARCHIVE.
        None if on_disk => Ok(json!({ "armed": true, "state": "pending" })),
        None => Err(ServiceError::Api(ApiError::new(
            "NO_ARCHIVE",
            "no transfer archive has been produced for this account",
            false,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Android local-backup export plumbing (contract revision 1.47, §4.46).
// ---------------------------------------------------------------------------

/// Map the backup handle table's content-free failures onto the wire codes —
/// the media chain's ladder: caller mistakes are `INVALID_REQUEST` (one
/// indistinguishable unknown-handle answer so handle space cannot be probed),
/// a mid-stream I/O failure is the transient `UPSTREAM_ERROR`.
fn map_backup_handle_error(error: crate::backup_export::BackupHandleError) -> ServiceError {
    let (code, message, retryable) = match error {
        crate::backup_export::BackupHandleError::NotFound => (
            "INVALID_REQUEST",
            "fileHandle is unknown, expired, or already closed",
            false,
        ),
        crate::backup_export::BackupHandleError::NotSequential { .. } => (
            "INVALID_REQUEST",
            "offset must match the bytes already read on this handle",
            false,
        ),
        crate::backup_export::BackupHandleError::Exhausted => (
            "INVALID_REQUEST",
            "the account already holds the maximum number of open backup file handles",
            false,
        ),
        crate::backup_export::BackupHandleError::Io => {
            ("UPSTREAM_ERROR", "snapshot file read failed", true)
        }
    };
    ServiceError::Api(ApiError::new(code, message, retryable))
}

/// Resolve the account and its latest snapshot directory, or answer the
/// no-snapshot code. Store work only — the caller runs it on the blocking
/// pool.
fn export_latest_snapshot(
    store: &Arc<Store>,
    data_dir: &Path,
    account_id: &str,
    signal_account: &str,
) -> Result<PathBuf, ServiceError> {
    let account = store
        .account_by_id(account_id)?
        .ok_or(ServiceError::Store(StoreError::AccountNotFound))?;
    if account.signal_account != signal_account {
        return Err(ServiceError::Store(StoreError::AccountNotFound));
    }
    let account_dir = crate::history_import::engine_account_dir(data_dir, signal_account).ok_or(
        ServiceError::from(crate::backup_export::BuildError::NoEngineDirectory),
    )?;
    crate::backup_export::latest_snapshot(&account_dir)
        .map(|entry| {
            account_dir
                .join(crate::backup_export::SNAPSHOT_ROOT)
                .join(entry.name)
        })
        .ok_or_else(|| {
            ServiceError::Api(ApiError::new(
                "BACKUP_SNAPSHOT_MISSING",
                "the account has no local-backup snapshot yet",
                false,
            ))
        })
}

/// The engine-down / unknown-outcome `backups.exportStatus` answer: the disk
/// truth (snapshot list) plus `idle` — the task registry is engine-process
/// memory, so without an engine there is provably no running task (§10.4).
fn export_status_idle_projection(
    data_dir: &Path,
    account_id: &str,
    signal_account: &str,
) -> Result<Value, ServiceError> {
    let account_dir = crate::history_import::engine_account_dir(data_dir, signal_account);
    let snapshots = account_dir
        .as_ref()
        .map(|dir| crate::backup_export::list_snapshots(dir))
        .unwrap_or_default();
    let snapshots = snapshots
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "mainBytes": entry.main_bytes,
            })
        })
        .collect::<Vec<_>>();
    let mut result = json!({
        "accountId": account_id,
        "state": "idle",
        "artifactPresent": false,
        "snapshots": snapshots,
    });
    if let Some(dir) = &account_dir
        && let Some(entry) = crate::backup_export::latest_snapshot(dir)
    {
        result["snapshot"] = json!({
            "name": entry.name,
            "mainBytes": entry.main_bytes,
        });
    }
    Ok(result)
}

/// The §4.115 plaintext arm of `backups.exportStatus`: the connector-local
/// task registry's own state — content-free numbers and error classes only
/// (red line 3) — with `artifactPresent: false` (no engine artifact exists on
/// this path) and the encrypted family's on-disk snapshot listing kept
/// verbatim (the disk truth is symmetric across the families). Pure disk
/// reads; the caller runs it on the blocking pool.
fn plaintext_status_projection(
    data_dir: &Path,
    account_id: &str,
    signal_account: &str,
    task: crate::backup_export::PlaintextTaskSnapshot,
) -> Value {
    let account_dir = crate::history_import::engine_account_dir(data_dir, signal_account);
    let snapshots = account_dir
        .as_ref()
        .map(|dir| crate::backup_export::list_snapshots(dir))
        .unwrap_or_default();
    let snapshots = snapshots
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "mainBytes": entry.main_bytes,
            })
        })
        .collect::<Vec<_>>();
    let mut result = json!({
        "accountId": account_id,
        "state": task.state.as_str(),
        "kind": "plaintext_jsonl",
        "artifactPresent": false,
        "startedAtMs": task.started_at_ms,
        "snapshots": snapshots,
    });
    // Honest absence for the optional keys — settled faces only when the
    // referent exists, never zero-filled.
    if let Some(finished_at_ms) = task.finished_at_ms {
        result["finishedAtMs"] = json!(finished_at_ms);
    }
    if let Some(lines) = task.lines {
        result["lines"] = json!(lines);
    }
    if let Some(bytes) = task.bytes {
        result["bytes"] = json!(bytes);
    }
    if let Some(error) = task.error {
        result["error"] = json!(error);
    }
    if let Some(counters) = task.counters {
        counters.merge_into(&mut result);
    }
    result
}

/// The engine-answering `backups.exportStatus` projection (§4.46): the engine
/// payload mirrors honestly, minus the raw `account` echo (the number never
/// crosses the host boundary) — `accountId` rides in its place, and the
/// connector's own skip counters merge in when a build has run.
fn export_status_projection(
    account_id: &str,
    _signal_account: &str,
    mut result: Value,
    counters: Option<crate::backup_export::SkipCounters>,
) -> Value {
    let object = result.as_object_mut().expect("engine result object");
    object.remove("account");
    object.insert(
        "accountId".to_string(),
        Value::String(account_id.to_string()),
    );
    if let Some(counters) = counters {
        counters.merge_into(&mut result);
    }
    result
}

/// Receive one stderr line, skipping lag gaps; None means the stream closed.
/// Pends forever when there is no subscription, so select! can ignore the branch.
async fn recv_stderr_line(rx: Option<&mut broadcast::Receiver<String>>) -> Option<String> {
    match rx {
        Some(rx) => loop {
            match rx.recv().await {
                Ok(line) => return Some(line),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        },
        None => std::future::pending().await,
    }
}

/// Heuristic over signal-cli stderr logs: true when the line indicates the
/// receive WebSocket to the Signal server is dead (the silent-failure signature
/// this watchdog exists for, since signal-cli does not reconnect on its own).
/// Matches "websocketioexception" directly, or "websocket" together with a
/// failure keyword; normal INFO logs must not match.
fn is_receive_fatal_stderr(line: &str) -> bool {
    let lower = line.to_lowercase();
    // Only terminal legacy signal-cli shapes are receive-fatal. The kt engine
    // logs normal reconnect/handover ("websocket link is dead; closing so the
    // receive stream reconnects", "Websocket error: tungstenite error") while
    // its receive loop keeps retrying in-process; treating those as fatal
    // restarts the whole engine and turns a recoverable proxy blip into a
    // process restart storm.
    lower.contains("websocketioexception")
        || (lower.contains("websocketconnection") && lower.contains("closed unexpectedly"))
        || lower.contains("websocket error while receiving")
        || lower.contains("websocket disconnected from server")
        || lower.contains("failed to connect websocket")
        || lower.contains("exception in websocket reader thread")
}

/// How the watchdog's stderr consumer surfaces one engine stderr line.
///
/// The engine's stderr used to be consumed for receive-fatal shape matching
/// alone, with every other line discarded — production logs could not show
/// which network egress the engine had declared, which cost hours of blind
/// proxy debugging. The classification keeps the fatal verdict primary so the
/// watchdog path is unchanged, and forwards everything else at a visible or
/// inspectable level instead of dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineStderrClass {
    /// Receive-fatal shape: the existing watchdog restart path, untouched.
    ReceiveFatal,
    /// Engine self-check INFO (the one-shot "network path" egress banner):
    /// forwarded at info level, once per line, reappearing with each engine
    /// restart because the banner does.
    NetworkPath,
    /// Any other non-fatal line: forwarded at debug level only, so the
    /// default INFO run stays quiet while a debug capture sees the rest.
    Diagnostic,
}

/// Classify one engine stderr line for the watchdog consumer. Fatal wins over
/// the network-path banner so a pathological line matching both still drives
/// the unchanged watchdog path. The banner is detected by the literal
/// "network path" substring (case-insensitive, mirroring the fatal matcher's
/// style) — deliberately no parsing of the egress value, which stays inside
/// the verbatim line.
fn classify_engine_stderr(line: &str) -> EngineStderrClass {
    if is_receive_fatal_stderr(line) {
        EngineStderrClass::ReceiveFatal
    } else if line.to_lowercase().contains("network path") {
        EngineStderrClass::NetworkPath
    } else {
        EngineStderrClass::Diagnostic
    }
}

/// Run one media governor pass on a blocking task (ADR 0004): pure
/// filesystem work — the store lock is never taken, so a deletion sweep can
/// never delay receives or host requests. Counts only in the log; never
/// paths or ids.
fn run_media_governor_pass(governor: MediaGovernor) -> JoinHandle<()> {
    tokio::spawn(async move {
        let stats = tokio::task::spawn_blocking(move || governor.run_pass())
            .await
            .unwrap_or_default();
        if stats.deleted > 0 {
            tracing::info!(
                deleted = stats.deleted,
                bytes_freed = stats.bytes_deleted,
                "media governor freed attachment storage"
            );
        }
    })
}

/// Contract 1.21: authorization failures observed on this group's engine mark
/// the dead account in the shared store and surface it on the host lane
/// (account.changed). The engine classifies the raw upstream error here —
/// this loop never sees error content, only the attributed decision.
/// Contract 1.134 §4.117: the loop is also the account-domain
/// transient-notification lane's consumer — the engine's standalone
/// account-scoped notifications (`receive.emptied` / `receive.clockskew` /
/// `receive.conversationState`) resolve their account through the store and
/// forward their host frames here; an unmatchable account drops warn-only
/// inside the service (never silently claimed as forwarded). Contract 1.141
/// §4.137: the storage-manifest pull outcome event (`engine.storagePull`)
/// joins the same lane with the same attribution discipline. Contract 1.165
/// §4.163: the engine's decryption-error receive envelope joins it too —
/// counted in the metrics snapshot, forwarded as the fact alone, and never
/// acted on (no session reset, no retry).
async fn engine_event_watch_loop(
    mut engine_events: broadcast::Receiver<EngineEvent>,
    service: Arc<Mutex<ConnectorService>>,
    store: Arc<Store>,
    host_events: broadcast::Sender<HostSideEvent>,
    background_sync: mpsc::Sender<String>,
) {
    loop {
        match engine_events.recv().await {
            Ok(EngineEvent::AccountUnauthorized { account }) => {
                let marked = {
                    let guard = service.lock().await;
                    if !guard.should_persist_account_unlink() {
                        // A link/re-key window still owns the account: the
                        // engine's transient 401 is provisioning noise, not a
                        // terminal unlink. Persisting it here would outlive
                        // the window and surface as a false "phone unlinked".
                        tracing::info!(
                            "device-unlinked observed during an active link; deferring the terminal write"
                        );
                        continue;
                    }
                    guard.mark_account_device_unlinked(&account)
                };
                match marked {
                    Ok(events) => {
                        for event in events {
                            let _ = host_events.send(event);
                        }
                    }
                    Err(error) => {
                        // The state re-syncs on the next failure or list;
                        // never take the watcher down over a store hiccup.
                        tracing::warn!(error_class = error.class(), "device-unlinked mark failed");
                    }
                }
            }
            Ok(EngineEvent::ConnectionState {
                account,
                state,
                close_code,
            }) => {
                // C: connection axis only. 4401/invalidated must never write
                // account state; the account remains linked until 401/
                // DeviceDelinked arrives through AccountUnauthorized.
                let epoch = store
                    .account_engine_epoch(&account)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                let publisher = EventPublisher::new(Arc::clone(&store), host_events.clone());
                if let Err(error) = publisher.publish(
                    epoch,
                    Some(&account),
                    "connection.stateChanged",
                    HostSideEvent::ConnectionStateChanged {
                        account_id: account.clone(),
                        state,
                        close_code,
                    },
                ) {
                    tracing::warn!(?error, "durable connection.stateChanged failed");
                }
            }
            Ok(EngineEvent::ReceiveEmptied { account }) => {
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_receive_emptied(&account)
                };
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::ReceiveClockSkew {
                account,
                skew_ms,
                server_timestamp,
            }) => {
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_clock_skew(&account, skew_ms, server_timestamp)
                };
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::ConversationState {
                account,
                conversations,
                overflow,
            }) => {
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_conversation_state(&account, conversations, overflow)
                };
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::StoragePull {
                account,
                trigger,
                contacts_ok,
                groups_ok,
            }) => {
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_storage_pull(&account, &trigger, contacts_ok, groups_ok)
                };
                // Batch I: consume the same completion frame the desktop
                // receives and kick the background store merge. The forward
                // arm already resolved the account (an unknown one queues
                // nothing), so the queue carries exactly the attribution the
                // host frame proves.
                if let Some(account_id) = background_sync_account(&forwarded) {
                    queue_background_sync(&background_sync, account_id);
                }
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::InitialSyncComplete {
                account,
                manifest_ok,
                profiles_ok,
            }) => {
                // Contract 1.220 §4.230: the link-window post-registration
                // sync completion joins the same account-domain transient
                // lane with the same attribution discipline (an unmatchable
                // account drops warn-only inside the service).
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_initial_sync_complete(&account, manifest_ok, profiles_ok)
                };
                if let Some(account_id) = background_sync_account(&forwarded) {
                    queue_background_sync(&background_sync, account_id);
                }
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::ReceiveDecryptionError { account }) => {
                // Contract 1.165 §4.163: the decryption-error envelope's
                // consumption arm — the count lands in the metrics snapshot
                // and the fact forwards through the account-domain transient
                // lane (an unmatchable account drops warn-only inside the
                // service). Observability only: no session reset, no retry,
                // no automatic action of any kind rides this arm (the
                // engine's DERM retry protocol is the self-heal path).
                crate::metrics::record_decryption_error();
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_decryption_error(&account)
                };
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::ReceiveIdentityChanged {
                account,
                source_uuid,
                timestamp,
            }) => {
                // 契约 §4.226：对端安全码（身份钥）变更通知的消费臂——
                // 转发宿主渲染时间线系统行。观测事件：不自动重置会话。
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_identity_changed(&account, &source_uuid, timestamp)
                };
                emit_forwarded(&host_events, forwarded);
            }
            Ok(EngineEvent::SessionReset {
                account,
                peer_aci,
                word,
                sent_at,
            }) => {
                // 契约 1.267 §4.251（批 Z12 · S15）：引擎 session-reset 投影的
                // 消费臂——官方两类 session-reset 时间线系统行落地面（词臂
                // endSession/chatSessionRefresh → 桌面 wire 键 1.181）。
                // sentAt 缺席臂（引擎 chatSessionRefresh 发送侧时刻未知时整
                // 键缺席，eba82d3 契约注）→ 行钟标本机时钟（identityChanged
                // 模板），事件绝不丢。
                let forwarded = {
                    let guard = service.lock().await;
                    guard.forward_session_reset(
                        &account,
                        &peer_aci,
                        &word,
                        sent_at.unwrap_or_else(now_ms),
                    )
                };
                emit_forwarded(&host_events, forwarded);
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Batch I: the account id of one forwarded completion frame whose
/// successful face the official background waits for. `engine.initialSyncComplete`
/// maps to the official link-window `contactSync:complete` +
/// `storageService:syncComplete` pair (the storage-manifest leg is the one
/// that imports contacts/groups; the profile-refresh leg does not gate the
/// merge), and `engine.storagePull` with both family legs ok maps to the
/// per-pull `storageService:syncComplete` signal. A false leg is not a
/// successful completion (the official events only fire on success); the
/// desktop gate keeps its own wait semantics and the next authenticated
/// connection retries.
fn background_sync_account(forwarded: &Result<Vec<HostSideEvent>, ServiceError>) -> Option<String> {
    forwarded
        .as_ref()
        .ok()?
        .iter()
        .find_map(|event| match event {
            HostSideEvent::StoragePull {
                account_id,
                contacts_ok: true,
                groups_ok: true,
                ..
            } => Some(account_id.clone()),
            HostSideEvent::InitialSyncComplete {
                account_id,
                manifest_ok: true,
                ..
            } => Some(account_id.clone()),
            _ => None,
        })
}

/// Batch I: hand one completion kick to the bounded worker queue. A full or
/// closed queue drops the kick (never blocks the engine-event watcher); the
/// 60 s marker and the desktop gate keep that lossy choice safe.
fn queue_background_sync(sender: &mpsc::Sender<String>, account_id: String) {
    if sender.try_send(account_id).is_err() {
        tracing::debug!(
            "background contacts sync queue full or closed; dropping this kick (the next completion event or the desktop gate converges)"
        );
    }
}

/// Send the lane's forwarded events onto the host stream; a store hiccup
/// warns content-free and never takes the watcher down (the account-unlink
/// arm's discipline).
fn emit_forwarded(
    host_events: &broadcast::Sender<HostSideEvent>,
    forwarded: Result<Vec<HostSideEvent>, ServiceError>,
) {
    match forwarded {
        Ok(events) => {
            for event in events {
                let _ = host_events.send(event);
            }
        }
        Err(error) => {
            tracing::warn!(
                error_class = error.class(),
                "transient notification forward failed"
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_persistence_loop(
    mut receives: mpsc::Receiver<QueuedReceive>,
    service: Arc<Mutex<ConnectorService>>,
    store: Arc<Store>,
    host_events: broadcast::Sender<HostSideEvent>,
    owner_group: String,
    media_governor: Option<MediaGovernor>,
    delivery_receipts: mpsc::Sender<DeliveryReceiptJob>,
    avatar_refresh: mpsc::Sender<(String, String)>,
    receive_evidence: Arc<AtomicU64>,
) {
    let mut storage_unavailable = false;
    // ADR 0004 trigger discipline: after every GOVERNOR_INBOUND_MESSAGE_INTERVAL
    // persisted inbound messages, one retention pass. A plain counter in this
    // single task — no shared state, no resident timer thread.
    let mut inbound_since_governor_pass = 0_u64;
    while let Some(queued) = receives.recv().await {
        // The engine delivered an envelope over its receive channel: this is
        // the watchdog's only positive proof that the receive WebSocket is
        // alive (the REST ping cannot see it). Bumped before the store
        // attempt — delivery, not persistence success, is the liveness signal.
        receive_evidence.fetch_add(1, Ordering::Relaxed);
        crate::metrics::receive_queue_drained();
        let mut retry_delay = RECEIVE_STORE_RETRY_MIN;
        loop {
            // S2a measurement (contract revision 1.133, §4.116): the
            // per-envelope ingest transaction — the registered
            // largest-bottleneck candidate (30-envelope burst = 30
            // transactions) — timed per attempt, outcome-counted, with the
            // landed transaction's host-event count as its realized batch
            // size. Measure-only: the call, its arguments, and the control
            // flow below are byte-identical to the pre-instrumentation
            // loop; counters are content-free (counts and durations only).
            let perf_started = tokio::time::Instant::now();
            // The ingest is a synchronous SQLite batch serialized under the
            // service lock as before, but it runs on the blocking pool so a
            // slow store never occupies a tokio worker thread.
            let result = blocking_service({
                let receive = queued.receive().clone();
                let service = Arc::clone(&service);
                let owner_group = owner_group.clone();
                move || {
                    service
                        .blocking_lock()
                        .ingest_receive(receive, &owner_group)
                }
            })
            .await;
            crate::perf_metrics::record_us(
                crate::perf_metrics::keys::RECEIVE_INGEST,
                perf_started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            );
            match result {
                Ok(events) => {
                    crate::perf_metrics::add(crate::perf_metrics::keys::RECEIVE_INGEST_OK, 1);
                    crate::perf_metrics::add(
                        crate::perf_metrics::keys::RECEIVE_INGEST_EVENTS,
                        events.len() as u64,
                    );
                    for event in &events {
                        if let HostSideEvent::AccountChanged(account) = event {
                            let epoch = store
                                .account_engine_epoch(&account.id)
                                .ok()
                                .flatten()
                                .unwrap_or(0);
                            let publisher =
                                EventPublisher::new(Arc::clone(&store), host_events.clone());
                            if let Err(error) = publisher.publish(
                                epoch,
                                Some(&account.id),
                                "account.changed",
                                event.clone(),
                            ) {
                                tracing::warn!(?error, "durable account.changed failed");
                            }
                        } else {
                            let _ = host_events.send(event.clone());
                        }
                    }
                    if storage_unavailable {
                        storage_unavailable = false;
                        tracing::info!(state = "recovered", "receive persistence recovered");
                        let _ =
                            host_events.send(HostSideEvent::StorageChanged { state: "recovered" });
                    }
                    if let Some(governor) = media_governor.as_ref()
                        && queued.receive().direction == "incoming"
                    {
                        inbound_since_governor_pass += 1;
                        if inbound_since_governor_pass
                            >= crate::media::GOVERNOR_INBOUND_MESSAGE_INTERVAL
                        {
                            inbound_since_governor_pass = 0;
                            run_media_governor_pass(governor.clone());
                        }
                    }
                    // Auto delivery receipt (contract revision 1.34): only a
                    // real landing proves eligibility — the MessageUpserted
                    // event in `events` means the row was inserted now (not a
                    // dedupe replay), and only incoming dataMessage envelopes
                    // carry an author the receipt can address. Bounded and
                    // lossy: a full queue drops the job silently.
                    if let Some(job) = delivery_receipt_job(queued.receive(), &events)
                        && let Err(_) = delivery_receipts.try_send(job)
                    {
                        // Queue full: drop the receipt, never block the
                        // receive pipeline.
                    }
                    // Batch X · S6① (S6 头像生命周期 ① 失效重拉时机): the
                    // same landed batch may carry stale-avatar faces — a
                    // peer profile change (contactProfileUpdated) or a group
                    // change batch with the official avatar member. The
                    // service resolves and invalidates under its lock (the
                    // store half of the lifecycle); the bounded worker
                    // refetches through the getAvatar read lane and the
                    // commit gate (the byte half). Lossy on a full queue.
                    if !events.is_empty() {
                        let targets = {
                            let guard = service.lock().await;
                            guard.stale_avatar_targets(&events)
                        };
                        for target in targets {
                            if avatar_refresh.try_send(target).is_err() {
                                tracing::debug!(
                                    "avatar refresh queue full or closed; dropping this kick (the next profile change or the desktop's own pull converges)"
                                );
                            }
                        }
                    }
                    break;
                }
                Err(error) => {
                    crate::perf_metrics::add(crate::perf_metrics::keys::RECEIVE_INGEST_ERR, 1);
                    if !storage_unavailable {
                        storage_unavailable = true;
                        // Classification only: the store error may carry a
                        // source chain now, and none of it is logged.
                        tracing::warn!(
                            state = "unavailable",
                            error_class = error.class(),
                            error = ?error,
                            "receive persistence failed; retrying"
                        );
                        let _ = host_events.send(HostSideEvent::StorageChanged {
                            state: "unavailable",
                        });
                    }
                    sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2).min(RECEIVE_STORE_RETRY_MAX);
                }
            }
        }
    }
}

/// Eligibility for one auto delivery receipt (contract revision 1.34): the
/// envelope must be an incoming dataMessage carrying account, author, and
/// timestamp, and the ingest pass must have produced a `MessageUpserted`
/// event for an incoming row — proof the row landed now, not that the
/// envelope deduped against an already-stored message.
fn delivery_receipt_job(
    receive: &NormalizedReceive,
    events: &[HostSideEvent],
) -> Option<DeliveryReceiptJob> {
    if receive.direction != "incoming" || receive.content_kind != "dataMessage" {
        return None;
    }
    let landed = events.iter().any(|event| {
        matches!(
            event,
            HostSideEvent::MessageUpserted(record) if record.direction == "incoming"
        )
    });
    if !landed {
        return None;
    }
    Some(DeliveryReceiptJob {
        account: receive.account.clone()?,
        recipient: receive.source.clone()?,
        timestamp: receive.timestamp?,
    })
}

async fn signal_account_present(
    engine: &EngineHandle,
    signal_account: &str,
) -> Result<bool, ServiceError> {
    for _ in 0..2 {
        let result = engine
            .call("listAccounts", json!({}), CallClass::ReadOnly)
            .await?;
        let accounts = result
            .as_array()
            .ok_or(ServiceError::Engine(EngineError::Protocol))?;
        if accounts
            .iter()
            .any(|account| account.get("number").and_then(Value::as_str) == Some(signal_account))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn find_contact_display_name(items: &[Value], peer_key: &str) -> Option<String> {
    let item = items.iter().find(|entry| {
        let number = entry.get("number").and_then(Value::as_str);
        let uuid = entry.get("uuid").and_then(Value::as_str);
        let number_uuid = entry.get("numberUuid").and_then(Value::as_str);
        number == Some(peer_key) || uuid == Some(peer_key) || number_uuid == Some(peer_key)
    })?;
    compose_contact_display_name(item)
}

/// The connector-wide contact address ladder (number before uuid, the
/// `numberUuid` projection tail included) — the same match
/// [`find_contact_display_name`] runs, exposed for the §4.58 factor stamp so
/// both consumers of one listContacts answer can never disagree about which
/// identity a row is addressed by. First present non-empty identity wins.
/// Contract 1.260 (§4.244): the pinned upstream `trustLevel` vocabulary
/// (TrustLevel.java:5-8) — the only words the identity trust leg stamps.
/// An engine answer outside the vocabulary is not stored (the row keeps
/// NULL and the sweep answers the probed-absent marker): the connector
/// never persists an unknown word as trust material.
const IDENTITY_TRUST_WORDS: &[&str] = &["UNTRUSTED", "TRUSTED_UNVERIFIED", "TRUSTED_VERIFIED"];
/// 契约 1.268（§4.252 · 批 Z12 · S16）：回写引擎存储的变化检测纯面——
/// item 显式携带 isHidden 位 ∧ 既有戳位不同（prev != item 位；None=戳
/// 缺席/未知，按变化收集——初写与翻转同路）→ 收集 (uuid, hidden)（引擎
/// setConversationHidden 只收 ACI，
/// uuid 非 ACI 形的条目诚实跳过）。有界 CAP/轮，余量留给下一节流窗口。
/// isHidden 缺席的条目（引擎读面未携带）绝不产生目标（未知不冒充变化）。
pub(crate) fn hidden_write_back_targets(
    items: &[Value],
    prev_of: &dyn Fn(&str) -> Option<bool>,
) -> Vec<(String, bool)> {
    const HIDDEN_WRITE_BACK_CAP: usize = 16;
    let mut targets = Vec::new();
    for item in items {
        if targets.len() >= HIDDEN_WRITE_BACK_CAP {
            break;
        }
        let hidden = item.get("isHidden").and_then(Value::as_bool);
        let Some(hidden) = hidden else {
            continue;
        };
        let Some(uuid) = item.get("uuid").and_then(Value::as_str) else {
            continue;
        };
        // prev = 既有戳位（None = 戳缺席/未知——按变化收集，初写与翻转同路；
        // store 读失败同形收敛，warn 由调用面承担）。
        let prev = prev_of(uuid);
        if prev != Some(hidden) {
            targets.push((uuid.to_string(), hidden));
        }
    }
    targets
}

fn contact_item_peer_key(item: &Value) -> Option<&str> {
    ["number", "uuid", "numberUuid"].iter().find_map(|key| {
        item.get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

/// Contract 1.65 (§4.58): serialize exactly the factor flags one engine
/// contact item exposed. The upstream names are the pinned signal-cli
/// `JsonContact` fields (`isHidden` / `profileSharing` / `isBlocked`); the
/// stored keys drop the `is` prefix for hidden/blocked to match the official
/// desktop's factor vocabulary (`hidden` / `profileSharing`). An item without
/// any of the three stamps the empty object — the probed-absent marker an
/// engine without the trio (the kt-engine read face today) legitimately
/// leaves, so the probe never re-fires for that row.
fn mrr_factors_stamp(item: &Value) -> String {
    let mut object = serde_json::Map::new();
    for (stored, upstream) in [
        ("hidden", "isHidden"),
        ("profileSharing", "profileSharing"),
        ("blocked", "isBlocked"),
    ] {
        if let Some(flag) = item.get(upstream).and_then(Value::as_bool) {
            object.insert(stored.to_string(), Value::Bool(flag));
        }
    }
    Value::Object(object).to_string()
}

fn display_name_from_contacts(result: &Value, number: &str) -> Option<String> {
    let items = result.as_array()?;
    let item = items
        .iter()
        .find(|entry| {
            entry
                .get("number")
                .and_then(Value::as_str)
                .is_some_and(|n| n == number)
        })
        .or_else(|| items.first())?;
    compose_contact_display_name(item)
}

/// Build a UI label from signal-cli listContacts JSON without logging numbers.
fn compose_contact_display_name(item: &Value) -> Option<String> {
    let profile = item.get("profile");
    let given = profile
        .and_then(|p| p.get("givenName"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let family = profile
        .and_then(|p| p.get("familyName"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let profile_name = match (given, family) {
        (Some(g), Some(f)) => Some(format!("{g} {f}")),
        (Some(g), None) => Some(g.to_string()),
        (None, Some(f)) => Some(f.to_string()),
        _ => None,
    };
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let nick = item
        .get("nickName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let username = item
        .get("username")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    profile_name
        .or(name)
        .or(nick)
        .or(username)
        .map(|s| s.chars().take(64).collect())
}

/// Contract 1.176 (§4.176): the `kind='contact'` row's `extra` JSON — the raw
/// upstream `JsonContact.username` under its own key, verbatim-trimmed and
/// bounded. `None`/empty/over-budget usernames leave the extra empty (absent
/// marker), the same informative-keys discipline as the group rows: the
/// desktop answers unknown for a row with no username evidence, never
/// invents one. Budget: Signal usernames are nickname(≤32)+discriminator;
/// 64 chars whole-value headroom with the over-budget key dropped, not
/// clipped (a clipped username would resolve the wrong account).
const CONTACT_USERNAME_MAX_CHARS: usize = 64;

fn contact_extra_json(username: Option<&str>) -> Option<String> {
    let username = username
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.chars().count() <= CONTACT_USERNAME_MAX_CHARS)?;
    Some(serde_json::json!({ "username": username }).to_string())
}

/// Project the engine's `getStickerPackManifest` result (contract 1.36,
/// §4.32): bounded title/author (KT 256-char bound, the official decoder
/// applies none), the optional cover, and the sticker list truncated at the
/// 1024-entry cap — the official decoder's truncation semantics, mirrored
/// rather than rejected. A result missing a required field is a protocol
/// error, not a partial manifest.
fn manifest_from_engine(result: &Value) -> Result<StickerPackManifest, ServiceError> {
    let title = bounded_manifest_text(
        result,
        "title",
        crate::service::MAX_STICKER_MANIFEST_TITLE_CHARS,
    )?;
    let author = bounded_manifest_text(
        result,
        "author",
        crate::service::MAX_STICKER_MANIFEST_AUTHOR_CHARS,
    )?;
    let cover = result.get("cover").map(manifest_entry_from_engine);
    let stickers_json = result
        .get("stickers")
        .and_then(Value::as_array)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    let stickers: Vec<StickerManifestEntry> = stickers_json
        .iter()
        .take(crate::service::MAX_STICKER_MANIFEST_ENTRIES)
        .map(manifest_entry_from_engine)
        .collect();
    let sticker_count = result
        .get("stickerCount")
        .and_then(Value::as_u64)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    if sticker_count > u32::MAX as u64 {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    Ok(StickerPackManifest {
        title,
        author,
        cover,
        stickers,
        sticker_count: sticker_count as u32,
    })
}

/// One manifest entry (cover or sticker): id required, emoji/contentType
/// optional and absent-on-absent so the wire matches the official optionality.
fn manifest_entry_from_engine(entry: &Value) -> StickerManifestEntry {
    let id = entry.get("id").and_then(Value::as_u64).unwrap_or(0) as u32;
    let emoji = entry
        .get("emoji")
        .and_then(Value::as_str)
        .map(str::to_string);
    let content_type = entry
        .get("contentType")
        .and_then(Value::as_str)
        .map(str::to_string);
    StickerManifestEntry {
        id,
        emoji,
        content_type,
    }
}

fn bounded_manifest_text(
    result: &Value,
    key: &str,
    max_chars: usize,
) -> Result<String, ServiceError> {
    let text = result
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    if text.chars().count() > max_chars {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    Ok(text.to_string())
}

/// Project the engine's `getStickerImage` result (contract 1.36, §4.32):
/// base64/size/contentType pass through; the encoded length is checked
/// against the 400 KB budget (300 KB CDN ceiling + base64 expansion), and a
/// `size` that disagrees with the decoded byte count is a protocol error.
fn image_from_engine(result: &Value) -> Result<StickerPackImage, ServiceError> {
    let data_base64 = result
        .get("dataBase64")
        .and_then(Value::as_str)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    if data_base64.len() > crate::service::MAX_STICKER_IMAGE_BASE64_CHARS {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    let content_type = result
        .get("contentType")
        .and_then(Value::as_str)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?
        .to_string();
    let size = result
        .get("size")
        .and_then(Value::as_u64)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    let mut decoded = Vec::new();
    let decodes = crate::service::base64_decode_to_vec(data_base64, &mut decoded);
    if size > u32::MAX as u64 || decodes.is_err() || decoded.len() != size as usize {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    Ok(StickerPackImage {
        data_base64: data_base64.to_string(),
        content_type,
        size: size as u32,
    })
}

/// Project the engine's `getAvatar` result (contract 1.48, §4.47): the data
/// URI passes through with the result-face bound — the engine caps a
/// download at [`MAX_AVATAR_DATA_URI_CHARS`] chars, the padded encoding of
/// the engine's 10 MiB decoded ceiling plus the URI prefix margin — and
/// `byteSize` must equal the decoded byte count, or the mismatching result
/// is a protocol error instead of shipping a truncated image. The decoded
/// bytes are never logged and never persisted.
fn avatar_from_engine(result: &Value) -> Result<AvatarDownload, ServiceError> {
    let data_uri = result
        .get("dataUri")
        .and_then(Value::as_str)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    if data_uri.len() > MAX_AVATAR_DATA_URI_CHARS {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    let byte_size = result
        .get("size")
        .and_then(Value::as_u64)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    let payload = data_uri
        .split_once(";base64,")
        .map(|(_, payload)| payload)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    let mut decoded = Vec::new();
    let decodes = crate::service::base64_decode_to_vec(payload, &mut decoded);
    if decodes.is_err() || decoded.len() as u64 != byte_size {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    Ok(AvatarDownload {
        data_uri: data_uri.to_string(),
        byte_size,
    })
}

/// Store-only (stale) projection (contract 1.292 §4.278, widened by §4.279).
///
/// A terminal `device_unlinked` row whose origin is the upstream verdict is
/// the one authority a parked slot has left: its engine is stopped by design,
/// so every listing of that slot is a store read. Laundering the state to
/// `unknown` here hid the death verdict from the host — the desktop keyed its
/// dead-session-binding release and its "re-link" entry on `device_unlinked`,
/// so the binding stayed active and the re-link answered
/// `session_already_bound` forever (the permanent deadlock this revision
/// fixes). Rows without an authoritative origin (pre-origin cache) keep the
/// pre-fix downgrade: an unverified terminal is not evidence.
fn apply_stale_account_evidence(account: &mut AccountSummary) {
    account.stale = true;
    if account.state == "device_unlinked" {
        let trusted = matches!(
            account.state_evidence.as_deref(),
            Some("upstream") | Some("engine")
        );
        if trusted {
            return;
        }
        account.state = "unknown";
    }
    account.state_evidence = Some("cache".to_owned());
}

fn apply_live_account_evidence(account: &mut AccountSummary) {
    if account.state == "device_unlinked" {
        let trusted = matches!(
            account.state_evidence.as_deref(),
            Some("upstream") | Some("engine")
        );
        if !trusted {
            account.state = "unknown";
            account.state_evidence = Some("cache".to_owned());
            account.stale = true;
        } else {
            account.stale = false;
        }
    } else {
        account.state_evidence = Some("inventory".to_owned());
        account.stale = false;
    }
}

/// Test-only re-export so the service-layer projection test can pin the
/// avatar result face (the same pattern as the engine error allowlist).
#[cfg(test)]
pub(crate) fn avatar_from_engine_for_tests(result: &Value) -> Result<AvatarDownload, ServiceError> {
    avatar_from_engine(result)
}

/// The `sendStory` engine answer projected (contract revision 1.76, §4.67):
/// the story `timestamp` plus the per-recipient `results` list, projected
/// entry for entry. The engine face is pinned — a missing or wrong-typed
/// required key is a protocol defect, answered loudly rather than smoothed
/// into a row-less send truth the desktop cannot reconcile; an entry count
/// past the request cap is the same drift (a silently dropped entry would
/// misreport one recipient's send state). Contract 1.157 (§4.155): the
/// additive `group` face passes through — absent (or null, the engine's
/// 缺席 caliber) stays absent and the projection keeps the pre-1.157 shape
/// byte-identically; present, both keys are pinned to the engine's
/// documented shape, the same pinned-face discipline as the required pair.
/// Contract 1.161 (§4.159): the additive `fileAttachment` pointer faces
/// pass through as raw values on both legs — the result's top level
/// carries the roster leg's upload pointer, the group face carries the
/// group leg's own (the mixed audience runs two independent uploads and
/// the pointers are distinct objects, hence the split keys); the pointer
/// face is never typed or reshaped (the engine projection owns its whole
/// shape, the locator stays opaque transit for the desktop's own
/// read-back chain), absent (or null) stays absent, and the pre-1.161
/// answer reads byte-identically.
fn story_from_engine(result: &Value) -> Result<StorySendResult, ServiceError> {
    let timestamp = result
        .get("timestamp")
        .and_then(Value::as_u64)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    let entries = result
        .get("results")
        .and_then(Value::as_array)
        .ok_or(ServiceError::Engine(EngineError::Protocol))?;
    if entries.len() > MAX_STORY_RECIPIENTS {
        return Err(ServiceError::Engine(EngineError::Protocol));
    }
    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        results.push(StorySendRecipientResult {
            recipient_number: entry
                .get("recipientNumber")
                .and_then(Value::as_str)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?
                .to_string(),
            success: StorySendSuccess {
                timestamp: entry
                    .get("success")
                    .and_then(|success| success.get("timestamp"))
                    .and_then(Value::as_u64)
                    .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            },
        });
    }
    let group = match result.get("group") {
        None | Some(Value::Null) => None,
        Some(face) => Some(StorySendGroupFace {
            group_id: face
                .get("groupId")
                .and_then(Value::as_str)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?
                .to_string(),
            timestamp: face
                .get("timestamp")
                .and_then(Value::as_u64)
                .ok_or(ServiceError::Engine(EngineError::Protocol))?,
            file_attachment: match face.get("fileAttachment") {
                None | Some(Value::Null) => None,
                Some(pointer) => Some(pointer.clone()),
            },
        }),
    };
    let file_attachment = match result.get("fileAttachment") {
        None | Some(Value::Null) => None,
        Some(pointer) => Some(pointer.clone()),
    };
    Ok(StorySendResult {
        timestamp,
        results,
        group,
        file_attachment,
    })
}

#[cfg(test)]
mod tests {
    use super::hidden_write_back_targets;
    use super::{AccountSummary, apply_live_account_evidence, apply_stale_account_evidence};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use rusqlite::Connection;
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::TempDir;

    use tokio::time::{Instant, sleep, timeout};

    fn account_for_evidence(state: &'static str, evidence: Option<&str>) -> AccountSummary {
        AccountSummary {
            id: "account-1".into(),
            display_name: None,
            masked_address: "•••".into(),
            state,
            linked_at: Some(1),
            last_message_at: None,
            unread_count: 0,
            proxy_group: "default".into(),
            aci: None,
            capabilities: None,
            state_evidence: evidence.map(str::to_string),
            state_observed_at: Some(1),
            stale: false,
            state_revision: 0,
            engine_epoch: 0,
        }
    }

    /// The link-finish budget is the last of three deadlines: the engine's own
    /// finish dispatch budget is 360 s and the desktop's link wait is 330 s, so
    /// the connector must never be the first party to give up. Answering first
    /// would turn a link the engine may still commit into a client-side
    /// failure, and a re-run of `finishLink` claims a second device slot.
    #[test]
    fn link_finish_budget_outranks_the_engine_and_desktop_deadlines() {
        assert_eq!(super::LINK_FINISH_TIMEOUT, Duration::from_secs(370));
        assert!(
            super::LINK_FINISH_TIMEOUT > Duration::from_secs(360),
            "the engine's own 360 s finish budget must expire first"
        );
        assert!(
            super::LINK_FINISH_TIMEOUT > Duration::from_secs(330),
            "the desktop's 330 s link wait must expire first"
        );
    }

    /// A budget-expired `finishLink` is the link-class unknown outcome, never
    /// the definite retryable `UPSTREAM_TIMEOUT`: the mutating call was in
    /// flight, so "definitely failed" is a lie the desktop would act on by
    /// re-running the finish.
    #[test]
    fn a_link_finish_timeout_answers_the_link_class_unknown_outcome() {
        let error = super::RuntimeSupervisor::link_finish_timeout_error();
        let api = match error {
            crate::service::ServiceError::Api(api) => api,
            other => panic!("a finish timeout must answer the host api face, got {other:?}"),
        };
        assert_eq!(api.code, "LINK_OUTCOME_UNKNOWN");
        assert!(
            !api.retryable,
            "an unknown link outcome must never be retried automatically"
        );
        assert_ne!(api.code, "UPSTREAM_TIMEOUT");
    }

    /// M3.3 + QR B1: the per-engine account ceiling refuses `finishLink` before
    /// the engine is touched. The refusal must clear the finish lane it took —
    /// a leaked lane answers every later finish with LINK_IN_PROGRESS and keeps
    /// the watchdog suppressed for good — and drop the spent session: a QR that
    /// can never commit must not keep `has_pending_link` true for its TTL.
    #[tokio::test]
    async fn a_ceiling_refused_finish_clears_its_lane_and_spends_the_session() {
        let temp = TempDir::new().unwrap();
        let store = Arc::new(test_store(temp.path()));
        for index in 0..super::MAX_ACCOUNTS_PER_ENGINE {
            store
                .upsert_account_from_signal(
                    &format!("+1555555{index:04}"),
                    Some(1),
                    DEFAULT_PROXY_GROUP_ID,
                )
                .unwrap();
        }
        let supervisor = Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        let link_session_id = supervisor
            .service
            .lock()
            .await
            .plant_link_session_for_test("KT-Ceiling", crate::link::LINK_SESSION_TTL);
        assert!(supervisor.has_pending_link().await);

        let refused = match supervisor.finish_link(link_session_id.clone()).await {
            Err(crate::service::ServiceError::Api(error)) => error,
            other => panic!("a full group must refuse the finish, got {other:?}"),
        };
        assert_eq!(refused.code, "ACCOUNT_LIMIT_REACHED");
        assert!(
            !supervisor.link_flow_active().await,
            "a refused finish must leave neither its lane nor a pending session behind"
        );
        assert!(
            !supervisor.has_pending_link().await,
            "the spent QR must not keep the watchdog suppressed"
        );

        // The next finish reaches the session judgment instead of a leaked
        // lane, and the session answers for its (spent) state.
        let again = match supervisor.finish_link(link_session_id).await {
            Err(crate::service::ServiceError::Api(error)) => error,
            other => panic!("a spent session must answer a definite code, got {other:?}"),
        };
        assert_eq!(again.code, "LINK_NOT_FOUND");
        assert_ne!(again.code, "LINK_IN_PROGRESS");
        assert!(!supervisor.link_flow_active().await);
    }

    /// QR B1: session state outranks engine liveness. A lost session's finish
    /// must still answer the definite LINK_LOST when the engine is terminal or
    /// missing — RUNTIME_NOT_RUNNING would report the runtime instead of the
    /// dead QR, and the desktop would not restart the link.
    #[tokio::test]
    async fn a_lost_session_finish_answers_link_lost_without_a_running_engine() {
        let temp = TempDir::new().unwrap();
        let supervisor = Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            Arc::new(test_store(temp.path())),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        // No start(): the slot holds no engine at all, so running_engine()
        // answers NotRunning.
        let link_session_id = supervisor
            .service
            .lock()
            .await
            .plant_link_session_for_test("KT-Lost", crate::link::LINK_SESSION_TTL);
        assert!(
            supervisor
                .service
                .lock()
                .await
                .mark_link_lost(&link_session_id)
        );

        for attempt in 0..2 {
            let error = match supervisor.finish_link(link_session_id.clone()).await {
                Err(crate::service::ServiceError::Api(error)) => error,
                other => {
                    panic!("attempt {attempt}: a lost session must answer LINK_LOST, got {other:?}")
                }
            };
            assert_eq!(error.code, "LINK_LOST", "attempt {attempt}");
            assert!(
                error.retryable,
                "the remedy is a fresh link.start, so LINK_LOST stays retryable"
            );
        }
        assert!(
            !supervisor.link_flow_active().await,
            "each refusal clears the lane it took"
        );
    }

    fn link_supervisor(temp: &TempDir) -> Arc<RuntimeSupervisor> {
        Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            Arc::new(test_store(temp.path())),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ))
    }

    /// Contract 1.286 (§4.272): an engine that states no rotate key is the
    /// capability degradation — rotation answers NOT_SUPPORTED without
    /// touching the engine (this slot holds none at all) and the single slot
    /// stays live and finishable.
    #[tokio::test]
    async fn rotate_without_an_engine_key_answers_not_supported_and_keeps_the_slot() {
        let temp = TempDir::new().unwrap();
        let supervisor = link_supervisor(&temp);
        let (attempt, slot) = supervisor.service.lock().await.plant_link_attempt_for_test(
            "KT-Rotate",
            None,
            crate::link::LINK_SESSION_TTL,
        );

        let refused = supervisor
            .rotate_link(attempt.clone())
            .await
            .expect_err("a pre-rotate engine cannot rotate");
        let api = match refused {
            crate::service::ServiceError::Api(error) => error,
            other => panic!("rotation degradation must answer the host api face, got {other:?}"),
        };
        assert_eq!(api.code, "NOT_SUPPORTED");
        assert!(!api.retryable, "the remedy is a fresh link.start");

        // The single slot is untouched: still live, still addressable.
        assert!(supervisor.has_pending_link().await);
        let service = supervisor.service.lock().await;
        assert!(service.has_link_session(&slot));
        assert!(service.has_link_attempt(&attempt));

        // An unknown attempt is its own definite answer, still engine-free.
        drop(service);
        let missing = supervisor
            .rotate_link("no-such-attempt".into())
            .await
            .expect_err("an unknown attempt answers LINK_ATTEMPT_NOT_FOUND");
        let api = match missing {
            crate::service::ServiceError::Api(error) => error,
            other => panic!("expected the host api face, got {other:?}"),
        };
        assert_eq!(api.code, "LINK_ATTEMPT_NOT_FOUND");
        assert!(!api.retryable);
    }

    /// Contract 1.286 (§4.272): a rotate key with no running engine reports
    /// the runtime, not the capability — the engine may carry the method once
    /// it lands, so NOT_SUPPORTED would be a lie.
    #[tokio::test]
    async fn rotate_with_a_key_but_no_engine_reports_the_runtime() {
        let temp = TempDir::new().unwrap();
        let supervisor = link_supervisor(&temp);
        let (attempt, _slot) = supervisor.service.lock().await.plant_link_attempt_for_test(
            "KT-Rotate",
            Some("engine-attempt-1"),
            crate::link::LINK_SESSION_TTL,
        );
        let error = supervisor
            .rotate_link(attempt)
            .await
            .expect_err("no engine is running");
        let api = error.into_api();
        assert_eq!(api.code, "RUNTIME_NOT_RUNNING");
        assert_ne!(api.code, "NOT_SUPPORTED");
    }

    /// Contract 1.286 (§4.272): the engine's method-not-found class folds to
    /// NOT_SUPPORTED; every other upstream face keeps its own answer.
    #[test]
    fn engine_method_not_found_classifies_structurally() {
        let upstream = |cause: Option<&str>, code: Option<i64>| EngineError::Upstream {
            cause: cause.map(str::to_string),
            code,
        };
        assert!(super::engine_method_missing(&upstream(None, Some(-32601))));
        assert!(super::engine_method_missing(&upstream(
            Some("(MethodNotFound)"),
            Some(-1)
        )));
        assert!(super::engine_method_missing(&upstream(
            Some("(MethodNotFoundError)"),
            Some(-32603)
        )));
        assert!(!super::engine_method_missing(&upstream(
            Some("(EngineBusy)"),
            Some(-32000)
        )));
        assert!(!super::engine_method_missing(&upstream(None, Some(-32603))));
        assert!(!super::engine_method_missing(&EngineError::Protocol));
    }

    /// Contract 1.286 (§4.272): a finish on any code of a committed attempt
    /// replays the same account — no second engine call, no second commit —
    /// and always releases the finish lane it took.
    #[tokio::test]
    async fn finishing_a_committed_attempt_replays_from_any_slot() {
        let temp = TempDir::new().unwrap();
        let supervisor = link_supervisor(&temp);
        let (attempt, first) = supervisor.service.lock().await.plant_link_attempt_for_test(
            "KT-Committed",
            Some("engine-attempt-1"),
            crate::link::LINK_SESSION_TTL,
        );
        let second = supervisor
            .service
            .lock()
            .await
            .attach_rotated_slot(&attempt, "sgnl://link?second".into(), super::now_ms())
            .expect("the attempt rotates");
        let committed = supervisor
            .service
            .lock()
            .await
            .complete_link_session_with_id(
                &second.link_session_id,
                "+15555550100",
                DEFAULT_PROXY_GROUP_ID,
                None,
                None,
            )
            .expect("the rotated slot commits");

        let replay = supervisor
            .finish_link(first)
            .await
            .expect("a committed attempt replay answers the account");
        assert_eq!(replay.id, committed.id);
        assert!(!supervisor.link_flow_active().await, "the lane is released");

        let again = supervisor
            .finish_link(second.link_session_id.clone())
            .await
            .expect("the committed slot replays too");
        assert_eq!(again.id, committed.id);
        assert_eq!(
            supervisor
                .service
                .lock()
                .await
                .list_accounts_in_group(DEFAULT_PROXY_GROUP_ID)
                .unwrap()
                .len(),
            1,
            "the attempt committed exactly once"
        );
    }

    /// §4.279: the store-only fallback is the ONLY face a parked terminal
    /// slot has left (its engine is stopped by design). An authoritative
    /// upstream unlink must survive it — laundering it to `unknown` hid the
    /// death verdict from the host, whose dead-binding release keys on
    /// `device_unlinked`, so the re-link answered `session_already_bound`
    /// forever. An origin-less legacy terminal keeps the pre-fix downgrade.
    #[test]
    fn stale_engine_fallback_keeps_only_an_authoritative_terminal_unlink() {
        let mut trusted = account_for_evidence("device_unlinked", Some("upstream"));
        apply_stale_account_evidence(&mut trusted);
        assert_eq!(trusted.state, "device_unlinked");
        assert_eq!(trusted.state_evidence.as_deref(), Some("upstream"));
        assert!(trusted.stale, "the evidence is remembered, not live");

        let mut legacy = account_for_evidence("device_unlinked", None);
        apply_stale_account_evidence(&mut legacy);
        assert_eq!(legacy.state, "unknown");
        assert_eq!(legacy.state_evidence.as_deref(), Some("cache"));
        assert!(legacy.stale);

        let mut ready = account_for_evidence("ready", Some("inventory"));
        apply_stale_account_evidence(&mut ready);
        assert_eq!(ready.state, "ready");
        assert_eq!(ready.state_evidence.as_deref(), Some("cache"));
        assert!(ready.stale);
    }

    #[test]
    fn live_inventory_trusts_only_an_authoritative_terminal_state() {
        let mut trusted = account_for_evidence("device_unlinked", Some("upstream"));
        apply_live_account_evidence(&mut trusted);
        assert_eq!(trusted.state, "device_unlinked");
        assert!(!trusted.stale);

        let mut legacy = account_for_evidence("device_unlinked", None);
        apply_live_account_evidence(&mut legacy);
        assert_eq!(legacy.state, "unknown");
        assert_eq!(legacy.state_evidence.as_deref(), Some("cache"));
        assert!(legacy.stale);

        let mut ready = account_for_evidence("ready", None);
        apply_live_account_evidence(&mut ready);
        assert_eq!(ready.state, "ready");
        assert_eq!(ready.state_evidence.as_deref(), Some("inventory"));
        assert!(!ready.stale);
    }

    /// §4.173: the send reply's `results` array counts into success/failure
    /// totals; direct sends (no array), empty arrays, and shape-hostile
    /// entries degrade to `None` (the pre-1.173 shape — no outcomes face).
    #[test]
    fn remote_delete_send_status_tracks_partial_recipient_results() {
        let map = RuntimeSupervisor::deleted_for_everyone_send_status_from_reply(&json!({
            "results": [
                { "recipientNumber": "+1", "success": { "timestamp": 7 } },
                { "recipientNumber": "+2", "failure": { "type": "NetworkFailure" } },
            ]
        }));
        assert_eq!(map.get("+1"), Some(&true));
        assert_eq!(map.get("+2"), Some(&false));
    }

    #[test]
    fn send_outcomes_from_reply_counts_group_results_entries() {
        assert_eq!(
            RuntimeSupervisor::send_outcomes_from_reply(&json!({
                "timestamp": 7,
                "results": [
                    { "recipientNumber": "+1", "success": { "timestamp": 7 } },
                    { "recipientNumber": "+2", "success": { "timestamp": 7 } },
                    { "recipientNumber": "+3", "failure": { "type": "NetworkFailure" } }
                ]
            })),
            Some(crate::store::MessageSendOutcomes {
                succeeded: 2,
                failed: 1,
                deleted_for_everyone_send_status: None,
            })
        );
        // No recognizable entry counts as no face (never an all-zero Some).
        assert_eq!(
            RuntimeSupervisor::send_outcomes_from_reply(&json!({
                "timestamp": 7,
                "results": [{ "recipientNumber": "+1" }]
            })),
            None
        );
        assert_eq!(
            RuntimeSupervisor::send_outcomes_from_reply(&json!({ "timestamp": 7 })),
            None
        );
        assert_eq!(
            RuntimeSupervisor::send_outcomes_from_reply(&json!({
                "timestamp": 7,
                "results": []
            })),
            None
        );
    }

    /// §4.190 ⑦: the same `results` array expands into per-recipient
    /// Sent/Failed seeds — the §4.173 counts de-aggregated, the official
    /// sendState fan-out posture. Entries without a usable recipient skip
    /// individually; direct sends (no array) and shape-hostile arrays answer
    /// `None` (no seeds face); the batch is bounded at 256.
    #[test]
    fn send_receipt_seeds_from_reply_expands_the_results_roster() {
        let seeds = RuntimeSupervisor::send_receipt_seeds_from_reply(&json!({
            "timestamp": 7,
            "results": [
                { "recipientNumber": "+1", "success": { "timestamp": 7 } },
                { "recipientNumber": "+2", "failure": { "type": "NetworkFailure" } },
                { "success": { "timestamp": 7 } },
                { "recipientNumber": "", "success": { "timestamp": 7 } },
                { "recipientNumber": "+3" }
            ]
        }))
        .expect("recognizable entries expand");
        assert_eq!(seeds.len(), 2, "{seeds:?}");
        assert_eq!(seeds[0].recipient, "+1");
        assert!(seeds[0].succeeded);
        assert_eq!(seeds[1].recipient, "+2");
        assert!(!seeds[1].succeeded);

        // The 256 bound: a hostile array cannot grow the seed batch.
        let hostile: Vec<serde_json::Value> = (0..600)
            .map(|index| {
                json!({ "recipientNumber": format!("+1555{index:04}"), "success": {"timestamp": 7} })
            })
            .collect();
        let seeds = RuntimeSupervisor::send_receipt_seeds_from_reply(&json!({
            "timestamp": 7,
            "results": hostile
        }))
        .expect("the bounded batch still answers");
        assert_eq!(seeds.len(), 256);

        // The direct-send shape (no array) and an empty array answer None.
        assert!(
            RuntimeSupervisor::send_receipt_seeds_from_reply(&json!({ "timestamp": 7 })).is_none()
        );
        assert!(
            RuntimeSupervisor::send_receipt_seeds_from_reply(&json!({
                "timestamp": 7,
                "results": []
            }))
            .is_none()
        );
    }

    use super::{
        EngineStderrClass, HistoryImportProbe, IMPORT_FAILURE_NO_ARCHIVE,
        MAX_IMPORT_FAILURE_CODE_CHARS, PendingRestart, RECEIPT_FAILURE_MAP_CAP, RestartSource,
        RuntimeSupervisor, arm_pending_restart, attachment_download_client, cdn_root_certificate,
        classify_engine_stderr, cloud_archive_face, cloud_status_from_engine,
        compose_contact_display_name, compose_import_progress, engine_import_failure_code,
        group_extra_json, history_import_status_projection, import_progress_from_engine_snapshot,
        is_receive_fatal_stderr, probe_history_import, receipt_failure_key,
        upload_status_from_engine, watchdog_restart_backoff,
    };
    use super::{WatchdogProbeVerdicts, account_scoped_engine_error};
    use crate::DEFAULT_PROXY_GROUP_ID;
    use crate::engine::{
        EngineConfig, NormalizedReceive, WATCHDOG_LIVENESS_BACKOFF_BASE,
        WATCHDOG_LIVENESS_BACKOFF_CAP,
    };
    use crate::service::HostSideEvent;
    use crate::store::{MessageRecord, Store, StoreKey};
    use crate::supervisor::EngineError;

    /// The liveness retry schedule is seconds-scale and independent of the
    /// five-minute anti-storm window: the first restart of an episode is
    /// immediate, then 10 s, 20 s, 40 s, ... capped at three minutes. A zero
    /// base (integration-test launchers) stays immediate.
    #[test]
    fn liveness_backoff_is_seconds_scale_and_caps() {
        let base = WATCHDOG_LIVENESS_BACKOFF_BASE;
        let cap = WATCHDOG_LIVENESS_BACKOFF_CAP;
        assert_eq!(watchdog_restart_backoff(base, 0, cap), Duration::ZERO);
        assert_eq!(
            watchdog_restart_backoff(base, 1, cap),
            Duration::from_secs(10)
        );
        assert_eq!(
            watchdog_restart_backoff(base, 2, cap),
            Duration::from_secs(20)
        );
        assert_eq!(
            watchdog_restart_backoff(base, 3, cap),
            Duration::from_secs(40)
        );
        assert_eq!(
            watchdog_restart_backoff(base, 5, cap),
            Duration::from_secs(160)
        );
        // 10 s * 2^5 = 320 s folds to the cap, and stays there.
        assert_eq!(watchdog_restart_backoff(base, 6, cap), cap);
        assert_eq!(watchdog_restart_backoff(base, 1_000, cap), cap);
        assert_eq!(
            watchdog_restart_backoff(Duration::ZERO, 9, cap),
            Duration::ZERO
        );
    }

    /// The liveness probe's attribution rule: only the engine's plain -32603
    /// internal error — the shape an unknown account earns, whose message text
    /// is not part of the pinned contract — can ever be account-scoped. Any
    /// other upstream code, any structured engine code, and every engine-level
    /// variant keep the pre-existing failure accounting, so the restart
    /// boundary is never weakened by an engine-wide fault.
    #[test]
    fn liveness_probe_attributes_only_the_plain_upstream_face_to_the_account() {
        // The unknown-account face: -32603, with or without a log-only cause.
        assert!(account_scoped_engine_error(&EngineError::Upstream {
            cause: None,
            code: Some(-32603)
        }));
        assert!(account_scoped_engine_error(&EngineError::Upstream {
            cause: Some("UnknownAccount".to_string()),
            code: Some(-32603)
        }));
        // Any other upstream code is engine-scoped: the generic -1 face is the
        // shape the existing liveness-failure tests pin, and a causeless error
        // without a code is unattributable.
        assert!(!account_scoped_engine_error(&EngineError::Upstream {
            cause: None,
            code: Some(-1)
        }));
        assert!(!account_scoped_engine_error(&EngineError::Upstream {
            cause: None,
            code: None
        }));
        // A structured engine code is never the unknown-account face.
        assert!(!account_scoped_engine_error(&EngineError::UpstreamCode {
            code: "ACCOUNT_NOT_FOUND",
            data: None
        }));
        for error in [
            EngineError::StartFailed,
            EngineError::NotRunning,
            EngineError::Backpressure,
            EngineError::Timeout,
            EngineError::UnknownOutcome,
            EngineError::Exited,
            EngineError::Protocol,
            EngineError::Unauthorized,
            EngineError::RateLimited {
                retry_after_secs: None,
            },
            EngineError::ProofRequired,
            EngineError::ServerUnavailable,
            EngineError::IdentityUnverified,
        ] {
            assert!(
                !account_scoped_engine_error(&error),
                "{error:?} is engine-scoped, never account-scoped"
            );
        }
    }

    /// Probe verdicts are per engine instance: a restart clears both the
    /// listAccounts verdict and the ping refusal, because the fresh engine may
    /// serve the account again.
    #[test]
    fn probe_verdicts_are_scoped_to_one_engine_instance() {
        let mut verdicts = WatchdogProbeVerdicts::default();
        verdicts.for_engine(Some(7));
        assert!(verdicts.engine_absent.insert("account-a".to_string()));
        assert!(verdicts.refuse("account-b"));
        // A repeated refusal is not a fresh exclusion (no extra count/log).
        assert!(!verdicts.refuse("account-b"));

        // Same instance: the verdicts persist across ticks.
        verdicts.for_engine(Some(7));
        assert!(verdicts.engine_absent.contains("account-a"));
        assert!(verdicts.refuses("account-b"));

        // A restarted engine re-earns its verdicts from scratch.
        verdicts.for_engine(Some(8));
        assert!(verdicts.engine_absent.is_empty());
        assert!(!verdicts.refuses("account-b"));
    }

    /// The production defaults are the review's acceptance bounds, and the
    /// retry base is decoupled from the 300 s anti-storm window: a dead
    /// receive path is retried in seconds, never once every five minutes.
    #[test]
    fn liveness_defaults_are_seconds_scale_and_decoupled_from_the_storm_window() {
        let config =
            EngineConfig::new(PathBuf::from("/nonexistent"), PathBuf::from("/nonexistent"));
        assert_eq!(
            config.watchdog_liveness_backoff_base,
            WATCHDOG_LIVENESS_BACKOFF_BASE
        );
        assert_eq!(
            config.watchdog_liveness_backoff_base,
            Duration::from_secs(10)
        );
        assert!(config.watchdog_liveness_backoff_base >= Duration::from_secs(5));
        assert!(config.watchdog_liveness_backoff_base <= Duration::from_secs(15));
        assert!(config.watchdog_min_restart_interval >= Duration::from_secs(5 * 60));
        assert!(
            config.watchdog_liveness_backoff_base < config.watchdog_min_restart_interval,
            "the retry base must not borrow the anti-storm window"
        );
        assert!(WATCHDOG_LIVENESS_BACKOFF_CAP >= Duration::from_secs(2 * 60));
        assert!(WATCHDOG_LIVENESS_BACKOFF_CAP <= Duration::from_secs(5 * 60));
    }

    /// A deferred restart's deadline is binding: later triggers never push
    /// it out (the "fault hangs forever" shape), ping may not displace an
    /// armed stderr trigger, and an earlier deadline wins within a source. A
    /// replacement also keeps the earliest receive-evidence snapshot, so an
    /// envelope delivered between two triggers still cancels the pending.
    #[test]
    fn pending_restart_keeps_the_earliest_deadline_and_stderr_priority() {
        let now = Instant::now();
        let mut pending = None;
        assert!(arm_pending_restart(
            &mut pending,
            PendingRestart {
                source: RestartSource::Ping,
                reason: "ping",
                due_at: now + Duration::from_secs(5),
                evidence: 7,
            },
        ));
        assert_eq!(pending.unwrap().due_at, now + Duration::from_secs(5));
        assert_eq!(pending.unwrap().evidence, 7);

        // A later ping trigger is a no-op: the fault already has a deadline.
        assert!(!arm_pending_restart(
            &mut pending,
            PendingRestart {
                source: RestartSource::Ping,
                reason: "ping",
                due_at: now + Duration::from_secs(9),
                evidence: 9,
            },
        ));
        assert_eq!(pending.unwrap().due_at, now + Duration::from_secs(5));

        // A receive-fatal stderr trigger replaces a ping-sourced pending even
        // with a later deadline: its source outranks a REST-only probe, and
        // the earlier evidence snapshot survives the replacement.
        assert!(arm_pending_restart(
            &mut pending,
            PendingRestart {
                source: RestartSource::Stderr,
                reason: "stderr",
                due_at: now + Duration::from_secs(9),
                evidence: 12,
            },
        ));
        assert_eq!(pending.unwrap().source, RestartSource::Stderr);
        assert_eq!(pending.unwrap().evidence, 7);

        // ...and a ping trigger cannot displace it afterwards.
        assert!(!arm_pending_restart(
            &mut pending,
            PendingRestart {
                source: RestartSource::Ping,
                reason: "ping",
                due_at: now + Duration::from_secs(1),
                evidence: 15,
            },
        ));
        assert_eq!(pending.unwrap().source, RestartSource::Stderr);
        assert_eq!(pending.unwrap().due_at, now + Duration::from_secs(9));
        assert_eq!(pending.unwrap().evidence, 7);
    }

    /// Contract 1.53: the running-state progress composition — download
    /// wins, else THIS account's active import pass renders stage
    /// processing, else the pre-1.53 shape.
    #[test]
    fn import_progress_composition_prefers_download_then_processing() {
        let downloading = json!({"stage": "downloading", "bytesTransferred": 1, "bytesTotal": 2});
        assert_eq!(
            compose_import_progress(Some(downloading.clone()), true),
            Some(downloading.clone())
        );
        assert_eq!(
            compose_import_progress(Some(downloading), false),
            Some(json!({"stage": "downloading", "bytesTransferred": 1, "bytesTotal": 2}))
        );
        assert_eq!(
            compose_import_progress(None, true),
            Some(json!({ "stage": "processing" }))
        );
        // Neither signal (including: the group slot is busy with another
        // account's pass — the boolean is already account-attributed by the
        // caller): the honest pre-1.53 shape, no progress invented.
        assert_eq!(compose_import_progress(None, false), None);
    }

    // -------------------------------------------------------------------------
    // Contract revision 1.148 (§4.146): the cancel face and the engine's
    // terminal download-failure consumption.
    // -------------------------------------------------------------------------

    /// The §4.146 failure-code gate: non-empty strings within the cap are
    /// codes (the known short family and unseen ones alike — the connector
    /// consumes fail-closed); absent, empty, oversized, and non-string values
    /// are malformed engine output and answer None (the pre-1.48 face).
    #[test]
    fn engine_import_failure_code_gate() {
        assert_eq!(IMPORT_FAILURE_NO_ARCHIVE, "no_archive");
        // The engine 0a2ab18 vocabulary — every one of the five consumes
        // immediately (never a ten-minute pending), and unseen codes ride
        // the same verbatim arm. The engine's §4.164 word-list additions
        // (`relink_requested`, `continue_without_upload`) pass through
        // unnormalized, exactly like every code before them — the gate is a
        // shape gate (non-empty string within the cap), never a whitelist;
        // the engine owns the word list, the connector adds no semantics.
        for code in [
            "no_archive",
            "network",
            "cdn_unreachable",
            "decode_failed",
            "io",
            "relink_requested",
            "continue_without_upload",
            "something_new",
        ] {
            assert_eq!(
                engine_import_failure_code(&json!({ "errorCode": code })),
                Some(code),
                "{code}"
            );
        }
        let boundary = "a".repeat(MAX_IMPORT_FAILURE_CODE_CHARS);
        assert_eq!(
            engine_import_failure_code(&json!({ "errorCode": boundary })),
            Some(boundary.as_str())
        );
        // Bytes may ride along; the code still reads.
        assert_eq!(
            engine_import_failure_code(&json!({
                "errorCode": "cdn_unreachable",
                "bytesRead": 5,
                "bytesTotal": 9
            })),
            Some("cdn_unreachable")
        );
        // Malformed: absent, empty, oversized, non-string.
        assert_eq!(
            engine_import_failure_code(&json!({ "present": true })),
            None
        );
        assert_eq!(
            engine_import_failure_code(&json!({ "errorCode": "" })),
            None
        );
        let oversized = "a".repeat(MAX_IMPORT_FAILURE_CODE_CHARS + 1);
        assert_eq!(
            engine_import_failure_code(&json!({ "errorCode": oversized })),
            None
        );
        assert_eq!(engine_import_failure_code(&json!({ "errorCode": 7 })), None);
    }

    /// A failure-carrying snapshot never renders byte progress (§4.146): the
    /// terminal face owns the answer, the ornament would lie.
    #[test]
    fn import_progress_rejects_failure_snapshots() {
        assert_eq!(
            import_progress_from_engine_snapshot(&json!({
                "present": true,
                "errorCode": "cdn_unreachable"
            })),
            None
        );
        assert_eq!(
            import_progress_from_engine_snapshot(&json!({
                "present": true,
                "errorCode": "io",
                "bytesRead": 1,
                "bytesTotal": 2
            })),
            None
        );
        // Sanity: the same snapshot without the code still renders.
        let progress = import_progress_from_engine_snapshot(&json!({
            "present": true,
            "bytesRead": 1,
            "bytesTotal": 2
        }))
        .unwrap();
        assert_eq!(progress["stage"], "downloading");
    }

    /// §4.146: the conditional running→failed/`cancelled` flip hits only a
    /// live row, never regresses a completed one, and never touches the
    /// attempt budget (the cancel itself is free; the run's own begin spent
    /// the one attempt).
    #[test]
    fn cancel_running_history_import_flips_only_running() {
        let temp = TempDir::new().unwrap();
        let store = test_store(temp.path());
        let account = store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();

        // No row at all: the race answer, not an error.
        assert!(!store.cancel_running_history_import(&account.id, 1).unwrap());

        // A running row flips with the class, attempts untouched.
        store.begin_history_import(&account.id, 2).unwrap();
        assert!(store.cancel_running_history_import(&account.id, 3).unwrap());
        let row = store.history_import_row(&account.id).unwrap().unwrap();
        assert_eq!(row.state, "failed");
        assert_eq!(row.error_class.as_deref(), Some("cancelled"));
        assert_eq!(row.attempts, 1);

        // A completed row never regresses.
        store.begin_history_import(&account.id, 4).unwrap();
        store
            .complete_history_import(
                &account.id,
                "completed",
                &crate::store::ImportCounters::default(),
                None,
                5,
            )
            .unwrap();
        assert!(!store.cancel_running_history_import(&account.id, 6).unwrap());
        let row = store.history_import_row(&account.id).unwrap().unwrap();
        assert_eq!(row.state, "completed");
        assert!(row.error_class.is_none());
    }

    /// §4.146: the atomic failure landing writes attempts=1 with the
    /// verbatim engine code when no row exists, and never clobbers a row
    /// that appeared mid-consult — the read-back winner is returned either
    /// way.
    #[test]
    fn land_history_import_failure_lands_once_and_never_clobbers() {
        let temp = TempDir::new().unwrap();
        let store = test_store(temp.path());
        let account = store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();

        let row = store
            .land_history_import_failure(&account.id, "cdn_unreachable", 7)
            .unwrap();
        assert_eq!(row.state, "failed");
        assert_eq!(row.error_class.as_deref(), Some("cdn_unreachable"));
        assert_eq!(row.attempts, 1);

        // A second observation over the now-persisted row changes nothing —
        // the read-back (still the first row) is the answer.
        let again = store
            .land_history_import_failure(&account.id, "io", 8)
            .unwrap();
        assert_eq!(again.error_class.as_deref(), Some("cdn_unreachable"));
        assert_eq!(again.attempts, 1);
        assert_eq!(again.started_at, row.started_at);

        // The same for a completed row: consumption never regresses it.
        store.clear_failed_history_import(&account.id).unwrap();
        store.begin_history_import(&account.id, 9).unwrap();
        store
            .complete_history_import(
                &account.id,
                "completed",
                &crate::store::ImportCounters::default(),
                None,
                10,
            )
            .unwrap();
        let completed = store
            .land_history_import_failure(&account.id, "decode_failed", 11)
            .unwrap();
        assert_eq!(completed.state, "completed");
    }

    /// The §4.146 status-projection ladder with consult faces: the row wins
    /// over everything (never a consult flag — the caller consults for
    /// `running` by state), the cancel marker beats the disk/window faces,
    /// the archive-on-disk `pending` never consults, and only the
    /// wait-window `pending` carries the consult flag.
    #[test]
    fn history_import_status_projection_orders_row_marker_disk_and_window() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let account_dir = signal_data.join("accounts").join("lk-unit");
        std::fs::create_dir_all(&account_dir).unwrap();
        std::fs::write(
            signal_data.join("engine-state.json"),
            r#"{"version":2,"accounts":[
                {"number":"+15555550100","dir":"accounts/lk-unit"},
                {"number":"+15555550101","dir":"accounts/lk-unit"},
                {"number":"+15555550102","dir":"accounts/lk-unit"}
            ]}"#,
        )
        .unwrap();
        let archive = account_dir.join("history-import.ndjson");
        std::fs::write(&archive, "{\"type\":\"recipient\"}\n").unwrap();

        let store = Arc::new(test_store(temp.path()));
        let now = crate::link::now_ms();
        let rowed = store
            .upsert_account_from_signal("+15555550100", Some(now), DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let disk_window = store
            .upsert_account_from_signal("+15555550101", Some(now), DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let expired = store
            .upsert_account_from_signal("+15555550102", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();

        let cancels = StdMutex::new(HashSet::new());

        // Archive on disk, no row, no marker: pending, and no engine consult
        // — the sweep or watcher claims it within seconds.
        let (status, consult) =
            history_import_status_projection(&store, &signal_data, &cancels, &disk_window.id)
                .unwrap();
        assert_eq!(status["state"], "pending");
        assert!(!consult);

        // The cancel marker beats the disk face: unavailable/cancelled, no
        // consult — no pending face may resurrect a cancelled account.
        cancels.lock().unwrap().insert(disk_window.id.clone());
        let (status, consult) =
            history_import_status_projection(&store, &signal_data, &cancels, &disk_window.id)
                .unwrap();
        assert_eq!(status["state"], "unavailable");
        assert_eq!(status["reason"], "cancelled");
        assert!(!consult);
        cancels.lock().unwrap().remove(&disk_window.id);

        // A persisted row wins over even the marker (the ledger is the
        // truth): running, no consult flag.
        cancels.lock().unwrap().insert(rowed.id.clone());
        store.begin_history_import(&rowed.id, now).unwrap();
        let (status, consult) =
            history_import_status_projection(&store, &signal_data, &cancels, &rowed.id).unwrap();
        assert_eq!(status["state"], "running");
        assert!(!consult);

        // Archive removed inside the wait window: pending WITH the consult
        // flag — the one state the engine's terminal snapshot can resolve.
        std::fs::remove_file(&archive).unwrap();
        let (status, consult) =
            history_import_status_projection(&store, &signal_data, &cancels, &disk_window.id)
                .unwrap();
        assert_eq!(status["state"], "pending");
        assert!(consult);

        // Window expired, no archive, no row: the pre-1.48 informational
        // face, no consult.
        let (status, consult) =
            history_import_status_projection(&store, &signal_data, &cancels, &expired.id).unwrap();
        assert_eq!(status["state"], "unavailable");
        assert_eq!(status["reason"], "no-archive");
        assert!(!consult);
    }

    /// §4.146: the eligibility probe answers Done for a cancelled account —
    /// the link watcher exits and the sweep skips on its next tick — and
    /// Ready for the same account without the marker.
    #[test]
    fn probe_history_import_honors_the_cancel_marker() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let account_dir = signal_data.join("accounts").join("lk-probe");
        std::fs::create_dir_all(&account_dir).unwrap();
        std::fs::write(
            signal_data.join("engine-state.json"),
            r#"{"version":2,"accounts":[{"number":"+15555550100","dir":"accounts/lk-probe"}]}"#,
        )
        .unwrap();
        std::fs::write(
            account_dir.join("history-import.ndjson"),
            "{\"type\":\"recipient\"}\n",
        )
        .unwrap();
        let store = Arc::new(test_store(temp.path()));
        let account = store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();

        let cancels = StdMutex::new(HashSet::new());
        let probe = probe_history_import(&store, &signal_data, &account.id, &cancels);
        let HistoryImportProbe::Ready(job) = probe else {
            panic!("archive present with no marker must be Ready");
        };
        assert_eq!(job.account_id, account.id);
        assert_eq!(job.signal_account, "+15555550100");

        cancels.lock().unwrap().insert(account.id.clone());
        assert!(matches!(
            probe_history_import(&store, &signal_data, &account.id, &cancels),
            HistoryImportProbe::Done
        ));
    }

    /// §4.69 cloudStatus shape gate (contract 1.83): well-formed snapshots
    /// mirror key-for-key with an absent `bytesTotal` staying an honest
    /// absence, and every malformed present-face fails UPSTREAM_PROTOCOL_ERROR
    /// rather than degrading to `present:false` (a read that delivered junk
    /// knows nothing — claiming absence would be the fake-0 lie in state form).
    #[test]
    fn cloud_status_projection_gates_the_engine_shape() {
        let absent = cloud_status_from_engine(&json!({ "present": false })).unwrap();
        assert_eq!(absent, json!({ "present": false }));

        let downloading = cloud_status_from_engine(&json!({
            "present": true,
            "phase": "downloading",
            "bytesRead": 40,
            "bytesTotal": 100
        }))
        .unwrap();
        assert_eq!(
            downloading,
            json!({ "present": true, "phase": "downloading", "bytesRead": 40, "bytesTotal": 100 })
        );

        // The honest-uncertainty form: no total is no key, never a zero.
        let totalless = cloud_status_from_engine(&json!({
            "present": true,
            "phase": "downloading",
            "bytesRead": 40
        }))
        .unwrap();
        assert_eq!(
            totalless,
            json!({ "present": true, "phase": "downloading", "bytesRead": 40 })
        );
        assert!(totalless.get("bytesTotal").is_none());

        let failed = cloud_status_from_engine(&json!({
            "present": true,
            "phase": "failed",
            "bytesRead": 40,
            "errorCode": "BACKUP_DOWNLOAD_FAILED"
        }))
        .unwrap();
        assert_eq!(failed["phase"], "failed");
        assert_eq!(failed["errorCode"], "BACKUP_DOWNLOAD_FAILED");

        for junk in [
            json!({}),
            json!({ "present": "yes" }),
            json!({ "present": true }),
            json!({ "present": true, "phase": "downloading" }),
            json!({ "present": true, "phase": "teleporting", "bytesRead": 1 }),
            json!({ "present": true, "phase": "downloading", "bytesRead": "40" }),
            json!({
                "present": true,
                "phase": "downloading",
                "bytesRead": 40,
                "bytesTotal": "100"
            }),
            json!({
                "present": true,
                "phase": "failed",
                "bytesRead": 40,
                "errorCode": 7
            }),
        ] {
            let error = cloud_status_from_engine(&junk)
                .expect_err("malformed snapshots must fail the gate")
                .into_api();
            assert_eq!(error.code, "UPSTREAM_PROTOCOL_ERROR", "{junk}");
            assert!(error.retryable, "{junk}");
        }
    }

    /// §4.72 uploadStatus shape gate (contract 1.87, engine
    /// cloud-backup-contract §6.2): well-formed snapshots mirror key-for-key
    /// across the three-phase set (exporting with its zero-count face,
    /// uploading with and without a total — an absent `bytesTotal` staying
    /// an honest absence —, failed with the structured errorCode), and
    /// every malformed present-face fails UPSTREAM_PROTOCOL_ERROR rather
    /// than degrading to `present:false` (a read that delivered junk knows
    /// nothing — claiming absence would be the fake-0 lie in state form).
    #[test]
    fn upload_status_projection_gates_the_engine_shape() {
        let absent = upload_status_from_engine(&json!({ "present": false })).unwrap();
        assert_eq!(absent, json!({ "present": false }));

        let exporting = upload_status_from_engine(&json!({
            "present": true,
            "phase": "exporting",
            "bytesRead": 0
        }))
        .unwrap();
        assert_eq!(
            exporting,
            json!({ "present": true, "phase": "exporting", "bytesRead": 0 })
        );
        assert!(
            exporting.get("bytesTotal").is_none(),
            "the assembly stage carries no total: {exporting}"
        );

        let uploading = upload_status_from_engine(&json!({
            "present": true,
            "phase": "uploading",
            "bytesRead": 131072,
            "bytesTotal": 1048576
        }))
        .unwrap();
        assert_eq!(
            uploading,
            json!({
                "present": true,
                "phase": "uploading",
                "bytesRead": 131072,
                "bytesTotal": 1048576
            })
        );

        // The honest-uncertainty form: no total is no key, never a zero.
        let totalless = upload_status_from_engine(&json!({
            "present": true,
            "phase": "uploading",
            "bytesRead": 131072
        }))
        .unwrap();
        assert_eq!(
            totalless,
            json!({ "present": true, "phase": "uploading", "bytesRead": 131072 })
        );
        assert!(totalless.get("bytesTotal").is_none());

        let failed = upload_status_from_engine(&json!({
            "present": true,
            "phase": "failed",
            "bytesRead": 131072,
            "errorCode": "BACKUP_UPLOAD_FAILED"
        }))
        .unwrap();
        assert_eq!(failed["phase"], "failed");
        assert_eq!(failed["errorCode"], "BACKUP_UPLOAD_FAILED");

        for junk in [
            json!({}),
            json!({ "present": "yes" }),
            json!({ "present": true }),
            json!({ "present": true, "phase": "uploading" }),
            // The restore phase enum does not pass the upload gate (and
            // vice versa): the two faces keep their own phase sets.
            json!({ "present": true, "phase": "downloading", "bytesRead": 1 }),
            json!({ "present": true, "phase": "teleporting", "bytesRead": 1 }),
            json!({ "present": true, "phase": "uploading", "bytesRead": "40" }),
            json!({
                "present": true,
                "phase": "uploading",
                "bytesRead": 40,
                "bytesTotal": "100"
            }),
            json!({
                "present": true,
                "phase": "failed",
                "bytesRead": 40,
                "errorCode": 7
            }),
        ] {
            let error = upload_status_from_engine(&junk)
                .expect_err("malformed snapshots must fail the gate")
                .into_api();
            assert_eq!(error.code, "UPSTREAM_PROTOCOL_ERROR", "{junk}");
            assert!(error.retryable, "{junk}");
        }
    }

    /// The cloud-archive freshness face (contract revision 1.84): absent is
    /// `None`, present is the `(mtime, len)` identity, and a rewrite with
    /// different bytes presents a different face — the watcher's stale-file
    /// guard.
    #[test]
    fn cloud_archive_face_tracks_presence_and_rewrite() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("history-import-cloud.ndjson");
        assert_eq!(cloud_archive_face(&archive), None, "absent is None");

        std::fs::write(&archive, b"first").unwrap();
        let first = cloud_archive_face(&archive).expect("present file has a face");
        assert_eq!(first.1, 5, "the face carries the byte length");
        assert_eq!(
            cloud_archive_face(&archive),
            Some(first),
            "stable when untouched"
        );

        // A fresh engine write (different bytes) must present a different
        // face — this is the only definite success signal, because the
        // engine's snapshot clears on success and `{present: false}` is the
        // same answer a never-started or restarted engine gives.
        std::fs::write(&archive, b"second write").unwrap();
        let second = cloud_archive_face(&archive).expect("rewritten file has a face");
        assert_ne!(first, second, "a rewrite changes the face");
    }

    /// Every test store is encrypted (Phase 3); secondary observer connections
    /// to the same file must present the same key.
    const TEST_KEY_BYTES: [u8; 32] = [0x5A; 32];

    fn test_store(dir: &std::path::Path) -> Store {
        Store::open(dir, Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap()
    }

    /// Contract 1.197 (§4.197, D4): every per-account in-memory cache is
    /// dropped with the account, and a neighbour's entries survive.
    #[tokio::test]
    async fn account_delete_drops_every_per_account_cache() {
        let temp = TempDir::new().unwrap();
        let store = Arc::new(test_store(temp.path()));
        let config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        let supervisor =
            RuntimeSupervisor::new(config, store, DEFAULT_PROXY_GROUP_ID.to_string(), None);
        supervisor
            .backup_counters
            .lock()
            .unwrap()
            .insert("acct-a".into(), Default::default());
        supervisor
            .backup_counters
            .lock()
            .unwrap()
            .insert("acct-b".into(), Default::default());
        supervisor
            .receipt_failures
            .lock()
            .unwrap()
            .insert("acct-a\u{0}conv\u{0}read".into(), std::time::Instant::now());
        supervisor
            .receipt_failures
            .lock()
            .unwrap()
            .insert("acct-b\u{0}conv\u{0}read".into(), std::time::Instant::now());
        supervisor
            .group_resync_stamps
            .lock()
            .unwrap()
            .insert(("acct-a".into(), "group-1".into()), 1);
        supervisor
            .group_resync_stamps
            .lock()
            .unwrap()
            .insert(("acct-b".into(), "group-1".into()), 1);
        supervisor
            .history_import_cancels
            .lock()
            .unwrap()
            .insert("acct-a".into());

        supervisor.clear_account_delete_files("acct-a");

        assert!(
            !supervisor
                .backup_counters
                .lock()
                .unwrap()
                .contains_key("acct-a")
        );
        assert!(
            supervisor
                .backup_counters
                .lock()
                .unwrap()
                .contains_key("acct-b")
        );
        assert!(
            !supervisor
                .receipt_failures
                .lock()
                .unwrap()
                .keys()
                .any(|key| key.starts_with("acct-a\u{0}"))
        );
        assert!(
            supervisor
                .receipt_failures
                .lock()
                .unwrap()
                .contains_key("acct-b\u{0}conv\u{0}read")
        );
        assert!(
            !supervisor
                .group_resync_stamps
                .lock()
                .unwrap()
                .contains_key(&("acct-a".into(), "group-1".into()))
        );
        assert!(
            supervisor
                .group_resync_stamps
                .lock()
                .unwrap()
                .contains_key(&("acct-b".into(), "group-1".into()))
        );
        assert!(
            !supervisor
                .history_import_cancels
                .lock()
                .unwrap()
                .contains("acct-a")
        );
    }

    fn keyed_observer(store: &Store) -> Connection {
        let conn = Connection::open(store.path()).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{}'\"",
            hex::encode(TEST_KEY_BYTES)
        ))
        .unwrap();
        conn
    }

    #[test]
    fn prefers_profile_given_and_family_name() {
        let item = json!({
            "number": "+15555550100",
            "name": "Contact",
            "username": "user.01",
            "profile": { "givenName": "Ada", "familyName": "Lovelace" }
        });
        assert_eq!(
            compose_contact_display_name(&item).as_deref(),
            Some("Ada Lovelace")
        );
    }

    /// Contract 1.176 (§4.176): the contact row's `extra` JSON carries the
    /// raw upstream `JsonContact.username` verbatim-trimmed and bounded —
    /// absent/blank leaves no marker, over-budget drops the key whole (a
    /// clipped username would resolve the wrong account), so pre-1.176 rows
    /// and peers without a username stay byte-identical on the wire.
    #[test]
    fn contact_extra_json_captures_bounded_username() {
        use super::contact_extra_json;
        assert_eq!(
            contact_extra_json(Some("ybx0614.42")),
            Some(r#"{"username":"ybx0614.42"}"#.to_string())
        );
        assert_eq!(
            contact_extra_json(Some("  ybx0614.42  ")),
            Some(r#"{"username":"ybx0614.42"}"#.to_string())
        );
        assert_eq!(contact_extra_json(None), None);
        assert_eq!(contact_extra_json(Some("   ")), None);
        assert!(contact_extra_json(Some(&"a".repeat(64))).is_some());
        assert_eq!(contact_extra_json(Some(&"a".repeat(65))), None);
    }

    /// Contract 1.65 (§4.58): the factor stamp serializes exactly the flags
    /// the engine item exposed — upstream `JsonContact` names minus the `is`
    /// prefix — and an item without any of the three stamps the honest
    /// probed-absent `{}` so the probe never re-fires for the row.
    #[test]
    fn mrr_factor_stamp_carries_exactly_the_exposed_flags() {
        use super::{contact_item_peer_key, mrr_factors_stamp};
        let contact_item = json!({
            "number": "+15555550101",
            "isBlocked": false,
            "isHidden": true,
            "profileSharing": false
        });
        assert_eq!(
            mrr_factors_stamp(&contact_item),
            r#"{"blocked":false,"hidden":true,"profileSharing":false}"#
        );
        assert_eq!(contact_item_peer_key(&contact_item), Some("+15555550101"));

        let kt_engine = json!({ "number": "+15555550102", "name": "Peer" });
        assert_eq!(mrr_factors_stamp(&kt_engine), "{}");
        assert_eq!(contact_item_peer_key(&kt_engine), Some("+15555550102"));

        // The address ladder: number wins before uuid, the numberUuid tail
        // included; an identity-less item contributes nothing.
        let uuid_only = json!({
            "uuid": "abcd1234-0000-0000-0000-000000000000",
            "numberUuid": "abcd1234-0000-0000-0000-000000000001"
        });
        assert_eq!(
            contact_item_peer_key(&uuid_only),
            Some("abcd1234-0000-0000-0000-000000000000")
        );
        assert_eq!(contact_item_peer_key(&json!({"name": "x"})), None);
    }

    /// 契约 1.268（§4.252 · 批 Z12 · S16）：回写目标纯面四臂——显式位 ∧
    /// 变化（初写 None→true/false 与翻转 true→false 都收）；显式位 ∧ 同值
    /// 不收；isHidden 缺席不收（未知绝不冒充变化）；uuid 缺席不收（引擎面
    /// 只收 ACI）；帽 16/轮（余量留下一节流窗口）。
    #[test]
    fn hidden_write_back_targets_collect_changed_bits_only() {
        let item = |uuid: &str, is_hidden: Option<bool>| {
            let mut object = serde_json::json!({ "uuid": uuid });
            if let Some(hidden) = is_hidden {
                object["isHidden"] = serde_json::json!(hidden);
            }
            object
        };
        let prevs: std::collections::HashMap<&str, Option<bool>> = [
            ("new-hidden", None),
            ("same-false", Some(false)),
            ("flip-true", Some(false)),
            ("flip-false", Some(true)),
            ("same-true", Some(true)),
        ]
        .into_iter()
        .collect();
        let prev_of = |uuid: &str| prevs.get(uuid).copied().flatten();
        let items = vec![
            item("new-hidden", Some(true)),
            item("same-false", Some(false)),
            item("flip-true", Some(true)),
            item("flip-false", Some(false)),
            item("same-true", Some(true)),
            item("unknown-arm", None),
            serde_json::json!({ "isHidden": true }),
        ];
        let targets = hidden_write_back_targets(&items, &prev_of);
        assert_eq!(
            targets,
            vec![
                ("new-hidden".to_string(), true),
                ("flip-true".to_string(), true),
                ("flip-false".to_string(), false),
            ]
        );
        // 帽 16/轮：17 个变化目标只收前 16。
        let flood: Vec<serde_json::Value> = (0..17)
            .map(|index| item(&format!("u{index}"), Some(true)))
            .collect();
        let targets = hidden_write_back_targets(&flood, &|_| None);
        assert_eq!(targets.len(), 16);
    }

    #[tokio::test]
    async fn history_retention_runs_once_per_start_in_the_background() {
        let temp = TempDir::new().unwrap();
        let store = test_store(temp.path());
        let account = store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let conversation = store
            .ensure_conversation(&account.id, "direct", "+15555550101", "contact")
            .unwrap();
        let expired_at = crate::link::now_ms() - 400 * 24 * 60 * 60 * 1_000;
        let mut expired = MessageRecord {
            is_erased: false,
            delete_failed: false,
            required_protocol_version: None,
            author_aci: None,
            id: "expired".into(),
            account_id: account.id.clone(),
            conversation_id: conversation.id.clone(),
            direction: "incoming",
            sender_id: "peer".into(),
            sender_name: None,
            mentions_self: false,
            sent_at: expired_at,
            received_at: Some(expired_at),
            text: Some("body".into()),
            text_bytes: Some(4),
            text_truncated: false,
            text_retrievable: true,
            status: "delivered",
            client_request_id: None,
            quote_message_id: None,
            quote_snapshot: None,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            edited_at: None,
            reactions: Vec::new(),
            edits: Vec::new(),
            delivered_at: None,
            read_at: None,
            viewed_at: None,
            send_outcomes: None,
            admin_deleted: false,
            sticker: None,
            expire_seconds: None,
            expire_start_at: None,
            server_guid: None,
            server_timestamp: None,
            is_story: false,
            story_message: None,
        };
        store
            .insert_message(&expired, None, Some("body"), true)
            .unwrap();
        let observer = keyed_observer(&store);
        let backdate = |id: &str| {
            observer
                .execute(
                    "UPDATE messages SET stored_at=?2 WHERE id=?1",
                    rusqlite::params![id, expired_at as i64],
                )
                .unwrap();
        };
        backdate("expired");
        let stored = || {
            observer
                .query_row("SELECT COUNT(*) FROM messages", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        let supervisor = Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            Arc::new(store),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));

        supervisor.spawn_history_retention();
        timeout(Duration::from_secs(2), async {
            while stored() != 0 {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("retention should drop expired history");

        // Asking again is a no-op for the life of the process.
        expired.id = "expired-later".into();
        supervisor
            .service
            .lock()
            .await
            .store_ref()
            .insert_message(&expired, None, Some("body"), true)
            .unwrap();
        backdate("expired-later");
        supervisor.spawn_history_retention();
        sleep(Duration::from_millis(200)).await;
        assert_eq!(stored(), 1);
    }

    #[tokio::test]
    async fn failed_receive_persistence_is_retained_and_recovers() {
        let temp = TempDir::new().unwrap();
        let store = test_store(temp.path());
        store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let recovery = keyed_observer(&store);
        recovery
            .execute_batch(
                "CREATE TRIGGER fail_receive_insert
                 BEFORE INSERT ON messages
                 BEGIN SELECT RAISE(FAIL, 'controlled test failure'); END;",
            )
            .unwrap();
        let supervisor = RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            Arc::new(store),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        );
        let mut host_events = supervisor.subscribe_host();
        supervisor
            .receive_ingress
            .enqueue(NormalizedReceive {
                required_protocol_version: None,
                timestamp: Some(42),
                content_kind: "dataMessage",
                direction: "incoming",
                account_present: true,
                account: Some("+15555550100".into()),
                source: Some("+15555550101".into()),
                source_uuid: None,
                peer_name: Some("Peer".into()),
                group_id: None,
                text: Some("persist me".into()),
                text_bytes: Some(10),
                text_truncated: false,
                quote: None,
                attachments: Vec::new(),
                rich: None,
                sticker: None,
                expire_seconds: None,
                expire_start_at: None,
                control: None,
                server_guid: None,
                reporting_token: None,
                server_timestamp: None,
            })
            .await
            .unwrap();

        let unavailable = timeout(Duration::from_secs(1), host_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            unavailable,
            HostSideEvent::StorageChanged {
                state: "unavailable"
            }
        ));
        recovery
            .execute_batch("DROP TRIGGER fail_receive_insert;")
            .unwrap();

        let (saw_message, saw_recovered) = timeout(Duration::from_secs(2), async {
            let mut saw_message = false;
            loop {
                match host_events.recv().await.unwrap() {
                    HostSideEvent::MessageUpserted(message) => {
                        saw_message = message.text.as_deref() == Some("persist me");
                    }
                    HostSideEvent::StorageChanged { state: "recovered" } => {
                        break (saw_message, true);
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        assert!(saw_message);
        assert!(saw_recovered);
    }

    /// Contract 1.170 (§4.170): the account-sync seam folds the freshly
    /// ACI'd account's number-keyed memo shell into the canonical ACI-keyed
    /// row and announces exactly the canonical summary on the host lane —
    /// the message material moves with it and the shell row is gone.
    #[tokio::test]
    async fn account_sync_backfills_the_memo_identity_and_announces_the_canonical_row() {
        let temp = TempDir::new().unwrap();
        let store = Arc::new(test_store(temp.path()));
        let supervisor = RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            store.clone(),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        );
        let mut host_events = supervisor.subscribe_host();

        let account = store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let shell = store
            .ensure_conversation(&account.id, "direct", "+15555550100", "Note to Self")
            .unwrap();
        store
            .insert_message(
                &MessageRecord {
                    is_erased: false,
                    delete_failed: false,
                    required_protocol_version: None,
                    author_aci: None,
                    id: "m-shell-1".into(),
                    account_id: account.id.clone(),
                    conversation_id: shell.id.clone(),
                    direction: "outgoing",
                    sender_id: "self".into(),
                    sender_name: None,
                    mentions_self: false,
                    sent_at: 1_000,
                    received_at: None,
                    text: Some("memo body".into()),
                    text_bytes: Some(9),
                    text_truncated: false,
                    text_retrievable: true,
                    status: "sent",
                    client_request_id: None,
                    quote_message_id: None,
                    quote_snapshot: None,
                    quote: None,
                    attachments: Vec::new(),
                    edited_at: None,
                    rich: None,
                    reactions: Vec::new(),
                    edits: Vec::new(),
                    delivered_at: None,
                    read_at: None,
                    viewed_at: None,
                    send_outcomes: None,
                    sticker: None,
                    expire_seconds: None,
                    expire_start_at: None,
                    admin_deleted: false,
                    server_guid: None,
                    server_timestamp: None,
                    is_story: false,
                    story_message: None,
                },
                None,
                Some("memo body"),
                false,
            )
            .unwrap();
        let aci = crate::store::canonical_aci("18E2E00B2AC755ECA25DD5646A80C042").unwrap();
        store.set_account_aci(&account.id, Some(&aci)).unwrap();

        supervisor
            .backfill_memo_identities(std::slice::from_ref(&account))
            .await;

        // The fold announces exactly the canonical row, marked self.
        let summary = match host_events.try_recv().unwrap() {
            HostSideEvent::ConversationChanged(summary) => summary,
            other => panic!("expected ConversationChanged, got {other:?}"),
        };
        let canonical = store
            .conversation_by_peer(&account.id, "direct", &aci)
            .unwrap()
            .expect("the canonical row exists");
        assert_eq!(summary.id, canonical.id);
        assert!(summary.is_self);

        // The shell is gone and the message moved with the fold.
        assert!(
            store
                .conversation_by_peer(&account.id, "direct", "+15555550100")
                .unwrap()
                .is_none()
        );
        let moved: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE conversation_id=?1",
                rusqlite::params![canonical.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(moved, 1);
    }

    #[test]
    fn falls_back_to_username() {
        let item = json!({
            "number": "+15555550100",
            "username": "signal.user",
            "profile": {}
        });
        assert_eq!(
            compose_contact_display_name(&item).as_deref(),
            Some("signal.user")
        );
    }

    /// The §4.53 requesting-members identity read: both identities of a
    /// candidate (number and uuid) land in the set, an address-less or
    /// malformed entry drops, a missing/foreign listGroups answer reads as
    /// empty (the fold's fail-closed direction), and the fold keeps only
    /// candidates the engine still reports requesting, in caller order.
    #[test]
    fn join_request_fold_keeps_only_requesting_candidates() {
        use super::{fold_join_request_candidates, requesting_member_identities};

        let listed = json!([
            {
                "id": "ZmFrZS1ncm91cC0x",
                "name": "Fixture Group",
                "isMember": true,
                "requestingMembers": [
                    {"number": "+15555550101"},
                    {
                        "number": "+15555550102",
                        "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10"
                    },
                    {"uuid": "0b7fca57-abcd-4d0e-9b0f-4f6c1f8a2e10"},
                    {},
                    {"number": 12345},
                    "not-an-object"
                ]
            }
        ]);
        let requesting = requesting_member_identities(&listed);
        assert!(requesting.contains("+15555550101"));
        assert!(requesting.contains("+15555550102"));
        assert!(requesting.contains("0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10"));
        assert!(requesting.contains("0b7fca57-abcd-4d0e-9b0f-4f6c1f8a2e10"));
        assert_eq!(requesting.len(), 4, "address-less/malformed entries drop");

        // The fold: requesting candidates survive in caller order; a stale
        // or mistaken candidate (an existing member, a stranger) drops.
        let folded = fold_join_request_candidates(
            vec![
                "+15555550102".into(),
                "+15555550999".into(),
                "+15555550101".into(),
            ],
            &requesting,
        );
        assert_eq!(
            folded,
            vec!["+15555550102".to_string(), "+15555550101".to_string()]
        );

        // The fail-closed direction: an engine answer without the face (or
        // a foreign shape) reads as empty and the fold empties — nothing
        // rides the member arrays.
        assert!(requesting_member_identities(&json!([])).is_empty());
        assert!(requesting_member_identities(&json!({"error": 1})).is_empty());
        assert!(requesting_member_identities(&json!([{"members": []}])).is_empty());
        assert!(
            fold_join_request_candidates(
                vec!["+15555550101".into()],
                &requesting_member_identities(&json!([]))
            )
            .is_empty()
        );
    }

    /// The §4.57 pending-invitees identity read: both identities of an
    /// invitee (number and uuid) land in the set, an address-less or
    /// malformed entry drops, a missing/foreign listGroups answer reads as
    /// empty (the fold's fail-closed direction), and the fold keeps only
    /// candidates the engine still reports pending, in caller order.
    #[test]
    fn invite_fold_keeps_only_pending_candidates() {
        use super::{fold_invite_candidates, pending_member_identities};

        let listed = json!([
            {
                "id": "ZmFrZS1ncm91cC0x",
                "name": "Fixture Group",
                "isMember": true,
                "pendingMembers": [
                    {"number": "+15555550101"},
                    {
                        "number": "+15555550102",
                        "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10"
                    },
                    {"uuid": "0b7fca57-abcd-4d0e-9b0f-4f6c1f8a2e10"},
                    {},
                    {"number": 12345},
                    "not-an-object"
                ]
            }
        ]);
        let pending = pending_member_identities(&listed);
        assert!(pending.contains("+15555550101"));
        assert!(pending.contains("+15555550102"));
        assert!(pending.contains("0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10"));
        assert!(pending.contains("0b7fca57-abcd-4d0e-9b0f-4f6c1f8a2e10"));
        assert_eq!(pending.len(), 4, "address-less/malformed entries drop");

        // The fold: pending invitees survive in caller order; a stale or
        // mistaken candidate (an existing member, a stranger) drops — never
        // rides the removeMembers array.
        let folded = fold_invite_candidates(
            vec![
                "+15555550102".into(),
                "+15555550999".into(),
                "+15555550101".into(),
            ],
            &pending,
        );
        assert_eq!(
            folded,
            vec!["+15555550102".to_string(), "+15555550101".to_string()]
        );

        // The fail-closed direction: an engine answer without the face (or
        // a foreign shape) reads as empty and the fold empties — nothing
        // rides the removeMembers array.
        assert!(pending_member_identities(&json!([])).is_empty());
        assert!(pending_member_identities(&json!({"error": 1})).is_empty());
        assert!(pending_member_identities(&json!([{"members": []}])).is_empty());
        assert!(
            fold_invite_candidates(
                vec!["+15555550101".into()],
                &pending_member_identities(&json!([]))
            )
            .is_empty()
        );
    }

    /// The §4.39 roster capture (contract revision 1.40): the historical
    /// signal-cli member/admin shapes mark admins through both channels, the
    /// kt-signal-engine shape marks none, address-less entries drop
    /// individually, and the roster cap holds while memberCount keeps the
    /// upstream length.
    /// Contract 1.255 (§4.240): the engine face's member word is captured
    /// only when explicitly false — the left/kicked residual the read side
    /// projects onto the official removalStage vocabulary; true and absent
    /// collapse to the absent marker (the healthy default never writes a
    /// key), and the terminated capture beside it stays independent.
    #[test]
    fn group_extra_json_captures_the_member_word_when_false() {
        use super::group_extra_json;
        let members = serde_json::json!([
            {"number": "+15555550101", "role": "DEFAULT"}
        ]);
        let removed = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &serde_json::json!({"id": "aWQ=", "isMember": false}),
        ))
        .unwrap();
        assert_eq!(removed["isMember"], serde_json::json!(false));
        let member = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &serde_json::json!({"id": "aWQ=", "isMember": true}),
        ))
        .unwrap();
        assert!(member.get("isMember").is_none());
        let absent = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &serde_json::json!({"id": "aWQ="}),
        ))
        .unwrap();
        assert!(absent.get("isMember").is_none());
        // The Gone stamp's shape — the legacy terminated face rides beside
        // the member word, one marker, two independent words.
        let gone =
            serde_json::from_str::<serde_json::Value>(r#"{"isTerminated":true,"isMember":false}"#)
                .unwrap();
        assert_eq!(gone["isTerminated"], serde_json::json!(true));
        assert_eq!(gone["isMember"], serde_json::json!(false));
    }

    #[test]
    fn group_extra_json_captures_the_bounded_roster() {
        use super::group_extra_json;
        // Pinned 0.14.8 shape: `members` carry {number, uuid, isAdmin}, the
        // group carries a separate `admins` address set. Alice is marked by
        // her per-member flag, Bob only through the admins set (his uuid),
        // and the address-less entry drops without failing the batch.
        let group = json!({
            "id": "ZmFrZS1ncm91cC0x",
            "name": "Fixture Group",
            "isMember": true,
            "admins": [{"uuid": "0b7fca57-6c3d-4a9e-b3e8-2f14c5d6a7b9"}],
        });
        let members = json!([
            {"number": "+15555550100"},
            {"number": "+15555550101", "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10", "isAdmin": true},
            {"uuid": "0b7fca57-6c3d-4a9e-b3e8-2f14c5d6a7b9"},
            {},
            "not-an-object",
        ]);
        let extra: serde_json::Value =
            serde_json::from_str(&group_extra_json(members.as_array().unwrap(), &group)).unwrap();
        assert_eq!(extra["memberCount"], 5);
        let roster = extra["members"].as_array().unwrap();
        assert_eq!(
            roster,
            &[
                json!({"id": "+15555550100"}),
                json!({
                    "id": "+15555550101",
                    "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                    "admin": true,
                }),
                json!({"id": "0b7fca57-6c3d-4a9e-b3e8-2f14c5d6a7b9", "admin": true}),
            ]
        );

        // Engine shape (kt-signal-engine listGroups): number-labeled entries
        // without a uuid key, carrying the GV2 `role` word — the
        // ADMINISTRATOR fold landed with contract 1.181 (§4.39's
        // "engine-mode rosters carry none" boundary described the capture's
        // own silence, not the engine's face); DEFAULT and UNKNOWN are
        // member states and never admin.
        let engine_group = json!({"id": "aWQ", "name": "g", "isMember": true});
        let engine_members = json!([
            {"number": "+15555550100", "role": "ADMINISTRATOR"},
            {"number": "+15555550101", "role": "DEFAULT"},
            {"number": "+15555550102", "role": "UNKNOWN"},
            {"number": "+15555550103"},
            {"number": "+15555550104", "role": "administrator"},
        ]);
        let extra: serde_json::Value = serde_json::from_str(&group_extra_json(
            engine_members.as_array().unwrap(),
            &engine_group,
        ))
        .unwrap();
        assert_eq!(
            extra["members"],
            json!([
                {"id": "+15555550100", "admin": true},
                {"id": "+15555550101"},
                {"id": "+15555550102"},
                {"id": "+15555550103"},
                {"id": "+15555550104"},
            ])
        );

        // The roster cap is the official group-size ceiling; memberCount
        // keeps the upstream length even when the roster truncates.
        let flood: Vec<serde_json::Value> = (0..crate::service::MAX_GROUP_MEMBERS + 10)
            .map(|index| json!({"number": format!("+1555555{index:04}")}))
            .collect();
        let extra: serde_json::Value = serde_json::from_str(&group_extra_json(
            &flood,
            &json!({"id": "aWQ", "isMember": true}),
        ))
        .unwrap();
        assert_eq!(extra["memberCount"], crate::service::MAX_GROUP_MEMBERS + 10);
        assert_eq!(
            extra["members"].as_array().unwrap().len(),
            crate::service::MAX_GROUP_MEMBERS
        );

        // Contract 1.53 (§4.50 appendix): the upstream isTerminated flag is
        // captured only when true — false and absent collapse to absent (the
        // informative-keys discipline), engines without the flag never set
        // it.
        let plain = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "isTerminated": false}),
        ))
        .unwrap();
        assert!(plain.get("isTerminated").is_none());
        let terminated = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "isTerminated": true}),
        ))
        .unwrap();
        assert_eq!(terminated["isTerminated"], serde_json::json!(true));

        // Contract 1.180 (§4.180): the upstream JsonGroup.addFromInviteLink
        // word is captured as `linkAccess` — only the official vocabulary
        // (ANY/ADMINISTRATOR/UNSATISFIABLE, the official
        // buildAccessControlAddFromInviteLinkChange enum); MEMBER/UNKNOWN/
        // malformed and absent all collapse to an absent key (unknown,
        // never a lie — the engines-without-the-face and pre-1.180 rows
        // answer the same absent key).
        for word in ["ANY", "ADMINISTRATOR", "UNSATISFIABLE"] {
            let extra = serde_json::from_str::<serde_json::Value>(&group_extra_json(
                members.as_array().unwrap(),
                &json!({"id": "aWQ", "isMember": true, "addFromInviteLink": word}),
            ))
            .unwrap();
            assert_eq!(extra["linkAccess"], serde_json::json!(word));
        }
        for word in ["MEMBER", "UNKNOWN", "not-a-word"] {
            let extra = serde_json::from_str::<serde_json::Value>(&group_extra_json(
                members.as_array().unwrap(),
                &json!({"id": "aWQ", "isMember": true, "addFromInviteLink": word}),
            ))
            .unwrap();
            assert!(extra.get("linkAccess").is_none(), "word {word} collapses");
        }
        let no_word = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true}),
        ))
        .unwrap();
        assert!(no_word.get("linkAccess").is_none());

        // Contract 1.252 (§4.237): the engine face — the only runtime —
        // never carries the top-level word; it rides inside accessControl
        // (the official client's own read position). A top-level absence
        // now falls back to the nested accessControl word under the
        // identical §4.180 vocabulary; the nested UNKNOWN (the engine's
        // unparsed fallback), MEMBER, and malformed values collapse to
        // absent exactly like their top-level twins.
        for word in ["ANY", "ADMINISTRATOR", "UNSATISFIABLE"] {
            let extra = serde_json::from_str::<serde_json::Value>(&group_extra_json(
                members.as_array().unwrap(),
                &json!({
                    "id": "aWQ",
                    "isMember": true,
                    "accessControl": {"addFromInviteLink": word},
                }),
            ))
            .unwrap();
            assert_eq!(
                extra["linkAccess"],
                serde_json::json!(word),
                "nested word {word} feeds the fallback"
            );
        }
        for word in ["MEMBER", "UNKNOWN", "not-a-word"] {
            let extra = serde_json::from_str::<serde_json::Value>(&group_extra_json(
                members.as_array().unwrap(),
                &json!({
                    "id": "aWQ",
                    "isMember": true,
                    "accessControl": {"addFromInviteLink": word},
                }),
            ))
            .unwrap();
            assert!(
                extra.get("linkAccess").is_none(),
                "nested word {word} collapses"
            );
        }
        // A malformed nested shape (non-object accessControl, non-string
        // word) drops silently — the capture never fails the sync.
        let malformed_nested = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "accessControl": 7}),
        ))
        .unwrap();
        assert!(malformed_nested.get("linkAccess").is_none());
        let malformed_word = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "accessControl": {"addFromInviteLink": 7},
            }),
        ))
        .unwrap();
        assert!(malformed_word.get("linkAccess").is_none());
        // The top-level word keeps precedence when a face carries both —
        // the engine shape (nested only) and the pinned signal-cli shape
        // (top-level only) are the only real faces; a blend never happens.
        let both = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "addFromInviteLink": "ANY",
                "accessControl": {"addFromInviteLink": "ADMINISTRATOR"},
            }),
        ))
        .unwrap();
        assert_eq!(both["linkAccess"], serde_json::json!("ANY"));
        // A top-level word outside the vocabulary collapses the key and
        // never falls through to the nested face — no cross-face guessing.
        let top_invalid = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "addFromInviteLink": "not-a-word",
                "accessControl": {"addFromInviteLink": "ANY"},
            }),
        ))
        .unwrap();
        assert!(top_invalid.get("linkAccess").is_none());

        // Contract 1.181 (§4.181): the announcements-only flag is captured
        // verbatim when the upstream JsonGroup carries the key (the engine's
        // listGroups always does — true and false both land); a face without
        // the key keeps the key absent (unknown, never a guessed false), and
        // a malformed value drops rather than fails the capture.
        for flag in [true, false] {
            let extra = serde_json::from_str::<serde_json::Value>(&group_extra_json(
                members.as_array().unwrap(),
                &json!({"id": "aWQ", "isMember": true, "announcementsOnly": flag}),
            ))
            .unwrap();
            assert_eq!(extra["announcementsOnly"], serde_json::json!(flag));
        }
        let no_flag = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true}),
        ))
        .unwrap();
        assert!(no_flag.get("announcementsOnly").is_none());
        let malformed_flag = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "announcementsOnly": "yes"}),
        ))
        .unwrap();
        assert!(malformed_flag.get("announcementsOnly").is_none());

        // Contract 1.188 (§4.188): the engine's decrypted group description
        // rides the sync capture under the write face's whole-value budget —
        // an over-budget description drops the key whole (never a truncated
        // lie), blank drops, a non-string drops, and the pinned signal-cli
        // JsonGroup shape (no description key — every earlier block above)
        // never sets it.
        let described = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "description": "周五晚上聚餐，地点老地方"}),
        ))
        .unwrap();
        assert_eq!(
            described["description"],
            serde_json::json!("周五晚上聚餐，地点老地方")
        );
        // Trim lands, blank never does.
        let padded = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "description": "  spaced  "}),
        ))
        .unwrap();
        assert_eq!(padded["description"], serde_json::json!("spaced"));
        let blank = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "description": "   "}),
        ))
        .unwrap();
        assert!(blank.get("description").is_none());
        // The budget boundary: exactly 4096 bytes lands, 4097 drops whole.
        let at_budget = "d".repeat(crate::service::GROUP_DESCRIPTION_MAX_BYTES);
        let over_budget = "d".repeat(crate::service::GROUP_DESCRIPTION_MAX_BYTES + 1);
        let fits = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "description": at_budget.clone()}),
        ))
        .unwrap();
        assert_eq!(fits["description"], serde_json::json!(at_budget));
        let drops = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "description": over_budget}),
        ))
        .unwrap();
        assert!(drops.get("description").is_none());
        let malformed_description = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "description": 7}),
        ))
        .unwrap();
        assert!(malformed_description.get("description").is_none());

        // Contract 1.221 (§4.231): the engine listGroups entry's
        // accessControl object projects arm by arm — only the two official
        // gate words (MEMBER / ADMINISTRATOR) ride; UNKNOWN/ANY/
        // UNSATISFIABLE and malformed shapes drop that arm, and the whole
        // key is absent when none survives. addFromInviteLink stays off
        // the three-arm object (the §4.180 boundary is unchanged) — and
        // since contract 1.252 (§4.237) its nested word feeds the
        // linkAccess fallback: the batch-H-era "never leaks" pin recorded
        // exactly the engine-mode linkAccess permanent absence this batch
        // fixes, so the pin flips with it.
        let triple = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "accessControl": {
                    "attributes": "MEMBER",
                    "members": "ADMINISTRATOR",
                    "memberLabel": "MEMBER",
                    "addFromInviteLink": "ADMINISTRATOR",
                },
            }),
        ))
        .unwrap();
        assert_eq!(
            triple["accessControl"],
            json!({
                "attributes": "MEMBER",
                "members": "ADMINISTRATOR",
                "memberLabel": "MEMBER",
            })
        );
        assert_eq!(
            triple["linkAccess"],
            json!("ADMINISTRATOR"),
            "the nested addFromInviteLink word feeds the §4.237 linkAccess fallback"
        );

        // Each arm is independent: a partial object keeps only the valid arm.
        let partial = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "accessControl": {"members": "MEMBER"},
            }),
        ))
        .unwrap();
        assert_eq!(partial["accessControl"], json!({"members": "MEMBER"}));

        // Every other word and shape collapses that arm; an all-invalid
        // object leaves the whole key absent (unknown, never a lie).
        let rejected = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "accessControl": {
                    "attributes": "UNKNOWN",
                    "members": "ANY",
                    "memberLabel": "UNSATISFIABLE",
                },
            }),
        ))
        .unwrap();
        assert!(rejected.get("accessControl").is_none());
        let malformed = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({
                "id": "aWQ",
                "isMember": true,
                "accessControl": {"attributes": 7, "members": null},
            }),
        ))
        .unwrap();
        assert!(malformed.get("accessControl").is_none());
        let not_an_object = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true, "accessControl": "MEMBER"}),
        ))
        .unwrap();
        assert!(not_an_object.get("accessControl").is_none());
        let absent = serde_json::from_str::<serde_json::Value>(&group_extra_json(
            members.as_array().unwrap(),
            &json!({"id": "aWQ", "isMember": true}),
        ))
        .unwrap();
        assert!(absent.get("accessControl").is_none());
    }

    #[test]
    fn group_extra_json_captures_member_labels_within_server_budgets() {
        // Contract 1.67 (§4.60): the pinned listGroups member label pair is
        // captured verbatim; label-less members, engines without the face,
        // and over-budget values (dropped, never truncated) follow the
        // informative-keys discipline.
        let group = json!({"id": "aWQ", "isMember": true});
        let members = json!([
            {
                "number": "+15555550100",
                "labelEmoji": "🛠️",
                "label": "Builders",
            },
            {"number": "+15555550101", "label": "  Design  "},
            {"number": "+15555550102", "labelEmoji": "", "label": "   "},
            {"number": "+15555550103", "label": "x".repeat(512)},
            {"number": "+15555550104", "label": "x".repeat(513)},
            {"number": "+15555550105", "labelEmoji": "x".repeat(64)},
            {"number": "+15555550106", "labelEmoji": "x".repeat(65)},
        ]);
        let extra: serde_json::Value =
            serde_json::from_str(&group_extra_json(members.as_array().unwrap(), &group)).unwrap();
        let roster = extra["members"].as_array().unwrap();
        assert_eq!(
            roster[0],
            json!({"id": "+15555550100", "labelEmoji": "🛠️", "label": "Builders"})
        );
        // Trimmed but otherwise verbatim.
        assert_eq!(roster[1]["label"], json!("Design"));
        assert!(roster[1].get("labelEmoji").is_none());
        // Empty/whitespace-only values drop (the upstream emits NON_NULL but
        // an empty string is not a label).
        assert_eq!(roster[2], json!({"id": "+15555550102"}));
        // Exactly at the 512-byte server string budget passes whole.
        assert_eq!(roster[3]["label"], json!("x".repeat(512)));
        // One byte over drops the key instead of truncating.
        assert_eq!(roster[4], json!({"id": "+15555550104"}));
        // The 64-byte emoji budget: a 64-byte value passes whole, 65 drops.
        // The budget is bytes, not graphemes.
        assert_eq!(roster[5]["labelEmoji"], json!("x".repeat(64)));
        assert_eq!(roster[6], json!({"id": "+15555550106"}));
    }

    #[test]
    fn fatal_stderr_matches_receive_websocket_failures() {
        assert!(is_receive_fatal_stderr(
            "WARN WebSocketConnection - WebSocket connection closed unexpectedly"
        ));
        assert!(is_receive_fatal_stderr(
            "ERROR o.a.s.manager.internal.ReceiveConfig - websocket error while receiving"
        ));
        assert!(is_receive_fatal_stderr(
            "org.asamk.signal.manager.WebSocketIOException: Connection reset"
        ));
        assert!(is_receive_fatal_stderr(
            "websocket disconnected from server"
        ));
        assert!(is_receive_fatal_stderr(
            "Failed to connect websocket, retrying"
        ));
        assert!(is_receive_fatal_stderr(
            "Exception in websocket reader thread"
        ));
    }

    #[test]
    fn fatal_stderr_ignores_normal_log_lines() {
        assert!(!is_receive_fatal_stderr(
            "INFO App - Starting signal-cli daemon"
        ));
        assert!(!is_receive_fatal_stderr(
            "INFO WebSocketConnection - Connected successfully"
        ));
        assert!(!is_receive_fatal_stderr(
            "INFO ManagerImpl - Checking for new messages"
        ));
        assert!(!is_receive_fatal_stderr(
            "WARN Scheduler - task failed to start" // no websocket context
        ));
        assert!(!is_receive_fatal_stderr(""));
    }

    /// The watchdog's stderr consumer grades every non-fatal line instead of
    /// dropping it (the proxy-debugging observability fix): the engine's
    /// one-shot "network path" egress banner lands at info level so the
    /// production log shows which exit the engine chose, everything else at
    /// debug only. The fatal verdict stays primary — a line matching both
    /// shapes still drives the unchanged watchdog restart path.
    #[test]
    fn stderr_classification_grades_lines_for_forwarding() {
        // The engine's egress self-check banner, verbatim shape: network
        // path wins over the debug bucket regardless of which exit (direct,
        // explicit-env, std-env, system-http, system-socks) it declares —
        // the matcher is the literal substring, never the value.
        assert_eq!(
            classify_engine_stderr(
                "kt-signal-engine: INFO network path: system-http (http://127.0.0.1:1082)"
            ),
            EngineStderrClass::NetworkPath
        );
        assert_eq!(
            classify_engine_stderr("kt-signal-engine: INFO network path: direct"),
            EngineStderrClass::NetworkPath
        );
        assert_eq!(
            classify_engine_stderr("kt-signal-engine: INFO network path: system-socks"),
            EngineStderrClass::NetworkPath
        );
        // Ordinary engine chatter (self-check INFO, WARN without the receive
        // fatal shape, even empty lines) is debug-forwarded, not dropped.
        assert_eq!(
            classify_engine_stderr("INFO App - Starting signal-cli daemon"),
            EngineStderrClass::Diagnostic
        );
        assert_eq!(
            classify_engine_stderr("INFO WebSocketConnection - Connected successfully"),
            EngineStderrClass::Diagnostic
        );
        assert_eq!(classify_engine_stderr(""), EngineStderrClass::Diagnostic);
        // Receive-fatal shapes stay on the watchdog path, unchanged.
        assert_eq!(
            classify_engine_stderr(
                "org.asamk.signal.manager.WebSocketIOException: Connection reset"
            ),
            EngineStderrClass::ReceiveFatal
        );
        assert_eq!(
            classify_engine_stderr(
                "WARN WebSocketConnection - WebSocket connection closed unexpectedly"
            ),
            EngineStderrClass::ReceiveFatal
        );
        // kt engine's recoverable reconnect/handover chatter is NOT a reason
        // to restart the process. These lines can repeat during a proxy blip;
        // the receive loop owns retry and the liveness watchdog owns death.
        assert_eq!(
            classify_engine_stderr(
                "WARN libsignal_service::websocket: websocket link is dead; closing so the receive stream reconnects cause=\"request response timeout\""
            ),
            EngineStderrClass::Diagnostic
        );
        assert_eq!(
            classify_engine_stderr(
                "WARN libsignal_service::websocket: websocket handover: terminating previous identified connection before dialing"
            ),
            EngineStderrClass::Diagnostic
        );
        assert_eq!(
            classify_engine_stderr(
                "ERROR libsignal_service::websocket: SignalWebSocket: Websocket error: tungstenite error"
            ),
            EngineStderrClass::Diagnostic
        );
        // A pathological line carrying both the banner and a fatal shape is
        // fatal first: the watchdog must never be muted by the new grading.
        assert_eq!(
            classify_engine_stderr(
                "websocketioexception after network path was declared: connection reset"
            ),
            EngineStderrClass::ReceiveFatal
        );
    }

    /// The engine runs the real fake-engine fixture (the same one the
    /// engine-integration suite drives): its `remoteDelete` handler exits with
    /// the mutating call in flight, so the upstream result is lost mid-call.
    /// The supervisor must surface that as the explicit `unknown` response —
    /// not a retryable error — and never re-issue the call.
    #[tokio::test]
    async fn remote_delete_with_a_lost_upstream_result_answers_unknown() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store.clone(),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let pending_id = match supervisor
            .service
            .lock()
            .await
            .prepare_send_text(
                &account.id,
                &conversation.id,
                "vanish",
                "req-rd-crash",
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        {
            crate::service::PreparedSend::Dispatch { pending_id, .. } => pending_id,
            crate::service::PreparedSend::Existing(_) => panic!("new client request must dispatch"),
        };
        supervisor
            .service
            .lock()
            .await
            .complete_send_success(&pending_id, &account.id, &conversation.id, 421, None)
            .unwrap();

        assert_eq!(
            supervisor
                .remote_delete(
                    account.id.clone(),
                    conversation.id.clone(),
                    pending_id.clone()
                )
                .await
                .unwrap(),
            "unknown",
            "a lost mutating result must answer unknown, never retry"
        );

        // The local row is untouched and no statusChanged event was emitted:
        // remoteDelete changes nothing locally (plan §3.6).
        let row = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .message_by_id(&account.id, &conversation.id, &pending_id)
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "sent");
        assert_eq!(row.sent_at, 421);
        supervisor.shutdown().await.unwrap();
    }

    /// The engine runs the real fake-engine fixture: its `sendReaction`
    /// handler exits with the mutating call in flight (targetTimestamp 423),
    /// so the upstream result is lost mid-call. The supervisor must surface
    /// that as the explicit `unknown` response — not a retryable error — and
    /// never re-issue the call. The local row is untouched: reactions change
    /// nothing locally (contract revision 1.7).
    #[tokio::test]
    async fn send_reaction_with_a_lost_upstream_result_answers_unknown() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let pending_id = match supervisor
            .service
            .lock()
            .await
            .prepare_send_text(
                &account.id,
                &conversation.id,
                "react to me",
                "req-sr-crash",
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        {
            crate::service::PreparedSend::Dispatch { pending_id, .. } => pending_id,
            crate::service::PreparedSend::Existing(_) => panic!("new client request must dispatch"),
        };
        supervisor
            .service
            .lock()
            .await
            .complete_send_success(&pending_id, &account.id, &conversation.id, 423, None)
            .unwrap();

        assert_eq!(
            supervisor
                .send_reaction(
                    account.id.clone(),
                    conversation.id.clone(),
                    pending_id.clone(),
                    "👍".to_string(),
                    false
                )
                .await
                .unwrap(),
            "unknown",
            "a lost mutating result must answer unknown, never retry"
        );

        // The local row is untouched and no statusChanged event was emitted:
        // sendReaction changes nothing locally (contract revision 1.7).
        let row = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .message_by_id(&account.id, &conversation.id, &pending_id)
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "sent");
        assert_eq!(row.sent_at, 423);
        supervisor.shutdown().await.unwrap();
    }

    /// 上行确认路径（fixture 正常应答，targetTimestamp≠423/351）：确认后
    /// complete 落库 own 反应（contract 1.27 actor 口径：account 本体、无名），
    /// 并向 host lane 推 conversation.changed——app 的乐观药丸由此获得权威
    /// 状态兜底，不再随窗口过期消失。
    #[tokio::test]
    async fn send_reaction_confirmed_persists_own_pill_and_pushes_conversation_changed() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let pending_id = match supervisor
            .service
            .lock()
            .await
            .prepare_send_text(
                &account.id,
                &conversation.id,
                "react confirmed",
                "req-sr-ok",
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        {
            crate::service::PreparedSend::Dispatch { pending_id, .. } => pending_id,
            crate::service::PreparedSend::Existing(_) => panic!("new client request must dispatch"),
        };
        supervisor
            .service
            .lock()
            .await
            .complete_send_success(&pending_id, &account.id, &conversation.id, 424, None)
            .unwrap();
        let mut host_lane = supervisor.subscribe_host();

        assert_eq!(
            supervisor
                .send_reaction(
                    account.id.clone(),
                    conversation.id.clone(),
                    pending_id.clone(),
                    "👍".to_string(),
                    false
                )
                .await
                .unwrap(),
            "sent"
        );

        let row = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .message_by_id(&account.id, &conversation.id, &pending_id)
            .unwrap()
            .unwrap();
        assert_eq!(row.reactions.len(), 1);
        assert_eq!(row.reactions[0].emoji, "👍");
        assert!(row.reactions[0].mine);
        assert!(row.reactions[0].actors.iter().all(|actor| actor.is_self));
        let event = tokio::time::timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("conversation.changed within timeout")
            .unwrap();
        assert!(matches!(event, HostSideEvent::ConversationChanged(_)));
        supervisor.shutdown().await.unwrap();
    }

    /// Contract 1.140 (§4.135) as amended by 1.201 (§6.5): the contacts pull no
    /// longer creates conversations at all (P0 crosstalk fix), so it also
    /// emits nothing on the host lane — a contact is not a chat. A pull inside
    /// the 60 s short-circuit window is likewise silent, and the account's chat
    /// list stays empty across both passes.
    #[tokio::test]
    async fn pull_contacts_sync_creates_no_conversations_and_emits_nothing() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        // Subscribe before any pull runs so whichever pass materializes the
        // skeletons — this call or the startup re-sync — has its change set
        // observable on the lane.
        let mut host_lane = supervisor.subscribe_host();

        supervisor.sync_contacts(&account.id).await.unwrap();

        // Drain any lane traffic the startup/self passes produced, then assert
        // the P0 invariant directly: the contacts the fixture lists are in the
        // cache, but no direct conversation was materialized for any of them.
        while timeout(Duration::from_millis(200), host_lane.recv())
            .await
            .is_ok()
        {}
        for peer_key in ["+15555550101", "+15555550102"] {
            assert!(
                supervisor
                    .service
                    .lock()
                    .await
                    .store_ref()
                    .conversation_by_peer(&account.id, "direct", peer_key)
                    .unwrap()
                    .is_none(),
                "the pull materialized a conversation for {peer_key}"
            );
        }
        // The pull may still materialize structurally-owned chats (a group the
        // account was synced into), but never a direct conversation for a person
        // it has not messaged.
        let page = supervisor
            .service
            .lock()
            .await
            .list_conversations(&account.id, 50, None)
            .unwrap();
        // The account's own Note-to-Self row is structurally owned and may
        // materialize; any *other* direct row would mean a contact became a chat.
        assert!(
            page.items
                .iter()
                .all(|row| row.kind != "direct" || row.is_self),
            "a contacts pull produced non-self direct chats: {page:?}"
        );

        // Drain the lane dry before the second pull so the silence proof is
        // about the second pass only. (Bounded: 300 ms of lane silence closes
        // the drain.)
        while let Ok(Ok(_)) = timeout(Duration::from_millis(300), host_lane.recv()).await {}

        // A second pull inside the window short-circuits: no event may arrive.
        supervisor.sync_contacts(&account.id).await.unwrap();
        let mut quiet = true;
        for _ in 0..6 {
            match timeout(Duration::from_millis(100), host_lane.recv()).await {
                Ok(Ok(HostSideEvent::ConversationChanged(_))) => {
                    quiet = false;
                    break;
                }
                Ok(Ok(_)) => {}
                _ => {}
            }
        }
        assert!(
            quiet,
            "a short-circuited pull must not emit conversation.changed"
        );
        supervisor.shutdown().await.unwrap();
    }

    /// The fixture's `sendPinMessage` handler exits with the mutating call in
    /// flight (target timestamp 424), so the upstream result is lost mid-call.
    /// sendPinMessage must answer the explicit `unknown` — never a retryable
    /// error, never an automatic retry — and write no pinned state locally
    /// (the reaction precedent, contract revision 1.33).
    #[tokio::test]
    async fn send_pin_message_with_a_lost_upstream_result_answers_unknown() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let pending_id = match supervisor
            .service
            .lock()
            .await
            .prepare_send_text(
                &account.id,
                &conversation.id,
                "pin me",
                "req-pin-crash",
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        {
            crate::service::PreparedSend::Dispatch { pending_id, .. } => pending_id,
            crate::service::PreparedSend::Existing(_) => panic!("new client request must dispatch"),
        };
        supervisor
            .service
            .lock()
            .await
            .complete_send_success(&pending_id, &account.id, &conversation.id, 424, None)
            .unwrap();

        assert_eq!(
            supervisor
                .send_pin_message(
                    account.id.clone(),
                    conversation.id.clone(),
                    pending_id.clone(),
                    Some(3600)
                )
                .await
                .unwrap(),
            "unknown",
            "a lost mutating result must answer unknown, never retry"
        );

        // No pinned state was written: the local conversation stays pin-free.
        assert!(
            supervisor
                .service
                .lock()
                .await
                .store_ref()
                .conversation_summary(&account.id, &conversation.id)
                .unwrap()
                .unwrap()
                .pinned_message
                .is_none()
        );
        supervisor.shutdown().await.unwrap();
    }

    /// 上行确认路径（fixture 正常应答，targetTimestamp≠424/352）：确认后
    /// pinned 状态落库（timed pin 带 expiry）并向 host lane 推
    /// conversation.changed；随后的 unpin 清除状态并再推一次——重载窗口
    /// 由此免重放即可渲染/摘除置顶条（contract revision 1.33）。
    #[tokio::test]
    async fn send_pin_message_confirmed_persists_pin_and_unpin_clears() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let pending_id = match supervisor
            .service
            .lock()
            .await
            .prepare_send_text(
                &account.id,
                &conversation.id,
                "pin confirmed",
                "req-pin-ok",
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        {
            crate::service::PreparedSend::Dispatch { pending_id, .. } => pending_id,
            crate::service::PreparedSend::Existing(_) => panic!("new client request must dispatch"),
        };
        supervisor
            .service
            .lock()
            .await
            .complete_send_success(&pending_id, &account.id, &conversation.id, 426, None)
            .unwrap();
        let mut host_lane = supervisor.subscribe_host();

        assert_eq!(
            supervisor
                .send_pin_message(
                    account.id.clone(),
                    conversation.id.clone(),
                    pending_id.clone(),
                    Some(3600)
                )
                .await
                .unwrap(),
            "sent"
        );
        let summary = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_summary(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        let pinned = summary.pinned_message.expect("the confirmed pin persists");
        assert_eq!(pinned.message_id, pending_id);
        assert_eq!(pinned.target_author, "+15555550100");
        assert_eq!(pinned.target_sent_timestamp, 426);
        assert!(pinned.expires_at.is_some(), "a timed pin carries expiry");
        let event = tokio::time::timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("conversation.changed within timeout")
            .unwrap();
        assert!(matches!(event, HostSideEvent::ConversationChanged(_)));

        assert_eq!(
            supervisor
                .send_unpin_message(account.id.clone(), conversation.id.clone(), pending_id)
                .await
                .unwrap(),
            "sent"
        );
        assert!(
            supervisor
                .service
                .lock()
                .await
                .store_ref()
                .conversation_summary(&account.id, &conversation.id)
                .unwrap()
                .unwrap()
                .pinned_message
                .is_none()
        );
        let event = tokio::time::timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("unpin conversation.changed within timeout")
            .unwrap();
        assert!(matches!(event, HostSideEvent::ConversationChanged(_)));
        supervisor.shutdown().await.unwrap();
    }

    /// The fixture's `updateContact` handler exits with the mutating call in
    /// flight (alias "[fixture-crash-alias]"), so the upstream result is lost
    /// mid-call. setLocalAlias must answer the explicit `unknown` — never a
    /// retryable error, never an automatic retry — and write nothing locally
    /// (contract revision 1.10).
    #[tokio::test]
    async fn set_local_alias_with_a_lost_upstream_result_answers_unknown() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();

        assert_eq!(
            supervisor
                .set_local_alias(
                    account.id.clone(),
                    conversation.peer_key.clone(),
                    "[fixture-crash-alias]".to_string()
                )
                .await
                .unwrap(),
            "unknown",
            "a lost mutating result must answer unknown, never retry"
        );

        // The direct conversation row is untouched by the rename: the alias
        // lives in upstream account data and returns via contacts.sync.
        let row = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_by_id(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert_eq!(row.peer_key, "+15555550101");
        supervisor.shutdown().await.unwrap();
    }

    /// The fixture's `sendTyping` handler exits with the mutating call in
    /// flight when the recipient is the magic peer "+15555550999", so the
    /// upstream result is lost mid-call. setTypingMessage must answer the
    /// explicit `unknown` — never a retryable error, never an automatic
    /// retry — and write nothing locally (contract revision 1.11).
    #[tokio::test]
    async fn set_typing_message_with_a_lost_upstream_result_answers_unknown() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550999", "Crash Peer")
            .unwrap();

        assert_eq!(
            supervisor
                .set_typing_message(account.id.clone(), conversation.id.clone(), false)
                .await
                .unwrap(),
            "unknown",
            "a lost mutating result must answer unknown, never retry"
        );

        // No local row changes: the indicator is ephemeral upstream state.
        let row = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_by_id(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert_eq!(row.peer_key, "+15555550999");
        supervisor.shutdown().await.unwrap();
    }

    // ---- Contract 1.42 (§4.41): expire sweep + timer route ----

    fn due_record(
        id: &str,
        account_id: &str,
        conversation_id: &str,
        deadline_ms: u64,
    ) -> MessageRecord {
        MessageRecord {
            is_erased: false,
            delete_failed: false,
            required_protocol_version: None,
            author_aci: None,
            id: id.into(),
            account_id: account_id.into(),
            conversation_id: conversation_id.into(),
            direction: "incoming",
            sender_id: "peer".into(),
            sender_name: None,
            mentions_self: false,
            sent_at: deadline_ms,
            received_at: Some(deadline_ms),
            text: Some("vanishing".into()),
            text_bytes: Some(9),
            text_truncated: false,
            text_retrievable: true,
            status: "delivered",
            client_request_id: None,
            quote_message_id: None,
            quote_snapshot: None,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            edited_at: None,
            reactions: Vec::new(),
            edits: Vec::new(),
            delivered_at: None,
            read_at: None,
            viewed_at: None,
            send_outcomes: None,
            admin_deleted: false,
            sticker: None,
            expire_seconds: Some(60),
            expire_start_at: Some(deadline_ms.saturating_sub(60_000)),
            server_guid: None,
            server_timestamp: None,
            is_story: false,
            story_message: None,
        }
    }

    /// One drain pass deletes a full batch's worth of due rows and keeps
    /// draining immediately when the batch came back full (the cap bounds
    /// rows, not conversations), emitting one batched `message.expired` event
    /// per touched conversation; the follow-up pass is quiet.
    #[tokio::test]
    async fn expire_sweep_drains_full_batches_and_emits_grouped_events() {
        let temp = TempDir::new().unwrap();
        let store = test_store(temp.path());
        let account = store
            .upsert_account_from_signal("+15555550100", Some(1), DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let conversation_a = store
            .ensure_conversation(&account.id, "direct", "+15555550101", "contact")
            .unwrap();
        let conversation_b = store
            .ensure_conversation(&account.id, "direct", "+15555550102", "contact")
            .unwrap();
        // One full batch plus one, interleaved across two conversations: the
        // first pass deletes exactly the cap, the second drains the rest, and
        // both conversations must have been named by some event.
        let total = super::EXPIRE_SWEEP_BATCH as usize + 1;
        for index in 0..total {
            let conversation = if index % 2 == 0 {
                &conversation_a
            } else {
                &conversation_b
            };
            let record = due_record(
                &format!("due-{index:04}"),
                &account.id,
                &conversation.id,
                10_000 + index as u64,
            );
            store
                .insert_message(&record, None, Some("vanishing"), true)
                .unwrap();
        }
        // A live row the timer has not touched yet survives the whole drain:
        // its countdown starts far beyond the real wall clock.
        let mut waiting = due_record("waiting", &account.id, &conversation_a.id, 1_000_000);
        waiting.expire_start_at = Some(crate::link::now_ms() + 100_000);
        store
            .insert_message(&waiting, None, Some("vanishing"), true)
            .unwrap();

        let supervisor = Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                temp.path().join("unused-engine"),
                temp.path().join("unused-signal-data"),
            ),
            Arc::new(store),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        let mut host_events = supervisor.subscribe_host();
        supervisor.run_expire_sweep_pass().await;

        let mut expired_ids = std::collections::HashSet::new();
        let mut conversations_seen = std::collections::HashSet::new();
        while expired_ids.len() < total {
            let event = timeout(Duration::from_secs(5), host_events.recv())
                .await
                .expect("expired events within timeout")
                .unwrap();
            let HostSideEvent::MessageExpired {
                account_id,
                conversation_id,
                message_ids,
            } = event
            else {
                continue;
            };
            assert_eq!(account_id, account.id);
            assert!(!message_ids.is_empty(), "a group never ships empty");
            conversations_seen.insert(conversation_id);
            expired_ids.extend(message_ids);
        }
        assert_eq!(expired_ids.len(), total, "every due row swept exactly once");
        assert_eq!(conversations_seen.len(), 2, "both conversations reported");

        // The follow-up pass is quiet: the sweeper's event lane stays silent.
        supervisor.run_expire_sweep_pass().await;
        sleep(Duration::from_millis(150)).await;
        assert!(host_events.try_recv().is_err(), "no second-wave events");
        supervisor.shutdown().await.unwrap();
    }

    /// The direct route dispatches the engine's mutating
    /// `setExpirationTimer` (`expirationInSeconds`, single-string
    /// recipient), mirrors the conversation state on the definite success,
    /// and rides the refreshed summary out on conversation.changed.
    #[tokio::test]
    async fn set_expire_timer_routes_set_expiration_timer_and_mirrors_state() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let mut host_lane = supervisor.subscribe_host();

        let result = supervisor
            .set_conversation_expire_timer(crate::service::ConversationsSetExpireTimerParams {
                account_id: account.id.clone(),
                conversation_id: conversation.id.clone(),
                expire_seconds: 604_800,
            })
            .await
            .unwrap();
        assert_eq!(result.expire_timer_seconds, 604_800);

        let send_log = std::fs::read_to_string(
            temp.path()
                .join("signal-data")
                .join(".fixture-send-log.jsonl"),
        )
        .expect("fixture must log the dispatch");
        let dispatch: serde_json::Value = send_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .find(|params: &serde_json::Value| params["expirationInSeconds"] == 604_800)
            .expect("the timer call must reach setExpirationTimer");
        assert_eq!(dispatch["account"], "+15555550100");
        assert_eq!(dispatch["recipient"], "+15555550101");
        let summary = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_summary(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert_eq!(summary.expire_timer_seconds, Some(604_800));
        let event = timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("conversation.changed within timeout")
            .unwrap();
        let HostSideEvent::ConversationChanged(changed) = event else {
            panic!("expected a conversation.changed event");
        };
        assert_eq!(changed.expire_timer_seconds, Some(604_800));
        supervisor.shutdown().await.unwrap();
    }

    /// conversations.setBlocked (contract 1.138, §4.131): the §4.47 upstream
    /// write is followed by the local mirror — the direct row's factor stamp
    /// carries the blocked bit and the refreshed summary rides
    /// conversation.changed, so the masking window and every other window
    /// converge without a re-read.
    #[tokio::test]
    async fn set_blocked_write_back_mirrors_the_local_stamp_and_pushes_changed() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let mut host_lane = supervisor.subscribe_host();

        let blocked = supervisor
            .set_conversation_blocked(crate::service::ConversationsSetBlockedParams {
                account_id: account.id.clone(),
                conversation_id: conversation.id.clone(),
                kind: "contact".into(),
                blocked: true,
            })
            .await
            .unwrap();
        assert!(
            blocked
                .blocked
                .iter()
                .any(|entry| entry.conversation_id == "+15555550101"),
            "the post-write cloud list answers the fresh mask (the resolved peer reference)"
        );
        let summary = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_summary(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert!(summary.blocked, "the local mirror carries the stamp");
        let event = timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("conversation.changed within timeout")
            .unwrap();
        let HostSideEvent::ConversationChanged(changed) = event else {
            panic!("expected a conversation.changed event");
        };
        assert_eq!(changed.id, conversation.id);
        assert!(changed.blocked);

        // The unblock mirror clears the stamp the same way.
        supervisor
            .set_conversation_blocked(crate::service::ConversationsSetBlockedParams {
                account_id: account.id.clone(),
                conversation_id: conversation.id.clone(),
                kind: "contact".into(),
                blocked: false,
            })
            .await
            .unwrap();
        let summary = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_summary(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert!(!summary.blocked);
        supervisor.shutdown().await.unwrap();
    }

    /// conversations.saveDraft / conversations.clearDraft (contract 1.138,
    /// §4.130): the local draft lane — no engine, no upstream, the stamp
    /// lands on the shared store, the refreshed summary rides
    /// conversation.changed on both writes, and an unknown conversation
    /// answers CONVERSATION_NOT_FOUND.
    #[tokio::test]
    async fn save_and_clear_draft_stamp_locally_and_push_changed() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let mut host_lane = supervisor.subscribe_host();

        let status = supervisor
            .save_conversation_draft(crate::service::ConversationsSaveDraftParams {
                account_id: account.id.clone(),
                conversation_id: conversation.id.clone(),
                draft_timestamp: 1_700_000_000_000,
            })
            .await
            .unwrap();
        assert_eq!(status, "saved");
        let summary = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_summary(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert_eq!(summary.draft_timestamp, Some(1_700_000_000_000));
        let event = timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("conversation.changed within timeout")
            .unwrap();
        let HostSideEvent::ConversationChanged(changed) = event else {
            panic!("expected a conversation.changed event");
        };
        assert_eq!(changed.draft_timestamp, Some(1_700_000_000_000));

        // The clear refreshes the stamp away.
        let status = supervisor
            .clear_conversation_draft(crate::service::ConversationsClearDraftParams {
                account_id: account.id.clone(),
                conversation_id: conversation.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(status, "cleared");
        let event = timeout(Duration::from_secs(2), host_lane.recv())
            .await
            .expect("conversation.changed within timeout")
            .unwrap();
        let HostSideEvent::ConversationChanged(changed) = event else {
            panic!("expected a conversation.changed event");
        };
        assert_eq!(changed.draft_timestamp, None);

        // An unknown conversation is addressed by nobody.
        assert!(matches!(
            supervisor
                .save_conversation_draft(crate::service::ConversationsSaveDraftParams {
                    account_id: account.id.clone(),
                    conversation_id: "no-such-conversation".into(),
                    draft_timestamp: 1,
                })
                .await,
            Err(crate::service::ServiceError::Store(
                crate::store::StoreError::ConversationNotFound
            ))
        ));
        supervisor.shutdown().await.unwrap();
    }

    /// Contract 1.74 (§4.65): the kt-engine username read faces route to the
    /// engine's `getUsername`/`usernameLookup` method names — getUsername
    /// projects the storage truth (set shape: both fields; the unset marker:
    /// both keys absent project the null face), usernameLookup shares the
    /// §4.55 array projection (no `number` key on the engine record). The
    /// dispatch log pins the engine method name and the resolved account.
    #[tokio::test]
    async fn username_read_faces_route_engine_methods() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);

        // getUsername: the set shape projects both fields.
        let read = supervisor
            .get_username(crate::service::AccountsGetUsernameParams {
                account_id: account.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(read.username.as_deref(), Some("fixture_user.01"));
        assert_eq!(
            read.username_link.as_deref(),
            Some("https://signal.me/username/fixture-link")
        );

        // The never-set shape (engine answers both keys absent): the null
        // face, not an error.
        let unset_marker = temp
            .path()
            .join("signal-data")
            .join(".fixture-username-unset");
        std::fs::write(&unset_marker, b"").unwrap();
        let unset = supervisor
            .get_username(crate::service::AccountsGetUsernameParams {
                account_id: account.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(unset.username, None);
        assert_eq!(unset.username_link, None);
        std::fs::remove_file(&unset_marker).unwrap();

        // usernameLookup: the engine array projects entry-for-entry.
        let lookup = supervisor
            .lookup_usernames(crate::service::UsernameLookupParams {
                account_id: account.id.clone(),
                usernames: vec!["kt_registered.01".into(), "kt_unregistered.02".into()],
            })
            .await
            .unwrap();
        assert_eq!(lookup.results.len(), 2);
        assert_eq!(lookup.results[0].recipient, "kt_registered.01");
        assert_eq!(
            lookup.results[0].username.as_deref(),
            Some("kt_registered.01")
        );
        assert!(lookup.results[0].uuid.is_some());
        assert!(
            lookup.results[0].number.is_none(),
            "engine records carry no number key"
        );
        assert!(lookup.results[0].is_registered);
        assert_eq!(lookup.results[1].recipient, "kt_unregistered.02");
        assert!(!lookup.results[1].is_registered);

        // The dispatch log carries the engine method names and the resolved
        // signal account (the raw account id never rides the frame).
        let send_log = std::fs::read_to_string(
            temp.path()
                .join("signal-data")
                .join(".fixture-send-log.jsonl"),
        )
        .expect("fixture must log the dispatches");
        let dispatches: Vec<serde_json::Value> = send_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let get_dispatch = dispatches
            .iter()
            .find(|params| params.get("usernames").is_none() && params.get("account").is_some())
            .expect("a getUsername dispatch must land");
        assert_eq!(get_dispatch["account"], "+15555550100");
        let lookup_dispatch = dispatches
            .iter()
            .find(|params| params.get("usernames").is_some())
            .expect("a usernameLookup dispatch must land");
        assert_eq!(lookup_dispatch["account"], "+15555550100");
        supervisor.shutdown().await.unwrap();
    }

    /// Contract 1.75 (§4.66): the kt-engine write face orchestrates the two
    /// hops — reserve adopts the candidate (a bare nickname's discriminator
    /// is the engine's pick), confirm lands the link; the delete hop rides
    /// usernameDelete. The structured server codes map through the allowlist
    /// (TAKEN/RESERVATION_GONE deterministic, RATE_LIMITED retryable); the
    /// torn two-hop (confirm refuses on a gone reservation) surfaces the
    /// code verbatim; a crash with reserve in flight answers
    /// SEND_OUTCOME_UNKNOWN, is never retried (exactly one reserve dispatch,
    /// no confirm hop), and the next call lands on a fresh engine.
    #[tokio::test]
    async fn username_write_face_two_hop_delete_and_structured_codes() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let set_params =
            |username: Option<String>, delete: bool| crate::service::AccountsSetUsernameParams {
                account_id: account.id.clone(),
                username,
                delete_username: delete,
            };

        // Set path: the full username echoes through both hops and the
        // write-back projects {username, usernameLink}.
        let set = supervisor
            .set_username(set_params(Some("kt_test_agent.07".into()), false))
            .await
            .unwrap();
        assert_eq!(set.username.as_deref(), Some("kt_test_agent.07"));
        assert_eq!(
            set.username_link.as_deref(),
            Some("https://signal.me/username/fixture-link")
        );

        // Bare nickname: the adopted candidate wins (the engine picks the
        // discriminator).
        let bare = supervisor
            .set_username(set_params(Some("kt_agent_bare".into()), false))
            .await
            .unwrap();
        assert_eq!(bare.username.as_deref(), Some("kt_agent_bare.07"));

        // Delete hop: usernameDelete → the null face.
        let deleted = supervisor
            .set_username(set_params(None, true))
            .await
            .unwrap();
        assert_eq!(deleted.username, None);
        assert_eq!(deleted.username_link, None);

        // Structured codes through the allowlist.
        let taken = supervisor
            .set_username(set_params(Some("fixture_username_taken.01".into()), false))
            .await
            .unwrap_err();
        // The structured codes surface as engine UpstreamCode literals (the
        // allowlist classification); the host-face mapping (code + retryable)
        // is pinned by the service-layer totality/mapping tests.
        assert!(matches!(
            taken,
            crate::service::ServiceError::Engine(EngineError::UpstreamCode {
                code: "USERNAME_TAKEN",
                ..
            })
        ));
        let rate = supervisor
            .set_username(set_params(
                Some("fixture_username_ratelimited.01".into()),
                false,
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            rate,
            crate::service::ServiceError::Engine(EngineError::UpstreamCode {
                code: "USERNAME_RATE_LIMITED",
                ..
            })
        ));
        // The torn two-hop: reserve succeeds, confirm refuses.
        let gone = supervisor
            .set_username(set_params(Some("fixture_username_gone.01".into()), false))
            .await
            .unwrap_err();
        assert!(matches!(
            gone,
            crate::service::ServiceError::Engine(EngineError::UpstreamCode {
                code: "USERNAME_RESERVATION_GONE",
                ..
            })
        ));

        // Crash with reserve in flight: SEND_OUTCOME_UNKNOWN, never retried;
        // an explicit restart lands a fresh engine and the next set works.
        let crash = supervisor
            .set_username(set_params(Some("fixture_crash_username.31".into()), false))
            .await
            .unwrap_err();
        assert!(matches!(crash, crate::service::ServiceError::Api(ref api)
                if api.code == "SEND_OUTCOME_UNKNOWN" && !api.retryable));
        supervisor.start().await.unwrap();
        let after = supervisor
            .set_username(set_params(Some("kt_after_crash.01".into()), false))
            .await
            .unwrap();
        assert_eq!(after.username.as_deref(), Some("kt_after_crash.01"));

        // The dispatch log pins the hop order and payloads: every set rode
        // reserve→confirm (the crash username has exactly one reserve, no
        // confirm), the delete rode usernameDelete, and the raw account id
        // never rides the frame.
        let send_log = std::fs::read_to_string(
            temp.path()
                .join("signal-data")
                .join(".fixture-send-log.jsonl"),
        )
        .expect("fixture must log the dispatches");
        let dispatches: Vec<serde_json::Value> = send_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let reserves: Vec<&serde_json::Value> = dispatches
            .iter()
            .filter(|params| {
                params.get("usernameHash").is_none() && params.get("username").is_some()
            })
            .collect();
        let confirms: Vec<&serde_json::Value> = dispatches
            .iter()
            .filter(|params| params.get("usernameHash").is_some())
            .collect();
        // Every reserve that succeeded rode a confirm hop; the refusals
        // (taken/rate/crash) legitimately stop at reserve.
        assert_eq!(reserves.len(), confirms.len() + 3);
        for name in [
            "kt_test_agent.07",
            "kt_agent_bare.07",
            "fixture_username_gone.01",
            "kt_after_crash.01",
        ] {
            assert_eq!(
                confirms
                    .iter()
                    .filter(|params| params["username"] == name)
                    .count(),
                1,
                "exactly one confirm hop for {name}"
            );
        }
        let crash_reserves = reserves
            .iter()
            .filter(|params| params["username"] == "fixture_crash_username.31")
            .count();
        let crash_confirms = confirms
            .iter()
            .filter(|params| params["username"] == "fixture_crash_username.31")
            .count();
        assert_eq!(
            crash_reserves, 1,
            "an unknown reserve outcome is never retried"
        );
        assert_eq!(crash_confirms, 0, "a lost reserve never reaches confirm");
        assert!(
            dispatches
                .iter()
                .any(|params| params.get("deleteUsername").is_none()
                    && params.get("username").is_none()
                    && params.get("usernameHash").is_none()
                    && params.get("account").and_then(serde_json::Value::as_str)
                        == Some("+15555550100")),
            "the delete hop rides usernameDelete with the bare account"
        );
        assert!(
            dispatches
                .iter()
                .all(|params| params.get("accountId").is_none())
        );
        supervisor.shutdown().await.unwrap();
    }

    /// The fixture exits with the max-legal timer call in flight, so the
    /// upstream result is lost mid-call: setExpireTimer answers the explicit
    /// SEND_OUTCOME_UNKNOWN — never a retry, and the local mirror stays
    /// untouched (an unconfirmed upstream value is never projected).
    #[tokio::test]
    async fn set_expire_timer_with_a_lost_upstream_result_answers_unknown() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();

        let outcome = supervisor
            .set_conversation_expire_timer(crate::service::ConversationsSetExpireTimerParams {
                account_id: account.id.clone(),
                conversation_id: conversation.id.clone(),
                expire_seconds: i32::MAX as u32,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(outcome, crate::service::ServiceError::Api(ref api) if api.code == "SEND_OUTCOME_UNKNOWN"),
            "a lost mutating result must answer SEND_OUTCOME_UNKNOWN"
        );

        // No mirror write: the summary's timer state stays unknown.
        let summary = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .conversation_summary(&account.id, &conversation.id)
            .unwrap()
            .unwrap();
        assert_eq!(summary.expire_timer_seconds, None);
        supervisor.shutdown().await.unwrap();
    }

    /// Contract 1.76 (§4.67): the kt-engine story send routes to the engine's
    /// `sendStory` face — the frame carries the resolved signal account and
    /// omits the default-keyed options (distributionListId absent = the
    /// MY_STORY zero-UUID semantic, textStyle DEFAULT = the key absent,
    /// allowsReplies always explicit); the crash sentinel answers
    /// SEND_OUTCOME_UNKNOWN and is never retried (rowless discipline — there
    /// is no pending row, the restart is explicit). The stories-disabled
    /// toggle round-trips through the store from the official default
    /// (enabled).
    #[tokio::test]
    async fn story_faces_route_engine_send_and_local_toggle() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);

        // The toggle round-trips from the official default (enabled).
        let before = supervisor
            .get_stories_disabled(crate::service::StoriesGetDisabledParams {
                account_id: account.id.clone(),
            })
            .await
            .unwrap();
        assert!(!before.disabled);
        let set = supervisor
            .set_stories_disabled(crate::service::StoriesSetDisabledParams {
                account_id: account.id.clone(),
                disabled: true,
            })
            .await
            .unwrap();
        assert!(set.disabled);
        let after = supervisor
            .get_stories_disabled(crate::service::StoriesGetDisabledParams {
                account_id: account.id.clone(),
            })
            .await
            .unwrap();
        assert!(after.disabled);
        supervisor
            .set_stories_disabled(crate::service::StoriesSetDisabledParams {
                account_id: account.id.clone(),
                disabled: false,
            })
            .await
            .unwrap();

        let story_params = |message: &str, full: bool| crate::service::MessagesSendStoryParams {
            account_id: account.id.clone(),
            message: Some(message.to_string()),
            recipients: vec!["+15555550101".into()],
            distribution_list_id: full.then(|| "11111111-2222-3333-4444-555555555555".into()),
            allows_replies: full,
            text_style: full.then(|| "BOLD".to_string()),
            body_ranges: full.then(|| {
                vec![crate::service::SendTextStyleParams {
                    style: "BOLD".to_string(),
                    start: 0,
                    length: 6,
                }]
            }),
            preview_image: full.then(|| "data:image/png;base64,AAAA".to_string()),
            // Contract 1.91 (§4.74): the link-preview metadata rides the
            // full-option dispatch; the lean shape stays key-free.
            preview_url: full.then(|| "https://example.com/story".to_string()),
            preview_title: full.then(|| "Example".to_string()),
            // Contract 1.156 (§4.154): the media story leg — the text-face
            // tests stay on the text leg, the attachment face has its own.
            attachment: None,
            // Contract 1.185 (§4.185): the media story's caption — the
            // dispatch tests stay caption-free, the caption face has its own.
            caption: None,
            // Contract 1.157 (§4.155): the group audience leg — the
            // dispatch tests stay on the list leg, the group face has its
            // own.
            group: None,
        };

        // The default-shape send projects the lean frame and the fake's
        // empty per-recipient list.
        let story = supervisor
            .send_story(story_params("fixture story body", false))
            .await
            .unwrap();
        assert!(story.timestamp > 0);
        assert!(story.results.is_empty(), "the fake answers the empty list");

        // The full-option send carries every optional key.
        let styled = supervisor
            .send_story(story_params("styled", true))
            .await
            .unwrap();
        assert!(styled.timestamp > 0);

        // Crash with the mutating call in flight: SEND_OUTCOME_UNKNOWN,
        // never retried; an explicit restart lands a fresh engine and the
        // next send works.
        let crash = supervisor
            .send_story(story_params("fixture_story_crash.31", false))
            .await
            .unwrap_err();
        assert!(matches!(crash, crate::service::ServiceError::Api(ref api)
                if api.code == "SEND_OUTCOME_UNKNOWN" && !api.retryable));
        supervisor.start().await.unwrap();
        let recovered = supervisor
            .send_story(story_params("after crash", false))
            .await
            .unwrap();
        assert!(recovered.timestamp > 0);

        // The dispatch log pins the frame shapes: the resolved signal
        // account rides every story frame, the default-keyed options stay
        // absent, the full-option frame carries them all, the crash sentinel
        // dispatched exactly once (no retry), and the raw account id never
        // rides any frame.
        let send_log = std::fs::read_to_string(
            temp.path()
                .join("signal-data")
                .join(".fixture-send-log.jsonl"),
        )
        .expect("fixture must log the dispatches");
        let dispatches: Vec<serde_json::Value> = send_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let story_dispatches: Vec<&serde_json::Value> = dispatches
            .iter()
            .filter(|params| params.get("recipients").is_some())
            .collect();
        assert_eq!(story_dispatches.len(), 4, "three sends + the crash");
        for dispatch in &story_dispatches {
            assert_eq!(dispatch["account"], "+15555550100");
            assert!(
                dispatch.get("accountId").is_none(),
                "the store account id never rides the frame"
            );
        }
        let lean = story_dispatches
            .iter()
            .find(|params| params["message"] == "fixture story body")
            .expect("the default-shape dispatch must land");
        assert!(lean.get("distributionListId").is_none());
        assert!(lean.get("textStyle").is_none());
        assert!(lean.get("bodyRanges").is_none());
        assert!(lean.get("previewImage").is_none());
        // Contract 1.91 (§4.74): the metadata keys are absent-optional.
        assert!(lean.get("previewUrl").is_none());
        assert!(lean.get("previewTitle").is_none());
        assert_eq!(lean["allowsReplies"], false);
        let full = story_dispatches
            .iter()
            .find(|params| params["message"] == "styled")
            .expect("the full-option dispatch must land");
        assert_eq!(
            full["distributionListId"],
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(full["textStyle"], "BOLD");
        assert_eq!(full["allowsReplies"], true);
        assert_eq!(full["bodyRanges"][0]["style"], "BOLD");
        assert_eq!(full["bodyRanges"][0]["start"], 0);
        assert_eq!(full["bodyRanges"][0]["length"], 6);
        assert!(full.get("previewImage").is_some());
        // The metadata keys ride the engine frame verbatim (camelCase).
        assert_eq!(full["previewUrl"], "https://example.com/story");
        assert_eq!(full["previewTitle"], "Example");
        assert_eq!(
            story_dispatches
                .iter()
                .filter(|params| params["message"] == "fixture_story_crash.31")
                .count(),
            1,
            "an unknown sendStory outcome is never retried"
        );
        supervisor.shutdown().await.unwrap();
    }

    /// Contract 1.157 (§4.155): the sendStory answer projection passes the
    /// engine's additive `group` face through — absent (and null, the
    /// engine's 缺席 caliber) keeps the pre-1.157 shape byte-identically
    /// (the key never serializes), present is pinned to the documented
    /// `{groupId, timestamp}` shape, and a malformed face is the same
    /// protocol defect the required keys answer.
    #[test]
    fn send_story_answer_group_face_passes_through_additively() {
        // The pre-1.157 answer: no group key, the projection keeps the
        // exact serialization shape (absent stays absent, never null).
        let pre = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [
                {"recipientNumber": "+15555550101",
                 "success": {"timestamp": 1001u64}}
            ],
        }))
        .unwrap();
        assert!(pre.group.is_none());
        assert_eq!(
            serde_json::to_value(&pre).unwrap(),
            json!({
                "timestamp": 1000u64,
                "results": [
                    {"recipientNumber": "+15555550101",
                     "success": {"timestamp": 1001u64}}
                ],
            })
        );

        // An explicit null face reads as absence (the engine's own caliber).
        let nulled = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [],
            "group": null,
        }))
        .unwrap();
        assert!(nulled.group.is_none());

        // The group face passes through pinned to the documented shape.
        let grouped = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [],
            "group": {"groupId": "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q=", "timestamp": 1001u64},
        }))
        .unwrap();
        let face = grouped.group.as_ref().expect("the group face rides");
        assert_eq!(
            face.group_id,
            "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q="
        );
        assert_eq!(face.timestamp, 1001);
        assert_eq!(
            serde_json::to_value(&grouped).unwrap(),
            json!({
                "timestamp": 1000u64,
                "results": [],
                "group": {
                    "groupId": "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q=",
                    "timestamp": 1001u64,
                },
            })
        );

        // A malformed face is a protocol defect, answered loudly.
        for broken in [
            json!({"timestamp": 1u64, "results": [], "group": {"timestamp": 2u64}}),
            json!({"timestamp": 1u64, "results": [], "group": {"groupId": "abc"}}),
            json!({"timestamp": 1u64, "results": [], "group": {"groupId": 7, "timestamp": 2u64}}),
            json!({"timestamp": 1u64, "results": [], "group": "abc"}),
        ] {
            let error = super::story_from_engine(&broken).err().unwrap();
            assert!(
                matches!(
                    error,
                    crate::service::ServiceError::Engine(EngineError::Protocol)
                ),
                "expected a protocol defect for {broken}"
            );
        }
    }

    /// Contract 1.161 (§4.159): the sendStory answer projection passes the
    /// engine's additive `fileAttachment` pointer faces through as raw
    /// values on both legs — the roster leg on the result's top level, the
    /// group leg inside the group face — untyped and unshaped (the pointer
    /// face is the engine projection's product; the locator stays opaque
    /// transit), the mixed audience's two independent uploads staying
    /// distinct objects under their split keys (the pointers never merge),
    /// a non-object raw value riding ungated (the whole value domain is
    /// the engine's, connector-side gating would eat the transit), and an
    /// explicit null folding to absence.
    #[test]
    fn send_story_answer_pointer_faces_ride_verbatim_and_split_by_leg() {
        // The roster media leg: the full pointer face rides the top level
        // byte-for-byte (the engine's documented face — the metadata family
        // plus the locator, exactly the keys fed).
        let roster_face = json!({
            "id": "",
            "contentType": "application/octet-stream",
            "size": 123456u64,
            "caption": "a caption",
            "blurHash": "blurred",
            "incrementalMac": "bWFj",
            "chunkSize": 8192u64,
            "isVoiceNote": false,
            "isBorderless": false,
            "isGif": false,
            "waveform": "d2F2ZWZvcm0=",
            "duration": 4.5,
            "locator": {
                "key": "a2V5",
                "cdnKey": "AWESOME-CDN-KEY",
                "cdnNumber": 3u64,
                "uploadTimestamp": 1_700_000_000_000u64,
                "digest": "ZGlnZXN0",
            },
        });
        let roster = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [
                {"recipientNumber": "+15555550101",
                 "success": {"timestamp": 1001u64}}
            ],
            "fileAttachment": roster_face.clone(),
        }))
        .unwrap();
        assert_eq!(roster.file_attachment.as_ref().unwrap(), &roster_face);
        let serialized = serde_json::to_value(&roster).unwrap();
        assert_eq!(serialized["fileAttachment"], roster_face);

        // The group media leg: the group leg's own pointer rides the group
        // face, byte-for-byte, beside the pinned {groupId, timestamp}.
        let group_face = json!({
            "id": "",
            "contentType": "application/octet-stream",
            "isVoiceNote": false,
            "isBorderless": false,
            "isGif": false,
            "locator": {"cdnKey": "GROUP-CDN-KEY", "cdnNumber": 3u64,
                        "uploadTimestamp": 1_700_000_000_001u64},
        });
        let grouped = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [],
            "group": {
                "groupId": "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q=",
                "timestamp": 1001u64,
                "fileAttachment": group_face.clone(),
            },
        }))
        .unwrap();
        let face = grouped.group.as_ref().expect("the group face rides");
        assert_eq!(face.file_attachment.as_ref().unwrap(), &group_face);
        assert_eq!(
            serde_json::to_value(&grouped).unwrap()["group"]["fileAttachment"],
            group_face
        );

        // The mixed audience: two distinct pointers under their split keys,
        // each preserved verbatim — the projection never merges, swaps, or
        // drops one leg's pointer into the other key.
        let mixed = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [],
            "fileAttachment": {"locator": {"cdnKey": "ROSTER-KEY"}},
            "group": {
                "groupId": "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q=",
                "timestamp": 1001u64,
                "fileAttachment": {"locator": {"cdnKey": "GROUP-KEY"}},
            },
        }))
        .unwrap();
        assert_eq!(
            mixed.file_attachment.as_ref().unwrap()["locator"]["cdnKey"],
            json!("ROSTER-KEY")
        );
        let face = mixed.group.as_ref().expect("the group face rides");
        assert_eq!(
            face.file_attachment.as_ref().unwrap()["locator"]["cdnKey"],
            json!("GROUP-KEY")
        );

        // A non-object raw value rides ungated — the pointer face's whole
        // value domain is the engine's, and a connector-side shape gate
        // would eat the transit instead of forwarding it.
        let bare = super::story_from_engine(&json!({
            "timestamp": 1u64,
            "results": [],
            "fileAttachment": "the-engine-owns-this",
        }))
        .unwrap();
        assert_eq!(
            bare.file_attachment.as_ref().unwrap(),
            &json!("the-engine-owns-this")
        );

        // An explicit null folds to absence (the engine's 缺席 caliber).
        let nulled = super::story_from_engine(&json!({
            "timestamp": 1u64,
            "results": [],
            "fileAttachment": null,
            "group": {"groupId": "abc", "timestamp": 2u64, "fileAttachment": null},
        }))
        .unwrap();
        assert!(nulled.file_attachment.is_none());
        let face = nulled.group.as_ref().expect("the group face rides");
        assert!(face.file_attachment.is_none());
        let serialized = serde_json::to_value(&nulled).unwrap();
        assert!(
            serialized.get("fileAttachment").is_none()
                && serialized["group"].get("fileAttachment").is_none(),
            "an absent pointer never serializes, null included"
        );
    }

    /// Contract 1.161 (§4.159): the pointer-less answers keep the exact
    /// pre-1.161 shapes — the text leg's answer (and a group face without
    /// its own upload) never serializes a pointer key — and the group
    /// face's half-form discipline stays a protocol defect with the
    /// pointer keys riding along (the additive keys change no pinned-face
    /// verdict).
    #[test]
    fn send_story_answer_pointer_absence_keeps_pre161_shapes_and_half_faces_protocol() {
        // The pre-1.161 text answer: the serialization shape is
        // byte-identical to the pre-1.157 shape (no pointer key, no group
        // key — absence never serializes).
        let pre = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [
                {"recipientNumber": "+15555550101",
                 "success": {"timestamp": 1001u64}}
            ],
        }))
        .unwrap();
        assert!(pre.file_attachment.is_none());
        assert_eq!(
            serde_json::to_value(&pre).unwrap(),
            json!({
                "timestamp": 1000u64,
                "results": [
                    {"recipientNumber": "+15555550101",
                     "success": {"timestamp": 1001u64}}
                ],
            })
        );

        // The group single leg without a media upload: the group face
        // serializes exactly its pinned pair, no pointer key inside.
        let group_text = super::story_from_engine(&json!({
            "timestamp": 1000u64,
            "results": [],
            "group": {
                "groupId": "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q=",
                "timestamp": 1001u64,
            },
        }))
        .unwrap();
        let serialized = serde_json::to_value(&group_text).unwrap();
        assert!(serialized["group"].get("fileAttachment").is_none());
        assert_eq!(
            serialized,
            json!({
                "timestamp": 1000u64,
                "results": [],
                "group": {
                    "groupId": "pUUd9rRO9u2Yffq7vIYYOXNTlNLAWzCvTfgAFpBYK5Q=",
                    "timestamp": 1001u64,
                },
            })
        );

        // The group face's half-form discipline stays a protocol defect
        // when a pointer key rides along — the additive keys pin no verdict
        // of their own (raw transit) and change none of the pinned pair's.
        for broken in [
            json!({
                "timestamp": 1u64, "results": [],
                "fileAttachment": {"locator": {"cdnKey": "k"}},
                "group": {"timestamp": 2u64},
            }),
            json!({
                "timestamp": 1u64, "results": [],
                "group": {"groupId": "abc", "fileAttachment": {"locator": {"cdnKey": "k"}}},
            }),
            json!({
                "timestamp": 1u64, "results": [],
                "group": {"timestamp": 2u64, "fileAttachment": "abc"},
            }),
        ] {
            let error = super::story_from_engine(&broken).err().unwrap();
            assert!(
                matches!(
                    error,
                    crate::service::ServiceError::Engine(EngineError::Protocol)
                ),
                "expected a protocol defect for {broken}"
            );
        }
    }

    /// stories.markViewed (contract 1.85, §4.70): the frame is
    /// exactly the engine's `sendViewedReceipt` params — resolved signal
    /// account, the trimmed author as the single recipient, one timestamp —
    /// the receipt-class answer is `sent`, a crash in flight degrades to
    /// `unknown` without a retry, an explicit restart lands a fresh engine
    /// and the next receipt sends again, and the raw store account id never
    /// rides any frame.
    #[tokio::test]
    async fn stories_mark_viewed_routes_sendviewedreceipt() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);

        let viewed = |author: &str, sent_at: u64| crate::service::StoriesMarkViewedParams {
            account_id: account.id.clone(),
            story_author: author.to_string(),
            story_sent_at: sent_at,
        };

        let sent = supervisor
            .send_story_viewed(viewed("  +15555550101  ", 1727000000000))
            .await
            .unwrap();
        assert_eq!(sent, "sent");

        // Crash with the mutating receipt in flight: the receipt may or may
        // not have reached the server — `unknown`, never retried.
        let crash = supervisor
            .send_story_viewed(viewed("+15555550101", 425))
            .await
            .unwrap();
        assert_eq!(crash, "unknown");
        supervisor.start().await.unwrap();
        let recovered = supervisor
            .send_story_viewed(viewed("+15555550101", 1727000000001))
            .await
            .unwrap();
        assert_eq!(recovered, "sent");

        // The dispatch log pins the frame shapes: resolved signal account,
        // the trimmed author as the single recipient, exactly one timestamp
        // per receipt, the crash sentinel dispatched exactly once (no
        // retry), and the raw account id never rides any frame.
        let send_log = std::fs::read_to_string(
            temp.path()
                .join("signal-data")
                .join(".fixture-send-log.jsonl"),
        )
        .expect("fixture must log the dispatches");
        let dispatches: Vec<serde_json::Value> = send_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let receipts: Vec<&serde_json::Value> = dispatches
            .iter()
            .filter(|params| params.get("recipient").is_some())
            .collect();
        assert_eq!(receipts.len(), 3, "one receipt + the crash + the recovery");
        for dispatch in &receipts {
            assert_eq!(dispatch["account"], "+15555550100");
            assert!(
                dispatch.get("accountId").is_none(),
                "the store account id never rides the frame"
            );
            assert_eq!(dispatch["timestamps"].as_array().unwrap().len(), 1);
        }
        assert_eq!(receipts[0]["recipient"], "+15555550101");
        assert_eq!(
            receipts[0]["timestamps"],
            serde_json::json!([1727000000000u64])
        );
        assert_eq!(receipts[1]["timestamps"], serde_json::json!([425]));
        assert_eq!(
            receipts[2]["timestamps"],
            serde_json::json!([1727000000001u64])
        );
        supervisor.shutdown().await.unwrap();
    }

    /// stories.sendReaction (contract 1.152, §4.151): the supervisor-level
    /// forward — the engine's `sendStoryReaction` crosses as its own
    /// mutating call, the `{}` success answer passes through untouched, and
    /// the one local refusal (`remove: true`) answers INVALID_REQUEST
    /// before any engine traffic (the face is place-only).
    #[tokio::test]
    async fn stories_send_reaction_forwards_the_engine_frame() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("signal-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(
            data_dir.join("engine-state.json"),
            r#"{"version":2,"accounts":[{"number":"+15555550100","dir":"accounts/lk-abc"}]}"#,
        )
        .unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            data_dir.clone(),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store,
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);

        let answered = supervisor
            .send_story_reaction(crate::service::StoriesSendReactionParams {
                account_id: account.id.clone(),
                story_author: "+15555550101".into(),
                story_sent_at: 1727000000000,
                emoji: "👍".into(),
                remove: false,
                group: None,
                operation_id: None,
            })
            .await
            .unwrap();
        assert_eq!(answered, serde_json::json!({}));

        let error = supervisor
            .send_story_reaction(crate::service::StoriesSendReactionParams {
                account_id: account.id,
                story_author: "+15555550101".into(),
                story_sent_at: 1727000000000,
                emoji: "👍".into(),
                remove: true,
                group: None,
                operation_id: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::service::ServiceError::Api(ref api)
                if api.code == "INVALID_REQUEST" && !api.retryable
        ));

        // The dispatch log pins the frame: the resolved signal account
        // under the engine's names, no remove key (the face is
        // place-only), and the remove refusal contributed no line.
        let send_log = std::fs::read_to_string(data_dir.join(".fixture-send-log.jsonl"))
            .expect("fixture must log the dispatches");
        let dispatches: Vec<serde_json::Value> = send_log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(dispatches.len(), 1, "{dispatches:?}");
        assert_eq!(
            dispatches[0],
            serde_json::json!({
                "account": "+15555550100",
                "storyAuthor": "+15555550101",
                "storyTimestamp": 1727000000000u64,
                "emoji": "👍",
            })
        );
        supervisor.shutdown().await.unwrap();
    }

    /// messages.markViewed (contract 1.94, §4.77) end to end:
    /// the selected incoming rows take their local `viewed_at` stamp while
    /// the upstream receipt still confirms `sent`, a group conversation
    /// stamps with an empty fan-out, and messages.markRead never stamps.
    #[tokio::test]
    async fn mark_viewed_stamps_locally_and_mark_read_does_not() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store.clone(),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let group = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "group", "ZmFrZS1ncm91cC0x", "Group")
            .unwrap();
        let seed = |id: &str, sent_at: u64, conversation_id: &str| {
            let record = crate::store::MessageRecord {
                is_erased: false,
                delete_failed: false,
                required_protocol_version: None,
                author_aci: None,
                id: id.into(),
                account_id: account.id.clone(),
                conversation_id: conversation_id.to_string(),
                direction: "incoming",
                sender_id: "peer-hash".into(),
                sender_name: None,
                mentions_self: false,
                sent_at,
                received_at: None,
                text: Some("voice note".into()),
                text_bytes: Some(10),
                text_truncated: false,
                text_retrievable: true,
                status: "delivered",
                client_request_id: None,
                quote_message_id: None,
                quote_snapshot: None,
                quote: None,
                attachments: Vec::new(),
                rich: None,
                edited_at: None,
                reactions: Vec::new(),
                edits: Vec::new(),
                delivered_at: None,
                read_at: None,
                viewed_at: None,
                send_outcomes: None,
                sticker: None,
                expire_seconds: None,
                expire_start_at: None,
                admin_deleted: false,
                server_guid: None,
                server_timestamp: None,
                is_story: false,
                story_message: None,
            };
            assert!(
                store
                    .insert_message(&record, None, Some("voice note"), true)
                    .unwrap()
            );
        };
        let now = crate::link::now_ms();
        seed("m1", now, &conversation.id);
        seed("m2", now + 1, &conversation.id);
        seed("m3", now + 2, &conversation.id);
        seed("g1", now + 4, &group.id);
        let viewed_at = |conversation_id: &str, id: &str| {
            store
                .message_by_id(&account.id, conversation_id, id)
                .unwrap()
                .unwrap()
                .viewed_at
        };

        // markRead first: the receipt fans out and confirms, and no row
        // takes any local stamp.
        let read_status = supervisor
            .send_read_receipt(
                account.id.clone(),
                conversation.id.clone(),
                Some(vec!["m1".into()]),
                None,
            )
            .await
            .unwrap();
        assert_eq!(read_status, "sent");
        assert_eq!(viewed_at(&conversation.id, "m1"), None);

        // markViewed with an explicit selection: the upstream receipt
        // confirms `sent` and the selected row is stamped locally.
        let viewed_status = supervisor
            .send_viewed_receipt(
                account.id.clone(),
                conversation.id.clone(),
                Some(vec!["m1".into()]),
            )
            .await
            .unwrap();
        assert_eq!(viewed_status, "sent");
        let first_stamp = viewed_at(&conversation.id, "m1");
        assert!(first_stamp.is_some(), "the selected row is stamped");
        assert_eq!(viewed_at(&conversation.id, "m2"), None);

        // The default selection covers the rest; the first stamp never
        // moves.
        let viewed_all = supervisor
            .send_viewed_receipt(account.id.clone(), conversation.id.clone(), None)
            .await
            .unwrap();
        assert_eq!(viewed_all, "sent");
        assert!(viewed_at(&conversation.id, "m2").is_some());
        assert!(viewed_at(&conversation.id, "m3").is_some());
        assert_eq!(viewed_at(&conversation.id, "m1"), first_stamp);

        // A group conversation's fan-out is empty — the answer is the
        // trivial `sent` — and the local stamp still lands.
        let group_status = supervisor
            .send_viewed_receipt(account.id.clone(), group.id.clone(), None)
            .await
            .unwrap();
        assert_eq!(group_status, "sent");
        assert!(viewed_at(&group.id, "g1").is_some());
        supervisor.shutdown().await.unwrap();
    }

    /// §4.119: a receipt-face failure records the conversation+face debounce.
    /// The immediate same-face replay answers `unknown` with zero new engine
    /// frames; the other face and another conversation keep their own keys;
    /// a face whose window has no failure still confirms `sent`.
    #[tokio::test]
    async fn receipt_failure_debounce_suppresses_same_face_replays_within_the_window() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let mut config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        config.request_timeout = Duration::from_secs(3);
        config.shutdown_grace = Duration::from_millis(100);
        let supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            store.clone(),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        supervisor.start().await.unwrap();
        let account = supervisor
            .service
            .lock()
            .await
            .sync_accounts_from_numbers(&[("+15555550100".into(), None)], DEFAULT_PROXY_GROUP_ID)
            .unwrap()
            .remove(0);
        let conversation = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550101", "Peer")
            .unwrap();
        let second = supervisor
            .service
            .lock()
            .await
            .store_ref()
            .ensure_conversation(&account.id, "direct", "+15555550102", "Other")
            .unwrap();
        let seed = |id: &str, sent_at: u64, conversation_id: &str| {
            let record = MessageRecord {
                is_erased: false,
                delete_failed: false,
                required_protocol_version: None,
                author_aci: None,
                id: id.into(),
                account_id: account.id.clone(),
                conversation_id: conversation_id.to_string(),
                direction: "incoming",
                sender_id: "peer-hash".into(),
                sender_name: None,
                mentions_self: false,
                sent_at,
                received_at: None,
                text: Some("body".into()),
                text_bytes: Some(4),
                text_truncated: false,
                text_retrievable: true,
                status: "delivered",
                client_request_id: None,
                quote_message_id: None,
                quote_snapshot: None,
                quote: None,
                attachments: Vec::new(),
                rich: None,
                edited_at: None,
                reactions: Vec::new(),
                edits: Vec::new(),
                delivered_at: None,
                read_at: None,
                viewed_at: None,
                send_outcomes: None,
                sticker: None,
                expire_seconds: None,
                expire_start_at: None,
                admin_deleted: false,
                server_guid: None,
                server_timestamp: None,
                is_story: false,
                story_message: None,
            };
            assert!(
                store
                    .insert_message(&record, None, Some("body"), true)
                    .unwrap()
            );
        };
        let now = crate::link::now_ms();
        seed("m1", now, &conversation.id);
        seed("m2", now + 1, &second.id);

        let send_log = temp
            .path()
            .join("signal-data")
            .join(".fixture-send-log.jsonl");
        let receipt_frames = |send_log: &std::path::Path| -> usize {
            std::fs::read_to_string(send_log)
                .map(|contents| {
                    contents
                        .lines()
                        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                        .filter(|params| params.get("timestamps").is_some())
                        .count()
                })
                .unwrap_or(0)
        };
        let fail_marker = temp
            .path()
            .join("signal-data")
            .join(".fixture-fail-receipt");

        // The read face fails upstream: the answer degrades to `unknown` and
        // the failure records the conversation+face debounce.
        std::fs::write(&fail_marker, b"").unwrap();
        let status = supervisor
            .send_read_receipt(account.id.clone(), conversation.id.clone(), None, None)
            .await
            .unwrap();
        assert_eq!(status, "unknown");
        assert_eq!(receipt_frames(&send_log), 1);

        // The immediate same-face replay never reaches the engine.
        let status = supervisor
            .send_read_receipt(account.id.clone(), conversation.id.clone(), None, None)
            .await
            .unwrap();
        assert_eq!(status, "unknown");
        assert_eq!(
            receipt_frames(&send_log),
            1,
            "a debounced replay must not dispatch an engine frame"
        );

        // The viewed face carries its own key: a real attempt, its own
        // failure record.
        let status = supervisor
            .send_viewed_receipt(account.id.clone(), conversation.id.clone(), None)
            .await
            .unwrap();
        assert_eq!(status, "unknown");
        assert_eq!(receipt_frames(&send_log), 2);

        // Another conversation is not debounced: with the marker gone its
        // read face reaches the engine and confirms.
        std::fs::remove_file(&fail_marker).unwrap();
        let status = supervisor
            .send_read_receipt(account.id.clone(), second.id.clone(), None, None)
            .await
            .unwrap();
        assert_eq!(status, "sent");
        assert_eq!(receipt_frames(&send_log), 3);

        // And the viewed face of the first conversation is now the one
        // debounced from its own failure.
        let status = supervisor
            .send_viewed_receipt(account.id.clone(), conversation.id.clone(), None)
            .await
            .unwrap();
        assert_eq!(status, "unknown");
        assert_eq!(receipt_frames(&send_log), 3);
        supervisor.shutdown().await.unwrap();
    }

    /// §4.119: the debounce map itself — a recorded failure gates its key
    /// inside the 60-second window and opens exactly past it (the expired
    /// entry is dropped), and the hard cap refuses insertion instead of
    /// growing unbounded (AGENTS.md).
    #[tokio::test]
    async fn receipt_failure_cooldown_expires_and_the_map_stays_bounded() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes(TEST_KEY_BYTES))).unwrap());
        let config = EngineConfig::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-engine.py"),
            temp.path().join("signal-data"),
        );
        let supervisor =
            RuntimeSupervisor::new(config, store, DEFAULT_PROXY_GROUP_ID.to_string(), None);
        let key = receipt_failure_key("acct", "conv", "sendReadReceipt");
        let now = std::time::Instant::now();
        assert!(!supervisor.receipt_failure_pending(&key, now));
        supervisor.note_receipt_failure(&key, now);
        assert!(supervisor.receipt_failure_pending(&key, now));
        assert!(
            supervisor.receipt_failure_pending(&key, now + Duration::from_secs(59)),
            "inside the window the gate holds"
        );
        assert!(
            !supervisor.receipt_failure_pending(&key, now + Duration::from_secs(61)),
            "past the window the gate opens"
        );
        // The expired entry is gone; the next failure starts a fresh window.
        assert_eq!(
            supervisor
                .receipt_failures
                .lock()
                .expect("receipt failures mutex")
                .len(),
            0
        );
        supervisor.note_receipt_failure(&key, now + Duration::from_secs(61));
        assert!(supervisor.receipt_failure_pending(&key, now + Duration::from_secs(61)));

        // The cap: live entries are never evicted, an overflow key is
        // refused (it keeps reaching the engine, the map stays bounded).
        for index in 0..RECEIPT_FAILURE_MAP_CAP {
            supervisor.note_receipt_failure(&format!("cap-{index}"), now);
        }
        supervisor.note_receipt_failure("cap-overflow", now);
        let failures = supervisor
            .receipt_failures
            .lock()
            .expect("receipt failures mutex");
        assert_eq!(failures.len(), RECEIPT_FAILURE_MAP_CAP);
        assert!(!failures.contains_key("cap-overflow"));
    }

    /// §4.38 step 3 (contract revision 1.98), direct branch: no environment
    /// value builds the same client the chain has always used — the budgets
    /// and the no-redirect posture, and no proxy layer.
    #[test]
    fn download_client_without_an_env_value_builds_the_direct_route() {
        assert!(attachment_download_client(None).is_ok());
    }

    /// The environment value parses through the doctor's tolerant parse, so
    /// a malformed value reads as unconfigured everywhere else too: the
    /// direct route, never a half-configured client.
    #[test]
    fn download_client_treats_a_malformed_env_value_as_unconfigured() {
        assert!(attachment_download_client(Some("not a proxy")).is_ok());
        assert!(attachment_download_client(Some("host-without-port")).is_ok());
    }

    /// The SOCKS branch, proven against the real transport: a loopback proxy
    /// port with no listener refuses the SOCKS handshake immediately, so the
    /// GET fails fast offline — a client that silently ignored the route
    /// would attempt the real DNS/TLS path instead (the doctor's
    /// `socks_refused` proof, mirrored for the CDN client). Both canonical
    /// `host:port` and the tolerated `socks5h://` prefix wire the route.
    #[tokio::test]
    async fn download_client_wires_the_socks_route_into_the_transport() {
        for value in ["127.0.0.1:1", "socks5h://127.0.0.1:1"] {
            let client = attachment_download_client(Some(value)).expect("client builds");
            let error = client
                .get("https://chat.signal.org/")
                .send()
                .await
                .expect_err("nothing listens on the loopback socks port");
            assert!(
                error.is_connect(),
                "the refusal must be the proxy hop, got: {error}"
            );
        }
    }

    /// §4.163: the CDN client's pinned anchor is the vendored Signal
    /// production root — present, parseable, and byte-identical to the file
    /// the doctor's strict leg pins (the SHA-256 pins the exact vendored
    /// bytes, so a swapped or truncated pem fails here before any client
    /// rides it). The real CDN chain terminates at Signal's private root,
    /// carried by neither the webpki set nor any platform keychain — the
    /// anchor is the whole clean-network story; a real-CDN TLS handshake is
    /// not unit-fixture material (the 1.163 boundary note stands), so this
    /// parse-and-build pin is the honest mount point.
    #[test]
    fn download_client_pins_the_vendored_signal_root() {
        let pem = include_bytes!("../vendor/certs/production-root-ca.pem");
        let digest = <sha2::Sha256 as sha2::Digest>::digest(pem);
        assert_eq!(
            hex::encode(digest),
            "d3f89b971ae3d1dee9ad250e8f101d140da6ab3ebb8c3580190fe22d1d52f1aa",
            "the vendored root pem moved — re-verify the Signal production root \
             fingerprint before updating this anchor"
        );
        let certificate = cdn_root_certificate().expect("the vendored production root CA parses");
        let _ = reqwest::Client::builder()
            .add_root_certificate(certificate)
            .build()
            .expect("the pinned-anchor client builds");
        assert!(attachment_download_client(None).is_ok());
    }

    /// §4.115 (contract revision 1.132): the plaintext arm of
    /// `backups.exportStatus` — the connector-local registry's own state,
    /// content-free numbers and classes only, honest absence for the
    /// optional keys, `artifactPresent: false` (no engine artifact exists on
    /// this path), and the encrypted family's snapshot listing kept beside
    /// it. Red line 3: no content ever rides this projection.
    #[test]
    fn plaintext_status_projection_reports_the_registry_state_content_free() {
        use crate::backup_export::{PlaintextTaskSnapshot, PlaintextTaskState};

        let temp = TempDir::new().unwrap();
        let task = PlaintextTaskSnapshot {
            state: PlaintextTaskState::Completed,
            started_at_ms: 1_000,
            finished_at_ms: Some(2_000),
            lines: Some(12),
            bytes: Some(1_234),
            error: None,
            counters: Some(crate::backup_export::SkipCounters {
                skipped_reactions: 3,
                ..Default::default()
            }),
        };
        let projected =
            super::plaintext_status_projection(temp.path(), "acct-1", "+15555550099", task);
        assert_eq!(projected["accountId"], "acct-1");
        assert_eq!(projected["state"], "completed");
        assert_eq!(projected["kind"], "plaintext_jsonl");
        assert_eq!(projected["artifactPresent"], false);
        assert_eq!(projected["startedAtMs"], 1_000);
        assert_eq!(projected["finishedAtMs"], 2_000);
        assert_eq!(projected["lines"], 12);
        assert_eq!(projected["bytes"], 1_234);
        assert_eq!(projected["skippedReactions"], 3);
        assert!(
            projected.get("error").is_none(),
            "a completed task carries no error class"
        );
        assert!(
            projected.get("snapshot").is_none(),
            "no engine snapshot exists on this path"
        );
        assert!(
            projected.get("frames").is_none(),
            "frame counts are the encrypted family's face, never invented"
        );

        // A failed task: the content-free class rides, the counters do not.
        let failed = PlaintextTaskSnapshot {
            state: PlaintextTaskState::Failed,
            started_at_ms: 5_000,
            finished_at_ms: Some(6_000),
            lines: None,
            bytes: None,
            error: Some("store-read"),
            counters: None,
        };
        let projected =
            super::plaintext_status_projection(temp.path(), "acct-1", "+15555550099", failed);
        assert_eq!(projected["state"], "failed");
        assert_eq!(projected["error"], "store-read");
        assert!(projected.get("lines").is_none(), "honest absence");
        assert!(projected.get("finishedAtMs").is_some());

        // A running task: no finished stamp, no counts.
        let running = PlaintextTaskSnapshot {
            state: PlaintextTaskState::Running,
            started_at_ms: 9_000,
            finished_at_ms: None,
            lines: None,
            bytes: None,
            error: None,
            counters: None,
        };
        let projected =
            super::plaintext_status_projection(temp.path(), "acct-1", "+15555550099", running);
        assert_eq!(projected["state"], "running");
        for key in ["finishedAtMs", "lines", "bytes", "error"] {
            assert!(projected.get(key).is_none(), "{key} stays absent");
        }
    }
}
