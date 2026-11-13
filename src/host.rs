// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, SplitSink};
use futures_util::{FutureExt, SinkExt, StreamExt};
use rand::RngCore;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{
    Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, broadcast, mpsc, watch,
};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};

use crate::auth::{BootstrapSecret, HandshakeParams, PendingChallenge};
use crate::ipc::LocalListener;
use crate::methods;
use crate::metrics;
use crate::protocol::{ApiError, HostEvent, HostRequest, HostResponse};
use crate::registry::{ProxyGroupRuntime, RegistryEvent, StartFailure, StopFailure};
use crate::service::{
    AccountDeleteLocalDataParams, AccountsDeviceCapabilitiesParams, AccountsGetDevicesParams,
    AccountsGetSyncStateParams, AccountsGetUsernameParams, AccountsSetExpireTimerParams,
    AccountsSetProfileParams, AccountsSetUsernameParams, AccountsUnlinkDeviceParams,
    AccountsUpdateConfigurationParams, BackupsCloudStatusParams,
    BackupsExportFileCloseHandleParams, BackupsExportFileOpenParams,
    BackupsExportFileReadChunkParams, BackupsExportParams, BackupsExportPlaintextParams,
    BackupsExportStatusParams, BackupsImportSnapshotParams, BackupsImportSnapshotStatusParams,
    BackupsRestoreFromCloudParams, BackupsUploadStatusParams, BackupsUploadToCloudParams,
    CallsCreateLinkAuthParams, CallsEndorsementsPublicKeyParams, CallsGetStateParams,
    CallsGroupMembersParams, CallsGroupProofParams, CallsLinkPresentationParams, CallsRelaysParams,
    CallsSendCallEventParams, CallsSendGroupCallUpdateParams, CallsSendSignalParams,
    ChatFoldersListParams, ChatFoldersSetRecordsParams, ContactsListParams,
    ContactsSetLocalAliasParams, ContactsSyncParams, ConversationsClearDraftParams,
    ConversationsGetAvatarParams, ConversationsGetBlockedParams, ConversationsGetPinnedParams,
    ConversationsGetStateParams, ConversationsListParams, ConversationsReportSpamParams,
    ConversationsSaveDraftParams, ConversationsSetBlockedParams, ConversationsSetExpireTimerParams,
    ConversationsSetPinnedParams, ConversationsSetStateParams, EventsListParams,
    GroupsApproveJoinRequestsParams, GroupsBuildInviteLinkParams, GroupsCancelJoinRequestParams,
    GroupsCommonParams, GroupsCreateParams, GroupsGetParams, GroupsInviteLinkPasswordParams,
    GroupsJoinViaLinkParams, GroupsMigrateParams, GroupsParseInviteLinkParams,
    GroupsPreviewViaLinkParams, GroupsQuitParams, GroupsRevokeInvitesParams, GroupsTerminateParams,
    GroupsUpdateParams, HistoryAttachmentDownloadParams, HistoryImportCancelParams,
    HistoryImportRetryParams, HistoryImportStatusParams, HostSideEvent, IdentitiesGetParams,
    IdentitiesVerifyParams, LinkRotateParams, LinkSessionParams, LinkStartParams,
    MessageGetByClientRequestIdParams, MessageGetReceiptsParams, MessageGetTextParams,
    MessageRequestParams, MessagesAdjacentMediaParams, MessagesAroundParams,
    MessagesAttachmentsCloseHandleParams, MessagesAttachmentsOpenParams,
    MessagesAttachmentsReadChunkParams, MessagesDeleteForMeMessagesParams,
    MessagesDeleteForMeParams, MessagesEditParams, MessagesListAttachmentDimensionsParams,
    MessagesListParams, MessagesMarkReadParams, MessagesMarkViewOnceOpenedParams,
    MessagesMarkViewedParams, MessagesRemoteDeleteParams, MessagesReportSpamParams,
    MessagesRetryTextParams, MessagesSearchParams, MessagesSendAdminDeleteParams,
    MessagesSendAttachmentParams, MessagesSendContactParams, MessagesSendPinMessageParams,
    MessagesSendPollCreateParams, MessagesSendPollTerminateParams, MessagesSendPollVoteParams,
    MessagesSendReactionParams, MessagesSendStickerParams, MessagesSendStoryParams,
    MessagesSendTextParams, MessagesSendUnpinMessageParams, MessagesSendViewOnceOpenParams,
    MessagesSetAttachmentDimensionsParams, MessagesSyncReadParams, MessagesSyncViewedParams,
    NotificationProfilesListParams, NotificationProfilesSetRecordsParams, PhoneLookupParams,
    PresenceSetTypingMessageParams, SendTarget, StickerPackGetSyncsParams, StickerPackImageParams,
    StickerPackManifestParams, StickerPackSetSyncParams, StorageGetCallLinksParams,
    StorageIngestParams, StorageSetCallLinkParams, StoriesDeleteForEveryoneParams,
    StoriesGetDisabledParams, StoriesMarkViewedParams, StoriesSendReactionParams,
    StoriesSetDisabledParams, StoryDistributionListsListParams,
    StoryDistributionListsSetRecordsParams, UsernameLookupParams,
};
use crate::store::{MAX_ADJACENT_MEDIA_LIMIT, MAX_PAGE_LIMIT};
use crate::{API_VERSION, DEFAULT_HOST_FRAME_LIMIT, advertised_capabilities};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// ADR 0006: how long the explicit busy answer may take. The frame is one
/// line; a peer that cannot read it within this window is closed rather than
/// allowed to hold the accept loop (and the live session's polling) open.
const HOST_BUSY_ANSWER_TIMEOUT: Duration = Duration::from_secs(1);
/// How many busy answers may be in flight at once. A connect flood beyond
/// this ceiling has its connection dropped immediately instead of growing a
/// task per attempt; the live session is never paused for a busy answer.
const HOST_BUSY_ANSWER_CONCURRENCY: usize = 4;
const HOST_DISPATCH_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the redacted in-process metrics (src/metrics.rs) are logged.
const METRICS_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Outer bound for runtime shutdown during host teardown. The engine shutdown
/// is already bounded internally (grace period, then a direct kill); this
/// covers everything around it (e.g. a store lock held by a wedged
/// persistence write) so a single stuck component cannot keep the process
/// alive. Must exceed the engine-internal shutdown budget.
const HOST_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);
const RECENT_REQUEST_IDS: usize = 128;
const MAX_PENDING_HOST_REQUESTS: usize = 128;
const MAX_PENDING_HOST_REQUESTS_PER_ACCOUNT: usize = 32;
const MAX_PENDING_HOST_BYTES: usize = 176 * 1024 * 1024;
/// 每账号的 dispatch lane 容量（CONTROL/READ/SEND 三档）。它们与桌面
/// `requestScheduler.ts` 的 lane 上限手工镜像（optimization-plan §5.2 B2）：
/// 改容量必须两侧同一改动，否则两个调度器漂移。方法 → lane 的归属在
/// `methods::METHODS`。
///
/// 为什么按账号而不是按连接器进程：官方模型是「一账号一客户端」——
/// `AttachmentDownloadManager.preload.ts:104-115` 的并发预算和
/// `JobManager.std.ts:156-176` 的单 job 队列都是按一个账号实例计量的。
/// 旧的进程级 control 1 / read 4 / send 2 会让 A 账号的读占满配额后把
/// 完全无关的 B 账号串行化（ADR 0005）。
const CONTROL_CONCURRENCY: usize = 1;
/// 单个 proxy group 的 `link.finish` 容量（ADR 0001 R3）：phone-approval
/// 等待按组隔离，不同组互不阻塞，同组第二个并发 finish 直接拒绝。
const LINK_WAIT_CONCURRENCY: usize = 1;
const READ_CONCURRENCY: usize = 4;
const SEND_CONCURRENCY: usize = 2;

/// 全局兜底 = 每账号容量 × 典型账号数（ADR 0005）。它只防资源失控
/// （N 个账号同时打满各自 lane 时给进程一个硬上界），不参与公平性：
/// 账号之间的隔离由 per-account lane 负责，全局 permit 落到哪个账号
/// 并不重要。这里取 4 个典型账号；账号数或并发超过这个规模时全局兜底
/// 才开始限流，这是容量告警信号，而不是正常调度路径。
const TYPICAL_ACCOUNT_COUNT: usize = 4;
const GLOBAL_CONTROL_CONCURRENCY: usize = CONTROL_CONCURRENCY * TYPICAL_ACCOUNT_COUNT;
const GLOBAL_READ_CONCURRENCY: usize = READ_CONCURRENCY * TYPICAL_ACCOUNT_COUNT;
const GLOBAL_SEND_CONCURRENCY: usize = SEND_CONCURRENCY * TYPICAL_ACCOUNT_COUNT;
/// Forensic floor and answer deadline for an admitted host dispatch
/// (§4.166 forensic line, §4.168 bounded answer): every bounded dispatch
/// budget has run out long before this — engine calls are timeout-capped at
/// seconds, media downloads at two minutes — so a request still in flight
/// here has already escaped every face that owns a budget. At this point the
/// §4.166 warn fires once and the dispatch is answered with the deadline
/// face (`INTERNAL_ERROR`, retryable) instead of pending forever; the lane
/// permit and the pending budget release with the answered future. `link.*`
/// waits are exempt (their approval window is legitimately long).
const HOST_DISPATCH_STALL_WARN_AFTER: Duration = Duration::from_secs(300);

/// The bounded per-session host write queue (§4.169): every
/// post-authentication frame — dispatch responses, rejects, registry and
/// host events — enters the writer task through this channel, and enqueue
/// never awaits socket writability. Count-bounded like the engine's A7
/// stdin queue; a saturated queue drops the frame with a warn (a response
/// drop still releases its pending-budget slot) instead of parking the
/// session loop behind a peer that stopped reading its socket.
const HOST_WRITE_QUEUE_CAPACITY: usize = 256;

type DispatchFuture = BoxFuture<'static, DispatchCompletion>;

/// The write half of one authenticated session (§4.169): pre-serialized
/// frames flow through `frames` to the single writer task that owns the
/// sink; the writer's own I/O failures surface on `failures` so the
/// session loop can end exactly as a direct write error did. Cloneable and
/// type-erased — dispatch futures hold a clone without carrying the socket
/// type.
#[derive(Clone)]
struct HostWriteChannel {
    frames: mpsc::Sender<String>,
    failures: mpsc::Sender<HostError>,
}

/// Enqueue one frame (§4.169): never awaits socket writability. A saturated
/// queue answers `WriteBackSaturated` and the caller owns the drop face; a
/// serialization failure answers `InvalidFrame` exactly as the pre-queue
/// `send_shared` did.
fn enqueue_frame<T: Serialize>(channel: &HostWriteChannel, value: &T) -> Result<(), HostError> {
    let encoded = serde_json::to_string(value).map_err(|_| HostError::InvalidFrame)?;
    channel
        .frames
        .try_send(encoded)
        .map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => HostError::WriteBackSaturated,
            mpsc::error::TrySendError::Closed(_) => HostError::PeerGone,
        })
}

/// Enqueue one already-built wire event (§4.169): a saturated queue drops
/// the frame with a warn and keeps the session alive — the event faces own
/// the same lossy discipline as the lagged-broadcast `eventBackpressure`
/// notice — while only a closed channel (a peer that left) ends it.
fn enqueue_event_or_break(
    channel: &HostWriteChannel,
    wire: &HostEvent<Value>,
) -> Result<(), HostError> {
    match enqueue_frame(channel, wire) {
        Ok(()) => Ok(()),
        Err(HostError::WriteBackSaturated) => {
            tracing::warn!(
                event = wire.event,
                "host event dropped: the write queue stayed saturated before delivery"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The session's single writer task (§4.169): it alone owns the sink, so a
/// host that stops reading parks only this task — the session loop and
/// every in-flight dispatch deadline keep being polled. One frame at a
/// time, in enqueue order. The first I/O failure is reported on the
/// failure channel and the task returns, dropping the sink (the same EOF
/// semantics the inline write path had).
async fn run_host_writer<S>(
    mut frames: mpsc::Receiver<String>,
    mut sink: SplitSink<Framed<S, LinesCodec>, String>,
    failures: mpsc::Sender<HostError>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = frames.recv().await {
        if let Err(error) = sink.feed(frame).await {
            let _ = failures.send(codec_failure(&error)).await;
            return;
        }
        if let Err(error) = sink.flush().await {
            let _ = failures.send(codec_failure(&error)).await;
            return;
        }
    }
}

struct DispatchCompletion {
    account_id: Option<String>,
    request_bytes: usize,
    write_result: Result<(), HostError>,
}

/// 一个已准入 dispatch 的全部资源守卫，生命周期覆盖整个 dispatch：
/// 提前 drop 任何一个都会让同账号请求交叠或丢掉全局上界。
///
/// 获取顺序固定为「账号互斥锁（仅 mutating）→ per-account lane → 全局
/// 兜底」：先拿账号锁再拿配额，避免一个忙账号攥着全局 permit 等自己
/// 的账号锁（旧的 acquire 注释已给出这个理由，per-account lane 之后
/// 仍然成立）。
struct HostDispatchPermit {
    /// per-account（或 unscoped 桶）lane permit；`link.finish` 走
    /// `_link_lane`，此项为 `None`。
    _account_lane: Option<OwnedSemaphorePermit>,
    /// 连接器全局兜底 permit；`link.finish` 豁免（它的等待窗口是人工
    /// 手机审批，按组有界），不计入全局 control 配额。
    _global_lane: Option<OwnedSemaphorePermit>,
    /// `link.finish` 的 per-group lane（ADR 0001 R3），与 dispatch lane
    /// 相互独立。
    _link_lane: Option<OwnedSemaphorePermit>,
    _account: Option<OwnedMutexGuard<()>>,
    _deleting: Option<DeletingAccountGuard>,
}

/// Marks an account as having a delete in progress for the whole dispatch
/// (refcounted, so overlapping deletes of the same account stay marked until
/// the last one finishes). Never held across an await in the guard itself.
struct DeletingAccountGuard {
    accounts: Arc<StdMutex<HashMap<String, usize>>>,
    account_key: String,
}

impl Drop for DeletingAccountGuard {
    fn drop(&mut self) {
        let Ok(mut accounts) = self.accounts.lock() else {
            return;
        };
        if let Some(count) = accounts.get_mut(&self.account_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                accounts.remove(&self.account_key);
            }
        }
    }
}

/// per-account lane 的键：`None` 是「无账号上下文」共享的 unscoped 桶。
type AccountLaneKey = (Option<String>, methods::Lane);

struct HostDispatchLimits {
    /// 全局兜底（per lane）：只做资源上界，不做账号间公平调度。
    global_control: Arc<Semaphore>,
    global_read: Arc<Semaphore>,
    global_send: Arc<Semaphore>,
    /// per-account lane：账号 + lane → 信号量。Weak-handle 纪律与
    /// `send_accounts` / `link_lanes` 相同：permit 自身持有 Arc，最后
    /// 一个 permit 释放后条目在下次 acquire 时回收。
    account_lanes: Mutex<HashMap<AccountLaneKey, Weak<Semaphore>>>,
    send_accounts: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    /// One bounded lane per proxy group for `link.finish` (ADR 0001 R3).
    /// Same weak-handle discipline as `send_accounts`.
    link_lanes: Mutex<HashMap<String, Weak<Semaphore>>>,
    /// Accounts with a delete in progress (refcounted). New mutating work for
    /// these accounts is rejected instead of queueing behind the delete.
    /// std mutex: only ever locked for a lookup/insert, never across an await.
    deleting_accounts: Arc<StdMutex<HashMap<String, usize>>>,
}

#[derive(Default)]
struct HostPendingBudget {
    total: usize,
    bytes: usize,
    by_account: HashMap<String, usize>,
}

impl HostPendingBudget {
    fn try_admit(&mut self, account_id: Option<&str>, request_bytes: usize) -> bool {
        let account_pending = account_id
            .and_then(|account| self.by_account.get(account))
            .copied()
            .unwrap_or(0);
        if self.total >= MAX_PENDING_HOST_REQUESTS
            || account_pending >= MAX_PENDING_HOST_REQUESTS_PER_ACCOUNT
            || self.bytes.saturating_add(request_bytes) > MAX_PENDING_HOST_BYTES
        {
            return false;
        }
        self.total += 1;
        self.bytes += request_bytes;
        if let Some(account) = account_id {
            *self.by_account.entry(account.to_string()).or_default() += 1;
        }
        metrics::set_host_pending(self.total);
        true
    }

    fn complete(&mut self, account_id: Option<&str>, request_bytes: usize) {
        self.total = self.total.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(request_bytes);
        metrics::set_host_pending(self.total);
        let Some(account_id) = account_id else {
            return;
        };
        if let Some(count) = self.by_account.get_mut(account_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.by_account.remove(account_id);
            }
        }
    }
}

/// 每账号 lane 的容量（与桌面 `requestScheduler.ts` 镜像，见上方常量注释）。
const fn lane_capacity(lane: methods::Lane) -> usize {
    match lane {
        methods::Lane::Control => CONTROL_CONCURRENCY,
        methods::Lane::Read => READ_CONCURRENCY,
        methods::Lane::Send => SEND_CONCURRENCY,
    }
}

/// 立即尝试取一个 lane permit；只有真正排队时才记一次等待。
///
/// ADR 0005 的观测面：per-account lane 上的排队是正常调度信号（同账号
/// 并发），全局兜底上的排队才是容量告警。信号量永不关闭，所以慢路径
/// 与旧 `acquire` 一样可以直接 unwrap。
async fn acquire_lane(semaphore: Arc<Semaphore>, record_wait: fn()) -> OwnedSemaphorePermit {
    match Arc::clone(&semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            record_wait();
            semaphore.acquire_owned().await.unwrap()
        }
    }
}

impl HostDispatchLimits {
    fn new() -> Self {
        Self {
            global_control: Arc::new(Semaphore::new(GLOBAL_CONTROL_CONCURRENCY)),
            global_read: Arc::new(Semaphore::new(GLOBAL_READ_CONCURRENCY)),
            global_send: Arc::new(Semaphore::new(GLOBAL_SEND_CONCURRENCY)),
            account_lanes: Mutex::new(HashMap::new()),
            send_accounts: Mutex::new(HashMap::new()),
            link_lanes: Mutex::new(HashMap::new()),
            deleting_accounts: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// 全局兜底信号量（容量 = 每账号容量 × 典型账号数；lane 归属在
    /// `methods::METHODS`）。它只在资源总量上兜底，不承担账号间公平性。
    fn global_lane(&self, lane: methods::Lane) -> Arc<Semaphore> {
        match lane {
            methods::Lane::Control => self.global_control.clone(),
            methods::Lane::Read => self.global_read.clone(),
            methods::Lane::Send => self.global_send.clone(),
        }
    }

    /// 取（或惰性创建）某账号在某条 lane 上的信号量。`account_id` 为
    /// `None` 时落 unscoped 共享桶（同样 per-lane）：没有账号上下文
    /// 的任务彼此之间仍要排队，只是不与任何账号争夺配额。
    ///
    /// Weak-handle 纪律照抄 `send_accounts` / `link_lanes`：permit 自己
    /// 持有 Arc，条目在最后一个 permit 释放后于下次调用时被回收。
    async fn account_lane(&self, account_id: Option<&str>, kind: methods::Lane) -> Arc<Semaphore> {
        let key = (account_id.map(str::to_string), kind);
        let mut lanes = self.account_lanes.lock().await;
        lanes.retain(|_, lane| lane.strong_count() > 0);
        if let Some(lane) = lanes.get(&key).and_then(Weak::upgrade) {
            lane
        } else {
            let lane = Arc::new(Semaphore::new(lane_capacity(kind)));
            lanes.insert(key, Arc::downgrade(&lane));
            lane
        }
    }

    /// Acquire the dispatch permit for one host request.
    ///
    /// 配额模型（ADR 0005）：每个账号每条 lane 一套信号量（control 1 /
    /// read 4 / send 2，与桌面 `requestScheduler.ts` 镜像），外加一组
    /// 进程级兜底（control 4 / read 16 / send 8）。这样 A 账号占满自己的
    /// read 时 B 账号仍能立刻 dispatch——旧实现只有进程级 read 4，
    /// 无关账号会被无端串行化。
    ///
    /// Mutating, account-scoped methods (`messages.sendText`,
    /// `messages.remoteDelete`, `contacts.sync`, `accounts.deleteLocalData`;
    /// membership comes from the single method table, `methods::METHODS`)
    /// share one per-account mutex, which doubles as the delete drain barrier:
    ///
    /// - A delete first marks the account as deleting (new sends/syncs are
    ///   rejected with `ACCOUNT_NOT_FOUND` instead of queueing), then waits on
    ///   the account mutex until every already-admitted send/sync for that
    ///   account has fully finished — including its completion write to the
    ///   store and its response write to the host. Only then does the upstream
    ///   `deleteLocalAccountData` and the local row cascade run. A "sent
    ///   upstream but locally rowless" message is therefore impossible.
    /// - The deleting mark is checked before taking the mutex, so a send that
    ///   raced past the check can still queue behind the delete; it then fails
    ///   deterministically at send preparation because the account row is
    ///   gone. Either interleaving linearizes the send strictly before or
    ///   strictly after the delete.
    async fn acquire(
        &self,
        method: &str,
        account_id: Option<&str>,
        lane_key: Option<&str>,
    ) -> Result<HostDispatchPermit, ApiError> {
        if methods::is_account_scoped_mutating(method) {
            let account_key = account_id.unwrap_or("").to_string();
            let deleting = if method == "accounts.deleteLocalData" {
                let mut accounts = self.deleting_accounts.lock().unwrap();
                *accounts.entry(account_key.clone()).or_insert(0) += 1;
                Some(DeletingAccountGuard {
                    accounts: Arc::clone(&self.deleting_accounts),
                    account_key: account_key.clone(),
                })
            } else {
                if self
                    .deleting_accounts
                    .lock()
                    .unwrap()
                    .contains_key(&account_key)
                {
                    return Err(ApiError::new(
                        "ACCOUNT_NOT_FOUND",
                        "account is being deleted",
                        false,
                    ));
                }
                None
            };
            let account_lock = {
                let mut accounts = self.send_accounts.lock().await;
                accounts.retain(|_, lock| lock.strong_count() > 0);
                if let Some(lock) = accounts.get(&account_key).and_then(Weak::upgrade) {
                    lock
                } else {
                    let lock = Arc::new(Mutex::new(()));
                    accounts.insert(account_key, Arc::downgrade(&lock));
                    lock
                }
            };
            // 顺序固定：账号锁 → per-account lane → 全局兜底。先账号后
            // 配额的旧理由仍然成立：一个忙账号不能一边攥着 permit 一边
            // 等自己的账号锁。
            let account = account_lock.lock_owned().await;
            let kind = methods::lane(method);
            let account_lane = acquire_lane(
                self.account_lane(account_id, kind).await,
                metrics::record_host_account_lane_wait,
            )
            .await;
            let global_lane = acquire_lane(
                self.global_lane(kind),
                metrics::record_host_global_lane_wait,
            )
            .await;
            return Ok(HostDispatchPermit {
                _account_lane: Some(account_lane),
                _global_lane: Some(global_lane),
                _link_lane: None,
                _account: Some(account),
                _deleting: deleting,
            });
        }

        if method == "link.finish" {
            // Dispatch resolves the owning group first; a finish without a
            // resolvable session is answered before any lane is taken, so a
            // missing key here means the caller skipped that step.
            let Some(group_key) = lane_key else {
                return Err(ApiError::new(
                    "LINK_NOT_FOUND",
                    "link session was not found",
                    false,
                ));
            };
            let lane = {
                let mut lanes = self.link_lanes.lock().await;
                lanes.retain(|_, lane| lane.strong_count() > 0);
                if let Some(lane) = lanes.get(group_key).and_then(Weak::upgrade) {
                    lane.clone()
                } else {
                    let lane = Arc::new(Semaphore::new(LINK_WAIT_CONCURRENCY));
                    lanes.insert(group_key.to_string(), Arc::downgrade(&lane));
                    lane
                }
            };
            // Contention inside one group rejects immediately (the wire
            // contract answers the second concurrent finish with
            // LINK_IN_PROGRESS); another group's lane is untouched.
            let permit = lane.try_acquire_owned().map_err(|_| {
                ApiError::new(
                    "LINK_IN_PROGRESS",
                    "a link finish request is already active for this proxy group",
                    false,
                )
            })?;
            // `link.finish` 不占 dispatch lane 与全局兜底：它的等待窗口是
            // 人工手机审批，按组有界（ADR 0001 R3）就已足够；计入全局
            // control 会让一次待审批吃掉 1/4 的兜底配额。
            return Ok(HostDispatchPermit {
                _account_lane: None,
                _global_lane: None,
                _link_lane: Some(permit),
                _account: None,
                _deleting: None,
            });
        }

        let kind = methods::lane(method);
        let account_lane = acquire_lane(
            self.account_lane(account_id, kind).await,
            metrics::record_host_account_lane_wait,
        )
        .await;
        let global_lane = acquire_lane(
            self.global_lane(kind),
            metrics::record_host_global_lane_wait,
        )
        .await;
        Ok(HostDispatchPermit {
            _account_lane: Some(account_lane),
            _global_lane: Some(global_lane),
            _link_lane: None,
            _account: None,
            _deleting: None,
        })
    }
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("local IPC failed")]
    Io(#[from] io::Error),
    #[error("host frame is invalid")]
    InvalidFrame,
    /// The peer vanished mid-frame. Internal only: it ends the session the same
    /// way a clean EOF does and never reaches the exit status or the host.
    #[error("host connection is gone")]
    PeerGone,
    /// The bounded host write queue stayed full (§4.169): the frame was
    /// dropped with a warn and the session continues. Internal only — the
    /// host never sees this face and it never ends the session.
    #[error("host write queue is saturated")]
    WriteBackSaturated,
    #[error("host authentication failed")]
    Authentication,
    #[error("engine runtime could not be stopped")]
    RuntimeShutdown,
}

/// Unix：父进程消失（被 reparent）时完成，让 `serve` 退出。
///
/// 判据是「父 PID 变化」而不是「父 PID == 1」：reparent 的目标不一定是 init。
/// 之所以不用「stdin EOF」：`--bootstrap-secret-stdin` 模式下密钥读完本来就是
/// EOF，把 EOF 当宿主死亡会让 connector 启动即退（台账 §23.7）。
#[cfg(unix)]
async fn parent_gone() {
    let parent = std::os::unix::process::parent_id();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        tick.tick().await;
        if std::os::unix::process::parent_id() != parent {
            return;
        }
    }
}

/// 非 Unix：Windows 侧已有 parent_pid 监控（main.rs 强制要求），此臂永不完成。
#[cfg(not(unix))]
async fn parent_gone() {
    std::future::pending::<()>().await;
}

pub async fn serve(
    listener: LocalListener,
    secret: BootstrapSecret,
    runtime: Arc<ProxyGroupRuntime>,
) -> Result<(), HostError> {
    let secret = Arc::new(secret);
    spawn_metrics_log(Arc::downgrade(&runtime));
    let busy_answers = Arc::new(Semaphore::new(HOST_BUSY_ANSWER_CONCURRENCY));
    loop {
        // P0（台账 §23）：Unix 下补「宿主进程消失即退」，与 Windows 的 parent_pid
        // 监控语义对齐。不加这条时 serve() 只有 ctrl_c / 连接 shutdown 两个出口，
        // 宿主崩溃后 connector 变孤儿进程，占着 endpoint 与数据目录不放。
        let parent_watch = parent_gone();
        let stream = tokio::select! {
            accepted = listener.accept() => accepted?,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                return Ok(());
            }
            _ = parent_watch => return Ok(()),
        };
        let authenticated = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let connection = handle_connection_until_shutdown(
            stream,
            secret.clone(),
            runtime.clone(),
            shutdown_rx,
            authenticated.clone(),
        );
        tokio::pin!(connection);
        let mut interrupted = false;
        // ADR 0006: one host session owns the connector. A second connection
        // is accepted only to be told so — it never queues in the kernel
        // backlog behind the live session. The first session keeps running;
        // the busy answer is bounded so a peer that stopped reading cannot
        // stall dispatch.
        let connection_result = loop {
            tokio::select! {
                result = &mut connection => break result,
                accepted = listener.accept() => match accepted {
                    Ok(stream) => {
                        // Spawn the answer so the live session keeps being
                        // polled; the ceiling bounds task growth under a
                        // connect flood, and an over-ceiling connection is
                        // closed without an answer.
                        if let Ok(permit) = busy_answers.clone().try_acquire_owned() {
                            tokio::spawn(async move {
                                let _permit = permit;
                                answer_host_busy(stream).await;
                            });
                        }
                    }
                    Err(error) => return Err(error.into()),
                },
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    interrupted = true;
                    let _ = shutdown_tx.send(true);
                    break connection.await;
                }
            }
        };
        if interrupted || authenticated.load(Ordering::Acquire) {
            match timeout(HOST_SHUTDOWN_TIMEOUT, runtime.shutdown()).await {
                Ok(result) => result.map_err(|_| HostError::RuntimeShutdown)?,
                // A stuck teardown must not keep the process alive: log and
                // exit with the connection outcome.
                Err(_) => tracing::warn!(
                    budget_ms = HOST_SHUTDOWN_TIMEOUT.as_millis() as u64,
                    "runtime shutdown exceeded the teardown budget"
                ),
            }
            return connection_result;
        }
        // A malformed or unauthenticated local probe must not consume the process. The first
        // successful authentication does: when that session ends, a fresh process and secret
        // are required.
    }
}

/// ADR 0006: answer a second host connection with an explicit busy frame and
/// close it. The frame is the same NDJSON envelope as every other event; it
/// deliberately does not send `runtime.challenge`, because a client that saw a
/// challenge would try to authenticate into a session it cannot own. The
/// answer carries fixed content only (a code, a static message, retryability)
/// — never a session id, account, or path.
async fn answer_host_busy<S>(stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(
        stream,
        LinesCodec::new_with_max_length(DEFAULT_HOST_FRAME_LIMIT),
    );
    let event = HostEvent::new(
        "runtime.busy",
        json!({
            "code": "HOST_BUSY",
            "message": "another host session already owns this connector",
            "retryable": true,
        }),
    );
    let Ok(line) = serde_json::to_string(&event) else {
        return;
    };
    let _ = timeout(HOST_BUSY_ANSWER_TIMEOUT, framed.send(line)).await;
}

#[cfg(test)]
async fn handle_connection<S>(
    stream: S,
    secret: Arc<BootstrapSecret>,
    runtime: Arc<ProxyGroupRuntime>,
) -> Result<(), HostError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    handle_connection_until_shutdown(
        stream,
        secret,
        runtime,
        shutdown_rx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

async fn handle_connection_until_shutdown<S>(
    stream: S,
    secret: Arc<BootstrapSecret>,
    runtime: Arc<ProxyGroupRuntime>,
    shutdown: watch::Receiver<bool>,
    authenticated: Arc<AtomicBool>,
) -> Result<(), HostError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // A host that closed the socket abruptly ended its session; it did not
    // violate the protocol, and this process must still exit cleanly. Normalize
    // here rather than at any single failure point, because every read and write
    // in the session below can be the one that discovers the peer is gone.
    match run_host_session(stream, secret, runtime, shutdown, authenticated).await {
        Err(HostError::PeerGone) => Ok(()),
        other => other,
    }
}

async fn run_host_session<S>(
    stream: S,
    secret: Arc<BootstrapSecret>,
    runtime: Arc<ProxyGroupRuntime>,
    mut shutdown: watch::Receiver<bool>,
    authenticated: Arc<AtomicBool>,
) -> Result<(), HostError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let codec = LinesCodec::new_with_max_length(DEFAULT_HOST_FRAME_LIMIT);
    let mut framed = Framed::new(stream, codec);
    let challenge = PendingChallenge::generate();
    send_json(
        &mut framed,
        &HostEvent::new("runtime.challenge", challenge.public()),
    )
    .await?;

    let handshake_line = tokio::select! {
        line = timeout(HANDSHAKE_TIMEOUT, framed.next()) => {
            line
                .map_err(|_| HostError::Authentication)?
                .ok_or(HostError::Authentication)?
                .map_err(|_| HostError::InvalidFrame)?
        }
        _ = shutdown.changed() => return Ok(()),
    };
    let handshake: HostRequest =
        serde_json::from_str(&handshake_line).map_err(|_| HostError::InvalidFrame)?;
    if let Err(error) = handshake.validate_envelope() {
        send_json(
            &mut framed,
            &HostResponse::failure(handshake.request_id, error),
        )
        .await?;
        return Err(HostError::Authentication);
    }
    if handshake.method != "handshake" {
        send_json(
            &mut framed,
            &HostResponse::failure(
                handshake.request_id,
                ApiError::new("AUTHENTICATION_FAILED", "authentication failed", false),
            ),
        )
        .await?;
        return Err(HostError::Authentication);
    }
    let params: HandshakeParams = match serde_json::from_value(handshake.params) {
        Ok(params) => params,
        Err(_) => {
            send_json(
                &mut framed,
                &HostResponse::failure(
                    handshake.request_id,
                    ApiError::new("AUTHENTICATION_FAILED", "authentication failed", false),
                ),
            )
            .await?;
            return Err(HostError::Authentication);
        }
    };
    if challenge.verify(&secret, &params).is_err() {
        send_json(
            &mut framed,
            &HostResponse::failure(
                handshake.request_id,
                ApiError::new("AUTHENTICATION_FAILED", "authentication failed", false),
            ),
        )
        .await?;
        return Err(HostError::Authentication);
    }
    authenticated.store(true, Ordering::Release);

    let handshake_request_id = handshake.request_id;
    send_json(
        &mut framed,
        &HostResponse::success(
            handshake_request_id.clone(),
            json!({
                "sessionId": random_identifier(),
                "apiVersion": API_VERSION,
                "capabilities": advertised_capabilities(runtime.media_ingest_armed()),
            }),
        ),
    )
    .await?;

    let (sink, mut stream) = framed.split();
    // §4.169: every post-authentication write goes through the bounded
    // queue and the single writer task below. The loop never awaits socket
    // writability, so a host that stops reading wedges only the writer —
    // every in-flight dispatch deadline stays observable.
    let (frames_tx, frames_rx) = mpsc::channel(HOST_WRITE_QUEUE_CAPACITY);
    let (failures_tx, mut failures_rx) = mpsc::channel::<HostError>(1);
    let writer = HostWriteChannel {
        frames: frames_tx,
        failures: failures_tx,
    };
    tokio::spawn(run_host_writer(frames_rx, sink, writer.failures.clone()));
    let limits = Arc::new(HostDispatchLimits::new());
    let mut dispatches = FuturesUnordered::<DispatchFuture>::new();
    let mut pending = HostPendingBudget::default();
    let mut recent_ids = RecentRequestIds::default();
    recent_ids.insert(handshake_request_id);
    let mut registry_events = runtime.subscribe();
    let mut host_events = runtime.subscribe_host();
    let connection_result = loop {
        tokio::select! {
            line = stream.next() => {
                let Some(line) = line else {
                    break Ok(());
                };
                let line = match line {
                    Ok(line) => line,
                    Err(error) => break Err(codec_failure(&error)),
                };
                let request_bytes = line.len();
                let request: HostRequest = match serde_json::from_str(&line) {
                    Ok(request) => request,
                    Err(_) => break Err(HostError::InvalidFrame),
                };
                if let Err(error) = request.validate_envelope() {
                    // KT (send latency probe): envelope 级校验拒绝归因
                    // （requestId 形状 / params 非对象两闸；应答原样）。
                    if error.code == "INVALID_REQUEST" {
                        let field = if error.message.contains("requestId") {
                            "requestId"
                        } else {
                            "params"
                        };
                        probe_reject_detail(&request.method, field, &error.message);
                    }
                    let response = HostResponse::failure(request.request_id, error);
                    match enqueue_frame(&writer, &response) {
                        Ok(()) => {}
                        Err(HostError::WriteBackSaturated) => {
                            tracing::warn!(
                                method_class = metrics::method_class(&request.method),
                                "host answer dropped: the write queue stayed saturated"
                            );
                        }
                        Err(error) => break Err(error),
                    }
                    continue;
                }
                if !recent_ids.insert(request.request_id.clone()) {
                    // KT (send latency probe): 会话级 requestId 重放闸归因。
                    probe_reject_detail(
                        &request.method,
                        "requestId",
                        "requestId was already used in this session",
                    );
                    let response = HostResponse::failure(
                        request.request_id,
                        ApiError::new("INVALID_REQUEST", "requestId was already used in this session", false),
                    );
                    match enqueue_frame(&writer, &response) {
                        Ok(()) => {}
                        Err(HostError::WriteBackSaturated) => {
                            tracing::warn!(
                                method_class = metrics::method_class(&request.method),
                                "host answer dropped: the write queue stayed saturated"
                            );
                        }
                        Err(error) => break Err(error),
                    }
                    continue;
                }

                let method = request.method.clone();
                let account_id = request_account_id(&request);
                if !pending.try_admit(account_id.as_deref(), request_bytes) {
                    tracing::warn!(
                        method_class = metrics::method_class(&method),
                        account_id = account_id.as_deref().unwrap_or("-"),
                        request_bytes,
                        "host request rejected: capacity exceeded"
                    );
                    // KT (send latency probe): queue-full gate face (admit
                    // budget) — the rejection reason behind the counters.
                    if metrics::method_class(&method) == "send" {
                        tracing::warn!(
                            target: "send_latency_probe",
                            stage = "connector.reject-gate",
                            gate = "admit_capacity",
                            method = %method,
                            op = %request
                                .params
                                .get("clientRequestId")
                                .and_then(|value| value.as_str())
                                .unwrap_or("-"),
                            account8 = %probe_prefix8(account_id.as_deref()),
                            "send-latency-probe",
                        );
                    }
                    let response = HostResponse::failure(
                        request.request_id,
                        ApiError::new(
                            "INTERNAL_ERROR",
                            "connector request capacity exceeded",
                            true,
                        ),
                    );
                    match enqueue_frame(&writer, &response) {
                        Ok(()) => {}
                        Err(HostError::WriteBackSaturated) => {
                            tracing::warn!(
                                method_class = metrics::method_class(&method),
                                "host answer dropped: the write queue stayed saturated"
                            );
                        }
                        Err(error) => break Err(error),
                    }
                    continue;
                }

                let task_account = account_id.clone();
                let task_runtime = runtime.clone();
                let task_writer = writer.clone();
                let task_limits = limits.clone();
                dispatches.push(async move {
                    // KT (send latency probe): the clientRequestId is the
                    // cross-repo join key (desktop main probe logs the same
                    // value); fall back to "-" for send-family methods that
                    // do not carry one. Red-line safe: id-shaped only.
                    let probe_op = request
                        .params
                        .get("clientRequestId")
                        .and_then(|value| value.as_str())
                        .unwrap_or("-")
                        .to_string();
                    // A rejected acquire (mutating work on an account whose
                    // delete is draining, a second concurrent finish in one
                    // group) never reaches dispatch; it is answered directly
                    // with the non-retryable error.
                    let started = Instant::now();
                    // `link.finish` routes through the lane of the group that
                    // owns the session (ADR 0001 R3); a session that no longer
                    // exists anywhere fails closed without occupying any lane.
                    // Unparseable finish params fall through to dispatch so its
                    // own parse produces the INVALID_REQUEST answer.
                    let link_params = if method == "link.finish" {
                        serde_json::from_value::<LinkSessionParams>(request.params.clone()).ok()
                    } else {
                        None
                    };
                    // §4.168: an admitted request must be answered within the
                    // stall budget. Both pre-dispatch waits (the lane permit,
                    // possibly held forever by a wedged earlier dispatch) and
                    // the dispatch itself are bounded by the same deadline;
                    // expiry answers the retryable `INTERNAL_ERROR` deadline
                    // face — the same shape as the capacity face — and drops
                    // the abandoned future, whose guards release the lane and
                    // the pending budget with it.
                    let stall_exempt = method.starts_with("link.");
                    let request_id = request.request_id.clone();
                    let acquired: Result<HostDispatchPermit, ApiError> = {
                        let acquire = async {
                            match &link_params {
                                Some(params) => {
                                    let Some(group) = task_runtime
                                        .resolve_link_session(&params.link_session_id)
                                        .await
                                    else {
                                        return Err(ApiError::new(
                                            "LINK_NOT_FOUND",
                                            "link session was not found",
                                            false,
                                        ));
                                    };
                                    task_limits
                                        .acquire(&method, task_account.as_deref(), Some(&group))
                                        .await
                                }
                                None => {
                                    task_limits
                                        .acquire(&method, task_account.as_deref(), None)
                                        .await
                                }
                            }
                        };
                        acquire_within_stall_budget(
                            acquire,
                            stall_exempt,
                            &method,
                            account_id.as_deref(),
                            request_bytes,
                        )
                        .await
                    };
                    // KT (send latency probe): admit → engine-call start.
                    // Everything before this point is the queueing segment
                    // (lane permit + per-account mutex + delete barrier) the
                    // dispatch duration_ms never exposed.
                    if acquired.is_ok() && metrics::method_class(&method) == "send" {
                        tracing::warn!(
                            target: "send_latency_probe",
                            stage = "connector.engine-call-start",
                            method = %method,
                            op = %probe_op,
                            account8 = %probe_prefix8(account_id.as_deref()),
                            wait_ms = started.elapsed().as_millis() as u64,
                            "send-latency-probe",
                        );
                    }
                    // The permit itself must stay bound for the whole
                    // dispatch: dropping it early (e.g. by reducing the
                    // acquire result to its error) would release the account
                    // mutex, the delete barrier and the lane before the work
                    // has run, letting same-account requests interleave.
                    let response = match acquired {
                        Ok(_permit) => {
                            if stall_exempt {
                                dispatch(request, &task_runtime).await
                            } else {
                                dispatch_within_stall_budget(
                                    async move { dispatch(request, &task_runtime).await },
                                    request_id,
                                    &method,
                                    account_id.as_deref(),
                                    request_bytes,
                                )
                                .await
                            }
                        }
                        Err(error) => HostResponse::failure(request_id, error),
                    };
                    let elapsed = started.elapsed();
                    let method_class = metrics::method_class(&method);
                    let result_class = metrics::result_class(response.error.as_ref());
                    metrics::record_request(method_class, result_class, elapsed);
                    // KT (send latency probe): one line per send-class
                    // failure carrying the wire rejection reason — the error
                    // code names the gate (validation / account busy /
                    // link conflict / upstream deny). Codes are fixed
                    // classification literals; nothing content-shaped.
                    if method_class == "send"
                        && let Some(error) = response.error.as_ref()
                    {
                        tracing::warn!(
                            target: "send_latency_probe",
                            stage = "connector.send-result",
                            method = %method,
                            op = %probe_op,
                            code = error.code,
                            class = result_class,
                            retryable = error.retryable,
                            dur_ms = elapsed.as_millis() as u64,
                            "send-latency-probe",
                        );
                    }
                    // The doctor's recent-error ring (§4.79): every host
                    // dispatch failure lands its wire error code as a family.
                    if let Some(error) = response.error.as_ref() {
                        crate::doctor::record_host_error(error.code, error.retryable);
                    }
                    log_dispatch(
                        method_class,
                        result_class,
                        response.error.as_ref().map(|error| error.code),
                        task_account.as_deref(),
                        request_bytes,
                        elapsed,
                    );
                    // §4.169: the answer enters the bounded write queue and
                    // the future returns immediately — a peer that stopped
                    // reading parks only the writer task, so the pending
                    // budget always releases and every §4.168 deadline stays
                    // observable. A saturated queue drops this answer with a
                    // warn (honest: it was never delivered) and keeps the
                    // session alive.
                    let write_result = match enqueue_frame(&task_writer, &response) {
                        Ok(()) => Ok(()),
                        Err(HostError::WriteBackSaturated) => {
                            tracing::warn!(
                                method = %method,
                                method_class = method_class,
                                account_id = task_account.as_deref().unwrap_or("-"),
                                request_bytes,
                                "host answer dropped: the write queue stayed saturated before delivery"
                            );
                            Ok(())
                        }
                        Err(error) => Err(error),
                    };
                    DispatchCompletion {
                        account_id: task_account,
                        request_bytes,
                        write_result,
                    }
                }.boxed());
            }
            completion = dispatches.next(), if !dispatches.is_empty() => {
                if let Some(completion) = completion {
                    pending.complete(
                        completion.account_id.as_deref(),
                        completion.request_bytes,
                    );
                    if let Err(error) = completion.write_result {
                        break Err(error);
                    }
                }
            }
            failure = failures_rx.recv() => {
                // §4.169: the writer task owns the sink, so its first I/O
                // failure is the session's write failure — end exactly as a
                // direct write error did (PeerGone normalization happens at
                // the same boundary below).
                break Err(failure.unwrap_or(HostError::PeerGone));
            }
            _ = shutdown.changed() => {
                break Ok(());
            }
            event = registry_events.recv() => {
                match event {
                    Ok(event) => {
                        let wire: HostEvent<Value> = match event {
                            // The aggregate keeps the pre-Phase-4 shape exactly.
                            RegistryEvent::AggregateStateChanged(status) => {
                                HostEvent::new(
                                    "runtime.stateChanged",
                                    serde_json::to_value(status).unwrap_or(Value::Null),
                                )
                            }
                            RegistryEvent::GroupStateChanged { group_id, status } => {
                                let mut payload = serde_json::to_value(&status)
                                    .unwrap_or(Value::Null);
                                if let Some(object) = payload.as_object_mut() {
                                    object.insert("groupId".into(), json!(group_id));
                                }
                                HostEvent::new("proxyGroup.stateChanged", payload)
                            }
                            RegistryEvent::ResourcePressure {
                                state,
                                pid,
                                rss_bytes,
                                group_id,
                            } => HostEvent::new(
                                "runtime.resourcePressure",
                                json!({
                                    "state": state,
                                    "pid": pid,
                                    "rssBytes": rss_bytes,
                                    "groupId": group_id
                                }),
                            ),
                            RegistryEvent::ProtocolWarning { kind } => {
                                crate::doctor::record_protocol_warning(kind);
                                HostEvent::new(
                                    "runtime.protocolWarning",
                                    json!({ "kind": kind }),
                                )
                            }
                            RegistryEvent::StorageChanged { state } => HostEvent::new(
                                "runtime.storageChanged",
                                json!({ "state": state }),
                            ),
                        };
                        enqueue_event_or_break(&writer, &wire)?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        enqueue_event_or_break(
                            &writer,
                            &HostEvent::new(
                                "runtime.protocolWarning",
                                json!({ "kind": "eventBackpressure" }),
                            ),
                        )?;
                    }
                    Err(broadcast::error::RecvError::Closed) => break Ok(()),
                }
            }
            event = host_events.recv() => {
                match event {
                    Ok(event) => {
                        let wire = host_event_frame(event)?;
                        enqueue_event_or_break(&writer, &wire)?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        enqueue_event_or_break(
                            &writer,
                            &HostEvent::new(
                                "runtime.protocolWarning",
                                json!({ "kind": "eventBackpressure" }),
                            ),
                        )?;
                    }
                    Err(broadcast::error::RecvError::Closed) => break Ok(()),
                }
            }
        }
    };

    // Closing the authenticated host connection owns runtime shutdown. This
    // resolves dispatched mutating calls as unknown before task futures drop.
    // Teardown is bounded: each engine shutdown has its own timeout-plus-kill
    // path, and this outer budget covers the rest, so a stuck component
    // cannot keep the process alive after its host is gone.
    if timeout(HOST_SHUTDOWN_TIMEOUT, runtime.shutdown())
        .await
        .is_err()
    {
        tracing::warn!(
            budget_ms = HOST_SHUTDOWN_TIMEOUT.as_millis() as u64,
            "runtime shutdown exceeded the teardown budget"
        );
    }
    let _ = timeout(HOST_DISPATCH_DRAIN_TIMEOUT, async {
        while let Some(completion) = dispatches.next().await {
            pending.complete(completion.account_id.as_deref(), completion.request_bytes);
        }
    })
    .await;
    // §4.168: the drain above cannot complete a dispatch that wedged past
    // every budget, so the process-global gauge would keep the stale count
    // after the session that owned it is gone. All dispatch futures are
    // done or dropped here and this process serves no second authenticated
    // session, so the honest gauge value is zero.
    metrics::set_host_pending(0);
    connection_result
}

/// Classify a codec failure: losing the peer is the end of a session, while a
/// frame we could not parse or that broke the line limit is a protocol error.
fn codec_failure(error: &LinesCodecError) -> HostError {
    let LinesCodecError::Io(error) = error else {
        return HostError::InvalidFrame;
    };
    match error.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::NotConnected => HostError::PeerGone,
        _ => HostError::InvalidFrame,
    }
}

fn request_account_id(request: &HostRequest) -> Option<String> {
    request
        .params
        .get("accountId")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Periodic redacted metrics dump (plan §8): one structured log line per
/// series, plus each engine's latest RSS sample (optimization-plan §6.4 M3.4)
/// read from the runtime status. Process-lifetime task; nothing is exported
/// over any socket. The runtime is held through a `Weak` so the task never
/// keeps the runtime alive past the serve loop.
fn spawn_metrics_log(runtime: std::sync::Weak<ProxyGroupRuntime>) {
    tokio::spawn(async move {
        let mut ticker = interval(METRICS_LOG_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Skip the immediate first tick so startup stays quiet.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            metrics::log_snapshot();
            if let Some(runtime) = runtime.upgrade() {
                // Contract revision 1.282 (§4.266): the store's own health —
                // schema version, gate verdict, file sizes, snapshot outcome —
                // rides the same periodic line, so an upgrade that rolled back
                // is visible in logs without a doctor call.
                metrics::log_store_health(&runtime.store().health());
                // Contract revision 1.283 (§4.267): the ledger's own series —
                // a floor that stopped advancing, or a ledger pinned at its
                // byte ceiling, has to be visible without a doctor call.
                metrics::log_event_log_health(&runtime.store().event_log_health());
                let status = runtime.status().await;
                let samples: Vec<_> = status
                    .proxy_groups
                    .into_iter()
                    .map(|group| (group.group_id, group.rss_bytes))
                    .collect();
                metrics::log_engine_rss(&samples);
                // O1: the handshake face beside the RSS sample — per engine
                // slot: the engine's own version, the contract revision it
                // states, and the connector's verdict.
                let contracts = runtime.engine_contract_samples().await;
                metrics::log_engine_contract(&contracts);
            }
        }
    });
}

/// One completed host dispatch, classified and redacted (plan §8): method
/// category, opaque account id, request size, duration, and result class. A
/// successful read/control poll stays at debug level so the default output
/// shows mutating work and failures only.
/// 发送延迟探针账号/请求 id 前缀：前 8 字符（字符界安全截取）。红线：
/// 只接受 id 与固定分类词，正文/号码/群名永不入日志。
fn probe_prefix8(value: Option<&str>) -> String {
    value.unwrap_or("-").chars().take(8).collect()
}

/// KT (send latency probe): 校验拒绝结构化归因单点（connector.reject-detail，
/// 既有 reject-gate 探针的补充维度——gate 行回答「哪个预算/容量闸拒的」，
/// 本行回答「哪个方法哪个字段被哪条校验拒的」）。每个 INVALID_REQUEST
/// 校验闸落一行：method=方法全名、field=校验失败字段名（参数形状闸固定
/// "params"，多字段闸逗号并列）、reason=校验词（即该闸应答 message 原文
/// ——全部静态字面量）。红线：只接受方法名/字段名/固定校验词，正文/
/// 号码/群名永不入日志。
fn probe_reject_detail(method: &str, field: &str, reason: &str) {
    tracing::warn!(
        target: "send_latency_probe",
        stage = "connector.reject-detail",
        method = %method,
        field = %field,
        reason = %reason,
        "send-latency-probe",
    );
}

/// 校验闸应答构造面：落 [`probe_reject_detail`] 归因行并返回与原
/// `ApiError::new("INVALID_REQUEST", reason, false)` 逐字节相同的应答
/// （wire 零变化——只是借道本单点同步落探针行）。
fn reject_probe(method: &str, field: &str, reason: &'static str) -> ApiError {
    probe_reject_detail(method, field, reason);
    ApiError::new("INVALID_REQUEST", reason, false)
}

fn log_dispatch(
    method_class: &'static str,
    result_class: &'static str,
    error_code: Option<&'static str>,
    account_id: Option<&str>,
    request_bytes: usize,
    duration: Duration,
) {
    let account_id = account_id.unwrap_or("-");
    let error_code = error_code.unwrap_or("-");
    let duration_ms = duration.as_millis() as u64;
    match result_class {
        "ok" if matches!(method_class, "read" | "control") => tracing::debug!(
            method_class,
            result_class,
            account_id,
            request_bytes,
            duration_ms,
            "host request completed"
        ),
        "ok" => tracing::info!(
            method_class,
            result_class,
            account_id,
            request_bytes,
            duration_ms,
            "host request completed"
        ),
        _ => tracing::warn!(
            method_class,
            result_class,
            error_code,
            account_id,
            request_bytes,
            duration_ms,
            "host request failed"
        ),
    }
}

/// §4.59 (contract revision 1.66): the two mutually exclusive payload forms
/// of `messages.attachments.send` — the §4.12 singular attachment (the
/// historical wire shape, unchanged) and the §4.59 plural `attachments`
/// array (the official forward face). `dataBase64`/`sizeBytes` stay optional
/// keys at the serde layer only because the form selection happens here;
/// each form's requirements are enforced deterministically at this boundary,
/// before any pending row exists.
enum AttachmentSendForm {
    Singular {
        data_base64: String,
        size_bytes: u64,
        filename: Option<String>,
        content_type: Option<String>,
        blur_hash: Option<String>,
    },
    Plural {
        entries: Vec<crate::service::MessagesSendAttachmentEntry>,
    },
}

/// §4.168: the lane-permit wait of one admitted dispatch, bounded by the
/// stall budget. A permit held forever by a wedged earlier dispatch used to
/// park every later same-lane request here with no timeout, no warn and no
/// answer — the admitted-but-forever-pending shape the intermittent-send
/// audit hit. Expiry warns once (the §4.166 fields, acquire-shaped message)
/// and answers the retryable `INTERNAL_ERROR` deadline face; the request
/// provably never started, so the face is honest for every method class.
/// `link.*` waits are exempt with the caller.
async fn acquire_within_stall_budget(
    acquire: impl Future<Output = Result<HostDispatchPermit, ApiError>>,
    stall_exempt: bool,
    method: &str,
    account_id: Option<&str>,
    request_bytes: usize,
) -> Result<HostDispatchPermit, ApiError> {
    if stall_exempt {
        return acquire.await;
    }
    match timeout(HOST_DISPATCH_STALL_WARN_AFTER, acquire).await {
        Ok(acquired) => acquired,
        Err(_) => {
            tracing::warn!(
                method = %method,
                method_class = metrics::method_class(method),
                account_id = account_id.unwrap_or("-"),
                request_bytes,
                stall_after_ms = HOST_DISPATCH_STALL_WARN_AFTER.as_millis() as u64,
                "host request still pending; no lane permit was granted before the stall budget expired"
            );
            // KT (send latency probe): lane-permit wait exceeded the stall
            // budget — the "lane full / wedged earlier dispatch" face.
            if metrics::method_class(method) == "send" {
                tracing::warn!(
                    target: "send_latency_probe",
                    stage = "connector.reject-gate",
                    gate = "lane_wait_budget",
                    method = %method,
                    account8 = %probe_prefix8(account_id),
                    stall_after_ms = HOST_DISPATCH_STALL_WARN_AFTER.as_millis() as u64,
                    "send-latency-probe",
                );
            }
            Err(ApiError::new(
                "INTERNAL_ERROR",
                "connector dispatch budget expired before dispatch",
                true,
            ))
        }
    }
}

/// §4.168: the execution of one permitted dispatch, bounded by the stall
/// budget. A dispatch wedged past every face budget used to warn once and
/// then hang forever — the permit, the pending budget and the answer itself
/// all stayed parked. Expiry emits the §4.166 stall warn (byte-identical
/// fields and message) and answers the retryable `INTERNAL_ERROR` deadline
/// face; the abandoned future drops at its await point, releasing every
/// guard it holds (lane permit, account mutex, store locks) exactly like a
/// connection teardown does.
async fn dispatch_within_stall_budget(
    dispatching: impl Future<Output = HostResponse>,
    request_id: String,
    method: &str,
    account_id: Option<&str>,
    request_bytes: usize,
) -> HostResponse {
    tokio::pin!(dispatching);
    match timeout(HOST_DISPATCH_STALL_WARN_AFTER, &mut dispatching).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                method = %method,
                method_class = metrics::method_class(method),
                account_id = account_id.unwrap_or("-"),
                request_bytes,
                stall_after_ms = HOST_DISPATCH_STALL_WARN_AFTER.as_millis() as u64,
                "host request still pending; every bounded face budget is exhausted"
            );
            // KT (send latency probe): the dispatch itself wedged past every
            // bounded budget and was abandoned (engine no-answer face).
            if metrics::method_class(method) == "send" {
                tracing::warn!(
                    target: "send_latency_probe",
                    stage = "connector.reject-gate",
                    gate = "dispatch_budget",
                    method = %method,
                    req8 = %probe_prefix8(Some(&request_id)),
                    account8 = %probe_prefix8(account_id),
                    stall_after_ms = HOST_DISPATCH_STALL_WARN_AFTER.as_millis() as u64,
                    "send-latency-probe",
                );
            }
            HostResponse::failure(
                request_id,
                ApiError::new(
                    "INTERNAL_ERROR",
                    "connector dispatch budget expired; the stalled dispatch was abandoned",
                    true,
                ),
            )
        }
    }
}

async fn dispatch(request: HostRequest, runtime: &Arc<ProxyGroupRuntime>) -> HostResponse {
    let request_id = request.request_id.clone();
    // Single terminal-account gate for every send-family mutating method.
    // The MRM group-send path uses a cached sender key and never calls
    // new_message_sender, so per-method auth checks miss it; this choke point
    // is authoritative for all current and future account-scoped mutations.
    // deleteLocalData is deliberately exempt: unlinking must remain deletable.
    if methods::is_account_scoped_mutating(&request.method)
        && request.method != "accounts.deleteLocalData"
        && let Some(account_id) = request_account_id(&request)
        && let Ok(Some("device_unlinked")) = runtime.account_state(&account_id).await
    {
        return HostResponse::failure(
            request_id,
            ApiError::new(
                "ACCOUNT_UNLINKED",
                "device was unlinked by the account holder",
                false,
            ),
        );
    }
    match request.method.as_str() {
        "runtime.status" if empty_params(&request.params) => HostResponse::success(
            request_id,
            serde_json::to_value(runtime.status().await).unwrap_or(Value::Null),
        ),
        "runtime.start" if empty_params(&request.params) => match runtime.start().await {
            Ok(status) => HostResponse::success(
                request_id,
                serde_json::to_value(status).unwrap_or(Value::Null),
            ),
            Err(failure) => HostResponse::failure(request_id, map_start_failure(failure)),
        },
        "runtime.stop" if empty_params(&request.params) => match runtime.stop().await {
            Ok(status) => HostResponse::success(
                request_id,
                serde_json::to_value(status).unwrap_or(Value::Null),
            ),
            Err(failure) => HostResponse::failure(request_id, map_stop_failure(failure)),
        },
        // D4 所有权执行面(阶段1 批1-5c):Main 所有权表裁决的 connector 执行
        // 臂。槽级操作——孤儿槽不走账号行解析(那会恰好拒掉清理对象);幂等,
        // `already-settled` 是合法答案不是错误。隔离移 `.quarantine-*`(字节
        // 保留可审计);休眠停引擎留目录(冷槽,下次请求自动唤醒)。
        "ownership.quarantineSlot" => match ownership_slot_params(&request.params) {
            Ok((account_id, reason)) => {
                let removed = runtime
                    .ownership_quarantine_slot(&account_id, &reason)
                    .await;
                HostResponse::success(
                    request_id,
                    serde_json::json!({
                        "accountId": account_id,
                        "outcome": if removed { "quarantined" } else { "already-settled" },
                    }),
                )
            }
            Err(probe) => HostResponse::failure(request_id, probe),
        },
        "ownership.hibernateSlot" => match ownership_slot_params(&request.params) {
            Ok((account_id, _reason)) => {
                let removed = runtime.ownership_hibernate_slot(&account_id).await;
                HostResponse::success(
                    request_id,
                    serde_json::json!({
                        "accountId": account_id,
                        "outcome": if removed { "hibernated" } else { "already-settled" },
                    }),
                )
            }
            Err(probe) => HostResponse::failure(request_id, probe),
        },
        "runtime.status" | "runtime.start" | "runtime.stop" => HostResponse::failure(
            request_id,
            reject_probe(
                &request.method,
                "params",
                "this method requires empty params",
            ),
        ),
        // Read-only diagnostic face (contract revision 1.97, §4.79): one
        // payload covering the version chain, data-dir and lock status, the
        // recent error families, and the reused connectivity surfaces. The
        // whole implementation lives in `doctor`; the dispatch stays one arm.
        "runtime.doctor" if empty_params(&request.params) => HostResponse::success(
            request_id,
            serde_json::to_value(crate::doctor::collect(runtime).await).unwrap_or(Value::Null),
        ),
        "runtime.doctor" => HostResponse::failure(
            request_id,
            reject_probe(
                &request.method,
                "params",
                "this method requires empty params",
            ),
        ),
        // events.list (contract 1.283, §4.267): the durable change ledger's
        // read face. The caller presents {afterSeq?, token?, limit?} and gets
        // back one token-stamped page plus the reset verdict; a reset carries
        // no events and points at the floor. Params are a strict struct, so an
        // unknown key, a negative cursor or an out-of-range limit fails closed
        // here instead of being silently dropped.
        "events.list" => match serde_json::from_value::<EventsListParams>(request.params) {
            Ok(params) => match runtime.events_page(params).await {
                Ok(page) => HostResponse::success(
                    request_id,
                    serde_json::to_value(page).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("events.list", "params", "invalid events.list params"),
            ),
        },
        "accounts.list" if empty_params(&request.params) => match runtime.list_accounts().await {
            Ok(accounts) => HostResponse::success(
                request_id,
                serde_json::to_value(accounts).unwrap_or(Value::Null),
            ),
            Err(error) => HostResponse::failure(request_id, error.into_api()),
        },
        "accounts.list" => HostResponse::failure(
            request_id,
            reject_probe(
                &request.method,
                "params",
                "this method requires empty params",
            ),
        ),
        "accounts.deleteLocalData" => {
            match serde_json::from_value::<AccountDeleteLocalDataParams>(request.params) {
                Ok(params) => match runtime
                    .delete_local_account(params.account_id, params.operation_id)
                    .await
                {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.deleteLocalData",
                        "params",
                        "invalid accounts.deleteLocalData params",
                    ),
                ),
            }
        }
        "accounts.updateConfiguration" => {
            match serde_json::from_value::<AccountsUpdateConfigurationParams>(request.params) {
                Ok(params) => match runtime.update_account_configuration(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.updateConfiguration",
                        "params",
                        "invalid accounts.updateConfiguration params",
                    ),
                ),
            }
        }
        "accounts.setProfile" => {
            match serde_json::from_value::<AccountsSetProfileParams>(request.params) {
                Ok(params) => match runtime.set_profile(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.setProfile",
                        "params",
                        "invalid accounts.setProfile params",
                    ),
                ),
            }
        }
        "accounts.setExpireTimer" => {
            match serde_json::from_value::<AccountsSetExpireTimerParams>(request.params) {
                Ok(params) => match runtime.set_account_expire_timer(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.setExpireTimer",
                        "params",
                        "invalid accounts.setExpireTimer params",
                    ),
                ),
            }
        }
        "accounts.setUsername" => {
            match serde_json::from_value::<AccountsSetUsernameParams>(request.params) {
                Ok(params) => match runtime.set_username(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.setUsername",
                        "params",
                        "invalid accounts.setUsername params",
                    ),
                ),
            }
        }
        "accounts.getUsername" => {
            match serde_json::from_value::<AccountsGetUsernameParams>(request.params) {
                Ok(params) => match runtime.get_username(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.getUsername",
                        "params",
                        "invalid accounts.getUsername params",
                    ),
                ),
            }
        }
        "accounts.deviceCapabilities" => {
            match serde_json::from_value::<AccountsDeviceCapabilitiesParams>(request.params) {
                Ok(params) => match runtime.get_device_capabilities(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.deviceCapabilities",
                        "params",
                        "invalid accounts.deviceCapabilities params",
                    ),
                ),
            }
        }
        // accounts.getSyncState (contract revision 1.286, §4.281): the
        // login-window sync projection's read face — a pure pass-through of
        // the engine's {contacts, storage, profile, sinceMs} behind the shape
        // gate, answering the desktop gate's polling fallback (SIGNAL-STAGE1
        // §二 P-B-3). Read lane, no mutation, no local persistence: a repeated
        // call answers the same face by construction.
        "accounts.getSyncState" => {
            match serde_json::from_value::<AccountsGetSyncStateParams>(request.params) {
                Ok(params) => match runtime.get_sync_state(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.getSyncState",
                        "params",
                        "invalid accounts.getSyncState params",
                    ),
                ),
            }
        }
        // Device-plane faces (contract revision 1.122, §4.103): the read
        // projects the bounded device list verbatim (the engine's bare
        // `account` identity never crosses — the answer strips it); the write
        // answers {status: unlinked} on the definite success, with the
        // indeterminate outcome folding to SEND_OUTCOME_UNKNOWN and never
        // retried.
        "accounts.getDevices" => {
            match serde_json::from_value::<AccountsGetDevicesParams>(request.params) {
                Ok(params) => match runtime.get_devices(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.getDevices",
                        "params",
                        "invalid accounts.getDevices params",
                    ),
                ),
            }
        }
        "accounts.unlinkDevice" => {
            match serde_json::from_value::<AccountsUnlinkDeviceParams>(request.params) {
                Ok(params) => match runtime.unlink_device(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "accounts.unlinkDevice",
                        "params",
                        "invalid accounts.unlinkDevice params",
                    ),
                ),
            }
        }
        "username.lookup" => match serde_json::from_value::<UsernameLookupParams>(request.params) {
            Ok(params) => match runtime.lookup_usernames(params).await {
                Ok(result) => HostResponse::success(
                    request_id,
                    serde_json::to_value(result).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe(
                    "username.lookup",
                    "params",
                    "invalid username.lookup params",
                ),
            ),
        },
        // Phone lookup (contract revision 1.164, §4.162): the CDSI batch read
        // projects the engine's answer entry-for-entry (the keys ride the
        // engine's names verbatim); the structured error faces
        // (PHONE_INVALID / PHONE_RATE_LIMITED + data.retryAfterSeconds /
        // PHONE_SERVER_FAILED) pass through the global mapping untouched.
        "phone.lookup" => match serde_json::from_value::<PhoneLookupParams>(request.params) {
            Ok(params) => match runtime.lookup_phones(params).await {
                Ok(result) => HostResponse::success(
                    request_id,
                    serde_json::to_value(result).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("phone.lookup", "params", "invalid phone.lookup params"),
            ),
        },
        "link.start" => match serde_json::from_value::<LinkStartParams>(request.params) {
            Ok(params) => {
                match runtime
                    .start_link(params.device_name, params.proxy_group)
                    .await
                {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                }
            }
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("link.start", "params", "invalid link.start params"),
            ),
        },
        "link.finish" => match serde_json::from_value::<LinkSessionParams>(request.params) {
            Ok(params) => match runtime.finish_link(params.link_session_id).await {
                Ok(account) => HostResponse::success(
                    request_id,
                    serde_json::to_value(account).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("link.finish", "params", "invalid link.finish params"),
            ),
        },
        // Rotating link attempt (contract 1.286, §4.272): the engine mints a
        // fresh provisioning session for the same attempt on its own
        // `rotateLink` face. The connector records the new code as a new slot
        // (at most two live; a third retires the oldest) and keeps the commit
        // attempt-scoped. An engine without the face answers NOT_SUPPORTED and
        // the single slot keeps working — never an upstream protocol error
        // leaking to the host.
        "link.rotate" => match serde_json::from_value::<LinkRotateParams>(request.params) {
            Ok(params) => match runtime.rotate_link(params.link_attempt_id).await {
                Ok(result) => HostResponse::success(request_id, result),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("link.rotate", "params", "invalid link.rotate params"),
            ),
        },
        "link.cancel" => match serde_json::from_value::<LinkSessionParams>(request.params) {
            Ok(params) => match runtime.cancel_link(params.link_session_id).await {
                Ok(result) => HostResponse::success(request_id, result),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("link.cancel", "params", "invalid link.cancel params"),
            ),
        },
        "conversations.list" => {
            match serde_json::from_value::<ConversationsListParams>(request.params) {
                Ok(params) if (1..=MAX_PAGE_LIMIT).contains(&params.limit) => {
                    match runtime
                        .list_conversations(params.account_id, params.limit, params.cursor)
                        .await
                    {
                        Ok(page) => HostResponse::success(
                            request_id,
                            serde_json::to_value(page).unwrap_or(Value::Null),
                        ),
                        Err(error) => HostResponse::failure(request_id, error.into_api()),
                    }
                }
                Ok(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.list",
                        "limit",
                        "limit must be between 1 and 200",
                    ),
                ),
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.list",
                        "params",
                        "invalid conversations.list params",
                    ),
                ),
            }
        }
        "history.importStatus" => {
            match serde_json::from_value::<HistoryImportStatusParams>(request.params) {
                Ok(params) => match runtime.history_import_status(params.account_id).await {
                    Ok(status) => HostResponse::success(request_id, status),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "history.importStatus",
                        "params",
                        "invalid history.importStatus params",
                    ),
                ),
            }
        }
        // Link-time history import manual retry (contract revision 1.53,
        // §4.38): the params-gate arm — shape errors answer INVALID_REQUEST
        // before any state inspection; the ladder (NOT_RETRYABLE /
        // NO_ARCHIVE) rides the runtime call; the definite success is
        // {"armed": true, "state": "pending"}.
        "history.importRetry" => {
            match serde_json::from_value::<HistoryImportRetryParams>(request.params) {
                Ok(params) => match runtime.history_import_retry(params.account_id).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "history.importRetry",
                        "params",
                        "invalid history.importRetry params",
                    ),
                ),
            }
        }
        // Link-time history import cancel (contract revision 1.148, §4.146):
        // the params-gate arm — shape errors answer INVALID_REQUEST before
        // any state inspection; success is
        // {"accountId", "cancelled", "state"} and is idempotent in every
        // state (cancel never spends the attempt budget).
        "history.importCancel" => {
            match serde_json::from_value::<HistoryImportCancelParams>(request.params) {
                Ok(params) => match runtime.history_import_cancel(params.account_id).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "history.importCancel",
                        "params",
                        "invalid history.importCancel params",
                    ),
                ),
            }
        }
        // History attachment download (contract revision 1.57, §4.38 step
        // 3): the params-gate arm — shape errors answer INVALID_REQUEST
        // before any staging; the ladder (capability gate, resolve chain,
        // pointer-face holes, download/verify failures) rides the runtime
        // call; success is {"sizeBytes": N}.
        "history.attachmentDownload" => {
            match serde_json::from_value::<HistoryAttachmentDownloadParams>(request.params) {
                Ok(params) => match runtime.history_attachment_download(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "history.attachmentDownload",
                        "params",
                        "invalid history.attachmentDownload params",
                    ),
                ),
            }
        }
        // Live attachment download (contract revision 1.61, §4.54): the
        // params-gate arm — shape errors answer INVALID_REQUEST before any
        // staging; the ladder (capability gate, resolve chain, locator-ladder
        // holes, download/verify failures) rides the runtime call; success is
        // {"sizeBytes": N}.
        "attachments.download" => {
            match serde_json::from_value::<crate::service::AttachmentDownloadParams>(request.params)
            {
                Ok(params) => match runtime.attachment_download(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "attachments.download",
                        "params",
                        "invalid attachments.download params",
                    ),
                ),
            }
        }
        // Attachment backfill request (contract revision 1.175, §4.175):
        // the request half of the official backfill loop — same row
        // addressing as attachments.download, success is {"status":
        // "sent"|"unknown"} (receipt-class posture; the response arrives
        // asynchronously and merges fresh transit pointers into the row's
        // live-locator column). Shape errors answer INVALID_REQUEST before
        // any engine traffic.
        "attachments.requestBackfill" => {
            match serde_json::from_value::<crate::service::AttachmentBackfillRequestParams>(
                request.params,
            ) {
                Ok(params) => match runtime.request_attachment_backfill(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "attachments.requestBackfill",
                        "params",
                        "invalid attachments.requestBackfill params",
                    ),
                ),
            }
        }
        // Story-anchored attachment download (contract revision 1.86,
        // §4.71): the params-gate arm — a caller-supplied pointer with a
        // missing or wrong-typed required field answers INVALID_REQUEST at
        // this gate, before any staging or network traffic; the caps ladder
        // and pointer decode ride the runtime call; success is
        // {"sizeBytes": N}. The pointer never appears in any error or log.
        "stories.downloadAttachment" => {
            match serde_json::from_value::<crate::service::StoryAttachmentDownloadParams>(
                request.params,
            ) {
                Ok(params) => match runtime.story_attachment_download(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.downloadAttachment",
                        "params",
                        "invalid stories.downloadAttachment params",
                    ),
                ),
            }
        }
        // Story-anchored attachment open (contract revision 1.86, §4.71):
        // the handle mint over an already-landed file — the
        // messages.attachments.open arm shape without the row addressing.
        "stories.openAttachment" => {
            match serde_json::from_value::<crate::service::StoryOpenAttachmentParams>(
                request.params,
            ) {
                Ok(params) => match runtime.story_open_attachment(params).await {
                    Ok(view) => HostResponse::success(
                        request_id,
                        serde_json::to_value(view).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.openAttachment",
                        "params",
                        "invalid stories.openAttachment params",
                    ),
                ),
            }
        }
        "backups.export" => match serde_json::from_value::<BackupsExportParams>(request.params) {
            Ok(params) => match runtime.export_local_backup(&params.account_id).await {
                Ok(result) => HostResponse::success(request_id, result),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("backups.export", "params", "invalid backups.export params"),
            ),
        },
        "backups.exportPlaintext" => {
            match serde_json::from_value::<BackupsExportPlaintextParams>(request.params) {
                Ok(params) => match runtime.export_plaintext(&params.account_id).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.exportPlaintext",
                        "params",
                        "invalid backups.exportPlaintext params",
                    ),
                ),
            }
        }
        "backups.exportStatus" => {
            match serde_json::from_value::<BackupsExportStatusParams>(request.params) {
                Ok(params) => match runtime.export_backup_status(&params.account_id).await {
                    Ok(status) => HostResponse::success(request_id, status),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.exportStatus",
                        "params",
                        "invalid backups.exportStatus params",
                    ),
                ),
            }
        }
        "backups.exportFile.open" => {
            match serde_json::from_value::<BackupsExportFileOpenParams>(request.params) {
                Ok(params) => {
                    match runtime
                        .export_file_open(&params.account_id, &params.file)
                        .await
                    {
                        Ok(view) => HostResponse::success(request_id, view),
                        Err(error) => HostResponse::failure(request_id, error.into_api()),
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.exportFile.open",
                        "params",
                        "invalid backups.exportFile.open params",
                    ),
                ),
            }
        }
        "backups.exportFile.readChunk" => {
            match serde_json::from_value::<BackupsExportFileReadChunkParams>(request.params) {
                Ok(params) => {
                    match runtime
                        .export_file_read_chunk(&params.file_handle, params.offset)
                        .await
                    {
                        Ok(chunk) => HostResponse::success(request_id, chunk),
                        Err(error) => HostResponse::failure(request_id, error.into_api()),
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.exportFile.readChunk",
                        "params",
                        "invalid backups.exportFile.readChunk params",
                    ),
                ),
            }
        }
        "backups.exportFile.closeHandle" => {
            match serde_json::from_value::<BackupsExportFileCloseHandleParams>(request.params) {
                Ok(params) => match runtime.export_file_close_handle(&params.file_handle).await {
                    Ok(view) => HostResponse::success(request_id, view),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.exportFile.closeHandle",
                        "params",
                        "invalid backups.exportFile.closeHandle params",
                    ),
                ),
            }
        }
        "backups.importSnapshot" => {
            match serde_json::from_value::<BackupsImportSnapshotParams>(request.params) {
                Ok(params) => {
                    match runtime
                        .import_local_snapshot(&params.account_id, &params.snapshot_dir)
                        .await
                    {
                        Ok(result) => HostResponse::success(request_id, result),
                        Err(error) => HostResponse::failure(request_id, error.into_api()),
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.importSnapshot",
                        "params",
                        "invalid backups.importSnapshot params",
                    ),
                ),
            }
        }
        "backups.importSnapshotStatus" => {
            match serde_json::from_value::<BackupsImportSnapshotStatusParams>(request.params) {
                Ok(params) => match runtime.import_snapshot_status(&params.account_id).await {
                    Ok(status) => HostResponse::success(request_id, status),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.importSnapshotStatus",
                        "params",
                        "invalid backups.importSnapshotStatus params",
                    ),
                ),
            }
        }
        // Cloud-backup restore passthrough (contract revision 1.83, §4.69):
        // both arms are the params-gate shape — the account resolution and the
        // engine dispatch ride the runtime call; the start face answers
        // {"status": "started"} for a definite acceptance and
        // SEND_OUTCOME_UNKNOWN on an indeterminate mutating outcome, the
        // status face mirrors the engine's progress snapshot through the
        // projection's shape gate.
        "backups.restoreFromCloud" => {
            match serde_json::from_value::<BackupsRestoreFromCloudParams>(request.params) {
                Ok(params) => match runtime.restore_from_cloud(&params.account_id).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.restoreFromCloud",
                        "params",
                        "invalid backups.restoreFromCloud params",
                    ),
                ),
            }
        }
        "backups.cloudStatus" => {
            match serde_json::from_value::<BackupsCloudStatusParams>(request.params) {
                Ok(params) => match runtime.cloud_backup_status(&params.account_id).await {
                    Ok(status) => HostResponse::success(request_id, status),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.cloudStatus",
                        "params",
                        "invalid backups.cloudStatus params",
                    ),
                ),
            }
        }
        // Cloud-backup upload passthrough (contract revision 1.87, §4.72):
        // the same params-gate shape as the restore arms — the account
        // resolution, the engine dispatch, and the §10.2 artifact build
        // ride the runtime call; the start face answers
        // {"status": "started"} for a definite acceptance and
        // SEND_OUTCOME_UNKNOWN on an indeterminate mutating outcome, the
        // status face mirrors the engine's progress snapshot through the
        // projection's shape gate.
        "backups.uploadToCloud" => {
            match serde_json::from_value::<BackupsUploadToCloudParams>(request.params) {
                Ok(params) => match runtime.upload_to_cloud(&params.account_id).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.uploadToCloud",
                        "params",
                        "invalid backups.uploadToCloud params",
                    ),
                ),
            }
        }
        "backups.uploadStatus" => {
            match serde_json::from_value::<BackupsUploadStatusParams>(request.params) {
                Ok(params) => match runtime.cloud_upload_status(&params.account_id).await {
                    Ok(status) => HostResponse::success(request_id, status),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "backups.uploadStatus",
                        "params",
                        "invalid backups.uploadStatus params",
                    ),
                ),
            }
        }
        "messages.list" => match serde_json::from_value::<MessagesListParams>(request.params) {
            Ok(params) if (1..=MAX_PAGE_LIMIT).contains(&params.limit) => {
                match runtime
                    .list_messages(
                        params.account_id,
                        params.conversation_id,
                        params.limit,
                        params.before,
                    )
                    .await
                {
                    Ok(page) => HostResponse::success(
                        request_id,
                        serde_json::to_value(page).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                }
            }
            Ok(_) => HostResponse::failure(
                request_id,
                reject_probe("messages.list", "limit", "limit must be between 1 and 200"),
            ),
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("messages.list", "params", "invalid messages.list params"),
            ),
        },
        // Persisted attachment dimensions (contract revision 1.271, §4.255):
        // the official data-model shape — Attachment.width/height — restored to
        // the connector's own store, so the desktop's media boxes are laid out
        // from data on the first frame instead of from an async measurement.
        // Write half: a local store write (send lane, account-scoped mutating,
        // zero engine traffic); the params gate is the shape ladder, and the
        // service ladder validates the pixel domain before the store write.
        "messages.setAttachmentDimensions" => {
            match serde_json::from_value::<MessagesSetAttachmentDimensionsParams>(request.params) {
                Ok(params) => match runtime.set_attachment_dimensions(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.setAttachmentDimensions",
                        "params",
                        "invalid messages.setAttachmentDimensions params",
                    ),
                ),
            }
        }
        // Read half: the conversation's persisted dimension table, bounded by a
        // row window — the desktop's open-conversation warm-up. Pure store
        // read (read lane), no unread side effect, no upstream traffic.
        "messages.listAttachmentDimensions" => {
            match serde_json::from_value::<MessagesListAttachmentDimensionsParams>(request.params) {
                Ok(params) => match runtime.list_attachment_dimensions(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.listAttachmentDimensions",
                        "params",
                        "invalid messages.listAttachmentDimensions params",
                    ),
                ),
            }
        }
        // 契约 1.204（M4b）：以锚点为中心取窗——官方
        // getConversationRangeCenteredOnMessage 对位。一次往返拿「锚前 + 锚 + 锚后」，
        // 取代「先拉最新页再补到锚」的两段式（省一次往返、消除中间态空窗）。
        // 返回与 messages.list 同形的升序 Page（items 含锚行本身）。
        "messages.around" => match serde_json::from_value::<MessagesAroundParams>(request.params) {
            Ok(params) if (3..=MAX_PAGE_LIMIT).contains(&params.limit) => {
                match runtime
                    .list_messages_around(
                        params.account_id,
                        params.conversation_id,
                        params.anchor_message_id,
                        params.limit,
                    )
                    .await
                {
                    // 无未读时 page 为 None → 显式回 null，桌面据此回落取最新页
                    // （不发明锚点，契约 1.208）。
                    Ok(page) => HostResponse::success(
                        request_id,
                        page.map(|page| serde_json::to_value(page).unwrap_or(Value::Null))
                            .unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                }
            }
            Ok(_) => HostResponse::failure(
                request_id,
                reject_probe(
                    "messages.around",
                    "limit",
                    "limit must be between 3 and 200",
                ),
            ),
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe(
                    "messages.around",
                    "params",
                    "invalid messages.around params",
                ),
            ),
        },
        // Adjacent visual-media probe (contract revision 1.93, §4.76): the
        // same params-gate shape as messages.list — the account/conversation
        // ladder, the anchor resolution, and the store-only scan ride the
        // runtime call; the result is the adjacency-ordered media-bearing
        // rows in the messages.list stored shape.
        "messages.adjacentMedia" => {
            match serde_json::from_value::<MessagesAdjacentMediaParams>(request.params) {
                Ok(params) if (1..=MAX_ADJACENT_MEDIA_LIMIT).contains(&params.limit) => {
                    match runtime
                        .list_adjacent_media(
                            params.account_id,
                            params.conversation_id,
                            params.anchor_message_id,
                            params.direction.into(),
                            params.limit,
                        )
                        .await
                    {
                        Ok(items) => {
                            HostResponse::success(request_id, serde_json::json!({ "items": items }))
                        }
                        Err(error) => HostResponse::failure(request_id, error.into_api()),
                    }
                }
                Ok(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.adjacentMedia",
                        "limit",
                        "limit must be between 1 and 20",
                    ),
                ),
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.adjacentMedia",
                        "params",
                        "invalid messages.adjacentMedia params",
                    ),
                ),
            }
        }
        "messages.getText" => {
            match serde_json::from_value::<MessageGetTextParams>(request.params) {
                Ok(params) => match runtime
                    .get_message_text(params.account_id, params.conversation_id, params.message_id)
                    .await
                {
                    Ok(message) => HostResponse::success(
                        request_id,
                        serde_json::to_value(message).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.getText",
                        "params",
                        "invalid messages.getText params",
                    ),
                ),
            }
        }
        "messages.receipts" => {
            match serde_json::from_value::<MessageGetReceiptsParams>(request.params) {
                Ok(params) => match runtime
                    .get_message_receipts(
                        params.account_id,
                        params.conversation_id,
                        params.message_id,
                    )
                    .await
                {
                    Ok(items) => {
                        HostResponse::success(request_id, serde_json::json!({ "items": items }))
                    }
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.receipts",
                        "params",
                        "invalid messages.receipts params",
                    ),
                ),
            }
        }
        "messages.search" => match serde_json::from_value::<MessagesSearchParams>(request.params) {
            Ok(params) if (1..=MAX_PAGE_LIMIT).contains(&params.limit) => {
                match runtime
                    .search_messages(
                        params.account_id,
                        params.query,
                        params.limit,
                        params.cursor,
                        params.conversation_id,
                    )
                    .await
                {
                    Ok(page) => HostResponse::success(
                        request_id,
                        serde_json::to_value(page).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                }
            }
            Ok(_) => HostResponse::failure(
                request_id,
                reject_probe(
                    "messages.search",
                    "limit",
                    "limit must be between 1 and 200",
                ),
            ),
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe(
                    "messages.search",
                    "params",
                    "invalid messages.search params",
                ),
            ),
        },
        // messages.getByClientRequestId (contract 1.172, §4.172): the
        // orphan-sweep read-only probe — the SAME ledger row the retry face
        // addresses, answered with its settled state (full read projection,
        // messages.list item shape). Read lane, zero mutation: a delivered
        // row the desktop lost the answer to answers sent/delivered/read
        // here, so the sweep flips the bubble instead of false-marking it
        // failed; a row the store never saw answers MESSAGE_NOT_FOUND and
        // the sweep keeps its honest error arm.
        "messages.getByClientRequestId" => {
            match serde_json::from_value::<MessageGetByClientRequestIdParams>(request.params) {
                Ok(params) => match runtime
                    .get_message_by_client_request(
                        params.account_id,
                        params.conversation_id,
                        params.client_request_id,
                    )
                    .await
                {
                    Ok(message) => HostResponse::success(
                        request_id,
                        serde_json::to_value(message).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.getByClientRequestId",
                        "params",
                        "invalid messages.getByClientRequestId params",
                    ),
                ),
            }
        }
        "messages.sendText" => {
            match serde_json::from_value::<MessagesSendTextParams>(request.params) {
                Ok(params) => {
                    // Exactly one addressing form: an existing conversationId,
                    // or a peer target (kind + peerKey, optional peerTitle).
                    let target = match (
                        params.conversation_id,
                        params.kind,
                        params.peer_key,
                        params.peer_title,
                    ) {
                        (Some(conversation_id), None, None, None) => {
                            Ok(SendTarget::Conversation(conversation_id))
                        }
                        (None, Some(kind), Some(peer_key), peer_title) => Ok(SendTarget::Peer {
                            kind,
                            peer_key,
                            peer_title,
                        }),
                        _ => Err(reject_probe(
                            "messages.sendText",
                            "conversationId,kind,peerKey",
                            "exactly one of conversationId or kind+peerKey must be provided",
                        )),
                    };
                    match target {
                        Ok(target) => match runtime
                            .send_text(
                                params.account_id,
                                target,
                                params.text,
                                params.client_request_id,
                                params.quote_message_id,
                                params.previews,
                                params.mentions,
                                params.text_style,
                                params.story_reply_author,
                                params.story_reply_timestamp,
                            )
                            .await
                        {
                            Ok(message) => HostResponse::success(
                                request_id,
                                serde_json::to_value(message).unwrap_or(Value::Null),
                            ),
                            Err(error) => HostResponse::failure(request_id, error.into_api()),
                        },
                        Err(error) => HostResponse::failure(request_id, error),
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendText",
                        "params",
                        "invalid messages.sendText params",
                    ),
                ),
            }
        }
        "messages.sendStory" => {
            match serde_json::from_value::<MessagesSendStoryParams>(request.params) {
                Ok(params) => match runtime.send_story(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendStory",
                        "params",
                        "invalid messages.sendStory params",
                    ),
                ),
            }
        }
        "stories.setDisabled" => {
            match serde_json::from_value::<StoriesSetDisabledParams>(request.params) {
                Ok(params) => match runtime.set_stories_disabled(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.setDisabled",
                        "params",
                        "invalid stories.setDisabled params",
                    ),
                ),
            }
        }
        "stories.getDisabled" => {
            match serde_json::from_value::<StoriesGetDisabledParams>(request.params) {
                Ok(params) => match runtime.get_stories_disabled(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.getDisabled",
                        "params",
                        "invalid stories.getDisabled params",
                    ),
                ),
            }
        }
        // Story viewed receipt (contract revision 1.85, §4.70): the
        // messages.markViewed receipt shape — params shape errors answer
        // INVALID_REQUEST, and the answer is {status: sent|unknown}; a
        // receipt send failure never fails the request.
        "stories.markViewed" => {
            match serde_json::from_value::<StoriesMarkViewedParams>(request.params) {
                Ok(params) => match runtime.send_story_viewed(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.markViewed",
                        "params",
                        "invalid stories.markViewed params",
                    ),
                ),
            }
        }
        // Story reaction send (contract 1.152, §4.151): the §4.150
        // call-event proxy shape on the stories family — params shape errors
        // answer INVALID_REQUEST, the engine's `{}` success answer and error
        // faces pass through untouched, and the whole value domain
        // (author/emoji/timestamp gates, identity and profileSharing) stays
        // the engine's parse (engine 4822e99), never re-gated or re-keyed
        // here. `remove: true` is the connector's one refusal (the upstream
        // face places only).
        "stories.sendReaction" => {
            match serde_json::from_value::<StoriesSendReactionParams>(request.params) {
                Ok(params) => match runtime.send_story_reaction(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.sendReaction",
                        "params",
                        "invalid stories.sendReaction params",
                    ),
                ),
            }
        }
        // Story delete-for-everyone fan-out (contract 1.153, §4.152): the
        // §4.150 proxy shape on the stories family — params shape errors
        // answer INVALID_REQUEST, the engine's `{timestamp}` answer and
        // error faces pass through untouched, and the whole value domain
        // (the timestamp domain, the recipients entries, the
        // updatedStoryRecipients shapes, the author resolution) stays the
        // engine's parse (engine 7320393), never re-gated or re-keyed here.
        "stories.deleteForEveryone" => {
            match serde_json::from_value::<StoriesDeleteForEveryoneParams>(request.params) {
                Ok(params) => match runtime.send_story_delete_for_everyone(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stories.deleteForEveryone",
                        "params",
                        "invalid stories.deleteForEveryone params",
                    ),
                ),
            }
        }
        "messages.retryText" => {
            match serde_json::from_value::<MessagesRetryTextParams>(request.params) {
                Ok(params) => {
                    match runtime
                        .retry_text(
                            params.account_id,
                            params.conversation_id,
                            params.client_request_id,
                        )
                        .await
                    {
                        Ok(message) => HostResponse::success(
                            request_id,
                            serde_json::to_value(message).unwrap_or(Value::Null),
                        ),
                        Err(error) => HostResponse::failure(request_id, error.into_api()),
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.retryText",
                        "params",
                        "invalid messages.retryText params",
                    ),
                ),
            }
        }
        "messages.attachments.send" => {
            match serde_json::from_value::<MessagesSendAttachmentParams>(request.params) {
                Ok(params) => {
                    // Exactly one addressing form, identical to sendText.
                    let target = match (
                        params.conversation_id,
                        params.kind,
                        params.peer_key,
                        params.peer_title,
                    ) {
                        (Some(conversation_id), None, None, None) => {
                            Ok(SendTarget::Conversation(conversation_id))
                        }
                        (None, Some(kind), Some(peer_key), peer_title) => Ok(SendTarget::Peer {
                            kind,
                            peer_key,
                            peer_title,
                        }),
                        _ => Err(reject_probe(
                            "messages.attachments.send",
                            "conversationId,kind,peerKey",
                            "exactly one of conversationId or kind+peerKey must be provided",
                        )),
                    };
                    // §4.59 (contract revision 1.66): the singular and plural
                    // payload forms are mutually exclusive. The plural form
                    // rejects any singular key outright (and the singular-only
                    // voiceNote/viewOnce markers, neither official multi-
                    // attachment face; §4.147 extends the same rule to a
                    // top-level `gif` — the plural face carries per-entry
                    // `gif` instead); the singular form requires exactly the
                    // §4.12 pair (dataBase64+sizeBytes). All rejections are
                    // deterministic and happen before any pending row exists.
                    // 契约 1.294 §4.284（BUG-11 wire 批）：width/height 是单数
                    // 形态的声明尺寸键，与 §4.127 blurHash 同族——数组旁出现即
                    // 单数/复数混形，INVALID_REQUEST。
                    if params.attachments.is_some()
                        && (params.voice_note
                            || params.view_once
                            || params.gif
                            || params.width.is_some()
                            || params.height.is_some())
                    {
                        return HostResponse::failure(
                            request_id,
                            reject_probe(
                                "messages.attachments.send",
                                "attachments,voiceNote,viewOnce,gif,width,height",
                                "voiceNote, viewOnce, gif, width and height apply to the singular attachment form only",
                            ),
                        );
                    }
                    // §4.127: a top-level `blurHash` is a singular-form key —
                    // beside the plural array it fails the same exclusivity
                    // tuple (per-entry `blurHash` rides the entries).
                    let form = match (
                        params.data_base64,
                        params.size_bytes,
                        params.filename,
                        params.content_type,
                        params.blur_hash,
                        params.attachments,
                    ) {
                        (
                            Some(data_base64),
                            Some(size_bytes),
                            filename,
                            content_type,
                            blur_hash,
                            None,
                        ) => Ok(AttachmentSendForm::Singular {
                            data_base64,
                            size_bytes,
                            filename,
                            content_type,
                            blur_hash,
                        }),
                        (None, None, None, None, None, Some(entries)) => {
                            Ok(AttachmentSendForm::Plural { entries })
                        }
                        _ => Err(reject_probe(
                            "messages.attachments.send",
                            "dataBase64,sizeBytes,attachments",
                            "either dataBase64+sizeBytes or the attachments array must be provided, never both",
                        )),
                    };
                    match (target, form) {
                        (
                            Ok(target),
                            Ok(AttachmentSendForm::Singular {
                                data_base64,
                                size_bytes,
                                filename,
                                content_type,
                                blur_hash,
                            }),
                        ) => {
                            // 契约 1.294 §4.284：声明尺寸的形状闸在 host（与
                            // blurHash/voiceNote 同层）——双参同进退、正整数、
                            // ≤ 16384；坏形状在写任何 pending 行之前被判。
                            let dimensions = match crate::service::validate_attachment_dimensions(
                                params.width,
                                params.height,
                            ) {
                                Ok(dimensions) => dimensions,
                                Err(error) => {
                                    return HostResponse::failure(request_id, error.into_api());
                                }
                            };
                            match runtime
                                .send_attachment_with_dimensions(
                                    params.account_id,
                                    target,
                                    params.client_request_id,
                                    data_base64,
                                    size_bytes,
                                    filename,
                                    content_type,
                                    params.text,
                                    params.quote_message_id,
                                    params.voice_note,
                                    params.view_once,
                                    blur_hash,
                                    params.gif,
                                    dimensions,
                                )
                                .await
                            {
                                Ok(message) => HostResponse::success(
                                    request_id,
                                    serde_json::to_value(message).unwrap_or(Value::Null),
                                ),
                                Err(error) => HostResponse::failure(request_id, error.into_api()),
                            }
                        }
                        (Ok(target), Ok(AttachmentSendForm::Plural { entries })) => {
                            match runtime
                                .send_attachments_multi(
                                    params.account_id,
                                    target,
                                    params.client_request_id,
                                    entries,
                                    params.text,
                                    params.quote_message_id,
                                )
                                .await
                            {
                                Ok(message) => HostResponse::success(
                                    request_id,
                                    serde_json::to_value(message).unwrap_or(Value::Null),
                                ),
                                Err(error) => HostResponse::failure(request_id, error.into_api()),
                            }
                        }
                        (Err(error), _) | (_, Err(error)) => {
                            HostResponse::failure(request_id, error)
                        }
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.attachments.send",
                        "params",
                        "invalid messages.attachments.send params",
                    ),
                ),
            }
        }
        // §4.262 (contract revision 1.278) + §4.263 (contract 1.279) + §4.264
        // (contract 1.280): the in-place attachment retry — the SAME row
        // re-sent, never a new message beside it, in the shape the original
        // used. Params shape takes the singular messages.attachments.send form
        // (same addressing rules); the plural §4.59 array is rejected outright
        // rather than silently taking its first entry (the row itself decides
        // whether the retry re-sends one attachment or its whole persisted
        // group). dataBase64/sizeBytes are optional together — omitted, the
        // connector reuses the original payload group persisted at first send
        // (refresh-safe, plural included); supplied, they serve a singular row
        // and replace its index-0 payload.
        "messages.attachments.retry" => {
            match serde_json::from_value::<MessagesSendAttachmentParams>(request.params) {
                Ok(params) => {
                    let target = match (
                        params.conversation_id,
                        params.kind,
                        params.peer_key,
                        params.peer_title,
                    ) {
                        (Some(conversation_id), None, None, None) => {
                            Ok(SendTarget::Conversation(conversation_id))
                        }
                        (None, Some(kind), Some(peer_key), peer_title) => Ok(SendTarget::Peer {
                            kind,
                            peer_key,
                            peer_title,
                        }),
                        _ => Err(reject_probe(
                            "messages.attachments.retry",
                            "conversationId,kind,peerKey",
                            "exactly one of conversationId or kind+peerKey must be provided",
                        )),
                    };
                    match target {
                        Ok(target) => {
                            if params.attachments.is_some() {
                                HostResponse::failure(
                                    request_id,
                                    reject_probe(
                                        "messages.attachments.retry",
                                        "attachments",
                                        "the retry face takes the singular attachment form and never the attachments array",
                                    ),
                                )
                            } else if params.data_base64.is_some() != params.size_bytes.is_some() {
                                HostResponse::failure(
                                    request_id,
                                    reject_probe(
                                        "messages.attachments.retry",
                                        "dataBase64,sizeBytes",
                                        "dataBase64 and sizeBytes must be provided together; omit both to reuse the persisted original payload",
                                    ),
                                )
                            } else {
                                // 契约 1.294 §4.284：重试面允许调用方重述尺寸
                                // （与 blurHash 同口径；缺席时回落到行 descriptor）。
                                let dimensions =
                                    match crate::service::validate_attachment_dimensions(
                                        params.width,
                                        params.height,
                                    ) {
                                        Ok(dimensions) => dimensions,
                                        Err(error) => {
                                            return HostResponse::failure(
                                                request_id,
                                                error.into_api(),
                                            );
                                        }
                                    };
                                match runtime
                                    .retry_attachment_with_dimensions(
                                        params.account_id,
                                        target,
                                        params.client_request_id,
                                        params.data_base64,
                                        params.size_bytes,
                                        params.filename,
                                        params.content_type,
                                        params.text,
                                        params.quote_message_id,
                                        params.voice_note,
                                        params.view_once,
                                        params.blur_hash,
                                        params.gif,
                                        dimensions,
                                    )
                                    .await
                                {
                                    Ok(message) => HostResponse::success(
                                        request_id,
                                        serde_json::to_value(message).unwrap_or(Value::Null),
                                    ),
                                    Err(error) => {
                                        HostResponse::failure(request_id, error.into_api())
                                    }
                                }
                            }
                        }
                        Err(error) => HostResponse::failure(request_id, error),
                    }
                }
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.attachments.retry",
                        "params",
                        "invalid messages.attachments.retry params",
                    ),
                ),
            }
        }
        "messages.sendSticker" => {
            match serde_json::from_value::<MessagesSendStickerParams>(request.params) {
                Ok(params) => match runtime.send_sticker(params).await {
                    Ok(message) => HostResponse::success(
                        request_id,
                        serde_json::to_value(message).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendSticker",
                        "params",
                        "invalid messages.sendSticker params",
                    ),
                ),
            }
        }
        "stickerPacks.getManifest" => {
            match serde_json::from_value::<StickerPackManifestParams>(request.params) {
                Ok(params) => match runtime.get_sticker_pack_manifest(params).await {
                    Ok(manifest) => HostResponse::success(
                        request_id,
                        serde_json::to_value(manifest).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stickerPacks.getManifest",
                        "params",
                        "invalid stickerPacks.getManifest params",
                    ),
                ),
            }
        }
        "stickerPacks.getImage" => {
            match serde_json::from_value::<StickerPackImageParams>(request.params) {
                Ok(params) => match runtime.get_sticker_image(params).await {
                    Ok(image) => HostResponse::success(
                        request_id,
                        serde_json::to_value(image).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stickerPacks.getImage",
                        "params",
                        "invalid stickerPacks.getImage params",
                    ),
                ),
            }
        }
        "conversations.getBlocked" => {
            match serde_json::from_value::<ConversationsGetBlockedParams>(request.params) {
                Ok(params) => match runtime.get_blocked_conversations(params).await {
                    Ok(blocked) => HostResponse::success(
                        request_id,
                        serde_json::to_value(blocked).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.getBlocked",
                        "params",
                        "invalid conversations.getBlocked params",
                    ),
                ),
            }
        }
        "conversations.getAvatar" => {
            match serde_json::from_value::<ConversationsGetAvatarParams>(request.params) {
                Ok(params) => match runtime.get_avatar(params).await {
                    Ok(avatar) => HostResponse::success(
                        request_id,
                        serde_json::to_value(avatar).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.getAvatar",
                        "params",
                        "invalid conversations.getAvatar params",
                    ),
                ),
            }
        }
        "conversations.setBlocked" => {
            match serde_json::from_value::<ConversationsSetBlockedParams>(request.params) {
                Ok(params) => match runtime.set_conversation_blocked(params).await {
                    Ok(blocked) => HostResponse::success(
                        request_id,
                        serde_json::to_value(blocked).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.setBlocked",
                        "params",
                        "invalid conversations.setBlocked params",
                    ),
                ),
            }
        }
        "conversations.saveDraft" => {
            match serde_json::from_value::<ConversationsSaveDraftParams>(request.params) {
                Ok(params) => match runtime.save_conversation_draft(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.saveDraft",
                        "params",
                        "invalid conversations.saveDraft params",
                    ),
                ),
            }
        }
        "conversations.clearDraft" => {
            match serde_json::from_value::<ConversationsClearDraftParams>(request.params) {
                Ok(params) => match runtime.clear_conversation_draft(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.clearDraft",
                        "params",
                        "invalid conversations.clearDraft params",
                    ),
                ),
            }
        }
        "conversations.getState" => {
            match serde_json::from_value::<ConversationsGetStateParams>(request.params) {
                Ok(params) => match runtime.get_conversation_state(params).await {
                    Ok(state) => HostResponse::success(
                        request_id,
                        serde_json::to_value(state).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.getState",
                        "params",
                        "invalid conversations.getState params",
                    ),
                ),
            }
        }
        "conversations.setState" => {
            match serde_json::from_value::<ConversationsSetStateParams>(request.params) {
                Ok(params) => match runtime.set_conversation_state(params).await {
                    Ok(state) => HostResponse::success(
                        request_id,
                        serde_json::to_value(state).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.setState",
                        "params",
                        "invalid conversations.setState params",
                    ),
                ),
            }
        }
        "conversations.acceptRequest" => {
            match serde_json::from_value::<MessageRequestParams>(request.params) {
                Ok(params) => match runtime.accept_message_request(params).await {
                    Ok(outcome) => HostResponse::success(
                        request_id,
                        serde_json::to_value(outcome).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.acceptRequest",
                        "params",
                        "invalid conversations.acceptRequest params",
                    ),
                ),
            }
        }
        "conversations.declineRequest" => {
            match serde_json::from_value::<MessageRequestParams>(request.params) {
                Ok(params) => match runtime.decline_message_request(params).await {
                    Ok(outcome) => HostResponse::success(
                        request_id,
                        serde_json::to_value(outcome).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.declineRequest",
                        "params",
                        "invalid conversations.declineRequest params",
                    ),
                ),
            }
        }
        "identities.get" => match serde_json::from_value::<IdentitiesGetParams>(request.params) {
            Ok(params) => match runtime.get_identity(params).await {
                Ok(identity) => HostResponse::success(
                    request_id,
                    serde_json::to_value(identity).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("identities.get", "params", "invalid identities.get params"),
            ),
        },
        "identities.verify" => {
            match serde_json::from_value::<IdentitiesVerifyParams>(request.params) {
                Ok(params) => match runtime.verify_identity(params).await {
                    Ok(outcome) => HostResponse::success(
                        request_id,
                        serde_json::to_value(outcome).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "identities.verify",
                        "params",
                        "invalid identities.verify params",
                    ),
                ),
            }
        }
        "calls.sendSignal" => {
            match serde_json::from_value::<CallsSendSignalParams>(request.params) {
                Ok(params) => match runtime.send_call_signal(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.sendSignal",
                        "params",
                        "invalid calls.sendSignal params",
                    ),
                ),
            }
        }
        // Group call update (contract revision 1.127, §4.108): the engine's
        // DataMessage.groupCallUpdate fan-out — the conversation row must
        // resolve to a group kind (the connector refuses anything else
        // before any upstream frame). A definite success answers the
        // explicit {"status":"sent"} (the engine's own body is empty); an
        // indeterminate mutating outcome folds to SEND_OUTCOME_UNKNOWN and
        // is never retried.
        "calls.sendGroupCallUpdate" => {
            match serde_json::from_value::<CallsSendGroupCallUpdateParams>(request.params) {
                Ok(params) => match runtime.send_group_call_update(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.sendGroupCallUpdate",
                        "params",
                        "invalid calls.sendGroupCallUpdate params",
                    ),
                ),
            }
        }
        "calls.getState" => match serde_json::from_value::<CallsGetStateParams>(request.params) {
            Ok(params) => match runtime.call_state(params).await {
                Ok(state) => HostResponse::success(request_id, state),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("calls.getState", "params", "invalid calls.getState params"),
            ),
        },
        // Call-link credential material passthrough (contract revision 1.88,
        // §4.73): all five arms are the params-gate shape — the b64 byte-budget
        // gates, account resolution, and the engine dispatch ride the
        // service prepare; the engine's result passes through untouched and
        // the two credential error codes map through the structured whitelist
        // (CALL_CREDENTIALS_FAILED with its data.status? face,
        // CALL_CREDENTIALS_UNAVAILABLE retryable). endorsementsPublicKey is
        // the account-less face: empty params, the default group's engine.
        "calls.linkPresentation" => {
            match serde_json::from_value::<CallsLinkPresentationParams>(request.params) {
                Ok(params) => match runtime.calls_link_presentation(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.linkPresentation",
                        "params",
                        "invalid calls.linkPresentation params",
                    ),
                ),
            }
        }
        "calls.createLinkAuth" => {
            match serde_json::from_value::<CallsCreateLinkAuthParams>(request.params) {
                Ok(params) => match runtime.calls_create_link_auth(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.createLinkAuth",
                        "params",
                        "invalid calls.createLinkAuth params",
                    ),
                ),
            }
        }
        "calls.groupProof" => {
            match serde_json::from_value::<CallsGroupProofParams>(request.params) {
                Ok(params) => match runtime.calls_group_proof(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.groupProof",
                        "params",
                        "invalid calls.groupProof params",
                    ),
                ),
            }
        }
        "calls.groupMembers" => {
            match serde_json::from_value::<CallsGroupMembersParams>(request.params) {
                Ok(params) => match runtime.calls_group_members(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.groupMembers",
                        "params",
                        "invalid calls.groupMembers params",
                    ),
                ),
            }
        }
        "calls.endorsementsPublicKey" => {
            match serde_json::from_value::<CallsEndorsementsPublicKeyParams>(request.params) {
                Ok(_) => match runtime.calls_endorsements_public_key().await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.endorsementsPublicKey",
                        "params",
                        "invalid calls.endorsementsPublicKey params",
                    ),
                ),
            }
        }
        // Call-relay configuration proxy (contract revision 1.145, §4.143):
        // the pure-proxy shape — account resolution rides the service
        // prepare, the engine's answer passes through untouched, and the
        // error face is the engine's verbatim (the plain -32603
        // unknown-account face through the structured ladder, the 401/403
        // unbound message through the §4.17 matcher to ACCOUNT_UNLINKED).
        "calls.relays" => match serde_json::from_value::<CallsRelaysParams>(request.params) {
            Ok(params) => match runtime.calls_relays(params).await {
                Ok(result) => HostResponse::success(request_id, result),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("calls.relays", "params", "invalid calls.relays params"),
            ),
        },
        // Call-event self-sync proxy (contract revision 1.151, §4.150): the
        // pure-proxy shape on the send lane — the account resolution rides
        // the service prepare, every other key crosses verbatim, the
        // engine's {timestamp} answer and error faces pass through
        // untouched, and the full parameter gate (the three word lists, the
        // per-leg conversation shapes, the callId domain, the per-leg
        // callId requirement) stays the engine's fail-closed parse
        // (engine 6d56660), never re-gated or re-keyed here.
        "calls.sendCallEvent" => {
            match serde_json::from_value::<CallsSendCallEventParams>(request.params) {
                Ok(params) => match runtime.send_call_event(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "calls.sendCallEvent",
                        "params",
                        "invalid calls.sendCallEvent params",
                    ),
                ),
            }
        }
        "conversations.getPinned" => {
            match serde_json::from_value::<ConversationsGetPinnedParams>(request.params) {
                Ok(params) => match runtime.get_pinned_conversations(params).await {
                    Ok(pinned) => HostResponse::success(
                        request_id,
                        serde_json::to_value(pinned).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.getPinned",
                        "params",
                        "invalid conversations.getPinned params",
                    ),
                ),
            }
        }
        "conversations.setPinned" => {
            match serde_json::from_value::<ConversationsSetPinnedParams>(request.params) {
                Ok(params) => match runtime.set_conversation_pinned(params).await {
                    Ok(pinned) => HostResponse::success(
                        request_id,
                        serde_json::to_value(pinned).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.setPinned",
                        "params",
                        "invalid conversations.setPinned params",
                    ),
                ),
            }
        }
        "conversations.setExpireTimer" => {
            match serde_json::from_value::<ConversationsSetExpireTimerParams>(request.params) {
                Ok(params) => match runtime.set_conversation_expire_timer(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.setExpireTimer",
                        "params",
                        "invalid conversations.setExpireTimer params",
                    ),
                ),
            }
        }
        "stickerPacks.getSyncs" => {
            match serde_json::from_value::<StickerPackGetSyncsParams>(request.params) {
                Ok(params) => match runtime.get_sticker_pack_syncs(params).await {
                    Ok(syncs) => HostResponse::success(
                        request_id,
                        serde_json::to_value(syncs).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stickerPacks.getSyncs",
                        "params",
                        "invalid stickerPacks.getSyncs params",
                    ),
                ),
            }
        }
        "stickerPacks.setSync" => {
            match serde_json::from_value::<StickerPackSetSyncParams>(request.params) {
                Ok(params) => match runtime.set_sticker_pack_sync(params).await {
                    Ok(syncs) => HostResponse::success(
                        request_id,
                        serde_json::to_value(syncs).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "stickerPacks.setSync",
                        "params",
                        "invalid stickerPacks.setSync params",
                    ),
                ),
            }
        }
        "chatFolders.list" => {
            match serde_json::from_value::<ChatFoldersListParams>(request.params) {
                Ok(params) => match runtime.chat_folders_list(params).await {
                    Ok(folders) => HostResponse::success(
                        request_id,
                        serde_json::to_value(folders).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "chatFolders.list",
                        "params",
                        "invalid chatFolders.list params",
                    ),
                ),
            }
        }
        "chatFolders.setRecords" => {
            match serde_json::from_value::<ChatFoldersSetRecordsParams>(request.params) {
                Ok(params) => match runtime.chat_folders_set_records(params).await {
                    Ok(folders) => HostResponse::success(
                        request_id,
                        serde_json::to_value(folders).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "chatFolders.setRecords",
                        "params",
                        "invalid chatFolders.setRecords params",
                    ),
                ),
            }
        }
        "notificationProfiles.list" => {
            match serde_json::from_value::<NotificationProfilesListParams>(request.params) {
                Ok(params) => match runtime.notification_profiles_list(params).await {
                    Ok(profiles) => HostResponse::success(
                        request_id,
                        serde_json::to_value(profiles).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "notificationProfiles.list",
                        "params",
                        "invalid notificationProfiles.list params",
                    ),
                ),
            }
        }
        "notificationProfiles.setRecords" => {
            match serde_json::from_value::<NotificationProfilesSetRecordsParams>(request.params) {
                Ok(params) => match runtime.notification_profiles_set_records(params).await {
                    Ok(profiles) => HostResponse::success(
                        request_id,
                        serde_json::to_value(profiles).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "notificationProfiles.setRecords",
                        "params",
                        "invalid notificationProfiles.setRecords params",
                    ),
                ),
            }
        }
        "storyDistributionLists.list" => {
            match serde_json::from_value::<StoryDistributionListsListParams>(request.params) {
                Ok(params) => match runtime.story_distribution_lists_list(params).await {
                    Ok(lists) => HostResponse::success(
                        request_id,
                        serde_json::to_value(lists).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "storyDistributionLists.list",
                        "params",
                        "invalid storyDistributionLists.list params",
                    ),
                ),
            }
        }
        "storyDistributionLists.setRecords" => {
            match serde_json::from_value::<StoryDistributionListsSetRecordsParams>(request.params) {
                Ok(params) => match runtime.story_distribution_lists_set_records(params).await {
                    Ok(lists) => HostResponse::success(
                        request_id,
                        serde_json::to_value(lists).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "storyDistributionLists.setRecords",
                        "params",
                        "invalid storyDistributionLists.setRecords params",
                    ),
                ),
            }
        }
        "storage.mergeContacts" => {
            match serde_json::from_value::<StorageIngestParams>(request.params) {
                Ok(params) => match runtime.storage_merge_contacts(params).await {
                    Ok(summary) => HostResponse::success(
                        request_id,
                        serde_json::to_value(summary).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "storage.mergeContacts",
                        "params",
                        "invalid storage.mergeContacts params",
                    ),
                ),
            }
        }
        "storage.importGroups" => {
            match serde_json::from_value::<StorageIngestParams>(request.params) {
                Ok(params) => match runtime.storage_import_groups(params).await {
                    Ok(summary) => HostResponse::success(
                        request_id,
                        serde_json::to_value(summary).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "storage.importGroups",
                        "params",
                        "invalid storage.importGroups params",
                    ),
                ),
            }
        }
        "storage.getCallLinks" => {
            match serde_json::from_value::<StorageGetCallLinksParams>(request.params) {
                Ok(params) => match runtime.storage_get_call_links(params).await {
                    Ok(links) => HostResponse::success(
                        request_id,
                        serde_json::to_value(links).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "storage.getCallLinks",
                        "params",
                        "invalid storage.getCallLinks params",
                    ),
                ),
            }
        }
        "storage.setCallLink" => {
            match serde_json::from_value::<StorageSetCallLinkParams>(request.params) {
                Ok(params) => match runtime.storage_set_call_link(params).await {
                    Ok(links) => HostResponse::success(
                        request_id,
                        serde_json::to_value(links).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "storage.setCallLink",
                        "params",
                        "invalid storage.setCallLink params",
                    ),
                ),
            }
        }
        "messages.edit" => {
            match serde_json::from_value::<MessagesEditParams>(request.params) {
                Ok(params) => match runtime.edit_message(params).await {
                    Ok(Some(message)) => HostResponse::success(
                        request_id,
                        serde_json::to_value(message).unwrap_or(Value::Null),
                    ),
                    // Indeterminate upstream outcome: the local row is
                    // unchanged and the caller must reconcile before retrying.
                    Ok(None) => HostResponse::failure(
                        request_id,
                        ApiError::new(
                            "SEND_OUTCOME_UNKNOWN",
                            "edit outcome is indeterminate; the message may or may not have been edited",
                            false,
                        ),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe("messages.edit", "params", "invalid messages.edit params"),
                ),
            }
        }
        "messages.remoteDelete" => {
            match serde_json::from_value::<MessagesRemoteDeleteParams>(request.params) {
                Ok(params) => match runtime.remote_delete(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.remoteDelete",
                        "params",
                        "invalid messages.remoteDelete params",
                    ),
                ),
            }
        }
        "messages.sendReaction" => {
            match serde_json::from_value::<MessagesSendReactionParams>(request.params) {
                Ok(params) => match runtime.send_reaction(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendReaction",
                        "params",
                        "invalid messages.sendReaction params",
                    ),
                ),
            }
        }
        // Pin family (contract 1.33): the reaction dispatch shape — params
        // shape errors answer INVALID_REQUEST, the outcome mirrors the
        // upstream mutating result ({status: sent|unknown}).
        "messages.sendPinMessage" => {
            match serde_json::from_value::<MessagesSendPinMessageParams>(request.params) {
                Ok(params) => match runtime.send_pin_message(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendPinMessage",
                        "params",
                        "invalid messages.sendPinMessage params",
                    ),
                ),
            }
        }
        "messages.sendUnpinMessage" => {
            match serde_json::from_value::<MessagesSendUnpinMessageParams>(request.params) {
                Ok(params) => match runtime.send_unpin_message(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendUnpinMessage",
                        "params",
                        "invalid messages.sendUnpinMessage params",
                    ),
                ),
            }
        }
        "messages.sendAdminDelete" => {
            match serde_json::from_value::<MessagesSendAdminDeleteParams>(request.params) {
                Ok(params) => match runtime.send_admin_delete(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendAdminDelete",
                        "params",
                        "invalid messages.sendAdminDelete params",
                    ),
                ),
            }
        }
        // Outbound receipt face (contract revision 1.34): the pin dispatch
        // shape — params shape errors answer INVALID_REQUEST, and the answer
        // is {status: sent|unknown}; a receipt send failure never fails the
        // request (the supervisor aggregates per-author calls into unknown).
        "messages.markRead" => {
            match serde_json::from_value::<MessagesMarkReadParams>(request.params) {
                Ok(params) => match runtime.send_mark_read(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.markRead",
                        "params",
                        "invalid messages.markRead params",
                    ),
                ),
            }
        }
        "messages.markViewed" => {
            match serde_json::from_value::<MessagesMarkViewedParams>(request.params) {
                Ok(params) => match runtime.send_mark_viewed(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.markViewed",
                        "params",
                        "invalid messages.markViewed params",
                    ),
                ),
            }
        }
        // Outbound read/viewed SELF-SYNC faces (contract revision 1.108,
        // §4.89): the receipt dispatch shape — params shape errors answer
        // INVALID_REQUEST, the answer is {status: sent|unknown}, a sync
        // failure never fails the request (the supervisor degrades the
        // answer; the SyncMessage.read/viewed self-sync channel is
        // independent of the readReceipts-gated peer receipt face).
        "messages.syncRead" => {
            match serde_json::from_value::<MessagesSyncReadParams>(request.params) {
                Ok(params) => match runtime.send_sync_read(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.syncRead",
                        "params",
                        "invalid messages.syncRead params",
                    ),
                ),
            }
        }
        "messages.syncViewed" => {
            match serde_json::from_value::<MessagesSyncViewedParams>(request.params) {
                Ok(params) => match runtime.send_sync_viewed(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.syncViewed",
                        "params",
                        "invalid messages.syncViewed params",
                    ),
                ),
            }
        }
        // Delete-for-me SELF-SYNC upstream leg (contract revision 1.118,
        // §4.99): the receipt dispatch shape again — params shape errors
        // answer INVALID_REQUEST, the answer is {status: sent|unknown}, and
        // a sync failure never fails the request (the supervisor degrades
        // it; the deleteForMeConversation self-sync channel mirrors the
        // syncRead/syncViewed pair).
        "messages.deleteForMe" => {
            match serde_json::from_value::<MessagesDeleteForMeParams>(request.params) {
                Ok(params) => match runtime.delete_for_me(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.deleteForMe",
                        "params",
                        "invalid messages.deleteForMe params",
                    ),
                ),
            }
        }
        // Message-level delete-for-me SELF-SYNC upstream leg (contract
        // revision 1.197, §4.197): the desktop addresses local row ids, the
        // connector resolves each to the official (author, sentTimestamp)
        // entry from its own store, and the whole batch rides one engine
        // `deleteForMeMessages` call. Receipt-class like the conversation
        // twin: params shape errors answer INVALID_REQUEST, the answer is
        // {status: sent|unknown}, and an engine failure never fails the
        // request.
        "messages.deleteForMeMessages" => {
            match serde_json::from_value::<MessagesDeleteForMeMessagesParams>(request.params) {
                Ok(params) => match runtime.delete_for_me_messages(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.deleteForMeMessages",
                        "params",
                        "invalid messages.deleteForMeMessages params",
                    ),
                ),
            }
        }
        // View-once faces (contract revision 1.38): the bare open-sync
        // passthrough answers {status: sent|unknown} like the receipt face;
        // the burn trigger runs the local burn first and reports the
        // best-effort upstream pair through the same receipt-class shape.
        "messages.sendViewOnceOpen" => {
            match serde_json::from_value::<MessagesSendViewOnceOpenParams>(request.params) {
                Ok(params) => match runtime.send_view_once_open(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendViewOnceOpen",
                        "params",
                        "invalid messages.sendViewOnceOpen params",
                    ),
                ),
            }
        }
        "messages.markViewOnceOpened" => {
            match serde_json::from_value::<MessagesMarkViewOnceOpenedParams>(request.params) {
                Ok(params) => match runtime.mark_view_once_opened(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.markViewOnceOpened",
                        "params",
                        "invalid messages.markViewOnceOpened params",
                    ),
                ),
            }
        }
        // Media ingest triple (ADR 0004): local chunked streaming behind the
        // `--media-ingest` launcher opt-in. Without it the service answers
        // CAPABILITY_UNAVAILABLE before any other check; with it, params
        // shape errors answer INVALID_REQUEST and every failure maps through
        // the service's content-free codes.
        "messages.attachments.open" => {
            match serde_json::from_value::<MessagesAttachmentsOpenParams>(request.params) {
                Ok(params) => match runtime.open_media(params).await {
                    Ok(view) => HostResponse::success(
                        request_id,
                        serde_json::to_value(view).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.attachments.open",
                        "params",
                        "invalid messages.attachments.open params",
                    ),
                ),
            }
        }
        "messages.attachments.readChunk" => {
            match serde_json::from_value::<MessagesAttachmentsReadChunkParams>(request.params) {
                Ok(params) => match runtime
                    .read_media_chunk(params.media_handle, params.offset)
                    .await
                {
                    Ok(chunk) => HostResponse::success(
                        request_id,
                        serde_json::to_value(chunk).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.attachments.readChunk",
                        "params",
                        "invalid messages.attachments.readChunk params",
                    ),
                ),
            }
        }
        "messages.attachments.closeHandle" => {
            match serde_json::from_value::<MessagesAttachmentsCloseHandleParams>(request.params) {
                Ok(params) => match runtime.close_media_handle(params.media_handle).await {
                    Ok(view) => HostResponse::success(
                        request_id,
                        serde_json::to_value(view).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.attachments.closeHandle",
                        "params",
                        "invalid messages.attachments.closeHandle params",
                    ),
                ),
            }
        }
        "contacts.sync" => match serde_json::from_value::<ContactsSyncParams>(request.params) {
            Ok(params) => match runtime.sync_contacts(&params.account_id).await {
                Ok(outcome) => HostResponse::success(
                    request_id,
                    serde_json::to_value(outcome).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("contacts.sync", "params", "invalid contacts.sync params"),
            ),
        },
        "contacts.list" => match serde_json::from_value::<ContactsListParams>(request.params) {
            Ok(params) if (1..=MAX_PAGE_LIMIT).contains(&params.limit) => {
                match runtime
                    .list_contacts(params.account_id, params.query, params.limit, params.cursor)
                    .await
                {
                    Ok(page) => HostResponse::success(
                        request_id,
                        serde_json::to_value(page).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                }
            }
            Ok(_) => HostResponse::failure(
                request_id,
                reject_probe("contacts.list", "limit", "limit must be between 1 and 200"),
            ),
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("contacts.list", "params", "invalid contacts.list params"),
            ),
        },
        "groups.get" => match serde_json::from_value::<GroupsGetParams>(request.params) {
            Ok(params) => match runtime.get_group(params).await {
                Ok(details) => HostResponse::success(
                    request_id,
                    serde_json::to_value(details).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("groups.get", "params", "invalid groups.get params"),
            ),
        },
        "groups.common" => match serde_json::from_value::<GroupsCommonParams>(request.params) {
            Ok(params) => match runtime.groups_common(params).await {
                Ok(details) => HostResponse::success(
                    request_id,
                    serde_json::to_value(details).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("groups.common", "params", "invalid groups.common params"),
            ),
        },
        "groups.update" => match serde_json::from_value::<GroupsUpdateParams>(request.params) {
            Ok(params) => match runtime.update_group(params).await {
                Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("groups.update", "params", "invalid groups.update params"),
            ),
        },
        "groups.quit" => match serde_json::from_value::<GroupsQuitParams>(request.params) {
            Ok(params) => match runtime.quit_group(params).await {
                Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("groups.quit", "params", "invalid groups.quit params"),
            ),
        },
        // Group termination (contract revision 1.52, §4.50, capability
        // group-terminate): the groups.quit dispatch shape — params shape
        // errors answer INVALID_REQUEST, the definite success is
        // {"status": "sent"}, and an indeterminate upstream outcome is the
        // SEND_OUTCOME_UNKNOWN error, never retried.
        "groups.terminate" => {
            match serde_json::from_value::<GroupsTerminateParams>(request.params) {
                Ok(params) => match runtime.terminate_group(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.terminate",
                        "params",
                        "invalid groups.terminate params",
                    ),
                ),
            }
        }
        // Group join-request approval (contract revision 1.58, §4.53,
        // capability group-join-approve): the groups.terminate dispatch
        // shape — params shape errors answer INVALID_REQUEST, the definite
        // success is {"status": "sent"}, the stale-candidate fold answers
        // JOIN_REQUEST_NO_LONGER_PENDING (retryable), and an indeterminate
        // upstream outcome is the SEND_OUTCOME_UNKNOWN error, never retried.
        "groups.approveJoinRequests" => {
            match serde_json::from_value::<GroupsApproveJoinRequestsParams>(request.params) {
                Ok(params) => match runtime.approve_join_requests(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.approveJoinRequests",
                        "params",
                        "invalid groups.approveJoinRequests params",
                    ),
                ),
            }
        }
        // Group invite revocation (contract revision 1.64, §4.57,
        // capability group-invite-revoke): the groups.approveJoinRequests
        // dispatch shape — params shape errors answer INVALID_REQUEST, the
        // definite success is {"status": "sent"}, the stale-candidate fold
        // answers INVITE_NO_LONGER_PENDING (retryable), and an
        // indeterminate upstream outcome is the SEND_OUTCOME_UNKNOWN error,
        // never retried.
        "groups.revokeInvites" => {
            match serde_json::from_value::<GroupsRevokeInvitesParams>(request.params) {
                Ok(params) => match runtime.revoke_invites(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.revokeInvites",
                        "params",
                        "invalid groups.revokeInvites params",
                    ),
                ),
            }
        }
        // Group invite-link family (contract revision 1.117, §4.98,
        // capability group-invite-links): the material/parse faces take no
        // account; the account-scoped faces share the groups.dispatch
        // shape — params shape errors answer INVALID_REQUEST, the reads
        // are plain projections, and the join-family writes keep the
        // groups.quit status verb.
        "groups.generateInviteLinkPassword" => {
            match serde_json::from_value::<GroupsInviteLinkPasswordParams>(request.params) {
                Ok(params) => match runtime.generate_group_invite_link_password(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.generateInviteLinkPassword",
                        "params",
                        "invalid groups.generateInviteLinkPassword params",
                    ),
                ),
            }
        }
        "groups.buildInviteLink" => {
            match serde_json::from_value::<GroupsBuildInviteLinkParams>(request.params) {
                Ok(params) => match runtime.build_group_invite_link(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.buildInviteLink",
                        "params",
                        "invalid groups.buildInviteLink params",
                    ),
                ),
            }
        }
        "groups.parseInviteLink" => {
            match serde_json::from_value::<GroupsParseInviteLinkParams>(request.params) {
                Ok(params) => match runtime.parse_group_invite_link(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.parseInviteLink",
                        "params",
                        "invalid groups.parseInviteLink params",
                    ),
                ),
            }
        }
        "groups.previewViaLink" => {
            match serde_json::from_value::<GroupsPreviewViaLinkParams>(request.params) {
                Ok(params) => match runtime.preview_group_via_link(params).await {
                    Ok(result) => HostResponse::success(
                        request_id,
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    ),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.previewViaLink",
                        "params",
                        "invalid groups.previewViaLink params",
                    ),
                ),
            }
        }
        "groups.joinViaLink" => {
            match serde_json::from_value::<GroupsJoinViaLinkParams>(request.params) {
                Ok(params) => match runtime.join_group_via_link(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.joinViaLink",
                        "params",
                        "invalid groups.joinViaLink params",
                    ),
                ),
            }
        }
        "groups.cancelJoinRequest" => {
            match serde_json::from_value::<GroupsCancelJoinRequestParams>(request.params) {
                Ok(params) => match runtime.cancel_join_request(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "groups.cancelJoinRequest",
                        "params",
                        "invalid groups.cancelJoinRequest params",
                    ),
                ),
            }
        }
        // Group create (contract revision 1.126, §4.107): the official
        // createGroupV2 upstream leg — the engine derives the new group
        // master key and the answer projects {groupId, revision} verbatim;
        // an indeterminate mutating outcome folds to SEND_OUTCOME_UNKNOWN
        // and is never retried.
        "groups.create" => match serde_json::from_value::<GroupsCreateParams>(request.params) {
            Ok(params) => match runtime.create_group(params).await {
                Ok(result) => HostResponse::success(
                    request_id,
                    serde_json::to_value(result).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("groups.create", "params", "invalid groups.create params"),
            ),
        },
        // Group migration (contract revision 1.123, §4.104): the GV1→GV2
        // upstream leg — the answer projects the engine's {groupId, revision}
        // verbatim (the new master key is the id every other group face
        // addresses); an indeterminate mutating outcome folds to
        // SEND_OUTCOME_UNKNOWN and is never retried.
        "groups.migrate" => match serde_json::from_value::<GroupsMigrateParams>(request.params) {
            Ok(params) => match runtime.migrate_group(params).await {
                Ok(result) => HostResponse::success(
                    request_id,
                    serde_json::to_value(result).unwrap_or(Value::Null),
                ),
                Err(error) => HostResponse::failure(request_id, error.into_api()),
            },
            Err(_) => HostResponse::failure(
                request_id,
                reject_probe("groups.migrate", "params", "invalid groups.migrate params"),
            ),
        },
        // Contact-card send (contract revision 1.124, §4.105): the engine's
        // sendContact face — the conversation row's kind decides the leg. The
        // answer projects the engine's send timestamp as {sentAt} (the
        // calls.sendSignal ack shape); an indeterminate mutating outcome
        // folds to SEND_OUTCOME_UNKNOWN and is never retried.
        "messages.sendContact" => {
            match serde_json::from_value::<MessagesSendContactParams>(request.params) {
                Ok(params) => match runtime.send_contact(params).await {
                    Ok(result) => HostResponse::success(request_id, result),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendContact",
                        "params",
                        "invalid messages.sendContact params",
                    ),
                ),
            }
        }
        // Poll send batch (contract revision 1.125, §4.106): the engine's
        // group-only poll faces — the remoteDelete answer discipline (a
        // definite success answers {"status":"sent"}, an indeterminate
        // outcome the explicit {"status":"unknown"}, a definite error
        // propagates; nothing retries).
        "messages.sendPollCreate" => {
            match serde_json::from_value::<MessagesSendPollCreateParams>(request.params) {
                Ok(params) => match runtime.send_poll_create(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendPollCreate",
                        "params",
                        "invalid messages.sendPollCreate params",
                    ),
                ),
            }
        }
        "messages.sendPollVote" => {
            match serde_json::from_value::<MessagesSendPollVoteParams>(request.params) {
                Ok(params) => match runtime.send_poll_vote(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendPollVote",
                        "params",
                        "invalid messages.sendPollVote params",
                    ),
                ),
            }
        }
        "messages.sendPollTerminate" => {
            match serde_json::from_value::<MessagesSendPollTerminateParams>(request.params) {
                Ok(params) => match runtime.send_poll_terminate(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.sendPollTerminate",
                        "params",
                        "invalid messages.sendPollTerminate params",
                    ),
                ),
            }
        }
        "messages.reportSpam" => {
            match serde_json::from_value::<MessagesReportSpamParams>(request.params) {
                Ok(params) => match runtime.report_spam(params).await {
                    Ok(result) => match serde_json::to_value(result) {
                        Ok(value) => HostResponse::success(request_id, value),
                        Err(_) => HostResponse::failure(
                            request_id,
                            ApiError::new("INTERNAL_ERROR", "result serialization failed", false),
                        ),
                    },
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "messages.reportSpam",
                        "params",
                        "invalid messages.reportSpam params",
                    ),
                ),
            }
        }
        "conversations.reportSpam" => {
            match serde_json::from_value::<ConversationsReportSpamParams>(request.params) {
                Ok(params) => match runtime.report_conversation_spam(params).await {
                    Ok(result) => match serde_json::to_value(result) {
                        Ok(value) => HostResponse::success(request_id, value),
                        Err(_) => HostResponse::failure(
                            request_id,
                            ApiError::new("INTERNAL_ERROR", "result serialization failed", false),
                        ),
                    },
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "conversations.reportSpam",
                        "params",
                        "invalid conversations.reportSpam params",
                    ),
                ),
            }
        }
        "contacts.setLocalAlias" => {
            match serde_json::from_value::<ContactsSetLocalAliasParams>(request.params) {
                Ok(params) => match runtime.set_local_alias(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "contacts.setLocalAlias",
                        "params",
                        "invalid contacts.setLocalAlias params",
                    ),
                ),
            }
        }
        "presence.setTypingMessage" => {
            match serde_json::from_value::<PresenceSetTypingMessageParams>(request.params) {
                Ok(params) => match runtime.set_typing_message(params).await {
                    Ok(status) => HostResponse::success(request_id, json!({ "status": status })),
                    Err(error) => HostResponse::failure(request_id, error.into_api()),
                },
                Err(_) => HostResponse::failure(
                    request_id,
                    reject_probe(
                        "presence.setTypingMessage",
                        "params",
                        "invalid presence.setTypingMessage params",
                    ),
                ),
            }
        }
        _ => HostResponse::failure(
            request_id,
            ApiError::new("METHOD_NOT_ALLOWED", "method is not allowed", false),
        ),
    }
}

fn empty_params(params: &Value) -> bool {
    params.as_object().is_some_and(serde_json::Map::is_empty)
}

/// D4 所有权执行面(1-5c)参数闸:`accountId` 必填非空字符串(槽键语义由
/// 池侧 discard 幂等兜底,这里只挡形状);`reason` 可选字符串(隔离打点用,
/// 休眠臂忽略)。坏形状 = `reject_probe` 同款拒绝,绝不猜默认。
fn ownership_slot_params(params: &Value) -> Result<(String, String), ApiError> {
    let invalid = |field: &'static str, reason: &'static str| -> ApiError {
        reject_probe("ownership.slot", field, reason)
    };
    let account_id = params
        .get("accountId")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| invalid("accountId", "a non-empty accountId string is required"))?
        .to_string();
    let reason = params
        .get("reason")
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| invalid("reason", "when present, reason must be a string"))
        })
        .transpose()?
        .unwrap_or_default();
    Ok((account_id, reason))
}

fn map_start_failure(failure: StartFailure) -> ApiError {
    match failure {
        StartFailure::AlreadyRunning => ApiError::new(
            "RUNTIME_ALREADY_RUNNING",
            "engine runtime is already running",
            false,
        ),
        StartFailure::StartFailed => ApiError::new(
            "RUNTIME_START_FAILED",
            "engine runtime could not be started",
            true,
        ),
        // Contract 1.291: every slot was refused by the store-migration gate.
        // That verdict is terminal for this process - a retry cannot heal a
        // latched block or an unarmed plaintext store - so the wire must not
        // promise one. The store code rides `data` beside the actionable
        // sentence the gate already produced.
        StartFailure::StoreMigrationBlocked { code, message } => ApiError {
            data: Some(json!({ "storeMigrationCode": code })),
            ..ApiError::new("STORE_MIGRATION_BLOCKED", message, false)
        },
        // O1: the structured fatal. `retryable: false` is the class's own
        // assertion (the supervisor latched the fault); the three facts the
        // launcher needs to repair ride `data`, mirrored by the byte-stable
        // KT_FATAL line the supervisor wrote to stderr.
        StartFailure::ContractMismatch(fault) => ApiError {
            data: Some(fault.report_data()),
            ..ApiError::new(
                "ENGINE_CONTRACT_MISMATCH",
                "engine contract mismatch: the engine states no identity, or a contract \
                 revision outside this connector's supported range",
                false,
            )
        },
    }
}

fn map_stop_failure(failure: StopFailure) -> ApiError {
    match failure {
        StopFailure::NotRunning => ApiError::new(
            "RUNTIME_NOT_RUNNING",
            "engine runtime is not running",
            false,
        ),
        StopFailure::StopFailed => ApiError::new(
            "RUNTIME_STOP_FAILED",
            "engine runtime could not be stopped",
            true,
        ),
    }
}

fn host_event_frame(event: HostSideEvent) -> Result<HostEvent<Value>, HostError> {
    match event {
        HostSideEvent::StorageChanged { state } => Ok(HostEvent::new(
            "runtime.storageChanged",
            json!({ "state": state }),
        )),
        HostSideEvent::AccountChanged(account) => Ok(HostEvent::new(
            "account.changed",
            serde_json::to_value(account).unwrap_or(Value::Null),
        )),
        HostSideEvent::ConnectionStateChanged {
            account_id,
            state,
            close_code,
        } => Ok(HostEvent::new(
            "connection.stateChanged",
            json!({
                "accountId": account_id,
                "state": state,
                "closeCode": close_code,
            }),
        )),
        HostSideEvent::ConversationChanged(conversation) => Ok(HostEvent::new(
            "conversation.changed",
            serde_json::to_value(conversation).unwrap_or(Value::Null),
        )),
        HostSideEvent::ConversationMerged {
            account_id,
            from_conversation_id,
            to_conversation,
        } => Ok(HostEvent::new(
            // Contract 1.259 (§4.243): the completed direct-identity fold —
            // the shell row is gone, the canonical summary rides `to`.
            "conversation.merged",
            json!({
                "accountId": account_id,
                "fromConversationId": from_conversation_id,
                "to": serde_json::to_value(to_conversation).unwrap_or(Value::Null),
            }),
        )),
        HostSideEvent::MessageUpserted(message) => Ok(HostEvent::new(
            "message.upserted",
            serde_json::to_value(message).unwrap_or(Value::Null),
        )),
        HostSideEvent::MessageStatusChanged {
            account_id,
            message_id,
            status,
            delivered_at,
            read_at,
            viewed_at,
        } => {
            // Contract 1.32: receipt stamps ride only when the transition
            // wrote them — absent keys keep the host merge total. Contract
            // 1.94: the viewed stamp (§4.77) follows the same discipline.
            let mut payload = json!({
                "accountId": account_id,
                "messageId": message_id,
                "status": status,
            });
            if let Some(at) = delivered_at {
                payload["deliveredAt"] = json!(at);
            }
            if let Some(at) = read_at {
                payload["readAt"] = json!(at);
            }
            if let Some(at) = viewed_at {
                payload["viewedAt"] = json!(at);
            }
            Ok(HostEvent::new("message.statusChanged", payload))
        }
        HostSideEvent::MessageReceiptsChanged {
            account_id,
            message_id,
            receipts,
        } => {
            // Contract 1.190 (§4.190 ⑤): the per-recipient ledger face — the
            // message's whole ledger rides the event (first stamps only,
            // absent tiers absent), so the host merge is total; the empty
            // array is always serialized so a merge never keeps stale rows.
            let payload = json!({
                "accountId": account_id,
                "messageId": message_id,
                "receipts": serde_json::to_value(&receipts).unwrap_or(json!([])),
            });
            Ok(HostEvent::new("message.receiptsChanged", payload))
        }
        HostSideEvent::MessageAttachmentBackfillError {
            account_id,
            conversation_id,
            message_id,
            error,
        } => {
            // Contract 1.192 (§4.192): the phone's terminal error answer for
            // a backfill request — officially MESSAGE_NOT_FOUND, rendered as
            // the BackfillFailureModal(NotFound) face. The error word rides
            // verbatim (bounded ≤64 chars at the §4.175 parse); the
            // addressing trio is the resolved row face the desktop's
            // per-key bookkeeping maps back.
            let payload = json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "messageId": message_id,
                "error": error,
            });
            Ok(HostEvent::new("message.attachmentBackfillError", payload))
        }
        HostSideEvent::MessageAttachmentBackfillSettled {
            account_id,
            conversation_id,
            message_id,
            attachments,
            long_text_pending,
            long_text_terminal,
        } => {
            // Contract 1.193 (§4.193): the pointer/status answer's whole
            // index-aligned face — one entry per remote attachment, index
            // ascending, status one of available/pending/terminal (the
            // official three-state walk, attachmentBackfill.preload
            // .ts:286-327). The array is always serialized (an empty list
            // is the official `pendingCount === 0` settle-and-cancel face),
            // so the desktop merge is total.
            //
            // Contract 1.195 (§4.195): the official `response.longText`
            // state rides two optional booleans — the official
            // `pendingCount` includes a pending long-text body
            // (attachmentBackfill.preload.ts:247-259), so an empty
            // attachment list does not by itself settle the request entry —
            // the desktop keeps its window bookkeeping. The request timer
            // itself is already disarmed on any response (:146-148).
            // Both keys stay absent when the entry is a pointer or absent
            // (the pre-1.195 frame byte-for-byte); a true value is the only
            // serialized form (the serde `skip_serializing_if` discipline).
            let mut payload = json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "messageId": message_id,
                "attachments": serde_json::to_value(&attachments).unwrap_or(json!([])),
            });
            if long_text_pending {
                payload["longTextPending"] = json!(true);
            }
            if long_text_terminal {
                payload["longTextTerminal"] = json!(true);
            }
            Ok(HostEvent::new("message.attachmentBackfillSettled", payload))
        }
        HostSideEvent::ConversationTyping {
            account_id,
            conversation_id,
            action,
            sender_id,
            sender_name,
        } => {
            // Contract 1.138 (§4.128): the sender identity rides only when
            // the envelope named it — absent keys keep the host merge total.
            let mut payload = json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "action": action,
            });
            if let Some(sender_id) = sender_id {
                payload["senderId"] = json!(sender_id);
            }
            if let Some(sender_name) = sender_name {
                payload["senderName"] = json!(sender_name);
            }
            Ok(HostEvent::new("conversation.typing", payload))
        }
        HostSideEvent::MessageViewOnceOpened {
            account_id,
            conversation_id,
            message_id,
            opened_at,
        } => Ok(HostEvent::new(
            "message.viewOnceOpened",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "messageId": message_id,
                "openedAt": opened_at,
            }),
        )),
        HostSideEvent::MessageExpired {
            account_id,
            conversation_id,
            message_ids,
        } => Ok(HostEvent::new(
            "message.expired",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "messageIds": message_ids,
            }),
        )),
        HostSideEvent::CallIncoming {
            account_id,
            conversation_id,
            call_id,
            signal_type,
            payload,
            call_kind,
        } => {
            // 契约 1.263（§4.247）：callKind 加性可选词（audio|video）——缺席
            // 键不在，pre-1.263 宿主读字节同形。
            let mut data = json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "callId": call_id,
                "type": signal_type,
                "payload": payload,
            });
            if let Some(kind) = call_kind {
                data["callKind"] = json!(kind);
            }
            Ok(HostEvent::new("call.incoming", data))
        }
        HostSideEvent::CallGroupCallUpdate {
            account_id,
            conversation_id,
            era_id,
        } => Ok(HostEvent::new(
            "call.groupCallUpdate",
            json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "eraId": era_id,
            }),
        )),
        HostSideEvent::CallGroupIncoming {
            account_id,
            sender,
            payload,
            urgency,
            destination_device_id,
        } => {
            // Contract 1.82, §4.49.2: envelope-level opaque signaling with no
            // conversation semantics — no conversationId key exists to emit,
            // and the destination device rides only when the engine
            // projected one (absent stays absent, the story.received
            // discipline).
            let mut data = json!({
                "accountId": account_id,
                "sender": sender,
                "payload": payload,
                "urgency": urgency,
            });
            if let Some(device_id) = destination_device_id {
                data["destinationDeviceId"] = json!(device_id);
            }
            Ok(HostEvent::new("call.groupIncoming", data))
        }
        HostSideEvent::StoryReceived {
            account_id,
            sender,
            sender_aci,
            sender_name,
            timestamp,
            story,
        } => {
            // Contract 1.76, §4.67: transient story receive — absent
            // optional identities stay absent so the host never has to
            // distinguish a masked source from a missing one.
            let mut payload = json!({
                "accountId": account_id,
                "story": story,
            });
            if let Some(sender) = sender {
                payload["sender"] = json!(sender);
            }
            if let Some(aci) = sender_aci {
                payload["senderAci"] = json!(aci);
            }
            if let Some(name) = sender_name {
                payload["senderName"] = json!(name);
            }
            if let Some(at) = timestamp {
                payload["timestamp"] = json!(at);
            }
            Ok(HostEvent::new("story.received", payload))
        }
        HostSideEvent::StoryViewed {
            account_id,
            viewer,
            viewer_aci,
            viewer_name,
            sent_timestamps,
            viewed_at,
        } => {
            // Contract 1.85, §4.70: transient own-story view receipts — the
            // story.received absent-optional-identity discipline, plus the
            // receipt face the desktop joins against its own story timeline
            // (signalStoryApplyView: senderKey 'self', sentAt per entry,
            // viewerKey = viewerAci ?? viewer, viewedAtMs = viewedAt).
            let mut payload = json!({
                "accountId": account_id,
                "sentTimestamps": sent_timestamps,
                "viewedAt": viewed_at,
            });
            if let Some(viewer) = viewer {
                payload["viewer"] = json!(viewer);
            }
            if let Some(aci) = viewer_aci {
                payload["viewerAci"] = json!(aci);
            }
            if let Some(name) = viewer_name {
                payload["viewerName"] = json!(name);
            }
            Ok(HostEvent::new("story.viewed", payload))
        }
        HostSideEvent::StoryReaction {
            account_id,
            emoji,
            remove,
            story_author,
            story_sent_at,
            group_id,
            sender,
            sender_aci,
            sender_name,
            timestamp,
        } => {
            // Contract 1.154 §4.153, group legs contract 1.158, §4.156:
            // transient story reaction — the story.received
            // absent-optional-identity discipline, `remove` always present
            // (the official reaction-remove is a real emoji delta, not an
            // absent key), the anchor named by its two wire keys, and the
            // group leg's groupId an absent-optional key like the identity
            // family.
            let mut payload = json!({
                "accountId": account_id,
                "emoji": emoji,
                "remove": remove,
                "storyAuthor": story_author,
                "storySentAt": story_sent_at,
            });
            if let Some(group) = group_id {
                payload["groupId"] = json!(group);
            }
            if let Some(sender) = sender {
                payload["sender"] = json!(sender);
            }
            if let Some(aci) = sender_aci {
                payload["senderAci"] = json!(aci);
            }
            if let Some(name) = sender_name {
                payload["senderName"] = json!(name);
            }
            if let Some(at) = timestamp {
                payload["timestamp"] = json!(at);
            }
            Ok(HostEvent::new("story.reaction", payload))
        }
        HostSideEvent::StoryDeleted {
            account_id,
            story_sent_at,
            group_id,
            sender,
            sender_aci,
            sender_name,
            timestamp,
        } => {
            // Contract 1.154 §4.153, group leg contract 1.158, §4.156:
            // transient story remote-delete — same absent-optional
            // discipline, the deleted story named by its upstream sentAt,
            // the conservative group leg's groupId absent-optional.
            let mut payload = json!({
                "accountId": account_id,
                "storySentAt": story_sent_at,
            });
            if let Some(group) = group_id {
                payload["groupId"] = json!(group);
            }
            if let Some(sender) = sender {
                payload["sender"] = json!(sender);
            }
            if let Some(aci) = sender_aci {
                payload["senderAci"] = json!(aci);
            }
            if let Some(name) = sender_name {
                payload["senderName"] = json!(name);
            }
            if let Some(at) = timestamp {
                payload["timestamp"] = json!(at);
            }
            Ok(HostEvent::new("story.deleted", payload))
        }
        HostSideEvent::StoryDeleteCandidate {
            account_id,
            group_id,
            target_sent_timestamp,
            sender,
            sender_aci,
            sender_name,
            timestamp,
        } => {
            // Contract 1.158, §4.156: transient group story delete
            // candidacy — the official group story deletion rides a regular
            // group DOE, so the true §4.91 buffer miss on a group leg claims
            // candidacy beside the unchanged buffer. Required keys pinned
            // (accountId, groupId, targetSentTimestamp); the identity family
            // rides the story.deleted absent-optional discipline. No gate,
            // nothing persists.
            let mut payload = json!({
                "accountId": account_id,
                "groupId": group_id,
                "targetSentTimestamp": target_sent_timestamp,
            });
            if let Some(sender) = sender {
                payload["sender"] = json!(sender);
            }
            if let Some(aci) = sender_aci {
                payload["senderAci"] = json!(aci);
            }
            if let Some(name) = sender_name {
                payload["senderName"] = json!(name);
            }
            if let Some(at) = timestamp {
                payload["timestamp"] = json!(at);
            }
            Ok(HostEvent::new("story.deleteCandidate", payload))
        }
        HostSideEvent::SyncStoryRecipientUpdate {
            account_id,
            timestamp,
            recipients,
        } => {
            // Contract 1.154, §4.153: transient own-story distribution sync —
            // the recipients ride verbatim in the sent-transcript
            // storyMessageRecipients shape (§4.88); an empty list stays an
            // empty list (the official list-narrowed semantics).
            let payload = json!({
                "accountId": account_id,
                "timestamp": timestamp,
                "storyMessageRecipients": recipients,
            });
            Ok(HostEvent::new("story.recipientUpdate", payload))
        }
        HostSideEvent::GroupChanged {
            account_id,
            conversation_id,
            revision,
            changes,
            editor,
            expire_timer_seconds,
        } => {
            // Contract 1.100, §4.81 D3: the verbatim change batch forwards
            // with the absent-optional discipline — an unnamed editor and a
            // timer-less batch stay absent keys.
            let mut payload = json!({
                "accountId": account_id,
                "conversationId": conversation_id,
                "revision": revision,
                "changes": changes,
            });
            if let Some(aci) = editor {
                payload["editor"] = json!(aci);
            }
            if let Some(seconds) = expire_timer_seconds {
                payload["expireTimerSeconds"] = json!(seconds);
            }
            Ok(HostEvent::new("group.changed", payload))
        }
        HostSideEvent::SyncDeleteForMe {
            account_id,
            deletes,
            conversations,
            attachments,
        } => {
            // Contract 1.102, §4.83: the delete groups ride with the
            // absent-optional discipline — a group nothing resolved stays
            // conversation-less, an unmatched entry stays messageId-less (the
            // serde skip keeps the keys absent).
            let mut payload = json!({
                "accountId": account_id,
                "deletes": deletes,
            });
            // Contract 1.182, §4.182: the whole-conversation answers ride the
            // same event (one transient lane, one desktop consumer). The key
            // is skipped when empty so a message-only envelope keeps the 1.102
            // byte shape exactly.
            if !conversations.is_empty() {
                payload["conversations"] =
                    serde_json::to_value(&conversations).unwrap_or(serde_json::Value::Null);
            }
            // Contract 1.196, §4.196: the single-attachment entries ride the
            // same additive lane. The key is skipped when empty so every
            // pre-1.196 envelope (and every envelope without the fourth arm)
            // keeps its previous frame byte-for-byte; within an entry the
            // serde skips keep an unresolved id or an absent leg out.
            if !attachments.is_empty() {
                payload["attachmentDeletes"] =
                    serde_json::to_value(&attachments).unwrap_or(serde_json::Value::Null);
            }
            Ok(HostEvent::new("message.deleteForMe", payload))
        }
        HostSideEvent::IdentityVerifiedChanged {
            account_id,
            destination_uuid,
            state,
            destination_number,
            identity_key,
            conversation_id,
        } => {
            // Contract 1.103, §4.84: the verified record forwards flat with
            // the absent-optional discipline — an unresolved destination
            // stays conversation-less, and the number/key ride only when the
            // projection carried them (the story.received conditional-insert
            // style).
            let mut payload = json!({
                "accountId": account_id,
                "destinationUuid": destination_uuid,
                "state": state,
            });
            if let Some(number) = destination_number {
                payload["destinationNumber"] = json!(number);
            }
            if let Some(key) = identity_key {
                payload["identityKey"] = json!(key);
            }
            if let Some(conversation_id) = conversation_id {
                payload["conversationId"] = json!(conversation_id);
            }
            Ok(HostEvent::new("identity.verifiedChanged", payload))
        }
        HostSideEvent::CallHistoryEvent {
            account_id,
            call_id,
            timestamp,
            kind,
            direction,
            outcome,
            peer_id,
            conversation_id,
        } => {
            // Contract 1.104, §4.85: the call-history record forwards flat
            // with the absent-optional discipline — the word legs ride only
            // when the projection carried them and an unresolved record
            // stays conversation-less (the story.received conditional-insert
            // style). Since 1.155 the record also rides the §4.85 raw
            // identity leg: the projection's own conversation identity goes
            // out verbatim as `peerId` — the same leg `call.logEvent`
            // already carries, the desktop's ad-hoc ledger join key — only
            // when the projection named one, absent staying absent.
            let mut payload = json!({
                "accountId": account_id,
                "callId": call_id,
                "timestamp": timestamp,
            });
            if let Some(kind) = kind {
                payload["type"] = json!(kind);
            }
            if let Some(direction) = direction {
                payload["direction"] = json!(direction);
            }
            if let Some(outcome) = outcome {
                payload["event"] = json!(outcome);
            }
            if let Some(peer_id) = peer_id {
                payload["peerId"] = json!(peer_id);
            }
            if let Some(conversation_id) = conversation_id {
                payload["conversationId"] = json!(conversation_id);
            }
            Ok(HostEvent::new("call.historyEvent", payload))
        }
        HostSideEvent::SettingsConfigurationSync {
            account_id,
            read_receipts,
            unidentified_delivery_indicators,
            typing_indicators,
            link_previews,
        } => {
            // Contract 1.106, §4.87: the flags forward flat with the
            // absent-optional discipline — a flag the projection did not
            // carry stays an absent key (the parse guarantees at least one
            // survivor).
            let mut payload = json!({ "accountId": account_id });
            if let Some(flag) = read_receipts {
                payload["readReceipts"] = json!(flag);
            }
            if let Some(flag) = unidentified_delivery_indicators {
                payload["unidentifiedDeliveryIndicators"] = json!(flag);
            }
            if let Some(flag) = typing_indicators {
                payload["typingIndicators"] = json!(flag);
            }
            if let Some(flag) = link_previews {
                payload["linkPreviews"] = json!(flag);
            }
            Ok(HostEvent::new("settings.configurationSync", payload))
        }
        HostSideEvent::FetchLatestSync { account_id, kind } => {
            // Contract 1.106, §4.87: the trigger forwards flat — the
            // SCREAMING word rides verbatim when the projection carried it,
            // absent otherwise (the official fires the same type-less event).
            let mut payload = json!({ "accountId": account_id });
            if let Some(kind) = kind {
                payload["type"] = json!(kind);
            }
            Ok(HostEvent::new("sync.fetchLatest", payload))
        }
        HostSideEvent::CallLinkUpdate {
            account_id,
            kind,
            root_key,
            admin_key,
        } => {
            // Contract 1.106, §4.87: the record forwards flat — the verb is
            // the parser's single-member whitelist verbatim, the root key is
            // the hard-gated subject, the admin key rides only when the
            // projection carried it. The material is never touched beyond
            // the pass-through (the §4.73 zero-parsing discipline).
            let mut payload = json!({
                "accountId": account_id,
                "type": kind,
                "rootKey": root_key,
            });
            if let Some(key) = admin_key {
                payload["adminKey"] = json!(key);
            }
            Ok(HostEvent::new("call.linkUpdate", payload))
        }
        HostSideEvent::CallLogEvent {
            account_id,
            kind,
            timestamp,
            conversation_id,
            call_id,
            resolved_conversation_id,
        } => {
            // Contract 1.106, §4.87: the mutation forwards flat — the verb
            // is the parser's hard-gated whitelist member, the projection's
            // own keys ride verbatim (absent staying absent). The raw
            // conversation identity rides `peerId` (the official
            // CallLogEventDetails name — the desktop's own official join
            // reads it), and the §4.85-ladder hit rides `conversationId` —
            // across the whole event surface that key always means the
            // resolved local conversation id, so the desktop can take the
            // shortcut or run its own join.
            let mut payload = json!({
                "accountId": account_id,
                "type": kind,
            });
            if let Some(timestamp) = timestamp {
                payload["timestamp"] = json!(timestamp);
            }
            if let Some(identity) = conversation_id {
                payload["peerId"] = json!(identity);
            }
            if let Some(call_id) = call_id {
                payload["callId"] = json!(call_id);
            }
            if let Some(conversation_id) = resolved_conversation_id {
                payload["conversationId"] = json!(conversation_id);
            }
            Ok(HostEvent::new("call.logEvent", payload))
        }
        HostSideEvent::DeviceNameChanged {
            account_id,
            device_id,
        } => {
            // Contract 1.106, §4.87: the id forwards flat; the local-device
            // comparison stays the desktop's.
            Ok(HostEvent::new(
                "account.deviceNameChanged",
                json!({
                    "accountId": account_id,
                    "deviceId": device_id,
                }),
            ))
        }
        HostSideEvent::UsernameChanged { account_id } => {
            // Contract 1.106, §4.87: the empty pure-signal sync forwards as
            // the fact alone; the new value converges through the host's own
            // profile read.
            Ok(HostEvent::new(
                "account.usernameChanged",
                json!({ "accountId": account_id }),
            ))
        }
        HostSideEvent::PniChanged {
            account_id,
            registration_id,
            new_e164,
        } => {
            // Contract 1.106, §4.87: the stripped face forwards flat with
            // the absent-optional discipline (the parse guarantees at least
            // one survivor; the key material never crossed the engine
            // boundary and the event carries none either).
            let mut payload = json!({ "accountId": account_id });
            if let Some(id) = registration_id {
                payload["registrationId"] = json!(id);
            }
            if let Some(number) = new_e164 {
                payload["newE164"] = json!(number);
            }
            Ok(HostEvent::new("identity.pniChanged", payload))
        }
        HostSideEvent::GroupTerminated {
            account_id,
            group_id,
            terminator,
            timestamp,
        } => {
            // Contract 1.134, §4.117: the engine's groupTerminated
            // projection forwards with the subject verbatim — absent
            // optional identities stay absent (the story.received
            // conditional-insert discipline).
            let mut payload = json!({ "accountId": account_id, "groupId": group_id });
            if let Some(aci) = terminator {
                payload["terminator"] = json!(aci);
            }
            if let Some(at) = timestamp {
                payload["timestamp"] = json!(at);
            }
            Ok(HostEvent::new("group.terminated", payload))
        }
        HostSideEvent::ContactProfileUpdated {
            account_id,
            aci,
            timestamp,
        } => {
            // Contract 1.134, §4.117: the profile-key-landed notify — the
            // subject aci plus the envelope timestamp when it carried one;
            // the re-fetch is the desktop's on-demand pull.
            let mut payload = json!({ "accountId": account_id, "aci": aci });
            if let Some(at) = timestamp {
                payload["timestamp"] = json!(at);
            }
            Ok(HostEvent::new("contact.profileUpdated", payload))
        }
        HostSideEvent::ReceiveEmptied { account_id } => {
            // Contract 1.134, §4.117: the account-domain transient lane —
            // the queue-drained advisory forwards as the fact alone.
            Ok(HostEvent::new(
                "receive.emptied",
                json!({ "accountId": account_id }),
            ))
        }
        HostSideEvent::ClockSkewObserved {
            account_id,
            skew_ms,
            server_timestamp,
        } => {
            // Contract 1.134, §4.117: the skew alert — the signed skew
            // forwards verbatim (positive = local clock fast); the
            // observing envelope's server stamp rides when projected.
            let mut payload = json!({ "accountId": account_id, "skewMs": skew_ms });
            if let Some(at) = server_timestamp {
                payload["serverTimestamp"] = json!(at);
            }
            Ok(HostEvent::new("receive.clockSkew", payload))
        }
        HostSideEvent::ConversationStateChanged {
            account_id,
            conversations,
            overflow,
        } => {
            // Contract 1.134, §4.117: the three-flag inbound batch — the
            // conversations array is the engine projection verbatim (the
            // owner red line: a passthrough structure error corrupts every
            // downstream consumer), never re-shaped or trimmed here; the
            // overflow tail marker rides beside it.
            Ok(HostEvent::new(
                "conversation.stateChanged",
                json!({
                    "accountId": account_id,
                    "conversations": conversations,
                    "overflow": overflow,
                }),
            ))
        }
        HostSideEvent::StoragePull {
            account_id,
            trigger,
            contacts_ok,
            groups_ok,
        } => {
            // Contract 1.141, §4.137: the storage-manifest pull outcome —
            // the trigger word rides verbatim (the value domain stays the
            // engine's; the connector never rewrites an unseen word into a
            // known one) beside the two per-family result legs.
            Ok(HostEvent::new(
                "engine.storagePull",
                json!({
                    "accountId": account_id,
                    "trigger": trigger,
                    "contactsOk": contacts_ok,
                    "groupsOk": groups_ok,
                }),
            ))
        }
        HostSideEvent::InitialSyncComplete {
            account_id,
            manifest_ok,
            profiles_ok,
        } => {
            // Contract 1.220, §4.230: the link-window post-registration sync
            // completion — the two per-leg result bits ride verbatim (the
            // connector never folds a false leg into a done bit); the
            // desktop's inbox gate owns the ok-face settle.
            Ok(HostEvent::new(
                "engine.initialSyncComplete",
                json!({
                    "accountId": account_id,
                    "manifestOk": manifest_ok,
                    "profilesOk": profiles_ok,
                }),
            ))
        }
        HostSideEvent::IdentityChanged {
            account_id,
            source_uuid,
            timestamp,
        } => {
            // 契约 §4.226（台账 §27.10）：对端安全码变更通知——转发宿主渲染
            // 时间线系统行。观测事件：不自动重置会话，信任决定权在用户。
            Ok(HostEvent::new(
                "identity.changed",
                json!({
                    "accountId": account_id,
                    "sourceUuid": source_uuid,
                    "timestamp": timestamp,
                }),
            ))
        }
        HostSideEvent::ContactSyncCompleted { account_id } => Ok(HostEvent::new(
            "contactSync.complete",
            json!({ "accountId": account_id }),
        )),
        HostSideEvent::ReceiveDecryptionError { account_id } => {
            // Contract 1.165, §4.163: the decryption-error envelope — the
            // fact alone (the receive.emptied posture). Observability only:
            // no reset action exists on this face, the metrics snapshot
            // counts independently.
            Ok(HostEvent::new(
                "receive.decryptionError",
                json!({ "accountId": account_id }),
            ))
        }
    }
}

async fn send_json<S, T>(framed: &mut Framed<S, LinesCodec>, value: &T) -> Result<(), HostError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize,
{
    let encoded = serde_json::to_string(value).map_err(|_| HostError::InvalidFrame)?;
    framed
        .send(encoded)
        .await
        .map_err(|error| codec_failure(&error))
}

fn random_identifier() -> String {
    let mut value = [0_u8; 16];
    rand::rng().fill_bytes(&mut value);
    hex::encode(value)
}

#[derive(Default)]
struct RecentRequestIds {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl RecentRequestIds {
    fn insert(&mut self, id: String) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        if self.order.len() == RECENT_REQUEST_IDS
            && let Some(expired) = self.order.pop_front()
        {
            self.set.remove(&expired);
        }
        self.set.insert(id.clone());
        self.order.push_back(id);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use futures_util::{FutureExt, SinkExt, StreamExt};
    use hmac::{Hmac, Mac};
    use serde_json::Value;
    use sha2::Sha256;
    use tempfile::TempDir;
    use tokio::io::duplex;

    use super::*;
    use crate::auth::BootstrapSecret;
    use crate::engine::EngineConfig;
    use crate::service::AttachmentBackfillSettledEntry;
    use crate::store::{Store, StoreKey};
    use crate::supervisor::RuntimeSupervisor;

    /// Serializes the host-session unit tests. `host_pending_requests` is a
    /// process-global gauge (production serves one authenticated session per
    /// process, so a global is the truthful model there); concurrent test
    /// sessions would race the gauge assertions in
    /// `connection_exit_resets_the_host_pending_gauge` and the §4.169 wedge
    /// tests. Holding this lock makes each test's zero-to-zero reading mean
    /// what it says.
    static HOST_SESSION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn test_supervisor() -> Arc<RuntimeSupervisor> {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = Store::open(temp.path(), Some(StoreKey::from_bytes([0x5A; 32]))).unwrap();
        // Leak TempDir for unit test lifetime; path stays valid for process.
        std::mem::forget(temp);
        Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                PathBuf::from("unused-engine"),
                PathBuf::from("/tmp/unused-signal-data"),
            ),
            Arc::new(store),
            crate::DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ))
    }

    /// A single-group runtime assembled the same way the launcher assembles
    /// multi-group plans; field-for-field identical on the wire.
    fn test_runtime() -> Arc<ProxyGroupRuntime> {
        ProxyGroupRuntime::new(vec![crate::registry::ProxyGroupSlot::new(
            crate::DEFAULT_PROXY_GROUP_ID.to_string(),
            test_supervisor(),
        )])
    }

    /// Contract revision 1.271 (§4.255): the two attachment-dimension methods
    /// ride the host frame with their own params faces — a params-shape miss
    /// answers INVALID_REQUEST through `reject_probe` before any store work,
    /// and the wire names stay exactly as declared (no key invention, no
    /// rename). This pins the strict `deny_unknown_fields` posture the rest of
    /// the family keeps plus the u32/negative refusals.
    #[test]
    fn attachment_dimension_params_faces_are_strict() {
        let write: crate::service::MessagesSetAttachmentDimensionsParams =
            serde_json::from_value(serde_json::json!({
                "accountId": "a",
                "conversationId": "c",
                "messageId": "m",
                "attachmentId": "att",
                "width": 1280,
                "height": 720
            }))
            .expect("the §4.255 write face parses");
        assert_eq!(write.width, 1280);
        assert_eq!(write.height, 720);

        // 未知键 = 形状错（与相邻 params 族同一 deny_unknown_fields 纪律）。
        assert!(
            serde_json::from_value::<crate::service::MessagesSetAttachmentDimensionsParams>(
                serde_json::json!({
                    "accountId": "a",
                    "conversationId": "c",
                    "messageId": "m",
                    "attachmentId": "att",
                    "width": 1,
                    "height": 1,
                    "extra": true
                }),
            )
            .is_err()
        );
        // 负值在反序列化层即拒（u32 面）。
        assert!(
            serde_json::from_value::<crate::service::MessagesSetAttachmentDimensionsParams>(
                serde_json::json!({
                    "accountId": "a",
                    "conversationId": "c",
                    "messageId": "m",
                    "attachmentId": "att",
                    "width": -1,
                    "height": 1
                }),
            )
            .is_err()
        );

        // 读面：limit 缺席合法（缺省窗口），在场必须是整数。
        let absent: crate::service::MessagesListAttachmentDimensionsParams =
            serde_json::from_value(serde_json::json!({
                "accountId": "a",
                "conversationId": "c"
            }))
            .expect("limit is optional on the §4.255 read face");
        assert_eq!(absent.limit, None);
        assert!(
            serde_json::from_value::<crate::service::MessagesListAttachmentDimensionsParams>(
                serde_json::json!({
                    "accountId": "a",
                    "conversationId": "c",
                    "limit": "many"
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn a_vanished_host_ends_the_session_instead_of_failing_the_process() {
        // The host closing its socket abruptly is how a session normally ends;
        // reporting it as a bad frame makes the process exit non-zero and tells
        // the user the protocol broke.
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::NotConnected,
        ] {
            assert!(matches!(
                codec_failure(&LinesCodecError::Io(io::Error::from(kind))),
                HostError::PeerGone,
            ));
        }
        // A frame we could not read is still a protocol error.
        assert!(matches!(
            codec_failure(&LinesCodecError::MaxLineLengthExceeded),
            HostError::InvalidFrame,
        ));
        assert!(matches!(
            codec_failure(&LinesCodecError::Io(io::Error::from(
                io::ErrorKind::InvalidData
            ))),
            HostError::InvalidFrame,
        ));
    }

    #[test]
    fn request_id_window_is_bounded_and_detects_replay() {
        let mut ids = RecentRequestIds::default();
        assert!(ids.insert("same".into()));
        assert!(!ids.insert("same".into()));
        for index in 0..RECENT_REQUEST_IDS {
            assert!(ids.insert(format!("id-{index}")));
        }
        assert!(ids.set.len() <= RECENT_REQUEST_IDS);
        assert!(ids.insert("same".into()));
    }

    #[test]
    fn pending_budget_bounds_global_account_and_bytes() {
        let mut per_account = HostPendingBudget::default();
        for _ in 0..MAX_PENDING_HOST_REQUESTS_PER_ACCOUNT {
            assert!(per_account.try_admit(Some("account-a"), 1));
        }
        assert!(!per_account.try_admit(Some("account-a"), 1));
        assert!(per_account.try_admit(Some("account-b"), 1));
        per_account.complete(Some("account-a"), 1);
        assert!(per_account.try_admit(Some("account-a"), 1));

        let mut global = HostPendingBudget::default();
        for _ in 0..MAX_PENDING_HOST_REQUESTS {
            assert!(global.try_admit(None, 1));
        }
        assert!(!global.try_admit(None, 1));

        let mut bytes = HostPendingBudget::default();
        assert!(bytes.try_admit(None, MAX_PENDING_HOST_BYTES));
        assert!(!bytes.try_admit(None, 1));
    }

    /// §4.168 bounded answer, starvation arm: a control permit held forever by
    /// a wedged earlier dispatch used to park every later same-lane request in
    /// `acquire` with no timeout, no warn and no answer. The stall budget now
    /// bounds the wait: one tick before it the request is still honestly
    /// pending, at it the retryable `INTERNAL_ERROR` deadline face comes back
    /// and the caller holds nothing.
    #[tokio::test(start_paused = true)]
    async fn starved_lane_permit_answers_the_deadline_face_within_the_stall_budget() {
        let limits = HostDispatchLimits::new();
        // The wedged head: holds the single control permit forever.
        let held = limits.acquire("runtime.status", None, None).await.unwrap();

        let waiter = acquire_within_stall_budget(
            limits.acquire("accounts.list", None, None),
            false,
            "accounts.list",
            None,
            10,
        );
        tokio::pin!(waiter);

        // First poll registers the deadline timer at the unadvanced clock;
        // the wait is honest at every tick before the budget.
        assert!(waiter.as_mut().now_or_never().is_none());
        tokio::time::advance(HOST_DISPATCH_STALL_WARN_AFTER - Duration::from_secs(1)).await;
        assert!(
            waiter.as_mut().now_or_never().is_none(),
            "one tick before the budget the request is still honestly pending"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        let answered = waiter
            .now_or_never()
            .expect("the stall budget must answer the starved request");
        let error = match answered {
            Ok(_) => panic!("the starved request must be answered, not permitted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "INTERNAL_ERROR");
        assert!(error.retryable, "the deadline face must be retryable");

        // The answered waiter never held a permit: once the wedged head
        // drains, the lane admits the next request immediately.
        drop(held);
        limits.acquire("accounts.list", None, None).await.unwrap();
    }

    /// §4.168 bounded answer, wedge arm: a dispatch stuck past every face
    /// budget used to warn once and then hang forever — permit, pending
    /// budget and the answer itself all parked. The stall budget now emits
    /// the §4.166 warn and answers the retryable `INTERNAL_ERROR` deadline
    /// face carrying the original request id, so every admitted request gets
    /// an answer and every guard drops with the abandoned future.
    #[tokio::test(start_paused = true)]
    async fn wedged_dispatch_answers_the_deadline_face_within_the_stall_budget() {
        let task = tokio::spawn(dispatch_within_stall_budget(
            std::future::pending::<HostResponse>(),
            "kt-9".to_string(),
            "accounts.list",
            None,
            10,
        ));
        // Let the spawned dispatch register its deadline timer before the
        // paused clock moves.
        tokio::task::yield_now().await;
        tokio::time::advance(HOST_DISPATCH_STALL_WARN_AFTER).await;
        let response = timeout(Duration::from_secs(1), task)
            .await
            .expect("the stall budget must answer the wedged dispatch")
            .unwrap();
        let error = response
            .error
            .expect("a wedged dispatch must be answered with the deadline face");
        assert_eq!(error.code, "INTERNAL_ERROR");
        assert!(error.retryable, "the deadline face must be retryable");
        assert_eq!(response.request_id, "kt-9");
    }

    /// §4.168: the stall deadline never touches a lane-starved `link.*`
    /// waiter — their approval window is legitimately long, so an exempt
    /// wait stays pending past the budget — while every non-exempt wait is
    /// bounded.
    /// §4.168: the stall budget never bounds a `link.*` wait — the caller
    /// marks them exempt because their approval window is legitimately long,
    /// so an exempt wait stays pending with the clock far past the budget
    /// (the §4.166-era behaviour, unchanged).
    #[tokio::test(start_paused = true)]
    async fn link_waits_stay_exempt_from_the_stall_budget() {
        let exempt = acquire_within_stall_budget(
            std::future::pending::<Result<HostDispatchPermit, ApiError>>(),
            true,
            "link.finish",
            None,
            10,
        );
        tokio::pin!(exempt);
        tokio::time::advance(HOST_DISPATCH_STALL_WARN_AFTER * 2).await;
        assert!(
            exempt.now_or_never().is_none(),
            "an exempt link wait stays pending beyond the budget"
        );
    }

    /// §4.168: a full session ends with the process-global pending gauge at
    /// zero — the exit reset keeps `host_pending_requests` a truthful
    /// picture even when the §4.166-era wedge shape would have left the
    /// teardown drain unable to complete a stuck dispatch.
    #[tokio::test]
    async fn connection_exit_resets_the_host_pending_gauge() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        metrics::set_host_pending(0);
        let secret_bytes = [7_u8; 32];
        let secret = Arc::new(BootstrapSecret::for_test(secret_bytes));
        let runtime = test_runtime();
        let (server_stream, client_stream) = duplex(64 * 1024);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());
        let challenge: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
        client
            .send(
                json!({
                    "apiVersion": API_VERSION,
                    "requestId": "handshake-1",
                    "method": "handshake",
                    "params": {
                        "clientNonce": hex::encode([9_u8; 32]),
                        "proof": client_proof(&secret_bytes, server_nonce, &hex::encode([9_u8; 32])),
                    }
                })
                .to_string(),
            )
            .await
            .unwrap();
        let _handshake_reply = client.next().await.unwrap().unwrap();
        client
            .send(
                json!({
                    "apiVersion": API_VERSION,
                    "requestId": "status-1",
                    "method": "runtime.status",
                    "params": {}
                })
                .to_string(),
            )
            .await
            .unwrap();
        let _status_reply: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        drop(client);
        let _ = server.await;

        assert_eq!(
            metrics::host_pending_requests(),
            0,
            "a finished session must leave the pending gauge at zero"
        );
    }

    /// An authenticated session over a small duplex for the §4.169 wedge
    /// tests: the server end runs `handle_connection`, the client end has
    /// completed the handshake and is returned to the caller, which stops
    /// reading from it — the wedge premise.
    async fn authenticated_session(
        buffer: usize,
    ) -> (
        tokio::task::JoinHandle<Result<(), HostError>>,
        Framed<tokio::io::DuplexStream, LinesCodec>,
    ) {
        let secret_bytes = [7_u8; 32];
        let secret = Arc::new(BootstrapSecret::for_test(secret_bytes));
        let runtime = test_runtime();
        let (server_stream, client_stream) = duplex(buffer);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());
        let challenge: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
        client
            .send(
                json!({
                    "apiVersion": API_VERSION,
                    "requestId": "handshake-1",
                    "method": "handshake",
                    "params": {
                        "clientNonce": hex::encode([9_u8; 32]),
                        "proof": client_proof(&secret_bytes, server_nonce, &hex::encode([9_u8; 32])),
                    }
                })
                .to_string(),
            )
            .await
            .unwrap();
        let _handshake_reply = client.next().await.unwrap().unwrap();
        (server, client)
    }

    fn status_request(id: &str) -> String {
        json!({
            "apiVersion": API_VERSION,
            "requestId": id,
            "method": "runtime.status",
            "params": {}
        })
        .to_string()
    }

    async fn wait_for_gauge_to_drain(what: &str) {
        timeout(Duration::from_secs(5), async {
            while metrics::host_pending_requests() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}"));
    }

    /// §4.169: a host that stops reading parks only the single writer task.
    /// The session loop never awaits socket writability, so follow-up work
    /// still completes and releases its budget slot — the pre-queue code
    /// parked inside the first answer's `send_shared` and the gauge froze
    /// with it (the 04:05:58Z wedge shape).
    #[tokio::test]
    async fn wedged_peer_parks_the_writer_task_and_the_session_loop_stays_alive() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        metrics::set_host_pending(0);
        let (server, mut client) = authenticated_session(1024).await;
        // Fill the 1 KiB duplex buffer with unanswered answers: the writer
        // parks inside its flush, the queue (256 slots) holds the rest.
        for index in 0..16 {
            client
                .send(status_request(&format!("fill-{index}")))
                .await
                .unwrap();
        }
        wait_for_gauge_to_drain("every admitted dispatch must complete while the writer is parked")
            .await;

        // The loop is alive: a follow-up request is admitted, dispatched and
        // its budget slot released, with no byte consumed by the peer.
        client.send(status_request("follow-up")).await.unwrap();
        wait_for_gauge_to_drain(
            "the session loop must keep completing work behind a parked writer",
        )
        .await;
        assert!(
            !server.is_finished(),
            "a parked writer must not tear the session down"
        );

        drop(client);
        let _ = timeout(Duration::from_secs(5), server).await;
    }

    /// §4.169: once the queue saturates behind the parked writer, further
    /// answers drop with the saturation warn — and the pending budget still
    /// releases, so `host_pending_requests` stays truthful and the loop
    /// keeps admitting (the lossy face, never a parked dispatch future).
    #[tokio::test]
    async fn saturated_write_queue_drops_the_answer_warns_and_releases_the_budget() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        metrics::set_host_pending(0);
        let (server, mut client) = authenticated_session(1024).await;
        // Flood past the queue capacity without reading: admissions beyond
        // the pending budget reject (reject frames enqueue too), dispatch
        // answers enqueue, the parked writer drains nothing — the queue
        // saturates and stays saturated.
        for index in 0..HOST_WRITE_QUEUE_CAPACITY + 32 {
            client
                .send(status_request(&format!("flood-{index}")))
                .await
                .unwrap();
        }
        wait_for_gauge_to_drain("dropped answers must still release every budget slot").await;

        // A request answered after saturation completes the same way: the
        // drop face, not a frozen lane.
        client
            .send(status_request("after-saturation"))
            .await
            .unwrap();
        wait_for_gauge_to_drain(
            "the saturated queue must drop answers instead of parking the loop",
        )
        .await;
        assert!(
            !server.is_finished(),
            "a saturated queue must not tear the session down"
        );

        drop(client);
        let _ = timeout(Duration::from_secs(5), server).await;
    }

    /// §4.169: the writer task owns the sink, so its I/O failure surfaces on
    /// the failure channel and the session ends exactly as a direct write
    /// error did — never a dead sink the loop keeps feeding forever.
    #[tokio::test]
    async fn writer_io_failure_still_ends_the_session() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        // Unit face: the wedged writer reports the sink failure and exits.
        let (peer, server_side) = duplex(64);
        let (failures_tx, mut failures_rx) = mpsc::channel(1);
        let (frames_tx, frames_rx) = mpsc::channel(8);
        let writer = tokio::spawn(run_host_writer(
            frames_rx,
            Framed::new(server_side, LinesCodec::new()).split().0,
            failures_tx,
        ));
        for _ in 0..8 {
            frames_tx.send("x".repeat(200)).await.unwrap();
        }
        // Let the writer park inside its flush on the full 64-byte buffer,
        // then break the pipe under it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(peer);
        let failure = timeout(Duration::from_secs(5), failures_rx.recv())
            .await
            .expect("the writer must report its failure on the channel")
            .expect("the failure sender stays alive while the writer runs");
        assert!(
            matches!(failure, HostError::PeerGone),
            "a vanished peer normalizes to PeerGone, got {failure:?}"
        );
        timeout(Duration::from_secs(5), writer)
            .await
            .expect("the writer task must exit after reporting the failure")
            .unwrap();

        // Session face: with the writer wedged and the sink then broken, the
        // session ends instead of running with a dead writer.
        metrics::set_host_pending(0);
        let (server, mut client) = authenticated_session(1024).await;
        for index in 0..16 {
            client
                .send(status_request(&format!("fill-{index}")))
                .await
                .unwrap();
        }
        wait_for_gauge_to_drain("the wedge must be in place before the drop").await;
        drop(client);
        let _ = timeout(Duration::from_secs(5), server)
            .await
            .expect("the session must end once the writer's sink fails")
            .expect("the vanished host stays PeerGone-normalized at teardown");
    }

    #[tokio::test]
    async fn phone_approval_wait_does_not_block_link_control() {
        let limits = Arc::new(HostDispatchLimits::new());
        let finish = limits
            .acquire("link.finish", None, Some("default"))
            .await
            .unwrap();

        let cancel = timeout(
            Duration::from_millis(50),
            limits.acquire("link.cancel", None, None),
        )
        .await
        .expect("link.cancel must use the independent control lane")
        .unwrap();

        // A second concurrent finish inside the SAME group is rejected with
        // the wire-contract code instead of queueing (ADR 0001 R3).
        let second_finish = limits
            .acquire("link.finish", None, Some("default"))
            .await
            .err()
            .expect("a second finish in one group must be rejected");
        assert_eq!(second_finish.code, "LINK_IN_PROGRESS");
        assert!(!second_finish.retryable);

        // Another group's lane is untouched by the first group's wait.
        timeout(
            Duration::from_millis(50),
            limits.acquire("link.finish", None, Some("team-b")),
        )
        .await
        .expect("a different group's finish lane must stay free")
        .unwrap();

        drop(cancel);
        drop(finish);
        // Once the first finish drains, its group's lane is free again.
        limits
            .acquire("link.finish", None, Some("default"))
            .await
            .unwrap();
    }

    /// ADR 0005：lane 配额按账号。A 占满自己的 read=4 时，B 的 read 必须
    /// 立刻拿到；旧实现的进程级 read=4 会让 B 无端排在 A 后面。
    #[tokio::test]
    async fn read_lanes_are_per_account_so_a_busy_account_does_not_serialize_another() {
        let limits = Arc::new(HostDispatchLimits::new());
        let mut account_a = Vec::new();
        for _ in 0..READ_CONCURRENCY {
            account_a.push(
                limits
                    .acquire("messages.list", Some("account-a"), None)
                    .await
                    .unwrap(),
            );
        }

        let account_b = timeout(
            Duration::from_secs(1),
            limits.acquire("messages.list", Some("account-b"), None),
        )
        .await
        .expect("account-b's read must not queue behind a full account-a lane")
        .unwrap();

        // A 的四个 permit 仍在手里：A 的第五个读只能等，证明 B 的通行
        // 不是因为 A 恰好释放了配额。
        let fifth_a = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.list", Some("account-a"), None),
        )
        .await;
        assert!(
            fifth_a.is_err(),
            "account-a's fifth read still waits on its own lane"
        );

        drop(account_a.pop());
        timeout(
            Duration::from_secs(1),
            limits.acquire("messages.list", Some("account-a"), None),
        )
        .await
        .expect("account-a's fifth read proceeds once its lane drains one permit")
        .unwrap();
        drop(account_b);
    }

    /// 单账号 read 容量仍是 4：第 5 个请求停在该账号自己的 lane 上，
    /// 不占全局兜底、也不影响别的账号。
    #[tokio::test]
    async fn a_fifth_read_on_one_account_waits_on_that_accounts_lane() {
        let limits = Arc::new(HostDispatchLimits::new());
        let mut held = Vec::new();
        for _ in 0..READ_CONCURRENCY {
            held.push(
                limits
                    .acquire("messages.list", Some("account-a"), None)
                    .await
                    .unwrap(),
            );
        }
        let fifth = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.list", Some("account-a"), None),
        )
        .await;
        assert!(fifth.is_err(), "the fifth read on one account must wait");

        drop(held.pop());
        timeout(
            Duration::from_secs(1),
            limits.acquire("messages.list", Some("account-a"), None),
        )
        .await
        .expect("one freed permit admits the fifth read")
        .unwrap();
    }

    /// 全局兜底 read=16：四个账号各占满 4 个 read 后，第五个账号即使
    /// 自己的 lane 全空，也只能等全局 permit。
    #[tokio::test]
    async fn the_global_read_backstop_bounds_many_accounts_at_sixteen() {
        let limits = Arc::new(HostDispatchLimits::new());
        let mut held = Vec::new();
        for account in ["account-a", "account-b", "account-c", "account-d"] {
            for _ in 0..READ_CONCURRENCY {
                held.push(
                    limits
                        .acquire("messages.list", Some(account), None)
                        .await
                        .unwrap(),
                );
            }
        }
        assert_eq!(held.len(), GLOBAL_READ_CONCURRENCY);

        let blocked = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.list", Some("account-e"), None),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the 17th read waits on the global backstop even with a free account lane"
        );

        drop(held.pop());
        timeout(
            Duration::from_secs(1),
            limits.acquire("messages.list", Some("account-e"), None),
        )
        .await
        .expect("a freed global permit admits the waiting account")
        .unwrap();
    }

    /// control 仍是每账号 1：同账号第二个 control 等待，不同账号各自可跑。
    #[tokio::test]
    async fn control_is_one_per_account_and_independent_across_accounts() {
        let limits = Arc::new(HostDispatchLimits::new());
        let account_a = limits
            .acquire("runtime.status", Some("account-a"), None)
            .await
            .unwrap();

        let second_a = timeout(
            Duration::from_millis(50),
            limits.acquire("runtime.status", Some("account-a"), None),
        )
        .await;
        assert!(
            second_a.is_err(),
            "the second control request on one account waits"
        );

        let account_b = timeout(
            Duration::from_secs(1),
            limits.acquire("runtime.status", Some("account-b"), None),
        )
        .await
        .expect("another account's control lane is free")
        .unwrap();

        drop(account_a);
        timeout(
            Duration::from_secs(1),
            limits.acquire("runtime.status", Some("account-a"), None),
        )
        .await
        .expect("the same-account control lane frees up after the permit drops")
        .unwrap();
        drop(account_b);
    }

    /// per-account lane 加入后，mutating 同账号仍严格串行：send lane 每账号
    /// 有 2 个、全局 8 个，第二个同账号 sendText 之所以等待，只可能是
    /// 账号互斥锁仍先于配额获取（既有 drain barrier 不回归）。
    #[tokio::test]
    async fn per_account_lanes_keep_same_account_mutations_serialized() {
        let limits = Arc::new(HostDispatchLimits::new());
        let send = limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .unwrap();

        let second = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.sendText", Some("account-a"), None),
        )
        .await;
        assert!(
            second.is_err(),
            "same-account mutations stay strictly serialized"
        );

        let other = timeout(
            Duration::from_secs(1),
            limits.acquire("messages.sendText", Some("account-b"), None),
        )
        .await
        .expect("another account's mutation is unaffected")
        .unwrap();

        drop(send);
        timeout(
            Duration::from_secs(1),
            limits.acquire("messages.sendText", Some("account-a"), None),
        )
        .await
        .expect("the next same-account mutation proceeds after the drain")
        .unwrap();
        drop(other);
    }

    /// 无账号上下文的任务落 unscoped 共享桶（per-lane），彼此排队；同时
    /// 它们仍受全局兜底约束——unscoped 桶空着也必须等全局 permit。
    #[tokio::test]
    async fn unscoped_requests_share_one_bucket_and_respect_the_global_backstop() {
        let limits = Arc::new(HostDispatchLimits::new());
        let first = limits.acquire("accounts.list", None, None).await.unwrap();
        let second = timeout(
            Duration::from_millis(50),
            limits.acquire("accounts.list", None, None),
        )
        .await;
        assert!(
            second.is_err(),
            "unscoped control requests share one bucket"
        );
        drop(first);
        let second = timeout(
            Duration::from_secs(1),
            limits.acquire("accounts.list", None, None),
        )
        .await
        .expect("the unscoped control lane frees up")
        .unwrap();
        drop(second);

        // 全局 read 兜底被四个账号占满；unscoped read 的桶是空的，唯一
        // 的等待原因只能是全局 permit。
        let mut held = Vec::new();
        for account in ["account-a", "account-b", "account-c", "account-d"] {
            for _ in 0..READ_CONCURRENCY {
                held.push(
                    limits
                        .acquire("messages.list", Some(account), None)
                        .await
                        .unwrap(),
                );
            }
        }
        let blocked = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.list", None, None),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the unscoped read still respects the global read backstop"
        );
        drop(held.pop());
        timeout(
            Duration::from_secs(1),
            limits.acquire("messages.list", None, None),
        )
        .await
        .expect("a freed global permit admits the unscoped read")
        .unwrap();
    }

    /// The account delete drain barrier: a delete marks the account, then waits
    /// for the in-flight send holding the per-account mutex; sends/syncs that
    /// arrive during the delete are rejected instead of queueing; once the
    /// delete dispatch ends, the mark is gone. Linearization point is the
    /// per-account mutex: a send either completes fully before the delete's
    /// upstream call, or it never reaches the upstream at all.
    #[tokio::test]
    async fn account_delete_drains_in_flight_send_and_rejects_new_mutations() {
        let limits = Arc::new(HostDispatchLimits::new());
        let send = limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .unwrap();

        // Spawn the delete: it marks the account immediately, then parks on
        // the account mutex while the send is still in flight.
        let delete_task = {
            let limits = Arc::clone(&limits);
            tokio::spawn(async move {
                limits
                    .acquire("accounts.deleteLocalData", Some("account-a"), None)
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !delete_task.is_finished(),
            "delete must wait for the in-flight send to drain"
        );
        assert!(
            limits
                .deleting_accounts
                .lock()
                .unwrap()
                .contains_key("account-a"),
            "delete marks the account before waiting for the drain"
        );

        // New mutating work for the deleting account is rejected, not queued.
        let rejected_send = limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .err()
            .expect("acquire must reject mutating work on a deleting account");
        assert_eq!(rejected_send.code, "ACCOUNT_NOT_FOUND");
        assert!(!rejected_send.retryable);
        let rejected_sync = limits
            .acquire("contacts.sync", Some("account-a"), None)
            .await
            .err()
            .expect("acquire must reject mutating work on a deleting account");
        assert_eq!(rejected_sync.code, "ACCOUNT_NOT_FOUND");

        // Other accounts and read-only methods are unaffected.
        limits
            .acquire("messages.sendText", Some("account-b"), None)
            .await
            .unwrap();
        limits
            .acquire("messages.list", Some("account-a"), None)
            .await
            .unwrap();

        // New mutating work covers remoteDelete too: rejected while the
        // delete drains, same-account serialized against sendText.
        let rejected_delete = limits
            .acquire("messages.remoteDelete", Some("account-a"), None)
            .await
            .err()
            .expect("acquire must reject mutating work on a deleting account");
        assert_eq!(rejected_delete.code, "ACCOUNT_NOT_FOUND");
        assert!(!rejected_delete.retryable);

        // Once the send drains, the delete proceeds; while it runs the mark
        // stays, and once the dispatch permit drops the mark is cleared so a
        // later send is admitted again (it then fails at preparation if the
        // account row is really gone).
        drop(send);
        let delete = timeout(Duration::from_secs(1), delete_task)
            .await
            .expect("delete must proceed once the send drained")
            .unwrap()
            .unwrap();
        let still_rejected = limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .err()
            .expect("acquire must reject mutating work on a deleting account");
        assert_eq!(still_rejected.code, "ACCOUNT_NOT_FOUND");
        drop(delete);
        assert!(
            limits.deleting_accounts.lock().unwrap().is_empty(),
            "a finished delete clears the mark"
        );
        limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .unwrap();
    }

    /// Overlapping deletes of the same account serialize on the account mutex,
    /// a delete whose wait is cancelled (timeout/dropped future) does not leave
    /// a stale mark, and an active delete keeps rejecting sends until it ends.
    #[tokio::test]
    async fn overlapping_deletes_keep_the_mark_until_the_last_one_finishes() {
        let limits = Arc::new(HostDispatchLimits::new());
        let first = limits
            .acquire("accounts.deleteLocalData", Some("account-a"), None)
            .await
            .unwrap();
        // A second delete marks too, then waits on the account mutex; when its
        // wait is cancelled, its mark is rolled back with the dropped future.
        let second_pending = timeout(
            Duration::from_millis(20),
            limits.acquire("accounts.deleteLocalData", Some("account-a"), None),
        )
        .await;
        assert!(second_pending.is_err());
        drop(first);
        assert!(
            limits.deleting_accounts.lock().unwrap().is_empty(),
            "a cancelled delete wait must not leave a stale mark"
        );

        let second = limits
            .acquire("accounts.deleteLocalData", Some("account-a"), None)
            .await
            .unwrap();
        let rejected = limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .err()
            .expect("acquire must reject mutating work on a deleting account");
        assert_eq!(rejected.code, "ACCOUNT_NOT_FOUND");
        drop(second);
        limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .unwrap();
    }

    /// remoteDelete and sendReaction are mutating, account-scoped methods:
    /// they share the send lane and the per-account mutex with sendText, so
    /// two same-account mutations can never interleave
    /// (docs/remote-delete-l2-plan.md §3.4).
    #[tokio::test]
    async fn remote_delete_and_send_text_serialize_per_account() {
        let limits = Arc::new(HostDispatchLimits::new());
        let send = limits
            .acquire("messages.sendText", Some("account-a"), None)
            .await
            .unwrap();

        // The second same-account mutation parks on the account mutex instead
        // of running concurrently (and not on lane capacity: the send lane
        // still has a free permit).
        let pending_delete = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.remoteDelete", Some("account-a"), None),
        )
        .await;
        assert!(
            pending_delete.is_err(),
            "remoteDelete must wait for the in-flight same-account send"
        );

        // A different account's remoteDelete is unaffected.
        timeout(
            Duration::from_millis(50),
            limits.acquire("messages.remoteDelete", Some("account-b"), None),
        )
        .await
        .expect("another account's remoteDelete must not serialize behind account-a")
        .unwrap();

        // sendReaction joins the same mutating set: same-account serialized,
        // other-account unaffected.
        let pending_reaction = timeout(
            Duration::from_millis(50),
            limits.acquire("messages.sendReaction", Some("account-a"), None),
        )
        .await;
        assert!(
            pending_reaction.is_err(),
            "sendReaction must wait for the in-flight same-account send"
        );
        timeout(
            Duration::from_millis(50),
            limits.acquire("messages.sendReaction", Some("account-c"), None),
        )
        .await
        .expect("another account's sendReaction must not serialize behind account-a")
        .unwrap();

        // contacts.setLocalAlias joins the same mutating set (contract
        // revision 1.10): same-account serialized against the send, and it
        // rides the send lane rather than the control lane.
        let pending_alias = timeout(
            Duration::from_millis(50),
            limits.acquire("contacts.setLocalAlias", Some("account-a"), None),
        )
        .await;
        assert!(
            pending_alias.is_err(),
            "setLocalAlias must wait for the in-flight same-account send"
        );
        timeout(
            Duration::from_millis(50),
            limits.acquire("contacts.setLocalAlias", Some("account-c"), None),
        )
        .await
        .expect("another account's setLocalAlias must not serialize behind account-a")
        .unwrap();

        drop(send);
        timeout(
            Duration::from_secs(1),
            limits.acquire("messages.remoteDelete", Some("account-a"), None),
        )
        .await
        .expect("remoteDelete must proceed once the send drained")
        .unwrap();
    }

    #[tokio::test]
    async fn authenticated_session_can_query_status_and_rejects_replayed_id() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        let secret_bytes = [7_u8; 32];
        let secret = Arc::new(BootstrapSecret::for_test(secret_bytes));
        let runtime = test_runtime();
        let (server_stream, client_stream) = duplex(64 * 1024);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());

        let challenge: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
        let client_nonce = hex::encode([9_u8; 32]);
        let proof = client_proof(&secret_bytes, server_nonce, &client_nonce);
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
        let handshake: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(handshake["requestId"], "handshake-1");
        assert_eq!(handshake["result"]["apiVersion"], API_VERSION);
        assert!(
            handshake["result"]["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "messages.sendText")
        );
        // Contract revision 1.98: this default runtime carries no armed
        // media table, so the attachment-download tag stays absent — the
        // desktop takes the honest metadata-only path instead of calling a
        // face that answers CAPABILITY_UNAVAILABLE for every download.
        assert!(
            !handshake["result"]["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "attachment-download"),
            "an unarmed runtime must not advertise attachment-download"
        );

        client
            .send(
                json!({
                    "apiVersion": API_VERSION,
                    "requestId": "handshake-1",
                    "method": "runtime.status",
                    "params": {}
                })
                .to_string(),
            )
            .await
            .unwrap();
        let handshake_replay: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(handshake_replay["error"]["code"], "INVALID_REQUEST");

        let status_request = json!({
            "apiVersion": API_VERSION,
            "requestId": "status-1",
            "method": "runtime.status",
            "params": {}
        })
        .to_string();
        client.send(status_request.clone()).await.unwrap();
        let status: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(status["result"]["state"], "stopped");

        client.send(status_request).await.unwrap();
        let replay: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(replay["error"]["code"], "INVALID_REQUEST");

        drop(client);
        assert!(server.await.unwrap().is_ok());
    }

    /// The handshake round trip with the advertised `capabilities` returned —
    /// the attachment-download gate test runs it against two runtimes.
    async fn handshake_capabilities(
        secret_bytes: [u8; 32],
        runtime: Arc<ProxyGroupRuntime>,
    ) -> Vec<String> {
        let secret = Arc::new(BootstrapSecret::for_test(secret_bytes));
        let (server_stream, client_stream) = duplex(64 * 1024);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());
        let challenge: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
        let client_nonce = hex::encode([9_u8; 32]);
        let proof = client_proof(&secret_bytes, server_nonce, &client_nonce);
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
        let handshake: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let capabilities = handshake["result"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().expect("capability tag").to_string())
            .collect();
        drop(client);
        assert!(server.await.unwrap().is_ok());
        capabilities
    }

    /// Contract revision 1.98: `attachment-download` is the one handshake
    /// tag the runtime state gates. The unarmed default runtime — the
    /// packaged shape: no `--media-ingest` (the launcher decision is the
    /// whole decision, the §4.102 pass-through) — omits the tag while every
    /// real method stays advertised; a runtime assembled with the armed media
    /// table (the exact gate the media methods answer) advertises the
    /// pre-1.98 payload unchanged.
    #[tokio::test]
    async fn handshake_gates_the_attachment_download_tag_on_media_ingest() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        let unarmed = handshake_capabilities([7_u8; 32], test_runtime()).await;
        assert!(
            !unarmed
                .iter()
                .any(|capability| capability == "attachment-download"),
            "an unarmed runtime must not advertise attachment-download"
        );
        assert!(
            unarmed
                .iter()
                .any(|capability| capability == "messages.sendText"),
            "the method table stays advertised either way"
        );

        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = Store::open(temp.path(), Some(StoreKey::from_bytes([0x5A; 32]))).unwrap();
        // Leak TempDir for unit test lifetime; path stays valid for process.
        std::mem::forget(temp);
        let mut config = EngineConfig::new(
            PathBuf::from("unused-engine"),
            PathBuf::from("/tmp/unused-signal-data"),
        );
        config.media_ingest = true;
        let armed_supervisor = Arc::new(RuntimeSupervisor::new(
            config,
            Arc::new(store),
            crate::DEFAULT_PROXY_GROUP_ID.to_string(),
            Some(Arc::new(crate::media::MediaHandleTable::new())),
        ));
        let armed_runtime = ProxyGroupRuntime::new(vec![crate::registry::ProxyGroupSlot::new(
            crate::DEFAULT_PROXY_GROUP_ID.to_string(),
            armed_supervisor,
        )]);
        let armed = handshake_capabilities([8_u8; 32], armed_runtime).await;
        assert!(
            armed
                .iter()
                .any(|capability| capability == "attachment-download"),
            "an armed runtime advertises attachment-download"
        );
    }

    /// The host frame limit carries the attachment contract (revision 1.13):
    /// a request above the pre-1.13 1 MiB limit (a ~5 MiB attachment base64
    /// payload arrives on this line) is accepted, and a frame beyond the
    /// 16 MiB codec limit ends the session instead of being parsed.
    #[tokio::test]
    async fn host_frame_limit_admits_attachment_sized_frames_and_rejects_beyond_it() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        let secret_bytes = [7_u8; 32];
        let secret = Arc::new(BootstrapSecret::for_test(secret_bytes));
        let runtime = test_runtime();
        // The duplex buffer holds the largest single write the client makes;
        // the ~2.2 MiB handshake-free line below fits alongside the challenge.
        let (server_stream, client_stream) = duplex(4 * 1024 * 1024);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());

        let challenge: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
        let client_nonce = hex::encode([9_u8; 32]);
        let proof = client_proof(&secret_bytes, server_nonce, &client_nonce);
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
        let handshake: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(handshake["result"]["apiVersion"], API_VERSION);

        // A frame far beyond the old 1 MiB limit is parsed and answered (the
        // method is real, so the answer is a normal response, not a protocol
        // error): ~2.2 MiB of attachment base64 plus envelope overhead.
        let payload = "QUJD".repeat(560_000); // 2_240_000 chars
        let oversized_request = json!({
            "apiVersion": API_VERSION,
            "requestId": "attach-frame-1",
            "method": "messages.attachments.send",
            "params": {
                "accountId": "a",
                "clientRequestId": "cr-1",
                "dataBase64": payload,
                "sizeBytes": 5
            }
        });
        let frame = oversized_request.to_string();
        assert!(frame.len() > 1024 * 1024);
        client.send(frame).await.unwrap();
        let response: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(response["requestId"], "attach-frame-1");
        assert!(
            response.get("result").is_some() || response.get("error").is_some(),
            "a beyond-1MiB frame must be answered, not dropped"
        );

        // A frame beyond the 16 MiB codec limit breaks the session: either the
        // send itself fails (the connector dropped the socket mid-frame) or
        // the reply stream simply ends — in both cases no further valid frame
        // can be exchanged on this connection.
        let huge = "A".repeat(DEFAULT_HOST_FRAME_LIMIT + 1024);
        let _ = client.send(huge).await;
        let ended = matches!(client.next().await, None | Some(Err(_)));
        assert!(ended, "a beyond-limit frame must terminate the session");
        let _ = server.await.expect("server task must not panic");
    }

    #[tokio::test]
    async fn a_host_that_leaves_right_after_authenticating_still_ends_cleanly() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        let secret_bytes = [7_u8; 32];
        let secret = Arc::new(BootstrapSecret::for_test(secret_bytes));
        let runtime = test_runtime();
        let (server_stream, client_stream) = duplex(64 * 1024);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());
        let challenge: Value =
            serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        let server_nonce = challenge["data"]["serverNonce"].as_str().unwrap();
        let client_nonce = hex::encode([9_u8; 32]);
        let proof = client_proof(&secret_bytes, server_nonce, &client_nonce);
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

        // Leave without collecting the handshake reply, so the write that
        // reports success is the one that finds the peer gone. This is a session
        // that ended, not a protocol failure, and the process must exit cleanly.
        drop(client);

        assert!(
            server.await.unwrap().is_ok(),
            "a host that vanished must not fail the process"
        );
    }

    #[tokio::test]
    async fn failed_authentication_returns_generic_error_and_closes() {
        let _host_session = HOST_SESSION_TEST_LOCK.lock().await;
        let secret = Arc::new(BootstrapSecret::for_test([7_u8; 32]));
        let runtime = test_runtime();
        let (server_stream, client_stream) = duplex(64 * 1024);
        let server = tokio::spawn(handle_connection(server_stream, secret, runtime));
        let mut client = Framed::new(client_stream, LinesCodec::new());
        let _challenge = client.next().await.unwrap().unwrap();
        client
            .send(
                json!({
                    "apiVersion": API_VERSION,
                    "requestId": "handshake-1",
                    "method": "handshake",
                    "params": {
                        "clientNonce": hex::encode([9_u8; 32])
                    }
                })
                .to_string(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_str(&client.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(response["error"]["code"], "AUTHENTICATION_FAILED");
        assert!(matches!(
            server.await.unwrap(),
            Err(HostError::Authentication)
        ));
    }

    fn client_proof(secret: &[u8; 32], server_nonce: &str, client_nonce: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(b"kt-signal-connector-v1\0");
        mac.update(server_nonce.as_bytes());
        mac.update(b"\0");
        mac.update(client_nonce.as_bytes());
        mac.update(b"\0");
        mac.update(API_VERSION.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// 契约 1.263/1.264（§4.247/§4.248）：callKind 加性可选词——缺席键不在，\n    /// pre-1.263 宿主读字节同形；群 era 更新事件三键逐字上 wire。\n    #[test]\n    fn call_events_encode_the_additive_faces() {\n        let frame: Value = serde_json::to_value(\n            host_event_frame(HostSideEvent::CallIncoming {\n                account_id: "acct-1".into(),\n                conversation_id: "conv-1".into(),\n                call_id: 7,\n                signal_type: "offer",\n                payload: json!({ "offer": { "id": 7, "type": "video" } }),\n                call_kind: Some("video"),\n            })\n            .unwrap(),\n        )\n        .unwrap();\n        assert_eq!(frame["event"], "call.incoming");\n        assert_eq!(frame["data"]["callKind"], "video");\n        assert_eq!(frame["data"]["type"], "offer");\n\n        let frame: Value = serde_json::to_value(\n            host_event_frame(HostSideEvent::CallIncoming {\n                account_id: "acct-1".into(),\n                conversation_id: "conv-1".into(),\n                call_id: 0,\n                signal_type: "opaque",\n                payload: json!({ "opaque": "c2Rw", "urgency": "droppable" }),\n                call_kind: None,\n            })\n            .unwrap(),\n        )\n        .unwrap();\n        assert!(\n            frame["data"].get("callKind").is_none(),\n            "absent kind stays a absent key, never null"\n        );\n\n        let frame: Value = serde_json::to_value(\n            host_event_frame(HostSideEvent::CallGroupCallUpdate {\n                account_id: "acct-1".into(),\n                conversation_id: "conv-1".into(),\n                era_id: "era-1".into(),\n            })\n            .unwrap(),\n        )\n        .unwrap();\n        assert_eq!(frame["event"], "call.groupCallUpdate");\n        assert_eq!(frame["data"]["eraId"], "era-1");\n        assert_eq!(frame["data"]["conversationId"], "conv-1");\n    }\n    /// The `story.received` wire frame (contract 1.91, §4.74): the story
    /// object rides the event payload verbatim — the engine-projected
    /// `textAttachment.preview.url`/`.title` reach the desktop byte-for-byte
    /// (and a key the contract never named rides the same way), while the
    /// absent-optional identity discipline keeps masked sources absent.
    #[tokio::test]
    async fn story_received_event_rides_the_story_projection_verbatim() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::StoryReceived {
                account_id: "acct-1".into(),
                sender: Some("+15555550101".into()),
                sender_aci: Some("22222222-2222-2222-2222-222222222222".into()),
                sender_name: None,
                timestamp: Some(1727000002000u64),
                story: json!({
                "textAttachment": {
                "text": "story body",
                "preview": {
                "url": "https://example.com/a",
                "title": "Example",
                "someLaterKey": {"rides": true},
                },
                },
                "allowsReplies": true,
                }),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "story.received");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        let story = &frame["data"]["story"];
        assert_eq!(
            story["textAttachment"]["preview"]["url"],
            json!("https://example.com/a")
        );
        assert_eq!(
            story["textAttachment"]["preview"]["title"],
            json!("Example")
        );
        assert_eq!(
            story["textAttachment"]["preview"]["someLaterKey"],
            json!({ "rides": true })
        );
        // The absent-optional discipline: a missing identity stays absent.
        assert!(frame["data"].get("senderName").is_none());
        assert_eq!(frame["data"]["timestamp"], 1727000002000u64);
    }

    /// Contract 1.190 (§4.190 ⑤): the per-recipient ledger event frame —
    /// `message.receiptsChanged` carrying the message's whole ledger with
    /// absent tiers absent (first stamps only), the empty array always
    /// serialized so a host merge never keeps stale rows.
    #[tokio::test]
    async fn receipts_changed_event_carries_the_ledger_face() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageReceiptsChanged {
                account_id: "acct-1".into(),
                message_id: "msg-1".into(),
                receipts: vec![
                    crate::store::RecipientReceiptRow {
                        recipient: "+15555550101".into(),
                        sent_at: Some(1000),
                        failed_at: None,
                        delivered_at: Some(2000),
                        read_at: None,
                        viewed_at: None,
                    },
                    crate::store::RecipientReceiptRow {
                        recipient: "+15555550102".into(),
                        sent_at: None,
                        failed_at: Some(1500),
                        delivered_at: None,
                        read_at: None,
                        viewed_at: None,
                    },
                ],
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "message.receiptsChanged");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["messageId"], "msg-1");
        let receipts = frame["data"]["receipts"].as_array().unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0]["recipient"], "+15555550101");
        assert_eq!(receipts[0]["sentAt"], 1000);
        assert_eq!(receipts[0]["deliveredAt"], 2000);
        assert!(
            receipts[0].get("readAt").is_none(),
            "absent tiers stay absent"
        );
        assert!(receipts[0].get("failedAt").is_none());
        assert_eq!(receipts[1]["recipient"], "+15555550102");
        assert_eq!(receipts[1]["failedAt"], 1500);
        assert!(receipts[1].get("sentAt").is_none());

        // The empty ledger still serializes the array (a total merge face).
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageReceiptsChanged {
                account_id: "acct-1".into(),
                message_id: "msg-2".into(),
                receipts: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["data"]["receipts"], json!([]));
    }

    /// Contract 1.192 (§4.192): the backfill error answer frame —
    /// `message.attachmentBackfillError` names the resolved row trio plus
    /// the bounded error word verbatim, the wire face the desktop's
    /// NotFound modal mapping consumes.
    #[tokio::test]
    async fn attachment_backfill_error_event_names_the_row() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageAttachmentBackfillError {
                account_id: "acct-1".into(),
                conversation_id: "conv-1".into(),
                message_id: "msg-1".into(),
                error: "MESSAGE_NOT_FOUND".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "message.attachmentBackfillError");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["conversationId"], "conv-1");
        assert_eq!(frame["data"]["messageId"], "msg-1");
        assert_eq!(frame["data"]["error"], "MESSAGE_NOT_FOUND");
    }

    /// Contract 1.193 (§4.193): the backfill settle frame —
    /// `message.attachmentBackfillSettled` carries the resolved row trio
    /// plus the index-aligned per-attachment face verbatim (index ascending,
    /// the three official status words). The empty list still serializes
    /// (the official `pendingCount === 0` cancel face), so a desktop merge
    /// is total. Contract 1.195 (§4.195): a pointer or absent longText keeps
    /// both optional state keys absent — the pre-1.195 frame byte-for-byte.
    #[tokio::test]
    async fn attachment_backfill_settled_event_names_every_attachment() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageAttachmentBackfillSettled {
                account_id: "acct-1".into(),
                conversation_id: "conv-1".into(),
                message_id: "msg-1".into(),
                attachments: vec![
                    AttachmentBackfillSettledEntry {
                        index: 0,
                        status: "available",
                    },
                    AttachmentBackfillSettledEntry {
                        index: 1,
                        status: "pending",
                    },
                    AttachmentBackfillSettledEntry {
                        index: 2,
                        status: "terminal",
                    },
                ],
                long_text_pending: false,
                long_text_terminal: false,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "message.attachmentBackfillSettled");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["conversationId"], "conv-1");
        assert_eq!(frame["data"]["messageId"], "msg-1");
        assert_eq!(
            frame["data"]["attachments"],
            json!([
                { "index": 0, "status": "available" },
                { "index": 1, "status": "pending" },
                { "index": 2, "status": "terminal" },
            ])
        );
        assert!(
            frame["data"].get("longTextPending").is_none()
                && frame["data"].get("longTextTerminal").is_none(),
            "no longText state means no keys: {frame}"
        );

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageAttachmentBackfillSettled {
                account_id: "acct-1".into(),
                conversation_id: "conv-1".into(),
                message_id: "msg-2".into(),
                attachments: Vec::new(),
                long_text_pending: false,
                long_text_terminal: false,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["data"]["attachments"], json!([]));
        assert!(
            frame["data"].get("longTextPending").is_none()
                && frame["data"].get("longTextTerminal").is_none(),
            "the empty attach list alone stays key-free: {frame}"
        );
    }

    #[tokio::test]
    async fn connection_state_frame_stays_on_connection_axis() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::ConnectionStateChanged {
                account_id: "acct-1".into(),
                state: "invalidated".into(),
                close_code: Some(4401),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "connection.stateChanged");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["state"], "invalidated");
        assert_eq!(frame["data"]["closeCode"], 4401);
    }

    /// Contract 1.195 (§4.195): the official `response.longText` state rides
    /// two optional booleans on the settled frame — `longTextPending` for
    /// `Status.PENDING` (attachmentBackfill.preload.ts:257-259; the official
    /// `pendingCount` keeps the timer armed, :191, :324-327) and
    /// `longTextTerminal` for `Status.TERMINAL_ERROR` (:260-267). The
    /// assertion is the whole frame verbatim: one key at a time, no other
    /// payload change, and an empty attachment list still rides (KT has no
    /// body-attachment slot).
    #[tokio::test]
    async fn attachment_backfill_settled_frame_reports_long_text_state() {
        let pending: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageAttachmentBackfillSettled {
                account_id: "acct-1".into(),
                conversation_id: "conv-1".into(),
                message_id: "msg-1".into(),
                attachments: Vec::new(),
                long_text_pending: true,
                long_text_terminal: false,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            pending,
            json!({
                "apiVersion": "1.0",
                "event": "message.attachmentBackfillSettled",
                "data": {
                    "accountId": "acct-1",
                    "conversationId": "conv-1",
                    "messageId": "msg-1",
                    "attachments": [],
                    "longTextPending": true,
                },
            })
        );

        let terminal: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::MessageAttachmentBackfillSettled {
                account_id: "acct-1".into(),
                conversation_id: "conv-1".into(),
                message_id: "msg-2".into(),
                attachments: Vec::new(),
                long_text_pending: false,
                long_text_terminal: true,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            terminal,
            json!({
                "apiVersion": "1.0",
                "event": "message.attachmentBackfillSettled",
                "data": {
                    "accountId": "acct-1",
                    "conversationId": "conv-1",
                    "messageId": "msg-2",
                    "attachments": [],
                    "longTextTerminal": true,
                },
            })
        );
    }

    /// Contract 1.134 (§4.117; the storage-pull face joins with 1.141,
    /// §4.137; the decryption-error face with 1.165, §4.163): the
    /// engine-notification wire frames — the two envelope-key projections
    /// with their absent-optional identities, and the account-domain lane's
    /// standalone notifications with the conversations array verbatim (no
    /// reshape, no trim, the overflow marker beside it).
    #[tokio::test]
    async fn engine_notification_events_ride_their_contract_frames() {
        let read_frame =
            |event: HostSideEvent| serde_json::to_value(host_event_frame(event).unwrap()).unwrap();

        let frame = read_frame(HostSideEvent::GroupTerminated {
            account_id: "acct-1".into(),
            group_id: "ZmFrZS1ncm91cC0x".into(),
            terminator: Some("33333333-3333-3333-3333-333333333333".into()),
            timestamp: Some(1726999999000),
        });
        assert_eq!(frame["event"], "group.terminated");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["groupId"], "ZmFrZS1ncm91cC0x");
        assert_eq!(
            frame["data"]["terminator"],
            "33333333-3333-3333-3333-333333333333"
        );
        assert_eq!(frame["data"]["timestamp"], 1726999999000u64);

        let frame = read_frame(HostSideEvent::GroupTerminated {
            account_id: "acct-1".into(),
            group_id: "ZmFrZS1ncm91cC0x".into(),
            terminator: None,
            timestamp: None,
        });
        assert!(
            frame["data"].get("terminator").is_none() && frame["data"].get("timestamp").is_none(),
            "absent optional identities stay absent: {frame}"
        );

        let frame = read_frame(HostSideEvent::ContactProfileUpdated {
            account_id: "acct-1".into(),
            aci: "22222222-2222-2222-2222-222222222222".into(),
            timestamp: None,
        });
        assert_eq!(frame["event"], "contact.profileUpdated");
        assert_eq!(frame["data"]["aci"], "22222222-2222-2222-2222-222222222222");
        assert!(frame["data"].get("timestamp").is_none());

        let frame = read_frame(HostSideEvent::ReceiveEmptied {
            account_id: "acct-1".into(),
        });
        assert_eq!(frame["event"], "receive.emptied");
        assert_eq!(frame["data"]["accountId"], "acct-1");

        let frame = read_frame(HostSideEvent::ClockSkewObserved {
            account_id: "acct-1".into(),
            skew_ms: -86_400_001,
            server_timestamp: Some(1727000000000),
        });
        assert_eq!(frame["event"], "receive.clockSkew");
        assert_eq!(frame["data"]["skewMs"], -86_400_001);
        assert_eq!(frame["data"]["serverTimestamp"], 1727000000000u64);

        let conversations = json!([
            {
                "conversationId": "11111111-1111-1111-1111-111111111111",
                "kind": "contact",
                "mutedUntilTimestamp": 1727000000000u64,
                "archived": true,
                "markedUnread": false,
                "unnamedSibling": { "rides": true },
            },
        ]);
        let frame = read_frame(HostSideEvent::ConversationStateChanged {
            account_id: "acct-1".into(),
            conversations: conversations.clone(),
            overflow: true,
        });
        assert_eq!(frame["event"], "conversation.stateChanged");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["conversations"], conversations, "verbatim");
        assert_eq!(frame["data"]["overflow"], true);

        // Contract 1.141 (§4.137): the storage-pull outcome frame — the
        // trigger word rides verbatim (an unseen engine word stays itself)
        // beside the two per-family legs.
        let frame = read_frame(HostSideEvent::StoragePull {
            account_id: "acct-1".into(),
            trigger: "fetchLatest".into(),
            contacts_ok: true,
            groups_ok: false,
        });
        assert_eq!(frame["event"], "engine.storagePull");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["trigger"], "fetchLatest");
        assert_eq!(frame["data"]["contactsOk"], true);
        assert_eq!(frame["data"]["groupsOk"], false);

        let frame = read_frame(HostSideEvent::StoragePull {
            account_id: "acct-1".into(),
            trigger: "someFutureEngineTrigger".into(),
            contacts_ok: false,
            groups_ok: true,
        });
        assert_eq!(
            frame["data"]["trigger"], "someFutureEngineTrigger",
            "an unseen trigger forwards verbatim: {frame}"
        );

        // Contract 1.220 (§4.230): the link-window post-registration sync
        // completion frame — the two per-leg bits ride verbatim (a false leg
        // is never folded into a done bit).
        let frame = read_frame(HostSideEvent::InitialSyncComplete {
            account_id: "acct-1".into(),
            manifest_ok: true,
            profiles_ok: false,
        });
        assert_eq!(frame["event"], "engine.initialSyncComplete");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["manifestOk"], true);
        assert_eq!(frame["data"]["profilesOk"], false);

        // Contract 1.165 (§4.163): the decryption-error frame — the fact
        // alone (the receive.emptied posture), observability only.
        let frame = read_frame(HostSideEvent::ReceiveDecryptionError {
            account_id: "acct-1".into(),
        });
        assert_eq!(frame["event"], "receive.decryptionError");
        assert_eq!(frame["data"]["accountId"], "acct-1");
    }

    /// Contract 1.100 (§4.81 D3): the `group.changed` wire frame — the
    /// change batch rides verbatim and the absent-optional keys stay
    /// absent.
    #[tokio::test]
    async fn group_changed_event_rides_the_batch_verbatim() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::GroupChanged {
                account_id: "acct-1".into(),
                conversation_id: "conv-1".into(),
                revision: 10,
                changes: json!([
                { "type": "title", "newTitle": "renamed" },
                { "type": "group-link-reset" },
                ]),
                editor: None,
                expire_timer_seconds: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "group.changed");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["conversationId"], "conv-1");
        assert_eq!(frame["data"]["revision"], 10);
        assert_eq!(
            frame["data"]["changes"],
            json!([
                { "type": "title", "newTitle": "renamed" },
                { "type": "group-link-reset" },
            ])
        );
        // The absent-optional discipline: no editor, no timer leg.
        assert!(frame["data"].get("editor").is_none());
        assert!(frame["data"].get("expireTimerSeconds").is_none());
    }

    /// Contract 1.102 (§4.83): the `message.deleteForMe` wire frame — the
    /// groups ride with the absent-optional discipline: a resolved group
    /// carries its `conversationId`, an unmatched entry stays
    /// `messageId`-less, an unresolved group stays conversation-less.
    #[tokio::test]
    async fn delete_for_me_event_rides_the_resolved_groups() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::SyncDeleteForMe {
                account_id: "acct-1".into(),
                deletes: vec![
                    crate::service::SyncDeleteForMeGroup {
                        conversation_id: Some("conv-1".into()),
                        messages: vec![
                            crate::service::SyncDeleteForMeEntry {
                                author: "22222222-2222-2222-2222-222222222222".into(),
                                timestamp: 1726999999000,
                                message_id: Some("msg-1".into()),
                            },
                            crate::service::SyncDeleteForMeEntry {
                                author: "+15555550101".into(),
                                timestamp: 1726999998000,
                                message_id: None,
                            },
                        ],
                    },
                    crate::service::SyncDeleteForMeGroup {
                        conversation_id: None,
                        messages: vec![crate::service::SyncDeleteForMeEntry {
                            author: "33333333-3333-3333-3333-333333333333".into(),
                            timestamp: 1726999997000,
                            message_id: None,
                        }],
                    },
                ],
                conversations: Vec::new(),
                attachments: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "message.deleteForMe");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert!(
            frame["data"].get("conversations").is_none(),
            "the empty arm keeps the 1.102 frame"
        );
        assert!(
            frame["data"].get("attachmentDeletes").is_none(),
            "the empty arm keeps the pre-1.196 frame"
        );
        assert_eq!(frame["data"]["deletes"].as_array().unwrap().len(), 2);
        let first = &frame["data"]["deletes"][0];
        assert_eq!(first["conversationId"], "conv-1");
        assert_eq!(
            first["messages"][0]["author"],
            "22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(first["messages"][0]["timestamp"], 1726999999000u64);
        assert_eq!(first["messages"][0]["messageId"], "msg-1");
        // The absent-optional discipline: an unmatched entry stays
        // messageId-less, an unresolved group stays conversation-less.
        assert!(first["messages"][1].get("messageId").is_none());
        assert!(frame["data"]["deletes"][1].get("conversationId").is_none());
    }

    /// Contract 1.196 (§4.196): the fourth `message.deleteForMe` arm. Each
    /// entry carries the raw one-of legs the projection stated plus the ids
    /// the connector resolved; an unresolved id or an absent leg stays out
    /// (the absent-optional discipline), and an envelope without the arm
    /// keeps the pre-1.196 frame exactly.
    #[tokio::test]
    async fn delete_for_me_event_rides_attachment_deletes() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::SyncDeleteForMe {
                account_id: "acct-1".into(),
                deletes: Vec::new(),
                conversations: Vec::new(),
                attachments: vec![
                    crate::service::SyncDeletedAttachment {
                        conversation_id: Some("conv-1".into()),
                        message_id: Some("msg-1".into()),
                        attachment_id: Some("att-1".into()),
                        client_uuid: Some("11111111-2222-4333-8444-555555555555".into()),
                        fallback_digest: None,
                        fallback_plaintext_hash: None,
                    },
                    crate::service::SyncDeletedAttachment {
                        conversation_id: Some("conv-1".into()),
                        message_id: Some("msg-1".into()),
                        attachment_id: None,
                        client_uuid: None,
                        fallback_digest: Some("ZGlnZXN0".into()),
                        fallback_plaintext_hash: Some("deadbeef".into()),
                    },
                    crate::service::SyncDeletedAttachment {
                        conversation_id: None,
                        message_id: None,
                        attachment_id: None,
                        client_uuid: None,
                        fallback_digest: None,
                        fallback_plaintext_hash: Some("cafebabe".into()),
                    },
                ],
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "message.deleteForMe");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert!(frame["data"].get("conversations").is_none());
        let entries = frame["data"]["attachmentDeletes"]
            .as_array()
            .expect("the fourth arm rides its own key");
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            json!({
                "conversationId": "conv-1",
                "messageId": "msg-1",
                "attachmentId": "att-1",
                "clientUuid": "11111111-2222-4333-8444-555555555555",
            })
        );
        assert_eq!(
            entries[1],
            json!({
                "conversationId": "conv-1",
                "messageId": "msg-1",
                "fallbackDigest": "ZGlnZXN0",
                "fallbackPlaintextHash": "deadbeef",
            })
        );
        assert_eq!(entries[2], json!({ "fallbackPlaintextHash": "cafebabe" }));
    }

    /// Contract 1.103 (§4.84): the `identity.verifiedChanged` wire frame —
    /// the record rides flat with the absent-optional discipline: the
    /// number/key/conversationId keys exist only when the projection carried
    /// them or the destination resolved.
    #[tokio::test]
    async fn verified_changed_event_rides_the_flat_record() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::IdentityVerifiedChanged {
                account_id: "acct-1".into(),
                destination_uuid: "11111111-1111-1111-1111-111111111111".into(),
                state: "verified",
                destination_number: Some("+15555550101".into()),
                identity_key: Some(
                    "05ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12".into(),
                ),
                conversation_id: Some("conv-1".into()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "identity.verifiedChanged");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(
            frame["data"]["destinationUuid"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(frame["data"]["state"], "verified");
        assert_eq!(frame["data"]["destinationNumber"], "+15555550101");
        assert!(frame["data"]["identityKey"].is_string());
        assert_eq!(frame["data"]["conversationId"], "conv-1");

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::IdentityVerifiedChanged {
                account_id: "acct-1".into(),
                destination_uuid: "22222222-2222-2222-2222-222222222222".into(),
                state: "default",
                destination_number: None,
                identity_key: None,
                conversation_id: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["data"]["state"], "default");
        // The absent-optional discipline: an unresolved destination carries
        // none of the three optional keys.
        assert!(frame["data"].get("destinationNumber").is_none());
        assert!(frame["data"].get("identityKey").is_none());
        assert!(frame["data"].get("conversationId").is_none());
    }

    /// Contract 1.104 (§4.85): the `call.historyEvent` wire frame — the
    /// record rides flat with the absent-optional discipline: the word legs
    /// exist only when the projection carried them and an unresolved record
    /// stays conversation-less. Since 1.155 the raw identity leg rides the
    /// same way: `peerId` forwards verbatim beside the ladder's
    /// `conversationId` (both keys coexisting on a hit), and an unprojected
    /// record carries neither — the pre-1.155 shape byte-identically.
    #[tokio::test]
    async fn call_history_event_rides_the_flat_record() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::CallHistoryEvent {
                account_id: "acct-1".into(),
                call_id: "18446744073709551615".into(),
                timestamp: 1726999999000,
                kind: Some("audio"),
                direction: Some("incoming"),
                outcome: Some("accepted"),
                peer_id: Some("deadbeef".into()),
                conversation_id: Some("conv-1".into()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "call.historyEvent");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["callId"], "18446744073709551615");
        assert_eq!(frame["data"]["timestamp"], 1726999999000u64);
        assert_eq!(frame["data"]["type"], "audio");
        assert_eq!(frame["data"]["direction"], "incoming");
        assert_eq!(frame["data"]["event"], "accepted");
        // The raw identity leg rides verbatim beside the ladder's hit.
        assert_eq!(frame["data"]["peerId"], "deadbeef");
        assert_eq!(frame["data"]["conversationId"], "conv-1");

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::CallHistoryEvent {
                account_id: "acct-1".into(),
                call_id: "42".into(),
                timestamp: 1726999998000,
                kind: None,
                direction: None,
                outcome: None,
                peer_id: None,
                conversation_id: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["data"]["callId"], "42");
        // The absent-optional discipline: an unprojected record carries none
        // of the five optional keys — the pre-1.155 shape byte-identically
        // (absence stays absence, never null).
        assert!(frame["data"].get("type").is_none());
        assert!(frame["data"].get("direction").is_none());
        assert!(frame["data"].get("event").is_none());
        assert!(frame["data"].get("peerId").is_none());
        assert!(frame["data"].get("conversationId").is_none());
    }

    /// Contract 1.106 (§4.87): the account-level sync frames ride flat with
    /// the absent-optional discipline — the configuration flags exist only
    /// when the projection carried them, the fetch-latest word likewise, and
    /// the device-name/username/PNI frames carry their facts alone.
    #[tokio::test]
    async fn account_level_sync_events_ride_flat() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::SettingsConfigurationSync {
                account_id: "acct-1".into(),
                read_receipts: None,
                unidentified_delivery_indicators: Some(true),
                typing_indicators: None,
                link_previews: Some(false),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "settings.configurationSync");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["unidentifiedDeliveryIndicators"], true);
        assert_eq!(frame["data"]["linkPreviews"], false);
        assert!(frame["data"].get("readReceipts").is_none());
        assert!(frame["data"].get("typingIndicators").is_none());

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::FetchLatestSync {
                account_id: "acct-1".into(),
                kind: Some("STORAGE_MANIFEST"),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "sync.fetchLatest");
        assert_eq!(frame["data"]["type"], "STORAGE_MANIFEST");

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::FetchLatestSync {
                account_id: "acct-1".into(),
                kind: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "sync.fetchLatest");
        assert!(frame["data"].get("type").is_none());

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::DeviceNameChanged {
                account_id: "acct-1".into(),
                device_id: 3,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "account.deviceNameChanged");
        assert_eq!(frame["data"]["deviceId"], 3);

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::UsernameChanged {
                account_id: "acct-1".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "account.usernameChanged");
        assert_eq!(frame["data"]["accountId"], "acct-1");

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::ContactSyncCompleted {
                account_id: "acct-1".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "contactSync.complete");
        assert_eq!(frame["data"]["accountId"], "acct-1");

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::PniChanged {
                account_id: "acct-1".into(),
                registration_id: Some(2718),
                new_e164: Some("+15555550199".into()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "identity.pniChanged");
        assert_eq!(frame["data"]["registrationId"], 2718);
        assert_eq!(frame["data"]["newE164"], "+15555550199");

        // The parse guarantees at least one PNI key, but the wire discipline
        // is conditional-insert either way: an absent-both face would carry
        // the bare accountId (the schema pins the parse guarantee, not the
        // serializer).
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::PniChanged {
                account_id: "acct-1".into(),
                registration_id: None,
                new_e164: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "identity.pniChanged");
        assert!(frame["data"].get("registrationId").is_none());
        assert!(frame["data"].get("newE164").is_none());
    }

    /// Contract 1.106 (§4.87): the data-plane sync frames ride flat — the
    /// call-link update carries its verb and verbatim material, the call-log
    /// mutation carries its verb, the raw `peerId` and the resolved
    /// `conversationId` beside it.
    #[tokio::test]
    async fn data_plane_sync_events_ride_flat() {
        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::CallLinkUpdate {
                account_id: "acct-1".into(),
                kind: "UPDATE",
                root_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                admin_key: Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".into()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "call.linkUpdate");
        assert_eq!(frame["data"]["accountId"], "acct-1");
        assert_eq!(frame["data"]["type"], "UPDATE");
        assert_eq!(
            frame["data"]["rootKey"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(
            frame["data"]["adminKey"],
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        );

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::CallLogEvent {
                account_id: "acct-1".into(),
                kind: "MARKED_AS_READ",
                timestamp: Some(1726999999000),
                conversation_id: Some("11111111-1111-1111-1111-111111111111".into()),
                call_id: Some(18446744073709551615),
                resolved_conversation_id: Some("conv-1".into()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["event"], "call.logEvent");
        assert_eq!(frame["data"]["type"], "MARKED_AS_READ");
        assert_eq!(frame["data"]["timestamp"], 1726999999000u64);
        assert_eq!(
            frame["data"]["peerId"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(frame["data"]["callId"], u64::MAX);
        assert_eq!(frame["data"]["conversationId"], "conv-1");

        let frame: Value = serde_json::to_value(
            host_event_frame(HostSideEvent::CallLogEvent {
                account_id: "acct-1".into(),
                kind: "CLEAR",
                timestamp: None,
                conversation_id: None,
                call_id: None,
                resolved_conversation_id: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(frame["data"]["type"], "CLEAR");
        // The absent-optional discipline: an unprojected mutation carries
        // only its verb.
        assert!(frame["data"].get("timestamp").is_none());
        assert!(frame["data"].get("peerId").is_none());
        assert!(frame["data"].get("callId").is_none());
        assert!(frame["data"].get("conversationId").is_none());
    }

    /// A start whose every slot is refused by the store gate is terminal:
    /// retrying cannot heal a latched block or an unarmed plaintext store, and
    /// the wire must carry the store code rather than a generic retry.
    #[test]
    fn a_store_blocked_start_is_terminal_and_carries_the_store_code() {
        let api = map_start_failure(StartFailure::StoreMigrationBlocked {
            code: "store_key_rejected".to_string(),
            message: "the encrypted store cannot be opened".to_string(),
        });
        assert_eq!(api.code, "STORE_MIGRATION_BLOCKED");
        assert!(!api.retryable, "a terminal store verdict must not retry");
        assert_eq!(
            api.data
                .as_ref()
                .and_then(|data| data.get("storeMigrationCode")),
            Some(&json!("store_key_rejected"))
        );
        assert_eq!(api.message, "the encrypted store cannot be opened");
    }
}
