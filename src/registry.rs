// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-group runtime facade (ADR 0001 R6-R9): one connector process, one
//! supervised signal-cli engine per launcher-defined proxy group. Sibling
//! connector processes on the same host are legal under the ADR 0002
//! namespace rules — disjoint endpoints and data directories (enforced by
//! the startup occupancy lock in `crate::datalock`) plus a per-instance
//! state-dir store; nothing inside this facade assumes it is the only
//! connector on the machine.
//!
//! The facade owns every [`RuntimeSupervisor`] in launcher configuration order
//! and is the only surface the host protocol talks to. Its responsibilities,
//! pinned by implementation-plan §4.4:
//!
//! - `runtime.*` results carry the pre-Phase-4 top-level aggregate plus the
//!   additive `proxyGroups[]` array. The aggregation rule is fixed: `running`
//!   if any group runs, else `faulted`, else `exited`, else `stopped`;
//!   `rssBytes` sums live samples; pressure ORs across groups; the top-level
//!   `pid` exists only when exactly one group exists — so a single-group
//!   deployment is field-for-field identical to Phase 3.
//! - Account-addressed methods route by the account's stored binding.
//! - Link flows are per group (`LINK_IN_PROGRESS` and restarts never cross
//!   group boundaries); unknown groups fail closed with
//!   `PROXY_GROUP_NOT_FOUND`.
//! - Per-group engine transitions fan out as `proxyGroup.stateChanged` while
//!   `runtime.stateChanged` keeps carrying the aggregate shape unchanged.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use futures_util::future::join_all;
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

use crate::DEFAULT_PROXY_GROUP_ID;
use crate::engine::{EngineConfig, EngineError, EngineEvent, EngineState, EngineStatus};
use crate::groups::{MAX_PROXY_GROUPS, ProxyGroupPlan};
use crate::protocol::ApiError;
use crate::service::{
    ConnectorService, ContactsSyncOutcome, EventsListParams, HostSideEvent, MessageText,
    SendTarget, SendTextMentionParams, SendTextPreviewParams, SendTextStyleParams, ServiceError,
};
use crate::store::{
    AccountDeletePlan, AccountSummary, ContactSummary, ConversationSummary, EventLedgerPage,
    MessageRecord, Page, Store, StoreError, StoreKey,
};
use crate::supervisor::RuntimeSupervisor;
use std::time::Duration;

/// Contract 1.283 (§4.267): how often the event ledger's head retention runs.
/// Thirty seconds is the same beat the disappearing-message sweeper uses — a
/// ledger that trims a little late is harmless (the read face is bounded by
/// both the page limit and its byte budget), while a fast loop would keep the
/// store lock hot for no gain.
const EVENT_LOG_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// One group slot: opaque id plus its full supervision stack.
pub struct ProxyGroupSlot {
    id: String,
    supervisor: Arc<RuntimeSupervisor>,
}

impl ProxyGroupSlot {
    /// Assemble one slot from an already-built supervision stack. Legacy
    /// plans come from [`open_group_runtime`]; the engine pool builds one
    /// routing handle per dynamic account slot from the same constructor, and
    /// unit tests build single-group runtimes by hand.
    pub(crate) fn new(id: String, supervisor: Arc<RuntimeSupervisor>) -> Self {
        Self { id, supervisor }
    }
}

/// Events merged from every group's supervision stack, already tagged and
/// aggregated for the wire.
#[derive(Clone, Debug)]
pub enum RegistryEvent {
    /// Top-level aggregate for `runtime.stateChanged` (shape unchanged).
    AggregateStateChanged(AggregateEngineStatus),
    /// Per-group detail for `proxyGroup.stateChanged`.
    GroupStateChanged {
        group_id: String,
        status: EngineStatus,
    },
    ProtocolWarning {
        kind: &'static str,
    },
    ResourcePressure {
        state: crate::resource::ResourcePressureState,
        pid: u32,
        rss_bytes: u64,
        group_id: String,
    },
    StorageChanged {
        state: &'static str,
    },
}

/// Pre-Phase-4 top-level runtime shape (`runtime.stateChanged` keeps exactly
/// this, and `runtime.status` flattens it before adding `proxyGroups`).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateEngineStatus {
    pub state: EngineState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    pub resource_pressure: bool,
    /// Engine-pool design §7.2 (F10's sibling): true when the aggregate is
    /// `running` but at least one slot is not — the pre-pool rule alone
    /// reported `running` for nine healthy engines and one crash. Only the
    /// per-account pool computes it; on the pre-pool path the field is false
    /// and omitted from the wire, so the flag-off shape stays byte-identical.
    #[serde(skip_serializing_if = "is_false")]
    pub degraded: bool,
}

/// Serde helper: omit `degraded` unless it is true.
fn is_false(value: &bool) -> bool {
    !*value
}

impl From<EngineStatus> for AggregateEngineStatus {
    fn from(status: EngineStatus) -> Self {
        Self {
            state: status.state,
            pid: status.pid,
            rss_bytes: status.rss_bytes,
            resource_pressure: status.resource_pressure,
            degraded: false,
        }
    }
}

/// One `proxyGroups[]` entry (implementation-plan §4.4).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyGroupStatus {
    pub group_id: String,
    pub state: EngineState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    pub resource_pressure: bool,
    /// Accounts bound to the group in the shared store.
    pub account_count: u64,
}

/// Result of `runtime.status` / `runtime.start` / `runtime.stop`: the pinned
/// top-level aggregate plus the additive group array.
#[derive(Clone, Debug)]
pub struct RuntimeStatusResult {
    pub aggregate: AggregateEngineStatus,
    pub proxy_groups: Vec<ProxyGroupStatus>,
    /// Engine-pool design §7.3 (additive): one entry per dynamically
    /// provisioned account engine.
    ///
    /// Pooled mode always emits the key — an empty pool answers `[]` — which
    /// is what lets the desktop tell "no accounts yet" from a pre-pool
    /// connector that never had the field. The pre-pool path omits the key
    /// entirely, so that wire shape stays byte-identical.
    pub engines: Vec<crate::pool::AccountEngineStatus>,
    /// Whether this answer was produced by the pooled runtime; it selects the
    /// `engines` wire shape above (the mode cannot be re-derived here: an empty
    /// pool and an empty legacy group list look alike).
    engines_pooled: bool,
}

impl Serialize for RuntimeStatusResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // `Some(&[])` still serializes as `"engines": []`; `None` drops the
        // key. That single choice is the whole pooled/legacy split.
        RuntimeStatusWire {
            aggregate: &self.aggregate,
            proxy_groups: &self.proxy_groups,
            engines: self.engines_pooled.then_some(self.engines.as_slice()),
        }
        .serialize(serializer)
    }
}

/// Wire projection of [`RuntimeStatusResult`]: the flatten rule for the pinned
/// aggregate is unchanged, and `engines` is present exactly when the answer
/// comes from the pooled runtime.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStatusWire<'a> {
    #[serde(flatten)]
    aggregate: &'a AggregateEngineStatus,
    proxy_groups: &'a [ProxyGroupStatus],
    #[serde(skip_serializing_if = "Option::is_none")]
    engines: Option<&'a [crate::pool::AccountEngineStatus]>,
}

/// Which supervisor owns a link session: a launcher-planned proxy group or a
/// dynamically provisioned per-account engine slot.
enum LinkOwner {
    Group(Arc<ProxyGroupSlot>),
    Account(Arc<crate::pool::AccountSlot>),
}

/// `ENGINE_NOT_PROVISIONED`: full pooling found an account row with no
/// engine slot. The binding is intact but its engine data is missing, so the
/// request cannot be served by any other engine (never a silent fallback to a
/// legacy group engine — there is none in pool mode).
fn engine_not_provisioned_error() -> ServiceError {
    ServiceError::Api(ApiError::new(
        "ENGINE_NOT_PROVISIONED",
        "this account has no engine slot in the pool; its local engine data is missing",
        false,
    ))
}

/// The v1-shaped delete answer (a recorded receipt under `deleted`, or an
/// empty object).
fn account_delete_result(receipt: Option<crate::store::AccountDeleteReceipt>) -> Value {
    match receipt {
        Some(receipt) => json!({ "deleted": receipt }),
        None => json!({}),
    }
}

/// `ACCOUNT_ALREADY_LINKED`: a per-account link finish resolved to a number
/// that already has a local account row, so keeping the fresh slot would run
/// two engines for one account (design F2/I1). The freshly linked device is
/// rolled back; the caller must delete the old local data before relinking.
fn account_already_linked_error() -> ServiceError {
    ServiceError::Api(ApiError::new(
        "ACCOUNT_ALREADY_LINKED",
        "this number already has a local account; delete its local data before linking again",
        false,
    ))
}

/// Why `runtime.start` failed when no group engine started.
#[derive(Debug)]
pub enum StartFailure {
    AlreadyRunning,
    StartFailed,
    /// Every slot that could start was refused by the store-migration gate
    /// (a latched terminal block, or the plaintext preflight). This is a
    /// terminal answer for the process: retrying the same runtime.start cannot
    /// heal it, so the host must render the reason instead of retrying. The
    /// store code rides along so the wire can name it.
    StoreMigrationBlocked {
        code: String,
        message: String,
    },
    /// O1: at least one engine refused the contract handshake (identity
    /// missing or revision outside the supported interval). Not retryable: the
    /// fault is latched on the supervisor and the same binary answers the same
    /// revision on every restart.
    ContractMismatch(crate::engine_contract::EngineContractFault),
    /// Contract 1.275: every pooled slot is parked in the terminal
    /// `device_unlinked` state. No retry can revive a dead credential, so the
    /// answer is the terminal ACCOUNT_UNLINKED face, never a retryable start
    /// failure that would invite one more doomed spawn.
    AccountUnlinked,
}

/// Why `runtime.stop` failed.
#[derive(Debug)]
pub enum StopFailure {
    NotRunning,
    StopFailed,
}

pub struct ProxyGroupRuntime {
    /// Legacy group supervisors. **Empty** when the engine pool is enabled:
    /// full pooling runs one engine per account and no group engine.
    groups: Vec<Arc<ProxyGroupSlot>>,
    /// Launcher-planned group ids in plan order. They stay the proxy-policy
    /// vocabulary (`proxyGroups[]`/binding) even when no group engine exists.
    group_ids: Vec<String>,
    /// Shared routing service over the one per-instance store (legacy mode
    /// reuses the first group's; pool mode builds a standalone one).
    router: Arc<Mutex<ConnectorService>>,
    /// The launcher's effective media-ingest decision (handshake gate).
    media_ingest_armed: bool,
    /// The one per-instance store (contract revision 1.282, §4.266). The
    /// routing service already owns a handle; this one exists so the
    /// process-wide store health face (doctor + metrics) does not have to take
    /// the service lock to answer.
    store: Arc<Store>,
    /// Dynamic per-account engine registry. `None` on the pre-pool path: no
    /// account routing, no `engines[]`, no `degraded`, and every legacy path
    /// runs exactly as before. `Some` is **full pooling**: no group engine is
    /// ever started; every account owns an engine slot.
    pool: Option<Arc<crate::pool::AccountPool>>,
    /// True between `runtime.start` and `runtime.stop`/`shutdown`. Cold
    /// dynamic slots wake only while the runtime is running; a stopped
    /// runtime keeps failing account calls with RUNTIME_NOT_RUNNING exactly
    /// like a legacy group engine parked by `runtime.stop`.
    running: AtomicBool,
    /// One process-wide history-retention pass (spawned on the first available
    /// supervisor, legacy or pooled).
    retention_spawned: AtomicBool,
    /// One process-wide event-ledger retention pass (contract 1.283, §4.267):
    /// the ledger is one table in the one store, so exactly one sweeper owns
    /// it per runtime no matter how many groups or account slots exist.
    event_log_sweeper: AtomicBool,
    events: broadcast::Sender<RegistryEvent>,
    host_events: broadcast::Sender<HostSideEvent>,
    /// Forwarder tasks merging every slot's streams into this runtime;
    /// aborted on drop. Never held across an await.
    forwarders: StdMutex<Vec<JoinHandle<()>>>,
    /// Dynamic account ids whose forwarders were already spawned (one pair of
    /// tasks per slot; a re-spawn would double every state event).
    forwarded_accounts: StdMutex<HashSet<String>>,
    /// The orphan sweep's copy of `running` (full pooling only). Every
    /// transition writes it; `None` on the legacy path, where no sweep reads
    /// it.
    shared_running: StdMutex<Option<Arc<AtomicBool>>>,
    /// The process-wide §4.46 backup file-handle table, when the launcher armed
    /// it (M6 D3 follow-up). Every supervisor already holds the same `Arc`;
    /// this one exists so the engine-free account delete can release one
    /// account's handles without borrowing a supervisor — a slot the
    /// store-migration gate refuses never gets one to borrow. Armed once, at
    /// assembly (`install_backup_handles`); `None` keeps the engine-free path
    /// down to its on-disk residue.
    backup_handles: StdMutex<Option<Arc<crate::backup_export::BackupFileHandleTable>>>,
}

impl ProxyGroupRuntime {
    /// Assemble the legacy runtime from launcher-planned groups and start the
    /// event forwarders. Callers must have spawned watchdogs/retention
    /// already.
    pub(crate) fn new(groups: Vec<ProxyGroupSlot>) -> Arc<Self> {
        assert!(
            !groups.is_empty(),
            "the launch plan always contains at least the default group"
        );
        let group_ids = groups.iter().map(|slot| slot.id.clone()).collect();
        let router = Arc::clone(groups[0].supervisor.service());
        let media_ingest_armed = groups[0].supervisor.media_ingest_armed();
        let store = groups[0].supervisor.store();
        Self::assemble(
            groups.into_iter().map(Arc::new).collect(),
            group_ids,
            router,
            media_ingest_armed,
            store,
            None,
        )
    }

    /// The full-pool assembly (engine-pool S1, switch on): one engine per
    /// account, no legacy group engine. `group_ids` keeps the launcher plan
    /// visible as proxy policy, and a standalone routing service serves the
    /// shared store. `running` is the flag shared with the orphan sweep, so a
    /// sweep can tell a running runtime from a stopped one.
    /// The full-pool assembly whose `running` flag is shared with the orphan
    /// sweep owner (a sweep must know whether this runtime is between start
    /// and stop before it classifies a cold slot's engine).
    pub(crate) fn full_pool_with_running(
        group_ids: Vec<String>,
        store: Arc<Store>,
        media_ingest: bool,
        pool: Arc<crate::pool::AccountPool>,
        running: Arc<AtomicBool>,
    ) -> Arc<Self> {
        assert!(
            !group_ids.is_empty(),
            "the launch plan always contains at least the default group"
        );
        assert!(
            group_ids.len() <= MAX_PROXY_GROUPS,
            "the launch plan enforces the group ceiling"
        );
        let health_store = Arc::clone(&store);
        let router = Arc::new(Mutex::new(ConnectorService::with_media(store, None)));
        let runtime = Self::assemble(
            Vec::new(),
            group_ids,
            router,
            media_ingest,
            health_store,
            Some(pool),
        );
        // The shared flag starts where the freshly assembled runtime stands
        // (stopped), then every start/stop writes it as well as its own.
        running.store(runtime.running.load(Ordering::Acquire), Ordering::Release);
        if let Ok(mut slot) = runtime.shared_running.lock() {
            *slot = Some(running);
        }
        runtime
    }

    /// Arm the process-wide §4.46 backup file-handle table this runtime's
    /// engine-free account delete clears (M6 D3 follow-up). Set once at
    /// assembly, from the same `Arc` every supervisor receives; the legacy
    /// path never needs it because it always has a supervisor to clear its own
    /// handles.
    fn install_backup_handles(&self, handles: Arc<crate::backup_export::BackupFileHandleTable>) {
        if let Ok(mut slot) = self.backup_handles.lock() {
            *slot = Some(handles);
        }
    }

    /// Publish the current running state to the sweep's copy. Called on every
    /// transition (start/stop/restart), so the sweep reads one writer's fact
    /// without a polling thread or a second source of truth.
    fn publish_running(&self) {
        if let Ok(shared) = self.shared_running.lock()
            && let Some(shared) = shared.as_ref()
        {
            shared.store(self.running.load(Ordering::Acquire), Ordering::Release);
        }
    }

    fn assemble(
        groups: Vec<Arc<ProxyGroupSlot>>,
        group_ids: Vec<String>,
        router: Arc<Mutex<ConnectorService>>,
        media_ingest_armed: bool,
        store: Arc<Store>,
        pool: Option<Arc<crate::pool::AccountPool>>,
    ) -> Arc<Self> {
        assert!(
            groups.len() <= MAX_PROXY_GROUPS && group_ids.len() <= MAX_PROXY_GROUPS,
            "the launch plan enforces the group ceiling"
        );
        assert!(
            (pool.is_some() && groups.is_empty())
                || (pool.is_none() && groups.len() == group_ids.len()),
            "full pooling has no group engines; legacy mode has one per planned group"
        );
        let (events, _) = broadcast::channel(1024);
        let (host_events, _) = broadcast::channel(1024);
        let runtime = Arc::new(Self {
            groups,
            group_ids,
            router,
            media_ingest_armed,
            store,
            pool,
            running: AtomicBool::new(false),
            retention_spawned: AtomicBool::new(false),
            event_log_sweeper: AtomicBool::new(false),
            events,
            host_events,
            forwarders: StdMutex::new(Vec::new()),
            forwarded_accounts: StdMutex::new(HashSet::new()),
            shared_running: StdMutex::new(None),
            backup_handles: StdMutex::new(None),
        });
        runtime.spawn_forwarders();
        runtime.spawn_event_log_sweeper();
        if let Some(pool) = &runtime.pool {
            for slot in pool.slots() {
                runtime.spawn_account_forwarders(&slot);
            }
            if let Some(first) = pool.slots().first() {
                runtime.ensure_history_retention(first.supervisor());
            }
            runtime.spawn_link_reaper();
        }
        runtime
    }

    /// The event ledger's retention pass (contract 1.283, §4.267): one
    /// process-wide task, because the ledger is one table in the one store.
    /// It runs one pass immediately (so an upgrade trims at startup instead of
    /// thirty seconds later) and then every EVENT_LOG_SWEEP_INTERVAL. Every
    /// pass is single-flight and runs on the blocking pool — rusqlite is
    /// synchronous and must never occupy a tokio worker — and a store failure
    /// only logs: the next tick retries.
    fn spawn_event_log_sweeper(self: &Arc<Self>) {
        // A runtime assembled outside a tokio context (unit fixtures) simply
        // does not sweep, and leaves the slot free so a later assembly inside
        // one still claims it; in production the assembly always runs inside
        // the runtime.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.event_log_sweeper.swap(true, Ordering::AcqRel) {
            return;
        }
        let store = Arc::clone(&self.store);
        handle.spawn(async move {
            loop {
                let outcome = tokio::task::spawn_blocking({
                    let store = Arc::clone(&store);
                    move || store.trim_event_log(crate::link::now_ms())
                })
                .await
                .unwrap_or(Err(StoreError::Unavailable(None)));
                match outcome {
                    Ok(outcome) if outcome.removed > 0 => tracing::info!(
                        removed = outcome.removed,
                        trimmed_through_seq = outcome.trimmed_through_seq,
                        rows = outcome.rows,
                        bytes = outcome.bytes,
                        "event ledger retention trimmed the head"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        error_class = error.class(),
                        "event ledger retention stopped: store unavailable"
                    ),
                }
                tokio::time::sleep(EVENT_LOG_SWEEP_INTERVAL).await;
            }
        });
    }

    /// Reclaim half-finished link slots (engine running, no committed store
    /// row, no live link session, idle past the link-session TTL). Without
    /// this an abandoned link would pin a data directory and one of the eight
    /// engine slots until the next process restart.
    fn spawn_link_reaper(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let Some(runtime) = weak.upgrade() else {
                    break;
                };
                runtime.reap_uncommitted_links().await;
            }
        });
        self.forwarders
            .lock()
            .expect("forwarder list mutex")
            .push(handle);
    }

    async fn reap_uncommitted_links(&self) {
        let Some(pool) = &self.pool else {
            return;
        };
        for slot in pool.slots() {
            if slot.is_provisioned() || slot.idle_for() < crate::pool::ABANDONED_LINK_TTL {
                continue;
            }
            if slot.supervisor().has_pending_link().await {
                continue;
            }
            let account_id = slot.account_id().to_string();
            // The lease is the only owner an uncommitted slot has: reap it
            // through exactly the same idempotent function finish/cancel use.
            if let Some(attempt_id) = slot.lease_attempt_id() {
                tracing::warn!(
                    target: "connector.pool",
                    invariant = crate::pool::LINK_SLOT_LEAK_INVARIANT,
                    stage = "abandoned_link_reaped",
                    account = %crate::pool::account_fingerprint(&account_id),
                    group_id = %slot.proxy_group(),
                    "abandoned link attempt lease is being reclaimed"
                );
                let outcome = pool.reclaim_link_attempt(&attempt_id).await;
                if matches!(
                    outcome,
                    crate::pool::LinkReclaimOutcome::Reclaimed
                        | crate::pool::LinkReclaimOutcome::Quarantined
                ) {
                    self.forget_account_forwarders(&account_id);
                }
                continue;
            }
            // A pre-lease slot (a crash window from an older build, or a
            // slot whose lease was already settled): the same teardown, no
            // lease record to address.
            tracing::warn!(
                account_id = %account_id,
                group_id = %slot.proxy_group(),
                "abandoned per-account link slot is being reclaimed"
            );
            pool.discard(&account_id, true).await;
            self.forget_account_forwarders(&account_id);
        }
    }

    /// The dynamic registry, when the per-account pool is enabled.
    /// The per-account pool of this runtime, when full pooling is armed. Read
    /// only: diagnostics and tests consult per-slot faces (status, migration
    /// block) through it; nothing routes work through this accessor.
    pub fn account_pool(&self) -> Option<&Arc<crate::pool::AccountPool>> {
        self.pool.as_ref()
    }

    /// D4 所有权执行面(阶段1 批1-5c,SIGNAL-STAGE1-DESIGN §三):Main 的
    /// 所有权表 quarantine 裁决在 connector 的执行臂。**槽级操作,不经账号
    /// 行解析**——孤儿槽(绑定已消失、只剩凭据目录)正是它的目标客户,
    /// 走 resolve 会恰好拒掉要清理的对象。停引擎 + 目录移 `.quarantine-*`
    /// (字节保留可审计)。幂等:返回 `false` = 无槽(已隔离/从未存在),
    /// 绝不重复移动目录。前向转发账(若在)同批忘却。
    pub async fn ownership_quarantine_slot(&self, account_id: &str, reason: &str) -> bool {
        let Some(pool) = self.pool.as_ref() else {
            return false; // legacy 无池布局:无槽可执行,幂等成功
        };
        let removed = pool.discard_quarantined(account_id).await;
        tracing::info!(
            account_id = %crate::pool::account_fingerprint(account_id),
            reason,
            removed,
            "ownership quarantine executed (D4)"
        );
        if removed {
            self.forget_account_forwarders(account_id);
        }
        removed
    }

    /// D4 所有权执行面(阶段1 批1-5c):Main 的 hibernate 裁决执行臂 —
    /// 停引擎 + 目录原地保留(冷槽语义:下次该账号请求自动重新拉起,
    /// 代价一次 spawn)。幂等同上;不触碰前向转发账(账号仍绑定,只是省内存)。
    pub async fn ownership_hibernate_slot(&self, account_id: &str) -> bool {
        let Some(pool) = self.pool.as_ref() else {
            return false;
        };
        let removed = pool.hibernate_slot(account_id).await;
        tracing::info!(
            account_id = %crate::pool::account_fingerprint(account_id),
            removed,
            "ownership hibernate executed (D4)"
        );
        removed
    }

    /// Exactly one process-wide history-retention pass, whichever supervisor
    /// happens to land first (a pool can legitimately have no slots at
    /// startup; the first linked account then owns the pass).
    fn ensure_history_retention(&self, supervisor: &Arc<RuntimeSupervisor>) {
        if !self.retention_spawned.swap(true, Ordering::AcqRel) {
            supervisor.spawn_history_retention();
        }
    }

    pub fn group_ids(&self) -> Vec<&str> {
        self.group_ids.iter().map(String::as_str).collect()
    }

    /// Whether the media-download capability is genuinely armed process-wide.
    /// The launcher decision (contract revision 1.98/§4.102) is the exact gate
    /// every media method answers; the field is the effective decision, so a
    /// full-pool runtime with no group supervisor still answers it honestly.
    pub fn media_ingest_armed(&self) -> bool {
        self.media_ingest_armed
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RegistryEvent> {
        self.events.subscribe()
    }

    pub fn subscribe_host(&self) -> broadcast::Receiver<HostSideEvent> {
        self.host_events.subscribe()
    }

    fn spawn_forwarders(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let mut handles = Vec::new();
        for slot in &self.groups {
            let group_id = slot.id.clone();
            let mut engine_rx = slot.supervisor.subscribe_engine();
            handles.push(tokio::spawn({
                let weak = weak.clone();
                async move {
                    loop {
                        match engine_rx.recv().await {
                            Ok(event) => {
                                let Some(runtime) = weak.upgrade() else {
                                    break;
                                };
                                runtime.on_group_engine_event(&group_id, event).await;
                            }
                            // A lagging forwarder drops transitions; the next
                            // transition or a poll re-syncs the aggregate.
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }));
            let mut host_rx = slot.supervisor.subscribe_host();
            handles.push(tokio::spawn({
                let host_tx = self.host_events.clone();
                async move {
                    loop {
                        match host_rx.recv().await {
                            // Host-side events (account/conversation/message/
                            // storage) are already wire-shaped and group-free
                            // or carry their own attribution.
                            Ok(event) => {
                                let _ = host_tx.send(event);
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }));
        }
        *self.forwarders.lock().expect("forwarder list mutex") = handles;
    }

    /// Spawn one dynamic slot's event forwarders (idempotent per account).
    /// Unlike the static groups these tasks never emit
    /// `proxyGroup.stateChanged`: an account is not a proxy group, and the
    /// pool's per-account detail rides `runtime.status` `engines[]`. Each
    /// task owns only its subscription receiver, so removing the slot closes
    /// the channels and ends the tasks.
    fn spawn_account_forwarders(self: &Arc<Self>, slot: &Arc<crate::pool::AccountSlot>) {
        let account_id = slot.account_id().to_string();
        {
            let mut forwarded = self
                .forwarded_accounts
                .lock()
                .expect("forwarded account list mutex");
            if !forwarded.insert(account_id.clone()) {
                return;
            }
        }
        let mut engine_rx = slot.supervisor().subscribe_engine();
        let mut host_rx = slot.supervisor().subscribe_host();
        let mut handles = Vec::new();
        let weak = Arc::downgrade(self);
        handles.push(tokio::spawn({
            let account_id = account_id.clone();
            async move {
                loop {
                    match engine_rx.recv().await {
                        Ok(event) => {
                            let Some(runtime) = weak.upgrade() else {
                                break;
                            };
                            runtime.on_account_engine_event(&account_id, event).await;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }));
        handles.push(tokio::spawn({
            let host_tx = self.host_events.clone();
            async move {
                loop {
                    match host_rx.recv().await {
                        Ok(event) => {
                            let _ = host_tx.send(event);
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }));
        self.forwarders
            .lock()
            .expect("forwarder list mutex")
            .extend(handles);
    }

    fn forget_account_forwarders(&self, account_id: &str) {
        if let Ok(mut forwarded) = self.forwarded_accounts.lock() {
            forwarded.remove(account_id);
        }
    }

    async fn on_group_engine_event(&self, group_id: &str, event: EngineEvent) {
        match event {
            EngineEvent::StateChanged(status) => {
                let _ = self.events.send(RegistryEvent::GroupStateChanged {
                    group_id: group_id.to_string(),
                    status: status.clone(),
                });
                let aggregate = self.aggregate_status().await;
                let _ = self
                    .events
                    .send(RegistryEvent::AggregateStateChanged(aggregate));
            }
            EngineEvent::ResourcePressure {
                state,
                pid,
                rss_bytes,
            } => {
                let _ = self.events.send(RegistryEvent::ResourcePressure {
                    state,
                    pid,
                    rss_bytes,
                    group_id: group_id.to_string(),
                });
            }
            EngineEvent::ProtocolWarning { kind } => {
                let _ = self.events.send(RegistryEvent::ProtocolWarning { kind });
            }
            EngineEvent::StorageChanged { state } => {
                let _ = self.events.send(RegistryEvent::StorageChanged { state });
            }
            EngineEvent::AccountUnauthorized { .. }
            | EngineEvent::ConnectionState { .. }
            | EngineEvent::ReceiveEmptied { .. }
            | EngineEvent::ReceiveClockSkew { .. }
            | EngineEvent::ConversationState { .. }
            | EngineEvent::StoragePull { .. }
            | EngineEvent::InitialSyncComplete { .. }
            | EngineEvent::ReceiveDecryptionError { .. }
            | EngineEvent::ReceiveIdentityChanged { .. }
            | EngineEvent::SessionReset { .. } => {
                // Contract 1.21: handled by the supervisor's engine-event
                // watcher, which owns the service handle. Contract 1.134
                // §4.117: the account-domain transient notifications ride
                // the same watcher (their host frames need the store-backed
                // account resolution); the registry has nothing to forward.
                // Contract 1.165 §4.163: the decryption-error envelope joins
                // the same lane (metrics count + transient host frame).
            }
        }
    }

    /// A dynamic slot's engine event. Per-account state detail is polled
    /// through `runtime.status` `engines[]`; the aggregate event keeps the
    /// desktop's existing subscription working and now carries `degraded`
    /// when the pool is partial. Account-less lanes (protocol warning,
    /// storage) keep their pre-pool forwarding; resource pressure is reported
    /// per slot in `engines[]` instead of inventing a group id for an account.
    async fn on_account_engine_event(&self, _account_id: &str, event: EngineEvent) {
        match event {
            EngineEvent::StateChanged(_) => {
                let aggregate = self.aggregate_status().await;
                let _ = self
                    .events
                    .send(RegistryEvent::AggregateStateChanged(aggregate));
            }
            EngineEvent::ProtocolWarning { kind } => {
                let _ = self.events.send(RegistryEvent::ProtocolWarning { kind });
            }
            EngineEvent::StorageChanged { state } => {
                let _ = self.events.send(RegistryEvent::StorageChanged { state });
            }
            EngineEvent::ResourcePressure { .. }
            | EngineEvent::AccountUnauthorized { .. }
            | EngineEvent::ConnectionState { .. }
            | EngineEvent::ReceiveEmptied { .. }
            | EngineEvent::ReceiveClockSkew { .. }
            | EngineEvent::ConversationState { .. }
            | EngineEvent::StoragePull { .. }
            | EngineEvent::InitialSyncComplete { .. }
            | EngineEvent::ReceiveDecryptionError { .. }
            | EngineEvent::ReceiveIdentityChanged { .. }
            | EngineEvent::SessionReset { .. } => {
                // The dynamic supervisor's own watchers own the account-level
                // notifications (contract 1.134); the registry forwards the
                // global lanes only.
            }
        }
    }

    /// Current per-group statuses in launcher order, with store-backed
    /// account counts. Full pooling has no group engine: the plan groups
    /// still ride `proxyGroups[]` (with the same account counts) but report
    /// `stopped` and no pid — the live engine health lives in `engines[]`.
    async fn group_statuses(&self) -> Vec<ProxyGroupStatus> {
        let mut statuses = Vec::with_capacity(self.group_ids.len());
        if self.pool.is_some() {
            for group_id in &self.group_ids {
                let account_count = self
                    .router
                    .lock()
                    .await
                    .count_accounts_in_group_lossy(group_id);
                statuses.push(ProxyGroupStatus {
                    group_id: group_id.clone(),
                    state: EngineState::Stopped,
                    pid: None,
                    rss_bytes: None,
                    resource_pressure: false,
                    account_count,
                });
            }
            return statuses;
        }
        for slot in &self.groups {
            let status = slot.supervisor.status().await;
            let account_count = self
                .router
                .lock()
                .await
                .count_accounts_in_group_lossy(&slot.id);
            statuses.push(ProxyGroupStatus {
                group_id: slot.id.clone(),
                state: status.state,
                pid: status.pid,
                rss_bytes: status.rss_bytes,
                resource_pressure: status.resource_pressure,
                account_count,
            });
        }
        statuses
    }

    /// The pinned aggregation rule (implementation-plan §4.4), extended by the
    /// engine pool: dynamic slots join the same running/faulted/exited ladder,
    /// and `degraded` reports a partial pool. The extra field is computed only
    /// when the pool is enabled (flag-off output stays byte-identical), and
    /// `pid` keeps the pre-pool "exactly one group" rule so a single-group
    /// deployment is field-for-field unchanged.
    fn aggregate_from(
        parts: &[EngineStatus],
        pid: Option<u32>,
        pool_enabled: bool,
    ) -> AggregateEngineStatus {
        let running = parts.iter().any(|part| part.state == EngineState::Running);
        let faulted = parts.iter().any(|part| part.state == EngineState::Faulted);
        let exited = parts.iter().any(|part| part.state == EngineState::Exited);
        let state = if running {
            EngineState::Running
        } else if faulted {
            EngineState::Faulted
        } else if exited {
            EngineState::Exited
        } else {
            EngineState::Stopped
        };
        AggregateEngineStatus {
            state,
            // Present only when exactly one group exists, regardless of state.
            pid,
            rss_bytes: parts
                .iter()
                .filter_map(|part| part.rss_bytes)
                .reduce(u64::saturating_add),
            resource_pressure: parts.iter().any(|part| part.resource_pressure),
            degraded: pool_enabled
                && running
                && parts.iter().any(|part| part.state != EngineState::Running),
        }
    }

    /// Engine statuses across the whole pool (legacy groups first, then
    /// dynamic slots in account-id order). Memory-only reads: no store query,
    /// which is what keeps the state-change hot path free of per-slot SQL
    /// (design F10).
    async fn slot_statuses(&self) -> Vec<EngineStatus> {
        let mut statuses = Vec::with_capacity(self.groups.len());
        for slot in &self.groups {
            statuses.push(slot.supervisor.status().await);
        }
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                statuses.push(slot.supervisor().status().await);
            }
        }
        statuses
    }

    /// The live engine child pids this runtime owns (legacy group engines and
    /// pool account engines), for the parent-loss exit path's bounded reap.
    /// Memory-only reads, same face as `slot_statuses`.
    pub async fn engine_pids(&self) -> Vec<u32> {
        self.slot_statuses()
            .await
            .into_iter()
            .filter_map(|status| status.pid)
            .collect()
    }

    /// The `pid` field keeps its pre-pool rule: only a deployment with exactly
    /// one proxy group (the flag-off shape) reports it at the top level.
    fn single_group_pid(&self, statuses: &[EngineStatus]) -> Option<u32> {
        if self.groups.len() == 1 {
            statuses.first().and_then(|status| status.pid)
        } else {
            None
        }
    }

    async fn aggregate_status(&self) -> AggregateEngineStatus {
        let statuses = self.slot_statuses().await;
        let pid = self.single_group_pid(&statuses);
        Self::aggregate_from(&statuses, pid, self.pool.is_some())
    }

    pub async fn status(&self) -> RuntimeStatusResult {
        let proxy_groups = self.group_statuses().await;
        let engines = match &self.pool {
            Some(pool) => pool.statuses().await,
            None => Vec::new(),
        };
        // Full pooling has no group engine: only the account engines join the
        // aggregate (a stopped proxyGroups[] entry is proxy policy, not a
        // fault). Legacy mode aggregates the group engines exactly as before.
        let mut statuses: Vec<EngineStatus> = if self.pool.is_some() {
            Vec::new()
        } else {
            proxy_groups
                .iter()
                .map(|group| EngineStatus {
                    state: group.state,
                    pid: group.pid,
                    rss_bytes: group.rss_bytes,
                    resource_pressure: group.resource_pressure,
                })
                .collect()
        };
        statuses.extend(engines.iter().map(|engine| EngineStatus {
            state: engine.state,
            pid: engine.pid,
            rss_bytes: engine.rss_bytes,
            resource_pressure: engine.resource_pressure,
        }));
        let pid = if self.groups.len() == 1 {
            proxy_groups.first().and_then(|group| group.pid)
        } else {
            None
        };
        RuntimeStatusResult {
            aggregate: Self::aggregate_from(&statuses, pid, self.pool.is_some()),
            proxy_groups,
            engines,
            // Pooled mode always names the key (an empty pool answers `[]`);
            // the legacy path omits it and keeps the pre-pool byte shape.
            engines_pooled: self.pool.is_some(),
        }
    }

    /// The read-only `runtime.doctor` face (§4.79): every group's supervisor
    /// with its opaque id, in launcher order. Read-only by contract — the
    /// doctor module owns the whole probe and never mutates runtime state.
    pub(crate) fn doctor_supervisors(
        &self,
    ) -> impl Iterator<Item = (&str, &Arc<RuntimeSupervisor>)> {
        self.groups
            .iter()
            .map(|slot| (slot.id.as_str(), &slot.supervisor))
    }

    /// O1: every engine slot's handshake state for the periodic per-group
    /// metrics line (legacy groups by group id, pooled slots by opaque account
    /// id). Read-only; the supervisor's lock is taken only to copy the state.
    pub async fn engine_contract_samples(&self) -> Vec<crate::metrics::EngineContractSample> {
        let mut samples = Vec::with_capacity(self.groups.len());
        for slot in &self.groups {
            samples.push(crate::metrics::EngineContractSample {
                group_id: slot.id.clone(),
                state: slot.supervisor.engine_contract_state().await,
            });
        }
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                samples.push(crate::metrics::EngineContractSample {
                    group_id: slot.account_id().to_string(),
                    state: slot.supervisor().engine_contract_state().await,
                });
            }
        }
        samples
    }

    /// The one store this process serves (contract revision 1.282, §4.266).
    /// The doctor's `store` face and the periodic metrics line read it; both
    /// are read-only and neither takes a group's service lock.
    pub(crate) fn store(&self) -> Arc<Store> {
        Arc::clone(&self.store)
    }

    /// Start every group's engine (R7). Success reports the per-group states;
    /// RUNTIME_START_FAILED only when no group engine started. With the
    /// per-account pool enabled, the resident window (top-K most recently
    /// used dynamic slots) starts here too.
    pub async fn start(&self) -> Result<RuntimeStatusResult, StartFailure> {
        self.running.store(true, Ordering::Release);
        self.publish_running();
        if let Some(pool) = &self.pool {
            // Full pooling: no group engine exists. The resident window (top-K
            // most recently used account slots) starts here.
            let start_block = pool.start_resident().await;
            // O1: one engine binary backs every slot, so one contract refusal
            // is a runtime-wide refusal. Stop what already started instead of
            // leaving a half-running account pipeline behind the fatal.
            if let Some(fault) = pool.contract_fault().await {
                pool.stop_all().await;
                self.running.store(false, Ordering::Release);
                self.publish_running();
                return Err(StartFailure::ContractMismatch(fault));
            }
            let mut any_running = false;
            for slot in pool.slots() {
                if slot.supervisor().status().await.state == EngineState::Running {
                    any_running = true;
                }
            }
            // Contract 1.291 (§4.277 A): a slot whose migration pass is still
            // running is *on its way up*, not failed. Counting it as a failure
            // would turn every asynchronous start into RUNTIME_START_FAILED.
            if pool.any_migration_in_flight() {
                any_running = true;
            }
            // A pool with no accounts legitimately has nothing to start (the
            // desktop still gets an honest stopped aggregate); only a pool
            // whose slots all failed answers RUNTIME_START_FAILED.
            if !any_running && !pool.is_empty() {
                // Contract 1.275: a pool whose every account was unlinked by
                // the holder has a terminal answer of its own. Retrying the same
                // runtime.start cannot heal a dead credential.
                if pool.every_slot_device_unlinked() {
                    return Err(StartFailure::AccountUnlinked);
                }
                // A terminal store refusal is not a retryable start failure: it
                // already names the account-level reason a human has to act on.
                if let Some(block) = start_block {
                    return Err(StartFailure::StoreMigrationBlocked {
                        code: block.code,
                        message: block.message,
                    });
                }
                return Err(StartFailure::StartFailed);
            }
            return Ok(self.status().await);
        }
        let mut any_running = false;
        let mut already_running = false;
        let mut started = Vec::new();
        let mut contract_fault = None;
        for slot in &self.groups {
            match slot.supervisor.start().await {
                Ok(status) => {
                    if status.state == EngineState::Running {
                        any_running = true;
                        started.push(std::sync::Arc::clone(slot));
                    }
                }
                Err(EngineError::Backpressure) => already_running = true,
                // O1: every group runs the same engine binary; the first
                // refusal is the runtime's verdict. Stop what already started
                // so no account pipeline keeps running behind the fatal.
                Err(EngineError::ContractMismatch(fault)) => {
                    contract_fault = Some(fault);
                    break;
                }
                Err(_) => {}
            }
        }
        if let Some(fault) = contract_fault {
            for slot in &started {
                if let Err(error) = slot.supervisor.stop().await {
                    tracing::warn!(
                        group_id = %slot.id,
                        error_class = error.class(),
                        "group engine did not stop after the contract refusal"
                    );
                }
            }
            self.running.store(false, Ordering::Release);
            self.publish_running();
            return Err(StartFailure::ContractMismatch(fault));
        }
        if !any_running && !already_running {
            return Err(StartFailure::StartFailed);
        }
        Ok(self.status().await)
    }

    /// Stop every group's engine (R7). Dynamic engines park too; their slots
    /// stay registered and cold so a later start rebuilds the resident window.
    pub async fn stop(&self) -> Result<RuntimeStatusResult, StopFailure> {
        self.running.store(false, Ordering::Release);
        self.publish_running();
        let mut any_stopped = false;
        let mut any_failed = false;
        for slot in &self.groups {
            match slot.supervisor.stop().await {
                Ok(_) => any_stopped = true,
                Err(EngineError::NotRunning) => {}
                Err(_) => any_failed = true,
            }
        }
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                match slot.supervisor().stop().await {
                    Ok(_) => any_stopped = true,
                    Err(EngineError::NotRunning) => {}
                    Err(_) => any_failed = true,
                }
            }
        }
        if any_failed {
            return Err(StopFailure::StopFailed);
        }
        if !any_stopped {
            return Err(StopFailure::NotRunning);
        }
        Ok(self.status().await)
    }

    /// Bounded teardown of the whole pool; used by host session end and
    /// signals. Legacy groups and dynamic slots stop **in parallel** under one
    /// global deadline (design §6.4/F7): the pre-pool loop was sequential, so
    /// ten engines at the old 5 s wait could hold process exit for 50 s. A
    /// slot that misses the deadline has its shutdown future dropped, which
    /// drops the engine handle and kills the child (`kill_on_drop`).
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.running.store(false, Ordering::Release);
        self.publish_running();
        let budget = self
            .pool
            .as_ref()
            .map(|pool| pool.policy().shutdown_budget)
            .unwrap_or(crate::pool::POOL_SHUTDOWN_BUDGET);
        let deadline = Instant::now() + budget;
        let mut identities: Vec<(Option<String>, String, Arc<RuntimeSupervisor>)> =
            Vec::with_capacity(self.groups.len());
        for slot in &self.groups {
            identities.push((None, slot.id.clone(), Arc::clone(&slot.supervisor)));
        }
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                identities.push((
                    Some(slot.account_id().to_string()),
                    slot.proxy_group().to_string(),
                    Arc::clone(slot.supervisor()),
                ));
            }
        }
        let futures = identities
            .into_iter()
            .map(|(_account_id, _group_id, supervisor)| {
                async move {
                    // Shut every remaining slot down even when one fails. The
                    // remaining global budget is passed into the supervisor so
                    // expiry force-kills the child while the handle is still
                    // owned (a dropped future would leave the actor's handle
                    // clone keeping the process alive).
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    supervisor.shutdown_within(Some(remaining)).await
                }
            });
        let mut first_error = None;
        for result in join_all(futures).await {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Union of every slot's live accounts (implementation-plan §4.4:
    /// `accounts.list` items gain an always-present `proxyGroup`). All slots
    /// are asked **in parallel** under one budget (design F9); a slot that
    /// misses it degrades to its local store rows, so a single wedged engine
    /// cannot stretch the host's list latency to O(N × engine timeout).
    /// Read the account terminal state through the shared router. Used by
    /// the host mutating gate before any send-family method reaches an engine.
    pub async fn account_state(
        &self,
        account_id: &str,
    ) -> Result<Option<&'static str>, ServiceError> {
        let service = self.router.lock().await;
        service.account_state(account_id)
    }

    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>, ServiceError> {
        let budget = self
            .pool
            .as_ref()
            .map(|pool| pool.policy().list_accounts_budget)
            .unwrap_or(crate::pool::LIST_ACCOUNTS_BUDGET);
        let deadline = Instant::now() + budget;
        let mut slots: Vec<(Option<String>, String, Arc<RuntimeSupervisor>)> =
            Vec::with_capacity(self.groups.len());
        for slot in &self.groups {
            slots.push((None, slot.id.clone(), Arc::clone(&slot.supervisor)));
        }
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                slots.push((
                    Some(slot.account_id().to_string()),
                    slot.proxy_group().to_string(),
                    Arc::clone(slot.supervisor()),
                ));
            }
        }
        let futures = slots.iter().map(|(_, _, supervisor)| {
            let supervisor = Arc::clone(supervisor);
            async move { timeout_at(deadline, supervisor.list_accounts()).await }
        });
        let results = join_all(futures).await;
        let mut accounts = Vec::new();
        let mut first_error: Option<ServiceError> = None;
        for ((account_id, group_id, supervisor), result) in slots.into_iter().zip(results) {
            match result {
                Ok(Ok(rows)) => accounts.extend(rows),
                Ok(Err(error)) => {
                    // An engine/store failure already degraded inside the
                    // supervisor where it could; try the local rows once
                    // more, then keep the error for the final answer.
                    match supervisor.list_local_accounts().await {
                        Ok(rows) => {
                            tracing::warn!(
                                account_id = account_id.as_deref().unwrap_or("-"),
                                group_id = %group_id,
                                error_class = error.class(),
                                "account listing degraded to local rows"
                            );
                            accounts.extend(rows);
                        }
                        Err(_) => {
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Deadline missed: answer from this slot's local rows.
                    match supervisor.list_local_accounts().await {
                        Ok(rows) => {
                            tracing::warn!(
                                account_id = account_id.as_deref().unwrap_or("-"),
                                group_id = %group_id,
                                budget_ms = budget.as_millis().min(u64::MAX as u128) as u64,
                                "account listing deadline missed; degraded to local rows"
                            );
                            accounts.extend(rows);
                        }
                        Err(error) => {
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                        }
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(accounts),
        }
    }

    /// Resolve the optional `link.start` proxyGroup to its plan id. Absent
    /// means `default`; anything outside the launch plan fails closed (R1/R9).
    /// The returned id is the account's immutable binding whichever runtime
    /// mode is active; full pooling never touches a group engine.
    fn link_group_id(&self, proxy_group: Option<&str>) -> Result<String, ApiError> {
        let requested = proxy_group.unwrap_or(DEFAULT_PROXY_GROUP_ID);
        if self.group_ids.iter().any(|id| id == requested) {
            Ok(requested.to_string())
        } else {
            Err(ApiError::new(
                "PROXY_GROUP_NOT_FOUND",
                format!("proxy group '{requested}' is not configured in this connector"),
                false,
            ))
        }
    }

    /// An account-less engine target for the sticker-pack faces (§4.32).
    /// Legacy mode uses the reserved `default` group. Full pooling has no
    /// group engine, so the first running account engine answers — a known
    /// S1 limitation (the design's shared anonymous slot is deferred); with
    /// nothing running the call honestly answers RUNTIME_NOT_RUNNING.
    async fn default_slot(&self) -> Result<Arc<ProxyGroupSlot>, ServiceError> {
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                if slot.supervisor().status().await.state == EngineState::Running {
                    return Ok(slot.routing());
                }
            }
            return Err(ServiceError::Engine(EngineError::NotRunning));
        }
        self.groups
            .iter()
            .find(|slot| slot.id == DEFAULT_PROXY_GROUP_ID)
            .cloned()
            .ok_or_else(|| {
                ServiceError::Api(ApiError::new(
                    "RUNTIME_NOT_RUNNING",
                    "the default proxy group is not configured in this connector",
                    false,
                ))
            })
    }

    /// `link.start`. With the per-account pool enabled the new link gets a
    /// pre-allocated account id, its own `<signal-data>/engines/<accountId>`
    /// data directory, its own supervisor/engine, and a proxy group binding
    /// taken from the launcher plan (design §5.3). Budget accounting:
    /// the admission lock is held only for the QR mint, never across
    /// `link.finish`'s phone-approval wait.
    pub async fn start_link(
        self: &Arc<Self>,
        device_name: String,
        proxy_group: Option<String>,
    ) -> Result<Value, ServiceError> {
        let group_id = self
            .link_group_id(proxy_group.as_deref())
            .map_err(ServiceError::Api)?;
        let Some(pool) = &self.pool else {
            let slot = self
                .groups
                .iter()
                .find(|slot| slot.id == group_id)
                .cloned()
                .expect("the legacy plan always contains the selected group slot");
            return slot.supervisor.start_link(device_name).await;
        };
        if !self.running.load(Ordering::Acquire) {
            // The pre-pool path answers RUNTIME_NOT_RUNNING from the engine
            // slot; keep that exact error class without provisioning a
            // directory that can never mint a QR.
            return Err(ServiceError::Engine(EngineError::NotRunning));
        }
        // A previous attempt whose QR expired (or whose finish was never
        // answered) must not hold one of the eight slots against this fresh
        // link. The reaper is the same lease-based reclaim every terminal
        // answer uses; running one pass here makes the free slot immediate
        // instead of waiting for the 30 s tick.
        self.reap_uncommitted_links().await;
        let _admission = pool.lock_admission().await;
        let account = pool.provision_slot(&group_id)?;
        // The slot is owned by the attempt, never by the preallocated account
        // id: mint the host-facing `linkAttemptId` before the engine is asked
        // for a code, open the lease, and let the guard below be the one
        // authority that either persists it (a live QR) or reclaims it (every
        // early exit).
        let attempt_id = crate::ids::random_id();
        let guard =
            match crate::pool::LinkAttemptGuard::open(Arc::clone(pool), &account, &attempt_id) {
                Some(guard) => guard,
                None => {
                    self.rollback_account_slot(&account).await;
                    return Err(ServiceError::Api(ApiError::new(
                        "CAPABILITY_UNAVAILABLE",
                        "the link attempt could not claim its engine slot",
                        false,
                    )));
                }
            };
        // Contract 1.275: a fresh link is the one human intent that may replace
        // a terminal `device_unlinked` verdict, so the slot's latch is cleared
        // before its QR engine is woken. Without this a re-link could only ever
        // answer ACCOUNT_UNLINKED and the account would stay unrecoverable. The
        // store row keeps its terminal state until link.finish commits the new
        // device (contract 1.275 owns that write).
        account.supervisor().clear_device_unlinked();
        self.spawn_account_forwarders(&account);
        self.ensure_history_retention(account.supervisor());
        // Start the account's engine before the QR mint (a fresh slot has no
        // process yet; the supervisor's engine lock keeps this single).
        //
        // Contract 1.291 (§4.277 C): this used to call the supervisor directly,
        // which was the one start face the store gate did not see. It now goes
        // through the pool's **waiting** wake: a link is a human flow with its
        // own budget, so it runs the migration inline instead of being told to
        // come back, and no path can spawn this engine without the gate's word.
        match pool.wake_slot_waiting(&account).await {
            Ok(()) => {}
            Err(refusal) => {
                self.settle_link_attempt(Some(guard), &account).await;
                return Err(refusal.into_service_error());
            }
        }
        match account
            .supervisor()
            .start_link_with_attempt(device_name, Some(attempt_id.clone()))
            .await
        {
            Ok(value) => {
                if let Some(session) = value.get("linkSessionId").and_then(Value::as_str) {
                    pool.remember_session(session, account.account_id());
                }
                pool.note_activity(&account);
                // A live QR exists: the attempt owns the slot until its
                // terminal answer. The lease record persists in the pool and
                // the guard disarms (its Drop must not reclaim a live link).
                guard.persist();
                tracing::info!(
                    account_id = %account.account_id(),
                    group_id = %account.proxy_group(),
                    "per-account link slot opened"
                );
                Ok(value)
            }
            Err(error) => {
                self.settle_link_attempt(Some(guard), &account).await;
                Err(error)
            }
        }
    }

    /// Settle one pooled link attempt through the single reclaim path. Every
    /// terminal caller (start rollback, finish failure/timeout, cancel) funnels
    /// here; the guard's own Drop is the no-bypass net behind it.
    async fn settle_link_attempt(
        &self,
        guard: Option<crate::pool::LinkAttemptGuard>,
        account: &Arc<crate::pool::AccountSlot>,
    ) -> crate::pool::LinkReclaimOutcome {
        match guard {
            Some(guard) => {
                let outcome = guard.reclaim().await;
                // Promoted means a committed row won the race: the slot is
                // still live, so its forwarders must stay. Only an actual
                // teardown releases them.
                if matches!(
                    outcome,
                    crate::pool::LinkReclaimOutcome::Reclaimed
                        | crate::pool::LinkReclaimOutcome::Quarantined
                ) {
                    self.forget_account_forwarders(account.account_id());
                }
                outcome
            }
            None => {
                self.rollback_account_slot(account).await;
                crate::pool::LinkReclaimOutcome::AlreadySettled
            }
        }
    }

    /// Tear a just-provisioned slot back down (link.start failed before any
    /// account was committed). The directory holds no credentials yet, so the
    /// delete is always safe (design §5.3 step ⑧).
    async fn rollback_account_slot(&self, account: &Arc<crate::pool::AccountSlot>) {
        if let Some(pool) = &self.pool {
            pool.discard(account.account_id(), true).await;
        }
        self.forget_account_forwarders(account.account_id());
    }

    /// Which proxy group owns a link session (expired sessions included, so
    /// the dispatched finish still answers the distinct LINK_EXPIRED). None
    /// means no live session anywhere. A dynamic session reports its proxy
    /// group: the host's per-group finish lane keeps its pre-pool shape, and
    /// two accounts in one group serialize their finishes exactly like two
    /// legacy links in one group always did.
    pub async fn resolve_link_session(&self, link_session_id: &str) -> Option<String> {
        match self.link_owner(link_session_id).await {
            Ok(LinkOwner::Group(slot)) => Some(slot.id.clone()),
            Ok(LinkOwner::Account(slot)) => Some(slot.proxy_group().to_string()),
            Err(_) => None,
        }
    }

    /// Which slot owns a link attempt (the `link.rotate` routing face). The
    /// attempt lives in exactly one supervisor's service table; the same
    /// bounded scan the finish face uses is the authority.
    async fn link_attempt_owner(&self, link_attempt_id: &str) -> Result<LinkOwner, ServiceError> {
        for slot in &self.groups {
            if slot
                .supervisor
                .service()
                .lock()
                .await
                .has_link_attempt(link_attempt_id)
            {
                return Ok(LinkOwner::Group(Arc::clone(slot)));
            }
        }
        if let Some(pool) = &self.pool {
            for slot in pool.slots() {
                if slot
                    .supervisor()
                    .service()
                    .lock()
                    .await
                    .has_link_attempt(link_attempt_id)
                {
                    return Ok(LinkOwner::Account(slot));
                }
            }
        }
        Err(ServiceError::Api(ApiError::new(
            "LINK_ATTEMPT_NOT_FOUND",
            "link attempt was not found",
            false,
        )))
    }

    async fn link_owner(&self, link_session_id: &str) -> Result<LinkOwner, ServiceError> {
        for slot in &self.groups {
            if slot
                .supervisor
                .service()
                .lock()
                .await
                .has_link_session(link_session_id)
            {
                return Ok(LinkOwner::Group(Arc::clone(slot)));
            }
        }
        if let Some(pool) = &self.pool {
            if let Some(account_id) = pool.session_owner(link_session_id)
                && let Some(slot) = pool.get(&account_id)
                // QR B1: pooled routing follows the same rule as the legacy
                // group scan above — the owning service's session table is the
                // authority, and it keeps lost sessions addressable so their
                // finish answers LINK_LOST instead of LINK_NOT_FOUND. A stale
                // pool map entry (the slot no longer owns that id) does not
                // route.
                && slot
                    .supervisor()
                    .service()
                    .lock()
                    .await
                    .has_link_session(link_session_id)
            {
                return Ok(LinkOwner::Account(slot));
            }
            // Contract 1.286 (§4.272): a rotated slot's session id was minted
            // after the pool registered the attempt, so the session map never
            // saw it. The bounded slot scan is the same authority rule, and a
            // pool holds at most the engine ceiling of slots.
            for slot in pool.slots() {
                if slot
                    .supervisor()
                    .service()
                    .lock()
                    .await
                    .has_link_session(link_session_id)
                {
                    return Ok(LinkOwner::Account(slot));
                }
            }
        }
        Err(ServiceError::Api(ApiError::new(
            "LINK_NOT_FOUND",
            "link session was not found",
            false,
        )))
    }

    pub async fn finish_link(
        &self,
        link_session_id: String,
    ) -> Result<AccountSummary, ServiceError> {
        match self.link_owner(&link_session_id).await? {
            LinkOwner::Group(slot) => slot.supervisor.finish_link(link_session_id).await,
            LinkOwner::Account(slot) => {
                // The attempt lease is resumed before the supervisor call, so
                // every exit below — success, a commit against another row, a
                // definite finish failure, a timeout — settles it through the
                // one promote/reclaim pair. The guard's Drop is the net for a
                // panic or a future early return.
                let guard = self.link_attempt_guard(&slot);
                // [link-stage] BUG-5 取证：槽转正计时从 registry 受理起算，
                // 与 supervisor 的 link-register 行同窗口（仅日志，零行为变更）。
                let slot_stage_started = std::time::Instant::now();
                let summary = slot.supervisor().finish_link(link_session_id.clone()).await;
                match summary {
                    Ok(summary) if summary.id == slot.account_id() => {
                        // Contract 1.275: the commit cleared the store's
                        // terminal state, so the slot's own latch follows - a
                        // device that just re-linked may serve again.
                        slot.supervisor().clear_device_unlinked();
                        if let Some(pool) = &self.pool {
                            pool.mark_provisioned(&slot);
                            pool.forget_session(&link_session_id);
                            pool.note_activity(&slot);
                        }
                        // The attempt committed: its lease is promoted to the
                        // account row and can never reclaim this slot again.
                        self.promote_link_attempt(guard, &slot);
                        // [link-stage] 槽转正完成（sidecar 已置 provisioned、会话
                        // 映射已释放）。elapsed 与 link-register 同窗口，可相减。
                        crate::link_stage::line(
                            "slot-promote",
                            slot_stage_started.elapsed(),
                            &link_session_id,
                            Some(slot.account_id()),
                            "pool slot provisioned",
                        );
                        tracing::info!(
                            account_id = %slot.account_id(),
                            group_id = %slot.proxy_group(),
                            "per-account link committed"
                        );
                        // §4.279: the commit takes a parked terminal number
                        // over; the replaced account's slot and files must not
                        // outlive the fresh link (an explicit delete already
                        // discards its slot in the same call, so a parked
                        // terminal slot with no store row is exactly the
                        // takeover residue).
                        self.reap_replaced_terminal_accounts(&summary.id).await;
                        Ok(summary)
                    }
                    Ok(summary) => {
                        // The number already belongs to another local account:
                        // committing it here would produce two engines for one
                        // account (I1). The freshly linked device/data-dir is
                        // reclaimed and the caller is told to delete the old
                        // local data before linking again.
                        if let Some(pool) = &self.pool {
                            pool.forget_session(&link_session_id);
                        }
                        self.settle_link_attempt(guard, &slot).await;
                        tracing::warn!(
                            account_id = %slot.account_id(),
                            existing_account_id = %summary.id,
                            "link landed on an already-linked number; the per-account slot was rolled back"
                        );
                        Err(account_already_linked_error())
                    }
                    Err(error) => {
                        // The three terminal answers — a definite finish
                        // failure, a cancellation, and a timeout/unknown
                        // outcome — all converge on the same idempotent
                        // reclaim. A retryable refusal (a concurrent finish
                        // lane, store hiccup, runtime not running) keeps the
                        // lease for its retry; that is not a terminal answer.
                        if Self::link_finish_is_terminal(&error) {
                            self.settle_link_attempt(guard, &slot).await;
                        } else if let Some(guard) = guard {
                            // A retryable refusal is not a terminal answer:
                            // the live attempt keeps its lease for the retry.
                            // Persist explicitly so the guard's Drop cannot
                            // mistake the early return for an abandoned link.
                            guard.persist();
                        }
                        Err(error)
                    }
                }
            }
        }
    }

    /// The attempt lease guard for one pooled slot, when the slot is leased.
    fn link_attempt_guard(
        &self,
        slot: &Arc<crate::pool::AccountSlot>,
    ) -> Option<crate::pool::LinkAttemptGuard> {
        let pool = self.pool.as_ref()?;
        let attempt_id = slot.lease_attempt_id()?;
        Some(crate::pool::LinkAttemptGuard::resume(
            Arc::clone(pool),
            &attempt_id,
        ))
    }

    /// Promote one attempt's lease (or the slot's residual lease if the guard
    /// was already gone). Promotion is idempotent and never deletes the slot.
    fn promote_link_attempt(
        &self,
        guard: Option<crate::pool::LinkAttemptGuard>,
        slot: &Arc<crate::pool::AccountSlot>,
    ) {
        if let Some(guard) = guard {
            let _ = guard.promote();
            return;
        }
        if let (Some(pool), Some(attempt_id)) = (&self.pool, slot.lease_attempt_id()) {
            pool.promote_link_attempt(&attempt_id);
        }
    }

    /// Whether a finish error is a **terminal** answer: the attempt can never
    /// commit again, so its preallocated slot must be reclaimed. Retryable
    /// refusals (a concurrent finish, a store hiccup, a stopped runtime) and
    /// protocol anomalies that leave the session alive are not in this set.
    fn link_finish_is_terminal(error: &ServiceError) -> bool {
        const TERMINAL: &[&str] = &[
            "LINK_OUTCOME_UNKNOWN",
            "LINK_LOST",
            "LINK_EXPIRED",
            "LINK_NOT_FOUND",
            "LINK_CANCELLED",
            "ACCOUNT_LIMIT_REACHED",
            "ACCOUNT_DELETE_IN_PROGRESS",
            "ACCOUNT_DELETE_OUTCOME_UNKNOWN",
        ];
        match error {
            ServiceError::Api(api) => TERMINAL.contains(&api.code),
            // The terminal link codes ride their engine shape through the
            // supervisor (LINK_LOST in particular); into_api wraps them
            // verbatim, so the reclaim decision cannot depend on the error
            // having already been flattened.
            ServiceError::Engine(EngineError::UpstreamCode { code, .. }) => TERMINAL.contains(code),
            _ => false,
        }
    }

    /// `link.rotate` (contract 1.286, §4.272): route the attempt to the slot
    /// that minted it. The attempt lives in exactly one supervisor's service
    /// table, so the same bounded scan the finish face uses is the authority;
    /// a rotation never provisions a second pool slot (the attempt keeps its
    /// engine, its data directory, and its binding).
    pub async fn rotate_link(&self, link_attempt_id: String) -> Result<Value, ServiceError> {
        match self.link_attempt_owner(&link_attempt_id).await? {
            LinkOwner::Group(slot) => slot.supervisor.rotate_link(link_attempt_id).await,
            LinkOwner::Account(slot) => {
                let result = slot.supervisor().rotate_link(link_attempt_id).await;
                if let Some(pool) = &self.pool {
                    pool.note_activity(&slot);
                }
                result
            }
        }
    }

    pub async fn cancel_link(&self, link_session_id: String) -> Result<Value, ServiceError> {
        match self.link_owner(&link_session_id).await? {
            LinkOwner::Group(slot) => slot.supervisor.cancel_link(link_session_id).await,
            LinkOwner::Account(slot) => {
                let guard = self.link_attempt_guard(&slot);
                let result = slot.supervisor().cancel_link(link_session_id.clone()).await;
                if let Some(pool) = &self.pool {
                    pool.forget_session(&link_session_id);
                }
                // An uncommitted link's directory holds no credentials: the
                // attempt's lease reclaims the slot through the same path the
                // finish failure and timeout take. A committed slot stays
                // (cancelling an already-committed session has nothing to
                // roll back) and its lease was already promoted.
                if !slot.is_provisioned() {
                    self.settle_link_attempt(guard, &slot).await;
                } else if let Some(guard) = guard {
                    // Defensive: a committed slot should carry no lease, but a
                    // residual one must never survive a cancel as a live
                    // reclaim candidate.
                    let _ = guard.promote();
                }
                result
            }
        }
    }

    /// Route by account. Full pooling consults **only** the per-account slot
    /// table (the binding column degenerates to accountId → engine); a cold
    /// slot wakes first, so the first request after a restart is served
    /// instead of answered RUNTIME_NOT_RUNNING. Legacy mode keeps the
    /// immutable group binding and the exact pre-pool error ladder, including
    /// the dormant answer for a group the launch plan does not contain.
    async fn slot_for_account(
        &self,
        account_id: &str,
    ) -> Result<Arc<ProxyGroupSlot>, ServiceError> {
        if let Some(pool) = &self.pool {
            let Some(slot) = pool.get(account_id) else {
                // Full pooling has no legacy fallback: an account row without
                // a slot is a broken pool (a migration/consistency bug), and
                // an unknown id keeps ACCOUNT_NOT_FOUND.
                return match self
                    .router_service()
                    .lock()
                    .await
                    .account_proxy_group(account_id)
                {
                    Ok(_) => Err(engine_not_provisioned_error()),
                    Err(error) => Err(error),
                };
            };
            if self.running.load(Ordering::Acquire) {
                pool.ensure_resident(&slot).await?;
            }
            return Ok(slot.routing());
        }
        let group = self
            .router_service()
            .lock()
            .await
            .account_proxy_group(account_id)?;
        self.groups
            .iter()
            .find(|slot| slot.id == group)
            .cloned()
            .ok_or_else(|| {
                ServiceError::Api(ApiError::new(
                    "CAPABILITY_UNAVAILABLE",
                    format!("account proxy group '{group}' is not configured in this connector"),
                    false,
                ))
            })
    }

    /// The v1-compatible delete of an account that has no local row (or an
    /// idempotent replay of an already-completed delete) in full-pool mode.
    /// There is no group supervisor to borrow, so the store-only plan runs
    /// through the shared routing service. A row that exists without a slot
    /// is a broken pool and fails closed.
    async fn delete_absent_account(
        &self,
        account_id: &str,
        operation_id: Option<String>,
    ) -> Result<Value, ServiceError> {
        if let Some(operation_id) = operation_id.as_deref() {
            crate::service::validate_account_delete_operation_id(operation_id)?;
        }
        let mut service = self.router_service().lock().await;
        if let Some(operation_id) = operation_id.as_deref() {
            match service.prepare_account_delete(account_id, operation_id)? {
                AccountDeletePlan::Completed => {
                    return Ok(account_delete_result(
                        service
                            .store_ref()
                            .account_delete_receipt(account_id)
                            .ok()
                            .flatten(),
                    ));
                }
                AccountDeletePlan::Dispatch { .. } => {
                    return Err(engine_not_provisioned_error());
                }
            }
        }
        if service
            .account_signal_number_optional(account_id)?
            .is_some()
        {
            return Err(engine_not_provisioned_error());
        }
        Ok(account_delete_result(
            service
                .store_ref()
                .account_delete_receipt(account_id)
                .ok()
                .flatten(),
        ))
    }

    /// The shared routing service over the one per-instance store.
    fn router_service(&self) -> &Arc<Mutex<ConnectorService>> {
        &self.router
    }

    /// The engine-free local delete (M6 D3 review M2).
    ///
    /// Used only when the store-migration gate refuses this slot an engine: an
    /// account whose engine can never start still has to be deletable, because
    /// "delete its local data and link it again" is the remedy its own block
    /// message states. Everything the engine's `deleteLocalAccountData` would
    /// have erased locally is covered here — the store rows, the media handles
    /// and files, the plaintext-backup scrub, the §4.197 file half (M6 D3
    /// follow-up, `clear_account_delete_files`) — and the slot directory
    /// itself is removed wholesale, so the engine-owned files (and the store it
    /// could not open) go with it.
    async fn delete_account_without_engine(
        &self,
        account_id: &str,
        operation_id: Option<String>,
    ) -> Result<Value, ServiceError> {
        // The same ladder the engine path opens with (`RuntimeSupervisor::
        // delete_local_account`) and the absent-account replay in this file
        // uses: a malformed operationId is a caller bug and is refused before
        // the idempotency ledger sees it. Bypassing the engine must not bypass
        // the bound — least of all here, where this branch exists precisely to
        // keep the delete answerable.
        if let Some(operation_id) = operation_id.as_deref() {
            crate::service::validate_account_delete_operation_id(operation_id)?;
        }
        let receipt = {
            let mut service = self.router_service().lock().await;
            if let Some(operation_id) = operation_id.as_deref()
                && let AccountDeletePlan::Completed =
                    service.prepare_account_delete(account_id, operation_id)?
            {
                // An idempotent replay: the rows are already gone. The
                // supervisor's own Completed arm still clears the account's
                // residue, so this path runs the same scrub and file cleanup
                // below instead of returning early with the receipt alone.
                service
                    .store_ref()
                    .account_delete_receipt(account_id)
                    .ok()
                    .flatten()
            } else {
                let receipt = service
                    .complete_account_delete_recorded(account_id, operation_id.as_deref())?;
                // ADR 0004 gate 3: a chunk-stream handle cannot outlive the
                // account session it was opened from.
                service.clear_media_for_account(account_id);
                receipt
            }
        };
        // §4.197: the scrub is VACUUM-sized blocking work — off the async
        // threads and outside the service lock, exactly like the supervisor's
        // engine-path sibling.
        let store = Arc::clone(&self.store);
        let scrub_id = account_id.to_string();
        let receipt = match receipt {
            Some(receipt) => {
                match tokio::task::spawn_blocking(move || {
                    store.finish_account_delete_residue(&scrub_id)
                })
                .await
                {
                    Ok(Ok(residue)) => residue.or(Some(receipt)),
                    _ => Some(receipt),
                }
            }
            None => None,
        };
        // §4.197 file half, before the slot goes: the shared handle tables and
        // the state-dir products outlive `pool.discard`.
        self.clear_account_delete_files(account_id);
        if let Some(pool) = &self.pool {
            pool.discard(account_id, true).await;
        }
        self.forget_account_forwarders(account_id);
        Ok(account_delete_result(receipt))
    }

    /// The §4.197 file half of an account delete, for the engine-free path
    /// (M6 D3 follow-up).
    ///
    /// The engine path clears this through its supervisor
    /// (`supervisor.rs` `clear_account_delete_files`), which a slot the
    /// store-migration gate refuses never has. What survives `pool.discard`
    /// is here, so here is where it is cleared:
    ///
    /// - the process-wide §4.46 backup file-handle table — a handle cannot
    ///   outlive the account session it was opened from (its residual cap and
    ///   addressability would otherwise survive the account);
    /// - this account's §4.115 `state-dir` plaintext export products — an
    ///   export never outlives its account, which is the whole point of the
    ///   delete remedy ("delete its local data and link it again").
    ///
    /// The slot-local in-memory caches the supervisor's version also clears
    /// (`plaintext_tasks`, skip counters, receipt failures, resync stamps,
    /// cancel flags) die with the supervisor `pool.discard` stops, so they
    /// need no entry here.
    fn clear_account_delete_files(&self, account_id: &str) {
        if let Ok(handles) = self.backup_handles.lock()
            && let Some(handles) = handles.as_ref()
        {
            handles.clear_account(account_id);
        }
        crate::backup_export::clear_plaintext_artifacts(self.store.state_dir(), account_id);
    }

    /// §4.279: reap what a re-link takeover replaced.
    ///
    /// The commit dropped the parked `device_unlinked` account's rows and
    /// rebound the number to the freshly linked slot. The replaced account's
    /// per-account engine slot, media handles, §4.197 file half, and
    /// plaintext-backup residue must not outlive it — that slot can never
    /// serve again (its credential is dead) and its directory is exactly the
    /// stale data the re-link superseded.
    ///
    /// The scan is safe by construction: an explicit local-data delete
    /// discards its slot in the same call, so a slot that still reports the
    /// terminal `device_unlinked` verdict while holding **no** store row can
    /// only be a replaced row (a store hiccup leaves the row in place and is
    /// skipped). Idempotent: a second pass finds nothing.
    async fn reap_replaced_terminal_accounts(&self, keep_account_id: &str) {
        let Some(pool) = &self.pool else {
            return;
        };
        for slot in pool.slots() {
            let account_id = slot.account_id().to_string();
            if account_id == keep_account_id {
                continue;
            }
            if !slot.supervisor().account_is_device_unlinked(&account_id) {
                continue;
            }
            match self.store.account_summary(&account_id) {
                Ok(None) => {}
                // The row is still there (or the store could not answer):
                // nothing was taken over, never touch the slot.
                Ok(Some(_)) | Err(_) => continue,
            }
            {
                let service = self.router_service().lock().await;
                service.clear_media_for_account(&account_id);
            }
            self.clear_account_delete_files(&account_id);
            let store = Arc::clone(&self.store);
            let scrub_id = account_id.clone();
            let _ =
                tokio::task::spawn_blocking(move || store.finish_account_delete_residue(&scrub_id))
                    .await;
            pool.discard(&account_id, true).await;
            self.forget_account_forwarders(&account_id);
            tracing::info!(
                account_id = %account_id,
                replacement_account_id = %keep_account_id,
                "a re-link reaped the replaced terminal account"
            );
        }
    }

    pub async fn delete_local_account(
        &self,
        account_id: String,
        operation_id: Option<String>,
    ) -> Result<Value, ServiceError> {
        // Delete idempotency lives in the shared operation ledger, not in the
        // routing row: once the account rows are gone, a replayed operationId
        // (or a v1-compatible delete of an absent account) must still resolve
        // through `prepare_account_delete` instead of answering
        // ACCOUNT_NOT_FOUND from the failed route lookup. Absent-account plans
        // complete inside the store and never touch an engine, so serving them
        // through any supervisor — all share one store — is group-agnostic.
        if let Some(pool) = &self.pool {
            let Some(slot) = pool.get(&account_id) else {
                return self.delete_absent_account(&account_id, operation_id).await;
            };
            if self.running.load(Ordering::Acquire) {
                // A delete is a human flow with its own budget (contract 1.291):
                // it waits for a migration pass rather than being answered "not yet".
                match pool.wake_slot_waiting(&slot).await {
                    Ok(()) => {}
                    // M2 (M6 D3 review): the store-migration gate may refuse
                    // this slot an engine. It must not thereby refuse the user
                    // the one action the gate's own message names ("delete its
                    // local data and link it again"), so the delete takes the
                    // engine-free path instead of being vetoed by a gate that
                    // is about serving traffic.
                    //
                    // Contract 1.275: the same rule covers the terminal
                    // `device_unlinked` slot. Its engine is stopped and its
                    // credential is dead, so an engine would only answer 401 -
                    // and the delete is exactly the remedy its own state names.
                    // Refusing it here would make the account undeletable and
                    // therefore unlinkable forever (the permanent-hang shape).
                    Err(refusal) if refusal.permits_engine_free_flow() => {
                        tracing::warn!(
                            account = %crate::pool::account_fingerprint(&account_id),
                            reason = if refusal.is_migration_gate() {
                                "storeMigration"
                            } else {
                                "deviceUnlinked"
                            },
                            "this slot cannot be served by an engine; deleting the local data without one"
                        );
                        return self
                            .delete_account_without_engine(&account_id, operation_id)
                            .await;
                    }
                    Err(refusal) => return Err(refusal.into_service_error()),
                }
            }
            let result = slot
                .supervisor()
                .delete_local_account(account_id.clone(), operation_id)
                .await;
            // A committed per-account slot owns a whole data directory: stop
            // its engine and delete the credentials (I5: after the process is
            // gone). Media is connector-owned (media/<accountId>) and is not
            // part of the engine directory, so this never touches another
            // account's media.
            if result.is_ok() {
                pool.discard(slot.account_id(), true).await;
                self.forget_account_forwarders(slot.account_id());
            }
            return result;
        }
        match self.slot_for_account(&account_id).await {
            Ok(slot) => {
                slot.supervisor
                    .delete_local_account(account_id.clone(), operation_id)
                    .await
            }
            Err(ServiceError::Store(StoreError::AccountNotFound)) => {
                self.groups[0]
                    .supervisor
                    .delete_local_account(account_id.clone(), operation_id)
                    .await
            }
            Err(error) => Err(error),
        }
    }

    pub async fn list_conversations(
        &self,
        account_id: String,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<Page<ConversationSummary>, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .list_conversations(account_id, limit, cursor)
            .await
    }

    /// history.importStatus (contract revision 1.39, §4.38): routed to the
    /// owning group's supervisor like every store-only read — all supervisors
    /// share one store, but the owning slot keeps the account-scoped shape
    /// uniform (unknown accounts answer ACCOUNT_NOT_FOUND the same way).
    pub async fn history_import_status(&self, account_id: String) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor.history_import_status(account_id).await
    }

    /// history.importRetry (contract revision 1.53, §4.38): the failed row
    /// and the archive face live with the account's group, so the re-arm
    /// routes through the account's owning supervisor like every other
    /// mutating face.
    pub async fn history_import_retry(&self, account_id: String) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor.history_import_retry(account_id).await
    }

    /// history.importCancel (contract revision 1.148, §4.146): the cancel
    /// marker, the live-pass abort, and the engine face all live with the
    /// account's group, so the cancel routes through the owning supervisor
    /// like every other mutating face.
    pub async fn history_import_cancel(&self, account_id: String) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor.history_import_cancel(account_id).await
    }

    /// history.attachmentDownload (contract revision 1.57, §4.38 step 3):
    /// the pointer face and the destination directory live with the
    /// account's group, so the chain routes through the owning supervisor
    /// like every other mutating face.
    pub async fn history_attachment_download(
        &self,
        params: crate::service::HistoryAttachmentDownloadParams,
    ) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.history_attachment_download(params).await
    }

    /// attachments.download (contract revision 1.61, §4.54): the pointer
    /// face and the destination directory live with the account's group, so
    /// the chain routes through the owning supervisor like every other
    /// mutating face.
    pub async fn attachment_download(
        &self,
        params: crate::service::AttachmentDownloadParams,
    ) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.attachment_download(params).await
    }

    /// attachments.requestBackfill (contract revision 1.175, §4.175): the
    /// backfill request addresses the account's own engine, so the call
    /// routes through the owning supervisor like every other mutating face.
    pub async fn request_attachment_backfill(
        &self,
        params: crate::service::AttachmentBackfillRequestParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.request_attachment_backfill(params).await
    }

    /// stories.downloadAttachment (contract revision 1.86, §4.71): the
    /// caller-supplied pointer face and the destination directory live with
    /// the account's group, so the chain routes through the owning
    /// supervisor like every other mutating face.
    pub async fn story_attachment_download(
        &self,
        params: crate::service::StoryAttachmentDownloadParams,
    ) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.story_attachment_download(params).await
    }

    /// stories.openAttachment (contract revision 1.86, §4.71): the handle
    /// mints against the account's per-account handle budget, so the open
    /// routes through the owning supervisor like every read.
    pub async fn story_open_attachment(
        &self,
        params: crate::service::StoryOpenAttachmentParams,
    ) -> Result<crate::service::MediaOpenView, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.story_open_attachment(params).await
    }

    /// messages.setAttachmentDimensions (contract revision 1.271, §4.255):
    /// the owning group's local write (no engine), routed like every other
    /// account-scoped store face.
    pub async fn set_attachment_dimensions(
        &self,
        params: crate::service::MessagesSetAttachmentDimensionsParams,
    ) -> Result<crate::service::AttachmentDimensionsWriteResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_attachment_dimensions(params).await
    }

    /// messages.listAttachmentDimensions (contract revision 1.271, §4.255): the
    /// owning group's bounded read.
    pub async fn list_attachment_dimensions(
        &self,
        params: crate::service::MessagesListAttachmentDimensionsParams,
    ) -> Result<crate::service::AttachmentDimensionsListResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.list_attachment_dimensions(params).await
    }

    pub async fn list_messages(
        &self,
        account_id: String,
        conversation_id: String,
        limit: u32,
        before: Option<String>,
    ) -> Result<Page<MessageRecord>, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .list_messages(account_id, conversation_id, limit, before)
            .await
    }

    /// 契约 1.204（M4b）：以锚点为中心取窗（三段返回）。
    pub async fn list_messages_around(
        &self,
        account_id: String,
        conversation_id: String,
        anchor_message_id: Option<String>,
        limit: u32,
    ) -> Result<Option<Page<MessageRecord>>, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .list_messages_around(account_id, conversation_id, anchor_message_id, limit)
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
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .list_adjacent_media(
                account_id,
                conversation_id,
                anchor_message_id,
                direction,
                limit,
            )
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
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .search_messages(account_id, query, limit, cursor, conversation_id)
            .await
    }

    pub async fn get_message_text(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<MessageText, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .get_message_text(account_id, conversation_id, message_id)
            .await
    }

    /// messages.receipts (contract 1.190, §4.190 ⑤): the per-recipient
    /// receipt ledger read, delegated to the account's supervisor like every
    /// store-only read face.
    pub async fn get_message_receipts(
        &self,
        account_id: String,
        conversation_id: String,
        message_id: String,
    ) -> Result<Vec<crate::store::RecipientReceiptRow>, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .get_message_receipts(account_id, conversation_id, message_id)
            .await
    }

    /// events.list (contract 1.283, §4.267). The ledger is process-wide, so
    /// this read does not need an account slot — but it still routes through
    /// the one routing service that owns the store handle, the same way every
    /// other store-only read face does.
    pub async fn events_page(
        &self,
        params: EventsListParams,
    ) -> Result<EventLedgerPage, ServiceError> {
        let service = self.router.lock().await;
        service.events_page(params)
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
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .send_text(
                account_id,
                target,
                text,
                client_request_id,
                quote_message_id,
                previews,
                mentions,
                text_styles,
                story_reply_author,
                story_reply_timestamp,
            )
            .await
    }

    /// messages.getByClientRequestId (contract 1.172, §4.172): the read-only
    /// single-row probe for the desktop orphan sweep — same slot routing as
    /// the retry face (the row lives in this account's proxy group).
    pub async fn get_message_by_client_request(
        &self,
        account_id: String,
        conversation_id: String,
        client_request_id: String,
    ) -> Result<MessageRecord, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .get_message_by_client_request(account_id, conversation_id, client_request_id)
            .await
    }

    /// Same-row retry of a definitively failed send (contract 1.31): routed
    /// through the account's own proxy-group slot exactly like the original
    /// send — the retry must reach the same engine the first attempt used.
    pub async fn retry_text(
        &self,
        account_id: String,
        conversation_id: String,
        client_request_id: String,
    ) -> Result<MessageRecord, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .retry_text(account_id, conversation_id, client_request_id)
            .await
    }

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
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .send_attachment(
                account_id,
                target,
                client_request_id,
                data_base64,
                size_bytes,
                filename,
                content_type,
                text,
                quote_message_id,
                voice_note,
                view_once,
                blur_hash,
                gif,
            )
            .await
    }

    /// Retry one definitively-failed outgoing attachment in place (contract
    /// revision 1.278, §4.262; bytes optional = 1.279, §4.263; plural rebuild =
    /// 1.280, §4.264): routed through the account's own proxy-group slot exactly
    /// like the original send — the retry must reach the same engine the first
    /// attempt used, and it settles the same row, in the shape the original
    /// used. A missing dataBase64/sizeBytes pair reuses the original payload
    /// group persisted at first send (one row per attachment index).
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
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .retry_attachment(
                account_id,
                target,
                client_request_id,
                data_base64,
                size_bytes,
                filename,
                content_type,
                text,
                quote_message_id,
                voice_note,
                view_once,
                blur_hash,
                gif,
            )
            .await
    }

    /// Multi-attachment send (contract revision 1.66, §4.59): routed through
    /// the account's own proxy-group slot exactly like the singular send.
    pub async fn send_attachments_multi(
        &self,
        account_id: String,
        target: SendTarget,
        client_request_id: String,
        entries: Vec<crate::service::MessagesSendAttachmentEntry>,
        text: Option<String>,
        quote_message_id: Option<String>,
    ) -> Result<MessageRecord, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .send_attachments_multi(
                account_id,
                target,
                client_request_id,
                entries,
                text,
                quote_message_id,
            )
            .await
    }

    pub async fn send_sticker(
        &self,
        params: crate::service::MessagesSendStickerParams,
    ) -> Result<MessageRecord, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_sticker(params).await
    }

    /// Sticker pack browsing (contract 1.36, §4.32): no account context, so
    /// the call rides the default group's engine — pack browsing is
    /// anonymous CDN traffic, not account state, and the single-group
    /// deployment (the default profile) has exactly one engine to serve it.
    pub async fn get_sticker_pack_manifest(
        &self,
        params: crate::service::StickerPackManifestParams,
    ) -> Result<crate::service::StickerPackManifest, ServiceError> {
        let slot = self.default_slot().await?;
        slot.supervisor.get_sticker_pack_manifest(params).await
    }

    pub async fn get_sticker_image(
        &self,
        params: crate::service::StickerPackImageParams,
    ) -> Result<crate::service::StickerPackImage, ServiceError> {
        let slot = self.default_slot().await?;
        slot.supervisor.get_sticker_image(params).await
    }

    pub async fn get_pinned_conversations(
        &self,
        params: crate::service::ConversationsGetPinnedParams,
    ) -> Result<crate::service::PinnedConversations, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_pinned_conversations(params).await
    }

    pub async fn set_conversation_pinned(
        &self,
        params: crate::service::ConversationsSetPinnedParams,
    ) -> Result<crate::service::PinnedConversations, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_conversation_pinned(params).await
    }

    /// conversations.setExpireTimer (contract 1.42, §4.41): the timer lives
    /// with the account's engine, so the write routes through the account's
    /// owning supervisor like every other mutating face.
    pub async fn set_conversation_expire_timer(
        &self,
        params: crate::service::ConversationsSetExpireTimerParams,
    ) -> Result<crate::service::ConversationsSetExpireTimerResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_conversation_expire_timer(params).await
    }

    /// Sticker pack sync (contract 1.37, §4.34): account state — the records
    /// live in the account's storage session, so both faces route through the
    /// account's owning engine, unlike the anonymous §4.32 browse face.
    pub async fn get_sticker_pack_syncs(
        &self,
        params: crate::service::StickerPackGetSyncsParams,
    ) -> Result<crate::service::StickerPackSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_sticker_pack_syncs(params).await
    }

    pub async fn set_sticker_pack_sync(
        &self,
        params: crate::service::StickerPackSetSyncParams,
    ) -> Result<crate::service::StickerPackSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_sticker_pack_sync(params).await
    }

    /// Chat-folder sync (contract 1.95, §4.78): account state — the folders
    /// live in the account's storage session, so both faces route through the
    /// account's owning engine (the §4.34 sync-face class).
    pub async fn chat_folders_list(
        &self,
        params: crate::service::ChatFoldersListParams,
    ) -> Result<crate::service::ChatFolderSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.chat_folders_list(params).await
    }

    pub async fn chat_folders_set_records(
        &self,
        params: crate::service::ChatFoldersSetRecordsParams,
    ) -> Result<crate::service::ChatFolderSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.chat_folders_set_records(params).await
    }

    /// Notification-profile sync (contract revision 1.129, §4.110): the
    /// §4.78 routing shape — the profile records live in the account's
    /// storage session, so both faces route through the account's owning
    /// engine.
    pub async fn notification_profiles_list(
        &self,
        params: crate::service::NotificationProfilesListParams,
    ) -> Result<crate::service::NotificationProfileSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.notification_profiles_list(params).await
    }

    pub async fn notification_profiles_set_records(
        &self,
        params: crate::service::NotificationProfilesSetRecordsParams,
    ) -> Result<crate::service::NotificationProfileSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .notification_profiles_set_records(params)
            .await
    }

    /// Story-distribution-list sync (contract revision 1.130, §4.111): the
    /// §4.78 routing shape — the list records live in the account's storage
    /// session, so both faces route through the account's owning engine.
    pub async fn story_distribution_lists_list(
        &self,
        params: crate::service::StoryDistributionListsListParams,
    ) -> Result<crate::service::StoryDistributionListSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.story_distribution_lists_list(params).await
    }

    pub async fn story_distribution_lists_set_records(
        &self,
        params: crate::service::StoryDistributionListsSetRecordsParams,
    ) -> Result<crate::service::StoryDistributionListSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .story_distribution_lists_set_records(params)
            .await
    }

    /// Storage merge/import/call-link faces (contract revision 1.131,
    /// §4.112): the §4.78 routing shape — the storage session lives in the
    /// account's owning engine, so all four route through its slot.
    pub async fn storage_merge_contacts(
        &self,
        params: crate::service::StorageIngestParams,
    ) -> Result<crate::service::MergeContactsSummary, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.storage_merge_contacts(params).await
    }

    pub async fn storage_import_groups(
        &self,
        params: crate::service::StorageIngestParams,
    ) -> Result<crate::service::ImportGroupsSummary, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.storage_import_groups(params).await
    }

    pub async fn storage_get_call_links(
        &self,
        params: crate::service::StorageGetCallLinksParams,
    ) -> Result<crate::service::CallLinkSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.storage_get_call_links(params).await
    }

    pub async fn storage_set_call_link(
        &self,
        params: crate::service::StorageSetCallLinkParams,
    ) -> Result<crate::service::CallLinkSyncs, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.storage_set_call_link(params).await
    }

    /// Account settings writes (contract 1.46, §4.45): account-record state —
    /// the writes live in the account's storage session, so all three route
    /// through the account's owning engine like every other mutating face.
    pub async fn update_account_configuration(
        &self,
        params: crate::service::AccountsUpdateConfigurationParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.update_account_configuration(params).await
    }

    pub async fn set_profile(
        &self,
        params: crate::service::AccountsSetProfileParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_profile(params).await
    }

    pub async fn set_account_expire_timer(
        &self,
        params: crate::service::AccountsSetExpireTimerParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_account_expire_timer(params).await
    }

    /// conversations.getBlocked (contract 1.46, §4.45): blocked state lives
    /// in the account's storage records, so the read routes through the
    /// account's owning engine.
    pub async fn get_blocked_conversations(
        &self,
        params: crate::service::ConversationsGetBlockedParams,
    ) -> Result<crate::service::BlockedConversations, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_blocked_conversations(params).await
    }

    /// accounts.deviceCapabilities (contract revision 1.100, §4.81): the
    /// device-face registration is the account's own upstream state, so the
    /// read routes through the account's owning engine.
    pub async fn get_device_capabilities(
        &self,
        params: crate::service::AccountsDeviceCapabilitiesParams,
    ) -> Result<crate::service::AccountDeviceCapabilities, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_device_capabilities(params).await
    }

    /// accounts.getSyncState (contract revision 1.286, §4.281): the login
    /// window projection lives in the account's owning engine process, so the
    /// read routes there (pure snapshot, never a transition).
    pub async fn get_sync_state(
        &self,
        params: crate::service::AccountsGetSyncStateParams,
    ) -> Result<crate::service::AccountSyncState, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_sync_state(params).await
    }

    /// accounts.getDevices (contract revision 1.122, §4.103): the device list
    /// is the account's own upstream state, so the read routes through the
    /// account's owning engine.
    pub async fn get_devices(
        &self,
        params: crate::service::AccountsGetDevicesParams,
    ) -> Result<crate::service::DeviceList, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_devices(params).await
    }

    /// accounts.unlinkDevice (contract revision 1.122, §4.103): the unlink is
    /// the account's own upstream state write, so it routes through the
    /// account's owning engine.
    pub async fn unlink_device(
        &self,
        params: crate::service::AccountsUnlinkDeviceParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.unlink_device(params).await
    }

    /// accounts.setUsername (contract 1.59, §4.55): the username is
    /// account-record upstream state, so the write routes through the
    /// account's owning engine like every other mutating face.
    pub async fn set_username(
        &self,
        params: crate::service::AccountsSetUsernameParams,
    ) -> Result<crate::service::AccountUsername, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_username(params).await
    }

    /// accounts.getUsername (contract 1.59, §4.55; the kt-engine read face
    /// opens with contract 1.74, §4.65): the read routes through the
    /// account's owning engine like every account-scoped read, so
    /// ACCOUNT_NOT_FOUND keeps its precedence — the face rides the engine's
    /// `getUsername` storage projection.
    pub async fn get_username(
        &self,
        params: crate::service::AccountsGetUsernameParams,
    ) -> Result<crate::service::AccountUsername, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_username(params).await
    }

    /// username.lookup (contract 1.59, §4.55): registration status is queried
    /// against the account's own engine session (its CDSI face), so the read
    /// routes through the account's owning engine.
    pub async fn lookup_usernames(
        &self,
        params: crate::service::UsernameLookupParams,
    ) -> Result<crate::service::UsernameLookupResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.lookup_usernames(params).await
    }

    /// phone.lookup (contract 1.164, §4.162): the number batch is resolved
    /// against the account's own engine session (its CDSI face, engine
    /// d088a59), so the read routes through the account's owning engine —
    /// ACCOUNT_NOT_FOUND keeps its precedence.
    pub async fn lookup_phones(
        &self,
        params: crate::service::PhoneLookupParams,
    ) -> Result<crate::service::PhoneLookupResult, ServiceError> {
        let slot = self.slot_for_account(&params.account).await?;
        slot.supervisor.lookup_phones(params).await
    }

    /// messages.sendStory (contract 1.76, §4.67): a story goes out through
    /// the sender account's own engine like every mutating face.
    pub async fn send_story(
        &self,
        params: crate::service::MessagesSendStoryParams,
    ) -> Result<crate::service::StorySendResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_story(params).await
    }

    /// stories.setDisabled / stories.getDisabled (contract 1.76, §4.67):
    /// the toggle is connector-local state, but it is still account-scoped —
    /// the ladder resolves the owning slot first so ACCOUNT_NOT_FOUND keeps
    /// its precedence, then the store write/read answers.
    pub async fn set_stories_disabled(
        &self,
        params: crate::service::StoriesSetDisabledParams,
    ) -> Result<crate::service::StoriesDisabled, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_stories_disabled(params).await
    }

    pub async fn get_stories_disabled(
        &self,
        params: crate::service::StoriesGetDisabledParams,
    ) -> Result<crate::service::StoriesDisabled, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_stories_disabled(params).await
    }

    /// conversations.getAvatar (contract 1.48, §4.47): the avatar bytes are
    /// account-scoped upstream state, so the read routes through the
    /// account's owning engine like every other account face.
    pub async fn get_avatar(
        &self,
        params: crate::service::ConversationsGetAvatarParams,
    ) -> Result<crate::service::AvatarDownload, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_avatar(params).await
    }

    /// conversations.setBlocked (contract 1.48, §4.47): the blocked bit
    /// lives in the account's storage records, so the write routes through
    /// the account's owning engine like every other mutating face.
    pub async fn set_conversation_blocked(
        &self,
        params: crate::service::ConversationsSetBlockedParams,
    ) -> Result<crate::service::BlockedConversations, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_conversation_blocked(params).await
    }

    /// conversations.saveDraft / conversations.clearDraft (contract 1.138,
    /// §4.130): the draft stamp is account-scoped local state, so both write
    /// faces route through the account's owning slot like every other
    /// mutating face — the engine stays out of the path (a local stamp, not
    /// upstream traffic).
    pub async fn save_conversation_draft(
        &self,
        params: crate::service::ConversationsSaveDraftParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.save_conversation_draft(params).await
    }

    pub async fn clear_conversation_draft(
        &self,
        params: crate::service::ConversationsClearDraftParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.clear_conversation_draft(params).await
    }

    /// conversations.getState / conversations.setState (contract 1.116,
    /// §4.97): the three mute/archive/unread bits live in the account's
    /// storage records, so the read and the write route through the
    /// account's owning engine like every other storage face.
    pub async fn get_conversation_state(
        &self,
        params: crate::service::ConversationsGetStateParams,
    ) -> Result<crate::service::ConversationState, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_conversation_state(params).await
    }

    pub async fn set_conversation_state(
        &self,
        params: crate::service::ConversationsSetStateParams,
    ) -> Result<crate::service::ConversationState, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.set_conversation_state(params).await
    }

    /// conversations.acceptRequest / conversations.declineRequest (contract
    /// 1.63, §4.56): the MRR sync write is account-scoped upstream traffic,
    /// so it routes through the account's owning engine like every other
    /// mutating face.
    pub async fn accept_message_request(
        &self,
        params: crate::service::MessageRequestParams,
    ) -> Result<crate::service::MessageRequestOutcome, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.accept_message_request(params).await
    }

    pub async fn decline_message_request(
        &self,
        params: crate::service::MessageRequestParams,
    ) -> Result<crate::service::MessageRequestOutcome, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.decline_message_request(params).await
    }

    /// identities.get (contract 1.68, §4.61): the safety number lives in the
    /// account's upstream identity store, so the read routes through the
    /// account's owning engine like every other account face.
    pub async fn get_identity(
        &self,
        params: crate::service::IdentitiesGetParams,
    ) -> Result<crate::service::IdentityRead, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.get_identity(params).await
    }

    /// identities.verify (contract 1.68, §4.61): the trust write is
    /// account-scoped upstream traffic, so it routes through the account's
    /// owning engine like every other mutating face.
    pub async fn verify_identity(
        &self,
        params: crate::service::IdentitiesVerifyParams,
    ) -> Result<crate::service::IdentityVerifyOutcome, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.verify_identity(params).await
    }

    /// calls.sendSignal (contract 1.50, §4.48): the signaling envelope is
    /// account-scoped upstream traffic, so the send routes through the
    /// account's owning engine like every other send face.
    pub async fn send_call_signal(
        &self,
        params: crate::service::CallsSendSignalParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_call_signal(params).await
    }

    /// calls.sendGroupCallUpdate (contract 1.127, §4.108): the group-call
    /// era update is account-scoped upstream traffic, so it routes through
    /// the account's owning engine like every other send face.
    pub async fn send_group_call_update(
        &self,
        params: crate::service::CallsSendGroupCallUpdateParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_group_call_update(params).await
    }

    /// calls.getState (contract 1.50, §4.48): a store-only read scoped to
    /// the account's owning connector slot — no engine call, no network.
    pub async fn call_state(
        &self,
        params: crate::service::CallsGetStateParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.call_state(params.account_id).await
    }

    /// calls.linkPresentation / calls.createLinkAuth / calls.groupProof /
    /// calls.groupMembers (contract 1.88, §4.73): account-addressed engine
    /// material passthrough, routed to the owning group's supervisor like
    /// every account-scoped face — the credential cache and the zkgroup
    /// chain live in that group's engine process.
    pub async fn calls_link_presentation(
        &self,
        params: crate::service::CallsLinkPresentationParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .calls_link_presentation(&params.account_id, &params.root_key)
            .await
    }

    pub async fn calls_create_link_auth(
        &self,
        params: crate::service::CallsCreateLinkAuthParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .calls_create_link_auth(&params.account_id, &params.root_key, &params.room_id)
            .await
    }

    pub async fn calls_group_proof(
        &self,
        params: crate::service::CallsGroupProofParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .calls_group_proof(&params.account_id, &params.group_id)
            .await
    }

    pub async fn calls_group_members(
        &self,
        params: crate::service::CallsGroupMembersParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .calls_group_members(&params.account_id, &params.group_id)
            .await
    }

    /// calls.endorsementsPublicKey (contract 1.88, §4.73): the one
    /// account-less material face — the constant derivation is per-engine
    /// but identical everywhere, so the default group's engine serves (the
    /// getStickerPackManifest anonymous-face posture).
    pub async fn calls_endorsements_public_key(&self) -> Result<serde_json::Value, ServiceError> {
        let slot = self.default_slot().await?;
        slot.supervisor.calls_endorsements_public_key().await
    }

    /// calls.relays (contract 1.145, §4.143): the account-scoped call-relay
    /// proxy — the owning group's engine serves (the §4.73 account-scoped
    /// material-face posture; the relay material is per-account).
    pub async fn calls_relays(
        &self,
        params: crate::service::CallsRelaysParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.calls_relays(&params.account_id).await
    }

    /// calls.sendCallEvent (contract 1.151, §4.150): the account-scoped
    /// call-event self-sync proxy — the owning group's engine serves (the
    /// §4.143 account-scoped posture; the self-send is per-account state).
    pub async fn send_call_event(
        &self,
        params: crate::service::CallsSendCallEventParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_call_event(params).await
    }

    pub async fn remote_delete(
        &self,
        params: crate::service::MessagesRemoteDeleteParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .remote_delete(params.account_id, params.conversation_id, params.message_id)
            .await
    }

    pub async fn send_reaction(
        &self,
        params: crate::service::MessagesSendReactionParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_reaction(
                params.account_id,
                params.conversation_id,
                params.message_id,
                params.emoji,
                params.remove,
            )
            .await
    }

    pub async fn send_pin_message(
        &self,
        params: crate::service::MessagesSendPinMessageParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_pin_message(
                params.account_id,
                params.conversation_id,
                params.message_id,
                params.pin_duration_seconds,
            )
            .await
    }

    pub async fn send_unpin_message(
        &self,
        params: crate::service::MessagesSendUnpinMessageParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_unpin_message(params.account_id, params.conversation_id, params.message_id)
            .await
    }

    pub async fn send_admin_delete(
        &self,
        params: crate::service::MessagesSendAdminDeleteParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_admin_delete(params.account_id, params.conversation_id, params.message_id)
            .await
    }

    /// Outbound read receipt routing (contract revision 1.34): the owning
    /// group's supervisor fans out per author over its own engine.
    pub async fn send_mark_read(
        &self,
        params: crate::service::MessagesMarkReadParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_read_receipt(
                params.account_id,
                params.conversation_id,
                params.message_ids,
                params.message_id,
            )
            .await
    }

    /// Outbound viewed receipt routing (contract revision 1.34).
    pub async fn send_mark_viewed(
        &self,
        params: crate::service::MessagesMarkViewedParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_viewed_receipt(
                params.account_id,
                params.conversation_id,
                params.message_ids,
            )
            .await
    }

    /// Outbound read SELF-SYNC routing (contract revision 1.108, §4.89):
    /// the owning group's supervisor rides the engine `markRead` face —
    /// SyncMessage.read to the account's own devices — receipt-class
    /// semantics end to end.
    pub async fn send_sync_read(
        &self,
        params: crate::service::MessagesSyncReadParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_sync_read_receipt(
                params.account_id,
                params.conversation_id,
                params.message_ids,
                params.message_id,
            )
            .await
    }

    /// Outbound viewed SELF-SYNC routing (contract revision 1.108, §4.89):
    /// the engine `markViewed` face, same discipline.
    pub async fn send_sync_viewed(
        &self,
        params: crate::service::MessagesSyncViewedParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .send_sync_viewed_receipt(
                params.account_id,
                params.conversation_id,
                params.message_ids,
            )
            .await
    }

    /// Delete-for-me SELF-SYNC routing (contract revision 1.118, §4.99):
    /// the owning group's supervisor forwards the engine
    /// `deleteForMeConversation` face, receipt-class semantics end to end.
    pub async fn delete_for_me(
        &self,
        params: crate::service::MessagesDeleteForMeParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.delete_for_me(params).await
    }

    /// Message-level delete-for-me SELF-SYNC routing (contract revision
    /// 1.197, §4.197): the same owning-group dispatch as the
    /// conversation-level twin; the connector resolves the local row ids to
    /// protocol entries in the service prepare ladder.
    pub async fn delete_for_me_messages(
        &self,
        params: crate::service::MessagesDeleteForMeMessagesParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.delete_for_me_messages(params).await
    }

    /// Story-anchored viewed receipt routing (contract revision 1.85,
    /// §4.70): the owning group's supervisor sends the single-author frame
    /// over its own engine, receipt-class semantics end to end.
    pub async fn send_story_viewed(
        &self,
        params: crate::service::StoriesMarkViewedParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_story_viewed(params).await
    }

    /// Story-anchored reaction routing (contract 1.152, §4.151): the owning
    /// group's supervisor forwards the story frame to its own engine, the
    /// §4.150 proxy posture on the stories family — the engine answer and
    /// error faces ride through untouched.
    pub async fn send_story_reaction(
        &self,
        params: crate::service::StoriesSendReactionParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_story_reaction(params).await
    }

    /// Story-anchored delete-for-everyone routing (contract 1.153, §4.152):
    /// the owning group's supervisor forwards the story delete frame to its
    /// own engine, the §4.150 proxy posture on the stories family — the
    /// engine answer and error faces ride through untouched.
    pub async fn send_story_delete_for_everyone(
        &self,
        params: crate::service::StoriesDeleteForEveryoneParams,
    ) -> Result<serde_json::Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_story_delete_for_everyone(params).await
    }

    /// View-once open sync routing (contract revision 1.38): the owning
    /// group's supervisor forwards the bare passthrough; receipt-class
    /// semantics end to end.
    pub async fn send_view_once_open(
        &self,
        params: crate::service::MessagesSendViewOnceOpenParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_view_once_open(params).await
    }

    /// View-once burn routing (contract revision 1.38): the owning group's
    /// supervisor runs the burn-then-orchestrate flow against its own engine
    /// and event lane.
    pub async fn mark_view_once_opened(
        &self,
        params: crate::service::MessagesMarkViewOnceOpenedParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.mark_view_once_opened(params).await
    }

    pub async fn edit_message(
        &self,
        params: crate::service::MessagesEditParams,
    ) -> Result<Option<crate::store::MessageRecord>, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .edit_message(
                params.account_id,
                params.conversation_id,
                params.message_id,
                params.text,
            )
            .await
    }

    /// Media ingest (ADR 0004): `open` routes by account like every other
    /// account-addressed method, so the file resolves in the owning group's
    /// data directory.
    pub async fn open_media(
        &self,
        params: crate::service::MessagesAttachmentsOpenParams,
    ) -> Result<crate::service::MediaOpenView, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.open_media(params).await
    }

    /// `readChunk` carries no accountId on the wire (ADR 0004): the
    /// process-wide handle table is the single-origin authority, so any
    /// supervisor's service resolves it identically. The first group serves.
    pub async fn read_media_chunk(
        &self,
        media_handle: String,
        offset: u64,
    ) -> Result<crate::service::MediaChunkView, ServiceError> {
        self.media_slot()?
            .supervisor
            .read_media_chunk(media_handle, offset)
            .await
    }

    /// Media handles are process-wide (ADR 0004), but full-pool mode has no
    /// legacy groups. Pick any live supervisor; the handle table resolves it.
    fn media_slot(&self) -> Result<Arc<ProxyGroupSlot>, ServiceError> {
        self.groups
            .first()
            .cloned()
            .or_else(|| {
                self.pool
                    .as_ref()
                    .and_then(|pool| pool.slots().first().map(|slot| slot.routing()))
            })
            .ok_or_else(engine_not_provisioned_error)
    }

    /// `closeHandle` — same process-wide-table reasoning as `readChunk`.
    pub async fn close_media_handle(
        &self,
        media_handle: String,
    ) -> Result<crate::service::MediaCloseView, ServiceError> {
        self.media_slot()?
            .supervisor
            .close_media_handle(media_handle)
            .await
    }

    /// backups.export / backups.exportStatus (contract revision 1.47, §4.46,
    /// capability backup-export): account-addressed, routed to the owning
    /// group's supervisor like every account-scoped face.
    pub async fn export_local_backup(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.export_local_backup(account_id).await
    }

    /// backups.exportPlaintext (contract revision 1.132, §4.115, capability
    /// backup-export — no new bit): account-addressed, routed to the owning
    /// group's supervisor like every account-scoped face; the build itself is
    /// connector-local and engine-free.
    pub async fn export_plaintext(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.export_plaintext(account_id).await
    }

    pub async fn export_backup_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.export_backup_status(account_id).await
    }

    /// backups.importSnapshot / backups.importSnapshotStatus (contract
    /// revision 1.78, §4.68): account-addressed, routed to the owning group's
    /// supervisor like every account-scoped face — the start face's watcher
    /// and the produced archive live with the account's group.
    pub async fn import_local_snapshot(
        &self,
        account_id: &str,
        snapshot_dir: &str,
    ) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor
            .import_local_snapshot(account_id, snapshot_dir)
            .await
    }

    pub async fn import_snapshot_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.import_snapshot_status(account_id).await
    }

    /// backups.restoreFromCloud / backups.cloudStatus (contract revision
    /// 1.83, §4.69): account-addressed, routed to the owning group's
    /// supervisor like every account-scoped face — the restore runs in that
    /// group's engine and its progress snapshot lives in the same process.
    pub async fn restore_from_cloud(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.restore_from_cloud(account_id).await
    }

    pub async fn cloud_backup_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.cloud_backup_status(account_id).await
    }

    /// backups.uploadToCloud / backups.uploadStatus (contract revision 1.87,
    /// §4.72): account-addressed, routed to the owning group's supervisor
    /// like every account-scoped face — the artifact build and the upload
    /// run against that group's engine and its data directory, and the
    /// progress snapshot lives in the same process.
    pub async fn upload_to_cloud(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.upload_to_cloud(account_id).await
    }

    pub async fn cloud_upload_status(&self, account_id: &str) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.cloud_upload_status(account_id).await
    }

    /// backups.exportFile.open: account-addressed — the snapshot lives in the
    /// owning group's engine data directory, so the owning group resolves it.
    pub async fn export_file_open(
        &self,
        account_id: &str,
        file: &str,
    ) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.export_file_open(account_id, file).await
    }

    /// `readChunk` carries no accountId on the wire (§4.46 reuses the ADR 0004
    /// shape): the process-wide backup handle table is the single-origin
    /// authority, so any supervisor's table resolves it identically. The
    /// first group serves.
    pub async fn export_file_read_chunk(
        &self,
        file_handle: &str,
        offset: u64,
    ) -> Result<Value, ServiceError> {
        self.groups[0]
            .supervisor
            .export_file_read_chunk(file_handle, offset)
            .await
    }

    /// `closeHandle` — same process-wide-table reasoning as `readChunk`.
    pub async fn export_file_close_handle(&self, file_handle: &str) -> Result<Value, ServiceError> {
        self.groups[0]
            .supervisor
            .export_file_close_handle(file_handle)
            .await
    }

    pub async fn sync_contacts(
        &self,
        account_id: &str,
    ) -> Result<ContactsSyncOutcome, ServiceError> {
        let slot = self.slot_for_account(account_id).await?;
        slot.supervisor.sync_contacts(account_id).await
    }

    pub async fn list_contacts(
        &self,
        account_id: String,
        query: Option<String>,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<Page<ContactSummary>, ServiceError> {
        let slot = self.slot_for_account(&account_id).await?;
        slot.supervisor
            .list_contacts(account_id, query, limit, cursor)
            .await
    }

    pub async fn get_group(
        &self,
        params: crate::service::GroupsGetParams,
    ) -> Result<crate::service::GroupDetails, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .get_group(params.account_id, params.group_key)
            .await
    }

    /// groups.common (contract 1.181, §4.181): a pure local-cache read over
    /// the account's captured rosters — routed to the owning supervisor like
    /// every other account-addressed face, zero engine traffic.
    pub async fn groups_common(
        &self,
        params: crate::service::GroupsCommonParams,
    ) -> Result<crate::service::CommonGroupsDetails, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .groups_common(params.account_id, params.conversation_id)
            .await
    }

    /// groups.update / groups.quit (contract revision 1.45, §4.44,
    /// capability group-management): the group state lives with the account's
    /// engine, so both writes route through the account's owning supervisor
    /// like every other mutating face.
    pub async fn update_group(
        &self,
        params: crate::service::GroupsUpdateParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.update_group(params).await
    }

    pub async fn quit_group(
        &self,
        params: crate::service::GroupsQuitParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.quit_group(params).await
    }

    /// groups.terminate (contract revision 1.52, §4.50, capability
    /// group-terminate): the terminated group state lives with the account's
    /// engine, so the write routes through the account's owning supervisor
    /// like every other mutating face.
    pub async fn terminate_group(
        &self,
        params: crate::service::GroupsTerminateParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.terminate_group(params).await
    }

    /// groups.approveJoinRequests (contract revision 1.58, §4.53, capability
    /// group-join-approve): the requested members' join state lives with the
    /// account's engine, so the write routes through the account's owning
    /// supervisor like every other mutating face.
    pub async fn approve_join_requests(
        &self,
        params: crate::service::GroupsApproveJoinRequestsParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.approve_join_requests(params).await
    }

    /// groups.revokeInvites (contract revision 1.64, §4.57, capability
    /// group-invite-revoke): the pending invitees' state lives with the
    /// account's engine, so the write routes through the account's owning
    /// supervisor like every other mutating face.
    pub async fn revoke_invites(
        &self,
        params: crate::service::GroupsRevokeInvitesParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.revoke_invites(params).await
    }

    /// groups.generateInviteLinkPassword / groups.parseInviteLink (contract
    /// revision 1.117, §4.98, capability group-invite-links): the
    /// account-less material-and-parse faces — no account routes them, so
    /// they ride the default supervisor like the anonymous sticker-browse
    /// faces.
    pub async fn generate_group_invite_link_password(
        &self,
        params: crate::service::GroupsInviteLinkPasswordParams,
    ) -> Result<crate::service::GroupInviteLinkPassword, ServiceError> {
        let slot = self.default_slot().await?;
        slot.supervisor
            .generate_group_invite_link_password(params)
            .await
    }

    pub async fn parse_group_invite_link(
        &self,
        params: crate::service::GroupsParseInviteLinkParams,
    ) -> Result<crate::service::GroupInviteLinkParse, ServiceError> {
        let slot = self.default_slot().await?;
        slot.supervisor.parse_group_invite_link(params).await
    }

    /// groups.buildInviteLink (contract revision 1.117, §4.98, capability
    /// group-invite-links): the group's link material lives with the
    /// account's engine, so the read routes through the account's owning
    /// supervisor.
    pub async fn build_group_invite_link(
        &self,
        params: crate::service::GroupsBuildInviteLinkParams,
    ) -> Result<crate::service::GroupInviteLink, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.build_group_invite_link(params).await
    }

    /// groups.previewViaLink (contract revision 1.117, §4.98, capability
    /// group-invite-links): the link's pre-join state lives with the
    /// account's engine — the account's owning supervisor, like the build
    /// read.
    pub async fn preview_group_via_link(
        &self,
        params: crate::service::GroupsPreviewViaLinkParams,
    ) -> Result<crate::service::GroupInviteLinkPreview, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.preview_group_via_link(params).await
    }

    /// groups.joinViaLink / groups.cancelJoinRequest (contract revision
    /// 1.117, §4.98, capability group-invite-links): the join-family
    /// writes route through the account's owning supervisor like every
    /// other mutating face.
    pub async fn join_group_via_link(
        &self,
        params: crate::service::GroupsJoinViaLinkParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.join_group_via_link(params).await
    }

    pub async fn cancel_join_request(
        &self,
        params: crate::service::GroupsCancelJoinRequestParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.cancel_join_request(params).await
    }

    /// groups.migrate (contract revision 1.123, §4.104): the migration is
    /// the account's own upstream group write, so it routes through the
    /// account's owning engine.
    pub async fn migrate_group(
        &self,
        params: crate::service::GroupsMigrateParams,
    ) -> Result<crate::service::GroupsMigrateResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.migrate_group(params).await
    }

    /// groups.create (contract revision 1.126, §4.107): the new-group write
    /// is the account's own upstream group write, so it routes through the
    /// account's owning engine.
    pub async fn create_group(
        &self,
        params: crate::service::GroupsCreateParams,
    ) -> Result<crate::service::GroupsCreateResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.create_group(params).await
    }

    /// messages.sendContact (contract revision 1.124, §4.105): the card send
    /// is the account's own upstream message write, so it routes through the
    /// account's owning engine like every send-lane face.
    pub async fn send_contact(
        &self,
        params: crate::service::MessagesSendContactParams,
    ) -> Result<Value, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_contact(params).await
    }

    /// messages.sendPollCreate (contract revision 1.125, §4.106): the poll
    /// write rides the account's owning engine like every send-lane face.
    pub async fn send_poll_create(
        &self,
        params: crate::service::MessagesSendPollCreateParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_poll_create(params).await
    }

    /// messages.sendPollVote (contract revision 1.125, §4.106): the poll
    /// write rides the account's owning engine like every send-lane face.
    pub async fn send_poll_vote(
        &self,
        params: crate::service::MessagesSendPollVoteParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_poll_vote(params).await
    }

    /// messages.sendPollTerminate (contract revision 1.125, §4.106): the
    /// poll write rides the account's owning engine like every send-lane
    /// face.
    pub async fn send_poll_terminate(
        &self,
        params: crate::service::MessagesSendPollTerminateParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.send_poll_terminate(params).await
    }

    /// messages.reportSpam (contract revision 1.49, §4.48, capability
    /// report-spam): the reported rows live with the account's engine, so
    /// the write routes through the account's owning supervisor like every
    /// other mutating face.
    pub async fn report_spam(
        &self,
        params: crate::service::MessagesReportSpamParams,
    ) -> Result<crate::service::ReportSpamResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.report_spam(params).await
    }

    /// conversations.reportSpam (contract revision 1.266, §4.250, capability
    /// report-spam): the conversation-level report routes through the
    /// account's owning supervisor like every other mutating face.
    pub async fn report_conversation_spam(
        &self,
        params: crate::service::ConversationsReportSpamParams,
    ) -> Result<crate::service::ConversationsReportSpamResult, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor.report_conversation_spam(params).await
    }

    pub async fn set_local_alias(
        &self,
        params: crate::service::ContactsSetLocalAliasParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .set_local_alias(params.account_id, params.peer_key, params.alias)
            .await
    }

    pub async fn set_typing_message(
        &self,
        params: crate::service::PresenceSetTypingMessageParams,
    ) -> Result<&'static str, ServiceError> {
        let slot = self.slot_for_account(&params.account_id).await?;
        slot.supervisor
            .set_typing_message(
                params.account_id,
                params.conversation_id,
                params.stop.unwrap_or(false),
            )
            .await
    }
}

impl Drop for ProxyGroupRuntime {
    fn drop(&mut self) {
        if let Ok(mut forwarders) = self.forwarders.lock() {
            for handle in forwarders.drain(..) {
                handle.abort();
            }
        }
    }
}

/// The launcher's media-ingest decision, passed through verbatim (contract
/// revision 1.121, §4.102): the kt-engine era's forced downgrade — arming
/// ingest kept the pre-1.17 shape whatever the launcher decided — is
/// retired. The engine projects the receive locator face (the 1.61
/// closure), so an armed runtime ingests media honestly: the argv drops
/// `--ignore-attachments`, the media governor bounds retention, receive rows
/// land with locator material, and the §4.54 download chain serves bytes on
/// demand. The 1.98 advertisement stays truthful because the handshake tag
/// keys on this same effective decision. The invariants that survive the
/// flip: locator-less legacy rows stay permanently non-downloadable
/// (`INVALID_REQUEST` before any network, the honest copy), pointer material
/// never logs, and every queue stays bounded.
fn effective_media_ingest(media_ingest: bool) -> bool {
    media_ingest
}

/// Whether the signal-data root carries a per-account pool layout (any
/// `engines/<accountId>/` directory with a registry or a store). The legacy
/// mode refuses to start in that state instead of hiding the accounts.
fn pool_layout_accounts(signal_data_dir: &Path) -> Option<usize> {
    let engines_root = signal_data_dir.join(crate::pool::ENGINE_SLOT_SUBDIR);
    let entries = std::fs::read_dir(engines_root).ok()?;
    let mut found = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !crate::pool::is_account_id(name) {
            continue;
        }
        let path = entry.path();
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let has_registry = path.join("engine-state.json").is_file();
        let has_store = path
            .join("accounts")
            .read_dir()
            .ok()
            .is_some_and(|mut accounts| {
                accounts.any(|account| {
                    account
                        .ok()
                        .is_some_and(|account| account.path().join("store.db").is_file())
                })
            });
        if has_registry || has_store {
            found += 1;
        }
    }
    (found > 0).then_some(found)
}

/// Launcher options for the per-account engine pool (design S1). The default
/// is the pre-pool runtime, byte for byte.
#[derive(Clone, Debug, Default)]
pub struct RuntimeOptions {
    /// The master switch. Two states only — **full pooling** (every account
    /// owns an engine; no group engine runs) or **full legacy** (today's
    /// single multi-account engine per proxy group). There is deliberately no
    /// mixed mode: the legacy path exists only as the rollback shape.
    pub per_account_engines: bool,
    pub pool_policy: crate::pool::EnginePoolPolicy,
    /// The launcher's single-account guard (`KT_ENGINE_SINGLE_ACCOUNT=1`,
    /// read once at startup and handed to every per-account engine child
    /// verbatim). Full legacy shares one engine process across a group's
    /// accounts, so the guard and full legacy are mutually exclusive: the open
    /// fails closed instead of silently dropping the guard.
    pub single_account_guard: bool,
    /// Watchdog cadence override (tests / operational diagnostics). Defaults
    /// to the production 30 s when absent. Applies to both runtime modes.
    pub watchdog_interval: Option<Duration>,
}

#[allow(clippy::too_many_arguments)]
pub fn open_group_runtime(
    plan: ProxyGroupPlan,
    engine_bin: PathBuf,
    state_dir: &Path,
    java_home: Option<PathBuf>,
    store_key: Option<StoreKey>,
    media_ingest: bool,
    expire_sweep_interval: Duration,
) -> Result<Arc<ProxyGroupRuntime>, crate::store::StoreError> {
    open_group_runtime_with_options(
        plan,
        engine_bin,
        state_dir,
        java_home,
        store_key,
        media_ingest,
        expire_sweep_interval,
        RuntimeOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn open_group_runtime_with_options(
    plan: ProxyGroupPlan,
    engine_bin: PathBuf,
    state_dir: &Path,
    java_home: Option<PathBuf>,
    store_key: Option<StoreKey>,
    media_ingest: bool,
    expire_sweep_interval: Duration,
    options: RuntimeOptions,
) -> Result<Arc<ProxyGroupRuntime>, crate::store::StoreError> {
    // Transitional launcher compatibility: the desktop launcher still passes
    // `--java-home` on every start (ADR 0003 defers the desktop-side cleanup);
    // the engine runs without a JVM, so the value is only acknowledged.
    if java_home.is_some() {
        tracing::warn!("--java-home is ignored: the kt engine runs without a JVM");
    }
    let media_ingest = effective_media_ingest(media_ingest);
    // Contract revision 1.288 (§4.274): the single-account guard is a
    // launcher-level promise ("one account per engine process"). The legacy
    // topology cannot keep it — a proxy-group engine serves every account of
    // its group from one process — so the mismatch fails the launch before
    // anything is opened. Silently ignoring the env would degrade the isolation
    // the operator asked for without telling anyone.
    if options.single_account_guard && !options.per_account_engines {
        return Err(StoreError::EnginePoolInvalid(
            "KT_ENGINE_SINGLE_ACCOUNT=1 requires --per-account-engines: a legacy proxy-group engine serves several accounts from one process, so the guard cannot hold. Start with --per-account-engines (full pooling) or unset the guard."
                .to_string(),
        ));
    }
    // M6 C phase: `Store::open` takes the root key over, but the per-account
    // engine keys are HKDF derivations of it, so one clone survives as that root
    // for as long as this runtime lives. It stays inside this process: a child
    // only ever receives its own account's derivation.
    let engine_store_root = store_key.clone();
    let store = Arc::new(Store::open(state_dir, store_key)?);
    let media_handles = std::sync::Arc::new(crate::media::MediaHandleTable::new());
    // §4.46: one process-wide backup file-handle table for every group —
    // `readChunk`/`closeHandle` carry no accountId, so handle resolution must
    // not depend on which supervisor the registry routed a request through.
    let backup_handles = Arc::new(crate::backup_export::BackupFileHandleTable::new());
    let group_ids: Vec<String> = plan.groups.iter().map(|group| group.id.clone()).collect();
    let signal_data_dir = plan
        .groups
        .iter()
        .find(|group| group.id == DEFAULT_PROXY_GROUP_ID)
        .map(|group| group.data_dir.clone())
        .unwrap_or_else(|| plan.groups[0].data_dir.clone());

    if options.per_account_engines {
        // Full pooling (S1 switch on). Migration and consistency run BEFORE
        // any engine exists: a state that cannot be proven complete aborts
        // startup, never a half-migrated serve (requirement 3).
        //
        // Contract revision 1.288 (§4.274): both layouts holding credentials
        // is the one state the connector refuses to resolve by itself. Running
        // the automatic pass there would have to guess which copy is
        // authoritative; the operator gets the `migrate-pool` command instead,
        // which reports the same layout and refuses the same ambiguity with a
        // plan. A pure legacy layout still migrates automatically (there is
        // exactly one candidate), and a pure pooled one is a no-op.
        let layout = crate::migrate::scan_engine_layout(&signal_data_dir)?;
        if layout.is_mixed() {
            return Err(StoreError::EnginePoolInvalid(mixed_layout_message(&layout)));
        }
        let report = crate::migrate::run(
            &store,
            &signal_data_dir,
            state_dir,
            false,
            options.pool_policy.max_resident,
        )?;
        tracing::info!(
            migrated = report.migrated,
            already_migrated = report.already_migrated,
            unprovisioned = report.unprovisioned,
            orphans_removed = report.orphans_removed,
            "engine pool migration pass complete"
        );
        let rows = store.list_all_account_rows()?;
        let max_engines = options
            .pool_policy
            .max_engines
            .clamp(1, crate::pool::MAX_PER_ACCOUNT_ENGINES);
        if rows.len() > max_engines {
            return Err(StoreError::EnginePoolInvalid(format!(
                "{} accounts exceed the per-account engine ceiling ({max_engines}); full pooling cannot start this data directory",
                rows.len()
            )));
        }
        // The guard is checked against the post-migration layout: every slot
        // must name exactly one account. The engine enforces the same rule at
        // its own startup (engine `main.rs`, `KT_ENGINE_SINGLE_ACCOUNT`, exit 1
        // with `SingleAccountRegistryViolation`); checking here makes the
        // failure explicit and fatal for the connector instead of a child that
        // dies in a restart loop while the account looks merely cold.
        if options.single_account_guard {
            let layout = crate::migrate::scan_engine_layout(&signal_data_dir)?;
            if let Some(slot) = layout.multi_account_slot() {
                return Err(StoreError::EnginePoolInvalid(
                    single_account_violation_message(slot),
                ));
            }
        }
        let pool = crate::pool::AccountPool::discover(crate::pool::EnginePoolConfig {
            engine_bin: engine_bin.clone(),
            signal_data_dir,
            state_dir: state_dir.to_path_buf(),
            media_ingest,
            expire_sweep_interval,
            store: Arc::clone(&store),
            media_handles: media_ingest.then(|| media_handles.clone()),
            backup_handles: Some(backup_handles.clone()),
            policy: options.pool_policy.clone(),
            single_account_guard: options.single_account_guard,
            watchdog_interval: options.watchdog_interval,
            root_store_key: engine_store_root,
            // M6 D3: the store-migration switch, resolved here (once, at
            // runtime assembly) rather than at each slot start, so one process
            // cannot migrate half its slots under one reading and half under
            // another. Off by default: no migrator is spawned.
            store_migration: crate::pool::StoreMigrationOptions::from_env(),
        });
        if pool.len() > rows.len() {
            return Err(StoreError::EnginePoolInvalid(format!(
                "{} account rows but {} engine slots after migration",
                rows.len(),
                pool.len()
            )));
        }
        if pool.len() < rows.len() {
            tracing::warn!(
                accounts = rows.len(),
                slots = pool.len(),
                unprovisioned = rows.len() - pool.len(),
                "engine pool starts with unprovisioned account rows"
            );
        }
        let running = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runtime = ProxyGroupRuntime::full_pool_with_running(
            group_ids,
            Arc::clone(&store),
            media_ingest,
            Arc::clone(&pool),
            Arc::clone(&running),
        );
        runtime.install_backup_handles(Arc::clone(&backup_handles));
        pool.install_orphan_sweep(running);
        tracing::info!(
            groups = json!(runtime.group_ids()).to_string(),
            pool_enabled = true,
            pool_accounts = runtime
                .account_pool()
                .map(|pool| pool.len())
                .unwrap_or_default(),
            "connector runtime assembled (full pooling)"
        );
        log_runtime_mode(RuntimeMode::Pooled, &options);
        return Ok(runtime);
    }

    // Full legacy (rollback shape): exactly the pre-pool runtime — but never
    // silently ignore a migrated pool layout. The legacy group engines cannot
    // see accounts whose stores moved to `engines/<accountId>/`; serving an
    // empty account list would look like data loss. Fail closed with the
    // remedy instead (the pool switch, or a restored pre-migration copy).
    if let Some(count) = pool_layout_accounts(&signal_data_dir) {
        return Err(StoreError::EnginePoolInvalid(format!(
            "this data directory holds {count} per-account engine slot(s); start with --per-account-engines (the legacy group engines cannot serve the pool layout). Run `kt-signal-connector migrate-pool --signal-data-dir <dir> --state-dir <dir> --dry-run` to review the layout first: one process never serves both layouts."
        )));
    }
    // M6 D3: a legacy group engine serves every account of its group from one
    // process, so there is no single account's key to migrate with
    // (EngineStoreKey::GroupEngineNoAccountKey). Say so once instead of
    // silently doing nothing when the operator armed the switch.
    let migration = crate::pool::StoreMigrationOptions::from_env();
    if migration.is_enabled() {
        tracing::warn!(
            store_migration = migration.mode.label(),
            store_migration_outcome = "skipped",
            reason = "legacy_group_topology",
            "store migration needs one account per engine; this legacy launch will not migrate"
        );
    }
    let mut slots = Vec::with_capacity(plan.groups.len());
    for entry in &plan.groups {
        let mut config = EngineConfig::new(engine_bin.clone(), entry.data_dir.clone());
        config.media_ingest = media_ingest;
        config.expire_sweep_interval = expire_sweep_interval;
        config.store_key = crate::store::EngineStoreKey::GroupEngineNoAccountKey;
        // M6 C phase: a legacy group engine serves every account of its group
        // from one process, so no single account's key may be injected here —
        // one account's key would silently unlock another's store. The plaintext
        // legacy store stands until the engine contract defines a group-scoped
        // key; the decision is therefore the explicit
        // `GroupEngineNoAccountKey` — not `RootKeyMissing`, which would claim
        // the connector has no root key when it may well have one.
        if let Some(interval) = options.watchdog_interval {
            config.watchdog_interval = interval;
        }
        let supervisor = Arc::new(RuntimeSupervisor::with_backup_handles(
            config,
            store.clone(),
            entry.id.clone(),
            media_ingest.then(|| media_handles.clone()),
            Some(backup_handles.clone()),
        ));
        supervisor.spawn_watchdog();
        supervisor.spawn_media_governor();
        supervisor.spawn_delivery_receipt_worker();
        supervisor.spawn_outbox_worker();
        supervisor.spawn_background_sync_worker();
        supervisor.spawn_avatar_refresh_worker();
        supervisor.spawn_expire_sweeper();
        slots.push(ProxyGroupSlot {
            id: entry.id.clone(),
            supervisor,
        });
    }
    slots[0].supervisor.spawn_history_retention();
    let runtime = ProxyGroupRuntime::new(slots);
    tracing::info!(
        groups = json!(runtime.group_ids()).to_string(),
        pool_enabled = false,
        "connector runtime assembled (legacy)"
    );
    log_runtime_mode(RuntimeMode::Legacy, &options);
    Ok(runtime)
}

/// The two runtime topologies (contract revision 1.288, §4.274). The mode is
/// chosen by the trusted launcher and never over IPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeMode {
    Legacy,
    Pooled,
}

impl RuntimeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Pooled => "pooled",
        }
    }
}

/// The one-shot startup line: the mode, the resident cap the pool will keep
/// (the legacy topology has no window), the hard ceiling, and whether the
/// single-account guard is on. Account ids, numbers, and paths never ride
/// along — the launcher reads this line to explain which topology is live.
fn log_runtime_mode(mode: RuntimeMode, options: &RuntimeOptions) {
    match mode {
        RuntimeMode::Pooled => {
            let resident_cap = options.pool_policy.max_resident.to_string();
            tracing::info!(
                mode = mode.as_str(),
                resident_cap = %resident_cap,
                pool_ceiling = options.pool_policy.max_engines,
                single_account_guard = options.single_account_guard,
                "connector runtime mode"
            );
        }
        RuntimeMode::Legacy => {
            // No window exists in the legacy topology: the launcher plans the
            // group engines directly, so the cap is honestly named rather than
            // reported as a zero that would read like "nothing may run".
            let resident_cap = "unbounded".to_string();
            tracing::info!(
                mode = mode.as_str(),
                resident_cap = %resident_cap,
                single_account_guard = options.single_account_guard,
                "connector runtime mode"
            );
        }
    }
}

/// Both layouts hold credentials: the automatic pass cannot tell which copy is
/// authoritative, so the operator gets the explicit migration face instead of a
/// guess. The message names counts and the exact command, never a path,
/// number, or key material.
fn mixed_layout_message(layout: &crate::migrate::EngineLayout) -> String {
    format!(
        "this data directory mixes engine layouts: {} account(s) still sit in the legacy proxy-group directories and {} account(s) already sit in per-account engine slots; refusing to guess which copy to serve. Stop every connector, run `kt-signal-connector migrate-pool --signal-data-dir <dir> --state-dir <dir> --dry-run` to review the move, re-run it without --dry-run, then start with --per-account-engines.",
        layout.legacy_accounts,
        layout.pooled_accounts()
    )
}

/// Under the guard one engine process may name one account. A slot whose own
/// registry lists more is a hand-built or copied directory, and the engine
/// would exit 1 on it; the connector stops before the spawn.
fn single_account_violation_message(slot: &crate::migrate::SlotLayout) -> String {
    format!(
        "engine slot {} names {} accounts but KT_ENGINE_SINGLE_ACCOUNT=1 allows exactly one account per engine process; refusing to start instead of serving a shared process. Give each account its own slot (migrate-pool) or unset the guard.",
        slot.account_id, slot.registry_accounts
    )
}

/// The slot table the P0 orphan sweep classifies against: every account slot
/// of one per-account engine pool, plus the runtime's running flag. Held by
/// the one supervisor the pool armed for sweeping, never owned by it (the
/// pool owns its supervisors; this struct holds them weakly by identity, and
/// `shutdown` drops it).
pub struct SweepOwner {
    pool: Arc<crate::pool::AccountPool>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl SweepOwner {
    pub(crate) fn new(
        pool: Arc<crate::pool::AccountPool>,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self { pool, running }
    }

    /// One entry per slot, keyed by the slot id the engine argv names
    /// (`<signal-data>/engines/<accountId>`).
    pub(crate) async fn facts(&self) -> Vec<(String, crate::parent::SlotFacts)> {
        let running = self.running.load(std::sync::atomic::Ordering::Acquire);
        let mut facts = Vec::new();
        for slot in self.pool.slots() {
            let owned_pid = slot.supervisor().owned_engine_pid().await;
            facts.push((
                slot.account_id().to_string(),
                crate::parent::SlotFacts {
                    provisioned: slot.is_provisioned(),
                    owned_pid,
                    running,
                },
            ));
        }
        facts
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::store::StoreKey;

    /// One supervisor per group over a single shared store, mirroring
    /// `open_group_runtime` without spawning real engines.
    fn two_group_runtime() -> Arc<ProxyGroupRuntime> {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes([0x5A; 32]))).unwrap());
        let slot = |id: &str| {
            ProxyGroupSlot::new(
                id.to_string(),
                Arc::new(RuntimeSupervisor::new(
                    EngineConfig::new(
                        PathBuf::from("unused-engine"),
                        PathBuf::from("/tmp/unused-signal-data"),
                    ),
                    store.clone(),
                    id.to_string(),
                    None,
                )),
            )
        };
        let runtime = ProxyGroupRuntime::new(vec![slot("default"), slot("team-b")]);
        // Leak the TempDir for the test lifetime so the store path stays valid
        // (same discipline as the host unit tests).
        std::mem::forget(temp);
        runtime
    }

    /// Routing contract for expired link sessions (implementation-plan §6.1):
    /// ownership survives expiry — an expired-but-known session still resolves
    /// to its owning group so its finish answers LINK_EXPIRED there instead of
    /// degrading to LINK_NOT_FOUND from the router.
    #[tokio::test]
    async fn expired_link_sessions_still_route_to_their_owning_group() {
        let runtime = two_group_runtime();
        let owner = &runtime.groups[1];
        // One group owns one session at a time, so each session is asserted
        // while it is the group's current one.
        let expired = owner
            .supervisor
            .service()
            .lock()
            .await
            .plant_link_session_for_test("KT-Expired", Duration::ZERO);
        assert_eq!(
            runtime.resolve_link_session(&expired).await.as_deref(),
            Some("team-b"),
            "an expired session must keep its owning group"
        );

        let live = owner
            .supervisor
            .service()
            .lock()
            .await
            .plant_link_session_for_test("KT-Live", Duration::from_secs(300));
        assert_eq!(
            runtime.resolve_link_session(&live).await.as_deref(),
            Some("team-b")
        );
        // QR B1: a lost session is dead for the watchdog but stays
        // attributable for the router, exactly like an expired one.
        owner
            .supervisor
            .service()
            .lock()
            .await
            .mark_link_lost(&live);
        assert_eq!(
            runtime.resolve_link_session(&live).await.as_deref(),
            Some("team-b"),
            "a lost session must keep its owning group"
        );
        assert_eq!(runtime.resolve_link_session("never-started").await, None);
    }

    /// QR B1: pooled routing follows the same authority rule as the legacy
    /// group scan — the owning slot's service session table decides. A lost
    /// session still routes (so finish answers LINK_LOST); a stale pool map
    /// entry with no backing service session does not.
    #[tokio::test]
    async fn pooled_link_sessions_route_by_the_owning_service_state() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes([0x5A; 32]))).unwrap());
        let pool = crate::pool::AccountPool::discover(crate::pool::EnginePoolConfig {
            engine_bin: PathBuf::from("unused-engine"),
            signal_data_dir: temp.path().join("signal-data"),
            state_dir: temp.path().join("state"),
            media_ingest: false,
            expire_sweep_interval: Duration::from_secs(30),
            store: Arc::clone(&store),
            media_handles: None,
            backup_handles: None,
            policy: crate::pool::EnginePoolPolicy::default(),
            single_account_guard: false,
            watchdog_interval: None,
            root_store_key: Some(StoreKey::from_bytes([0x5A; 32])),
            store_migration: crate::pool::StoreMigrationOptions::default(),
        });
        let slot = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        let runtime = ProxyGroupRuntime::full_pool_with_running(
            vec![DEFAULT_PROXY_GROUP_ID.to_string()],
            store,
            false,
            Arc::clone(&pool),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        // A pool map entry without a matching service session is stale.
        pool.remember_session("kt-stale", slot.account_id());
        assert_eq!(
            runtime.resolve_link_session("kt-stale").await,
            None,
            "a stale pool map entry must not route"
        );

        let session = slot
            .supervisor()
            .service()
            .lock()
            .await
            .plant_link_session_for_test("KT-Lost-Pool", Duration::from_secs(300));
        assert!(
            slot.supervisor()
                .service()
                .lock()
                .await
                .mark_link_lost(&session)
        );
        pool.remember_session(&session, slot.account_id());
        assert_eq!(
            runtime.resolve_link_session(&session).await.as_deref(),
            Some(DEFAULT_PROXY_GROUP_ID),
            "a lost pooled session must keep its owning slot route"
        );
        std::mem::forget(temp);
    }

    /// The effective media-ingest decision is the launcher's decision
    /// (contract 1.121, §4.102): the kt-engine downgrade is retired — an
    /// armed launcher arms the media path (argv, governor, advertisement)
    /// and an unarmed one keeps the honest CAPABILITY_UNAVAILABLE answer.
    #[test]
    fn media_ingest_passes_through() {
        assert!(effective_media_ingest(true));
        assert!(!effective_media_ingest(false));
    }

    fn running() -> EngineStatus {
        EngineStatus {
            state: EngineState::Running,
            pid: Some(1),
            rss_bytes: Some(1),
            resource_pressure: false,
        }
    }

    fn faulted() -> EngineStatus {
        EngineStatus {
            state: EngineState::Faulted,
            pid: None,
            rss_bytes: None,
            resource_pressure: false,
        }
    }

    /// Engine-pool §7.2: nine healthy engines and one crash must not read as
    /// a plain `running` aggregate. Full pooling reports `degraded`; the
    /// legacy path keeps the pre-pool bytes (no `degraded` key at all).
    #[test]
    fn pooled_aggregate_is_degraded_while_the_legacy_shape_is_unchanged() {
        let mut statuses = vec![running(); 9];
        statuses.push(faulted());
        let pooled = ProxyGroupRuntime::aggregate_from(&statuses, None, true);
        assert_eq!(pooled.state, EngineState::Running);
        assert!(pooled.degraded);
        let wire = serde_json::to_value(&pooled).unwrap();
        assert_eq!(wire["degraded"], true);

        let legacy = ProxyGroupRuntime::aggregate_from(&statuses, None, false);
        assert_eq!(legacy.state, EngineState::Running);
        assert!(!legacy.degraded);
        let wire = serde_json::to_value(&legacy).unwrap();
        assert!(
            wire.get("degraded").is_none(),
            "the flag-off shape must not gain a field"
        );
    }

    /// The pool ceiling is enforced at startup too: a migrated directory
    /// with more accounts than the per-account engine ceiling must fail closed
    /// rather than silently start only the first eight.
    #[test]
    fn pool_runtime_refuses_more_accounts_than_the_engine_ceiling() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        let store = Store::open(&state_dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap();
        for index in 1..=9u8 {
            let id = format!("{index:032x}");
            let number = format!("+1555555{index:08}");
            store
                .upsert_account_from_signal_with_id(
                    &number,
                    Some(1),
                    DEFAULT_PROXY_GROUP_ID,
                    Some(&id),
                )
                .unwrap();
            let slot = signal_data.join("engines").join(&id);
            std::fs::create_dir_all(slot.join("accounts/lk-one")).unwrap();
            std::fs::write(slot.join("accounts/lk-one/store.db"), b"store").unwrap();
            std::fs::write(
                slot.join("engine-state.json"),
                serde_json::to_vec(&json!({
                    "version": 2,
                    "accounts": [{"number": number, "dir": "accounts/lk-one"}],
                }))
                .unwrap(),
            )
            .unwrap();
        }
        drop(store);
        let plan = crate::groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let error = open_group_runtime_with_options(
            plan,
            PathBuf::from("unused-engine"),
            &state_dir,
            None,
            Some(StoreKey::from_bytes([0x5A; 32])),
            false,
            Duration::from_secs(30),
            RuntimeOptions {
                per_account_engines: true,
                ..RuntimeOptions::default()
            },
        )
        .err()
        .expect("nine accounts exceed the eight-engine ceiling");
        assert!(
            matches!(error, StoreError::EnginePoolInvalid(_)),
            "{error:?}"
        );
    }

    /// Rollback data boundary: legacy mode must refuse a migrated pool
    /// layout instead of silently serving an empty account list.
    #[test]
    fn legacy_runtime_refuses_a_migrated_pool_layout() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let slot = signal_data
            .join("engines")
            .join("0123456789abcdef0123456789abcdef");
        std::fs::create_dir_all(&slot).unwrap();
        std::fs::write(
            slot.join("engine-state.json"),
            b"{\"version\":2,\"accounts\":[{\"number\":\"+15555550100\",\"dir\":\"accounts/lk-x\"}]}",
        )
        .unwrap();
        let plan = crate::groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let error = open_group_runtime(
            plan,
            PathBuf::from("unused-engine"),
            &temp.path().join("state"),
            None,
            Some(StoreKey::from_bytes([0x5A; 32])),
            false,
            Duration::from_secs(30),
        )
        .err()
        .expect("legacy mode must fail closed on the pool layout");
        assert!(
            matches!(error, StoreError::EnginePoolInvalid(_)),
            "{error:?}"
        );
        assert_eq!(pool_layout_accounts(&signal_data), Some(1));
        assert_eq!(pool_layout_accounts(&temp.path().join("elsewhere")), None);
    }

    /// Helper: one account row plus one slot holding `accounts` accounts, the
    /// first of which is the row's own number and has a present store. Returns
    /// the slot directory. The pooled open must fail before any engine starts.
    fn seed_slot_with_accounts(
        signal_data: &Path,
        state_dir: &Path,
        account_id: &str,
        number: &str,
        extra_numbers: &[&str],
    ) {
        let store = Store::open(state_dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap();
        store
            .upsert_account_from_signal_with_id(
                number,
                Some(1),
                DEFAULT_PROXY_GROUP_ID,
                Some(account_id),
            )
            .unwrap();
        let slot = signal_data.join("engines").join(account_id);
        let mut registry = Vec::new();
        let mut numbers = vec![number];
        numbers.extend_from_slice(extra_numbers);
        for (index, value) in numbers.iter().enumerate() {
            let store_name = format!("lk-slot-{index}");
            std::fs::create_dir_all(slot.join("accounts").join(&store_name)).unwrap();
            std::fs::write(
                slot.join("accounts").join(&store_name).join("store.db"),
                b"store",
            )
            .unwrap();
            registry.push(json!({"number": value, "dir": format!("accounts/{store_name}")}));
        }
        std::fs::write(
            slot.join("engine-state.json"),
            serde_json::to_vec(&json!({"version": 2, "accounts": registry})).unwrap(),
        )
        .unwrap();
    }

    /// P1 runtime isolation (§4.274): the guard and full legacy are mutually
    /// exclusive, and the mismatch fails the launch instead of being dropped.
    #[test]
    fn the_single_account_guard_requires_full_pooling() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let plan = crate::groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let error = open_group_runtime_with_options(
            plan,
            PathBuf::from("unused-engine"),
            &temp.path().join("state"),
            None,
            Some(StoreKey::from_bytes([0x5A; 32])),
            false,
            Duration::from_secs(30),
            RuntimeOptions {
                per_account_engines: false,
                single_account_guard: true,
                ..RuntimeOptions::default()
            },
        )
        .err()
        .expect("legacy topology cannot keep the single-account guard");
        let message = error.to_string();
        assert!(
            matches!(error, StoreError::EnginePoolInvalid(_)),
            "{message}"
        );
        assert!(message.contains("KT_ENGINE_SINGLE_ACCOUNT=1"), "{message}");
        assert!(message.contains("--per-account-engines"), "{message}");
    }

    /// P1 runtime isolation (§4.274): a slot whose own engine registry names a
    /// second account is an explicit startup failure, not a cold account that
    /// silently never starts. The engine enforces the same rule at exit-1
    /// (`SingleAccountRegistryViolation`); this check lands before the spawn.
    #[test]
    fn the_single_account_guard_refuses_a_second_account_in_one_slot() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        let id = "0123456789abcdef0123456789abcdef";
        seed_slot_with_accounts(
            &signal_data,
            &state_dir,
            id,
            "+15555550100",
            &["+15555550101"],
        );
        let plan = crate::groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let error = open_group_runtime_with_options(
            plan,
            PathBuf::from("unused-engine"),
            &state_dir,
            None,
            Some(StoreKey::from_bytes([0x5A; 32])),
            false,
            Duration::from_secs(30),
            RuntimeOptions {
                per_account_engines: true,
                single_account_guard: true,
                ..RuntimeOptions::default()
            },
        )
        .err()
        .expect("two accounts in one engine process are refused");
        let message = error.to_string();
        assert!(
            matches!(error, StoreError::EnginePoolInvalid(_)),
            "{message}"
        );
        assert!(message.contains(id), "{message}");
        assert!(message.contains("KT_ENGINE_SINGLE_ACCOUNT=1"), "{message}");
        assert!(message.contains("names 2 accounts"), "{message}");
    }

    /// P1 runtime isolation (§4.274): both layouts holding credentials is the
    /// one state the connector refuses to resolve by itself — pooled mode would
    /// have to guess which copy is authoritative. The refusal names the
    /// migration command; legacy mode refuses the pool layout for the same
    /// reason (it cannot serve accounts whose stores moved).
    #[test]
    fn mixed_layouts_fail_closed_with_migration_instructions() {
        let temp = TempDir::new().unwrap();
        let signal_data = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        std::fs::create_dir_all(&signal_data).unwrap();
        let store = Store::open(&state_dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap();
        let legacy_id = "11111111111111111111111111111111";
        store
            .upsert_account_from_signal_with_id(
                "+15555550110",
                Some(1),
                DEFAULT_PROXY_GROUP_ID,
                Some(legacy_id),
            )
            .unwrap();
        drop(store);
        std::fs::create_dir_all(signal_data.join("accounts/lk-legacy")).unwrap();
        std::fs::write(signal_data.join("accounts/lk-legacy/store.db"), b"legacy").unwrap();
        std::fs::write(
            signal_data.join("engine-state.json"),
            serde_json::to_vec(&json!({
                "version": 2,
                "accounts": [{"number": "+15555550110", "dir": "accounts/lk-legacy"}],
            }))
            .unwrap(),
        )
        .unwrap();
        seed_slot_with_accounts(
            &signal_data,
            &state_dir,
            "22222222222222222222222222222222",
            "+15555550111",
            &[],
        );

        let plan = crate::groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let pooled = open_group_runtime_with_options(
            plan,
            PathBuf::from("unused-engine"),
            &state_dir,
            None,
            Some(StoreKey::from_bytes([0x5A; 32])),
            false,
            Duration::from_secs(30),
            RuntimeOptions {
                per_account_engines: true,
                ..RuntimeOptions::default()
            },
        )
        .err()
        .expect("a mixed layout is never resolved by guessing");
        let message = pooled.to_string();
        assert!(
            matches!(pooled, StoreError::EnginePoolInvalid(_)),
            "{message}"
        );
        assert!(message.contains("mixes engine layouts"), "{message}");
        assert!(message.contains("migrate-pool"), "{message}");
        assert!(message.contains("--per-account-engines"), "{message}");

        let plan = crate::groups::build_group_plan(&[], None, None, &signal_data).unwrap();
        let legacy = open_group_runtime_with_options(
            plan,
            PathBuf::from("unused-engine"),
            &state_dir,
            None,
            Some(StoreKey::from_bytes([0x5A; 32])),
            false,
            Duration::from_secs(30),
            RuntimeOptions::default(),
        )
        .err()
        .expect("legacy mode cannot serve the pool layout");
        let message = legacy.to_string();
        assert!(
            matches!(legacy, StoreError::EnginePoolInvalid(_)),
            "{message}"
        );
        assert!(message.contains("per-account engine slot"), "{message}");
        assert!(message.contains("migrate-pool"), "{message}");
    }

    fn account_engine(account_id: &str) -> crate::pool::AccountEngineStatus {
        crate::pool::AccountEngineStatus {
            account_id: account_id.to_string(),
            proxy_group: Some(DEFAULT_PROXY_GROUP_ID.to_string()),
            state: EngineState::Running,
            pid: Some(1),
            rss_bytes: Some(1),
            resource_pressure: false,
            resident: true,
            restarts: 0,
            store_migration: None,
            needs_relink: false,
        }
    }

    /// `engines` is a **mode marker**, not a list-length signal: the pooled
    /// answer always names it — an empty pool answers `[]`, which is exactly
    /// what lets the desktop tell "no accounts yet" from a pre-pool connector
    /// — while the legacy shape keeps the key absent and byte-identical to the
    /// pre-pool build.
    #[test]
    fn engines_is_present_exactly_on_the_pooled_status_shape() {
        let legacy = RuntimeStatusResult {
            aggregate: ProxyGroupRuntime::aggregate_from(&[running()], Some(1), false),
            proxy_groups: Vec::new(),
            engines: Vec::new(),
            engines_pooled: false,
        };
        let wire = serde_json::to_value(legacy).unwrap();
        assert!(
            wire.get("engines").is_none(),
            "a legacy answer must not gain the key: {wire}"
        );
        assert!(wire.get("degraded").is_none());

        let empty_pool = RuntimeStatusResult {
            aggregate: ProxyGroupRuntime::aggregate_from(&[], None, true),
            proxy_groups: Vec::new(),
            engines: Vec::new(),
            engines_pooled: true,
        };
        let wire = serde_json::to_value(empty_pool).unwrap();
        assert_eq!(
            wire.get("engines"),
            Some(&json!([])),
            "a pooled answer with no accounts must still name engines as []: {wire}"
        );

        let sized = RuntimeStatusResult {
            aggregate: ProxyGroupRuntime::aggregate_from(&[running(), running()], None, true),
            proxy_groups: Vec::new(),
            engines: vec![
                account_engine("00000000000000000000000000000001"),
                account_engine("00000000000000000000000000000002"),
            ],
            engines_pooled: true,
        };
        let wire = serde_json::to_value(sized).unwrap();
        let engines = wire["engines"]
            .as_array()
            .expect("engines rides as an array");
        assert_eq!(engines.len(), 2);
        assert_eq!(engines[0]["accountId"], "00000000000000000000000000000001");
    }

    /// M6 D3 follow-up: the engine-free delete is the one delete path with no
    /// supervisor to borrow, and the §4.46 backup handle table is process-wide
    /// — `pool.discard` takes the slot, never the handle. The file half the
    /// delete calls must release that account's handles (and only that
    /// account's), or a handle outlives the session it was opened from.
    #[tokio::test]
    async fn the_engine_free_delete_releases_that_accounts_backup_handles() {
        let temp = TempDir::new().unwrap();
        let store =
            Arc::new(Store::open(temp.path(), Some(StoreKey::from_bytes([0x5A; 32]))).unwrap());
        let supervisor = Arc::new(RuntimeSupervisor::new(
            EngineConfig::new(
                PathBuf::from("unused-engine"),
                PathBuf::from("/tmp/unused-signal-data"),
            ),
            Arc::clone(&store),
            DEFAULT_PROXY_GROUP_ID.to_string(),
            None,
        ));
        let runtime = ProxyGroupRuntime::new(vec![ProxyGroupSlot::new(
            DEFAULT_PROXY_GROUP_ID.to_string(),
            supervisor,
        )]);
        let handles = Arc::new(crate::backup_export::BackupFileHandleTable::new());
        runtime.install_backup_handles(Arc::clone(&handles));
        let snapshot = temp.path().join("snapshot.db");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        let deleted = handles.open("acct-a", snapshot.clone(), 8).unwrap();
        let kept = handles.open("acct-b", snapshot, 8).unwrap();
        assert!(
            handles.read_chunk(&deleted, 0).is_ok(),
            "the handle is live"
        );
        assert!(handles.read_chunk(&kept, 0).is_ok(), "the handle is live");

        runtime.clear_account_delete_files("acct-a");

        assert!(
            matches!(
                handles.read_chunk(&deleted, 8),
                Err(crate::backup_export::BackupHandleError::NotFound)
            ),
            "a handle cannot outlive the account session it was opened from"
        );
        assert!(
            handles.read_chunk(&kept, 8).is_ok(),
            "another account's handle is untouched"
        );
    }
}
