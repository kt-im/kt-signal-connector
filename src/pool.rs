// SPDX-License-Identifier: AGPL-3.0-only

//! Per-account engine slots (engine-pool design S1, 2026-10-21).
//!
//! The pre-pool runtime is a fixed vector of launcher-planned proxy-group
//! engines. This module adds the second half of the pool: dynamically
//! provisioned, one-account engines that live under
//! `<signal-data>/engines/<accountId>/`, while the legacy proxy-group engines
//! keep their exact pre-pool shape and data directory.
//!
//! Invariants (design §3.2) this module owns:
//!
//! - **I1/I2**: at most one engine per account slot. A slot's process starts
//!   only behind the supervisor's single engine slot, and every dynamic data
//!   directory is additionally protected by a `flock` (`crate::datalock`)
//!   acquired before the child can start and held for process lifetime.
//! - **I4**: the data-directory name is the connector's opaque account id
//!   (32 lowercase hex). No phone number or ACI ever appears in a path or a
//!   log line.
//! - **I5**: a slot's directory is removed only after the engine has stopped
//!   (used by link-cancel and account-delete cleanup).
//!
//! Capacity (S1 decision, revised 2026-10-21): at most
//! [`MAX_PER_ACCOUNT_ENGINES`] accounts are provisioned (the link entry
//! refuses the next one with `ENGINE_POOL_FULL`), and **all linked accounts
//! are resident by default** — the resident window equals the hard ceiling
//! [`MAX_RESIDENT_ENGINES`] = 8. Real-time receive is a product invariant, and
//! the measured live-engine cost is ~33 MB per account (8 ≈ 264 MB + the
//! connector), not the 64.3 MB that once suggested K = 5.
//!
//! Idle demotion is therefore **off by default**: with the window equal to the
//! ceiling `enforce_window` can never fire. Operators on low-memory machines
//! may opt into a smaller window with `KT_SIGNAL_POOL_MAX_RESIDENT=5`; only
//! then do accounts beyond the window stay cold (started on their first
//! account-addressed request) and an idle least-recently-used resident get
//! demoted in the background.
//!
//! Media stays connector-owned: a dynamic slot's engine runs with its own
//! data directory, but its media namespace is the connector root
//! `<signal-data>/media/<accountId>/attachments` (never
//! `engines/<accountId>/media`). The engine's own log file follows the data
//! directory — `engines/<accountId>/logs/engine-stderr.log` — which is what
//! keeps two engines' logs disjoint.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use serde::Serialize;

use crate::DEFAULT_PROXY_GROUP_ID;
use crate::datalock::DataDirLock;
use crate::engine::{EngineConfig, EngineError, EngineState};
use crate::ids::random_id;
use crate::protocol::ApiError;
use crate::service::ServiceError;
use crate::store::Store;
use crate::supervisor::RuntimeSupervisor;

/// Hard ceiling on provisioned per-account engines. Aligned with
/// [`crate::groups::MAX_ACCOUNTS_PER_ENGINE`] (design §8.5): the ninth link is
/// refused at the link entry, before a QR is minted.
pub const MAX_PER_ACCOUNT_ENGINES: usize = 8;

/// Default resident window: the hard ceiling. Every linked account's engine
/// stays started and keeps receiving; the measured live cost is ~33 MB per
/// account (8 ≈ 264 MB + connector), so keeping all eight hot fits the target
/// machines. See [`POOL_MAX_RESIDENT_ENV`] for the low-memory opt-out.
pub const MAX_RESIDENT_ENGINES: usize = MAX_PER_ACCOUNT_ENGINES;

/// Launcher override for the resident window (S1 revision 2026-10-21). The
/// default equals the hard ceiling, so every linked account stays hot and
/// keeps receiving; a low-memory machine may set e.g. `5` to re-enable idle
/// demotion. Parsed once at connector startup, never over IPC.
pub const POOL_MAX_RESIDENT_ENV: &str = "KT_SIGNAL_POOL_MAX_RESIDENT";

/// Subdirectory of `--signal-data-dir` holding one directory per account
/// engine (design §3.3).
pub const ENGINE_SLOT_SUBDIR: &str = "engines";

/// The engine's own single-account guard (engine
/// `kt-signal-engine/src/main.rs:416-446`, `KT_ENGINE_SINGLE_ACCOUNT`, P1
/// runtime isolation §4.274). Only an explicit
/// trimmed `"1"` turns it on — the same strict reading as
/// `KT_ENGINE_FAKE_SERVICE` — and the connector hands the decision to every
/// per-account engine child explicitly (never by inheritance), so a child can
/// never carry a guard the connector did not reason about.
pub const SINGLE_ACCOUNT_ENV: &str = "KT_ENGINE_SINGLE_ACCOUNT";

/// Pure parse: exactly `"1"` after trimming turns the guard on; every other
/// value (including unset) leaves it off and preserves the multi-account
/// compatibility path.
pub fn single_account_guard_enabled(raw: Option<&str>) -> bool {
    raw.map(str::trim) == Some("1")
}

/// Read the launcher's guard decision once at startup.
pub fn single_account_guard_from_env() -> bool {
    single_account_guard_enabled(std::env::var(SINGLE_ACCOUNT_ENV).ok().as_deref())
}

/// Connector-state subdirectory holding the provisioning sidecars
/// `<state-dir>/engines/<accountId>.json`. A sidecar is the crash-window
/// recovery record between "the engine wrote the account into its own
/// registry" and "the connector store committed the row": it carries the
/// proxy group, never a number or an ACI.
pub const PROVISION_SIDECAR_SUBDIR: &str = "engines";

/// Global budget for tearing the whole pool down (design §6.4/F7). The
/// pre-pool shutdown loop was sequential — ten engines at the old 5 s wait
/// could hold process exit for 50 s; the pool stops them in parallel and
/// abandons (then kills) whatever is still running at this deadline.
pub const POOL_SHUTDOWN_BUDGET: Duration = Duration::from_secs(8);

/// Global budget for one `accounts.list` pass (design §F9). Every engine is
/// asked in parallel; a slot that misses the deadline degrades to its local
/// store rows, so one wedged engine cannot stretch the host's list latency to
/// O(N × engine timeout).
pub const LIST_ACCOUNTS_BUDGET: Duration = Duration::from_secs(3);

/// A half-finished link's slot is reclaimed once it has been idle this long
/// and holds no live link session (the link session TTL is five minutes; the
/// two windows align so a retryable session is never reaped underneath the
/// user).
pub const ABANDONED_LINK_TTL: Duration = Duration::from_secs(300);

/// Minimum idle time before a resident slot may be demoted to make room for a
/// freshly woken account. Only meaningful when the operator opts into a window
/// smaller than the ceiling (idle demotion is **off by default**). Keeps a hot
/// account from being evicted between two requests; an idle window this long
/// means no user is waiting on it.
pub const DEMOTE_IDLE_AFTER: Duration = Duration::from_secs(60);

/// Pool size policy. Production uses [`Self::default`]; integration tests
/// tighten the budgets.
#[derive(Clone, Debug)]
pub struct EnginePoolPolicy {
    pub max_engines: usize,
    pub max_resident: usize,
    pub shutdown_budget: Duration,
    pub list_accounts_budget: Duration,
    pub demote_idle_after: Duration,
}

impl Default for EnginePoolPolicy {
    fn default() -> Self {
        Self {
            max_engines: MAX_PER_ACCOUNT_ENGINES,
            max_resident: MAX_RESIDENT_ENGINES,
            shutdown_budget: POOL_SHUTDOWN_BUDGET,
            list_accounts_budget: LIST_ACCOUNTS_BUDGET,
            demote_idle_after: DEMOTE_IDLE_AFTER,
        }
    }
}

impl EnginePoolPolicy {
    /// Production policy: every provisioned account engine is resident, so
    /// idle demotion is disabled unless `KT_SIGNAL_POOL_MAX_RESIDENT` asks for
    /// a smaller window.
    pub fn from_env() -> Self {
        let mut policy = Self::default();
        if let Ok(value) = std::env::var(POOL_MAX_RESIDENT_ENV) {
            match value.trim().parse::<usize>() {
                Ok(parsed) => policy.max_resident = parsed,
                Err(_) => tracing::warn!(
                    env = POOL_MAX_RESIDENT_ENV,
                    "invalid per-account resident window; using the default"
                ),
            }
        }
        policy.normalized()
    }

    fn normalized(mut self) -> Self {
        self.max_engines = self.max_engines.clamp(1, MAX_PER_ACCOUNT_ENGINES);
        self.max_resident = self.max_resident.clamp(1, self.max_engines);
        self
    }
}

/// Everything needed to assemble a dynamic slot. The handle tables are the
/// same process-wide `Arc`s the legacy groups receive (ADR 0004: handle
/// resolution must not depend on which supervisor routed the request).
pub struct EnginePoolConfig {
    pub engine_bin: PathBuf,
    pub signal_data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub media_ingest: bool,
    pub expire_sweep_interval: Duration,
    pub store: Arc<Store>,
    pub media_handles: Option<Arc<crate::media::MediaHandleTable>>,
    pub backup_handles: Option<Arc<crate::backup_export::BackupFileHandleTable>>,
    pub policy: EnginePoolPolicy,
    /// Hand `KT_ENGINE_SINGLE_ACCOUNT=1` to every account engine child (P1
    /// runtime isolation, §4.274). The pool already owns one account per
    /// process; the guard makes that invariant the engine's own contract.
    pub single_account_guard: bool,
    /// Watchdog cadence override (tests); `None` keeps the production 30 s.
    pub watchdog_interval: Option<Duration>,
    /// The connector's root store key, kept only as the HKDF root for each
    /// account's engine key (M6 C phase). The root itself never reaches a child:
    /// every slot derives `HKDF(salt = accountId, info =
    /// store::ENGINE_STORE_KEY_INFO)` at build time. `None` means no root key is
    /// configured — no slot gets one, the plaintext legacy engine store stands,
    /// and the operator hears about it once.
    pub root_store_key: Option<crate::store::StoreKey>,
}

/// One `runtime.status` `engines[]` entry (design §7.3, additive): the
/// per-account engine's live state, pid, RSS sample, pressure flag, whether
/// the slot's engine is currently started, and its successful restart count.
/// With the default window every linked account is resident; only an explicit
/// smaller `KT_SIGNAL_POOL_MAX_RESIDENT` leaves slots cold. Deliberately no
/// data-directory path and no address material.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEngineStatus {
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_group: Option<String>,
    pub state: EngineState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    pub resource_pressure: bool,
    /// Whether the slot's engine is currently **started** (awake). The default
    /// window equals the ceiling, so every linked account is resident; a
    /// smaller `KT_SIGNAL_POOL_MAX_RESIDENT` window leaves accounts beyond it
    /// cold (`false`) until their first account-addressed request wakes them.
    pub resident: bool,
    pub restarts: u64,
}

/// One dynamically provisioned account engine: its routing handle, its own
/// data directory, the process-lifetime occupancy lock, and the small amount
/// of in-memory bookkeeping the pool needs.
pub struct AccountSlot {
    account_id: String,
    proxy_group: String,
    data_dir: PathBuf,
    sidecar: PathBuf,
    routing: Arc<crate::registry::ProxyGroupSlot>,
    supervisor: Arc<RuntimeSupervisor>,
    /// Serializes cold-start wakes of this slot (the supervisor's engine slot
    /// already makes a second process impossible; this keeps the second
    /// caller from observing a half-started engine).
    wake: tokio::sync::Mutex<()>,
    resident: AtomicBool,
    provisioned: AtomicBool,
    lock: StdMutex<Option<DataDirLock>>,
    last_used: StdMutex<Instant>,
}

impl AccountSlot {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn proxy_group(&self) -> &str {
        &self.proxy_group
    }

    pub fn supervisor(&self) -> &Arc<RuntimeSupervisor> {
        &self.supervisor
    }

    pub(crate) fn routing(&self) -> Arc<crate::registry::ProxyGroupSlot> {
        Arc::clone(&self.routing)
    }

    pub fn is_resident(&self) -> bool {
        self.resident.load(Ordering::Relaxed)
    }

    fn set_resident(&self, value: bool) {
        self.resident.store(value, Ordering::Relaxed);
    }

    pub fn is_provisioned(&self) -> bool {
        self.provisioned.load(Ordering::Relaxed)
    }

    pub fn touch(&self) {
        if let Ok(mut last) = self.last_used.lock() {
            *last = Instant::now();
        }
    }

    fn last_used(&self) -> Instant {
        self.last_used
            .lock()
            .map(|last| *last)
            .unwrap_or_else(|poisoned| *poisoned.into_inner())
    }

    pub(crate) fn idle_for(&self) -> Duration {
        Instant::now().saturating_duration_since(self.last_used())
    }

    fn holds_lock(&self) -> bool {
        self.lock.lock().map(|lock| lock.is_some()).unwrap_or(false)
    }
}

/// The dynamic registry: `accountId -> AccountSlot`, plus the link-session
/// ownership map the registry consults before the static group table.
pub struct AccountPool {
    config: EnginePoolConfig,
    slots: StdRwLock<BTreeMap<String, Arc<AccountSlot>>>,
    sessions: StdMutex<HashMap<String, String>>,
    /// Serializes dynamic link admission so the capacity ceiling cannot be
    /// overshot by two concurrent `link.start` calls. Held only for the QR
    /// mint, never across `link.finish`'s phone-approval wait.
    link_lock: tokio::sync::Mutex<()>,
    available: bool,
}

impl AccountPool {
    /// Scan `<signal-data>/engines/` and rebuild a cold slot for every
    /// provisioned account. No engine is started here: `runtime.start` (or
    /// the first request) owns the resident window.
    pub fn discover(config: EnginePoolConfig) -> Arc<Self> {
        let config = EnginePoolConfig {
            policy: config.policy.clone().normalized(),
            ..config
        };
        let engines_root = config.signal_data_dir.join(ENGINE_SLOT_SUBDIR);
        let available = match ensure_private_dir(&engines_root) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(
                    error_class = error_class(&error),
                    "per-account engine root could not be prepared; the pool is unavailable"
                );
                false
            }
        };
        let mut slots = BTreeMap::new();
        if available {
            match std::fs::read_dir(&engines_root) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                            continue;
                        };
                        if !is_account_id(&name) {
                            continue;
                        }
                        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
                        if !is_dir {
                            continue;
                        }
                        let sidecar = sidecar_path(&config.state_dir, &name);
                        let sidecar_record = read_sidecar(&sidecar);
                        let bound_group = config
                            .store
                            .account_by_id(&name)
                            .ok()
                            .flatten()
                            .map(|row| row.proxy_group)
                            .or_else(|| {
                                sidecar_record
                                    .as_ref()
                                    .map(|record| record.proxy_group.clone())
                            })
                            .filter(|group| !group.is_empty())
                            .unwrap_or_else(|| DEFAULT_PROXY_GROUP_ID.to_string());
                        let provisioned = sidecar_record
                            .as_ref()
                            .map(|record| record.provisioned)
                            .unwrap_or(false)
                            || config.store.account_by_id(&name).ok().flatten().is_some();
                        let lock = DataDirLock::acquire(&name, &path).map(Some).unwrap_or_else(
                            |error| {
                                tracing::warn!(
                                    account_id = %name,
                                    error_class = error_class(&error),
                                    "per-account engine directory is occupied; the slot stays cold"
                                );
                                None
                            },
                        );
                        let slot = build_slot(
                            &config,
                            name,
                            bound_group,
                            path,
                            sidecar,
                            provisioned,
                            modified_instant(&entry.path()),
                            lock,
                        );
                        slots.insert(slot.account_id.clone(), slot);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => tracing::warn!(
                    error_class = error_class(&error),
                    "per-account engine root could not be listed"
                ),
            }
        }
        let count = slots.len();
        let pool = Arc::new(Self {
            config,
            slots: StdRwLock::new(slots),
            sessions: StdMutex::new(HashMap::new()),
            link_lock: tokio::sync::Mutex::new(()),
            available,
        });
        tracing::info!(accounts = count, "per-account engine pool discovered");
        pool
    }

    /// P0 orphan-engine sweep arming: exactly one watchdog clock per data
    /// directory owns the pass. Called by the registry once the runtime
    /// exists, and again after a slot is provisioned (a pool that started
    /// empty has no supervisor to arm yet). Idempotent.
    pub(crate) fn install_orphan_sweep(
        self: &Arc<Self>,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let Some(slot) = self.slots().first().cloned() else {
            return;
        };
        slot.supervisor().arm_orphan_sweep(
            self.config.signal_data_dir.clone(),
            Arc::new(crate::registry::SweepOwner::new(Arc::clone(self), running)),
        );
    }

    pub fn policy(&self) -> &EnginePoolPolicy {
        &self.config.policy
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn len(&self) -> usize {
        self.slots
            .read()
            .map(|slots| slots.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn at_capacity(&self) -> bool {
        self.len() >= self.config.policy.max_engines
    }

    pub fn get(&self, account_id: &str) -> Option<Arc<AccountSlot>> {
        self.slots
            .read()
            .ok()
            .and_then(|slots| slots.get(account_id).cloned())
    }

    pub fn slots(&self) -> Vec<Arc<AccountSlot>> {
        self.slots
            .read()
            .map(|slots| slots.values().cloned().collect())
            .unwrap_or_default()
    }

    fn resident_count(&self) -> usize {
        self.slots()
            .iter()
            .filter(|slot| slot.is_resident())
            .count()
    }

    pub fn session_owner(&self, link_session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(link_session_id).cloned())
    }

    pub fn session_owner_exists(&self, link_session_id: &str) -> bool {
        self.session_owner(link_session_id).is_some()
    }

    pub fn remember_session(&self, link_session_id: &str, account_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(link_session_id.to_string(), account_id.to_string());
        }
    }

    pub fn forget_session(&self, link_session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(link_session_id);
        }
    }

    /// Admission + materialization of a fresh slot for `link.start`. The
    /// returned slot is registered but its engine is not started yet; the
    /// caller starts it and rolls the slot back through [`Self::discard`] if
    /// the QR mint fails. A slot occupies a data directory, an occupancy lock,
    /// and a supervisor from this point on, so the capacity check and the
    /// insert share one write lock.
    pub fn provision_slot(&self, proxy_group: &str) -> Result<Arc<AccountSlot>, ServiceError> {
        if !self.available {
            return Err(ServiceError::Api(ApiError::new(
                "CAPABILITY_UNAVAILABLE",
                "the per-account engine pool is unavailable on this host",
                false,
            )));
        }
        let mut slots = self.slots.write().map_err(|_| pool_unavailable_error())?;
        if slots.len() >= self.config.policy.max_engines {
            return Err(ServiceError::Api(ApiError::new(
                "ENGINE_POOL_FULL",
                format!(
                    "the per-account engine pool already holds {} accounts; delete an account before linking another",
                    self.config.policy.max_engines
                ),
                false,
            )));
        }
        let account_id = random_id();
        let engines_root = self.config.signal_data_dir.join(ENGINE_SLOT_SUBDIR);
        let data_dir = engines_root.join(&account_id);
        ensure_private_dir(&data_dir).map_err(|_| pool_unavailable_error())?;
        // 注册表必须先于 store 存在（migrate.rs:21 已确立的纪律）：
        // 引擎只把"注册表缺失 + 有 store"判为不可信（state.rs RegistryMissingWithStores），
        // 而 link 过程中引擎自己会建 accounts/lk-*；若此刻引擎重启（崩溃/watchdog/
        // 换二进制），缺注册表会被误判为孤儿目录 → 隔离 → 隔离区非空 → 此后每次
        // 启动 fail closed（实测无限重启）。这里先写一份有效但空的 V2 注册表，
        // 引擎看到 V2 即不再检查 store，link 完成后再由 supervisor 写入真实条目。
        write_empty_engine_registry(&data_dir).map_err(|_| pool_unavailable_error())?;
        let lock = match DataDirLock::acquire(&account_id, &data_dir) {
            Ok(lock) => Some(lock),
            Err(error) => {
                let _ = std::fs::remove_dir(&data_dir);
                tracing::warn!(
                    account_id = %account_id,
                    error_class = error_class(&error),
                    "per-account engine directory is occupied; refusing the slot"
                );
                return Err(ServiceError::Api(ApiError::new(
                    "CAPABILITY_UNAVAILABLE",
                    "the account engine data directory is occupied",
                    false,
                )));
            }
        };
        let sidecar = sidecar_path(&self.config.state_dir, &account_id);
        if let Err(error) = write_sidecar(&sidecar, &account_id, proxy_group, false) {
            tracing::warn!(
                account_id = %account_id,
                error_class = error_class(&error),
                "engine slot provisioning sidecar could not be written"
            );
        }
        let slot = build_slot(
            &self.config,
            account_id.clone(),
            proxy_group.to_string(),
            data_dir,
            sidecar,
            false,
            Instant::now(),
            lock,
        );
        slots.insert(account_id, Arc::clone(&slot));
        tracing::info!(
            account_id = %slot.account_id,
            group_id = %slot.proxy_group,
            pool_size = slots.len(),
            "per-account engine slot provisioned"
        );
        Ok(slot)
    }

    pub async fn lock_admission(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.link_lock.lock().await
    }

    /// Mark a slot as freshly used and keep the resident window bounded. The
    /// link path calls this once the new engine is live, so the account it
    /// just linked stays resident ahead of older idle slots.
    pub fn note_activity(self: &Arc<Self>, slot: &Arc<AccountSlot>) {
        slot.touch();
        slot.set_resident(true);
        self.enforce_window(Arc::clone(slot));
    }

    /// Persist the committed-link marker and refresh the sidecar. Best-effort:
    /// a sidecar write failure degrades crash-window recovery to the store
    /// lookup, never the link answer.
    pub fn mark_provisioned(&self, slot: &AccountSlot) {
        slot.provisioned.store(true, Ordering::Relaxed);
        if let Err(error) = write_sidecar(&slot.sidecar, &slot.account_id, &slot.proxy_group, true)
        {
            tracing::warn!(
                account_id = %slot.account_id,
                error_class = error_class(&error),
                "engine slot provisioning sidecar could not be updated"
            );
        }
    }

    /// Remove a slot from the registry and stop its engine. `remove_dir`
    /// deletes the slot's data directory **after** the process is gone (I5);
    /// used by link-cancel/failed-link rollback and account deletion. A link
    /// rollback deletes a directory the connector created moments ago for an
    /// uncommitted link, so no credentials can be lost.
    pub async fn discard(self: &Arc<Self>, account_id: &str, remove_dir: bool) {
        let slot = self
            .slots
            .write()
            .ok()
            .and_then(|mut slots| slots.remove(account_id));
        let Some(slot) = slot else {
            return;
        };
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, owner| owner != account_id);
        }
        slot.set_resident(false);
        slot.supervisor.stop_background_tasks();
        if let Err(error) = slot.supervisor.shutdown().await {
            tracing::warn!(
                account_id = %slot.account_id,
                error_class = error.class(),
                "per-account engine did not stop cleanly before slot removal"
            );
        }
        if remove_dir {
            self.remove_slot_directory(&slot);
        }
        tracing::info!(
            account_id = %slot.account_id,
            group_id = %slot.proxy_group,
            "per-account engine slot removed"
        );
    }

    fn remove_slot_directory(&self, slot: &AccountSlot) {
        let account_id = slot.account_id.as_str();
        if !is_account_id(account_id) {
            return;
        }
        let engines_root = self.config.signal_data_dir.join(ENGINE_SLOT_SUBDIR);
        if slot.data_dir.parent() != Some(engines_root.as_path()) {
            return;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&slot.data_dir) else {
            return;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return;
        }
        if let Err(error) = std::fs::remove_dir_all(&slot.data_dir) {
            tracing::warn!(
                account_id = %slot.account_id,
                error_class = error_class(&error),
                "per-account engine directory could not be removed"
            );
        }
        let _ = std::fs::remove_file(&slot.sidecar);
    }

    /// Start the top-K most recently used slots (design §6.1 step ④, S1
    /// bounded form: process starts are cheap, the expensive part is the
    /// engine's own receive stream, which stays asynchronous either way).
    pub async fn start_resident(self: &Arc<Self>) {
        let mut slots = self.slots();
        slots.sort_by(|left, right| {
            right
                .last_used()
                .cmp(&left.last_used())
                .then_with(|| left.account_id.cmp(&right.account_id))
        });
        for slot in slots.into_iter().take(self.config.policy.max_resident) {
            if !slot.holds_lock() {
                continue;
            }
            match slot.supervisor.start().await {
                Ok(status) if status.state == EngineState::Running => {
                    slot.set_resident(true);
                    tracing::info!(
                        account_id = %slot.account_id,
                        group_id = %slot.proxy_group,
                        pid = status.pid.unwrap_or(0),
                        "per-account engine started (resident window)"
                    );
                }
                Ok(_) => {}
                Err(EngineError::Backpressure) => slot.set_resident(true),
                Err(error) => tracing::warn!(
                    account_id = %slot.account_id,
                    group_id = %slot.proxy_group,
                    error_class = error.class(),
                    "per-account engine did not start"
                ),
            }
        }
    }

    /// O1: the first latched contract refusal across the pool's slots, if any.
    /// Every slot spawns the same engine binary, so one refusal is the whole
    /// pool's verdict.
    pub async fn contract_fault(&self) -> Option<crate::engine_contract::EngineContractFault> {
        for slot in self.slots() {
            if let Some(fault) = slot.supervisor().latched_contract_fault().await {
                return Some(fault);
            }
        }
        None
    }

    /// Stop every dynamic engine (runtime.stop), leaving the slots registered
    /// and cold so a later runtime.start can rebuild the resident window.
    pub async fn stop_all(&self) {
        for slot in self.slots() {
            slot.set_resident(false);
            match slot.supervisor.stop().await {
                Ok(_) | Err(EngineError::NotRunning) => {}
                Err(error) => tracing::warn!(
                    account_id = %slot.account_id,
                    error_class = error.class(),
                    "per-account engine did not stop"
                ),
            }
        }
    }

    /// Cold-start wake used by account-addressed routing. Idempotent and
    /// serialized per slot; a slot whose data-directory lock was lost at
    /// startup refuses to start rather than risk a second process (I2).
    pub async fn ensure_resident(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Result<(), ServiceError> {
        slot.touch();
        if slot.supervisor.status().await.state == EngineState::Running {
            slot.set_resident(true);
            return Ok(());
        }
        if !slot.holds_lock() {
            return Err(ServiceError::Api(ApiError::new(
                "CAPABILITY_UNAVAILABLE",
                "the account engine data directory is occupied",
                false,
            )));
        }
        let _wake = slot.wake.lock().await;
        if slot.supervisor.status().await.state != EngineState::Running {
            match slot.supervisor.start().await {
                Ok(status) if status.state == EngineState::Running => {}
                Ok(_) => return Err(ServiceError::Engine(EngineError::StartFailed)),
                Err(EngineError::Backpressure) => {}
                Err(error) => return Err(ServiceError::Engine(error)),
            }
        }
        slot.set_resident(true);
        tracing::info!(
            account_id = %slot.account_id,
            group_id = %slot.proxy_group,
            "per-account engine woke"
        );
        self.enforce_window(Arc::clone(slot));
        Ok(())
    }

    /// Keep the resident set bounded: demote least-recently-used idle slots
    /// (never the slot that just woke, never one used inside the idle window)
    /// in the background. If every resident slot is hot, the temporary
    /// overshoot is allowed up to the hard ceiling — eviction must never make
    /// a live user wait.
    fn enforce_window(self: &Arc<Self>, keep: Arc<AccountSlot>) {
        if self.resident_count() <= self.config.policy.max_resident {
            return;
        }
        let pool = Arc::clone(self);
        let keep_id = keep.account_id.clone();
        tokio::spawn(async move {
            let mut excess = pool
                .resident_count()
                .saturating_sub(pool.config.policy.max_resident);
            if excess == 0 {
                return;
            }
            let mut candidates = pool.slots();
            candidates.sort_by_key(|left| left.last_used());
            for slot in candidates {
                if excess == 0 {
                    break;
                }
                if !slot.is_resident()
                    || slot.account_id == keep_id
                    || slot.idle_for() < pool.config.policy.demote_idle_after
                {
                    continue;
                }
                slot.set_resident(false);
                slot.supervisor.stop_background_tasks();
                let supervisor = Arc::clone(&slot.supervisor);
                tokio::spawn(async move {
                    let _ = supervisor.shutdown().await;
                });
                tracing::info!(
                    account_id = %slot.account_id,
                    group_id = %slot.proxy_group,
                    "per-account engine demoted out of the resident window"
                );
                excess -= 1;
            }
        });
    }

    /// Per-slot status snapshot for `runtime.status` `engines[]`, in
    /// deterministic account-id order.
    pub async fn statuses(&self) -> Vec<AccountEngineStatus> {
        let mut statuses = Vec::new();
        for slot in self.slots() {
            let status = slot.supervisor.status().await;
            statuses.push(AccountEngineStatus {
                account_id: slot.account_id.clone(),
                proxy_group: Some(slot.proxy_group.clone()),
                state: status.state,
                pid: status.pid,
                rss_bytes: status.rss_bytes,
                resource_pressure: status.resource_pressure,
                resident: slot.is_resident(),
                restarts: slot.supervisor.restart_count(),
            });
        }
        statuses
    }
}

#[allow(clippy::too_many_arguments)]
fn build_slot(
    config: &EnginePoolConfig,
    account_id: String,
    proxy_group: String,
    data_dir: PathBuf,
    sidecar: PathBuf,
    provisioned: bool,
    last_used: Instant,
    lock: Option<DataDirLock>,
) -> Arc<AccountSlot> {
    let mut engine_config = EngineConfig::new(config.engine_bin.clone(), data_dir.clone());
    engine_config.media_ingest = config.media_ingest;
    engine_config.single_account_guard = config.single_account_guard;
    engine_config.expire_sweep_interval = config.expire_sweep_interval;
    // M6 C phase: this slot's engine gets its own account's derivation of the
    // connector root key, so two engines of the same connector never share key
    // material. Without a root key the slot builds unkeyed (never a generated
    // stand-in): the engine keeps its plaintext legacy store.
    engine_config.store_key =
        crate::store::engine_store_key_for_account(config.root_store_key.as_ref(), &account_id);
    if let Some(interval) = config.watchdog_interval {
        engine_config.watchdog_interval = interval;
    }
    let supervisor = Arc::new(RuntimeSupervisor::with_media_root(
        engine_config,
        Arc::clone(&config.store),
        proxy_group.clone(),
        config.media_handles.clone(),
        config.backup_handles.clone(),
        // Media stays at the connector root: `<signal-data>/media/<acct>`.
        Some(config.signal_data_dir.clone()),
        Some(account_id.clone()),
    ));
    supervisor.spawn_watchdog();
    supervisor.spawn_media_governor();
    supervisor.spawn_delivery_receipt_worker();
    supervisor.spawn_outbox_worker();
    supervisor.spawn_background_sync_worker();
    supervisor.spawn_avatar_refresh_worker();
    supervisor.spawn_expire_sweeper();
    let routing = Arc::new(crate::registry::ProxyGroupSlot::new(
        account_id.clone(),
        Arc::clone(&supervisor),
    ));
    Arc::new(AccountSlot {
        account_id,
        proxy_group,
        data_dir,
        sidecar,
        routing,
        supervisor,
        wake: tokio::sync::Mutex::new(()),
        resident: AtomicBool::new(false),
        provisioned: AtomicBool::new(provisioned),
        lock: StdMutex::new(lock),
        last_used: StdMutex::new(last_used),
    })
}

/// Account-id grammar: exactly 32 lowercase hex characters — the
/// `crate::ids::random_id` shape. Anything else is never a provisioned slot,
/// so a stray directory (or a hostile name) can neither be adopted nor
/// traversed.
pub fn is_account_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sidecar_path(state_dir: &Path, account_id: &str) -> PathBuf {
    state_dir
        .join(PROVISION_SIDECAR_SUBDIR)
        .join(format!("{account_id}.json"))
}

#[derive(Debug)]
struct SidecarRecord {
    proxy_group: String,
    provisioned: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SidecarWire<'a> {
    account_id: &'a str,
    proxy_group: &'a str,
    provisioned: bool,
    created_at_ms: u128,
}

fn read_sidecar(path: &Path) -> Option<SidecarRecord> {
    let raw = std::fs::read(path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let proxy_group = value.get("proxyGroup")?.as_str()?.to_string();
    let provisioned = value
        .get("provisioned")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Some(SidecarRecord {
        proxy_group,
        provisioned,
    })
}

fn write_sidecar(
    path: &Path,
    account_id: &str,
    proxy_group: &str,
    provisioned: bool,
) -> io::Result<()> {
    if !is_account_id(account_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid account id",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sidecar parent"))?;
    ensure_private_dir(parent)?;
    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or_default();
    let wire = SidecarWire {
        account_id,
        proxy_group,
        provisioned,
        created_at_ms,
    };
    let bytes = serde_json::to_vec(&wire)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sidecar encoding"))?;
    let temp = parent.join(format!(".{account_id}.json.tmp"));
    std::fs::write(&temp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&temp, path)
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// 在槽目录写一份有效但空的 V2 注册表：version=2, accounts=[]。
///
/// 为什么必须在建目录后立刻写：引擎的 EngineState::load 只在注册表**缺失**时
/// 才做「有 store 即不可信」的判定（RegistryMissingWithStores）。link 流程里引擎
/// 自己会建 accounts/lk-*，若此时引擎重启，缺注册表会被误判为孤儿目录、记入
/// accounts/_quarantine/，而隔离区非空会让此后每次启动都 fail closed。
/// 写入 V2 后引擎直接采信注册表（空账号表），不再检查 store；link 完成时由
/// supervisor 覆盖为含真实条目的注册表。
///
/// 原子写 + 0600，与注册表其他写入点（migrate / state）保持同一权限纪律。
fn write_empty_engine_registry(data_dir: &Path) -> io::Result<()> {
    use std::io::Write;

    let payload = serde_json::to_vec(&serde_json::json!({
        "version": 2,
        "accounts": [],
    }))
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let path = data_dir.join(crate::history_import::ENGINE_REGISTRY_FILE);
    let temp = data_dir.join(format!(
        ".engine-state.json.tmp-{}",
        crate::ids::random_id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(&payload)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, &path)
}

fn modified_instant(path: &Path) -> Instant {
    let modified = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(UNIX_EPOCH);
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    Instant::now().checked_sub(age).unwrap_or_else(Instant::now)
}

fn error_class(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::AlreadyExists => "already_exists",
        io::ErrorKind::InvalidInput => "invalid_input",
        _ => "io",
    }
}

fn pool_unavailable_error() -> ServiceError {
    ServiceError::Api(ApiError::new(
        "CAPABILITY_UNAVAILABLE",
        "the per-account engine pool is unavailable on this host",
        false,
    ))
}

/// Test hook: the connector-owned media root a dynamic slot uses. Production
/// code reads it through `RuntimeSupervisor::media_root`; the pool tests pin
/// that it is the signal-data root, never the engine data directory.
#[cfg(test)]
pub(crate) fn slot_media_root(slot: &AccountSlot) -> Option<PathBuf> {
    slot.supervisor.media_root().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::store::StoreKey;

    fn config(temp: &TempDir, media_ingest: bool) -> EnginePoolConfig {
        let store = Arc::new(
            Store::open(
                &temp.path().join("state"),
                Some(StoreKey::from_bytes([0x5A; 32])),
            )
            .unwrap(),
        );
        EnginePoolConfig {
            engine_bin: PathBuf::from("/bin/false"),
            signal_data_dir: temp.path().join("signal-data"),
            state_dir: temp.path().join("state"),
            media_ingest,
            expire_sweep_interval: std::time::Duration::from_secs(30),
            store,
            media_handles: media_ingest.then(|| Arc::new(crate::media::MediaHandleTable::new())),
            backup_handles: None,
            policy: EnginePoolPolicy::default(),
            single_account_guard: false,
            watchdog_interval: None,
            root_store_key: Some(StoreKey::from_bytes([0x5A; 32])),
        }
    }

    #[test]
    fn account_id_grammar_accepts_only_the_opaque_hex_shape() {
        assert!(is_account_id("0123456789abcdef0123456789abcdef"));
        for value in [
            "",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "../0123456789abcdef0123456789abc",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(!is_account_id(value), "{value:?} must be rejected");
        }
    }

    #[tokio::test]
    async fn capacity_refuses_the_ninth_slot_and_frees_on_discard() {
        let temp = TempDir::new().unwrap();
        let pool = AccountPool::discover(config(&temp, false));
        let mut slots = Vec::new();
        for _ in 0..MAX_PER_ACCOUNT_ENGINES {
            slots.push(pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap());
        }
        assert_eq!(pool.len(), MAX_PER_ACCOUNT_ENGINES);
        let error = pool
            .provision_slot(DEFAULT_PROXY_GROUP_ID)
            .err()
            .expect("the ninth slot is refused");
        assert_eq!(error.into_api().code, "ENGINE_POOL_FULL");
        assert_eq!(pool.len(), MAX_PER_ACCOUNT_ENGINES);

        let removed = slots.pop().unwrap();
        pool.discard(removed.account_id(), true).await;
        assert_eq!(pool.len(), MAX_PER_ACCOUNT_ENGINES - 1);
        let replacement = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        assert_eq!(pool.len(), MAX_PER_ACCOUNT_ENGINES);
        pool.discard(replacement.account_id(), true).await;
    }

    #[tokio::test]
    async fn discovery_prefers_the_store_binding_over_the_sidecar() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp, false);
        let store = Arc::clone(&cfg.store);
        let id = "0123456789abcdef0123456789abcdef";
        store
            .upsert_account_from_signal_with_id("+15550000001", Some(1), "team-b", Some(id))
            .unwrap();
        let slot_dir = cfg.signal_data_dir.join(ENGINE_SLOT_SUBDIR).join(id);
        std::fs::create_dir_all(slot_dir.join("accounts").join("lk-one")).unwrap();
        std::fs::write(
            slot_dir.join("engine-state.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "accounts": [{"number": "+15550000001", "dir": "accounts/lk-one"}],
            }))
            .unwrap(),
        )
        .unwrap();
        // Foreign names are never adopted.
        std::fs::create_dir_all(
            cfg.signal_data_dir
                .join(ENGINE_SLOT_SUBDIR)
                .join("not-an-account"),
        )
        .unwrap();
        std::fs::create_dir_all(
            cfg.signal_data_dir
                .join(ENGINE_SLOT_SUBDIR)
                .join("_anonymous"),
        )
        .unwrap();

        let pool = AccountPool::discover(cfg);
        assert_eq!(pool.len(), 1);
        let slot = pool.get(id).expect("discovered slot");
        assert_eq!(slot.proxy_group(), "team-b");
    }

    #[tokio::test]
    async fn media_root_is_the_connector_root_not_the_engine_directory() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp, true);
        let signal_data_dir = cfg.signal_data_dir.clone();
        let pool = AccountPool::discover(cfg);
        let slot = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        let root = slot_media_root(&slot).expect("media root armed");
        assert_eq!(root, signal_data_dir);
        assert_ne!(
            root,
            signal_data_dir
                .join(ENGINE_SLOT_SUBDIR)
                .join(slot.account_id())
        );
        pool.discard(slot.account_id(), true).await;
    }

    /// Two account buckets under one connector media root stay disjoint, and
    /// removing one account's engine slot never touches the other's files.
    #[tokio::test]
    async fn media_buckets_stay_disjoint_when_a_slot_is_discarded() {
        let temp = TempDir::new().unwrap();
        let cfg = config(&temp, true);
        let root = cfg.signal_data_dir.clone();
        let pool = AccountPool::discover(cfg);
        let first = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        let second = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        let governor = crate::media::MediaGovernor::new(root.clone());
        let first_dir = governor
            .ensure_account_attachments_dir(first.account_id())
            .unwrap();
        let second_dir = governor
            .ensure_account_attachments_dir(second.account_id())
            .unwrap();
        // Concurrent writes into two account buckets under one media root.
        let first_path = first_dir.join("one.bin");
        let second_path = second_dir.join("two.bin");
        let (first_write, second_write) = tokio::join!(
            tokio::task::spawn_blocking(move || std::fs::write(first_path, b"first")),
            tokio::task::spawn_blocking(move || std::fs::write(second_path, b"second")),
        );
        first_write.unwrap().unwrap();
        second_write.unwrap().unwrap();

        pool.discard(first.account_id(), true).await;
        // Media is connector-owned: removing the first account's engine data
        // directory must not remove its media bucket (and never the other
        // account's files).
        assert!(
            first_dir.join("one.bin").is_file(),
            "media must not live inside the discarded engine data directory"
        );
        assert!(second_dir.join("two.bin").is_file());
        assert_eq!(
            std::fs::read(second_dir.join("two.bin")).unwrap(),
            b"second"
        );
        pool.discard(second.account_id(), true).await;
    }

    /// QR B1 (issue #951): a lost session remains owned by its slot for
    /// routing (the registry asks session_owner before dispatching a finish),
    /// while has_pending_link reads false so the abandoned-link reaper is not
    /// suppressed by a dead QR forever.
    #[tokio::test]
    async fn lost_sessions_keep_their_slot_ownership_for_routing() {
        let temp = TempDir::new().unwrap();
        let pool = AccountPool::discover(config(&temp, false));
        let slot = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        let service = slot.supervisor().service();
        let session = service
            .lock()
            .await
            .plant_link_session_for_test("KT-Lost", Duration::from_secs(300));
        assert!(service.lock().await.mark_link_lost(&session));
        pool.remember_session(&session, slot.account_id());

        assert_eq!(
            pool.session_owner(&session).as_deref(),
            Some(slot.account_id()),
            "the pool keeps a lost session's owner for finish routing"
        );
        assert!(
            service.lock().await.has_link_session(&session),
            "the slot's service keeps the lost session addressable"
        );
        assert!(
            !service.lock().await.has_pending_link(),
            "a lost session must not suppress the abandoned-link reaper"
        );
        pool.discard(slot.account_id(), true).await;
    }

    #[tokio::test]
    async fn session_ownership_is_forgotten_with_the_slot() {
        let temp = TempDir::new().unwrap();
        let pool = AccountPool::discover(config(&temp, false));
        let slot = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        pool.remember_session("kt-link-1", slot.account_id());
        assert_eq!(
            pool.session_owner("kt-link-1").as_deref(),
            Some(slot.account_id())
        );
        pool.discard(slot.account_id(), true).await;
        assert!(pool.session_owner("kt-link-1").is_none());
    }

    /// Product decision (2026-10-21): the default resident window equals the
    /// hard ceiling, so idle demotion is off; the env opt-out is parsed into a
    /// smaller window.
    #[test]
    fn default_resident_window_equals_the_ceiling() {
        let policy = EnginePoolPolicy::default();
        assert_eq!(policy.max_engines, MAX_PER_ACCOUNT_ENGINES);
        assert_eq!(policy.max_resident, MAX_RESIDENT_ENGINES);
        assert_eq!(policy.max_resident, policy.max_engines);
        let normalized = EnginePoolPolicy {
            max_resident: usize::MAX,
            ..EnginePoolPolicy::default()
        }
        .normalized();
        assert_eq!(normalized.max_resident, normalized.max_engines);
    }
}
