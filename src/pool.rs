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

/// The store-migration switch (M6 phase D3). Three values, and the default is
/// off: a connector that was never told to migrate behaves exactly as it did
/// before this phase - no child is spawned, no store byte is read, and no
/// account changes state.
///
/// | value | behaviour |
/// |---|---|
/// | off (default, also for any unrecognised value) | no migration; start the engine as before |
/// | dry-run | run the migrator with --dry-run (plans only, writes nothing), then start the engine regardless of what it answered |
/// | apply | for a slot whose engine is **not** running: migrate with the account's derived key, then start the engine (a live engine is left alone - it answers already_running). Exit 0 also marks the slot migrated for this process, so later starts skip the whole-store verify; exit 10 keeps the plaintext store and retries on the next start; exit 11 blocks the slot with an actionable message |
pub const STORE_MIGRATE_ENV: &str = "KT_ENGINE_STORE_MIGRATE";

/// Migration budget override, in milliseconds. The migrator copies and exports
/// a whole store, so it gets its own budget instead of inheriting the 15 s
/// request timeout - a request budget would fail the migration precisely on
/// the slow disks that need it most. Default: STORE_MIGRATION_BUDGET. Clamped
/// to a floor so a typo cannot make every migration time out.
pub const STORE_MIGRATE_BUDGET_ENV: &str = "KT_ENGINE_STORE_MIGRATE_BUDGET_MS";

/// Default per-slot migration budget (engine design 8.2: 120 s per account,
/// deliberately independent of the request timeout).
pub const STORE_MIGRATION_BUDGET: Duration = Duration::from_secs(120);

/// Floor for the budget override: below this a legitimate copy of a real store
/// would time out by construction.
pub const STORE_MIGRATION_BUDGET_FLOOR: Duration = Duration::from_millis(200);

/// Attempts per slot start for a retryable (exit 10) migration. Bounded on
/// purpose: exit 10 means "wait and it may work" (busy store, transient I/O),
/// not "spin until it does". A run that timed out is never retried in the same
/// pass - retrying a wedged copy would stretch one slot start to
/// attempts x budget.
pub const STORE_MIGRATION_ATTEMPTS: usize = 3;

/// Backoff between retryable migration attempts.
pub const STORE_MIGRATION_BACKOFF: Duration = Duration::from_millis(200);

/// Three-valued migration switch. Unknown input is off, never an error: this
/// key decides whether a destructive-capable pass runs, so the fail-safe
/// direction is "do nothing", and a typo must not take the connector down -
/// one env key is a bad way to cause an outage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StoreMigrationMode {
    #[default]
    Off,
    DryRun,
    Apply,
}

impl StoreMigrationMode {
    /// Strict, case-insensitive parse. Unset is off; anything outside the three
    /// words answers None so the caller can warn and stay off.
    pub fn parse(raw: Option<&str>) -> Option<Self> {
        match raw.map(str::trim) {
            None | Some("") => Some(Self::Off),
            Some(value) => match value.to_ascii_lowercase().as_str() {
                "off" => Some(Self::Off),
                "dry-run" | "dry_run" | "dryrun" => Some(Self::DryRun),
                "apply" => Some(Self::Apply),
                _ => None,
            },
        }
    }

    /// The log label. A label only, never input for a decision.
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::DryRun => "dry_run",
            Self::Apply => "apply",
        }
    }
}

/// The resolved switch plus budget for one connector process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreMigrationOptions {
    pub mode: StoreMigrationMode,
    pub budget: Duration,
}

impl Default for StoreMigrationOptions {
    fn default() -> Self {
        Self {
            mode: StoreMigrationMode::Off,
            budget: STORE_MIGRATION_BUDGET,
        }
    }
}

impl StoreMigrationOptions {
    /// Read the launcher's decision once, at runtime assembly. An invalid mode
    /// keeps the safe direction (off) with one warning; an invalid budget keeps
    /// the default with one warning.
    pub fn from_env() -> Self {
        let mode = match StoreMigrationMode::parse(std::env::var(STORE_MIGRATE_ENV).ok().as_deref())
        {
            Some(mode) => mode,
            None => {
                tracing::warn!(
                    env = STORE_MIGRATE_ENV,
                    store_migration = StoreMigrationMode::Off.label(),
                    "unrecognised store-migration mode; staying off"
                );
                StoreMigrationMode::Off
            }
        };
        let budget = match std::env::var(STORE_MIGRATE_BUDGET_ENV) {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(ms) => Duration::from_millis(ms).max(STORE_MIGRATION_BUDGET_FLOOR),
                Err(_) => {
                    tracing::warn!(
                        env = STORE_MIGRATE_BUDGET_ENV,
                        "invalid store-migration budget; using the default"
                    );
                    STORE_MIGRATION_BUDGET
                }
            },
            Err(_) => STORE_MIGRATION_BUDGET,
        };
        Self { mode, budget }
    }

    pub fn is_enabled(self) -> bool {
        self.mode != StoreMigrationMode::Off
    }
}

/// What the gate decided for one slot start. The caller does exactly two things
/// with it: starts the engine, or refuses to (with a reason it logs and, where
/// a host asked, hands back).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreMigrationDecision {
    /// Start the engine. Outcome is the log label: disabled, skipped, migrated,
    /// noop, planned, or planned_failed.
    Start { outcome: &'static str },
    /// Do not start this pass: the migration was retryable (exit 10) or ran out
    /// of budget. The store is untouched, nothing is latched, and the next start
    /// retries.
    Retry { code: String },
    /// Do not start, ever, until a human acts. Latched on the slot.
    Blocked { block: StoreMigrationBlock },
    /// The migrator rejected the invocation itself (exit 2): an integration bug
    /// in the connector, not a property of the account. Never latched, never
    /// retried within this pass.
    Misconfigured,
}

/// A latched terminal migration failure for one account: the engine code plus
/// one human-readable, actionable sentence - never a key, an address, a path, or
/// raw engine output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreMigrationBlock {
    pub code: String,
    pub exit: Option<i32>,
    /// The operator/host-facing sentence. Stable enough to render in a UI.
    pub message: String,
}

impl StoreMigrationBlock {
    /// The API face of a blocked account: not retryable, because retrying is
    /// exactly what a restart storm does and exit 11 says it will not work.
    pub fn service_error(&self) -> ServiceError {
        ServiceError::Api(ApiError::new(
            "CAPABILITY_UNAVAILABLE",
            self.message.clone(),
            false,
        ))
    }
}

/// The human-readable text for a terminal migration failure. One sentence the
/// operator can act on, derived only from the engine's closed code vocabulary;
/// an unknown code still gets the generic remedy rather than a silent pass.
pub fn store_migration_block_message(code: &str) -> String {
    let remedy = "Re-link the account (delete its local data and link it again) to rebuild the \
                  store, or restore the store key this account was migrated with, then restart \
                  KT Desktop.";
    match code {
        // Key material problems: the store is fine, the key it needs is not.
        "StoreKeyRequired" | "StoreKeyInvalid" | "store_key_mismatch" | "store_key_rejected" => {
            format!(
                "the encrypted store of this account cannot be opened with the current store key \
                 ({code}). The plaintext store and its backup were left untouched. {remedy}"
            )
        }
        // Store content problems: a human has to rebuild this one account.
        "store_corrupt" | "store_state_invalid" | "store_migration_verify_failed" => format!(
            "the local Signal store of this account is damaged or failed verification ({code}), \
             so it cannot be moved to the encrypted format. The plaintext store and its backup \
             were left untouched. {remedy}"
        ),
        // A deployment problem, and the one code that must *not* offer the
        // re-link remedy (M6 D3 review M6): an engine build without the store
        // cipher cannot open this format at all, so the account data is intact
        // and a correct build reads it as it is. Telling the operator to delete
        // it would destroy a store that was never broken.
        "StoreCipherUnavailable" => format!(
            "the engine build this connector launched cannot use the encrypted store format \
             ({code}), so this account's store was not moved. This is a deployment problem, not \
             a problem with the account: install the engine build that carries the store cipher \
             (the connector and the engine must come from the same release) and restart KT \
             Desktop. Do not delete or re-link this account - a correct engine build opens its \
             data as it is."
        ),
        _ => format!(
            "the encrypted store of this account could not be built ({code}), and this failure \
             will not resolve by retrying. The plaintext store and its backup were left \
             untouched. {remedy}"
        ),
    }
}

/// The operator-facing text for a retryable/store-not-ready slot. Honest about
/// the two things that matter: nothing was damaged, and the next start tries
/// again.
pub fn store_migration_retry_message(code: &str) -> String {
    format!(
        "the encrypted store of this account is not ready yet ({code}); its engine stays stopped \
         for now and the migration is retried on the next start. The plaintext store was left \
         untouched."
    )
}

/// The operator-facing text for a rejected invocation (exit 2). M6 D3 review
/// M5: "usage error" is engine-speak for one concrete situation the operator
/// can act on - a connector and an engine from different releases, or an engine
/// build without the migration mode - so the sentence names those, says the
/// data is untouched, and carries no stray formatting.
pub fn store_migration_misconfigured_message() -> &'static str {
    "the engine binary this connector launched does not understand the storeMigrate mode (exit 2): \
     the connector and the engine come from different versions, or this engine build has no \
     storeMigrate subcommand. Install the engine build that matches this connector, then restart \
     KT Desktop. No account data was touched, and the migration is tried again on the next start."
}

/// The wire answer for a gate refusal: the retryable/terminal split the decision
/// already carries, in the same shape `ensure_resident` has always used (code
/// `CAPABILITY_UNAVAILABLE`, `retryable` set by whether a later start can
/// succeed on its own).
fn store_migration_refusal_error(decision: StoreMigrationDecision) -> ServiceError {
    match decision {
        StoreMigrationDecision::Blocked { block } => block.service_error(),
        StoreMigrationDecision::Retry { code } => ServiceError::Api(ApiError::new(
            "CAPABILITY_UNAVAILABLE",
            store_migration_retry_message(&code),
            true,
        )),
        StoreMigrationDecision::Misconfigured => ServiceError::Api(ApiError::new(
            "CAPABILITY_UNAVAILABLE",
            store_migration_misconfigured_message(),
            false,
        )),
        // Not a refusal. Only a caller that already got a refusal asks for an
        // error, so this arm is unreachable in practice; answering the engine
        // failure is still truer than inventing a migration verdict.
        StoreMigrationDecision::Start { .. } => ServiceError::Engine(EngineError::StartFailed),
    }
}

/// Classify one migration run into the gate's decision. The exit code is the
/// only authority (engine design 2.4: 0 done/no-op/planned, 2 usage, 10
/// retryable, 11 terminal); the parsed document only supplies the evidence
/// label the log line quotes.
///
/// Dry-run never blocks and never defers a start: it is an observation mode, so
/// even a failing plan answers Start with a "planned_failed" label. Anything
/// that is not a stated exit code is treated as retryable, not terminal - an
/// effect we cannot classify is not a reason to brick a working account.
pub fn classify_store_migration(
    mode: StoreMigrationMode,
    run: &crate::engine::StoreMigrationRun,
) -> StoreMigrationDecision {
    let dry_run = mode == StoreMigrationMode::DryRun;
    if run.timed_out {
        return if dry_run {
            StoreMigrationDecision::Start {
                outcome: "planned_failed",
            }
        } else {
            StoreMigrationDecision::Retry {
                code: "store_migration_timeout".to_string(),
            }
        };
    }
    if run.failed {
        return if dry_run {
            StoreMigrationDecision::Start {
                outcome: "planned_failed",
            }
        } else {
            StoreMigrationDecision::Retry {
                code: "store_migration_spawn_failed".to_string(),
            }
        };
    }
    match run.exit {
        Some(0) => {
            let outcome = if dry_run {
                "planned"
            } else {
                match run.action.as_deref() {
                    Some("migrate") => "migrated",
                    Some("noop") => "noop",
                    Some("absent") => "absent",
                    _ => "completed",
                }
            };
            StoreMigrationDecision::Start { outcome }
        }
        Some(2) => {
            if dry_run {
                StoreMigrationDecision::Start {
                    outcome: "planned_failed",
                }
            } else {
                StoreMigrationDecision::Misconfigured
            }
        }
        Some(10) => {
            if dry_run {
                StoreMigrationDecision::Start {
                    outcome: "planned_failed",
                }
            } else {
                StoreMigrationDecision::Retry {
                    code: run
                        .code
                        .clone()
                        .unwrap_or_else(|| "store_migration_retryable".to_string()),
                }
            }
        }
        Some(11) => {
            if dry_run {
                StoreMigrationDecision::Start {
                    outcome: "planned_failed",
                }
            } else {
                let code = run
                    .code
                    .clone()
                    .unwrap_or_else(|| "store_migration_blocked".to_string());
                StoreMigrationDecision::Blocked {
                    block: StoreMigrationBlock {
                        message: store_migration_block_message(&code),
                        code,
                        exit: run.exit,
                    },
                }
            }
        }
        _ => {
            if dry_run {
                StoreMigrationDecision::Start {
                    outcome: "planned_failed",
                }
            } else {
                StoreMigrationDecision::Retry {
                    code: "store_migration_unexpected_exit".to_string(),
                }
            }
        }
    }
}

/// Short account fingerprint for log lines: the first eight characters of the
/// opaque account id - enough to correlate two lines of the same account, never
/// an address, a number, or key material.
pub fn account_fingerprint(account_id: &str) -> String {
    account_id.chars().take(8).collect()
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
    /// The launcher's store-migration decision (M6 D3), resolved once at
    /// runtime assembly. Off - the default - spawns no migrator at all.
    pub store_migration: StoreMigrationOptions,
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

/// Why a cold wake did not end with a live engine.
///
/// Split out of [`ServiceError`] for one reason (M6 D3 review M2): a caller
/// whose job is not to serve traffic must be able to tell "the store-migration
/// gate refused this account" - a verdict about this account's store, which
/// deleting its local data resolves - from "this slot cannot start at all".
/// Every other caller gets the same wire answer as before through
/// [`SlotWakeRefusal::into_service_error`].
#[derive(Debug)]
pub enum SlotWakeRefusal {
    /// The store-migration gate refused this start.
    MigrationGate(StoreMigrationDecision),
    /// Anything else: no data-directory lock, a supervisor that would not
    /// start, or an engine that exited.
    Failed(ServiceError),
}

impl SlotWakeRefusal {
    /// Whether the store-migration gate is what refused this start.
    pub fn is_migration_gate(&self) -> bool {
        matches!(self, Self::MigrationGate(_))
    }

    /// The host-facing error. Byte-for-byte what `ensure_resident` answered
    /// before this split existed; the distinction is internal.
    pub fn into_service_error(self) -> ServiceError {
        match self {
            Self::MigrationGate(decision) => store_migration_refusal_error(decision),
            Self::Failed(error) => error,
        }
    }
}

/// The window a repeated startup-refusal line waits between emissions.
pub const REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(60);

/// A rate limit for one line a restart storm would otherwise repeat once a
/// second (M6 D3 review M5). A watchdog, a host retry and an operator all
/// reaching the same refusal is one fact; printing it every second is how the
/// fact gets ignored. The first occurrence always logs; later ones log at most
/// once per window and carry how many repeats they stood for.
#[derive(Debug, Default)]
struct RepeatThrottle {
    state: StdMutex<Option<ThrottleWindow>>,
}

#[derive(Clone, Copy, Debug)]
struct ThrottleWindow {
    last: Instant,
    suppressed: u64,
}

impl RepeatThrottle {
    /// `Some(suppressed)` when this occurrence should be logged, carrying the
    /// repeats dropped since the previous line; `None` inside the window.
    fn allow(&self, window: Duration) -> Option<u64> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match state.as_mut() {
            Some(previous) if previous.last.elapsed() < window => {
                previous.suppressed = previous.suppressed.saturating_add(1);
                None
            }
            Some(previous) => {
                let suppressed = previous.suppressed;
                *previous = ThrottleWindow {
                    last: Instant::now(),
                    suppressed: 0,
                };
                Some(suppressed)
            }
            None => {
                *state = Some(ThrottleWindow {
                    last: Instant::now(),
                    suppressed: 0,
                });
                Some(0)
            }
        }
    }
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
    /// Latched terminal store-migration failure (M6 D3). Set once from an
    /// engine exit 11 and never cleared for the life of the process: the point
    /// of the latch is that no later start, wake, or watchdog pass turns "a
    /// human must act" into a restart loop.
    migration_block: StdMutex<Option<StoreMigrationBlock>>,
    /// Set once a run has left this slot's store in the encrypted format
    /// (`action: migrate`) or found it already there (`noop`) - M6 D3 review
    /// M4. The whole-store verification is the expensive half of a migration
    /// run, and re-running it on every later start of a store this process has
    /// already proved buys nothing. Process-scoped on purpose: the next process
    /// pays for one check, so a store restored from a backup still migrates.
    store_migrated: AtomicBool,
    /// Throttle for the exit-2 line (M6 D3 review M5).
    misconfigured_log: RepeatThrottle,
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

    /// The latched terminal migration failure for this slot, if any. Read-only:
    /// clearing it means a new process, because the store state a human had to
    /// fix is not something a running connector may re-judge.
    pub fn migration_block(&self) -> Option<StoreMigrationBlock> {
        self.migration_block
            .lock()
            .map(|block| block.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    fn latch_migration_block(&self, block: StoreMigrationBlock) {
        if let Ok(mut slot) = self.migration_block.lock() {
            *slot = Some(block);
        }
    }

    /// Whether this process has already proved this slot's store encrypted
    /// (a completed migration, or a run that found it already done).
    pub fn store_migrated(&self) -> bool {
        self.store_migrated.load(Ordering::Relaxed)
    }

    fn mark_store_migrated(&self) {
        self.store_migrated.store(true, Ordering::Relaxed);
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
            // M6 D3: (stop ->) migrate -> start. The gate is a no-op unless
            // KT_ENGINE_STORE_MIGRATE says otherwise, it leaves a live engine
            // alone (M1), and it short-circuits a store this process already
            // migrated (M4). When it does refuse, the slot simply stays stopped
            // this pass (the reason is already logged with the account
            // fingerprint and the engine's exit code).
            match self.gate_slot_start(&slot).await {
                StoreMigrationDecision::Start { .. } => {}
                _ => continue,
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
    /// M6 phase D3: the store-migration gate that runs **before** a slot's
    /// engine is spawned.
    ///
    /// The ordering is the point and it is not negotiable: stop the slot (no
    /// engine may hold the store) -> migrate with that account's own derived key
    /// -> only then start the engine. No migration ever runs behind a live
    /// engine, and no engine ever opens a store the migrator is still writing.
    ///
    /// Off - the default - returns before touching anything: no process, no
    /// read, no per-account line.
    async fn gate_slot_start(self: &Arc<Self>, slot: &Arc<AccountSlot>) -> StoreMigrationDecision {
        let options = self.config.store_migration;
        if !options.is_enabled() {
            return StoreMigrationDecision::Start {
                outcome: "disabled",
            };
        }
        // M6 D3 review M1: an engine that is already live is success, not a
        // reason to restart. Its store is open in that process, so nothing can
        // be migrated under it - and doing "stop -> migrate -> start" on a
        // healthy slot would cut every in-flight request of that account for a
        // migration it does not need. Same reading ensure_resident applies
        // before it ever reaches this gate (`Running` answers Ok).
        if slot.supervisor.status().await.state == EngineState::Running {
            return StoreMigrationDecision::Start {
                outcome: "already_running",
            };
        }
        // M6 D3 review M4: this process has already migrated this slot's store
        // (or found it migrated). A later start - after a stop, an idle
        // demotion, or a runtime.stop/start cycle - has nothing left to prove:
        // the whole-store verification is the expensive half, and re-running it
        // on every start is pure cost.
        if slot.store_migrated() {
            return StoreMigrationDecision::Start {
                outcome: "already_migrated",
            };
        }
        // A latched terminal failure is answered without spawning anything:
        // that is exactly what keeps exit 11 from becoming a restart storm.
        if let Some(block) = slot.migration_block() {
            return StoreMigrationDecision::Blocked { block };
        }
        // Nothing to migrate without a directory: the engine creates its own
        // store on first start, and a migrator pointed at a missing directory
        // answers a terminal data_dir_missing that would block a brand-new
        // account for no reason.
        if !slot.data_dir.is_dir() {
            tracing::info!(
                store_migration = options.mode.label(),
                account = %account_fingerprint(&slot.account_id),
                store_migration_outcome = "skipped",
                reason = "no_data_dir",
                "engine store migration skipped"
            );
            return StoreMigrationDecision::Start { outcome: "skipped" };
        }
        // Only a pooled slot maps to exactly one account, so only a pooled slot
        // has exactly one account's key. Any other decision must not migrate:
        // opening several accounts' stores with one account's derivation is the
        // cross-account unlock the key model forbids.
        let key = match crate::store::engine_store_key_for_account(
            self.config.root_store_key.as_ref(),
            &slot.account_id,
        ) {
            crate::store::EngineStoreKey::Account(key) => key,
            other => {
                tracing::warn!(
                    store_migration = options.mode.label(),
                    account = %account_fingerprint(&slot.account_id),
                    store_migration_outcome = "skipped",
                    engine_store_key = other.decision(),
                    "engine store migration skipped: no per-account store key"
                );
                return StoreMigrationDecision::Start { outcome: "skipped" };
            }
        };
        // Stop the slot before the migrator touches the store. A slot whose
        // engine refuses to stop is busy: retryable, never latching.
        if slot.supervisor.status().await.state != EngineState::Stopped
            && slot.supervisor.stop().await.is_err()
        {
            tracing::warn!(
                store_migration = options.mode.label(),
                account = %account_fingerprint(&slot.account_id),
                store_migration_outcome = "retry",
                reason = "engine_did_not_stop",
                "engine store migration deferred: the slot did not stop"
            );
            return StoreMigrationDecision::Retry {
                code: "store_busy".to_string(),
            };
        }
        let mut attempt = 0_usize;
        loop {
            attempt += 1;
            let run = crate::engine::run_store_migration(
                &self.config.engine_bin,
                &slot.data_dir,
                &key,
                options.mode == StoreMigrationMode::DryRun,
                options.budget,
            )
            .await;
            let decision = classify_store_migration(options.mode, &run);
            let retryable_in_pass = matches!(decision, StoreMigrationDecision::Retry { .. })
                && !run.timed_out
                && attempt < STORE_MIGRATION_ATTEMPTS;
            match &decision {
                StoreMigrationDecision::Start { outcome } => {
                    // A run that left the store encrypted - or found it so - is
                    // this slot's proof for this process (M4): remember it so a
                    // later start skips the verify entirely. A plan, a skip and
                    // an absent store are not that proof.
                    if options.mode == StoreMigrationMode::Apply
                        && matches!(*outcome, "migrated" | "noop")
                    {
                        slot.mark_store_migrated();
                    }
                    tracing::info!(
                        store_migration = options.mode.label(),
                        account = %account_fingerprint(&slot.account_id),
                        store_migration_outcome = *outcome,
                        run = %run.outcome_label(),
                        exit = run.exit,
                        code = run.code.as_deref(),
                        attempts = attempt,
                        "engine store migration finished"
                    );
                }
                StoreMigrationDecision::Retry { code } if retryable_in_pass => tracing::warn!(
                    store_migration = options.mode.label(),
                    account = %account_fingerprint(&slot.account_id),
                    store_migration_outcome = "retry",
                    run = %run.outcome_label(),
                    exit = run.exit,
                    code = %code,
                    attempt = attempt,
                    "engine store migration is retryable; trying again"
                ),
                StoreMigrationDecision::Retry { code } => tracing::warn!(
                    store_migration = options.mode.label(),
                    account = %account_fingerprint(&slot.account_id),
                    store_migration_outcome = "retry_pending",
                    run = %run.outcome_label(),
                    exit = run.exit,
                    code = %code,
                    attempts = attempt,
                    "engine store migration did not finish; the slot stays stopped this pass"
                ),
                StoreMigrationDecision::Blocked { block } => {
                    slot.latch_migration_block(block.clone());
                    tracing::error!(
                        store_migration = options.mode.label(),
                        account = %account_fingerprint(&slot.account_id),
                        store_migration_outcome = "blocked",
                        run = %run.outcome_label(),
                        exit = block.exit,
                        code = %block.code,
                        "engine store migration is terminal; this account stays stopped until it is resolved"
                    );
                    tracing::error!(
                        account = %account_fingerprint(&slot.account_id),
                        message = %block.message,
                        "engine store migration blocked: what the operator can do"
                    );
                }
                // M6 D3 review M5: the same version skew answers this line on
                // every start, and a start storm would make it one error a
                // second. Throttled per slot; the suppressed count rides on the
                // next line so nothing is silently lost.
                StoreMigrationDecision::Misconfigured => {
                    if let Some(suppressed) = slot.misconfigured_log.allow(REFUSAL_LOG_WINDOW) {
                        tracing::error!(
                            store_migration = options.mode.label(),
                            account = %account_fingerprint(&slot.account_id),
                            store_migration_outcome = "misconfigured",
                            run = %run.outcome_label(),
                            exit = run.exit,
                            suppressed,
                            message = store_migration_misconfigured_message(),
                            "the engine does not understand the storeMigrate mode (exit 2): mixed \
                             connector/engine versions, or an engine build without it"
                        );
                    }
                }
            }
            if retryable_in_pass {
                tokio::time::sleep(STORE_MIGRATION_BACKOFF * attempt as u32).await;
                continue;
            }
            return decision;
        }
    }

    /// The latched terminal migration failure for one account, if any. The
    /// read-only face a diagnostics endpoint or a test can consult without
    /// spawning anything.
    pub fn migration_block(&self, account_id: &str) -> Option<StoreMigrationBlock> {
        self.get(account_id).and_then(|slot| slot.migration_block())
    }

    /// Wake a cold slot for traffic, answering exactly the wire errors it
    /// always has: a latched block (not retryable), a retryable deferral, or the
    /// supervisor's own failure. The typed refusal stays inside
    /// [`Self::wake_slot`].
    pub async fn ensure_resident(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Result<(), ServiceError> {
        self.wake_slot(slot)
            .await
            .map_err(SlotWakeRefusal::into_service_error)
    }

    /// Wake one cold slot and keep the reason it did not work distinguishable.
    ///
    /// Same gate as the resident window, under the wake lock: a cold slot woken
    /// by an account-addressed request migrates before it serves, and a
    /// gateway refusal answers the caller with the matching error instead of
    /// starting an engine that cannot work.
    ///
    /// A caller that needs an engine **only as a means** to reach the store -
    /// the local-data delete, its one non-routing user - can tell
    /// [`SlotWakeRefusal::MigrationGate`] from a plain failure and take the
    /// engine-free path, instead of letting the gate veto the very action its
    /// own message prescribes.
    pub async fn wake_slot(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Result<(), SlotWakeRefusal> {
        slot.touch();
        if slot.supervisor.status().await.state == EngineState::Running {
            slot.set_resident(true);
            return Ok(());
        }
        if !slot.holds_lock() {
            return Err(SlotWakeRefusal::Failed(ServiceError::Api(ApiError::new(
                "CAPABILITY_UNAVAILABLE",
                "the account engine data directory is occupied",
                false,
            ))));
        }
        let _wake = slot.wake.lock().await;
        if slot.supervisor.status().await.state != EngineState::Running {
            match self.gate_slot_start(slot).await {
                StoreMigrationDecision::Start { .. } => {}
                refusal => return Err(SlotWakeRefusal::MigrationGate(refusal)),
            }
        }
        if slot.supervisor.status().await.state != EngineState::Running {
            match slot.supervisor.start().await {
                Ok(status) if status.state == EngineState::Running => {}
                Ok(_) => {
                    return Err(SlotWakeRefusal::Failed(ServiceError::Engine(
                        EngineError::StartFailed,
                    )));
                }
                Err(EngineError::Backpressure) => {}
                Err(error) => return Err(SlotWakeRefusal::Failed(ServiceError::Engine(error))),
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
        migration_block: StdMutex::new(None),
        store_migrated: AtomicBool::new(false),
        misconfigured_log: RepeatThrottle::default(),
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
            store_migration: StoreMigrationOptions::default(),
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

    // ———————————————————— M6 D3: store-migration switch ————————————————————

    #[test]
    fn store_migration_mode_parses_only_the_three_documented_words() {
        assert_eq!(
            StoreMigrationMode::parse(None),
            Some(StoreMigrationMode::Off)
        );
        assert_eq!(
            StoreMigrationMode::parse(Some("")),
            Some(StoreMigrationMode::Off)
        );
        assert_eq!(
            StoreMigrationMode::parse(Some(" off ")),
            Some(StoreMigrationMode::Off)
        );
        assert_eq!(
            StoreMigrationMode::parse(Some("dry-run")),
            Some(StoreMigrationMode::DryRun)
        );
        assert_eq!(
            StoreMigrationMode::parse(Some("dry_run")),
            Some(StoreMigrationMode::DryRun)
        );
        assert_eq!(
            StoreMigrationMode::parse(Some("DRY-RUN")),
            Some(StoreMigrationMode::DryRun)
        );
        assert_eq!(
            StoreMigrationMode::parse(Some("apply")),
            Some(StoreMigrationMode::Apply)
        );
        // An unrecognised value is *not* a mode: the caller warns and stays off,
        // because one typo must never arm a migration pass.
        assert_eq!(StoreMigrationMode::parse(Some("1")), None);
        assert_eq!(StoreMigrationMode::parse(Some("on")), None);
        assert_eq!(StoreMigrationMode::parse(Some("applyy")), None);
    }

    #[test]
    fn store_migration_options_default_to_off_and_only_off_is_disabled() {
        let options = StoreMigrationOptions::default();
        assert_eq!(options.mode, StoreMigrationMode::Off);
        assert!(!options.is_enabled());
        assert_eq!(options.budget, STORE_MIGRATION_BUDGET);
        for (mode, enabled) in [
            (StoreMigrationMode::Off, false),
            (StoreMigrationMode::DryRun, true),
            (StoreMigrationMode::Apply, true),
        ] {
            assert_eq!(
                StoreMigrationOptions { mode, ..options }.is_enabled(),
                enabled,
                "{mode:?}"
            );
        }
    }

    fn migration_run(
        exit: Option<i32>,
        action: Option<&str>,
        code: Option<&str>,
    ) -> crate::engine::StoreMigrationRun {
        crate::engine::StoreMigrationRun {
            exit,
            action: action.map(str::to_string),
            code: code.map(str::to_string),
            ..crate::engine::StoreMigrationRun::default()
        }
    }

    #[test]
    fn exit_zero_starts_the_engine_and_names_the_action() {
        for (action, expected) in [
            (Some("migrate"), "migrated"),
            (Some("noop"), "noop"),
            (Some("absent"), "absent"),
            (None, "completed"),
        ] {
            let decision = classify_store_migration(
                StoreMigrationMode::Apply,
                &migration_run(Some(0), action, Some("store_migrated")),
            );
            assert_eq!(
                decision,
                StoreMigrationDecision::Start { outcome: expected },
                "action {action:?}"
            );
        }
    }

    #[test]
    fn exit_ten_is_retryable_and_keeps_the_engine_stopped() {
        let decision = classify_store_migration(
            StoreMigrationMode::Apply,
            &migration_run(Some(10), Some("failed"), Some("store_busy")),
        );
        assert_eq!(
            decision,
            StoreMigrationDecision::Retry {
                code: "store_busy".to_string()
            }
        );
    }

    #[test]
    fn exit_eleven_is_terminal_and_carries_an_actionable_message() {
        let decision = classify_store_migration(
            StoreMigrationMode::Apply,
            &migration_run(Some(11), Some("failed"), Some("store_key_rejected")),
        );
        let StoreMigrationDecision::Blocked { block } = decision else {
            panic!("exit 11 must latch a block, got {decision:?}");
        };
        assert_eq!(block.code, "store_key_rejected");
        assert_eq!(block.exit, Some(11));
        assert!(block.message.contains("store_key_rejected"), "{block:?}");
        assert!(block.message.contains("Re-link the account"), "{block:?}");
        // The API face is not retryable: exit 11 says retrying will not work.
        match block.service_error() {
            ServiceError::Api(error) => {
                assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
                assert!(!error.retryable);
                assert!(error.message.contains("Re-link the account"));
            }
            other => panic!("a blocked slot must answer an API error, got {other:?}"),
        }
    }

    #[test]
    fn exit_two_is_a_connector_bug_not_an_account_failure() {
        assert_eq!(
            classify_store_migration(
                StoreMigrationMode::Apply,
                &migration_run(Some(2), None, None)
            ),
            StoreMigrationDecision::Misconfigured
        );
    }

    #[test]
    fn an_unstated_exit_is_retryable_never_terminal() {
        for run in [
            migration_run(Some(101), Some("failed"), None),
            migration_run(None, None, None),
            crate::engine::StoreMigrationRun {
                timed_out: true,
                ..crate::engine::StoreMigrationRun::default()
            },
            crate::engine::StoreMigrationRun {
                failed: true,
                ..crate::engine::StoreMigrationRun::default()
            },
        ] {
            assert!(
                matches!(
                    classify_store_migration(StoreMigrationMode::Apply, &run),
                    StoreMigrationDecision::Retry { .. }
                ),
                "{run:?} must not brick an account"
            );
        }
    }

    #[test]
    fn dry_run_never_blocks_and_never_defers_a_start() {
        for run in [
            migration_run(Some(0), Some("dry-run"), Some("store_migration_planned")),
            migration_run(Some(2), None, None),
            migration_run(Some(10), Some("failed"), Some("store_busy")),
            migration_run(Some(11), Some("failed"), Some("store_corrupt")),
            crate::engine::StoreMigrationRun {
                timed_out: true,
                ..crate::engine::StoreMigrationRun::default()
            },
        ] {
            match classify_store_migration(StoreMigrationMode::DryRun, &run) {
                StoreMigrationDecision::Start { outcome } => {
                    assert!(
                        outcome == "planned" || outcome == "planned_failed",
                        "{outcome}"
                    );
                }
                other => panic!("dry-run must still start the engine, got {other:?}"),
            }
        }
    }

    #[test]
    fn retry_message_is_honest_about_state_and_next_step() {
        let message = store_migration_retry_message("store_busy");
        assert!(message.contains("store_busy"));
        assert!(message.contains("retried on the next start"));
        assert!(message.contains("plaintext store was left untouched"));
        assert!(!message.contains("Re-link the account"));
    }

    #[test]
    fn block_messages_name_the_code_and_the_remedy_without_key_material() {
        for code in [
            "StoreKeyRequired",
            "store_key_rejected",
            "store_corrupt",
            "store_state_invalid",
            "store_migration_verify_failed",
            "something_new",
        ] {
            let message = store_migration_block_message(code);
            assert!(message.contains(code), "{message}");
            assert!(message.contains("Re-link the account"), "{message}");
            assert!(
                message.contains("plaintext store and its backup were left untouched"),
                "{message}"
            );
            // No 64-hex run, ever: a message that could carry a derived key is a
            // message that will, the first time someone formats one in.
            assert!(
                !message
                    .split(|c: char| !c.is_ascii_hexdigit())
                    .any(|run| run.len() >= 64),
                "{message}"
            );
        }
    }

    #[test]
    fn exit_two_message_names_the_version_skew_without_formatting_noise() {
        let message = store_migration_misconfigured_message();
        assert!(message.contains("storeMigrate"), "{message}");
        assert!(message.contains("different versions"), "{message}");
        assert!(message.contains("No account data was touched"), "{message}");
        // The sentence a host renders must not carry the old run of spaces.
        assert!(!message.contains("  "), "no run of spaces: {message}");
        // Exit 2 is not an account failure: the data remedy would be a lie.
        assert!(!message.contains("Re-link"), "{message}");
    }

    #[test]
    fn a_cipherless_engine_build_gets_its_own_deployment_remedy() {
        let message = store_migration_block_message("StoreCipherUnavailable");
        assert!(message.contains("StoreCipherUnavailable"), "{message}");
        assert!(message.contains("deployment problem"), "{message}");
        assert!(message.contains("Do not delete or re-link"), "{message}");
        assert!(
            !message.contains("Re-link the account"),
            "a correct engine build opens this data as it is: {message}"
        );
        assert!(
            !message
                .split(|c: char| !c.is_ascii_hexdigit())
                .any(|run| run.len() >= 64),
            "{message}"
        );
    }

    #[test]
    fn the_exit_two_line_is_throttled_per_window() {
        let throttle = RepeatThrottle::default();
        assert_eq!(
            throttle.allow(REFUSAL_LOG_WINDOW),
            Some(0),
            "the first line always logs"
        );
        assert_eq!(throttle.allow(REFUSAL_LOG_WINDOW), None);
        assert_eq!(throttle.allow(REFUSAL_LOG_WINDOW), None);
        // A zero window means "no limit", and the repeats it stood for ride on
        // the next emitted line so nothing is silently lost.
        assert_eq!(throttle.allow(Duration::ZERO), Some(2));
    }

    #[test]
    fn a_gate_refusal_stays_distinguishable_from_a_plain_start_failure() {
        let retry = SlotWakeRefusal::MigrationGate(StoreMigrationDecision::Retry {
            code: "store_busy".to_string(),
        });
        assert!(retry.is_migration_gate());
        match retry.into_service_error() {
            ServiceError::Api(error) => {
                assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
                assert!(error.retryable, "the next start may work");
                assert!(error.message.contains("store_busy"));
            }
            other => panic!("a gate refusal is an API error, got {other:?}"),
        }
        let skewed = SlotWakeRefusal::MigrationGate(StoreMigrationDecision::Misconfigured);
        match skewed.into_service_error() {
            ServiceError::Api(error) => {
                assert!(!error.retryable);
                assert!(error.message.contains("storeMigrate"));
                assert!(!error.message.contains("  "), "{}", error.message);
            }
            other => panic!("exit 2 is an API error, got {other:?}"),
        }
        let failed = SlotWakeRefusal::Failed(ServiceError::Engine(EngineError::StartFailed));
        assert!(!failed.is_migration_gate());
    }

    #[test]
    fn account_fingerprint_is_short_and_never_the_whole_id() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(account_fingerprint(id), "01234567");
        assert_eq!(account_fingerprint("abc"), "abc");
        assert_eq!(account_fingerprint(""), "");
        // Multi-byte input must not panic on a byte boundary.
        assert_eq!(account_fingerprint("账号标识"), "账号标识");
    }
}
