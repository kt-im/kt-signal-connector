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

use std::cell::Cell;
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
use crate::service::{HostSideEvent, ServiceError};
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
    /// The operator's own intent (contract 1.291, §4.277 D): this host must not
    /// run accounts on plaintext stores. Independent of `mode` - the switch says
    /// whether this connector migrates, the intent says whether plaintext is
    /// acceptable at all - and off by default, so an unarmed process keeps the
    /// pre-4.277 posture exactly.
    pub require_encrypted: bool,
}

impl Default for StoreMigrationOptions {
    fn default() -> Self {
        Self {
            mode: StoreMigrationMode::Off,
            budget: STORE_MIGRATION_BUDGET,
            require_encrypted: false,
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
        Self {
            mode,
            budget,
            require_encrypted: crate::store_preflight::intent_from_env(),
        }
    }

    pub fn is_enabled(self) -> bool {
        self.mode != StoreMigrationMode::Off
    }

    /// Whether this process has to look at a slot's store at all: a migration
    /// is armed, or the operator asked for encrypted stores. False is the
    /// zero-cost posture - no read, no lock, no log line, no new field.
    pub fn touches_store(self) -> bool {
        self.is_enabled() || self.require_encrypted
    }
}

/// The lifecycle state of one slot's store migration (contract 1.291, §4.277).
///
/// The machine is deliberately small: a pass is **scheduled** (pending),
/// **runs** (migrating), and lands in exactly one state for that pass
/// (migrated / blocked / failed). Off is the posture of a connector whose
/// switch is not armed, and it is the only state the wire face omits.
///
/// Re-entrancy and crash recovery: a later start may leave a failed pass behind
/// for one more attempt (that is what "retried on the next start" means), while
/// a blocked slot never re-enters the migrator - the latch is terminal for the
/// life of the process. **This machine is memory, not truth**: a process
/// restart forgets it entirely and the encrypted-store header on disk becomes
/// the authority again, so a pass killed mid-flight is simply re-run and
/// answers whatever the header says. That is what makes the lifecycle
/// idempotent across a crash without a single byte of connector-written state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreMigrationState {
    /// The switch is off: no pass was scheduled, and the status face omits the
    /// whole storeMigration key.
    #[default]
    Off,
    /// A pass is scheduled (or required) and has not landed yet.
    Pending,
    /// The migrator is running for this slot right now.
    Migrating,
    /// This process proved this slot's store is encrypted. Starts stop asking.
    Migrated,
    /// Terminal: a human has to act. The gate never spawns a migrator again.
    Blocked,
    /// The last pass did not land (retryable, usage error, timeout, or nothing
    /// to migrate). The next start asks again.
    Failed,
}

impl StoreMigrationState {
    /// The wire/log label. A label only, never input for a decision.
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Pending => "pending",
            Self::Migrating => "migrating",
            Self::Migrated => "migrated",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }

    /// Whether a start handed to the gate in this state may spawn an engine
    /// without running another pass.
    pub fn allows_start(self) -> bool {
        matches!(self, Self::Off | Self::Migrated)
    }
}

/// The bound on the code a status face may carry (contract 1.291, §4.277). The
/// engine's vocabulary is closed and short; the face is bounded anyway, so an
/// unknown engine code can never grow the wire.
pub const STORE_MIGRATION_CODE_MAX_CHARS: usize = 64;

/// Clamp a status code to [`STORE_MIGRATION_CODE_MAX_CHARS`] **characters** (not
/// bytes: a multi-byte code must never be split into invalid UTF-8).
pub fn clamp_store_migration_code(code: &str) -> String {
    code.chars().take(STORE_MIGRATION_CODE_MAX_CHARS).collect()
}

/// The closed status codes of the `blocked` state (contract 1.291, §4.277 B).
/// The connector owns this vocabulary: the desktop renders a state and one of
/// these words, and never has to guess from an engine's internal code.
pub const STORE_CODE_CAPABILITY_MISSING: &str = "CAPABILITY_MISSING";
pub const STORE_CODE_KEY_INVALID: &str = "KEY_INVALID";
pub const STORE_CODE_VERIFY_FAILED: &str = "VERIFY_FAILED";
pub const STORE_CODE_REQUIRED: &str = "REQUIRED";
/// The closed status codes of the `failed` state.
pub const STORE_CODE_INTERRUPTED: &str = "INTERRUPTED";
pub const STORE_CODE_IO_ERROR: &str = "IO_ERROR";
pub const STORE_CODE_LOCKED: &str = "LOCKED";
pub const STORE_CODE_TIMEOUT: &str = "TIMEOUT";

/// Map one finished pass onto the status face's code vocabulary.
///
/// The engine speaks its own closed vocabulary (StoreKeyRequired, store_busy,
/// ...); the status face speaks eight words the desktop can switch on. Keeping
/// the translation here - beside the decision the connector already makes - is
/// what lets the contract say "the connector decides, the desktop renders".
/// An unknown terminal code maps to VERIFY_FAILED (the closest honest word for
/// "the store could not be proven encrypted") rather than being passed through.
pub fn store_migration_face_code(
    decision: &StoreMigrationDecision,
    engine_code: Option<&str>,
) -> &'static str {
    match decision {
        StoreMigrationDecision::Blocked { block }
            if block.code == STORE_PLAINTEXT_REQUIRES_MIGRATION =>
        {
            STORE_CODE_REQUIRED
        }
        StoreMigrationDecision::Blocked { .. } => match engine_code {
            Some("StoreCipherUnavailable" | "store_cipher_unavailable") => {
                STORE_CODE_CAPABILITY_MISSING
            }
            Some(
                "StoreKeyRequired" | "StoreKeyInvalid" | "store_key_mismatch"
                | "store_key_rejected",
            ) => STORE_CODE_KEY_INVALID,
            _ => STORE_CODE_VERIFY_FAILED,
        },
        // Exit 2 is the connector/engine version skew: a capability problem,
        // not an account problem, and the state stays `failed` because fixing
        // the deployment heals it without anyone touching the account.
        StoreMigrationDecision::Misconfigured => STORE_CODE_CAPABILITY_MISSING,
        StoreMigrationDecision::Retry { code } => {
            if code.contains("timeout") {
                STORE_CODE_TIMEOUT
            } else if code.contains("busy") || code.contains("lock") {
                STORE_CODE_LOCKED
            } else if code.contains("spawn") || code.contains("abandoned") {
                STORE_CODE_INTERRUPTED
            } else {
                STORE_CODE_IO_ERROR
            }
        }
        // A start lands `migrated` or `pending`; the only start outcome that
        // carries a code is the one that could not migrate at all.
        StoreMigrationDecision::Start { outcome } => {
            if *outcome == "skipped" {
                STORE_CODE_CAPABILITY_MISSING
            } else {
                STORE_CODE_IO_ERROR
            }
        }
    }
}
/// The retryable code a caller gets while a pass is running: this account is
/// being prepared, and a later start serves it. Kept distinct from a failed pass
/// so a host can render "one moment" instead of "something broke".
pub const STORE_MIGRATION_IN_PROGRESS: &str = "store_migration_in_progress";

/// The code a preflight refusal carries (contract 1.291, D): a plaintext store
/// is still on disk, nothing is armed to migrate it, and the operator asked for
/// encrypted stores. Also the code a status face reports for that slot.
pub const STORE_PLAINTEXT_REQUIRES_MIGRATION: &str = "store_plaintext_requires_migration";

/// engines[].storeMigration (contract 1.291, §4.277): the per-slot migration
/// lifecycle a host can render. Absent - the whole key - while the switch is
/// off, so an unarmed connector's runtime.status stays byte-identical.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreMigrationStatus {
    pub state: StoreMigrationState,
    /// The engine's own closed code for the last pass, clamped. Never a key, a
    /// path, an address, or raw engine output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}
/// Whether a wake may spend the caller's clock on the store gate (contract
/// 1.291, §4.277 A). The request path defers - it schedules the pass and answers
/// a retryable deferral - while the two human flows (a local-data delete, a link)
/// wait for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotStartMode {
    /// Return as soon as a pass is scheduled: never run a whole-store copy on
    /// the caller's budget.
    Defer,
    /// Run the pass inline, bounded by the migration budget.
    Wait,
}

/// One finished store-migration pass: the classification the gate acts on, plus
/// the engine's own evidence code for the status face. The code is carried
/// separately because the classification owns a *different* code on exit 10/11
/// (the engine's, passed through) than on a start (the run's `code` field).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreMigrationPass {
    pub decision: StoreMigrationDecision,
    pub code: Option<String>,
}

impl StoreMigrationPass {
    fn plain(decision: StoreMigrationDecision) -> Self {
        Self {
            decision,
            code: None,
        }
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

/// The sentence a preflight refusal carries (contract 1.291, D). It names both
/// ways out - migrate the store, or stop demanding encryption - and says plainly
/// that nothing was touched, so nobody deletes a healthy account over it.
pub fn store_plaintext_refusal_message() -> &'static str {
    "this account's local store is still plaintext and this host asks for encrypted stores (KT_ENGINE_STORE_REQUIRE_ENCRYPTED), but no store migration is armed (KT_ENGINE_STORE_MIGRATE is off), so nothing would ever make it encrypted. Nothing was changed and the store is intact. Either arm the migration with KT_ENGINE_STORE_MIGRATE=apply and restart KT Desktop so this store is migrated, or turn the requirement off if a plaintext store is acceptable on this host."
}

/// The host-facing sentence for a pass that already failed (contract 1.291,
/// B/UX 2). It says the two things a caller can act on: nothing is damaged, and
/// the retry is the caller's explicit decision - not something a timer will do.
pub fn store_migration_failed_message(code: &str) -> String {
    format!(
        "the last store migration attempt for this account did not finish ({code}). It is not \
         retried automatically: fix the cause, then start the runtime again (or restart KT \
         Desktop) to retry it. The plaintext store was left untouched."
    )
}

/// The host-facing sentence for a spawn the store gate deferred (contract
/// 1.291 C). Keyed by the closed literal the supervisor carries, so the text
/// and the state the status face reports always tell the same story.
pub fn store_gate_deferral_message(code: &str) -> String {
    match code {
        STORE_PLAINTEXT_REQUIRES_MIGRATION => store_plaintext_refusal_message().to_string(),
        "store_migration_blocked" => {
            "this account's store migration is in a terminal state and needs a human: re-link the account or restore the store key it was migrated with, then restart KT Desktop. No engine was started for it."
                .to_string()
        }
        "store_migration_misconfigured" => store_migration_misconfigured_message().to_string(),
        _ => store_migration_retry_message(STORE_MIGRATION_IN_PROGRESS),
    }
}

/// The operator-facing text for a retryable/store-not-ready slot. Honest about
/// the two things that matter: nothing was damaged, and the next start tries
/// again.
pub fn store_migration_retry_message(code: &str) -> String {
    // A pass that is running right now is not a failure: the account is being
    // prepared, and the very next start serves it. Saying "retried on the next
    // start" would read as "something went wrong", so this arm says what is
    // actually happening and still promises the same thing.
    if code == STORE_MIGRATION_IN_PROGRESS {
        return "this account is being prepared: its store is being migrated right now, so its \
                engine is not up yet. Retry in a moment - the migration finishes on its own and \
                the plaintext store is left untouched while it runs."
            .to_string();
    }
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
        // A pass that is running right now will finish on its own, so "retry in
        // a moment" is true. Every other retryable code means the last pass
        // **failed**, and contract 1.291 (UX 2) says nothing retries a failed
        // pass by itself - only an explicit runtime.start does. Answering
        // retryable=true there would be the lie this revision removes.
        StoreMigrationDecision::Retry { code } if code == STORE_MIGRATION_IN_PROGRESS => {
            ServiceError::Api(ApiError::new(
                "CAPABILITY_UNAVAILABLE",
                store_migration_retry_message(&code),
                true,
            ))
        }
        StoreMigrationDecision::Retry { code } => ServiceError::Api(ApiError::new(
            "CAPABILITY_UNAVAILABLE",
            store_migration_failed_message(&code),
            false,
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
    /// Contract 1.291 (§4.277 B): this slot's store-migration lifecycle.
    /// Absent - the whole key - while the migration switch is off, so an
    /// unarmed connector's status face stays byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_migration: Option<StoreMigrationStatus>,
    /// Contract 1.275: the account holder unlinked this device, so the slot is
    /// parked and **no** engine will start for it until a fresh link lands.
    /// Additive and omitted while false, so every other status face stays
    /// byte-identical; the boolean is the machine-readable half of the
    /// `needs-relink` verdict the desktop renders.
    #[serde(skip_serializing_if = "is_false")]
    pub needs_relink: bool,
}

/// Serde helper: omit the key while the flag is false (additive wire shape).
fn is_false(value: &bool) -> bool {
    !*value
}

/// The terminal wire answer for an account whose device the account holder
/// unlinked (contract 1.21/1.275): the credential is dead, so no wake, no
/// `runtime.start` and no retry can serve it. Byte-identical to the service's
/// `EngineError::Unauthorized` mapping, which is why it uses the same code,
/// sentence and `retryable=false`.
pub fn account_unlinked_error() -> ServiceError {
    ServiceError::Api(ApiError::new(
        "ACCOUNT_UNLINKED",
        "device was unlinked by the account holder",
        false,
    ))
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
    /// The account holder unlinked this device (contract 1.275): the slot is
    /// terminal. Retrying cannot help, and the one action its message names -
    /// "link it again" - needs a fresh link, never a fresh engine.
    DeviceUnlinked,
    /// Anything else: no data-directory lock, a supervisor that would not
    /// start, or an engine that exited.
    Failed(ServiceError),
}

impl SlotWakeRefusal {
    /// Whether the store-migration gate is what refused this start.
    pub fn is_migration_gate(&self) -> bool {
        matches!(self, Self::MigrationGate(_))
    }

    /// Whether a caller whose job is **not** to serve traffic - above all the
    /// local-data delete - may take the engine-free path instead of being
    /// refused. Both terminal verdicts answer a remediation ("delete its local
    /// data and link it again") that must stay reachable: a store-migration gate
    /// must not veto the very action its own message prescribes, and a
    /// `device_unlinked` slot has no credential left for an engine to delete
    /// with. Anything else keeps the pre-existing refusal.
    pub fn permits_engine_free_flow(&self) -> bool {
        matches!(self, Self::MigrationGate(_) | Self::DeviceUnlinked)
    }

    /// The host-facing error. Byte-for-byte what `ensure_resident` answered
    /// before this split existed; the distinction is internal.
    pub fn into_service_error(self) -> ServiceError {
        match self {
            Self::MigrationGate(decision) => store_migration_refusal_error(decision),
            Self::DeviceUnlinked => account_unlinked_error(),
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

/// One slot's migration bookkeeping. Held under one lock so a reader can never
/// observe a state from one pass beside a code from another.
#[derive(Clone, Debug, Default)]
struct MigrationLifecycle {
    state: StoreMigrationState,
    code: Option<String>,
    /// The classification of the last landed pass (the wake path re-answers it).
    verdict: Option<StoreMigrationDecision>,
    /// The latched terminal block (exit 11, or a preflight refusal).
    block: Option<StoreMigrationBlock>,
}

/// The tracing invariant name a leaked link-attempt slot is reported under.
/// The same literal is used by the startup quarantine scan, the live reaper
/// and the guard, so a log query finds every leak witness in one place.
pub const LINK_SLOT_LEAK_INVARIANT: &str = "link_attempt_slot_leaked";

/// One link attempt's ownership record over a preallocated slot
///
/// A `link.start` slot is provisioned under an opaque account id that has
/// **no store row yet**, so that id is not an owner: the attempt
/// (`linkAttemptId`) owns the slot until `link.finish` commits it. Only a
/// committed finish promotes the lease to the account row; every other
/// terminal answer (finish failure, cancel, timeout) reclaims it through
/// [`AccountPool::reclaim_link_attempt`].
#[derive(Clone, Debug)]
pub struct LinkAttemptLease {
    pub attempt_id: String,
    pub account_id: String,
    /// When the attempt claimed the slot (the abandoned-attempt reaper's age).
    pub opened_at: Instant,
}

/// The one idempotent outcome of a link-attempt reclaim pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkReclaimOutcome {
    /// A committed account row owns the slot: the lease was dropped, the
    /// slot and its data stay. This is the promotion that must never delete.
    Promoted,
    /// The engine was stopped and the slot directory removed.
    Reclaimed,
    /// The engine was stopped and the credential-bearing directory was moved
    /// aside under `engines/.quarantine-<id>-<token>` (bytes stay auditable).
    Quarantined,
    /// Nothing was leased under that attempt id: an idempotent replay, or a
    /// slot another terminal path already reclaimed.
    AlreadySettled,
}

/// What teardown does with a removed slot's directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotDisposition {
    /// Leave the directory in place (runtime.stop keeps slots cold).
    Keep,
    /// Remove it (an uncommitted slot holds no credentials).
    Delete,
    /// Move it under `engines/.quarantine-*` (credential-bearing bytes).
    Quarantine,
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
    /// The attempt that owns this uncommitted slot. `None` on a committed
    /// account (promoted) or before the first `link.start` lease.
    lease_attempt_id: StdMutex<Option<String>>,
    lock: StdMutex<Option<DataDirLock>>,
    last_used: StdMutex<Instant>,
    /// The store-migration lifecycle of this slot (contract 1.291, §4.277):
    /// the state a host renders, the engine code of the last pass, the last
    /// classification (so a wake can answer the same verdict without running
    /// the migrator again), and the latched terminal block.
    migration: StdMutex<MigrationLifecycle>,
    /// Single-flight for this slot's migration task: at most one pass per slot,
    /// whatever the number of callers that ask at the same moment.
    migration_in_flight: AtomicBool,
    /// Set once a run has left this slot's store in the encrypted format
    /// (`action: migrate`) or found it already there (`noop`) - M6 D3 review
    /// M4. The whole-store verification is the expensive half of a migration
    /// run, and re-running it on every later start of a store this process has
    /// already proved buys nothing. Process-scoped on purpose: the next process
    /// pays for one check, so a store restored from a backup still migrates.
    store_migrated: AtomicBool,
    /// Throttle for the exit-2 line (M6 D3 review M5).
    misconfigured_log: RepeatThrottle,
    /// Throttle for the plaintext-backup warning: one informational line per
    /// window, never one per start.
    backup_warn: RepeatThrottle,
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
        self.migration().block.clone()
    }

    fn latch_migration_block(&self, block: StoreMigrationBlock) {
        self.migration().block = Some(block);
    }

    fn migration(&self) -> std::sync::MutexGuard<'_, MigrationLifecycle> {
        self.migration
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The lifecycle state alone (the gate's fast input).
    pub fn migration_state(&self) -> StoreMigrationState {
        self.migration().state
    }

    /// The status face of this slot: the key is omitted entirely while the
    /// switch is off (task B: an off connector adds no field and no behaviour).
    pub fn store_migration_face(&self) -> Option<StoreMigrationStatus> {
        let lifecycle = self.migration();
        if lifecycle.state == StoreMigrationState::Off {
            return None;
        }
        Some(StoreMigrationStatus {
            state: lifecycle.state,
            code: lifecycle.code.clone(),
        })
    }

    /// The classification of the last completed pass, if any: the same sentence
    /// and the same retryable bit a wake must answer without re-running the
    /// migrator.
    fn last_migration_decision(&self) -> Option<StoreMigrationDecision> {
        self.migration().verdict.clone()
    }

    fn set_migration_state(&self, state: StoreMigrationState, code: Option<&str>) {
        let mut lifecycle = self.migration();
        lifecycle.state = state;
        lifecycle.code = code.map(clamp_store_migration_code);
    }

    /// Record one pass's verdict: the state a host renders, the contract code,
    /// the classification a later wake re-answers, the terminal latch, and (for
    /// a pass that proved the store encrypted) the in-process M4 marker.
    fn record_migration_decision(
        &self,
        decision: &StoreMigrationDecision,
        mode: StoreMigrationMode,
        engine_code: Option<&str>,
    ) {
        let (state, code, latch) = match decision {
            StoreMigrationDecision::Start { outcome } => {
                // A dry run observes and never proves: the store is still
                // exactly as it was, so the honest state is "a pass is still
                // owed", never "migrated". It carries no code: nothing failed.
                if mode == StoreMigrationMode::DryRun {
                    (StoreMigrationState::Pending, None, None)
                } else if matches!(*outcome, "migrated" | "noop") {
                    self.mark_store_migrated();
                    (StoreMigrationState::Migrated, None, None)
                } else if *outcome == "absent" {
                    // No store on disk yet: the engine creates the encrypted
                    // one with its key on start. There is no plaintext to move,
                    // so the slot is migrated - never "a pass still owed".
                    (StoreMigrationState::Migrated, None, None)
                } else {
                    // completed / skipped: nothing was proven. `skipped` means
                    // this slot cannot be migrated at all (no per-account key),
                    // which is a capability answer, not an account one.
                    let code = if *outcome == "skipped" {
                        Some(STORE_CODE_CAPABILITY_MISSING)
                    } else {
                        None
                    };
                    (StoreMigrationState::Failed, code, None)
                }
            }
            StoreMigrationDecision::Retry { .. } | StoreMigrationDecision::Misconfigured => {
                let code = store_migration_face_code(decision, engine_code);
                (StoreMigrationState::Failed, Some(code), None)
            }
            StoreMigrationDecision::Blocked { block } => {
                let code = store_migration_face_code(decision, engine_code);
                (
                    StoreMigrationState::Blocked,
                    Some(code),
                    Some(block.clone()),
                )
            }
        };
        {
            let mut lifecycle = self.migration();
            lifecycle.state = state;
            lifecycle.code = code.map(clamp_store_migration_code);
            lifecycle.verdict = Some(decision.clone());
        }
        if let Some(block) = latch {
            self.latch_migration_block(block);
        }
    }

    /// Claim this slot's single-flight migration slot. False means a pass is
    /// already running (or just finished and has not been collected), and the
    /// caller must not start a second one.
    fn begin_migration_flight(&self) -> bool {
        self.migration_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn end_migration_flight(&self) {
        self.migration_in_flight.store(false, Ordering::Release);
    }

    /// Whether a migration pass is running for this slot right now.
    pub fn migration_in_flight(&self) -> bool {
        self.migration_in_flight.load(Ordering::Acquire)
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

    /// The attempt that currently owns this uncommitted slot, if any. This is
    /// the slot's side of the lease record; `AccountPool::leases` is the
    /// attempt-keyed authority and the two are written together.
    pub fn lease_attempt_id(&self) -> Option<String> {
        self.lease_attempt_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_lease_attempt(&self, attempt_id: Option<String>) {
        *self
            .lease_attempt_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = attempt_id;
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
    /// Open link-attempt leases, keyed by the host-facing `linkAttemptId`.
    /// This is the ownership authority for a preallocated slot that has no
    /// account row yet; only a committed `link.finish` removes a record by
    /// promotion, every other terminal answer removes it through
    /// [`AccountPool::reclaim_link_attempt`].
    leases: StdMutex<HashMap<String, LinkAttemptLease>>,
    /// Serializes dynamic link admission so the capacity ceiling cannot be
    /// overshot by two concurrent `link.start` calls. Held only for the QR
    /// mint, never across `link.finish`'s phone-approval wait.
    link_lock: tokio::sync::Mutex<()>,
    available: bool,
    /// Set by `stop_all` (runtime.stop) and cleared by `start_resident`: a
    /// migration pass that lands *after* a stop must not resurrect an engine
    /// the caller just asked to stop. Reported, never silently dropped.
    stopping: AtomicBool,
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
                        // §4.279: seed the terminal latch from the store's
                        // authoritative verdict, not only from a live event.
                        // A connector restart discovers the dead slot cold; the
                        // latch is what lets the re-link takeover reap exactly
                        // this slot once the row has been replaced, and it
                        // keeps the parked verdict honest before any wake.
                        if config
                            .store
                            .account_summary(&slot.account_id)
                            .ok()
                            .flatten()
                            .is_some_and(|row| row.state == "device_unlinked")
                        {
                            slot.supervisor().note_device_unlinked();
                        }
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
            leases: StdMutex::new(HashMap::new()),
            link_lock: tokio::sync::Mutex::new(()),
            available,
            stopping: AtomicBool::new(false),
        });
        pool.install_start_gates();
        for slot in pool.slots() {
            pool.seed_store_migration_face(&slot);
        }
        pool.warn_leaked_slots();
        tracing::info!(accounts = count, "per-account engine pool discovered");
        pool
    }

    /// Startup invariant witness: a slot that carries credentials while the
    /// store has no row for its id is a leaked link-attempt slot. The startup
    /// migration pass quarantines these before the pool is built; this second
    /// read-only pass keeps the invariant visible even when the pool is
    /// assembled from a store a test or another launcher opened.
    fn warn_leaked_slots(&self) {
        for slot in self.slots() {
            match self.config.store.account_by_id(&slot.account_id) {
                // A row exists, or the store cannot answer (an unreadable
                // store is never evidence of a leak): say nothing.
                Ok(Some(_)) | Err(_) => continue,
                Ok(None) => {}
            }
            if slot_has_credentials(&slot) {
                tracing::warn!(
                    target: "connector.pool",
                    invariant = LINK_SLOT_LEAK_INVARIANT,
                    account = %account_fingerprint(&slot.account_id),
                    "engine slot has credentials but no account row: leaked link-attempt slot"
                );
            }
        }
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

    /// BUG-8: whether this account's engine data directory still exists on
    /// disk when the slot table has no entry for it. The pool is rebuilt from
    /// that directory at startup, so "no slot" normally means "no data"; a
    /// directory that is there anyway is a broken pool (an unreadable root, a
    /// held occupancy lock, a name the pool refuses) and must never be read as
    /// "the data is gone" — the delete reconcile fails closed on it.
    ///
    /// A symlink counts as present: the entry is something this process does
    /// not own, and following it would cross the account boundary.
    pub(crate) fn slot_dir_present(&self, account_id: &str) -> bool {
        if !is_account_id(account_id) {
            // Not addressable as a slot: never evidence that the data is gone.
            return true;
        }
        let path = self
            .config
            .signal_data_dir
            .join(ENGINE_SLOT_SUBDIR)
            .join(account_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) => error.kind() != io::ErrorKind::NotFound,
        }
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

    /// Open a link attempt's lease over a freshly provisioned slot. The
    /// attempt id is the host-facing `linkAttemptId` minted before the engine
    /// is asked for a code, so the slot is owned by the attempt from the
    /// moment it exists. Returns the record on success; `None` means the
    /// attempt id is empty, already leased, or this slot already carries a
    /// different attempt (never silently overwrite an owner).
    pub fn open_link_lease(
        &self,
        slot: &Arc<AccountSlot>,
        attempt_id: &str,
    ) -> Option<LinkAttemptLease> {
        let attempt_id = attempt_id.trim();
        if attempt_id.is_empty() || slot.lease_attempt_id().is_some() {
            return None;
        }
        let lease = LinkAttemptLease {
            attempt_id: attempt_id.to_string(),
            account_id: slot.account_id.clone(),
            opened_at: Instant::now(),
        };
        let mut leases = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if leases.contains_key(attempt_id) {
            return None;
        }
        leases.insert(attempt_id.to_string(), lease.clone());
        drop(leases);
        slot.set_lease_attempt(Some(attempt_id.to_string()));
        Some(lease)
    }

    /// The attempt leasing this account's slot, if any.
    pub fn lease_for_account(&self, account_id: &str) -> Option<String> {
        let slot = self.get(account_id)?;
        if let Some(attempt_id) = slot.lease_attempt_id() {
            return Some(attempt_id);
        }
        self.leases
            .lock()
            .ok()?
            .values()
            .find(|lease| lease.account_id == account_id)
            .map(|lease| lease.attempt_id.clone())
    }

    /// One open lease by attempt id (diagnostics and tests).
    pub fn link_lease(&self, attempt_id: &str) -> Option<LinkAttemptLease> {
        self.leases
            .lock()
            .ok()
            .and_then(|leases| leases.get(attempt_id).cloned())
    }

    /// Number of open link-attempt leases (the pool's uncommitted-slot count).
    pub fn open_link_leases(&self) -> usize {
        self.leases
            .lock()
            .map(|leases| leases.len())
            .unwrap_or_default()
    }

    /// Promote a lease to its committed account row: the finish that owns the
    /// attempt succeeded, so the slot is no longer reclaimable by the attempt
    /// (it belongs to the account from here on). Idempotent.
    pub fn promote_link_attempt(&self, attempt_id: &str) -> bool {
        let lease = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(attempt_id);
        let Some(lease) = lease else {
            return false;
        };
        if let Some(slot) = self.get(&lease.account_id) {
            slot.set_lease_attempt(None);
        }
        true
    }

    /// The one idempotent reclaim path every terminal link answer converges
    /// on: finish failure, cancel and timeout all call this exact function
    /// (directly through [`LinkAttemptGuard`]).
    ///
    /// Steps, all idempotent:
    /// 1. take the attempt's lease out of the ownership table (a second call
    ///    finds nothing and answers [`LinkReclaimOutcome::AlreadySettled`]);
    /// 2. refuse to touch a slot a committed account row already owns
    ///    (promotion wins any race with a late cleanup);
    /// 3. ask the engine once — one bounded, read-only `listAccounts` — whether
    ///    the provisioning completed after all (BUG-1 soften): the engine
    ///    registers an account only after the phone approval committed, so a
    ///    listed number materializes the missing account row and promotes the
    ///    slot. A failed, unsupported or timed-out probe falls through: the
    ///    pre-softening reclaim is unchanged;
    /// 4. stop the engine process through [`Self::discard_with`] (slot map
    ///    removal, session-map purge, supervisor shutdown);
    /// 5. delete the directory when it holds no credentials, or move it into
    ///    `engines/.quarantine-<id>-<token>` when it does (auditable bytes,
    ///    never a live slot);
    /// 6. the sidecar and every session mapping for the slot are cleared.
    pub async fn reclaim_link_attempt(self: &Arc<Self>, attempt_id: &str) -> LinkReclaimOutcome {
        let lease = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(attempt_id);
        let Some(lease) = lease else {
            return LinkReclaimOutcome::AlreadySettled;
        };
        let Some(slot) = self.get(&lease.account_id) else {
            // The slot was already discarded by a sibling path; the lease is
            // the only residue and it is gone now.
            return LinkReclaimOutcome::AlreadySettled;
        };
        slot.set_lease_attempt(None);
        // A committed row is the durable proof the attempt succeeded even if
        // its lease cleanup was lost (crash window between the store commit
        // and the in-memory promotion). Never delete such a slot; an
        // unreadable store is not evidence of abandonment either, so it also
        // fails closed to "leave the slot alone".
        let committed = slot.is_provisioned()
            || match self.config.store.account_by_id(&lease.account_id) {
                Ok(Some(_)) | Err(_) => true,
                Ok(None) => false,
            };
        if committed {
            tracing::info!(
                account = %account_fingerprint(&lease.account_id),
                "link attempt lease was promoted: a committed account row owns the slot"
            );
            return LinkReclaimOutcome::Promoted;
        }
        // BUG-1 softening: the engine may have committed the link after the
        // connector's finish budget expired — the phone approved under the
        // engine's own deadline, but the answer never reached this process.
        // Before calling the slot abandoned, ask the engine **once**: a
        // bounded, read-only `listAccounts`. The engine registers an account
        // only after its provisioning flow wrote the registration and the
        // commit landed, so a listed number is the durable proof the connector
        // is missing. A completed link is promoted: the account row is
        // materialized through the same sync the account list uses, the slot
        // is marked provisioned (sidecar included) and the credential-bearing
        // directory stays exactly where it is. A failed, unsupported or
        // timed-out probe keeps the pre-softening reclaim.
        let probe_budget = self.config.policy.list_accounts_budget;
        if let Some(account) = slot
            .supervisor()
            .adopt_engine_completed_link(probe_budget)
            .await
        {
            tracing::info!(
                target: "connector.pool",
                account = %account_fingerprint(&lease.account_id),
                engine_account = %account.id,
                budget_ms = probe_budget.as_millis().min(u64::MAX as u128) as u64,
                "link attempt lease was promoted: the engine reports the provisioning completed"
            );
            if let Ok(mut sessions) = self.sessions.lock() {
                // The finish session is spent: no host call may route to this
                // slot through the pre-commit link id any more.
                sessions.retain(|_, owner| owner != &lease.account_id);
            }
            self.mark_provisioned(&slot);
            self.note_activity(&slot);
            return LinkReclaimOutcome::Promoted;
        }
        let credentials = slot_has_credentials(&slot);
        if credentials {
            tracing::warn!(
                target: "connector.pool",
                invariant = LINK_SLOT_LEAK_INVARIANT,
                account = %account_fingerprint(&lease.account_id),
                "reclaiming a link-attempt slot that still holds credentials; quarantining"
            );
            self.discard_with(&lease.account_id, SlotDisposition::Quarantine)
                .await;
            LinkReclaimOutcome::Quarantined
        } else {
            tracing::info!(
                account = %account_fingerprint(&lease.account_id),
                "reclaiming an uncommitted link-attempt slot"
            );
            self.discard_with(&lease.account_id, SlotDisposition::Delete)
                .await;
            LinkReclaimOutcome::Reclaimed
        }
    }

    /// Admission + materialization of a fresh slot for `link.start`. The
    /// returned slot is registered but its engine is not started yet; the
    /// caller starts it and rolls the slot back through [`Self::discard`] if
    /// the QR mint fails. A slot occupies a data directory, an occupancy lock,
    /// and a supervisor from this point on, so the capacity check and the
    /// insert share one write lock.
    pub fn provision_slot(
        self: &Arc<Self>,
        proxy_group: &str,
    ) -> Result<Arc<AccountSlot>, ServiceError> {
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
        self.seed_store_migration_face(&slot);
        // The new supervisor must pass the same gate as every other start
        // (contract 1.291 C: the link path is not allowed to bypass it).
        slot.supervisor().set_start_gate(Arc::new(SlotStartGate {
            slot: Arc::downgrade(&slot),
            pool: Arc::downgrade(self),
        }));
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
        let disposition = if remove_dir {
            SlotDisposition::Delete
        } else {
            SlotDisposition::Keep
        };
        self.discard_with(account_id, disposition).await;
    }

    /// D4 所有权执行面(阶段1 批1-5c):Main 所有权表 quarantine 裁决的
    /// connector 执行臂——停引擎 + 凭据目录移 `engines/.quarantine-*`
    /// (字节保留可审计,BUG-1 纪律)。幂等:槽不存在(已隔离/从未存在)
    /// 返回 `false`,绝不重复移动目录。
    pub async fn discard_quarantined(self: &Arc<Self>, account_id: &str) -> bool {
        self.discard_with(account_id, SlotDisposition::Quarantine)
            .await
    }

    /// D4 所有权执行面(阶段1 批1-5c):Main 所有权表 hibernate 裁决的
    /// connector 执行臂——停引擎 + 目录原地保留(冷槽语义:下次账号请求
    /// 自动重新拉起,代价一次 spawn)。幂等同上。
    pub async fn hibernate_slot(self: &Arc<Self>, account_id: &str) -> bool {
        self.discard_with(account_id, SlotDisposition::Keep).await
    }

    /// The one teardown every slot-removal path uses (account delete,
    /// link rollback, reclaim, D4 ownership exec). Removing the slot from
    /// the map first makes the pass idempotent: a concurrent second caller
    /// finds no slot and does nothing. The engine is always stopped before
    /// the directory is touched (I5), and the attempt lease — whatever its
    /// state — is cleared with the slot so no reclaim can address a dead
    /// slot afterwards. Returns whether a slot was actually torn down
    /// (`false` = idempotent no-op: nothing was there).
    async fn discard_with(
        self: &Arc<Self>,
        account_id: &str,
        disposition: SlotDisposition,
    ) -> bool {
        let slot = self
            .slots
            .write()
            .ok()
            .and_then(|mut slots| slots.remove(account_id));
        let Some(slot) = slot else {
            return false;
        };
        if let Ok(mut leases) = self.leases.lock() {
            leases.retain(|_, lease| lease.account_id != account_id);
        }
        slot.set_lease_attempt(None);
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
        match disposition {
            SlotDisposition::Keep => {}
            SlotDisposition::Delete => self.remove_slot_directory(&slot),
            SlotDisposition::Quarantine => self.quarantine_slot_directory(&slot),
        }
        tracing::info!(
            account_id = %slot.account_id,
            group_id = %slot.proxy_group,
            "per-account engine slot removed"
        );
        true
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

    /// Move a credential-bearing slot directory out of the live slot
    /// namespace. Unlike an uncommitted empty directory this one may hold a
    /// device credential (an engine-side link the connector never committed),
    /// so the bytes stay on disk for audit instead of being deleted. A rename
    /// failure falls back to deletion: a stopped engine's orphan directory
    /// must never keep blocking the pool.
    fn quarantine_slot_directory(&self, slot: &AccountSlot) {
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
        let target = engines_root.join(format!(
            ".quarantine-{account_id}-{}",
            crate::ids::random_id()
        ));
        match std::fs::rename(&slot.data_dir, &target) {
            Ok(()) => tracing::warn!(
                target: "connector.pool",
                invariant = LINK_SLOT_LEAK_INVARIANT,
                account = %account_fingerprint(account_id),
                "credential-bearing link-attempt slot quarantined"
            ),
            Err(error) => {
                tracing::warn!(
                    target: "connector.pool",
                    invariant = LINK_SLOT_LEAK_INVARIANT,
                    account = %account_fingerprint(account_id),
                    error_class = error_class(&error),
                    "credential-bearing slot could not be quarantined; deleting it instead"
                );
                let _ = std::fs::remove_dir_all(&slot.data_dir);
            }
        }
        let _ = std::fs::remove_file(&slot.sidecar);
    }

    /// Start the top-K most recently used slots (design §6.1 step ④, S1
    /// bounded form: process starts are cheap, the expensive part is the
    /// engine's own receive stream, which stays asynchronous either way).
    ///
    /// Contract 1.291 (§4.277 A): with the migration switch armed this is a
    /// **scheduler**. A slot whose store still needs a pass is scheduled and left
    /// stopped; the pass runs in its own task under the migration budget and
    /// starts the engine when it lands. runtime.start therefore returns in
    /// milliseconds even when eight accounts each need a whole-store copy, so the
    /// host's dispatch deadline can never kill a migration half-way.
    pub async fn start_resident(self: &Arc<Self>) -> Option<StoreMigrationBlock> {
        self.stopping.store(false, Ordering::Release);
        let mut slots = self.slots();
        slots.sort_by(|left, right| {
            right
                .last_used()
                .cmp(&left.last_used())
                .then_with(|| left.account_id.cmp(&right.account_id))
        });
        let mut first_block = None;
        for slot in slots.into_iter().take(self.config.policy.max_resident) {
            if !slot.holds_lock() {
                continue;
            }
            if let Some(block) = self.start_or_schedule(&slot).await
                && first_block.is_none()
            {
                first_block = Some(block);
            }
        }
        first_block
    }

    /// The pool's own start of one slot: start it now when its store is ready,
    /// otherwise schedule the pass that starts it when it lands. A whole-store
    /// migration never runs on the caller's clock (§4.277 A). The return value
    /// is a terminal refusal (a latched block or a preflight refusal) so the
    /// caller can answer runtime.start honestly instead of a retryable lie.
    async fn start_or_schedule(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Option<StoreMigrationBlock> {
        // Contract 1.275: a terminal unlink is not a start failure to retry -
        // `runtime.start` must not spawn an engine that can only answer 401.
        // Contract 1.293 (§4.282): the skip is also how a domain with zero
        // serviceable accounts stays *ready* - the start reports
        // `serviceableAccountCount: 0` instead of failing, and the account face
        // carries the re-link prompt.
        if slot
            .supervisor()
            .account_is_device_unlinked(&slot.account_id)
        {
            slot.supervisor().note_device_unlinked();
            slot.set_resident(false);
            return None;
        }
        if slot.supervisor.status().await.state == EngineState::Running {
            slot.set_resident(true);
            return None;
        }
        let options = self.config.store_migration;
        match options.mode {
            StoreMigrationMode::Apply => {
                // The whole-store copy is the expensive half: schedule it and
                // let this start return (§4.277 A).
                match self.admit_engine_start(slot, true).await {
                    Ok(()) => {}
                    Err(decision) => return terminal_store_block(&decision),
                }
            }
            StoreMigrationMode::DryRun => {
                // A dry run also runs in its own task. It is observation only,
                // so the pass itself starts the engine when the plan lands -
                // runtime.start must never serially spend eight plan budgets
                // on the host's 300 s dispatch clock (§4.277 A).
                if slot.store_migrated() {
                    self.start_engine_after_gate(slot).await;
                    return None;
                }
                let state = self.begin_store_migration(slot);
                if state == StoreMigrationState::Migrated && !slot.migration_in_flight() {
                    self.start_engine_after_gate(slot).await;
                }
                return None;
            }
            StoreMigrationMode::Off => {
                // Off keeps the pre-migration path plus the operator's
                // preflight; the preflight is a bounded 16-byte read per slot,
                // never a migrator run.
                match self.gate_slot_start(slot).await.decision {
                    StoreMigrationDecision::Start { .. } => {}
                    decision => return terminal_store_block(&decision),
                }
            }
        }
        self.start_engine_after_gate(slot).await;
        None
    }

    /// Spawn the engine of a slot whose store gate the caller already cleared -
    /// the pool's scheduled start, a wake, and the link path all land here.
    async fn start_engine_after_gate(self: &Arc<Self>, slot: &Arc<AccountSlot>) {
        if self.stopping.load(Ordering::Acquire) {
            tracing::info!(
                account_id = %slot.account_id,
                group_id = %slot.proxy_group,
                "per-account engine start dropped: the runtime is stopping"
            );
            return;
        }
        if !self.still_registered(slot) {
            tracing::info!(
                account_id = %slot.account_id,
                group_id = %slot.proxy_group,
                "per-account engine start dropped: the slot was reclaimed"
            );
            return;
        }
        match slot.supervisor.start_after_store_gate().await {
            Ok(status) if status.state == EngineState::Running => {
                slot.set_resident(true);
                tracing::info!(
                    account_id = %slot.account_id,
                    group_id = %slot.proxy_group,
                    pid = status.pid.unwrap_or(0),
                    "per-account engine started (resident window)"
                );
                self.enforce_window(Arc::clone(slot));
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

    /// Whether this exact slot is still the one the pool serves for its account.
    fn still_registered(self: &Arc<Self>, slot: &Arc<AccountSlot>) -> bool {
        self.get(slot.account_id())
            .is_some_and(|current| Arc::ptr_eq(&current, slot))
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
    ///
    /// Contract 1.291: a migration pass that lands after this point must not
    /// resurrect an engine the caller just asked to stop, so the pool is marked
    /// stopping before the first engine is touched.
    pub async fn stop_all(&self) {
        self.stopping.store(true, Ordering::Release);
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
    ///
    /// Contract 1.291 (§4.277 D): the operator's intent is checked **before** the
    /// switch. A plaintext store that nothing is armed to migrate is a reason not
    /// to start whatever the mode says; with the intent off (the default) this
    /// costs one boolean and the gate below is exactly the 4.276 gate.
    async fn gate_slot_start(self: &Arc<Self>, slot: &Arc<AccountSlot>) -> StoreMigrationPass {
        let options = self.config.store_migration;
        if let Some(decision) = self.preflight_refusal(slot) {
            return StoreMigrationPass::plain(decision);
        }
        if !options.is_enabled() {
            return StoreMigrationPass::plain(StoreMigrationDecision::Start {
                outcome: "disabled",
            });
        }
        // M6 D3 review M1: an engine that is already live is success, not a
        // reason to restart. Its store is open in that process, so nothing can
        // be migrated under it - and doing "stop -> migrate -> start" on a
        // healthy slot would cut every in-flight request of that account for a
        // migration it does not need. Same reading ensure_resident applies
        // before it ever reaches this gate (`Running` answers Ok).
        if slot.supervisor.status().await.state == EngineState::Running {
            return StoreMigrationPass::plain(StoreMigrationDecision::Start {
                outcome: "already_running",
            });
        }
        // M6 D3 review M4: this process has already migrated this slot's store
        // (or found it migrated). A later start - after a stop, an idle
        // demotion, or a runtime.stop/start cycle - has nothing left to prove:
        // the whole-store verification is the expensive half, and re-running it
        // on every start is pure cost.
        if slot.store_migrated() {
            return StoreMigrationPass::plain(StoreMigrationDecision::Start {
                outcome: "already_migrated",
            });
        }
        // A latched terminal failure is answered without spawning anything:
        // that is exactly what keeps exit 11 from becoming a restart storm.
        if let Some(block) = slot.migration_block() {
            return StoreMigrationPass::plain(StoreMigrationDecision::Blocked { block });
        }
        // No non-empty store file: there is nothing a migrator could act on.
        // A true fresh slot's engine creates the encrypted store with its key;
        // a zero-byte placeholder is replaced the same way. This is a no-op
        // pass (`migrated`), never `skipped`/`failed` (task-24).
        if !crate::store_preflight::has_any_store(&slot.data_dir) {
            tracing::info!(
                store_migration = options.mode.label(),
                account = %account_fingerprint(&slot.account_id),
                store_migration_outcome = "noop",
                reason = "no_store",
                "engine store migration is a no-op: no store file to migrate"
            );
            return StoreMigrationPass::plain(StoreMigrationDecision::Start { outcome: "noop" });
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
                return StoreMigrationPass::plain(StoreMigrationDecision::Start {
                    outcome: "skipped",
                });
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
            return StoreMigrationPass::plain(StoreMigrationDecision::Retry {
                code: "store_busy".to_string(),
            });
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
            return StoreMigrationPass {
                decision,
                code: run.code.clone(),
            };
        }
    }

    /// The operator's intent as a refusal (contract 1.291, §4.277 D). Three
    /// conditions are evaluated here beside the pool's own answer to the fourth
    /// (this is a pooled slot, by construction): a plaintext store is still on
    /// disk, the migrator is off, and KT_ENGINE_STORE_REQUIRE_ENCRYPTED is on.
    ///
    /// The connector's own plaintext backup (`connector.sqlite3.plaintext-backup`)
    /// is a **warning only**: the store it copies is already encrypted, so nothing
    /// on the runtime path reads it.
    fn preflight_refusal(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Option<StoreMigrationDecision> {
        let options = self.config.store_migration;
        if !options.require_encrypted {
            return None;
        }
        if crate::store_preflight::plaintext_backup_present(&self.config.state_dir)
            && slot.backup_warn.allow(REFUSAL_LOG_WINDOW).is_some()
        {
            tracing::warn!(
                env = crate::store_preflight::REQUIRE_ENCRYPTED_ENV,
                file = crate::store_preflight::PLAINTEXT_BACKUP_FILE,
                "a plaintext backup of the connector store is still on disk; the live store is encrypted, so this is informational"
            );
        }
        let crate::store_preflight::PreflightVerdict::Refuse { code } =
            crate::store_preflight::check(
                options.require_encrypted,
                options.is_enabled(),
                &slot.data_dir,
            )
        else {
            return None;
        };
        // Deliberately **no** status state here: with the switch off the face must
        // stay empty (task B), and `check` only refuses while it is off - so this
        // refusal reaches a host through the error face and the log line, never
        // through `engines[].storeMigration`. §4.277 records that boundary.
        tracing::error!(
            store_migration = options.mode.label(),
            account = %account_fingerprint(&slot.account_id),
            store_migration_outcome = "preflight_blocked",
            code,
            "this account's store is plaintext, no migration is armed, and this host asks for encrypted stores; the engine is not started"
        );
        Some(StoreMigrationDecision::Blocked {
            block: StoreMigrationBlock {
                code: code.to_string(),
                exit: None,
                message: store_plaintext_refusal_message().to_string(),
            },
        })
    }

    /// Whether a migration pass could change this slot's answer at all: there is
    /// a directory to look in and exactly one account's key to open it with. A
    /// slot with neither is the old gate's "skipped" - it starts normally.
    fn migration_pass_applies(&self, slot: &AccountSlot) -> bool {
        slot.data_dir.is_dir()
            // A directory is not a store. An empty data directory (a fresh
            // link's empty V2 registry) has no plaintext to move; running the
            // migrator there only answers `accounts: []`, which used to be
            // classified as `completed` -> `failed` (task-24). A non-empty
            // store file is the entry fee for a pass.
            && crate::store_preflight::has_any_store(&slot.data_dir)
            && matches!(
                crate::store::engine_store_key_for_account(
                    self.config.root_store_key.as_ref(),
                    &slot.account_id
                ),
                crate::store::EngineStoreKey::Account(_)
            )
    }

    /// The admission gate every engine spawn passes (contract 1.291, §4.277 A/C).
    ///
    /// Ok means "spawn now". Err carries the same classification the wake path
    /// hands a host, and a slot that needs a pass has that pass **scheduled**
    /// here: the pass starts the engine itself when the store is ready, so a
    /// refused spawn is a deferral, never a dropped start.
    ///
    /// The default posture - switch off, intent off - answers Ok without a read,
    /// a lock, or a log line.
    ///
    /// `retry_failed` is the UX ruling (docs/plan/store-migration-ux.md): a
    /// `failed` pass is **not** retried automatically - not by a watchdog tick,
    /// not by a request waking the slot. Only an explicit runtime.start (the
    /// user's own "try again") schedules another pass; every other face answers
    /// the last verdict and leaves the state alone, so a transient failure can
    /// neither spin in the background nor be silently forgotten.
    pub(crate) async fn admit_engine_start(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
        retry_failed: bool,
    ) -> Result<(), StoreMigrationDecision> {
        let options = self.config.store_migration;
        if !options.touches_store() {
            return Ok(());
        }
        if let Some(decision) = self.preflight_refusal(slot) {
            return Err(decision);
        }
        if !options.is_enabled() {
            return Ok(());
        }
        if slot.supervisor.status().await.state == EngineState::Running {
            return Ok(());
        }
        if slot.store_migrated() {
            return Ok(());
        }
        if let Some(block) = slot.migration_block() {
            return Err(StoreMigrationDecision::Blocked { block });
        }
        if !self.migration_pass_applies(slot) {
            return Ok(());
        }
        // A pass that is already running owns the store. This check precedes
        // the dry-run arm on purpose: a crash restart must not spawn an engine
        // while a dry-run pass is reading the store either.
        let state = slot.migration_state();
        if slot.migration_in_flight() || state == StoreMigrationState::Migrating {
            return Err(StoreMigrationDecision::Retry {
                code: STORE_MIGRATION_IN_PROGRESS.to_string(),
            });
        }
        // Dry-run observes and never withholds a start (§4.276): when no pass
        // is running, a wake may let the engine come up without waiting. The
        // runtime.start scheduler handles its own quiet-store pass separately.
        if options.mode == StoreMigrationMode::DryRun {
            return Ok(());
        }
        // UX 2: a failed pass waits for the user. Refuse here with the verdict
        // it failed on, and leave the state exactly as the pass left it.
        if state == StoreMigrationState::Failed && !retry_failed {
            return Err(last_verdict_refusal(slot));
        }
        // The verdict of the last landed pass is the honest answer for this
        // refusal: a retryable failure stays retryable, an exit-2 version skew
        // stays non-retryable, and a first-ever pass answers "being prepared".
        let last = slot.last_migration_decision();
        let begun = self.begin_store_migration(slot);
        // begin_store_migration reads the header first and may prove the store
        // already encrypted without scheduling a pass; that is a start, not a
        // deferral.
        if begun == StoreMigrationState::Migrated && !slot.migration_in_flight() {
            return Ok(());
        }
        Err(match last {
            Some(StoreMigrationDecision::Misconfigured) => StoreMigrationDecision::Misconfigured,
            Some(StoreMigrationDecision::Retry { code }) => StoreMigrationDecision::Retry { code },
            Some(StoreMigrationDecision::Blocked { block }) => {
                StoreMigrationDecision::Blocked { block }
            }
            _ => StoreMigrationDecision::Retry {
                code: STORE_MIGRATION_IN_PROGRESS.to_string(),
            },
        })
    }

    /// Schedule one migration pass for a slot and answer the state a caller may
    /// report. Single-flight: a second caller joins the pass already in flight
    /// instead of starting another, which is what makes two concurrent
    /// runtime.start calls one migration rather than two migrator processes on
    /// one store.
    fn begin_store_migration(self: &Arc<Self>, slot: &Arc<AccountSlot>) -> StoreMigrationState {
        if !slot.begin_migration_flight() {
            return slot.migration_state();
        }
        // A true fresh slot has no store file to act on (an empty V2 registry
        // is not a store): the migrator would answer `accounts: []` over an
        // empty directory, which is a no-op, not work. The engine creates the
        // encrypted store itself on this start.
        if !crate::store_preflight::has_any_store(&slot.data_dir) && !slot_has_store_path(slot) {
            slot.set_migration_state(StoreMigrationState::Migrated, None);
            slot.end_migration_flight();
            return StoreMigrationState::Migrated;
        }
        // The store header, not memory, is the authority (contract 1.291 B).
        // A process restart forgets the old face; reading the header before
        // writing `pending` keeps an already-encrypted store from being
        // re-announced as un-migrated, and keeps `store_migrated` true so the
        // first start of the new process does not pay for a whole-store verify.
        let evidence = crate::store_preflight::store_files(&slot.data_dir);
        let encrypted = evidence.iter().any(|path| {
            crate::store_preflight::store_file_state(path)
                == crate::store_preflight::StoreFileState::Encrypted
        });
        let has_plaintext = evidence.iter().any(|path| {
            crate::store_preflight::store_file_state(path)
                == crate::store_preflight::StoreFileState::Plaintext
        });
        if !has_plaintext && encrypted {
            slot.mark_store_migrated();
            slot.set_migration_state(StoreMigrationState::Migrated, None);
            slot.end_migration_flight();
            return StoreMigrationState::Migrated;
        }
        slot.set_migration_state(StoreMigrationState::Pending, None);
        let pool = Arc::clone(self);
        let owned = Arc::clone(slot);
        tokio::spawn(async move { pool.run_migration_pass(owned).await });
        slot.migration_state()
    }

    /// One scheduled pass: the whole lifecycle of a slot's migration, off the
    /// caller's clock.
    ///
    /// Crash recovery is not this function's problem, and that is the design: it
    /// writes nothing to disk, so a process killed here leaves the store exactly
    /// as the migrator left it - and the next process re-runs the same pass, whose
    /// idempotency is the store's own header.
    async fn run_migration_pass(self: Arc<Self>, slot: Arc<AccountSlot>) {
        let _wake = slot.wake.lock().await;
        slot.set_migration_state(StoreMigrationState::Migrating, None);
        let pass = self.gate_slot_start(&slot).await;
        slot.record_migration_decision(
            &pass.decision,
            self.config.store_migration.mode,
            pass.code.as_deref(),
        );
        let started = matches!(pass.decision, StoreMigrationDecision::Start { .. });
        if started {
            // The pass owns the start: it is the only caller that may spawn this
            // account's engine without asking the gate again (it just cleared it).
            self.start_engine_after_gate(&slot).await;
        } else {
            tracing::info!(
                store_migration = self.config.store_migration.mode.label(),
                account = %account_fingerprint(&slot.account_id),
                store_migration_outcome = slot.migration_state().label(),
                "the migration pass did not land; this slot stays stopped until the next start"
            );
        }
        slot.end_migration_flight();
    }

    /// Recompute a slot's migration face from the **store header on disk**
    /// (contract 1.291, §4.277 B/UX-4).
    ///
    /// The stored format is the only durable fact in this design, so `migrated`
    /// is derived, not remembered: a restart reports `migrated` for a store that
    /// is already encrypted and `pending` for one that is still plaintext (or
    /// not there yet). No connector-written state file exists to drift from it.
    ///
    /// Only the *face* is seeded: the process-scoped "already migrated" skip
    /// marker stays clear, so the first start of the new process still runs the
    /// migrator once and gets the engine's own verdict (a `noop` for a healthy
    /// encrypted store, a terminal code for a damaged one). Reporting from the
    /// header costs one bounded read; skipping the verdict would cost an
    /// operator the only diagnosis they get.
    fn seed_store_migration_face(&self, slot: &Arc<AccountSlot>) {
        if !self.config.store_migration.touches_store() {
            return;
        }
        let state = if !crate::store_preflight::plaintext_stores(&slot.data_dir).is_empty() {
            StoreMigrationState::Pending
        } else if crate::store_preflight::has_any_store(&slot.data_dir) {
            // The header is the durable fact: an encrypted store is already
            // migrated, so the process-scoped marker must say so as well. A
            // later start then skips the whole-store verify instead of paying
            // for it again after every restart.
            slot.mark_store_migrated();
            StoreMigrationState::Migrated
        } else if slot_has_store_path(slot) {
            // A zero-byte, unreadable or symlinked placeholder is not proof of
            // a migrated store (task-22 ruling): the engine creates the real
            // one on start, so a pass is still owed.
            StoreMigrationState::Pending
        } else {
            // A true fresh slot - empty V2 registry, no store file at all.
            // There is no plaintext to migrate and an engine started with the
            // account key creates the encrypted store itself, so the honest
            // face is `migrated`, never `failed` (task-24).
            StoreMigrationState::Migrated
        };
        slot.set_migration_state(state, None);
    }

    /// The migration face of one slot, as this connector reports it.
    ///
    /// `None` while the migration switch is off: the operator's intent alone does
    /// not add a field (task B - an unarmed connector's status face stays
    /// byte-identical), it only decides whether an engine may start on a
    /// plaintext store.
    fn store_migration_face(&self, slot: &AccountSlot) -> Option<StoreMigrationStatus> {
        if !self.config.store_migration.is_enabled() {
            return None;
        }
        slot.store_migration_face()
    }

    /// The migration lifecycle of one account, if it has a slot.
    pub fn store_migration_status(&self, account_id: &str) -> Option<StoreMigrationStatus> {
        self.get(account_id)
            .and_then(|slot| self.store_migration_face(&slot))
    }

    /// Whether any slot has a migration pass running (runtime.start's "this pool
    /// is on its way up" answer).
    pub fn any_migration_in_flight(&self) -> bool {
        self.slots().iter().any(|slot| slot.migration_in_flight())
    }

    /// Wait until this account's migration lifecycle stops moving, bounded.
    /// A diagnostics/test helper: nothing on the serving path blocks on it.
    pub async fn wait_for_store_migration(
        self: &Arc<Self>,
        account_id: &str,
        budget: Duration,
    ) -> Option<StoreMigrationStatus> {
        let deadline = Instant::now() + budget;
        loop {
            let slot = self.get(account_id)?;
            if !slot.migration_in_flight() || Instant::now() >= deadline {
                return self.store_migration_face(&slot);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// Wait for the pass a waiting human flow just scheduled. The pass owns
    /// the engine start; this only maps its recorded verdict back to the
    /// caller, so a failed/blocked pass is never re-run here.
    async fn wait_for_scheduled_store_pass(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Result<(), SlotWakeRefusal> {
        let per_pass = self.config.store_migration.budget;
        let deadline = Instant::now()
            + per_pass.saturating_mul(STORE_MIGRATION_ATTEMPTS as u32 + 1)
            + Duration::from_secs(5);
        while slot.migration_in_flight() {
            if Instant::now() >= deadline {
                return Err(SlotWakeRefusal::MigrationGate(
                    StoreMigrationDecision::Retry {
                        code: "store_migration_timeout".to_string(),
                    },
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        match slot.last_migration_decision() {
            Some(StoreMigrationDecision::Start { .. }) => {
                if slot.supervisor.status().await.state != EngineState::Running {
                    self.start_engine_after_gate(slot).await;
                }
                Ok(())
            }
            Some(decision) => Err(SlotWakeRefusal::MigrationGate(decision)),
            None => Err(SlotWakeRefusal::MigrationGate(
                StoreMigrationDecision::Retry {
                    code: STORE_MIGRATION_IN_PROGRESS.to_string(),
                },
            )),
        }
    }

    /// Wire this pool's gate into every supervisor's start face (contract 1.291,
    /// §4.277 C). Idempotent; called after the pool is assembled and after every
    /// provisioned slot.
    fn install_start_gates(self: &Arc<Self>) {
        for slot in self.slots() {
            slot.supervisor().set_start_gate(Arc::new(SlotStartGate {
                slot: Arc::downgrade(&slot),
                pool: Arc::downgrade(self),
            }));
        }
    }

    /// The latched terminal migration failure for one account, if any. The
    /// read-only face a diagnostics endpoint or a test can consult without
    /// spawning anything.
    pub fn migration_block(&self, account_id: &str) -> Option<StoreMigrationBlock> {
        self.get(account_id).and_then(|slot| slot.migration_block())
    }

    /// How many accounts this pool could serve **right now** (contract 1.293,
    /// §4.282): every registered slot except the ones parked by an upstream
    /// `device_unlinked` verdict. Zero is a legal, domain-ready reading - all
    /// accounts are terminal, so there is nothing to serve and no engine to
    /// spawn - and `runtime.start` answers success with it instead of a start
    /// failure. Read-only, memory-only (the supervisor latch + the store row),
    /// same face as `every_slot_device_unlinked`.
    pub fn serviceable_account_count(&self) -> u32 {
        self.slots()
            .iter()
            .filter(|slot| {
                !slot
                    .supervisor()
                    .account_is_device_unlinked(&slot.account_id)
            })
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    /// Whether every registered slot is parked in the terminal unlink state
    /// (contract 1.275, re-read by contract 1.293 §4.282). This is a **state**
    /// question, not a start verdict: since §4.282 `runtime.start` answers
    /// success with `serviceableAccountCount: 0` here (the account face owns
    /// the re-link prompt), while every account-addressed call keeps answering
    /// the terminal ACCOUNT_UNLINKED.
    pub fn every_slot_device_unlinked(&self) -> bool {
        let slots = self.slots();
        !slots.is_empty()
            && slots.iter().all(|slot| {
                slot.supervisor()
                    .account_is_device_unlinked(&slot.account_id)
            })
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

    /// Wake one cold slot on the **request** path and keep the reason it did not
    /// work distinguishable.
    ///
    /// Contract 1.291 (§4.277 A): a request never waits for a whole-store
    /// migration. When the slot's store still needs a pass, this schedules it
    /// and answers the caller the retryable deferral; the pass starts the engine
    /// itself, so the retry a moment later is served. Nothing is lost and no
    /// request budget is stretched to the migration budget.
    pub async fn wake_slot(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Result<(), SlotWakeRefusal> {
        self.wake_slot_with(slot, SlotStartMode::Defer).await
    }

    /// Wake one cold slot and **wait** for the store gate (contract 1.291): the
    /// two callers that must not be answered "not yet" - a local-data delete and
    /// a link - are human flows with their own budget, and both would rather
    /// block for the pass than be told to come back.
    pub async fn wake_slot_waiting(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
    ) -> Result<(), SlotWakeRefusal> {
        self.wake_slot_with(slot, SlotStartMode::Wait).await
    }

    /// A caller that needs an engine **only as a means** to reach the store -
    /// the local-data delete, its one non-routing user - can tell
    /// [`SlotWakeRefusal::MigrationGate`] from a plain failure and take the
    /// engine-free path, instead of letting the gate veto the very action its
    /// own message prescribes.
    async fn wake_slot_with(
        self: &Arc<Self>,
        slot: &Arc<AccountSlot>,
        mode: SlotStartMode,
    ) -> Result<(), SlotWakeRefusal> {
        slot.touch();
        // Contract 1.275: a device the account holder unlinked is a terminal
        // slot. Neither a wake nor the retry behind it can revive the
        // credential, so the answer is the terminal one (ACCOUNT_UNLINKED,
        // retryable=false) even while a still-resident process is winding down.
        if slot
            .supervisor()
            .account_is_device_unlinked(&slot.account_id)
        {
            // Discovering the terminal state on the request path is also where
            // the doomed process has to go: the wake refuses *and* parks the
            // slot (idempotent), so no engine sits resident behind a credential
            // that can only answer 401.
            slot.supervisor().stop_watchdog();
            slot.supervisor().retire_device_unlinked().await;
            slot.set_resident(false);
            return Err(SlotWakeRefusal::DeviceUnlinked);
        }
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
        match mode {
            SlotStartMode::Wait => {
                // A human flow (link.start, local-data delete) waits for the
                // store gate, but it must join the same single-flight pass as
                // every other caller: `admit_engine_start` owns the
                // begin_migration_flight CAS and the failed-pass policy. When
                // it schedules a pass, wait for that pass to record its
                // verdict; a completed pass starts the engine itself.
                match self.admit_engine_start(slot, false).await {
                    Ok(()) => {}
                    Err(StoreMigrationDecision::Retry { code })
                        if code == STORE_MIGRATION_IN_PROGRESS =>
                    {
                        self.wait_for_scheduled_store_pass(slot).await?;
                    }
                    Err(decision) => return Err(SlotWakeRefusal::MigrationGate(decision)),
                }
            }
            SlotStartMode::Defer => {
                if let Err(refusal) = self.admit_engine_start(slot, false).await {
                    return Err(SlotWakeRefusal::MigrationGate(refusal));
                }
            }
        }
        if slot.supervisor.status().await.state != EngineState::Running {
            match slot.supervisor.start_after_store_gate().await {
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
                store_migration: self.store_migration_face(&slot),
                needs_relink: slot
                    .supervisor()
                    .account_is_device_unlinked(&slot.account_id),
            });
        }
        statuses
    }
}

/// RAII guard for one link attempt's slot lease.
///
/// The normal lifecycle is explicit: `link.start` opens the guard and
/// persists it once the QR exists; `link.finish` resumes it and either
/// promotes (committed) or reclaims (terminal failure); `link.cancel`
/// resumes and reclaims. The guard's `Drop` is the no-bypass net: any early
/// return, panic, or future edit that forgets to settle the attempt still
/// schedules the **same** idempotent [`AccountPool::reclaim_link_attempt`].
/// It holds the pool strongly on purpose — only an operation-scoped guard, never
/// a slot, so no pool cycle is created.
pub struct LinkAttemptGuard {
    pool: Arc<AccountPool>,
    attempt_id: String,
    /// Armed until an explicit `persist`/`promote`/`reclaim` settles it.
    armed: Cell<bool>,
}

impl LinkAttemptGuard {
    /// Open a fresh lease for a just-provisioned slot. `None` means the
    /// attempt id was already leased or this slot has an owner (a bug, never
    /// silently overwritten).
    pub fn open(pool: Arc<AccountPool>, slot: &Arc<AccountSlot>, attempt_id: &str) -> Option<Self> {
        pool.open_link_lease(slot, attempt_id)?;
        Some(Self {
            pool,
            attempt_id: attempt_id.to_string(),
            armed: Cell::new(true),
        })
    }

    /// Resume the lease an existing terminal operation is about to settle.
    /// The lease is not created here: a finish/cancel on an attempt without a
    /// lease is the legacy path and keeps its old behavior.
    pub fn resume(pool: Arc<AccountPool>, attempt_id: &str) -> Self {
        Self {
            pool,
            attempt_id: attempt_id.to_string(),
            armed: Cell::new(true),
        }
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// The attempt now outlives this call (a live QR is on screen). The lease
    /// stays in the pool table; the guard must not reclaim on drop.
    pub fn persist(self) {
        self.armed.set(false);
    }

    /// The attempt committed: the account row owns the slot from now on.
    pub fn promote(self) -> bool {
        self.armed.set(false);
        self.pool.promote_link_attempt(&self.attempt_id)
    }

    /// Terminal answer: run the one idempotent reclaim path and report what
    /// it did. Consuming the guard makes a double settle impossible.
    pub async fn reclaim(self) -> LinkReclaimOutcome {
        self.armed.set(false);
        self.pool.reclaim_link_attempt(&self.attempt_id).await
    }
}

impl Drop for LinkAttemptGuard {
    fn drop(&mut self) {
        if !self.armed.get() {
            return;
        }
        self.armed.set(false);
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                target: "connector.pool",
                invariant = LINK_SLOT_LEAK_INVARIANT,
                attempt = %self.attempt_id,
                "link attempt guard dropped outside a runtime; the startup scan will reclaim the slot"
            );
            return;
        };
        let pool = Arc::clone(&self.pool);
        let attempt_id = self.attempt_id.clone();
        handle.spawn(async move {
            let outcome = pool.reclaim_link_attempt(&attempt_id).await;
            tracing::info!(
                attempt = %attempt_id,
                outcome = ?outcome,
                "unsettled link attempt guard ran the reclaim path"
            );
        });
    }
}

/// The bridge from a supervisor's start face to this pool's gate (contract
/// 1.291, §4.277 C). Weak refs on purpose: a gate must never keep a reclaimed
/// slot - or the whole pool - alive.
struct SlotStartGate {
    slot: std::sync::Weak<AccountSlot>,
    pool: std::sync::Weak<AccountPool>,
}

impl crate::supervisor::EngineStartGate for SlotStartGate {
    fn admit_engine_start(&self) -> futures_util::future::BoxFuture<'_, Result<(), &'static str>> {
        Box::pin(async move {
            let (Some(slot), Some(pool)) = (self.slot.upgrade(), self.pool.upgrade()) else {
                // The slot is gone: there is no store left to protect, and
                // refusing here would only break a shutdown path.
                return Ok(());
            };
            pool.admit_engine_start(&slot, false)
                .await
                .map_err(|decision| store_migration_refusal_code(&decision))
        })
    }
}

/// A terminal gate verdict for a start that cannot ever succeed in this
/// process: a latched block or the preflight refusal. Retry-shaped verdicts
/// return None (they may be re-tried by an explicit runtime.start).
fn terminal_store_block(decision: &StoreMigrationDecision) -> Option<StoreMigrationBlock> {
    match decision {
        StoreMigrationDecision::Blocked { block } => Some(block.clone()),
        StoreMigrationDecision::Misconfigured => Some(StoreMigrationBlock {
            code: "store_migration_misconfigured".to_string(),
            exit: None,
            message: store_migration_misconfigured_message().to_string(),
        }),
        _ => None,
    }
}

/// The refusal a slot that already failed re-answers, without running (or
/// scheduling) anything: the same sentence and the same retryable bit its own
/// pass produced, so a host sees a stable verdict instead of a timer.
fn last_verdict_refusal(slot: &AccountSlot) -> StoreMigrationDecision {
    match slot.last_migration_decision() {
        Some(StoreMigrationDecision::Retry { code }) => StoreMigrationDecision::Retry { code },
        Some(StoreMigrationDecision::Misconfigured) => StoreMigrationDecision::Misconfigured,
        Some(StoreMigrationDecision::Blocked { block }) => {
            StoreMigrationDecision::Blocked { block }
        }
        _ => StoreMigrationDecision::Retry {
            code: STORE_MIGRATION_IN_PROGRESS.to_string(),
        },
    }
}

/// The closed literal a supervisor start refusal carries. The host face renders
/// the sentence; this word is only for the log line and the caller's match.
fn store_migration_refusal_code(decision: &StoreMigrationDecision) -> &'static str {
    match decision {
        StoreMigrationDecision::Blocked { block }
            if block.code == STORE_PLAINTEXT_REQUIRES_MIGRATION =>
        {
            STORE_PLAINTEXT_REQUIRES_MIGRATION
        }
        StoreMigrationDecision::Blocked { .. } => "store_migration_blocked",
        StoreMigrationDecision::Retry { .. } => "store_migration_pending",
        StoreMigrationDecision::Misconfigured => "store_migration_misconfigured",
        StoreMigrationDecision::Start { .. } => "store_migration_settled",
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
    let slot = Arc::new(AccountSlot {
        account_id,
        proxy_group,
        data_dir,
        sidecar,
        routing,
        supervisor,
        wake: tokio::sync::Mutex::new(()),
        resident: AtomicBool::new(false),
        provisioned: AtomicBool::new(provisioned),
        lease_attempt_id: StdMutex::new(None),
        lock: StdMutex::new(lock),
        last_used: StdMutex::new(last_used),
        migration: StdMutex::new(MigrationLifecycle::default()),
        migration_in_flight: AtomicBool::new(false),
        store_migrated: AtomicBool::new(false),
        misconfigured_log: RepeatThrottle::default(),
        backup_warn: RepeatThrottle::default(),
    });
    // Contract 1.275: the slot's own consumer of the terminal-unlink lane.
    spawn_device_unlink_guard(Arc::downgrade(&slot), slot.supervisor().subscribe_host());
    slot
}

/// The terminal-unlink guard of one per-account slot (contract 1.275).
///
/// The supervisor's account-unlink watcher persists `device_unlinked` and only
/// then emits `account.changed`; this task consumes exactly that lane, so the
/// pool acts **after** the terminal write landed (a link window that defers the
/// write emits nothing and is left alone). Acting means: park the restart lane,
/// stop the engine process, and leave the slot in place for a re-link - the
/// engine must not outlive the credential, and the slot's resident bit must not
/// keep a dead engine warm.
///
/// Weak on purpose: the task exits when the slot is reclaimed, and the receiver
/// closes with the supervisor.
fn spawn_device_unlink_guard(
    slot: std::sync::Weak<AccountSlot>,
    mut host_events: tokio::sync::broadcast::Receiver<HostSideEvent>,
) {
    tokio::spawn(async move {
        loop {
            match host_events.recv().await {
                Ok(HostSideEvent::AccountChanged(account)) => {
                    if account.state != "device_unlinked" {
                        continue;
                    }
                    let Some(slot) = slot.upgrade() else {
                        return;
                    };
                    if account.id != slot.account_id {
                        continue;
                    }
                    // Park the restart lane before the process goes: a watchdog
                    // tick that raced the unlink must not re-spawn the engine
                    // between the two lines.
                    slot.supervisor().stop_watchdog();
                    slot.set_resident(false);
                    slot.supervisor().retire_device_unlinked().await;
                    tracing::warn!(
                        account_id = %slot.account_id,
                        group_id = %slot.proxy_group,
                        "per-account slot parked: the device was unlinked upstream and needs a re-link"
                    );
                }
                Ok(_) => {}
                // A slow consumer skips what it missed; the state is read from
                // the store again on the next event and by every start face.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
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

/// Whether a slot's data directory holds any store-shaped path at all - even
/// a zero-byte, unreadable or symlinked placeholder the preflight classifies
/// as `Absent`/`Unverifiable`. A true fresh slot (empty V2 registry, no store
/// file) has none; that distinction lets the migration face call a fresh slot
/// `migrated` without calling a zero-byte placeholder a store (task-22).
fn slot_has_store_path(slot: &AccountSlot) -> bool {
    if std::fs::symlink_metadata(slot.data_dir.join(crate::store_preflight::STORE_FILE_NAME))
        .is_ok()
    {
        return true;
    }
    let accounts = slot.data_dir.join("accounts");
    let Ok(metadata) = std::fs::symlink_metadata(&accounts) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(&accounts) else {
        return false;
    };
    entries
        .flatten()
        .take(crate::store_preflight::MAX_SCANNED_ACCOUNT_DIRS)
        .any(|entry| {
            entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                && std::fs::symlink_metadata(
                    entry.path().join(crate::store_preflight::STORE_FILE_NAME),
                )
                .is_ok()
        })
}

/// Whether a slot directory carries something a reclaim must not delete
/// silently: a non-empty engine registry account list, or any store-shaped
/// path under `accounts/`. A fresh `link.start` slot writes an empty V2
/// registry and nothing else, so it is safe to delete; anything beyond that is
/// an engine-side link the connector never committed and goes to quarantine.
fn slot_has_credentials(slot: &AccountSlot) -> bool {
    let has_accounts = std::fs::read(
        slot.data_dir
            .join(crate::history_import::ENGINE_REGISTRY_FILE),
    )
    .ok()
    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    .and_then(|state| {
        state
            .get("accounts")
            .and_then(serde_json::Value::as_array)
            .map(|accounts| !accounts.is_empty())
    })
    .unwrap_or(false);
    has_accounts || slot_has_store_path(slot)
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

    /// 3: begin_store_migration must read the store header before writing
    /// `pending`; an encrypted store it discovers belongs to a finished
    /// migration, not to a pass that is owed. This is the in-process half of
    /// the persistence guarantee (the seed covers process assembly).
    #[tokio::test]
    async fn begin_store_migration_reads_the_header_before_writing_pending() {
        let temp = TempDir::new().unwrap();
        let mut config = config(&temp, false);
        config.store_migration = StoreMigrationOptions {
            mode: StoreMigrationMode::Apply,
            ..StoreMigrationOptions::default()
        };
        let account = "0123456789abcdef0123456789abcdef";
        let store = config
            .signal_data_dir
            .join("engines")
            .join(account)
            .join("accounts")
            .join("lk-0123456789abcdef")
            .join("store.db");
        std::fs::create_dir_all(store.parent().unwrap()).unwrap();
        std::fs::write(&store, [0x9a_u8, 0x1f, 0x00, 0x5c, 0x11, 0x7d]).unwrap();
        let pool = AccountPool::discover(config);
        let slot = pool.get(account).expect("the encrypted slot is discovered");
        assert_eq!(slot.migration_state(), StoreMigrationState::Migrated);
        // Simulate the state a fresh process has before the seed runs: the
        // header is the only authority left.
        slot.store_migrated.store(false, Ordering::Relaxed);
        slot.set_migration_state(StoreMigrationState::Pending, None);
        let state = pool.begin_store_migration(&slot);
        assert_eq!(state, StoreMigrationState::Migrated);
        assert!(slot.store_migrated(), "the header sets the process marker");
        assert_eq!(slot.migration_state(), StoreMigrationState::Migrated);
        assert!(
            !slot.migration_in_flight(),
            "no pass is scheduled for an already encrypted store"
        );
    }

    /// task-24: an empty data directory (empty V2 registry, no store file) is
    /// not migration work: no pass applies, and the face is `migrated`.
    #[tokio::test]
    async fn a_fresh_empty_slot_is_migrated_without_a_pass() {
        let temp = TempDir::new().unwrap();
        let mut config = config(&temp, false);
        config.store_migration = StoreMigrationOptions {
            mode: StoreMigrationMode::Apply,
            ..StoreMigrationOptions::default()
        };
        let pool = AccountPool::discover(config);
        let slot = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        assert!(
            !pool.migration_pass_applies(&slot),
            "an empty directory is not a store"
        );
        assert_eq!(
            slot.migration_state(),
            StoreMigrationState::Migrated,
            "a fresh slot has no plaintext to migrate"
        );
        assert_eq!(
            pool.begin_store_migration(&slot),
            StoreMigrationState::Migrated,
            "the scheduler must not queue a pass over an empty directory"
        );
        assert!(!slot.migration_in_flight(), "no migrator task is scheduled");
        pool.discard(slot.account_id(), true).await;
    }

    /// BUG-1: a slot whose engine-side registry carries an account (a phone
    /// approval the connector never committed) must be stopped and moved into
    /// `engines/.quarantine-*`, never deleted silently; a replay is a quiet
    /// no-op and never touches the bytes again.
    #[tokio::test]
    async fn reclaim_quarantines_a_credential_bearing_slot_and_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let pool = AccountPool::discover(config(&temp, false));
        let slot = pool.provision_slot(DEFAULT_PROXY_GROUP_ID).unwrap();
        let account = slot.account_id().to_string();
        let dir = slot.data_dir.clone();
        // The engine's own registry proves a credential was linked (the
        // connector never wrote a row): this is exactly the leak shape.
        std::fs::write(
            dir.join("engine-state.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "accounts": [{"number": "+15550000123", "dir": "accounts/lk-one"}],
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(pool.open_link_lease(&slot, "leaked-attempt").is_some());

        assert_eq!(
            pool.reclaim_link_attempt("leaked-attempt").await,
            LinkReclaimOutcome::Quarantined
        );
        assert!(!dir.exists(), "the live slot directory is gone");
        assert!(pool.get(&account).is_none());
        assert_eq!(pool.open_link_leases(), 0);

        let engines_root = temp.path().join("signal-data").join(ENGINE_SLOT_SUBDIR);
        let quarantined: Vec<_> = std::fs::read_dir(&engines_root)
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".quarantine-{account}-"))
            })
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert!(
            quarantined[0].path().join("engine-state.json").is_file(),
            "the credential bytes stay auditable"
        );
        // Idempotent: the replay removes nothing and reports settled.
        assert_eq!(
            pool.reclaim_link_attempt("leaked-attempt").await,
            LinkReclaimOutcome::AlreadySettled
        );
        assert!(quarantined[0].path().join("engine-state.json").is_file());
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
        // A pass that is running right now is the one retryable verdict: it
        // finishes on its own and the next start serves the account.
        let running = SlotWakeRefusal::MigrationGate(StoreMigrationDecision::Retry {
            code: STORE_MIGRATION_IN_PROGRESS.to_string(),
        });
        assert!(running.is_migration_gate());
        match running.into_service_error() {
            ServiceError::Api(error) => {
                assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
                assert!(error.retryable, "the pass is still running");
                assert!(
                    error.message.contains("being prepared"),
                    "{}",
                    error.message
                );
                assert!(
                    error.message.contains("Retry in a moment"),
                    "{}",
                    error.message
                );
            }
            other => panic!("a gate refusal is an API error, got {other:?}"),
        }
        // A pass that already failed does not: contract 1.291 (UX 2) retires
        // the "the next start may work" promise, because nothing retries it.
        let failed = SlotWakeRefusal::MigrationGate(StoreMigrationDecision::Retry {
            code: "store_busy".to_string(),
        });
        match failed.into_service_error() {
            ServiceError::Api(error) => {
                assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
                assert!(!error.retryable, "nothing retries this on its own");
                assert!(error.message.contains("store_busy"));
                assert!(error.message.contains("not retried automatically"));
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
    fn the_five_wire_states_map_onto_start_permission() {
        // Only an unarmed connector and a proven-encrypted store may spawn
        // without asking the migrator again (contract 1.291).
        for state in [
            StoreMigrationState::Off,
            StoreMigrationState::Pending,
            StoreMigrationState::Migrating,
            StoreMigrationState::Migrated,
            StoreMigrationState::Blocked,
            StoreMigrationState::Failed,
        ] {
            assert_eq!(
                state.allows_start(),
                matches!(
                    state,
                    StoreMigrationState::Off | StoreMigrationState::Migrated
                ),
                "{}",
                state.label()
            );
        }
        assert_eq!(StoreMigrationState::default().label(), "off");
        // The wire never carries the off word: a slot whose switch is off omits
        // the whole key instead (see the schema consistency test).
        assert_eq!(
            [
                StoreMigrationState::Pending.label(),
                StoreMigrationState::Migrating.label(),
                StoreMigrationState::Migrated.label(),
                StoreMigrationState::Blocked.label(),
                StoreMigrationState::Failed.label(),
            ],
            ["pending", "migrating", "migrated", "blocked", "failed"]
        );
    }

    #[test]
    fn the_status_code_is_clamped_by_characters_not_bytes() {
        let long = "x".repeat(STORE_MIGRATION_CODE_MAX_CHARS + 20);
        assert_eq!(clamp_store_migration_code(&long).chars().count(), 64);
        // A multi-byte code must be cut on a character boundary, never mid-byte.
        let multibyte = "存".repeat(STORE_MIGRATION_CODE_MAX_CHARS + 5);
        let clamped = clamp_store_migration_code(&multibyte);
        assert_eq!(clamped.chars().count(), 64);
        assert_eq!(clamped, multibyte.chars().take(64).collect::<String>());
        assert_eq!(clamp_store_migration_code("LOCKED"), "LOCKED");
    }

    #[test]
    fn the_engine_vocabulary_maps_onto_the_connector_words() {
        let blocked = |code: &str| {
            store_migration_face_code(
                &StoreMigrationDecision::Blocked {
                    block: StoreMigrationBlock {
                        code: code.to_string(),
                        exit: Some(11),
                        message: store_migration_block_message(code),
                    },
                },
                Some(code),
            )
        };
        assert_eq!(blocked("StoreKeyRequired"), STORE_CODE_KEY_INVALID);
        assert_eq!(blocked("store_key_rejected"), STORE_CODE_KEY_INVALID);
        assert_eq!(blocked("store_corrupt"), STORE_CODE_VERIFY_FAILED);
        assert_eq!(
            blocked("store_migration_verify_failed"),
            STORE_CODE_VERIFY_FAILED
        );
        assert_eq!(
            blocked("StoreCipherUnavailable"),
            STORE_CODE_CAPABILITY_MISSING
        );
        // An unknown terminal code still lands on a closed word.
        assert_eq!(blocked("something_new"), STORE_CODE_VERIFY_FAILED);
        // The preflight's own refusal is the REQUIRED word.
        assert_eq!(
            store_migration_face_code(
                &StoreMigrationDecision::Blocked {
                    block: StoreMigrationBlock {
                        code: STORE_PLAINTEXT_REQUIRES_MIGRATION.to_string(),
                        exit: None,
                        message: store_plaintext_refusal_message().to_string(),
                    },
                },
                None,
            ),
            STORE_CODE_REQUIRED
        );
        let retry = |code: &str| {
            store_migration_face_code(
                &StoreMigrationDecision::Retry {
                    code: code.to_string(),
                },
                None,
            )
        };
        assert_eq!(retry("store_migration_timeout"), STORE_CODE_TIMEOUT);
        assert_eq!(retry("store_busy"), STORE_CODE_LOCKED);
        assert_eq!(retry("store_lock_held"), STORE_CODE_LOCKED);
        assert_eq!(
            retry("store_migration_spawn_failed"),
            STORE_CODE_INTERRUPTED
        );
        assert_eq!(retry("store_pull_failed"), STORE_CODE_IO_ERROR);
        assert_eq!(
            store_migration_face_code(&StoreMigrationDecision::Misconfigured, None),
            STORE_CODE_CAPABILITY_MISSING
        );
    }

    #[test]
    fn a_failed_pass_never_promises_an_automatic_retry() {
        let message = store_migration_failed_message("store_busy");
        assert!(message.contains("store_busy"), "{message}");
        assert!(message.contains("not retried automatically"), "{message}");
        assert!(
            message.contains("plaintext store was left untouched"),
            "{message}"
        );
        // The old sentence promised a retry nobody makes; it must not come back.
        assert!(!message.contains("retried on the next start"), "{message}");
    }

    #[test]
    fn a_preflight_refusal_names_both_ways_out() {
        let message = store_plaintext_refusal_message();
        assert!(message.contains("KT_ENGINE_STORE_MIGRATE"), "{message}");
        assert!(
            message.contains("KT_ENGINE_STORE_REQUIRE_ENCRYPTED"),
            "{message}"
        );
        assert!(message.contains("Nothing was changed"), "{message}");
        // It must not read as a data problem: a plaintext store is intact.
        assert!(!message.contains("Re-link"), "{message}");
        assert!(
            store_gate_deferral_message(STORE_PLAINTEXT_REQUIRES_MIGRATION)
                .contains("KT_ENGINE_STORE_REQUIRE_ENCRYPTED")
        );
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
