// SPDX-License-Identifier: AGPL-3.0-only

//! Legacy → per-account engine data migration (engine-pool design S2, shipped
//! with the full-pool S1 switch).
//!
//! The pre-pool layout answers every account from its proxy group's engine
//! data directory:
//!
//! ~~~text
//! <signal-data>/engine-state.json                  # default group
//! <signal-data>/accounts/lk-<hex>/store.db
//! <signal-data>/proxy-groups/<group>/engine-state.json
//! <signal-data>/proxy-groups/<group>/accounts/lk-<hex>/store.db
//! ~~~
//!
//! The pool needs one directory per account:
//! `<signal-data>/engines/<accountId>/`. This module moves each account's
//! presage store with a same-volume `rename` (never a copy) and keeps the
//! engine registries consistent at every step:
//!
//! 1. write the target `engine-state.json` (exactly one account) **before**
//!    moving the store, so a crash can never leave a target directory whose
//!    registry is missing;
//! 2. `rename` the `accounts/lk-*` directory into it;
//! 3. rewrite the source registry without that entry;
//! 4. verify (target store present, target registry names it, source no
//!    longer lists it).
//!
//! Every step is journaled to `<signal-data>/migration/<runId>.jsonl`
//! (opaque ids and group names only — never a number, ACI, or key path) and
//! re-running the pass resumes from whatever the filesystem shows: a target
//! registry with a missing store continues with the move; a completed target
//! with a stale source registry repairs the source. Any state that cannot be
//! proven safe (both copies present, registry unreadable, unexpected version,
//! a symlink, a store with no registry entry) aborts startup fail-closed.
//!
//! `dry_run` performs every read/validation and emits the same plan without
//! touching the filesystem, so operators can compare the report with the
//! applied result. It never creates a journal, a slot, or a lock file, and it
//! never rewrites a registry (contract revision 1.288, §4.274).
//!
//! The report is the operator's actionable checklist, not a log: the current
//! layout (`legacy` / `pooled` / `mixed` / `empty`), the account count, how
//! many engines the next pooled start will keep resident versus cold-start, the
//! exit code the applied pass is expected to produce, and the next commands to
//! run. `scan_engine_layout` is the same read-only observation the registry
//! uses to fail closed on a mixed layout — it is exported so the refusal and
//! the plan cannot drift apart.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::DEFAULT_PROXY_GROUP_ID;
use crate::groups::is_valid_group_id;
use crate::pool::{ENGINE_SLOT_SUBDIR, is_account_id};
use crate::store::{AccountRow, Store, StoreError};

const STATE_FILE: &str = "engine-state.json";
const ACCOUNTS_DIR: &str = "accounts";
const STORE_DB_FILE: &str = "store.db";
const STATE_VERSION: u32 = 2;
/// Bound on one engine registry file. The real registry is a few hundred
/// bytes per account; anything larger is corrupt or hostile and must fail
/// closed without allocating it.
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MIGRATION_DIR: &str = "migration";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AccountEntry {
    number: String,
    dir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    accounts: Vec<AccountEntry>,
}

/// One account's migration outcome. `action` is stable machine-readable text
/// (the CLI report and the integration test compare it):
/// - `migrated`: the store moved on this run;
/// - `alreadyMigrated`: the target was already complete;
/// - `wouldMigrate`: dry-run plan for a store that still sits in a legacy
///   directory;
/// - `removedOrphan` / `wouldRemoveOrphan`: an empty engine directory with no
///   account row and no credentials (a rolled-back link's leftover).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationEntry {
    pub account_id: String,
    pub proxy_group: String,
    pub action: String,
    /// Terminal intent for the row, when the action name alone is ambiguous
    /// (e.g. a quarantined slot that still lets the connector start). Additive:
    /// older consumers ignore the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

/// How the signal data directory is laid out right now (contract revision
/// 1.288, §4.274). `Mixed` is the only state the connector refuses to resolve
/// on its own: both layouts hold credential stores, and picking one would be a
/// guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EngineLayoutKind {
    Empty,
    Legacy,
    Pooled,
    Mixed,
}

/// One `engines/<accountId>/` directory the layout scan found.
/// `registry_accounts` is the number the engine's own single-account guard
/// compares against (`KT_ENGINE_SINGLE_ACCOUNT`, engine `main.rs`: the
/// registry count, not the store count); `stores_present` is how many of those
/// accounts still have their presage store on disk, which is what "this slot
/// holds credentials" means for layout classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotLayout {
    pub account_id: String,
    pub registry_accounts: usize,
    pub stores_present: usize,
}

/// The whole data directory's layout, read without touching it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineLayout {
    pub legacy_accounts: usize,
    pub slots: Vec<SlotLayout>,
}

impl EngineLayout {
    pub fn pooled_accounts(&self) -> usize {
        self.slots.iter().map(|slot| slot.stores_present).sum()
    }

    /// Both layouts hold credential stores: the migration cannot tell which
    /// copy is authoritative, so this is an operator decision
    /// (`migrate-pool`), never a startup guess.
    pub fn is_mixed(&self) -> bool {
        self.legacy_accounts > 0 && self.pooled_accounts() > 0
    }

    pub fn kind(&self) -> EngineLayoutKind {
        if self.legacy_accounts > 0 && self.pooled_accounts() > 0 {
            EngineLayoutKind::Mixed
        } else if self.legacy_accounts > 0 {
            EngineLayoutKind::Legacy
        } else if !self.slots.is_empty() {
            // A slot directory exists even if its store is gone (an interrupted
            // provision or a damaged copy): the directory is on the pool
            // layout, and the migration report is where the missing store
            // shows up as `unprovisioned`.
            EngineLayoutKind::Pooled
        } else {
            EngineLayoutKind::Empty
        }
    }

    /// The first slot whose own engine registry names more than one account.
    /// Under `KT_ENGINE_SINGLE_ACCOUNT=1` the engine refuses to start such a
    /// process; the connector refuses to even reach the spawn.
    pub fn multi_account_slot(&self) -> Option<&SlotLayout> {
        self.slots.iter().find(|slot| slot.registry_accounts > 1)
    }
}

/// Read the data directory's layout: which accounts still sit in the legacy
/// proxy-group directories (store present), and what every per-account engine
/// slot's own registry names. Read-only, bounded, and only plain account-id
/// directory names are ever adopted.
pub fn scan_engine_layout(signal_data_dir: &Path) -> Result<EngineLayout, StoreError> {
    Ok(EngineLayout {
        legacy_accounts: legacy_account_count(signal_data_dir)?,
        slots: scan_slots(&signal_data_dir.join(ENGINE_SLOT_SUBDIR))?,
    })
}

fn legacy_account_count(root: &Path) -> Result<usize, StoreError> {
    let mut group_dirs = vec![root.to_path_buf()];
    match fs::read_dir(root.join("proxy-groups")) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(pool_invalid_io)?;
                if !entry.file_type().map_err(pool_invalid_io)?.is_dir() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if is_valid_group_id(&name) {
                    group_dirs.push(entry.path());
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(pool_invalid_io(error)),
    }
    let mut accounts = 0;
    for dir in group_dirs {
        let Some(state) = read_state_lenient(&dir.join(STATE_FILE))? else {
            continue;
        };
        for entry in &state.accounts {
            let Some(relative) = entry.dir.as_deref() else {
                continue;
            };
            let Ok(store_name) = validated_store_component(relative) else {
                continue;
            };
            if dir
                .join(ACCOUNTS_DIR)
                .join(store_name)
                .join(STORE_DB_FILE)
                .is_file()
            {
                accounts += 1;
            }
        }
    }
    Ok(accounts)
}

fn scan_slots(engines_root: &Path) -> Result<Vec<SlotLayout>, StoreError> {
    let entries = match fs::read_dir(engines_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(pool_invalid_io(error)),
    };
    let mut slots = Vec::new();
    for entry in entries {
        let entry = entry.map_err(pool_invalid_io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_account_id(&name) || !entry.file_type().map_err(pool_invalid_io)?.is_dir() {
            continue;
        }
        let dir = entry.path();
        let state = read_state_lenient(&dir.join(STATE_FILE))?;
        let mut stores_present = 0;
        if let Some(state) = state.as_ref() {
            for entry in &state.accounts {
                let Some(relative) = entry.dir.as_deref() else {
                    continue;
                };
                let Ok(store_name) = validated_store_component(relative) else {
                    continue;
                };
                if dir
                    .join(ACCOUNTS_DIR)
                    .join(store_name)
                    .join(STORE_DB_FILE)
                    .is_file()
                {
                    stores_present += 1;
                }
            }
        }
        // A directory that carries neither a registry nor an accounts tree is
        // a rolled-back provision, not layout material; the pool's orphan
        // sweep removes it.
        if state.is_none() && !dir.join(ACCOUNTS_DIR).is_dir() {
            continue;
        }
        slots.push(SlotLayout {
            account_id: name,
            registry_accounts: state
                .as_ref()
                .map(|state| state.accounts.len())
                .unwrap_or_default(),
            stores_present,
        });
    }
    slots.sort_by(|left, right| left.account_id.cmp(&right.account_id));
    Ok(slots)
}

/// The migration/dry-run report (log-safe: opaque ids and group names only).
/// Since contract revision 1.288 (§4.274) it is also the operator's
/// actionable plan: the layout, the account count, the next pooled boot's
/// resident/cold split, the expected exit code, and the next commands.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    pub dry_run: bool,
    pub layout: EngineLayoutKind,
    pub accounts: usize,
    pub resident_cap: usize,
    pub resident_on_start: usize,
    pub cold_starts: usize,
    pub expected_exit_code: i32,
    pub blockers: Vec<String>,
    pub next_steps: Vec<String>,
    pub entries: Vec<MigrationEntry>,
    pub migrated: usize,
    pub already_migrated: usize,
    pub unprovisioned: usize,
    pub orphans_removed: usize,
}

impl MigrationReport {
    /// A dry-run plan that cannot be applied: nothing is migrated, the exit
    /// code says so, and the blocker is the one message the pass produced.
    /// Used by the CLI so a refuse-to-migrate state is still an actionable
    /// report instead of a bare error line.
    pub fn blocked(
        layout: EngineLayoutKind,
        accounts: usize,
        resident_cap: usize,
        blocker: String,
    ) -> Self {
        Self {
            dry_run: true,
            layout,
            accounts,
            resident_cap,
            resident_on_start: 0,
            cold_starts: 0,
            expected_exit_code: 1,
            blockers: vec![blocker],
            next_steps: vec![
                "resolve the blocker above, then re-run migrate-pool --dry-run".to_string(),
            ],
            entries: Vec::new(),
            migrated: 0,
            already_migrated: 0,
            unprovisioned: 0,
            orphans_removed: 0,
        }
    }

    /// A dry-run plan refused because the store was stamped by a newer
    /// connector (contract revision 1.284, §4.268, read at the dry-run face).
    /// The applied pass refuses the same store at `Store::open`, so this plan
    /// carries both of that refusal's texts verbatim — the classified message
    /// and the fixed `KT_FATAL` launcher line — and stays blocked
    /// (`expectedExitCode=1`, process exit 1). `accounts` is 0 because the
    /// probe refuses before it reads a row: a count invented from a schema this
    /// build does not know would be a guess.
    ///
    /// No step suggests dropping `--dry-run`: the applied pass cannot succeed
    /// against this store either, so the only move is a newer connector. The
    /// plan also states that the probe left no marker behind — that file is the
    /// applied refusal's record, never the dry run's.
    pub fn blocked_newer_schema(
        layout: EngineLayoutKind,
        resident_cap: usize,
        current: i64,
        supported: i64,
    ) -> Self {
        let refusal = crate::store::StoreError::SchemaNewer { current, supported };
        let mut blockers = vec![refusal.to_string()];
        if let Some(line) = crate::store::fatal_line_for(&refusal) {
            blockers.push(line);
        }
        Self {
            dry_run: true,
            layout,
            accounts: 0,
            resident_cap,
            resident_on_start: 0,
            cold_starts: 0,
            expected_exit_code: 1,
            blockers,
            next_steps: vec![
                format!(
                    "upgrade the connector to a build that knows schema {current} (this binary supports {supported}); the store is never downgraded"
                ),
                "the store was read only: no -shm/-wal, no snapshot, and no schema-newer marker were written"
                    .to_string(),
                "re-run this plan with the upgraded connector; the applied pass refuses this store for the same reason"
                    .to_string(),
            ],
            entries: Vec::new(),
            migrated: 0,
            already_migrated: 0,
            unprovisioned: 0,
            orphans_removed: 0,
        }
    }

    /// Fill the plan's derived numbers once every account has an outcome.
    fn finish(&mut self) {
        let provisioned = self
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.action.as_str(),
                    "migrated" | "alreadyMigrated" | "wouldMigrate"
                )
            })
            .count();
        let cap = self.resident_cap.max(1);
        self.resident_on_start = provisioned.min(cap);
        self.cold_starts = provisioned.saturating_sub(cap);
        let would_move = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.action.as_str(), "migrated" | "wouldMigrate"))
            .count();
        self.next_steps = next_steps(self.dry_run, would_move, self.unprovisioned);
    }
}

fn next_steps(dry_run: bool, would_move: usize, unprovisioned: usize) -> Vec<String> {
    let mut steps = Vec::new();
    if would_move > 0 {
        steps.push(
            "back up the signal-data and state directories first: the move is one-way and rollback is a restore"
                .to_string(),
        );
    }
    if dry_run && would_move > 0 {
        steps.push("stop every connector, then re-run this command without --dry-run".to_string());
    }
    if unprovisioned > 0 {
        steps.push(format!(
            "{unprovisioned} account row(s) have no engine data; they answer ENGINE_NOT_PROVISIONED until re-linked"
        ));
    }
    steps.push("start the connector with --per-account-engines (full pooling)".to_string());
    steps
}

/// Run (or dry-run) the whole pass. `resident_cap` is the launcher's pool
/// resident window ([crate::pool::EnginePoolPolicy::max_resident]); it only
/// shapes the plan's cold-start count. Returns `EnginePoolInvalid` with a
/// log-safe description on any state that cannot be proven safe; the caller
/// must abort startup in that case ("no half-migrated serve", requirement 3).
pub fn run(
    store: &Store,
    signal_data_dir: &Path,
    state_dir: &Path,
    dry_run: bool,
    resident_cap: usize,
) -> Result<MigrationReport, StoreError> {
    run_for_rows(
        &store.list_all_account_rows()?,
        signal_data_dir,
        state_dir,
        dry_run,
        resident_cap,
    )
}

/// The same pass over rows the caller already holds. `migrate-pool --dry-run`
/// enters here: its rows come from the read-only store probe
/// ([`crate::store::probe_account_rows`]), so a plan over a `--state-dir` that
/// does not exist yet needs no writable store at all — no directory, no
/// `connector.sqlite3`, no WAL (contract revision 1.288, §4.274).
pub fn run_for_rows(
    rows: &[AccountRow],
    signal_data_dir: &Path,
    state_dir: &Path,
    dry_run: bool,
    resident_cap: usize,
) -> Result<MigrationReport, StoreError> {
    let layout = scan_engine_layout(signal_data_dir)?;
    let engines_root = signal_data_dir.join(ENGINE_SLOT_SUBDIR);
    let mut journal = if dry_run {
        None
    } else {
        Some(Journal::open(signal_data_dir).map_err(pool_invalid_io)?)
    };
    if let Some(journal) = journal.as_mut() {
        journal.record("run", None, None, "start");
    }
    let mut report = MigrationReport {
        dry_run,
        layout: layout.kind(),
        accounts: rows.len(),
        resident_cap,
        resident_on_start: 0,
        cold_starts: 0,
        expected_exit_code: 0,
        blockers: Vec::new(),
        next_steps: Vec::new(),
        entries: Vec::new(),
        migrated: 0,
        already_migrated: 0,
        unprovisioned: 0,
        orphans_removed: 0,
    };
    for row in rows {
        let entry = migrate_account(
            row,
            signal_data_dir,
            &engines_root,
            state_dir,
            dry_run,
            journal.as_mut(),
        )?;
        match entry.action.as_str() {
            "migrated" => report.migrated += 1,
            "alreadyMigrated" => report.already_migrated += 1,
            "unprovisioned" => report.unprovisioned += 1,
            _ => {}
        }
        report.entries.push(entry);
    }
    reconcile_orphans(rows, &engines_root, dry_run, journal.as_mut(), &mut report)?;
    if let Some(journal) = journal.as_mut() {
        journal.record(
            "done",
            None,
            None,
            &format!(
                "migrated={} already={} unprovisioned={} orphans={}",
                report.migrated,
                report.already_migrated,
                report.unprovisioned,
                report.orphans_removed
            ),
        );
    }
    report.finish();
    Ok(report)
}

fn migrate_account(
    row: &AccountRow,
    signal_data_dir: &Path,
    engines_root: &Path,
    state_dir: &Path,
    dry_run: bool,
    mut journal: Option<&mut Journal>,
) -> Result<MigrationEntry, StoreError> {
    if !is_account_id(&row.id) {
        return Err(pool_invalid(format!(
            "account {} has no opaque pool id and cannot name an engine directory",
            row.id
        )));
    }
    let legacy_dir = legacy_group_dir(signal_data_dir, &row.proxy_group)?;
    let target_dir = engines_root.join(&row.id);
    let target_state_path = target_dir.join(STATE_FILE);
    let target_state = read_state_lenient(&target_state_path)?;
    let target_store = target_state.as_ref().and_then(|state| {
        state
            .accounts
            .iter()
            .find(|entry| entry.number == row.signal_account)
            .and_then(|entry| entry.dir.as_deref())
            .map(|dir| (dir.to_string(), account_store_path(&target_dir, dir)))
    });
    let target_complete = target_store
        .as_ref()
        .is_some_and(|(_, store_path)| store_path.join(STORE_DB_FILE).is_file());

    let legacy_state_path = legacy_dir.join(STATE_FILE);
    let legacy_state = read_state_lenient(&legacy_state_path)?;
    let legacy_entry = legacy_state.as_ref().and_then(|state| {
        state
            .accounts
            .iter()
            .find(|entry| entry.number == row.signal_account)
            .cloned()
    });

    if target_complete {
        // Two live copies of one account's credentials: the target is complete
        // and the legacy side still has its own store. Choosing the target
        // would silently strand a readable credential copy, so this is an
        // operator decision, never a startup guess (contract revision 1.288,
        // §4.274 — the same ambiguity the registry refuses on a mixed layout).
        if legacy_store_present(&legacy_dir, &legacy_entry) {
            return Err(pool_invalid(format!(
                "account {} has two copies of its store (legacy and engine slot); refusing to choose one",
                row.id
            )));
        }
        // Crash window (c) / a previous run: the target is authoritative.
        // Repair a source registry that still lists the moved account (the
        // store itself is gone, so only metadata converges).
        if legacy_entry.is_some() {
            journal_record(
                &mut journal,
                "sourceRegistry",
                Some(&row.id),
                Some(&row.proxy_group),
                if dry_run {
                    "wouldRewrite"
                } else {
                    "rewriteStale"
                },
            );
            if !dry_run {
                remove_legacy_entry(&legacy_state_path, &row.signal_account)?;
            }
        }
        journal_record(
            &mut journal,
            "verify",
            Some(&row.id),
            Some(&row.proxy_group),
            "alreadyMigrated",
        );
        return Ok(MigrationEntry {
            account_id: row.id.clone(),
            proxy_group: row.proxy_group.clone(),
            action: "alreadyMigrated".to_string(),
            outcome: None,
        });
    }

    if let Some(state) = &target_state
        && state
            .accounts
            .iter()
            .any(|entry| entry.number != row.signal_account)
    {
        return Err(pool_invalid(format!(
            "engine slot {} already belongs to a different account; refusing to overwrite it",
            row.id
        )));
    }
    if target_state.is_some() {
        // A target registry exists but does not point at a present store. If
        // the legacy side still owns it, the move is resumable; anything else
        // is a state we cannot prove safe.
        if target_store.is_some() && !legacy_store_present(&legacy_dir, &legacy_entry) {
            return Err(pool_invalid(format!(
                "engine slot {} has a registry entry without a store and no legacy source",
                row.id
            )));
        }
    } else if target_dir.exists() {
        // An empty directory is legal (a rolled-back provision); anything
        // else (files, a partial store) must be inspected, never overwritten.
        let mut entries = fs::read_dir(&target_dir).map_err(pool_invalid_io)?;
        if entries.next().is_some() {
            return Err(pool_invalid(format!(
                "engine slot {} exists without a registry and cannot be adopted safely",
                row.id
            )));
        }
    }

    let Some(entry) = legacy_entry else {
        // A store row with no legacy data and no target slot has no credentials
        // to move. Blocking every healthy account on such an orphan turns one
        // stale row into a total outage; keep it unprovisioned so addressed
        // requests answer ENGINE_NOT_PROVISIONED while the rest of the pool
        // serves normally. Unsafe cases (target registry present but empty)
        // were rejected above.
        journal_record(
            &mut journal,
            "plan",
            Some(&row.id),
            Some(&row.proxy_group),
            if dry_run {
                "wouldUnprovision"
            } else {
                "unprovisioned"
            },
        );
        return Ok(MigrationEntry {
            account_id: row.id.clone(),
            proxy_group: row.proxy_group.clone(),
            action: "unprovisioned".to_string(),
            outcome: None,
        });
    };
    let Some(relative) = entry.dir.as_deref() else {
        return Err(pool_invalid(format!(
            "account {} has no presage store directory in its legacy registry",
            row.id
        )));
    };
    let store_name = validated_store_component(relative)?;
    let legacy_store = legacy_dir.join(ACCOUNTS_DIR).join(&store_name);
    let target_store_path = target_dir.join(ACCOUNTS_DIR).join(&store_name);
    let legacy_has_store = legacy_store.join(STORE_DB_FILE).is_file();
    let target_has_store = target_store_path.join(STORE_DB_FILE).is_file();
    if legacy_has_store && target_has_store {
        return Err(pool_invalid(format!(
            "account {} has two copies of its store (legacy and engine slot); refusing to choose one",
            row.id
        )));
    }
    if !legacy_has_store && !target_has_store {
        return Err(pool_invalid(format!(
            "account {} has a registry entry but no store.db on either side",
            row.id
        )));
    }

    journal_record(
        &mut journal,
        "plan",
        Some(&row.id),
        Some(&row.proxy_group),
        if dry_run { "wouldMigrate" } else { "migrate" },
    );
    if dry_run {
        return Ok(MigrationEntry {
            account_id: row.id.clone(),
            proxy_group: row.proxy_group.clone(),
            action: "wouldMigrate".to_string(),
            outcome: None,
        });
    }

    ensure_private_dir(&target_dir).map_err(pool_invalid_io)?;
    ensure_private_dir(&target_dir.join(ACCOUNTS_DIR)).map_err(pool_invalid_io)?;
    // (1) Target registry first: a crash from here on leaves a resumable
    // "registry without store" (the next run still sees the legacy store and
    // performs the move), never a store without a registry.
    let target_entries = vec![AccountEntry {
        number: row.signal_account.clone(),
        dir: Some(relative.to_string()),
    }];
    write_state(&target_dir, &target_entries).map_err(pool_invalid_io)?;
    journal_record(
        &mut journal,
        "targetRegistry",
        Some(&row.id),
        Some(&row.proxy_group),
        "written",
    );

    // (2) Move the store. rename(2) is atomic and same-volume by
    // construction here (both paths live under --signal-data-dir).
    if !target_has_store {
        match fs::rename(&legacy_store, &target_store_path) {
            Ok(()) => {}
            Err(error) => {
                let _ = fs::remove_file(target_dir.join(STATE_FILE));
                return Err(pool_invalid_io(error));
            }
        }
        if !target_store_path.join(STORE_DB_FILE).is_file() {
            return Err(pool_invalid(format!(
                "account {} store move did not land",
                row.id
            )));
        }
    }
    journal_record(
        &mut journal,
        "moveStore",
        Some(&row.id),
        Some(&row.proxy_group),
        "renamed",
    );

    // (3) Source registry convergence: the legacy engine must no longer see
    // an account whose store left its directory.
    remove_legacy_entry(&legacy_state_path, &row.signal_account)?;
    journal_record(
        &mut journal,
        "sourceRegistry",
        Some(&row.id),
        Some(&row.proxy_group),
        "rewritten",
    );

    // (4) Verify before declaring success.
    let verified_state = read_state_strict(&target_dir.join(STATE_FILE))?;
    let verified = verified_state
        .accounts
        .iter()
        .filter(|entry| entry.number == row.signal_account)
        .count();
    if verified != 1 || !target_store_path.join(STORE_DB_FILE).is_file() {
        return Err(pool_invalid(format!(
            "account {} migration verification failed",
            row.id
        )));
    }
    journal_record(
        &mut journal,
        "verified",
        Some(&row.id),
        Some(&row.proxy_group),
        "ok",
    );
    // Record the provisioning sidecar for crash-window discovery symmetry.
    // Best-effort: the store row is authoritative for a migrated account.
    let _ = state_dir;
    Ok(MigrationEntry {
        account_id: row.id.clone(),
        proxy_group: row.proxy_group.clone(),
        action: "migrated".to_string(),
        outcome: None,
    })
}

/// Empty engine directories with no account row and no credentials are
/// rolled-back link leftovers: remove them (dry-run: report only). Anything
/// that still carries a registry account or a store aborts fail-closed — the
/// pool must never start with an unaccounted-for credential directory.
fn reconcile_orphans(
    rows: &[AccountRow],
    engines_root: &Path,
    dry_run: bool,
    mut journal: Option<&mut Journal>,
    report: &mut MigrationReport,
) -> Result<(), StoreError> {
    let known: std::collections::HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    let entries = match fs::read_dir(engines_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(pool_invalid_io(error)),
    };
    for entry in entries {
        let entry = entry.map_err(pool_invalid_io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_account_id(&name) || known.contains(name.as_str()) {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type().map_err(pool_invalid_io)?;
        if !file_type.is_dir() {
            continue;
        }
        let state = read_state_lenient(&path.join(STATE_FILE))?;
        let has_accounts = state
            .as_ref()
            .is_some_and(|state| !state.accounts.is_empty());
        let has_store = account_store_dirs(&path)
            .map_err(pool_invalid_io)?
            .is_some();
        if has_accounts || has_store {
            // 无账号行的槽不可服务；隔离而不是拒绝启动：留下字节可审计，
            // 但不让它挡住整个连接器（放弃的 link 尝试会留下这种槽）。
            if !dry_run {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                let target = engines_root.join(format!(".quarantine-{name}-{stamp}"));
                if let Err(error) = fs::rename(&path, &target) {
                    return Err(pool_invalid_io(error));
                }
                report.entries.push(MigrationEntry {
                    account_id: name.clone(),
                    proxy_group: String::new(),
                    action: "quarantine".to_string(),
                    outcome: Some("quarantined".to_string()),
                });
                tracing::warn!(
                    target: "connector.pool",
                    // The invariant witness: a slot that holds credentials
                    // while the store has no row for its id is a leaked
                    // link-attempt slot. The quarantine below is the startup
                    // backstop; the live reclaim path runs the same invariant
                    // name through `AccountPool::reclaim_link_attempt`.
                    invariant = crate::pool::LINK_SLOT_LEAK_INVARIANT,
                    stage = "orphan_slot_quarantined",
                    slot = %name,
                    has_accounts,
                    has_store,
                    "engine slot has credentials but no account row; quarantined"
                );
                continue;
            }
            report.entries.push(MigrationEntry {
                account_id: name,
                proxy_group: String::new(),
                action: "quarantine".to_string(),
                outcome: Some("would-continue".to_string()),
            });
            continue;
        }
        if dry_run {
            report.entries.push(MigrationEntry {
                account_id: name,
                proxy_group: String::new(),
                action: "wouldRemoveOrphan".to_string(),
                outcome: None,
            });
            continue;
        }
        fs::remove_dir_all(&path).map_err(pool_invalid_io)?;
        journal_record(&mut journal, "orphan", Some(&name), None, "removed");
        report.orphans_removed += 1;
        report.entries.push(MigrationEntry {
            account_id: name,
            proxy_group: String::new(),
            action: "removedOrphan".to_string(),
            outcome: None,
        });
    }
    Ok(())
}

fn legacy_group_dir(root: &Path, proxy_group: &str) -> Result<PathBuf, StoreError> {
    if proxy_group == DEFAULT_PROXY_GROUP_ID {
        return Ok(root.to_path_buf());
    }
    if !is_valid_group_id(proxy_group) {
        return Err(pool_invalid(format!(
            "account binding names an invalid proxy group {proxy_group:?}"
        )));
    }
    Ok(root.join("proxy-groups").join(proxy_group))
}

/// The legacy registry's `dir` value must be a plain `accounts/lk-<hex>`
/// relative path. Anything else (absolute, `..`, symlink-shaped) is refused
/// rather than followed.
fn validated_store_component(relative: &str) -> Result<String, StoreError> {
    let path = Path::new(relative);
    let components: Vec<Component<'_>> = path.components().collect();
    if components.len() != 2 {
        return Err(pool_invalid(
            "legacy registry store directory is not a plain accounts/<dir> path".to_string(),
        ));
    }
    if components[0] != Component::Normal(ACCOUNTS_DIR.as_ref()) {
        return Err(pool_invalid(
            "legacy registry store directory is outside accounts/".to_string(),
        ));
    }
    let Component::Normal(name) = components[1] else {
        return Err(pool_invalid(
            "legacy registry store directory is malformed".to_string(),
        ));
    };
    let name = name.to_string_lossy().into_owned();
    if !name.starts_with("lk-")
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        return Err(pool_invalid(
            "legacy registry store directory name is not lk-<opaque>".to_string(),
        ));
    }
    Ok(name)
}

fn account_store_path(root: &Path, relative: &str) -> PathBuf {
    root.join(relative)
}

fn legacy_store_present(legacy_dir: &Path, entry: &Option<AccountEntry>) -> bool {
    entry
        .as_ref()
        .and_then(|entry| entry.dir.as_deref())
        .is_some_and(|dir| {
            legacy_dir
                .join(ACCOUNTS_DIR)
                .join(Path::new(dir).file_name().unwrap_or_default())
                .join(STORE_DB_FILE)
                .is_file()
        })
}

fn account_store_dirs(root: &Path) -> io::Result<Option<PathBuf>> {
    let accounts = root.join(ACCOUNTS_DIR);
    let entries = match fs::read_dir(&accounts) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("lk-") && entry.path().join(STORE_DB_FILE).is_file() {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn read_state_lenient(path: &Path) -> Result<Option<PersistedState>, StoreError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            if metadata.len() > MAX_STATE_BYTES {
                return Err(pool_invalid(format!(
                    "engine registry at {} is larger than the {MAX_STATE_BYTES}-byte bound",
                    path.file_name().unwrap_or_default().to_string_lossy()
                )));
            }
            read_state_strict(path).map(Some)
        }
        Ok(_) => Err(pool_invalid(
            "engine registry path exists but is not a file".to_string(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(pool_invalid_io(error)),
    }
}

fn read_state_strict(path: &Path) -> Result<PersistedState, StoreError> {
    let bytes = fs::read(path).map_err(pool_invalid_io)?;
    let state: PersistedState = serde_json::from_slice(&bytes)
        .map_err(|_| pool_invalid("engine registry is corrupt; refusing to migrate".to_string()))?;
    if state.version != STATE_VERSION {
        return Err(pool_invalid(format!(
            "engine registry version {} is unsupported (expected {STATE_VERSION}); refusing to migrate",
            state.version
        )));
    }
    if state.accounts.len() > 64 {
        return Err(pool_invalid(
            "engine registry names more accounts than any legal data directory".to_string(),
        ));
    }
    Ok(state)
}

fn write_state(dir: &Path, accounts: &[AccountEntry]) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(&PersistedState {
        version: STATE_VERSION,
        accounts: accounts.to_vec(),
    })
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "serialize"))?;
    let target = dir.join(STATE_FILE);
    let temp = dir.join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
    fs::write(&temp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    }
    if let Err(error) = fs::rename(&temp, &target) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

/// Remove one number's entry from a legacy registry, preserving every other
/// entry. A missing or already-clean source is a no-op (idempotent resume).
fn remove_legacy_entry(path: &Path, number: &str) -> Result<(), StoreError> {
    let Some(mut state) = read_state_lenient(path)? else {
        return Ok(());
    };
    let before = state.accounts.len();
    state.accounts.retain(|entry| entry.number != number);
    if state.accounts.len() == before {
        return Ok(());
    }
    write_state(
        path.parent()
            .ok_or_else(|| pool_invalid("legacy registry has no parent directory".to_string()))?,
        &state.accounts,
    )
    .map_err(pool_invalid_io)
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn pool_invalid(message: String) -> StoreError {
    StoreError::EnginePoolInvalid(message)
}

fn pool_invalid_io(error: io::Error) -> StoreError {
    StoreError::EnginePoolInvalid(format!("io: {}", error.kind()))
}

struct Journal {
    file: fs::File,
}

impl Journal {
    fn open(signal_data_dir: &Path) -> io::Result<Self> {
        let dir = signal_data_dir.join(MIGRATION_DIR);
        ensure_private_dir(&dir)?;
        // Bound the audit trail: keep the newest 19 runs plus this one. Each
        // pool-mode startup writes a journal even when there is nothing to
        // move, and an unbounded directory of tiny files is still unbounded.
        if let Ok(entries) = fs::read_dir(&dir) {
            let mut journals: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "jsonl")
                })
                .collect();
            journals.sort();
            let excess = journals.len().saturating_sub(19);
            for path in journals.into_iter().take(excess) {
                let _ = fs::remove_file(path);
            }
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or_default();
        let path = dir.join(format!("{stamp}-{}.jsonl", std::process::id()));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { file })
    }

    fn record(
        &mut self,
        step: &str,
        account_id: Option<&str>,
        proxy_group: Option<&str>,
        status: &str,
    ) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or_default();
        let mut object = serde_json::Map::new();
        object.insert("ts".into(), serde_json::json!(stamp));
        object.insert("step".into(), serde_json::json!(step));
        object.insert("status".into(), serde_json::json!(status));
        if let Some(account_id) = account_id {
            object.insert("accountId".into(), serde_json::json!(account_id));
        }
        if let Some(proxy_group) = proxy_group {
            object.insert("groupId".into(), serde_json::json!(proxy_group));
        }
        let line = serde_json::Value::Object(object).to_string();
        let _ = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.write_all(b"\n"));
    }
}

fn journal_record(
    journal: &mut Option<&mut Journal>,
    step: &str,
    account_id: Option<&str>,
    proxy_group: Option<&str>,
    status: &str,
) {
    if let Some(journal) = journal.as_mut() {
        journal.record(step, account_id, proxy_group, status);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::store::StoreKey;

    fn test_store(state_dir: &Path) -> Store {
        Store::open(state_dir, Some(StoreKey::from_bytes([0x5A; 32]))).unwrap()
    }

    fn account_id(index: u8) -> String {
        format!("{index:032x}")
    }

    fn seed_legacy(
        root: &Path,
        store: &Store,
        group: &str,
        id: &str,
        number: &str,
        store_name: &str,
    ) {
        store
            .upsert_account_from_signal_with_id(number, Some(1), group, Some(id))
            .unwrap();
        let data_dir = if group == DEFAULT_PROXY_GROUP_ID {
            root.to_path_buf()
        } else {
            root.join("proxy-groups").join(group)
        };
        let store_dir = data_dir.join(ACCOUNTS_DIR).join(store_name);
        fs::create_dir_all(&store_dir).unwrap();
        fs::write(store_dir.join(STORE_DB_FILE), b"fixture-store").unwrap();
        let state_path = data_dir.join(STATE_FILE);
        let mut state: serde_json::Value = fs::read(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| json!({"version": 2, "accounts": []}));
        state["accounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"number": number, "dir": format!("accounts/{store_name}")}));
        fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    }

    /// The dry run reports exactly the actions the applied pass performs, and
    /// the applied pass moves (never copies) each store into its own slot.
    #[test]
    fn dry_run_matches_apply_and_moves_stores_without_copying() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        seed_legacy(
            &root,
            &store,
            DEFAULT_PROXY_GROUP_ID,
            &account_id(1),
            "+15550000001",
            "lk-one",
        );
        seed_legacy(
            &root,
            &store,
            "team-b",
            &account_id(2),
            "+15550000002",
            "lk-two",
        );

        let dry = run(&store, &root, &state_dir, true, 8).unwrap();
        assert_eq!(dry.migrated, 0);
        assert_eq!(dry.already_migrated, 0);
        assert_eq!(dry.entries.len(), 2);
        assert!(
            dry.entries
                .iter()
                .all(|entry| entry.action == "wouldMigrate")
        );
        assert!(
            !root.join(ENGINE_SLOT_SUBDIR).exists(),
            "a dry run must not create engine directories"
        );
        assert!(
            root.join(ACCOUNTS_DIR)
                .join("lk-one")
                .join(STORE_DB_FILE)
                .is_file(),
            "a dry run must not move stores"
        );

        let applied = run(&store, &root, &state_dir, false, 8).unwrap();
        assert_eq!(applied.migrated, 2);
        assert_eq!(applied.already_migrated, 0);
        let actions: Vec<&str> = applied
            .entries
            .iter()
            .map(|entry| entry.action.as_str())
            .collect();
        assert_eq!(actions, ["migrated", "migrated"]);

        for (id, number, store_name) in [
            (account_id(1), "+15550000001", "lk-one"),
            (account_id(2), "+15550000002", "lk-two"),
        ] {
            let slot = root.join(ENGINE_SLOT_SUBDIR).join(&id);
            assert!(slot.join(STATE_FILE).is_file());
            assert!(
                slot.join(ACCOUNTS_DIR)
                    .join(store_name)
                    .join(STORE_DB_FILE)
                    .is_file()
            );
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(slot.join(STATE_FILE)).unwrap()).unwrap();
            assert_eq!(state["version"], 2);
            assert_eq!(state["accounts"].as_array().unwrap().len(), 1);
            assert_eq!(state["accounts"][0]["number"], number);
            // No copy left behind in the legacy directory.
            let legacy = if store_name == "lk-one" {
                root.clone()
            } else {
                root.join("proxy-groups").join("team-b")
            };
            assert!(!legacy.join(ACCOUNTS_DIR).join(store_name).exists());
            let legacy_state: serde_json::Value =
                serde_json::from_slice(&fs::read(legacy.join(STATE_FILE)).unwrap()).unwrap();
            assert!(
                legacy_state["accounts"].as_array().unwrap().is_empty(),
                "the legacy registry converges to an empty shell"
            );
        }

        // Re-running is idempotent and reports the complete targets.
        let again = run(&store, &root, &state_dir, false, 8).unwrap();
        assert_eq!(again.migrated, 0);
        assert_eq!(again.already_migrated, 2);

        // Every run writes its own journal. The union covers the applied
        // pass (the dry run writes none, per the no-mutation contract).
        let journal_dir = root.join(MIGRATION_DIR);
        let journals: Vec<String> = fs::read_dir(&journal_dir)
            .unwrap()
            .flatten()
            .map(|entry| fs::read_to_string(entry.path()).unwrap())
            .collect();
        assert_eq!(journals.len(), 2, "apply + idempotent re-run journals");
        let journal = journals.join("\n");
        for step in [
            "plan",
            "targetRegistry",
            "moveStore",
            "sourceRegistry",
            "verified",
        ] {
            assert!(journal.contains(step), "journal missing step {step}");
        }
        assert!(!journal.contains("+1555"), "journal must not carry numbers");
    }

    /// Crash window: the target registry landed but the store did not move.
    /// The next pass resumes the move instead of failing or duplicating it.
    #[test]
    fn resumes_after_a_crash_between_the_target_registry_and_the_move() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        let id = account_id(3);
        seed_legacy(
            &root,
            &store,
            DEFAULT_PROXY_GROUP_ID,
            &id,
            "+15550000003",
            "lk-three",
        );
        // Simulate the crash: the target registry was written, the store was
        // not moved yet.
        let slot = root.join(ENGINE_SLOT_SUBDIR).join(&id);
        fs::create_dir_all(slot.join(ACCOUNTS_DIR)).unwrap();
        fs::write(
            slot.join(STATE_FILE),
            serde_json::to_vec_pretty(&json!({
                "version": 2,
                "accounts": [{"number": "+15550000003", "dir": "accounts/lk-three"}],
            }))
            .unwrap(),
        )
        .unwrap();

        let report = run(&store, &root, &state_dir, false, 8).unwrap();
        assert_eq!(report.migrated, 1);
        assert!(
            slot.join(ACCOUNTS_DIR)
                .join("lk-three")
                .join(STORE_DB_FILE)
                .is_file(),
            "the resumed pass performs the move"
        );
        assert!(!root.join(ACCOUNTS_DIR).join("lk-three").exists());
    }

    /// A copied (not moved) store leaves two credential copies. The migration
    /// refuses to choose one and fails closed.
    #[test]
    fn refuses_two_copies_of_the_same_store() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        let id = account_id(4);
        seed_legacy(
            &root,
            &store,
            DEFAULT_PROXY_GROUP_ID,
            &id,
            "+15550000004",
            "lk-four",
        );
        let copied = root
            .join(ENGINE_SLOT_SUBDIR)
            .join(&id)
            .join(ACCOUNTS_DIR)
            .join("lk-four");
        fs::create_dir_all(&copied).unwrap();
        fs::write(copied.join(STORE_DB_FILE), b"copied").unwrap();

        let error = run(&store, &root, &state_dir, false, 8).unwrap_err();
        assert!(
            matches!(error, StoreError::EnginePoolInvalid(_)),
            "{error:?}"
        );
        assert!(
            root.join(ACCOUNTS_DIR)
                .join("lk-four")
                .join(STORE_DB_FILE)
                .is_file(),
            "fail closed must leave both copies intact"
        );
    }

    #[test]
    fn store_row_without_any_engine_data_is_unprovisioned_not_fatal() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        let id = account_id(8);
        store
            .upsert_account_from_signal_with_id(
                "+15550000008",
                Some(1),
                DEFAULT_PROXY_GROUP_ID,
                Some(&id),
            )
            .unwrap();

        let report = run(&store, &root, &state_dir, false, 8).expect("orphan row is not fatal");
        assert_eq!(report.unprovisioned, 1);
        assert_eq!(report.migrated, 0);
        assert!(!root.join(ENGINE_SLOT_SUBDIR).join(id).exists());
    }

    #[test]
    fn refuses_a_corrupt_legacy_registry() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        store
            .upsert_account_from_signal_with_id(
                "+15550000005",
                Some(1),
                DEFAULT_PROXY_GROUP_ID,
                Some(&account_id(5)),
            )
            .unwrap();
        fs::write(root.join(STATE_FILE), b"{not json").unwrap();
        let error = run(&store, &root, &state_dir, false, 8).unwrap_err();
        assert!(
            matches!(error, StoreError::EnginePoolInvalid(_)),
            "{error:?}"
        );
    }

    /// Empty engine directories are rolled-back link leftovers and are
    /// removed; a directory that still carries credentials with no account
    /// row is a leaked link-attempt slot and is quarantined (bytes stay
    /// auditable, never a live slot) instead of blocking startup.
    #[test]
    fn dry_run_reports_the_same_quarantine_it_would_apply() {
        // 双向诚实（11-11 dry-run 谎报案立的规矩）：apply 会隔离后继续，
        // dry-run 必须报同一件事，不能用 Err 把人吓退。
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        let orphan = root.join(ENGINE_SLOT_SUBDIR).join(account_id(8));
        fs::create_dir_all(orphan.join(ACCOUNTS_DIR).join("lk-eight")).unwrap();
        fs::write(
            orphan
                .join(ACCOUNTS_DIR)
                .join("lk-eight")
                .join(STORE_DB_FILE),
            b"credentials",
        )
        .unwrap();
        fs::write(
            orphan.join(STATE_FILE),
            serde_json::to_vec_pretty(&json!({
                "version": 2,
                "accounts": [{"number": "+15550000008", "dir": "accounts/lk-eight"}],
            }))
            .unwrap(),
        )
        .unwrap();

        let report = run(&store, &root, &state_dir, true, 8)
            .expect("a dry run must not turn a recoverable quarantine into an error");
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.account_id == account_id(8))
            .expect("the leaked slot appears in the dry-run plan");
        assert_eq!(entry.action, "quarantine");
        assert_eq!(entry.outcome.as_deref(), Some("would-continue"));
        assert!(orphan.exists(), "a dry run never moves bytes");

        let applied =
            run(&store, &root, &state_dir, false, 8).expect("apply quarantines and continues");
        let applied_entry = applied
            .entries
            .iter()
            .find(|entry| entry.account_id == account_id(8))
            .expect("apply reports the quarantine too");
        assert_eq!(applied_entry.action, "quarantine");
        assert_eq!(applied_entry.outcome.as_deref(), Some("quarantined"));
        assert!(!orphan.exists());
    }

    #[test]
    fn removes_empty_orphans_and_quarantines_orphan_credentials() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        let empty = root.join(ENGINE_SLOT_SUBDIR).join(account_id(6));
        fs::create_dir_all(&empty).unwrap();
        let report = run(&store, &root, &state_dir, false, 8).unwrap();
        assert_eq!(report.orphans_removed, 1);
        assert!(!empty.exists());

        let orphan = root.join(ENGINE_SLOT_SUBDIR).join(account_id(7));
        fs::create_dir_all(orphan.join(ACCOUNTS_DIR).join("lk-seven")).unwrap();
        fs::write(
            orphan
                .join(ACCOUNTS_DIR)
                .join("lk-seven")
                .join(STORE_DB_FILE),
            b"credentials",
        )
        .unwrap();
        fs::write(
            orphan.join(STATE_FILE),
            serde_json::to_vec_pretty(&json!({
                "version": 2,
                "accounts": [{"number": "+15550000007", "dir": "accounts/lk-seven"}],
            }))
            .unwrap(),
        )
        .unwrap();
        let report =
            run(&store, &root, &state_dir, false, 8).expect("a leaked slot is quarantined");
        assert_eq!(
            report.orphans_removed, 0,
            "the second pass removes no empty orphan; the credential slot is quarantined"
        );
        assert!(
            !orphan.exists(),
            "the credential-bearing slot must leave the live namespace"
        );
        let quarantine: Vec<_> = fs::read_dir(root.join(ENGINE_SLOT_SUBDIR))
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".quarantine-{}", account_id(7)))
            })
            .collect();
        assert_eq!(quarantine.len(), 1, "exactly one quarantine entry");
        assert!(
            quarantine[0].path().join(STATE_FILE).is_file(),
            "credentials stay auditable in the quarantine"
        );
    }

    /// P1 runtime isolation (§4.274): the layout scan is the single read-only
    /// observation behind both the startup refusal and the CLI plan.
    #[test]
    fn layout_scan_names_legacy_pooled_and_mixed_states() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        assert_eq!(
            scan_engine_layout(&root).unwrap().kind(),
            EngineLayoutKind::Empty
        );

        seed_legacy(
            &root,
            &store,
            DEFAULT_PROXY_GROUP_ID,
            &account_id(1),
            "+15550000021",
            "lk-one",
        );
        let legacy = scan_engine_layout(&root).unwrap();
        assert_eq!(legacy.legacy_accounts, 1);
        assert_eq!(legacy.pooled_accounts(), 0);
        assert_eq!(legacy.kind(), EngineLayoutKind::Legacy);
        assert!(!legacy.is_mixed());

        // A second account already lives in its own engine slot: both layouts
        // hold credentials, which is the state the connector refuses to guess.
        let id = account_id(2);
        store
            .upsert_account_from_signal_with_id(
                "+15550000022",
                Some(1),
                DEFAULT_PROXY_GROUP_ID,
                Some(&id),
            )
            .unwrap();
        let slot = root.join(ENGINE_SLOT_SUBDIR).join(&id);
        fs::create_dir_all(slot.join(ACCOUNTS_DIR).join("lk-two")).unwrap();
        fs::write(
            slot.join(ACCOUNTS_DIR).join("lk-two").join(STORE_DB_FILE),
            b"pooled",
        )
        .unwrap();
        fs::write(
            slot.join(STATE_FILE),
            serde_json::to_vec(&json!({
                "version": 2,
                "accounts": [{"number": "+15550000022", "dir": "accounts/lk-two"}],
            }))
            .unwrap(),
        )
        .unwrap();
        let mixed = scan_engine_layout(&root).unwrap();
        assert_eq!(mixed.kind(), EngineLayoutKind::Mixed);
        // The pool-only state is its own layout, credentials or not.
        let pool_only_root = temp.path().join("pool-only");
        let pool_only_slot = pool_only_root.join(ENGINE_SLOT_SUBDIR).join(&id);
        fs::create_dir_all(&pool_only_slot).unwrap();
        fs::write(
            pool_only_slot.join(STATE_FILE),
            serde_json::to_vec(&json!({"version": 2, "accounts": []})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            scan_engine_layout(&pool_only_root).unwrap().kind(),
            EngineLayoutKind::Pooled
        );
        assert_eq!(mixed.pooled_accounts(), 1);
        assert!(mixed.multi_account_slot().is_none());

        // The guard reads the registry count, not the store count: a slot that
        // names a second account without a store is still a violation.
        fs::write(
            slot.join(STATE_FILE),
            serde_json::to_vec(&json!({
                "version": 2,
                "accounts": [
                    {"number": "+15550000022", "dir": "accounts/lk-two"},
                    {"number": "+15550000023", "dir": "accounts/lk-three"},
                ],
            }))
            .unwrap(),
        )
        .unwrap();
        let violation = scan_engine_layout(&root).unwrap();
        assert_eq!(
            violation
                .multi_account_slot()
                .map(|slot| slot.registry_accounts),
            Some(2)
        );
    }

    /// P1 runtime isolation (§4.274): the dry-run report is the operator's
    /// checklist — layout, account count, the resident/cold split of the next
    /// pooled boot, the expected exit code, and the next commands — and it is
    /// produced without writing a byte under the signal data directory.
    #[test]
    fn the_dry_run_plan_carries_the_counts_the_next_boot_will_see() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("signal-data");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        let store = test_store(&state_dir);
        for index in 1..=3u8 {
            seed_legacy(
                &root,
                &store,
                DEFAULT_PROXY_GROUP_ID,
                &account_id(index),
                &format!("+155500001{index:02}"),
                &format!("lk-plan-{index}"),
            );
        }
        let before = tree_snapshot(&root);

        let dry = run(&store, &root, &state_dir, true, 2).unwrap();
        assert_eq!(dry.layout, EngineLayoutKind::Legacy);
        assert_eq!(dry.accounts, 3);
        assert_eq!(dry.entries.len(), 3);
        assert_eq!(dry.resident_cap, 2);
        assert_eq!(dry.resident_on_start, 2);
        assert_eq!(dry.cold_starts, 1);
        assert_eq!(dry.expected_exit_code, 0);
        assert!(dry.blockers.is_empty());
        assert!(
            dry.next_steps
                .iter()
                .any(|step| step.contains("without --dry-run")),
            "{:?}",
            dry.next_steps
        );
        assert!(
            dry.next_steps
                .iter()
                .any(|step| step.contains("--per-account-engines")),
            "{:?}",
            dry.next_steps
        );
        assert_eq!(tree_snapshot(&root), before, "a dry run writes nothing");
        assert!(
            !root.join(MIGRATION_DIR).exists(),
            "no journal for a dry run"
        );

        let applied = run(&store, &root, &state_dir, false, 2).unwrap();
        assert_eq!(applied.layout, EngineLayoutKind::Legacy);
        assert_eq!(applied.migrated, 3);
        assert_eq!(applied.resident_on_start, 2);
        assert_eq!(applied.cold_starts, 1);
        assert_eq!(applied.expected_exit_code, 0);
    }

    /// Every byte the connector could create in the signal data directory:
    /// a dry run must leave this list identical.
    fn tree_snapshot(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        let mut entries = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    entries.push((relative, None));
                    stack.push(path);
                } else {
                    entries.push((relative, Some(fs::read(&path).unwrap())));
                }
            }
        }
        entries.sort();
        entries
    }
}
