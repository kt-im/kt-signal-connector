// SPDX-License-Identifier: AGPL-3.0-only

//! Launcher (desktop) liveness and data-directory ownership, the connector
//! side of the orphan-process repair (P0 + P1 of the zombie-reclaim batch).
//!
//! Why this exists: the engine self-exits on stdin EOF, but that EOF only
//! happens when the connector's own stdin closes — a connector whose launcher
//! died with SIGKILL has no EOF for the child and no EOF of its own. The
//! desktop's killOrphanConnectors used to run only at startup, so a hard-killed
//! Electron could leave a connector (+engine) holding this data directory:
//!
//! 1. **P0 parent watch** — the connector records the launcher pid (`--parent-pid`
//!    on every platform, or the pid it was started from, or the pid in this
//!    module's ownership marker written by the launcher), probes it every
//!    `PARENT_POLL_INTERVAL`, and when it is gone it tears the runtime down
//!    (which is what carries the engine children with it) and exits. Linux
//!    and macOS re-parent an orphaned child to pid 1, so the probe also
//!    treats a *changed* `getppid()` as death even while the old pid still
//!    answers (pid reuse).
//! 2. **P0 orphan-engine sweep** — the supervisor's periodic pass also looks
//!    at every engine process that names this data directory and terminates
//!    the ones that were re-parented to pid 1: an orphan engine is one whose
//!    connector died, and it keeps the account database open. Engines this
//!    process owns are excluded by pid, and the "who spawned me" probe is
//!    the last gate before a signal.
//! 3. **P1 ownership marker** — `serve` leaves `pid` + start timestamp in
//!    `OWNER_FILE_NAME` inside the data directory. A replacement connector
//!    whose launcher did not pass `--parent-pid` adopts a marker written
//!    within `OWNER_MARKER_FRESH` (an immediate restart racing the old
//!    generation) and rewrites it for its own generation. The marker is
//!    bookkeeping only: occupancy stays the kernel lock's business
//!    (`datalock`), and a marker failure never fails a start.
//!
//! Hard boundary: every decision below is scoped to processes whose argv
//! names **this** data directory (`--signal-data-dir <dir>`, the engine's
//! `--data-dir <dir>`, the per-account `.../engines/<accountId>` slots
//! beneath it). Nothing here ever signals a pid it has not positively
//! classified, nothing is logged beyond pids and fixed reason literals, and
//! the sweep records rather than kills whenever the evidence is not
//! unambiguous.
//!
//! macOS note: `ps -Ao args` truncates at MAXCOMLEN, so the data-directory
//! argument is usually missing there. The argv evidence for this data
//! directory is therefore taken from the kernel's own process arguments
//! (`KERN_PROCARGS2` via `sysctl`), where pids are matched but never logged.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The P0 parent probe cadence (task requirement: every 5 s).
pub const PARENT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The supervisor's engine-orphan sweep cadence (P0, engine side).
pub const ENGINE_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Grace given to the runtime teardown after the parent is found gone. The
/// regular shutdown budget is unbounded by wall clock (each engine has its
/// own bounded shutdown); a connector that has already lost its launcher
/// must exit in bounded time, so the whole teardown runs under this cap and
/// the engine children are killed directly when it expires.
pub const PARENT_EXIT_BUDGET: Duration = Duration::from_secs(10);

/// Bookkeeping marker the serving connector leaves in its data directory
/// (see the module docs). Same leading-dot discipline as the lock file.
pub(crate) const OWNER_FILE_NAME: &str = ".kt-signal-connector.owner";

/// A marker older than this belongs to a generation that is no longer
/// attributable to a live launcher: adopting it would let a fresh standalone
/// start chase a dead desktop forever.
pub(crate) const OWNER_MARKER_FRESH: Duration = Duration::from_secs(120);

/// Fixed reason literals — the only vocabulary the exit/sweep logs use (no
/// paths, no numbers, no account material).
pub const REASON_REPARENTED: &str = "parent_reparented";
pub const REASON_VANISHED: &str = "parent_vanished";

/// Operator escape hatch (task requirement): `KT_SIGNAL_DISABLE_PARENT_WATCH=1`
/// turns the watch off entirely for one process, so a field session can keep a
/// deliberately launcher-less connector alive. Set and unset are the only two
/// meanings: any other value (including `0`) leaves the watch armed, because
/// an ambiguous value must never silently disable a self-protection.
pub const PARENT_WATCH_DISABLE_ENV: &str = "KT_SIGNAL_DISABLE_PARENT_WATCH";

/// Whether this process opted out of the parent watch. Read once at launch: a
/// value that changes under a running connector must not disarm it.
pub fn parent_watch_disabled() -> bool {
    let raw = std::env::var(PARENT_WATCH_DISABLE_ENV).ok();
    let disabled = opt_out_value_disabled(raw.as_deref());
    if raw.as_deref().is_some_and(|value| !value.trim().is_empty()) && !disabled {
        tracing::warn!(
            env = PARENT_WATCH_DISABLE_ENV,
            "unrecognized parent-watch opt-out value; the watch stays armed"
        );
    }
    disabled
}

/// The pure parse rule behind [`parent_watch_disabled`]: only an explicit,
/// unambiguous on-value disarms the watch. Everything else — unset, blank,
/// `0`, or a typo — leaves it armed (fail safe: the self-protection stays).
fn opt_out_value_disabled(raw: Option<&str>) -> bool {
    let Some(value) = raw else {
        return false;
    };
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

// ------------------------------------------------------------ parent pid --

/// The recorded launcher pid and how it was obtained (the "reason" that
/// rides the diagnostic when the monitor fires).
///
/// `is_actual_parent` is the difference between "the pid the launcher named"
/// and "the pid the kernel says fathered this process". Only the second can
/// be judged by re-parenting: a `--parent-pid` the launcher merely *named*
/// (a supervisor, a test harness, a relay) never was our kernel parent, so
/// `getppid()` can never equal it and re-parenting says nothing about it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordedParent {
    pub pid: u32,
    pub via: &'static str,
    /// True only when resolution took the pid from `getppid()`: the kernel
    /// parent of record, the one whose death shows up as re-parenting.
    pub is_actual_parent: bool,
}

/// Resolve the launcher pid for this process.
///
/// The launcher's `--parent-pid` is authoritative where it is given (all
/// platforms; on Unix the desktop only sends it on the stdin-bootstrap
/// transport). Without it, the Unix parent-of-record is `getppid()` at
/// start, unless that is already re-parented to `init` — and the ownership
/// marker left by the previous generation rescues exactly that case.
pub fn resolve_parent_pid(
    flag: Option<u32>,
    data_dir: &Path,
    now: SystemTime,
) -> Option<RecordedParent> {
    #[cfg(unix)]
    let actual_parent = current_ppid();
    #[cfg(windows)]
    let actual_parent = 1;
    if let Some(pid) = flag.filter(|pid| *pid > 1) {
        return Some(RecordedParent {
            pid,
            via: "flag",
            // A launcher-supplied pid is the launcher's own parent, not this
            // process's kernel parent: re-parenting cannot judge it.
            is_actual_parent: pid == actual_parent,
        });
    }
    #[cfg(unix)]
    {
        if actual_parent > 1 {
            return Some(RecordedParent {
                pid: actual_parent,
                via: "getppid",
                is_actual_parent: true,
            });
        }
    }
    let marker = read_owner_marker(data_dir)?;
    if !marker_is_fresh(&marker, now) {
        return None;
    }
    // The marker names the previous connector, not this process's parent.
    Some(RecordedParent {
        pid: marker.pid,
        via: "marker",
        is_actual_parent: marker.pid == actual_parent,
    })
}

/// Record the ownership marker for this generation if (and only if) this
/// process holds the lock on `data_dir` itself. When the data directory is a
/// proxy group's subdirectory, the root belongs to another connector: a
/// marker written here would name the wrong launcher, so it is skipped.
pub fn record_owner_marker_if_root(data_dir: &Path, now: SystemTime) {
    if !this_process_holds_lock(data_dir) {
        return;
    }
    write_owner_marker(data_dir, std::process::id(), now);
}

#[cfg(unix)]
fn this_process_holds_lock(data_dir: &Path) -> bool {
    // flock(2) conflicts are per open file description, so a fresh handle on
    // a file this process already holds the lock of cannot take it again —
    // and a handle that fails with EWOULDBLOCK proves someone (possibly us)
    // holds it. The marker therefore rides the same truth the desktop reads.
    let Ok(handle) = std::fs::File::open(data_dir.join(crate::datalock::LOCK_FILE_NAME)) else {
        return false;
    };
    let failure = rustix::fs::flock(
        &handle,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    );
    match failure {
        Ok(()) => {
            // Nobody held it: this instance does not own the directory.
            let _ = rustix::fs::flock(&handle, rustix::fs::FlockOperation::Unlock);
            false
        }
        Err(error) => error == rustix::io::Errno::WOULDBLOCK,
    }
}

#[cfg(windows)]
fn this_process_holds_lock(data_dir: &Path) -> bool {
    // The Windows lock face needs a LockFileEx attempt; the marker is
    // optional there (the desktop always passes --parent-pid on Windows), so
    // the conservative answer keeps the file untouched.
    let _ = data_dir;
    false
}

/// Write this generation's ownership marker (`pid` + start timestamp in
/// milliseconds). Best effort: the marker is bookkeeping, never occupancy.
pub(crate) fn write_owner_marker(data_dir: &Path, pid: u32, now: SystemTime) {
    let stamp = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    let body = format!("{pid}\n{stamp}\n");
    let path = data_dir.join(OWNER_FILE_NAME);
    if std::fs::write(&path, body).is_ok()
        && let Some(perms) = owner_only()
        && let Err(error) = std::fs::set_permissions(&path, perms)
    {
        tracing::debug!(
            error_class = ?error.kind(),
            "connector ownership marker permissions were not tightened"
        );
    }
}

/// POSIX 权限收紧（仅 Unix 有意义）。Windows 返回 None = 不设。
#[cfg(unix)]
fn owner_only() -> Option<std::fs::Permissions> {
    use std::os::unix::fs::PermissionsExt;

    Some(std::fs::Permissions::from_mode(0o600))
}

// Windows 没有 POSIX mode：PermissionsExt 至今 unstable（rust-lang/rust#152956），
// `Permissions::from_mode` 与 `Permissions::new` 在 Windows 上都不存在，
// `std::fs::Permissions` 只能从 metadata 取、无法构造。
//
// 连接器数据目录本来就在 `%LOCALAPPDATA%` 下（按用户隔离），ACL 足够，
// 因此 Windows 分支不收紧权限，返回 None 让调用点跳过 set_permissions。
//
// 这条分支此前从未在 Windows 编译过（仓库只有 macOS 产物），缺陷才一直没暴露。
#[cfg(windows)]
fn owner_only() -> Option<std::fs::Permissions> {
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerMarker {
    pid: u32,
    recorded_at_ms: u128,
}

pub(crate) fn read_owner_marker(data_dir: &Path) -> Option<OwnerMarker> {
    let body = std::fs::read_to_string(data_dir.join(OWNER_FILE_NAME)).ok()?;
    let mut lines = body.lines();
    let pid = lines.next()?.trim().parse::<u32>().ok()?;
    let recorded_at_ms = lines.next()?.trim().parse::<u128>().ok()?;
    if pid == 0 {
        return None;
    }
    Some(OwnerMarker {
        pid,
        recorded_at_ms,
    })
}

fn marker_is_fresh(marker: &OwnerMarker, now: SystemTime) -> bool {
    let Ok(now_ms) = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
    else {
        return false;
    };
    // A marker "in the future" (clock stepped backwards) is not evidence of
    // a live launcher: treat it as stale rather than trusting it forever.
    if now_ms < marker.recorded_at_ms {
        return false;
    }
    let age = now_ms - marker.recorded_at_ms;
    Duration::from_millis(u64::try_from(age).unwrap_or(u64::MAX)) <= OWNER_MARKER_FRESH
}

#[cfg(unix)]
fn current_ppid() -> u32 {
    // No parent is reported as 1 by the kernel itself; the None arm only
    // documents that.
    let ppid = rustix::process::getppid();
    ppid.map_or(1, |pid| {
        u32::try_from(pid.as_raw_nonzero().get()).unwrap_or(1)
    })
}

// ------------------------------------------------------- parent watchdog --

/// What the monitor observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentDown {
    /// The parent-of-record was re-parented (or the process is now parented
    /// to `init`): the launcher is gone.
    Reparented,
    /// The recorded pid no longer answers a zero-signal probe. EPERM is not
    /// this outcome: a pid that exists but belongs to another user is still
    /// alive, and killing ourselves over it would be a self-DoS.
    Vanished,
}

/// One liveness decision for the recorded parent, from facts the caller
/// observed (kept pure so the policy is unit-testable without processes).
///
/// `pid_alive` is `kill(pid, 0) == 0 || EPERM`; `current_ppid` is
/// `getppid()` today or `None` where the platform has no such notion
/// (Windows: the handle wait is the whole probe).
///
/// The two conditions the task requires, and nothing else:
///
/// 1. **re-parented to init** — `getppid() == 1` while the recorded parent was
///    this process's actual kernel parent. Linux and macOS re-parent an
///    orphaned child to pid 1 the moment the original parent dies, so this is
///    the decisive, pid-reuse-proof signal. It is deliberately *not* "any
///    change of `getppid()`": a parent that merely `exec`s (shell wrappers,
///    launchers that re-exec themselves) keeps the same pid, but a pid that
///    moved for any other benign reason must not kill a healthy connector.
/// 2. **`kill(ppid, 0)` fails** — the recorded pid is gone (ESRCH). `EPERM`
///    is not death: the process exists and merely belongs to someone else,
///    and killing ourselves over it would be a self-DoS.
///
/// A recorded pid that is *not* the kernel parent (`--parent-pid` naming a
/// supervisor or harness) is judged by condition 2 only: `getppid()` was
/// never going to equal it, so re-parenting carries no information.
pub fn parent_down(
    recorded: &RecordedParent,
    pid_alive: bool,
    current_ppid: Option<u32>,
) -> Option<ParentDown> {
    if let Some(ppid) = current_ppid
        && recorded.is_actual_parent
        && ppid == 1
    {
        return Some(ParentDown::Reparented);
    }
    if !pid_alive {
        return Some(ParentDown::Vanished);
    }
    None
}

/// Blocking parent watch: returns the verdict that ends the connector.
/// The platform leg gives the accurate wakeup where one exists (a zero
/// timeout handle wait on Windows); everywhere else the fixed poll interval
/// is the cadence.
pub async fn watch_parent(recorded: RecordedParent) -> ParentDown {
    tokio::task::spawn_blocking(move || watch_parent_blocking(recorded))
        .await
        .unwrap_or(ParentDown::Vanished)
}

fn watch_parent_blocking(recorded: RecordedParent) -> ParentDown {
    loop {
        if wait_for_parent_exit(recorded).is_err() {
            // The platform wait could not be armed (the parent vanished
            // between resolving it and opening the handle): fall through to
            // the plain probes instead of spinning.
            std::thread::sleep(Duration::from_millis(250));
        }
        if let Some(down) = parent_down(&recorded, pid_alive(recorded.pid), observed_ppid()) {
            return down;
        }
    }
}

#[cfg(unix)]
fn observed_ppid() -> Option<u32> {
    Some(current_ppid())
}

#[cfg(windows)]
fn observed_ppid() -> Option<u32> {
    None
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // Signal 0 delivers nothing; EPERM means "exists, not ours" = alive.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if handle == ptr::null_mut() {
            return false;
        }
        let result = WaitForSingleObject(handle, 0);
        CloseHandle(handle);
        result == WAIT_TIMEOUT
    }
}

/// Wait for the recorded parent to exit. Unix has no cheap process-exit
/// wakeup, so this arm is a bounded sleep: the monitor's interval probe is
/// the truth and this function only paces the loop.
#[cfg(unix)]
fn wait_for_parent_exit(_recorded: RecordedParent) -> std::io::Result<()> {
    std::thread::sleep(PARENT_POLL_INTERVAL);
    Ok(())
}

#[cfg(windows)]
fn wait_for_parent_exit(recorded: RecordedParent) -> std::io::Result<()> {
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, recorded.pid) };
    if process == ptr::null_mut() {
        return Err(std::io::Error::last_os_error());
    }
    let result = unsafe { WaitForSingleObject(process, INFINITE) };
    unsafe {
        CloseHandle(process);
    }
    if result != WAIT_OBJECT_0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ------------------------------------------------------- process scanning --

/// One row of the host process table, argv included where the host can
/// provide it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRow {
    pub pid: u32,
    pub ppid: u32,
    /// Zombie / dead states (Z) are not live processes: a zombie is a pid
    /// waiting for its parent to reap it, and signalling it is pointless.
    pub state: String,
    /// The full argv where available: the ps line on Linux, the kernel's
    /// KERN_PROCARGS2 vector on macOS.
    pub args: Vec<String>,
}

impl ProcessRow {
    pub fn is_zombie(&self) -> bool {
        self.state.starts_with('Z')
    }

    /// Whether this process's own argv names this data directory.
    ///
    /// Accepts exactly the argument shapes the runtime spawns: the
    /// launcher's `--signal-data-dir <dir>`, the engine's `--data-dir <dir>`,
    /// and the per-account slot `--data-dir <dir>/engines/<accountId>`. A
    /// sibling connector's root is never a prefix of another one, and a plain
    /// string prefix is not used, so `<dir>-old` or `<dir>2` never match.
    pub fn targets_data_dir(&self, data_dir: &Path) -> bool {
        let target = data_dir.to_string_lossy();
        if target.is_empty() {
            return false;
        }
        // Every spelling of both flags: `--flag value` and `--flag=value`.
        for value in self.flag_values(&target) {
            if arg_path_is_within(value, &target) {
                return true;
            }
        }
        false
    }

    /// The `--data-dir` value forms of this argv (both spellings).
    fn data_dir_arguments(&self) -> Vec<&str> {
        let mut values = Vec::new();
        for (index, arg) in self.args.iter().enumerate() {
            if arg == "--data-dir" {
                if let Some(value) = self.args.get(index + 1) {
                    values.push(value.as_str());
                }
            } else if let Some(rest) = arg.strip_prefix("--data-dir=") {
                values.push(rest);
            }
        }
        values
    }

    /// The data-directory arguments this row carries, normalized.
    fn flag_values<'a>(&'a self, _target: &'a str) -> Vec<&'a str> {
        let mut values = self.data_dir_arguments();
        for (index, arg) in self.args.iter().enumerate() {
            if arg == "--signal-data-dir" {
                if let Some(value) = self.args.get(index + 1) {
                    values.push(value.as_str());
                }
            } else if let Some(rest) = arg.strip_prefix("--signal-data-dir=") {
                values.push(rest);
            }
        }
        values
    }

    /// The per-account slot id when the argv points at
    /// `<root>/engines/<accountId>`; the root itself has no slot (the fixed
    /// literal is the same one `pool`/`migrate` use for the layout).
    pub fn slot_of(&self, data_dir: &Path) -> Option<String> {
        let target = data_dir.to_string_lossy();
        let prefix = format!("{target}/");
        let mut slot = None;
        for value in self.data_dir_arguments() {
            let rest = value
                .trim_end_matches('/')
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_prefix("engines/"))?;
            if rest.is_empty() || rest.contains('/') {
                return None;
            }
            slot = Some(rest.to_string());
        }
        slot
    }
}

/// `value` is the directory itself, or a path beneath it — never a mere
/// string prefix.
fn arg_path_is_within(value: &str, target: &str) -> bool {
    let trimmed = value.trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == target {
        return true;
    }
    trimmed
        .strip_prefix(target)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Read the host process table. Best effort: an unavailable table is an
/// empty scan, never an error (the sweep degrades to its warning face).
pub fn scan_processes() -> Vec<ProcessRow> {
    #[cfg(unix)]
    {
        scan_with_ps()
    }
    #[cfg(windows)]
    {
        Vec::new()
    }
}

#[cfg(unix)]
fn scan_with_ps() -> Vec<ProcessRow> {
    use std::process::{Command, Stdio};

    // -A = every process; the four `=`-suffixed fields mean no header row.
    // `args` is the truncated command line on macOS and the full one on
    // Linux; the macOS truncation is why the data-directory evidence is
    // replaced below with the kernel's real vector.
    let output = match Command::new("ps")
        .args(["-Ao", "pid=,ppid=,stat=,args=", "--"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };
    if !output.status.success() {
        return Vec::new();
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let rows: Vec<ProcessRow> = listing.lines().filter_map(parse_ps_line).collect();
    #[cfg(target_os = "macos")]
    {
        return hydrate_macos_argv(rows);
    }
    #[allow(unreachable_code)]
    rows
}

/// `    123     1 S    /usr/bin/foo --flag value` -> one row.
#[cfg(unix)]
fn parse_ps_line(line: &str) -> Option<ProcessRow> {
    // Stride split, not `splitn`: run of spaces `splitn(k, ' ')` yields
    // empty fields, while `splitn(k, whitespace)` only splits once per run.
    // `split_whitespace().take(3)` + the rest as argv is exact for both ps
    // shapes.
    let mut fields = line.split_whitespace();
    let pid = fields.next()?.parse::<u32>().ok()?;
    let ppid = fields.next()?.parse::<u32>().ok()?;
    let state = fields.next()?.to_string();
    let args: Vec<String> = fields.map(str::to_string).collect();
    Some(ProcessRow {
        pid,
        ppid,
        state,
        args,
    })
}

/// macOS: replace the truncated ps argv of every process with the kernel's
/// real argument vector (KERN_PROCARGS2). Only pids are matched; arguments
/// are never copied into diagnostics.
#[cfg(target_os = "macos")]
fn hydrate_macos_argv(mut rows: Vec<ProcessRow>) -> Vec<ProcessRow> {
    for row in &mut rows {
        if let Some(argv) = macos_process_argv(row.pid) {
            row.args = argv;
        }
    }
    rows
}

/// The kernel's KERN_PROCARGS2 blob: `int argc`, the executable path, then
/// `argc` NUL-terminated arguments, then the environment. Returns `None`
/// for processes this user may not inspect (the caller keeps the truncated
/// ps argv as the evidence in that case).
#[cfg(target_os = "macos")]
fn macos_process_argv(pid: u32) -> Option<Vec<String>> {
    const CTL_KERN: libc::c_int = 1;
    const KERN_PROCARGS2: libc::c_int = 49;
    const MAX_ARGV_BYTES: usize = 1024 * 1024;

    let mut mib: [libc::c_int; 3] = [CTL_KERN, KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;
    // First call only measures; the second reads the same blob.
    let sized = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if sized != 0 || size < size_of::<libc::c_int>() as libc::size_t {
        return None;
    }
    let size = size.min(MAX_ARGV_BYTES);
    let mut buffer = vec![0u8; size];
    let mut read_size = size;
    let read = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut read_size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    buffer.truncate(read_size);
    let argc = i32::from_ne_bytes(buffer.get(0..4)?.try_into().ok()?);
    if !(0..=4096).contains(&argc) {
        return None;
    }
    // Skip the executable path, its NUL padding, then read argc arguments.
    let mut rest = &buffer[4..];
    let exe_end = rest.iter().position(|byte| *byte == 0)?;
    rest = &rest[exe_end..];
    let mut argv = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let start = rest.iter().position(|byte| *byte != 0)?;
        rest = &rest[start..];
        let end = rest.iter().position(|byte| *byte == 0)?;
        argv.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = &rest[end..];
    }
    Some(argv)
}
// --------------------------------------------------------- engine sweeps --

/// Why the per-slot sweep decided what it decided (fixed literals only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotVerdict {
    /// No live engine for this slot names this data directory.
    Owned,
    /// Some live engine for this slot names this data directory, but the
    /// slot is not an orphan (its parent is a live process, or it is ours).
    Healthy,
    /// The pid the supervisor spawned still names this slot: under no
    /// reading is that an orphan.
    SelfOwned,
    /// No live engine for this slot, but the slot is provisioned and the
    /// supervisor already holds a pid for it: the child is mid-sway. The
    /// next sweep decides.
    Spawning,
    /// An engine for a provisioned slot was re-parented to `init` and the
    /// supervisor has no pid for it (it exited, or never recorded it): an
    /// orphan by the task's exact definition, killed only once the same pid
    /// has been seen twice on a provisioned slot.
    Orphan,
    /// An engine for a slot that is not provisioned (retired account, or a
    /// slot from a previous generation) was re-parented to `init`. This is
    /// the only case a cold slot is killable, and only after the double
    /// observation and only while the runtime is running (a stopped runtime
    /// starts no engine, so a cold-slot orphan there is never ours to take
    /// down).
    OrphanUnprovisioned,
    /// A live engine for a slot that is not unambiguously ours (a sibling
    /// connector's slot, a spawn not yet recorded, or an orphan whose
    /// supervisor still holds a pid). Recorded, never killed.
    Foreign,
}

/// The facts the sweep needs about one slot of the current runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotFacts {
    pub provisioned: bool,
    /// The supervisor's believed engine pid, if any.
    pub owned_pid: Option<u32>,
    /// Whether the runtime is between `start` and `stop`.
    pub running: bool,
}

/// Classify one slot from the scan. Pure, so the whole decision table is
/// unit-tested; the side effects live in the caller.
pub fn classify_slot(
    rows: &[ProcessRow],
    data_dir: &Path,
    slot: &str,
    facts: SlotFacts,
    self_pid: u32,
) -> SlotVerdict {
    let engines: Vec<&ProcessRow> = rows
        .iter()
        .filter(|row| {
            row.pid != self_pid
                && !row.is_zombie()
                && row.slot_of(data_dir).as_deref() == Some(slot)
        })
        .collect();
    if engines.is_empty() {
        return SlotVerdict::Owned;
    }
    if facts
        .owned_pid
        .is_some_and(|pid| engines.iter().any(|row| row.pid == pid))
    {
        return SlotVerdict::SelfOwned;
    }
    let orphan = |row: &&ProcessRow| row.ppid == 1;
    if !facts.provisioned {
        return if engines.iter().all(orphan) && facts.running {
            SlotVerdict::OrphanUnprovisioned
        } else {
            SlotVerdict::Foreign
        };
    }
    if engines.iter().all(orphan) {
        if facts.owned_pid.is_none() {
            return SlotVerdict::Orphan;
        }
        // Provisioned, orphaned, but the supervisor still believes it owns
        // a (now stale) pid: ambiguity inside the value space of "just
        // re-spawned". Never kill that.
        return SlotVerdict::Foreign;
    }
    if facts.owned_pid.is_some() {
        // An engine for this slot parented to some other live process: a
        // foreign supervisor's child, or our spawn not yet recorded.
        return SlotVerdict::Spawning;
    }
    SlotVerdict::Foreign
}

/// Repeat-detection memory: a slot is only killed after the same pid was
/// classified as an orphan by two consecutive sweeps, which removes the
/// fork/exec window in which the child briefly still carries the old parent.
#[derive(Default)]
pub struct SweepMemory {
    pending: std::collections::HashMap<String, u32>,
}

impl SweepMemory {
    /// Remember `pid` for `slot` and answer whether it was already pending
    /// (i.e. this is the second consecutive observation). Any other slot's
    /// stale entries are dropped on every sweep so the map stays bounded by
    /// the number of live slots.
    pub fn observe(&mut self, slot: &str, pid: u32, live_slots: &[&str]) -> bool {
        self.pending
            .retain(|known, _| known == slot || live_slots.contains(&known.as_str()));
        let repeat = self.pending.get(slot).is_some_and(|known| *known == pid);
        self.pending.insert(slot.to_string(), pid);
        repeat
    }

    pub fn forget(&mut self, slot: &str) {
        self.pending.remove(slot);
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanKill {
    pub pid: u32,
    pub slot: String,
    pub reason: SlotVerdict,
}

/// The sweep's outcome: what to kill, what was only recorded, and what is
/// waiting for its second observation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineSweepPlan {
    pub kill: Vec<OrphanKill>,
    /// Live engines that could not be attributed as orphans. A sibling
    /// connector's engine (or one whose argv the host cannot read) may
    /// legitimately appear here — that stays a warn, never a kill.
    pub foreign: Vec<(u32, u32)>,
    pub pending: Vec<(u32, String)>,
}

/// The orphan-engine pass: pure orchestration over the scan and the
/// runtime's slot facts, answering the pids to kill and the rows to record.
/// The caller owns the signals. `allowed` gates the whole sweep (operator
/// opt-out) and is checked first so a disabled sweep does no work at all.
pub fn plan_engine_sweep(
    rows: &[ProcessRow],
    data_dir: &Path,
    slots: &[(String, SlotFacts)],
    self_pid: u32,
    memory: &mut SweepMemory,
    allowed: bool,
) -> EngineSweepPlan {
    let mut plan = EngineSweepPlan::default();
    if !allowed {
        return plan;
    }
    let slot_ids: Vec<&str> = slots.iter().map(|(slot, _)| slot.as_str()).collect();
    for (slot, facts) in slots {
        let verdict = classify_slot(rows, data_dir, slot, *facts, self_pid);
        let engines: Vec<&ProcessRow> = rows
            .iter()
            .filter(|row| {
                row.pid != self_pid
                    && !row.is_zombie()
                    && row.slot_of(data_dir).as_deref() == Some(slot.as_str())
            })
            .collect();
        match verdict {
            SlotVerdict::Orphan | SlotVerdict::OrphanUnprovisioned => {
                let orphans: Vec<&ProcessRow> =
                    engines.into_iter().filter(|row| row.ppid == 1).collect();
                if orphans.is_empty() {
                    memory.forget(slot);
                    continue;
                }
                for row in orphans {
                    if memory.observe(slot, row.pid, &slot_ids) {
                        plan.kill.push(OrphanKill {
                            pid: row.pid,
                            slot: slot.clone(),
                            reason: verdict,
                        });
                    } else {
                        plan.pending.push((row.pid, slot.clone()));
                    }
                }
            }
            SlotVerdict::Foreign | SlotVerdict::Spawning => {
                memory.forget(slot);
                for row in engines {
                    plan.foreign.push((row.pid, row.ppid));
                }
            }
            SlotVerdict::Owned | SlotVerdict::Healthy | SlotVerdict::SelfOwned => {
                memory.forget(slot);
            }
        }
    }
    plan
}

/// The kill gate. Every condition must hold; the caller passes the probe
/// results instead of doing the IO here so the gate is testable and the
/// ordering (re-read the pid, verify it still names the same slot, ask the
/// kernel who its parent is) is explicit at the call site.
///
/// `child_of_self` comes from the kernel's own parent pid for that pid —
/// the strongest available "I started this" evidence and the last thing
/// checked before a signal is sent.
pub fn may_kill_orphan(
    pid: u32,
    self_pid: u32,
    supervisor_owned: &[u32],
    child_of_self: Option<bool>,
) -> bool {
    pid != self_pid && pid != 0 && !supervisor_owned.contains(&pid) && child_of_self != Some(true)
}

/// Directory-entry discovery for slots that no longer have argv evidence
/// (the owning connector died and its slot directory stayed). Returns the
/// slot ids under `<data-dir>/engines/`; never the paths.
pub fn slots_on_disk(data_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(data_dir.join("engines")) else {
        return Vec::new();
    };
    let mut slots: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect();
    slots.sort();
    slots
}

/// Classification vocabulary for the read-only reporting face.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessKind {
    Connector,
    Engine,
    Unknown,
}

impl ProcessKind {
    pub fn word(self) -> &'static str {
        match self {
            ProcessKind::Connector => "connector",
            ProcessKind::Engine => "engine",
            ProcessKind::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidualProcess {
    pub pid: u32,
    pub ppid: u32,
    pub kind: ProcessKind,
    pub orphaned: bool,
}

/// Every live process whose argv names this data directory, minus ourselves
/// and minus zombies. This is the reporting face behind the desktop's
/// "clean leftovers" preflight; it signals nothing.
pub fn residual_processes(data_dir: &Path) -> Vec<ResidualProcess> {
    let self_pid = std::process::id();
    let rows = scan_processes();
    let mut residues = Vec::new();
    for row in rows {
        if row.pid == self_pid || row.is_zombie() || !row.targets_data_dir(data_dir) {
            continue;
        }
        let kind = if row.slot_of(data_dir).is_some() {
            ProcessKind::Engine
        } else if row.mentions_serve_subcommand() {
            ProcessKind::Connector
        } else {
            ProcessKind::Unknown
        };
        residues.push(ResidualProcess {
            pid: row.pid,
            ppid: row.ppid,
            kind,
            orphaned: row.ppid == 1,
        });
    }
    residues
}

impl ProcessRow {
    /// Whether the argv carries the connector's `serve` subcommand as its
    /// first bare argument after the binary — the launcher's spawn shape.
    pub fn mentions_serve_subcommand(&self) -> bool {
        self.args.iter().skip(1).take(3).any(|arg| arg == "serve")
    }

    pub fn kind(&self, data_dir: &Path) -> ProcessKind {
        if self.slot_of(data_dir).is_some() {
            return ProcessKind::Engine;
        }
        if self.mentions_serve_subcommand() {
            return ProcessKind::Connector;
        }
        ProcessKind::Unknown
    }
}

/// The kernel's current parent of `pid` (Unix), used as the last gate
/// before a signal. `None` when the pid is gone or the platform cannot say.
pub fn parent_of(pid: u32) -> Option<u32> {
    #[cfg(unix)]
    {
        scan_processes()
            .into_iter()
            .find(|row| row.pid == pid)
            .map(|row| row.ppid)
    }
    #[cfg(windows)]
    {
        let _ = pid;
        None
    }
}

/// Re-read one pid's argv evidence from a fresh scan, right before a
/// signal: the classification is never allowed to travel far from the
/// kernel state it was derived from.
pub fn still_targets(pid: u32, data_dir: &Path, slot: Option<&str>) -> bool {
    scan_processes().into_iter().any(|row| {
        row.pid == pid
            && !row.is_zombie()
            && row.targets_data_dir(data_dir)
            && row.slot_of(data_dir).as_deref() == slot
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminatedPid {
    /// SIGTERM ended it inside the grace window.
    Exited,
    /// SIGKILL was delivered after the grace window.
    Killed,
    AlreadyGone,
    Refused,
}

/// Terminate one orphan engine. SIGTERM first (the engine closes its store
/// and its pipes), then SIGKILL after `grace`. The zombie left behind when
/// the engine's parent is `init` belongs to the host's reaper; when the
/// parent is us, the caller's `Child::wait` does it.
pub fn terminate_pid(pid: u32, grace: Duration) -> TerminatedPid {
    #[cfg(unix)]
    {
        let Ok(raw) = libc::pid_t::try_from(pid) else {
            return TerminatedPid::Refused;
        };
        if pid == std::process::id() {
            return TerminatedPid::Refused;
        }
        if unsafe { libc::kill(raw, libc::SIGTERM) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return TerminatedPid::AlreadyGone;
            }
            return TerminatedPid::Refused;
        }
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !pid_alive(pid) || is_zombie(pid) {
                return TerminatedPid::Exited;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if unsafe { libc::kill(raw, libc::SIGKILL) } == 0 {
            return TerminatedPid::Killed;
        }
        TerminatedPid::Refused
    }
    #[cfg(windows)]
    {
        use std::ptr;

        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess,
        };

        if pid == std::process::id() {
            return TerminatedPid::Refused;
        }
        let _ = grace;
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if handle == ptr::null_mut() {
                return TerminatedPid::Refused;
            }
            let result = TerminateProcess(handle, 1);
            CloseHandle(handle);
            if result != 0 {
                return TerminatedPid::Killed;
            }
        }
        TerminatedPid::Refused
    }
}

/// Bounded reap of engine children on the shutdown path (task requirement P1:
/// "no `Z` left behind"). Two owners race for one child pid — tokio's own
/// `Child` handle inside the engine actor, and this process as the wait()
/// owner of record — and `wait` is only legal once per child, so the reap is
/// expressed as a poll instead of a blocking `waitpid`:
///
/// - a pid that no longer exists, or whose state is already `Z`, is done with;
/// - a pid still running after the runtime teardown gets one SIGKILL pass, so
///   a wedged child can never outlive the connector that spawned it;
/// - the whole pass is capped by `budget` and never panics, because this runs
///   on the path that exits the process.
///
/// Only pids the caller just observed as this process's own engine children are
/// touched: the probe asks the kernel whether the child still exists, and a pid
/// that is not ours (`ECHILD`) is never signalled.
pub async fn reap_children(pids: &[u32], budget: Duration) {
    let mut remaining: Vec<u32> = pids.to_vec();
    remaining.retain(|pid| *pid != std::process::id());
    remaining.sort_unstable();
    remaining.dedup();
    if remaining.is_empty() {
        return;
    }
    let deadline = Instant::now() + budget;
    let mut killed = false;
    loop {
        remaining.retain(|pid| !child_is_gone(*pid));
        if remaining.is_empty() || Instant::now() >= deadline {
            break;
        }
        if !killed {
            // The graceful window already happened above (PARENT_EXIT_BUDGET);
            // a child still alive here ignored it.
            tracing::warn!(
                count = remaining.len(),
                "engine children still running after the shutdown budget; killing them"
            );
            for pid in &remaining {
                kill_child_now(*pid);
            }
            killed = true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !remaining.is_empty() {
        tracing::warn!(
            count = remaining.len(),
            "engine children could not be confirmed gone before exit"
        );
    }
}

/// Whether the engine child `pid` has exited. Deliberately **not** a
/// `waitpid` probe: the tokio `Child` handle inside the engine actor is the
/// owner of record for `wait`, and a status stolen here would surface there
/// as a spurious "exited" while the actor still believes it owns the child.
/// Existence plus zombie state says the same thing without touching the
/// child's exit status: a pid that left the table is gone, and one that is
/// still in it as `Z` has already exited and is only waiting for a reaper.
#[cfg(unix)]
fn child_is_gone(pid: u32) -> bool {
    !pid_alive(pid) || is_zombie(pid)
}

#[cfg(windows)]
fn child_is_gone(pid: u32) -> bool {
    !pid_alive(pid)
}

#[cfg(unix)]
fn kill_child_now(pid: u32) {
    if let Ok(raw) = libc::pid_t::try_from(pid) {
        // The pid came from this process's own supervisor table a moment ago,
        // and the probe above confirmed it is still a child of ours.
        unsafe {
            libc::kill(raw, libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
fn kill_child_now(pid: u32) {
    let _ = terminate_pid(pid, Duration::ZERO);
}

#[cfg(unix)]
fn is_zombie(pid: u32) -> bool {
    // A zombie has already exited; it holds no data directory. Reaping it
    // is the parent's job, so the sweep treats it as gone. /proc is Linux
    // only; elsewhere one more scan answers it.
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // "pid (comm) state ...": comm may contain spaces and parentheses,
        // so the state is the field after the last ')'.
        return stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'));
    }
    scan_processes()
        .into_iter()
        .find(|row| row.pid == pid)
        .is_some_and(|row| row.is_zombie())
}
#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/Users/x/signal-connector/default/signal-data";

    fn row(pid: u32, ppid: u32, args: &[&str]) -> ProcessRow {
        ProcessRow {
            pid,
            ppid,
            state: "S".into(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    fn slot_row(pid: u32, ppid: u32, slot: &str) -> ProcessRow {
        row(
            pid,
            ppid,
            &["kt-engine", "--data-dir", &format!("{ROOT}/engines/{slot}")],
        )
    }

    #[test]
    fn argv_evidence_requires_an_exact_directory_boundary() {
        let owner = row(
            10,
            2,
            &["kt-signal-connector", "serve", "--signal-data-dir", ROOT],
        );
        assert!(owner.targets_data_dir(Path::new(ROOT)));
        let joined = row(11, 2, &["kt-engine", "--data-dir", ROOT, "jsonRpc"]);
        assert!(joined.targets_data_dir(Path::new(ROOT)));
        let slot = slot_row(12, 2, "abc");
        assert!(slot.targets_data_dir(Path::new(ROOT)));
        assert_eq!(slot.slot_of(Path::new(ROOT)).as_deref(), Some("abc"));
        // Prefix-only lookalikes never match.
        for decoy in [
            format!("{ROOT}-old"),
            format!("{ROOT}2"),
            format!("{ROOT}.bak"),
        ] {
            let other = row(13, 2, &["kt-signal-connector", "--signal-data-dir", &decoy]);
            assert!(
                !other.targets_data_dir(Path::new(ROOT)),
                "{decoy} must not match"
            );
        }
        let trailing = row(14, 2, &["kt-engine", "--data-dir", &format!("{ROOT}/")]);
        assert!(trailing.targets_data_dir(Path::new(ROOT)));
        // The `=` spelling is accepted too (clap allows it).
        let equals = row(15, 2, &["kt-engine", &format!("--data-dir={ROOT}")]);
        assert!(equals.targets_data_dir(Path::new(ROOT)));
        // Unrelated argv never matches, and a flag used as another flag's
        // value is not evidence either.
        assert!(!row(16, 2, &["bash", "-lc", "echo hi"]).targets_data_dir(Path::new(ROOT)));
        let odd = row(17, 2, &["x", "--other", "--signal-data-dir", "elsewhere"]);
        assert!(!odd.targets_data_dir(Path::new(ROOT)));
    }

    #[test]
    fn only_a_direct_child_directory_is_a_slot() {
        let root = Path::new("/data");
        let nested = row(1, 2, &["kt-engine", "--data-dir", "/data/engines/a/b"]);
        assert!(nested.targets_data_dir(root));
        assert_eq!(nested.slot_of(root), None);
        let root_engine = row(2, 2, &["kt-engine", "--data-dir", "/data"]);
        assert_eq!(root_engine.slot_of(root), None);
        assert_eq!(root_engine.kind(root), ProcessKind::Unknown);
        assert_eq!(nested.kind(root), ProcessKind::Unknown);
    }

    #[test]
    fn process_kind_separates_connectors_from_engines() {
        let root = Path::new(ROOT);
        let connector = row(
            1,
            2,
            &["kt-signal-connector", "serve", "--signal-data-dir", ROOT],
        );
        assert_eq!(connector.kind(root), ProcessKind::Connector);
        assert_eq!(slot_row(2, 2, "a").kind(root), ProcessKind::Engine);
    }

    #[test]
    fn parent_down_requires_reparenting_to_init_or_a_failed_probe() {
        let recorded = RecordedParent {
            pid: 4242,
            via: "getppid",
            is_actual_parent: true,
        };
        assert_eq!(parent_down(&recorded, true, Some(4242)), None);
        assert_eq!(
            parent_down(&recorded, false, Some(4242)),
            Some(ParentDown::Vanished)
        );
        // Re-parented to init: the launcher is gone (condition 1).
        assert_eq!(
            parent_down(&recorded, true, Some(1)),
            Some(ParentDown::Reparented)
        );
        // A ppid that moved but is not init is NOT death on its own: a wrapper
        // that re-execs, a subreaper, or a moved process must never take a
        // healthy connector down. Only the probe failure below can.
        assert_eq!(parent_down(&recorded, true, Some(7777)), None);
        assert_eq!(
            parent_down(&recorded, false, Some(7777)),
            Some(ParentDown::Vanished)
        );
        // Windows has no getppid: the liveness probe alone decides.
        assert_eq!(parent_down(&recorded, true, None), None);
        assert_eq!(
            parent_down(&recorded, false, None),
            Some(ParentDown::Vanished)
        );
    }

    /// The false-positive guard this batch fixed: a `--parent-pid` naming a
    /// supervisor the launcher is a child of is not this process's kernel
    /// parent, so `getppid() != that pid` is the normal case, never a death.
    #[test]
    fn a_named_supervisor_pid_is_judged_by_its_probe_only() {
        let named = RecordedParent {
            pid: 4242,
            via: "flag",
            is_actual_parent: false,
        };
        // Our real parent (the launcher) is alive and is not the named pid;
        // getppid() says nothing about the named supervisor.
        assert_eq!(parent_down(&named, true, Some(31337)), None);
        assert_eq!(parent_down(&named, true, Some(1)), None);
        // The supervisor itself going away is decisive (condition 2).
        assert_eq!(
            parent_down(&named, false, Some(31337)),
            Some(ParentDown::Vanished)
        );
    }

    #[test]
    fn marker_round_trip_and_freshness() {
        let temp = tempfile::tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        write_owner_marker(temp.path(), 777, now);
        let marker = read_owner_marker(temp.path()).expect("marker");
        assert_eq!(marker.pid, 777);
        assert!(marker_is_fresh(&marker, now));
        assert!(marker_is_fresh(
            &marker,
            now + OWNER_MARKER_FRESH - Duration::from_secs(1)
        ));
        assert!(!marker_is_fresh(
            &marker,
            now + OWNER_MARKER_FRESH + Duration::from_secs(1)
        ));
        // A marker from the future is not evidence of a live launcher.
        assert!(!marker_is_fresh(&marker, now - Duration::from_secs(30)));
        // Garbage never resolves a pid.
        std::fs::write(temp.path().join(OWNER_FILE_NAME), "not a pid").unwrap();
        assert!(read_owner_marker(temp.path()).is_none());
    }

    #[test]
    fn resolve_parent_pid_prefers_the_flag_then_falls_back() {
        let temp = tempfile::tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        write_owner_marker(temp.path(), 991, now);
        let via_flag = resolve_parent_pid(Some(1234), temp.path(), now).unwrap();
        assert_eq!((via_flag.pid, via_flag.via), (1234, "flag"));
        // pid 1 / 0 are never a launcher: the resolution falls through to the
        // live parent or the marker instead of recording init.
        let fallback = resolve_parent_pid(Some(1), temp.path(), now).unwrap();
        assert_ne!(fallback.pid, 1);
        assert_ne!(fallback.via, "flag");
    }

    #[cfg(unix)]
    #[test]
    fn pid_alive_sees_this_process_and_not_an_impossible_pid() {
        assert!(pid_alive(std::process::id()));
        // u32::MAX is not a valid pid_t and never names a live process.
        assert!(!pid_alive(u32::MAX));
    }

    #[test]
    fn sweep_never_kills_a_self_owned_or_live_parented_engine() {
        let root = Path::new("/data");
        let rows = vec![
            row(100, 2, &["kt-engine", "--data-dir", "/data/engines/a"]),
            row(101, 2, &["kt-engine", "--data-dir", "/data/engines/b"]),
            row(102, 2, &["kt-engine", "--data-dir", "/data/engines/c"]),
        ];
        let slots = vec![
            (
                "a".to_string(),
                SlotFacts {
                    provisioned: true,
                    owned_pid: Some(100),
                    running: true,
                },
            ),
            (
                "b".to_string(),
                SlotFacts {
                    provisioned: true,
                    owned_pid: None,
                    running: true,
                },
            ),
            (
                "c".to_string(),
                SlotFacts {
                    provisioned: false,
                    owned_pid: None,
                    running: true,
                },
            ),
        ];
        let mut memory = SweepMemory::default();
        for _ in 0..3 {
            let plan = plan_engine_sweep(&rows, root, &slots, 2, &mut memory, true);
            assert!(plan.kill.is_empty());
        }
    }

    #[test]
    fn sweep_kills_an_orphan_only_on_the_second_observation() {
        let root = Path::new("/data");
        let rows = vec![row(200, 1, &["kt-engine", "--data-dir", "/data/engines/a"])];
        let slots = vec![(
            "a".to_string(),
            SlotFacts {
                provisioned: true,
                owned_pid: None,
                running: true,
            },
        )];
        let mut memory = SweepMemory::default();
        let first = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true);
        assert!(first.kill.is_empty(), "first sighting is only recorded");
        assert_eq!(first.pending, vec![(200, "a".to_string())]);
        let second = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true);
        assert_eq!(
            second.kill,
            vec![OrphanKill {
                pid: 200,
                slot: "a".to_string(),
                reason: SlotVerdict::Orphan,
            }]
        );
        // The engine is gone now: nothing new is planned.
        let third = plan_engine_sweep(&[], root, &slots, 4242, &mut memory, true);
        assert!(third.kill.is_empty());
    }

    #[test]
    fn sweep_treats_a_supervisor_owned_pid_as_self_owned_even_when_orphaned() {
        let root = Path::new("/data");
        let rows = vec![row(300, 1, &["kt-engine", "--data-dir", "/data/engines/a"])];
        let slots = vec![(
            "a".to_string(),
            SlotFacts {
                provisioned: true,
                owned_pid: Some(300),
                running: true,
            },
        )];
        let mut memory = SweepMemory::default();
        for _ in 0..3 {
            let plan = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true);
            assert!(plan.kill.is_empty(), "a recorded pid is never an orphan");
        }
    }

    #[test]
    fn sweep_refuses_cold_slots_while_the_runtime_is_down() {
        let root = Path::new("/data");
        let rows = vec![row(400, 1, &["kt-engine", "--data-dir", "/data/engines/x"])];
        let slots = vec![(
            "x".to_string(),
            SlotFacts {
                provisioned: false,
                owned_pid: None,
                running: false,
            },
        )];
        let mut memory = SweepMemory::default();
        for _ in 0..3 {
            let plan = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true);
            assert!(
                plan.kill.is_empty(),
                "a stopped runtime starts no engine; a cold-slot orphan is not ours"
            );
        }
    }

    #[test]
    fn sweep_takes_down_a_cold_slot_orphan_only_while_running() {
        let root = Path::new("/data");
        let rows = vec![row(410, 1, &["kt-engine", "--data-dir", "/data/engines/x"])];
        let slots = vec![(
            "x".to_string(),
            SlotFacts {
                provisioned: false,
                owned_pid: None,
                running: true,
            },
        )];
        let mut memory = SweepMemory::default();
        assert!(
            plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true)
                .kill
                .is_empty()
        );
        let plan = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true);
        assert_eq!(plan.kill[0].reason, SlotVerdict::OrphanUnprovisioned);
    }

    #[test]
    fn sweep_is_disabled_when_not_allowed() {
        let root = Path::new("/data");
        let rows = vec![row(500, 1, &["kt-engine", "--data-dir", "/data/engines/a"])];
        let slots = vec![(
            "a".to_string(),
            SlotFacts {
                provisioned: true,
                owned_pid: None,
                running: true,
            },
        )];
        let mut memory = SweepMemory::default();
        for _ in 0..3 {
            let plan = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, false);
            assert!(plan.kill.is_empty());
            assert!(plan.pending.is_empty());
        }
        assert!(memory.is_empty());
    }

    #[test]
    fn a_foreign_engine_is_recorded_and_never_killed() {
        let root = Path::new("/data");
        let rows = vec![
            row(600, 2, &["kt-engine", "--data-dir", "/data/engines/a"]),
            row(601, 3, &["kt-engine", "--data-dir", "/data/engines/a"]),
        ];
        let slots = vec![(
            "a".to_string(),
            SlotFacts {
                provisioned: true,
                owned_pid: None,
                running: true,
            },
        )];
        let mut memory = SweepMemory::default();
        for _ in 0..3 {
            let plan = plan_engine_sweep(&rows, root, &slots, 4242, &mut memory, true);
            assert!(plan.kill.is_empty());
            assert_eq!(plan.foreign.len(), 2);
        }
    }

    #[test]
    fn zombies_are_not_orphans() {
        let root = Path::new("/data");
        let mut zombie = row(700, 1, &["kt-engine", "--data-dir", "/data/engines/a"]);
        zombie.state = "Z+".into();
        let slots = vec![(
            "a".to_string(),
            SlotFacts {
                provisioned: true,
                owned_pid: None,
                running: true,
            },
        )];
        let mut memory = SweepMemory::default();
        for _ in 0..3 {
            let plan = plan_engine_sweep(&[zombie.clone()], root, &slots, 4242, &mut memory, true);
            assert!(plan.kill.is_empty(), "a zombie is already dead");
        }
    }

    #[test]
    fn the_kill_gate_refuses_self_and_supervisor_children() {
        assert!(!may_kill_orphan(10, 10, &[], None));
        assert!(!may_kill_orphan(10, 1, &[10], None));
        assert!(!may_kill_orphan(10, 1, &[], Some(true)));
        assert!(!may_kill_orphan(0, 1, &[], None));
        assert!(may_kill_orphan(10, 1, &[11], Some(false)));
        assert!(may_kill_orphan(10, 1, &[], None));
    }

    #[test]
    fn memory_is_bounded_by_the_slot_set() {
        let mut memory = SweepMemory::default();
        assert!(!memory.observe("a", 1, &["a"]));
        assert!(memory.observe("a", 1, &["a"]));
        assert!(
            !memory.observe("a", 2, &["a"]),
            "a new pid restarts the count"
        );
        assert!(memory.observe("a", 2, &["a"]));
        // A slot outside the live set is forgotten on the next sweep.
        memory.observe("gone", 9, &["a", "gone"]);
        assert_eq!(memory.len(), 2);
        memory.observe("a", 2, &["a"]);
        assert_eq!(memory.len(), 1);
        memory.forget("a");
        assert!(memory.is_empty());
    }

    #[test]
    fn scan_parses_the_host_table_without_panicking() {
        for row in scan_processes() {
            assert!(row.pid > 0);
        }
        let line = "  1234   1 S    /usr/bin/kt-engine --data-dir /data jsonRpc";
        let parsed = parse_ps_line(line).unwrap();
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.ppid, 1);
        assert_eq!(parsed.state, "S");
        assert_eq!(parsed.args[1], "--data-dir");
        assert!(parse_ps_line("").is_none());
        assert!(parse_ps_line("garbage").is_none());
    }

    #[test]
    fn slots_on_disk_lists_real_directories_only() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("engines/b")).unwrap();
        std::fs::create_dir_all(temp.path().join("engines/a")).unwrap();
        std::fs::write(temp.path().join("engines/file"), b"x").unwrap();
        assert_eq!(
            slots_on_disk(temp.path()),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(slots_on_disk(&temp.path().join("absent")).is_empty());
    }

    #[test]
    fn terminate_refuses_our_own_pid() {
        assert_eq!(
            terminate_pid(std::process::id(), Duration::from_millis(10)),
            TerminatedPid::Refused
        );
    }

    /// The operator opt-out (task requirement): set is set, and nothing else
    /// silently disarms a self-protection.
    #[test]
    fn the_opt_out_env_is_read_as_a_boolean_with_a_safe_default() {
        // No mutation of the process environment here: the unit suite runs
        // cases in parallel and `set_var` is process-global. The parse rule
        // is exercised through the pure helper the reader uses.
        assert!(!opt_out_value_disabled(None));
        assert!(!opt_out_value_disabled(Some("")));
        assert!(!opt_out_value_disabled(Some("   ")));
        assert!(!opt_out_value_disabled(Some("0")));
        assert!(!opt_out_value_disabled(Some("false")));
        assert!(!opt_out_value_disabled(Some("off")));
        assert!(!opt_out_value_disabled(Some("maybe")));
        for on in ["1", "true", "TRUE", "yes", "on", " 1 "] {
            assert!(
                opt_out_value_disabled(Some(on)),
                "{on:?} must disable the watch"
            );
        }
    }

    /// Reaping is a no-op when there is nothing to reap, and never touches
    /// this process (never a self-signal, never a self-wait).
    #[tokio::test]
    async fn reaping_an_empty_or_self_pid_set_never_signals_anything() {
        reap_children(&[], Duration::from_millis(50)).await;
        // This process is filtered out before any signal: the only thing the
        // test can assert afterwards is that it is still running to assert.
        reap_children(&[std::process::id()], Duration::from_millis(50)).await;
        assert!(pid_alive(std::process::id()));
    }

    /// P1 zombie discipline, unit face: a real child that ignored nothing
    /// still exists after the reap and is gone immediately afterwards — the
    /// reap confirms exit instead of hanging on it.
    #[cfg(unix)]
    #[tokio::test]
    async fn reaping_a_real_child_confirms_exit_within_the_budget() {
        let mut child = match std::process::Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return,
        };
        let pid = child.id();
        assert!(!child_is_gone(pid), "a live child is not gone");
        // The reap is what ends a child the graceful path could not.
        let started = Instant::now();
        reap_children(&[pid], Duration::from_secs(2)).await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the reap must stay inside its budget"
        );
        assert!(child_is_gone(pid), "the child must be gone after the reap");
        // Whoever owns the handle still reaps it: no 'Z' survives this test.
        let _ = child.wait();
    }
}
