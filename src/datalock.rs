// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-process occupancy lock for signal-cli data directories (ADR 0002).
//!
//! Two connector processes sharing one data directory would run two
//! signal-cli engines against one account database. The lock below turns
//! that into a startup error: an advisory exclusive lock on
//! `<data-dir>/.kt-signal-connector.lock`, `flock(2)` on Unix and
//! `LockFileEx` on Windows. Both are kernel-owned and released
//! automatically when the holding process exits for *any* reason —
//! including SIGKILL — so a crashed holder never bricks the next start and
//! there is no stale-lock detection or takeover logic to get wrong. The
//! lock file itself is deliberately left on disk after release: deleting it
//! would only reopen the takeover race the kernel lock already closes.
//!
//! Locks are taken per planned group data directory — the `default`
//! group's `--signal-data-dir` root and every `proxy-groups/<groupId>/`
//! subdirectory alike — at serve startup, before the bootstrap payload is
//! read and before the endpoint is published, and held for process
//! lifetime: `runtime.stop` parks engines but must not release occupancy.
//! Locking a path rather than comparing path strings also stays correct
//! across symlinked or relative spellings of the same directory: opening
//! the lock file resolves to the same inode.

use std::io;
use std::path::Path;

use crate::groups::ProxyGroupPlan;

/// The lock file placed inside every occupied data directory. The leading
/// dot keeps it out of signal-cli's way; the name is distinct enough that
/// it can never collide with signal-cli's own files. The connector's own
/// pid is written into the file at acquire time so the read-only
/// `runtime.doctor` face (§4.79) can report the holder identity; the kernel
/// lock, never the file content, stays the occupancy truth.
pub(crate) const LOCK_FILE_NAME: &str = ".kt-signal-connector.lock";

/// An acquired data-directory occupancy lock. The held file handle *is* the
/// lock: dropping the guard releases it, and any process exit (clean or
/// crash) releases it via the kernel. The lock file is left in place on
/// purpose (module docs).
#[derive(Debug)]
pub struct DataDirLock {
    handle: std::fs::File,
}

impl DataDirLock {
    /// Acquire the process-lifetime exclusive lock for one planned group
    /// data directory. `group_id` names the conflicting group in the error
    /// message; the directory path itself never enters diagnostics
    /// (AGENTS.md log discipline).
    pub fn acquire(group_id: &str, data_dir: &Path) -> io::Result<Self> {
        // The engine creates and hardens this directory at first start; the
        // lock must exist before any engine can, so create it here with the
        // same owner-only discipline (the engine re-validates on start).
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let lock_path = data_dir.join(LOCK_FILE_NAME);
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
        }
        lock_exclusive(&handle).map_err(|error| occupied_error(group_id, error))?;
        // Record the holder pid for the doctor's lock face (§4.79). The file
        // is this connector's own lock artifact, written once at acquire;
        // a write failure is non-fatal (the kernel lock is already held, so
        // occupancy is unaffected and the doctor reports an unknown pid).
        let pid_note = format!("{}", std::process::id());
        let _ = handle.set_len(0);
        let _ = std::io::Write::write_all(&mut &handle, pid_note.as_bytes());
        Ok(Self { handle })
    }

    /// Dry-run-safe occupancy probe (contract revision 1.288, §4.274): the
    /// same kernel lock, but it never creates the data directory or the lock
    /// file and never rewrites the holder pid. A missing directory or lock
    /// file means no connector ever occupied this path — there is nothing to
    /// conflict with, so `None` is the honest answer. When a lock file does
    /// exist the flock/LockFileEx semantics are exactly those of
    /// [`Self::acquire`], so a live holder is still refused.
    pub fn acquire_quiescent(group_id: &str, data_dir: &Path) -> io::Result<Option<Self>> {
        if !data_dir.is_dir() {
            return Ok(None);
        }
        let lock_path = data_dir.join(LOCK_FILE_NAME);
        let handle = match std::fs::OpenOptions::new().read(true).open(&lock_path) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        lock_exclusive(&handle).map_err(|error| occupied_error(group_id, error))?;
        Ok(Some(Self { handle }))
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        // Deterministic release before the handle closes (the kernel would
        // release it on close anyway). Never removes the lock file.
        let _ = unlock(&self.handle);
    }
}

/// Acquire the occupancy lock for every group data directory in the launch
/// plan (the `default` root and each `proxy-groups/<groupId>/`
/// subdirectory). All-or-nothing: on failure every lock already taken is
/// released, so a failed start never pins a data directory it does not
/// serve, and the error names the first conflicting group.
pub fn lock_plan_data_dirs(plan: &ProxyGroupPlan) -> Result<Vec<DataDirLock>, String> {
    let mut locks = Vec::with_capacity(plan.groups.len());
    for entry in &plan.groups {
        match DataDirLock::acquire(&entry.id, &entry.data_dir) {
            Ok(lock) => locks.push(lock),
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(locks)
}

/// Translate the platform "already locked" failure into the startup
/// diagnostic; anything else is a genuine I/O failure and passes through.
fn occupied_error(group_id: &str, error: io::Error) -> io::Error {
    #[cfg(unix)]
    let occupied = error.kind() == io::ErrorKind::WouldBlock;
    #[cfg(windows)]
    let occupied = {
        // ERROR_LOCK_VIOLATION is what LOCKFILE_FAIL_IMMEDIATELY reports.
        error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION as i32)
    };
    if occupied {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "signal data directory of proxy group '{group_id}' \
                 is already in use by another connector process"
            ),
        )
    } else {
        error
    }
}

#[cfg(unix)]
fn lock_exclusive(handle: &std::fs::File) -> io::Result<()> {
    Ok(rustix::fs::flock(
        handle,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )?)
}

#[cfg(unix)]
fn unlock(handle: &std::fs::File) -> io::Result<()> {
    Ok(rustix::fs::flock(
        handle,
        rustix::fs::FlockOperation::Unlock,
    )?)
}

#[cfg(windows)]
fn lock_exclusive(handle: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    // Lock the whole file range [0, u64::MAX] exclusively, failing
    // immediately when any byte of it is already locked.
    let locked = unsafe {
        LockFileEx(
            handle.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if locked == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn unlock(handle: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    let unlocked = unsafe {
        UnlockFileEx(
            handle.as_raw_handle(),
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if unlocked == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
