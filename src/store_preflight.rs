// SPDX-License-Identifier: AGPL-3.0-only

//! The plaintext-store preflight (contract 1.291, §4.277 item D).
//!
//! The migration switch (KT_ENGINE_STORE_MIGRATE) is a *machine* decision: it
//! says whether this connector migrates. The preflight answers the operator's
//! own question - "did I ask for encrypted stores?" - and refuses to start an
//! engine on a plaintext store when the answer is yes and nothing is armed to
//! migrate it. Refusing is the only honest answer there: the engine would build
//! new plaintext state, and the operator believes the opposite.
//!
//! The answer is read from the **file header only** (16 bytes), never by
//! opening the database and never with a key: an encrypted store has no header
//! at all, so the header is the whole distinction and reading it costs one
//! bounded read per candidate file.

use std::path::{Path, PathBuf};

/// The operator's intent: this host must not run accounts on plaintext stores.
/// Unset - the default - keeps every pre-migration behaviour byte for byte.
/// Read once at runtime assembly, like every other launcher decision.
pub const REQUIRE_ENCRYPTED_ENV: &str = "KT_ENGINE_STORE_REQUIRE_ENCRYPTED";

/// The first 16 bytes of every SQLite 3 database. A SQLCipher store starts with
/// ciphertext instead, so a matching header is proof of a *plaintext* store and
/// a non-matching one is proof of nothing (it may be encrypted, empty, or gone).
pub const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// The engine's store file name inside one account directory.
pub const STORE_FILE_NAME: &str = "store.db";

/// The plaintext backup the connector's own store migration leaves beside the
/// encrypted `connector.sqlite3` in the state dir.
pub const PLAINTEXT_BACKUP_FILE: &str = "connector.sqlite3.plaintext-backup";

/// Upper bound on the account directories one preflight pass inspects. A data
/// directory holds at most the pool ceiling; the bound keeps a hostile or
/// damaged tree from turning one slot start into an unbounded directory walk.
pub const MAX_SCANNED_ACCOUNT_DIRS: usize = 32;

/// Strict, case-insensitive parse of the intent. Unset and empty are off;
/// anything outside the accepted words answers None so the caller can warn and
/// stay off - the fail-safe direction for a key that changes what starts.
pub fn parse_intent(raw: Option<&str>) -> Option<bool> {
    match raw.map(str::trim) {
        None | Some("") => Some(false),
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" => Some(false),
            "on" | "1" | "true" | "yes" => Some(true),
            _ => None,
        },
    }
}

/// Read the launcher's intent once. An unrecognised value warns exactly once
/// and stays off: a typo must not arm a refusal that stops every account.
pub fn intent_from_env() -> bool {
    match parse_intent(std::env::var(REQUIRE_ENCRYPTED_ENV).ok().as_deref()) {
        Some(intent) => intent,
        None => {
            tracing::warn!(
                env = REQUIRE_ENCRYPTED_ENV,
                "unrecognised store-encryption intent; staying off"
            );
            false
        }
    }
}

/// What one on-disk path says about a store, read from metadata plus at most
/// the first 16 bytes. `Unverifiable` is a first-class answer, not an error:
/// a symlink is never followed and an unreadable file is never guessed at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFileState {
    /// Missing, not a regular file, or zero bytes: nothing to migrate.
    Absent,
    /// A readable SQLite plaintext header: positive evidence of a plaintext
    /// store.
    Plaintext,
    /// Readable and non-empty with a non-SQLite header: the encrypted shape
    /// (the connector cannot tell ciphertext from garbage by design).
    Encrypted,
    /// A symlink, an unreadable file, or any other metadata failure: no
    /// evidence either way, and never a reason to refuse a start.
    Unverifiable,
}

impl StoreFileState {
    /// Whether this evidence proves a store file is really there (for the
    /// "already migrated" seed). Only positive, readable evidence counts:
    /// zero-byte and unreadable files are treated like an absent store.
    pub fn has_store(self) -> bool {
        matches!(self, Self::Plaintext | Self::Encrypted)
    }
}

/// Classify one store path without following a symlink and without opening a
/// database. A zero-length file is `Absent` (the same reading `db_file_state`
/// uses); a short but non-empty file is `Encrypted` because it passed the
/// readable/non-empty gate; an unreadable file is `Unverifiable`.
pub fn store_file_state(path: &Path) -> StoreFileState {
    use std::io::Read;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StoreFileState::Absent;
        }
        Err(_) => return StoreFileState::Unverifiable,
    };
    if metadata.file_type().is_symlink() {
        return StoreFileState::Unverifiable;
    }
    if !metadata.is_file() {
        return StoreFileState::Absent;
    }
    if metadata.len() == 0 {
        return StoreFileState::Absent;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return StoreFileState::Unverifiable;
    };
    let mut header = [0_u8; 16];
    match file.read_exact(&mut header) {
        Ok(()) if &header == SQLITE_HEADER => StoreFileState::Plaintext,
        Ok(()) => StoreFileState::Encrypted,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            StoreFileState::Encrypted
        }
        Err(_) => StoreFileState::Unverifiable,
    }
}

/// Whether this file starts with the plaintext SQLite header. Every read error
/// (missing, unreadable, shorter than the header, a symlink) answers false:
/// only positive evidence may refuse a start.
pub fn has_plaintext_header(path: &Path) -> bool {
    store_file_state(path) == StoreFileState::Plaintext
}

/// Candidate store paths under one engine data directory, in deterministic
/// order. Directory entries are inspected with `symlink_metadata`: a symlinked
/// account directory is skipped, never traversed. The bound keeps a hostile or
/// damaged tree from turning one slot start into an unbounded directory walk.
fn candidate_store_files(data_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    match std::fs::symlink_metadata(data_dir) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
        _ => return candidates,
    }
    candidates.push(data_dir.join(STORE_FILE_NAME));
    let accounts = data_dir.join("accounts");
    match std::fs::symlink_metadata(&accounts) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
        _ => {
            candidates.sort();
            return candidates;
        }
    }
    let Ok(entries) = std::fs::read_dir(&accounts) else {
        candidates.sort();
        return candidates;
    };
    for entry in entries.flatten().take(MAX_SCANNED_ACCOUNT_DIRS) {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() || !kind.is_dir() {
            continue;
        }
        candidates.push(path.join(STORE_FILE_NAME));
    }
    candidates.sort();
    candidates
}

/// Every real store file under one engine data directory (plaintext or
/// encrypted), in deterministic order. Same layout and bound as
/// [`plaintext_stores`]; zero-byte, unreadable and symlinked paths are not
/// stores.
pub fn store_files(data_dir: &Path) -> Vec<PathBuf> {
    candidate_store_files(data_dir)
        .into_iter()
        .filter(|path| store_file_state(path).has_store())
        .collect()
}

/// Whether this data directory holds any real store at all. A slot with none -
/// including a zero-byte or unreadable file - is a fresh link: the engine
/// creates the store on its first start.
pub fn has_any_store(data_dir: &Path) -> bool {
    !store_files(data_dir).is_empty()
}

/// Every plaintext store under one engine data directory, in deterministic
/// order. Checks the pre-pool layout (`<data-dir>/store.db`) and the pooled one
/// (`<data-dir>/accounts/<account>/store.db`), bounded to
/// [`MAX_SCANNED_ACCOUNT_DIRS`] account directories.
pub fn plaintext_stores(data_dir: &Path) -> Vec<PathBuf> {
    candidate_store_files(data_dir)
        .into_iter()
        .filter(|path| store_file_state(path) == StoreFileState::Plaintext)
        .collect()
}

/// Whether the connector's own plaintext backup is still in the state dir. A
/// warning, never a refusal: it is a copy of a store that is already encrypted,
/// so nothing on the runtime path reads it (the store's own 7-day sweep owns
/// its removal).
pub fn plaintext_backup_present(state_dir: &Path) -> bool {
    state_dir.join(PLAINTEXT_BACKUP_FILE).is_file()
}

/// The preflight's verdict for one pooled slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightVerdict {
    /// Nothing to say: the intent is off, a migration is armed, or this slot's
    /// store is not plaintext.
    Allow,
    /// Do not start this slot's engine: its store is plaintext, nothing will
    /// migrate it, and the operator asked for encrypted stores.
    Refuse { code: &'static str },
}

/// The four-condition gate: pooled slot + a plaintext store still on disk + the
/// migrator off + the intent on. All four are evaluated here so the caller
/// cannot accidentally combine three of them.
pub fn check(require_encrypted: bool, migration_armed: bool, data_dir: &Path) -> PreflightVerdict {
    if !require_encrypted || migration_armed {
        return PreflightVerdict::Allow;
    }
    if plaintext_stores(data_dir).is_empty() {
        return PreflightVerdict::Allow;
    }
    PreflightVerdict::Refuse {
        code: crate::pool::STORE_PLAINTEXT_REQUIRES_MIGRATION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_store(root: &Path, account: &str) -> PathBuf {
        let dir = root.join("accounts").join(account);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(STORE_FILE_NAME)
    }

    #[test]
    fn the_intent_parses_strictly_and_a_typo_stays_off() {
        assert_eq!(parse_intent(None), Some(false));
        assert_eq!(parse_intent(Some("")), Some(false));
        assert_eq!(parse_intent(Some(" on ")), Some(true));
        assert_eq!(parse_intent(Some("TRUE")), Some(true));
        assert_eq!(parse_intent(Some("0")), Some(false));
        // A typo is not an intent: the caller warns and stays off.
        assert_eq!(parse_intent(Some("yes please")), None);
        assert_eq!(parse_intent(Some("2")), None);
    }

    #[test]
    fn only_a_sqlite_header_counts_as_plaintext() {
        let temp = tempfile::TempDir::new().unwrap();
        let plain = temp.path().join("plain.db");
        std::fs::write(&plain, b"SQLite format 3\0rest").unwrap();
        assert!(has_plaintext_header(&plain));
        let encrypted = temp.path().join("encrypted.db");
        std::fs::write(&encrypted, [0x9a_u8, 0x1f, 0x00, 0x5c, 0x11]).unwrap();
        assert!(!has_plaintext_header(&encrypted));
        // Short, missing and unreadable files are never evidence.
        let short = temp.path().join("short.db");
        std::fs::write(&short, b"SQLite").unwrap();
        assert!(!has_plaintext_header(&short));
        assert!(!has_plaintext_header(&temp.path().join("absent.db")));
    }

    #[test]
    fn the_scan_finds_both_layouts_and_ignores_encrypted_stores() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(root.join(STORE_FILE_NAME), b"SQLite format 3\0x").unwrap();
        let pooled = account_store(root, "lk-1");
        std::fs::write(&pooled, b"SQLite format 3\0y").unwrap();
        let encrypted = account_store(root, "lk-2");
        std::fs::write(&encrypted, [0x01_u8, 0x02, 0x03]).unwrap();
        let found = plaintext_stores(root);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|path| !path.ends_with("lk-2/store.db")));
        // An empty or absent tree answers nothing (never a refusal).
        assert!(plaintext_stores(&root.join("absent")).is_empty());
    }

    #[test]
    fn all_four_conditions_are_required_to_refuse() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let store = account_store(root, "lk-1");
        std::fs::write(&store, b"SQLite format 3\0").unwrap();
        assert_eq!(
            check(false, false, root),
            PreflightVerdict::Allow,
            "intent off: the pre-migration posture, byte for byte"
        );
        assert_eq!(
            check(true, true, root),
            PreflightVerdict::Allow,
            "a migration is armed: it will do the work"
        );
        assert!(matches!(
            check(true, false, root),
            PreflightVerdict::Refuse {
                code: crate::pool::STORE_PLAINTEXT_REQUIRES_MIGRATION
            }
        ));
        // Intent on, migrator off, but the store is already encrypted.
        std::fs::write(&store, [0xaa_u8, 0xbb]).unwrap();
        assert_eq!(check(true, false, root), PreflightVerdict::Allow);
        // A slot with no store at all (a fresh link) is never refused.
        assert_eq!(
            check(true, false, &root.join("fresh")),
            PreflightVerdict::Allow
        );
    }

    #[test]
    fn the_plaintext_backup_is_detected_beside_the_connector_store() {
        let temp = tempfile::TempDir::new().unwrap();
        assert!(!plaintext_backup_present(temp.path()));
        std::fs::write(temp.path().join(PLAINTEXT_BACKUP_FILE), b"x").unwrap();
        assert!(plaintext_backup_present(temp.path()));
    }

    #[test]
    fn zero_length_and_unreadable_files_are_not_stores() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let zero = account_store(root, "lk-zero");
        std::fs::write(&zero, b"").unwrap();
        assert_eq!(store_file_state(&zero), StoreFileState::Absent);
        assert!(
            !has_any_store(root),
            "zero bytes is a fresh store, not a migrated one"
        );

        let short = account_store(root, "lk-short");
        std::fs::write(&short, b"SQLite").unwrap();
        assert_eq!(store_file_state(&short), StoreFileState::Encrypted);
        assert!(
            has_any_store(root),
            "a readable non-empty file is store-shaped"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let unreadable = account_store(root, "lk-unreadable");
            std::fs::write(&unreadable, b"ciphertext").unwrap();
            let mut perms = std::fs::metadata(&unreadable).unwrap().permissions();
            perms.set_mode(0o000);
            std::fs::set_permissions(&unreadable, perms).unwrap();
            assert_eq!(store_file_state(&unreadable), StoreFileState::Unverifiable);
            assert!(
                !store_files(root).contains(&unreadable),
                "an unreadable file must not be seeded as migrated"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_store_is_unverifiable_and_never_read() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("slot");
        let account = root.join("accounts").join("lk-1");
        std::fs::create_dir_all(&account).unwrap();
        let outside = temp.path().join("outside.db");
        std::fs::write(&outside, b"SQLite format 3\0outside").unwrap();
        let link = account.join(STORE_FILE_NAME);
        symlink(&outside, &link).unwrap();

        assert_eq!(store_file_state(&link), StoreFileState::Unverifiable);
        assert!(
            plaintext_stores(&root).is_empty(),
            "a symlink must never be followed into a plaintext verdict"
        );
        assert!(!has_any_store(&root), "a symlink is not stored evidence");
        assert_eq!(
            check(true, false, &root),
            PreflightVerdict::Allow,
            "an unverifiable path is never a reason to refuse"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_accounts_directory_is_not_traversed() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("slot");
        std::fs::create_dir_all(&root).unwrap();
        let outside = temp.path().join("outside-accounts");
        std::fs::create_dir_all(outside.join("lk-1")).unwrap();
        std::fs::write(
            outside.join("lk-1").join(STORE_FILE_NAME),
            b"SQLite format 3\0outside",
        )
        .unwrap();
        symlink(&outside, root.join("accounts")).unwrap();

        assert!(plaintext_stores(&root).is_empty());
        assert!(!has_any_store(&root));
    }
}
