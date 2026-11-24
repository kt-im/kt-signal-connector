// SPDX-License-Identifier: AGPL-3.0-only

//! Android local-backup export consumption (contract revision 1.47, §4.46):
//! the three connector-side machines behind `backups.*`.
//!
//! [`build_artifact`] projects the store into the one-JSON-object-per-line
//! artifact the engine's export task consumes (`backup-export-input.ndjson`
//! in the engine's per-account data directory, backup-export-contract §10.2).
//! Skip decisions belong here — the engine never drops a line silently, so
//! every store row or column that cannot project into the v1 line set is
//! counted per cause in [`SkipCounters`] and reported through
//! `backups.exportStatus` instead.
//!
//! The snapshot caretaker owns the lifecycle the engine contract assigns to
//! the connector (§10.6): clear `-tmp` residue, keep only the most recent
//! snapshot, and preempt the same-second collision by removing a newest
//! snapshot whose name matches the second the next export will stamp.
//!
//! [`BackupFileHandleTable`] streams the two fixed snapshot files back to the
//! desktop with the media three-chain shape (ADR 0004): unguessable handles,
//! strictly sequential chunk reads, 300 s TTL, ≤ 8 live handles per account.
//! Like the media table it is process-wide: `readChunk`/`closeHandle` carry
//! no accountId, so all groups must resolve handles from one table.
//!
//! Boundaries: no raw path, number, or key material ever crosses the host
//! boundary — handles are random tokens, and the snapshot files are the only
//! addressable bytes (a two-value `file` enum, never a path).

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::ids::{random_id, stable_hash_id};
use crate::protocol::ApiError;
use crate::service::ServiceError;
use crate::store::Store;

/// The transitional artifact file name, beside the engine's
/// `history-import.ndjson` in the account store directory (§10.2). The
/// engine deletes it when the task leaves `running`; the connector treats it
/// as write-once and rebuilds it before every export attempt.
pub const ARTIFACT_FILE_NAME: &str = "backup-export-input.ndjson";
/// Snapshot root inside one account store directory (§10.6).
pub const SNAPSHOT_ROOT: &str = "SignalBackups";
/// Snapshot directory prefix; the suffix is UTC `yyyy-MM-dd-HH-mm-ss` and
/// lexicographic order is time order (engine export.rs).
pub const SNAPSHOT_PREFIX: &str = "signal-backup-";
/// The engine's transient write name (`-tmp`, renamed away atomically).
pub const SNAPSHOT_TMP_SUFFIX: &str = "-tmp";
/// Per-line artifact cap (§10.2, mirrored by the schema description and the
/// engine's fail-closed gate).
pub const MAX_ARTIFACT_LINE_BYTES: usize = 1_048_576;
/// Total artifact line cap (§10.2): far above the store's own retention
/// bounds — a pure runaway fuse.
pub const MAX_ARTIFACT_LINES: u64 = 4_000_000;
/// Total artifact byte cap (§10.2).
pub const MAX_ARTIFACT_TOTAL_BYTES: u64 = 2_147_483_648;
/// `chat_item.body` cap (§10.2): the store's own 128 KiB inbound body bound,
/// re-checked per exported row.
pub const MAX_ARTIFACT_BODY_BYTES: usize = 131_072;
/// Snapshot list cap, newest-first (§10.4).
pub const MAX_SNAPSHOT_ENTRIES: usize = 32;
/// Raw bytes per `backups.exportFile.readChunk` — the media chain's chunk
/// size (ADR 0004); base64 expands one chunk to 349,528 characters.
pub const CHUNK_BYTES: u64 = 262_144;
/// Handle lifetime — the media chain's TTL backstop.
pub const HANDLE_TTL: Duration = Duration::from_secs(300);
/// Live handles one account may hold at once.
pub const MAX_HANDLES_PER_ACCOUNT: usize = 8;
/// The v1 artifact projects a contact's display name into `givenName` only
/// (the Contact proto face this connector can fill); titles are bounded
/// upstream, so no extra cap is layered on here.
const GIVEN_NAME_SOURCE_BYTES: usize = 256;

/// Why one artifact build refused to start or had to abort. Never carries
/// paths, ids, or content — the wire message is the fixed literal.
#[derive(Debug)]
pub enum BuildError {
    /// The engine's `engine-state.json` registry names no store directory for
    /// this account (or an unreadable/malformed registry): fail closed
    /// instead of writing an artifact into a guessed location.
    NoEngineDirectory,
    /// A store read failed.
    Store(crate::store::StoreError),
    /// The connector's own projection exceeded an artifact cap (§10.2). The
    /// engine would fail-closed on the same artifact; refusing locally keeps
    /// the failure before any engine call.
    CapExceeded(&'static str),
    /// The artifact could not be written (missing account directory, disk
    /// full, permissions).
    Io,
}

impl From<BuildError> for ServiceError {
    fn from(error: BuildError) -> Self {
        match error {
            BuildError::NoEngineDirectory => ServiceError::Api(ApiError::new(
                "UPSTREAM_ERROR",
                "the engine has no data directory registered for this account",
                true,
            )),
            BuildError::Store(error) => ServiceError::Store(error),
            BuildError::CapExceeded(what) => ServiceError::Api(ApiError::new(
                "INVALID_REQUEST",
                format!("the backup export projection exceeds the {what} cap"),
                false,
            )),
            BuildError::Io => ServiceError::Api(ApiError::new(
                "STORAGE_WRITE_FAILED",
                "the backup export artifact could not be written",
                true,
            )),
        }
    }
}

/// Per-cause skip counts from one artifact build (§4.46). Every field is a
/// real measurement of the artifact that was just written — zeros included —
/// so the block is published only after a successful build and stays absent
/// before the first one (honest absence, never fabricated).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkipCounters {
    /// `message_events` rows (contract 1.16) — no reaction face in v1.
    pub skipped_reactions: u64,
    /// `message_edits` rows (contract 1.32) — the row body is the latest
    /// body; edit history has no v1 face.
    pub skipped_edits: u64,
    /// Messages carrying a quote — quotes have no v1 face.
    pub skipped_quotes: u64,
    /// Messages carrying attachment descriptors — bytes/metadata have no v1
    /// face; a row with a body still exports the body.
    pub skipped_attachments: u64,
    /// View-once rows — the burn-on-restore semantics have no v1 face.
    pub skipped_view_once: u64,
    /// Sticker rows — packs have no v1 face.
    pub skipped_stickers: u64,
    /// Contacts-sync skeleton peers whose address cannot project into a
    /// contact identity (§6.5): their chats and items are skipped.
    pub skipped_skeleton_chats: u64,
    /// Rows with a truncated preview body — a preview must never become the
    /// canonical restored body.
    pub skipped_body_truncated: u64,
    /// Rows skipped for every other reason: system rows, remote/admin-delete
    /// tombstones, unconfirmed outgoing rows, empty bodies, and group items
    /// whose author does not resolve to a projected contact.
    pub skipped_rows: u64,
}

impl SkipCounters {
    /// Merge one build's counters into an `exportStatus` result object. Takes
    /// `self` by value: the stored counters are `Copy`, and a fresh copy per
    /// answer cannot race a concurrent rebuild.
    pub(super) fn merge_into(self, result: &mut Value) {
        let Ok(object) = serde_json::to_value(self) else {
            return;
        };
        if let (Some(target), Some(source)) = (result.as_object_mut(), object.as_object()) {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

/// The fixed v1 body of the `account` line's `profileKey`: the store does not
/// track the linked account's real profile key, so the build derives a
/// deterministic stand-in from the account address. Restoration on Android
/// re-reads the live profile from the network; this value only has to be a
/// stable, well-formed 32-byte key.
fn derived_account_profile_key(signal_account: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"kt-signal-connector/backup-export/account-profile-key");
    hasher.update([0]);
    hasher.update(signal_account.as_bytes());
    hex::encode(hasher.finalize())
}

/// Chunk base64 for the file three-chain — the connector's one canonical
/// padded encoder (the media chain's), shared so the two chunk faces cannot
/// drift. The host surface only ever sees the string; the test suite
/// round-trips through it instead of pulling a decoder dependency.
pub fn encode_chunk(data: &[u8]) -> String {
    crate::service::base64_encode(data)
}

/// One projected contact: the artifact id, both identity forms it is known
/// by, and the single-field display-name projection. `id` stays 0 through the
/// collection pass — ids allocate only after every source has contributed, in
/// canonical-key order, so the same store always builds the same artifact.
struct ContactEntry {
    id: u64,
    aci: Option<String>,
    e164: Option<String>,
    given_name: Option<String>,
    /// Every store spelling this contact is known by — the canonical forms
    /// plus the raw peer-key/roster strings: the receive path hashes whatever
    /// form the envelope carried, so every spelling needs a reverse-map entry.
    forms: Vec<String>,
}

/// The identity forms one peer key can carry: a 16-byte ACI (UUID or raw
/// hex) and/or an E.164 number.
struct PeerIdentity {
    aci: Option<String>,
    /// The E.164 spelling exactly as the store carries it (`+<digits>`); the
    /// contact line projects it as a bare u64 (§10.2).
    e164: Option<String>,
}

/// `+<digits>` (no whitespace, length over 1, value over 0) is an E.164 peer
/// key; the spelling is kept verbatim for the identity forms.
fn parse_e164(peer_key: &str) -> Option<String> {
    let digits = peer_key.strip_prefix('+')?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .map(|_| peer_key.to_string())
}

/// A UUID-shaped peer key (or an already-raw 32-char hex string) is an ACI;
/// the canonical artifact form is 32 lowercase hex chars.
fn parse_aci(peer_key: &str) -> Option<String> {
    let hex_chars: String = if peer_key.len() == 36
        && peer_key.as_bytes()[8] == b'-'
        && peer_key.as_bytes()[13] == b'-'
        && peer_key.as_bytes()[18] == b'-'
        && peer_key.as_bytes()[23] == b'-'
    {
        let stripped: String = peer_key.chars().filter(|c| *c != '-').collect();
        stripped
    } else if peer_key.len() == 32 {
        peer_key.to_ascii_lowercase()
    } else {
        return None;
    };
    hex_chars
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| hex_chars.to_ascii_lowercase())
}

fn peer_identity(peer_key: &str, aci_by_peer: &HashMap<String, String>) -> PeerIdentity {
    let e164 = parse_e164(peer_key);
    let mut aci = parse_aci(peer_key);
    // The receive path can key a conversation by the E.164 while the ACI is
    // only known from a later envelope observation (`peer_identities`).
    if aci.is_none() {
        aci = aci_by_peer.get(peer_key).cloned();
    }
    PeerIdentity { aci, e164 }
}

/// The group master key behind a group peer key. The engine's group
/// conversation ids are the standard base64 of the 32-byte master key
/// (engine `decode_group_id`), so the decode mirrors the engine exactly; a
/// group id that does not decode to 32 bytes is a skeleton (§6.5).
fn parse_group_master_key(peer_key: &str) -> Option<String> {
    use crate::service::base64_decode_to_vec;
    let mut decoded = Vec::new();
    base64_decode_to_vec(peer_key.trim(), &mut decoded).ok()?;
    (decoded.len() == 32).then(|| hex::encode(decoded))
}

/// Canonical contact-map key: the ACI when known, else the E.164, else the
/// raw spelling (the skeleton case never reaches the map).
fn canonical_contact_key(identity: &PeerIdentity) -> Option<String> {
    if let Some(aci) = &identity.aci {
        return Some(format!("aci:{aci}"));
    }
    identity.e164.as_ref().map(|e164| format!("e164:{e164}"))
}

/// Merge one identity into the contact set (first-wins on every field). The
/// canonical forms and every raw spelling the caller saw ride `forms` so the
/// sender reverse map covers whichever string the receive envelope hashed.
/// `None` — no contact — is the skeleton case: the peer has neither ACI nor
/// E.164 shape, so nothing about it can project (§6.5).
fn record_contact(
    contacts: &mut BTreeMap<String, ContactEntry>,
    identity: PeerIdentity,
    given_name: Option<String>,
    raw_forms: &[&str],
) -> Option<String> {
    let key = canonical_contact_key(&identity)?;
    let entry = contacts.entry(key.clone()).or_insert_with(|| ContactEntry {
        id: 0,
        aci: None,
        e164: None,
        given_name: None,
        forms: Vec::new(),
    });
    if entry.aci.is_none() {
        entry.aci = identity.aci.clone();
    }
    if entry.e164.is_none() {
        entry.e164 = identity.e164.clone();
    }
    if entry.given_name.is_none() {
        entry.given_name =
            given_name.filter(|name| !name.is_empty() && name.len() <= GIVEN_NAME_SOURCE_BYTES);
    }
    let raw = raw_forms.iter().map(|form| (*form).to_string());
    for form in identity.aci.into_iter().chain(identity.e164).chain(raw) {
        if !form.is_empty() && !entry.forms.contains(&form) {
            entry.forms.push(form);
        }
    }
    Some(key)
}

/// Project one group roster (`extra` JSON `members` array, §4.39) into the
/// contact set so group chat items resolve their authors. The linked account's
/// own membership form is skipped — the engine declares self from the account
/// line, so the account is never a contact row. A roster entry with neither
/// ACI nor E.164 shape is simply not a contact: the row-level `skipped_rows`
/// counter catches its messages, not the roster.
fn record_roster_members(
    extra: &Option<String>,
    aci_by_peer: &HashMap<String, String>,
    signal_account: &str,
    contacts: &mut BTreeMap<String, ContactEntry>,
) {
    let Some(extra) = extra
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
    else {
        return;
    };
    let Some(members) = extra.get("members").and_then(Value::as_array) else {
        return;
    };
    for member in members {
        let Some(member) = member.as_object() else {
            continue;
        };
        let id = member.get("id").and_then(Value::as_str);
        let uuid = member.get("uuid").and_then(Value::as_str);
        if id.is_none() && uuid.is_none() {
            continue;
        }
        // One member, two spellings: `uuid` is the ACI form, `id` the
        // address the sync captured (number or raw uuid). Merge them into
        // one identity so the contact set holds one entry with both forms —
        // never two half-identified contacts.
        let raw_forms: Vec<&str> = [id, uuid].into_iter().flatten().collect();
        let base = uuid
            .filter(|uuid| !uuid.is_empty())
            .or(id)
            .unwrap_or_default();
        if raw_forms.contains(&signal_account) {
            continue;
        }
        let mut identity = peer_identity(base, aci_by_peer);
        if identity.aci.is_none()
            && let Some(form) = raw_forms.iter().find(|form| parse_aci(form).is_some())
        {
            identity.aci = parse_aci(form);
        }
        if identity.e164.is_none()
            && let Some(form) = raw_forms.iter().find(|form| parse_e164(form).is_some())
        {
            identity.e164 = parse_e164(form);
        }
        record_contact(contacts, identity, None, &raw_forms);
    }
}

/// A chat line's recipient reference, resolved after the id-allocation pass.
enum ChatRecipient {
    /// Note to Self: the engine's reserved self recipient (id 0, auto-declared
    /// from the account line — the store's own account cache entry never
    /// becomes a contact row).
    NoteToSelf,
    /// A projected contact, by canonical contact-map key.
    Contact(String),
    /// A group, by master key (`groups`' map key).
    Group(String),
}

/// One conversation the artifact carries a `chat` line (and chat items) for,
/// kept in conversation store-id order — that order becomes the chat id order.
struct PendingChat {
    conversation_id: String,
    recipient: ChatRecipient,
}

/// The artifact file writer: counts lines and bytes against the §10.2 caps as
/// it writes, so a runaway projection fails closed mid-build; a failed build
/// never leaves a partial file behind (`build_artifact` removes it).
struct ArtifactWriter {
    file: std::io::BufWriter<std::fs::File>,
    total_bytes: u64,
    lines: u64,
}

impl ArtifactWriter {
    fn create(path: &Path) -> Result<Self, BuildError> {
        let file = std::fs::File::create(path).map_err(|_| BuildError::Io)?;
        Ok(Self {
            file: std::io::BufWriter::new(file),
            total_bytes: 0,
            lines: 0,
        })
    }

    fn write_line(&mut self, line: &Value) -> Result<(), BuildError> {
        let mut bytes = serde_json::to_vec(line).map_err(|_| BuildError::Io)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_ARTIFACT_LINE_BYTES {
            return Err(BuildError::CapExceeded("per-line byte"));
        }
        self.total_bytes += bytes.len() as u64;
        self.lines += 1;
        if self.total_bytes > MAX_ARTIFACT_TOTAL_BYTES {
            return Err(BuildError::CapExceeded("artifact byte"));
        }
        if self.lines > MAX_ARTIFACT_LINES {
            return Err(BuildError::CapExceeded("line count"));
        }
        self.file.write_all(&bytes).map_err(|_| BuildError::Io)
    }

    fn flush(mut self) -> Result<(), BuildError> {
        self.file.flush().map_err(|_| BuildError::Io)
    }
}

/// Build the §4.46 artifact for one account from the store and return the
/// per-cause skip counters. Runs on the blocking pool — no service lock, no
/// engine lock. The artifact is written whole before the engine call; a
/// failed build removes the partial file, so the engine never sees one.
///
/// Row order follows §10.2's reference rule (a referenced line always
/// precedes its referencing line): account, contacts, groups, chats, then
/// chat items per chat in store order, then the closing `all_chat_folder`.
pub fn build_artifact(
    store: &Store,
    data_dir: &Path,
    account_id: &str,
    signal_account: &str,
) -> Result<SkipCounters, BuildError> {
    let Some(account_dir) = crate::history_import::engine_account_dir(data_dir, signal_account)
    else {
        return Err(BuildError::NoEngineDirectory);
    };
    let artifact_path = account_dir.join(ARTIFACT_FILE_NAME);

    let mut counters = SkipCounters {
        skipped_reactions: store
            .count_reaction_events(account_id)
            .map_err(BuildError::Store)?,
        skipped_edits: store
            .count_message_edits(account_id)
            .map_err(BuildError::Store)?,
        ..SkipCounters::default()
    };

    // -- Identity projection ------------------------------------------------
    let aci_by_peer: HashMap<String, String> = store
        .backup_peer_identity_rows(account_id)
        .map_err(BuildError::Store)?
        .into_iter()
        .collect();
    let mut contacts: BTreeMap<String, ContactEntry> = BTreeMap::new();
    let mut groups: BTreeMap<String, ()> = BTreeMap::new();

    for row in store
        .backup_contact_rows(account_id)
        .map_err(BuildError::Store)?
    {
        match row.kind {
            "contact" => {
                if row.peer_key == signal_account {
                    // The linked account's own cache entry (§4.43): the engine
                    // declares self from the account line, so the account is
                    // never a contact row and its chat is Note to Self.
                    continue;
                }
                let identity = peer_identity(&row.peer_key, &aci_by_peer);
                if record_contact(&mut contacts, identity, Some(row.title), &[&row.peer_key])
                    .is_none()
                {
                    counters.skipped_skeleton_chats += 1;
                }
            }
            "group" => match parse_group_master_key(&row.peer_key) {
                Some(master_key) => {
                    groups.insert(master_key, ());
                    record_roster_members(&row.extra, &aci_by_peer, signal_account, &mut contacts);
                }
                None => counters.skipped_skeleton_chats += 1,
            },
            _ => {}
        }
    }

    let mut chats: Vec<PendingChat> = Vec::new();
    for conversation in store
        .backup_conversation_rows(account_id)
        .map_err(BuildError::Store)?
    {
        let recipient = match conversation.kind {
            "direct" => {
                if conversation.peer_key == signal_account {
                    ChatRecipient::NoteToSelf
                } else {
                    let identity = peer_identity(&conversation.peer_key, &aci_by_peer);
                    match record_contact(
                        &mut contacts,
                        identity,
                        Some(conversation.title.clone()),
                        &[&conversation.peer_key],
                    ) {
                        Some(key) => ChatRecipient::Contact(key),
                        None => {
                            counters.skipped_skeleton_chats += 1;
                            continue;
                        }
                    }
                }
            }
            "group" => match parse_group_master_key(&conversation.peer_key) {
                Some(master_key) => {
                    groups.insert(master_key.clone(), ());
                    ChatRecipient::Group(master_key)
                }
                None => {
                    counters.skipped_skeleton_chats += 1;
                    continue;
                }
            },
            _ => continue,
        };
        chats.push(PendingChat {
            conversation_id: conversation.id,
            recipient,
        });
    }

    // -- Id allocation (deterministic) ---------------------------------------
    // Contacts follow canonical-key order, groups master-key order, chats
    // conversation store-id order; every id allocates only after all sources
    // have contributed, so no reference can dangle.
    let next_id = 1_u64;
    for (i, entry) in (0_u64..).zip(contacts.values_mut()) {
        entry.id = next_id + i;
    }
    let group_ids: HashMap<&str, u64> = groups
        .keys()
        .enumerate()
        .map(|(i, master_key)| (master_key.as_str(), 1_u64 + i as u64))
        .collect();

    // The sender reverse map: every registered spelling of every contact under
    // both conversation namespaces, because the receive path stamps
    // `sender_id = stable_hash_id([account_id, kind, source])` with whatever
    // spelling the envelope carried.
    let mut sender_ids: HashMap<String, u64> = HashMap::new();
    for entry in contacts.values() {
        for form in &entry.forms {
            for namespace in ["direct", "group"] {
                sender_ids.insert(stable_hash_id(&[account_id, namespace, form]), entry.id);
            }
        }
    }

    // -- Write ---------------------------------------------------------------
    let outcome = write_artifact(
        store,
        &artifact_path,
        account_id,
        signal_account,
        &contacts,
        &groups,
        &group_ids,
        &chats,
        &sender_ids,
        &mut counters,
    );
    if outcome.is_err() {
        let _ = std::fs::remove_file(&artifact_path);
    }
    outcome
}

/// The write pass: open the artifact, emit every line, flush. Split from
/// [`build_artifact`] so the error path (partial-file removal) has exactly
/// one owner.
#[allow(clippy::too_many_arguments)]
fn write_artifact(
    store: &Store,
    artifact_path: &Path,
    account_id: &str,
    signal_account: &str,
    contacts: &BTreeMap<String, ContactEntry>,
    groups: &BTreeMap<String, ()>,
    group_ids: &HashMap<&str, u64>,
    chats: &[PendingChat],
    sender_ids: &HashMap<String, u64>,
    counters: &mut SkipCounters,
) -> Result<SkipCounters, BuildError> {
    let display_name = store
        .account_summary(account_id)
        .map_err(BuildError::Store)?
        .and_then(|account| account.display_name)
        .filter(|name| !name.is_empty());
    let mut writer = ArtifactWriter::create(artifact_path)?;
    let write = write_lines(
        &mut writer,
        signal_account,
        display_name.as_deref(),
        contacts,
        groups,
        group_ids,
        chats,
        sender_ids,
        store,
        account_id,
        counters,
    );
    let flush = writer.flush();
    match (write, flush) {
        (Ok(()), Ok(())) => Ok(*counters),
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
    }
}

/// Emit the §10.2 line set in reference order.
#[allow(clippy::too_many_arguments)]
fn write_lines(
    writer: &mut ArtifactWriter,
    signal_account: &str,
    display_name: Option<&str>,
    contacts: &BTreeMap<String, ContactEntry>,
    groups: &BTreeMap<String, ()>,
    group_ids: &HashMap<&str, u64>,
    chats: &[PendingChat],
    sender_ids: &HashMap<String, u64>,
    store: &Store,
    account_id: &str,
    counters: &mut SkipCounters,
) -> Result<(), BuildError> {
    // account — the first line, exactly once (§10.2).
    let mut account_line = json!({
        "type": "account",
        "profileKey": derived_account_profile_key(signal_account),
    });
    if let Some(name) = display_name {
        account_line["givenName"] = Value::String(name.to_string());
    }
    writer.write_line(&account_line)?;

    // contacts — canonical-key order (the allocation order).
    for entry in contacts.values() {
        let mut line = json!({ "type": "contact", "id": entry.id });
        if let Some(aci) = &entry.aci {
            line["aci"] = Value::String(aci.clone());
        }
        if let Some(e164) = &entry.e164 {
            // parse_e164 validated the digits; the line form is a bare u64.
            if let Ok(number) = e164.trim_start_matches('+').parse::<u64>() {
                line["e164"] = json!(number);
            }
        }
        if let Some(name) = &entry.given_name {
            line["givenName"] = Value::String(name.clone());
        }
        writer.write_line(&line)?;
    }

    // groups — master-key order.
    for master_key in groups.keys() {
        writer.write_line(&json!({
            "type": "group",
            "id": group_ids[master_key.as_str()],
            "masterKey": master_key,
        }))?;
    }

    // chats — conversation store-id order.
    for (index, chat) in chats.iter().enumerate() {
        let recipient = match &chat.recipient {
            ChatRecipient::NoteToSelf => 0_u64,
            ChatRecipient::Contact(key) => contacts[key].id,
            ChatRecipient::Group(master_key) => group_ids[master_key.as_str()],
        };
        writer.write_line(&json!({
            "type": "chat",
            "id": index as u64 + 1,
            "recipient": recipient,
        }))?;
    }

    // chat items — per chat in chat order, messages oldest first (the store
    // read's `sent_at ASC, id ASC`).
    for (index, chat) in chats.iter().enumerate() {
        let chat_id = index as u64 + 1;
        for row in store
            .backup_message_rows(account_id, &chat.conversation_id)
            .map_err(BuildError::Store)?
        {
            // Row-level gates first: system rows and tombstones carry no
            // conversational content; an unconfirmed outgoing row must not
            // masquerade as delivered history on the restored device.
            if row.status == "system"
                || row.direction == "system"
                || row.status == "remote-deleted"
                || row.admin_deleted
            {
                counters.skipped_rows += 1;
                continue;
            }
            if row.direction == "outgoing" && !matches!(row.status, "sent" | "delivered" | "read") {
                counters.skipped_rows += 1;
                continue;
            }
            // Column counters: features with no v1 face. A row carrying one
            // still exports its body when it has one.
            if rich_has_view_once(row.rich_json.as_deref()) {
                counters.skipped_view_once += 1;
            }
            if row.sticker_json.is_some() {
                counters.skipped_stickers += 1;
            }
            if row.has_quote {
                counters.skipped_quotes += 1;
            }
            // Attachment face (S13, contract 1.262): descriptors ride the
            // line with the pointer face — the §4.38 v2 locator shape
            // verbatim (the project_pointer_common isomorph; the engine's
            // frame builder is its exact inverse). Entries that cannot build
            // a valid official frame are the honest hole: the official
            // MessageAttachment requires a FilePointer with an integrity
            // check (libsignal file.rs NoFilePointer/MissingIntegrityCheck;
            // plaintextHash⇒key, digest⇒key+transit pair), so a
            // metadata-only entry would fail the whole snapshot. A row that
            // lost any entry counts `skippedAttachments` once; a fully
            // projected row does not (nothing was skipped).
            let (attachment_entries, attachments_dropped) = project_row_attachments(&row);
            if attachments_dropped {
                counters.skipped_attachments += 1;
            }
            let body = row.body.as_deref().unwrap_or("");
            if body.is_empty() && attachment_entries.is_empty() {
                counters.skipped_rows += 1;
                continue;
            };
            if row.body_truncated {
                // A bounded preview must never become the canonical restored
                // body — counted here only, never in `skippedRows` too.
                counters.skipped_body_truncated += 1;
                continue;
            }
            if body.len() > MAX_ARTIFACT_BODY_BYTES {
                return Err(BuildError::CapExceeded("chat item body"));
            }
            let author = if row.direction == "outgoing" {
                0_u64
            } else if let Some(id) = sender_ids.get(&row.sender_id) {
                *id
            } else {
                // A group or direct author the projection never met: the item
                // cannot reference a contact that does not exist.
                counters.skipped_rows += 1;
                continue;
            };
            let mut line = json!({
                "type": "chat_item",
                "chat": chat_id,
                "author": author,
                "dateSent": row.sent_at,
                "direction": row.direction,
                "dateReceived": row.received_at.unwrap_or(row.sent_at),
                "body": body,
            });
            if !attachment_entries.is_empty() {
                line["attachments"] = json!(attachment_entries);
            }
            writer.write_line(&line)?;
        }
    }

    // The closing marker (§6.1): emitted so the frame set is explicit rather
    // than relying on the engine's default completion.
    writer.write_line(&json!({ "type": "all_chat_folder" }))?;
    Ok(())
}

/// Whether a row's stored rich payload carries the view-once marker (the
/// serialized `NormalizedRich` camelCase shape).
fn rich_has_view_once(rich_json: Option<&str>) -> bool {
    let Some(raw) = rich_json else {
        return false;
    };
    let Ok(rich) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    ["viewOnce", "viewOnceInvalid"]
        .iter()
        .any(|key| rich.get(key).and_then(Value::as_bool).unwrap_or(false))
}

/// The row's artifact attachment entries (S13, contract 1.262): descriptors
/// (`attachments_json`) joined with their index-aligned locator faces
/// (`attachment_locators`), projected into the §4.38 v2 locator shape —
/// `project_pointer_common`'s output keys verbatim, because the engine's
/// frame builder (backup/artifact.rs `build_attachment`) is its exact
/// inverse and the official validator (libsignal message-backup file.rs) is
/// the shared referee. Returns `(entries, dropped)`: a row that lost any
/// entry (malformed columns, broken index alignment, or a pointer face that
/// cannot build a valid official frame) answers `dropped = true` — the
/// row's `skippedAttachments` cause, exported body intact.
fn project_row_attachments(row: &crate::store::BackupMessageRow) -> (Vec<Value>, bool) {
    let Some(raw) = row.attachments_json.as_deref() else {
        return (Vec::new(), false);
    };
    let Ok(attachments) = serde_json::from_str::<Vec<crate::engine::NormalizedAttachment>>(raw)
    else {
        return (Vec::new(), true);
    };
    let locators: Vec<crate::store::HistoryAttachmentLocator> = row
        .attachment_locators_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    let mut dropped = false;
    let mut entries = Vec::with_capacity(attachments.len());
    for (index, attachment) in attachments.iter().enumerate() {
        match project_attachment_entry(attachment, locators.get(index)) {
            Some(entry) => entries.push(entry),
            None => dropped = true,
        }
    }
    (entries, dropped)
}

/// One entry of the artifact attachment face. `None` = the entry cannot
/// build a valid official frame and is the row's honest hole: the official
/// MessageAttachment requires a FilePointer whose LocatorInfo carries an
/// integrity check (libsignal file.rs `MissingIntegrityCheck`), the
/// plaintextHash form additionally requires the key (the official
/// content/key ladder), and the digest form requires key + transit pair
/// (`EncryptedDigestMissingTransitInfo`/`MissingKey`) with the cdn pair
/// all-or-nothing (`TransitCdnMismatch`).
fn project_attachment_entry(
    attachment: &crate::engine::NormalizedAttachment,
    locator: Option<&crate::store::HistoryAttachmentLocator>,
) -> Option<Value> {
    let mut entry = serde_json::Map::new();
    if let Some(content_type) = attachment.content_type.as_deref().filter(|t| !t.is_empty()) {
        entry.insert("contentType".into(), json!(content_type));
    }
    if let Some(filename) = attachment.filename.as_deref().filter(|f| !f.is_empty()) {
        entry.insert("fileName".into(), json!(filename));
    }
    if let Some(size) = attachment.size {
        entry.insert("size".into(), json!(size));
    }
    // The official MessageAttachment.Flag is mutually exclusive; the store's
    // three booleans project in the enum's own order, absence = Flag::None
    // (no key — the engine's frame builder maps it back one to one).
    if attachment.is_voice_note {
        entry.insert("flag".into(), json!("voiceMessage"));
    } else if attachment.is_borderless {
        entry.insert("flag".into(), json!("borderless"));
    } else if attachment.is_gif {
        entry.insert("flag".into(), json!("gif"));
    }
    if let Some(width) = attachment.width {
        entry.insert("width".into(), json!(width));
    }
    if let Some(height) = attachment.height {
        entry.insert("height".into(), json!(height));
    }
    if let Some(caption) = attachment.caption.as_deref().filter(|c| !c.is_empty()) {
        entry.insert("caption".into(), json!(caption));
    }
    if let Some(blur_hash) = attachment.blur_hash.as_deref().filter(|b| !b.is_empty()) {
        entry.insert("blurHash".into(), json!(blur_hash));
    }
    // The incremental pair rides both-or-neither (the §4.88 ingest drops a
    // half pair, so this join is exact).
    if let (Some(mac), Some(chunk)) = (&attachment.incremental_mac, attachment.chunk_size) {
        entry.insert("incrementalMac".into(), json!(mac));
        entry.insert("chunkSize".into(), json!(chunk));
    }
    let locator = locator?;
    let key = locator.key.as_deref().filter(|key| !key.is_empty())?;
    let plaintext_hash = locator
        .plaintext_hash
        .as_deref()
        .filter(|hash| !hash.is_empty());
    let digest = locator
        .digest
        .as_deref()
        .filter(|digest| !digest.is_empty());
    let integrity = if plaintext_hash.is_some() {
        "plaintextHash"
    } else if digest.is_some() {
        "digest"
    } else {
        return None;
    };
    let transit = match (locator.cdn_key.as_deref(), locator.cdn_number) {
        (None, None) => None,
        (Some(cdn_key), Some(cdn_number)) if !cdn_key.is_empty() => Some((cdn_key, cdn_number)),
        _ => return None,
    };
    if integrity == "digest" && transit.is_none() {
        return None;
    }
    let mut face = serde_json::Map::new();
    face.insert("key".into(), json!(key));
    if let Some((cdn_key, cdn_number)) = transit {
        face.insert("cdnKey".into(), json!(cdn_key));
        face.insert("cdnNumber".into(), json!(cdn_number));
        // The upload stamp rides the transit pair only (the official
        // UnexpectedTransitCdnUploadTimestamp rule).
        if let Some(timestamp) = locator.upload_timestamp.filter(|ts| *ts > 0) {
            face.insert("uploadTimestamp".into(), json!(timestamp));
        }
    }
    match integrity {
        "plaintextHash" => {
            face.insert("plaintextHash".into(), json!(plaintext_hash.unwrap()));
        }
        _ => {
            face.insert("digest".into(), json!(digest.unwrap()));
        }
    }
    entry.insert("locator".into(), Value::Object(face));
    Some(Value::Object(entry))
}

// -------------------------------------------------------------------------
// Plaintext chat export (contract revision 1.132, §4.115): the connector-
// local store projection — the engine takes zero part in the data path
// (no network, no artifact in the engine's data tree; the build below never
// calls the engine), and the §4.46 machine above moves
// not at all. The line set is the plaintext family's own: identity
// projection (account/contacts/groups/chats) reuses this module's
// deterministic machinery verbatim; message lines widen the projection to
// the faces the owner admitted — quotes, sticker metadata, attachment
// metadata placeholders, reactions, receipt stamps — while the row gates,
// the caps, and the failure discipline stay byte-identical to §4.46.
// Red line 3: bodies, quote previews, file names, and captions never enter
// logs or error messages — counters and content-free error classes only.
// -------------------------------------------------------------------------

/// Plaintext artifact root inside the connector's state directory (§4.115):
/// `plaintext-exports/<accountId>/`.
pub const PLAINTEXT_DIR_NAME: &str = "plaintext-exports";
/// Artifact file name prefix; the infix is UTC `yyyy-MM-dd-HH-mm-ss` (the
/// §4.46 snapshot-name timestamp shape), so lexicographic order is time
/// order.
pub const PLAINTEXT_FILE_PREFIX: &str = "plaintext-export-";
/// Artifact file name suffix.
pub const PLAINTEXT_FILE_SUFFIX: &str = ".jsonl";
/// The connector's transient write name (`-tmp`, renamed away atomically —
/// red line 4: an interrupted build never leaves an addressable partial
/// product).
pub const PLAINTEXT_TMP_SUFFIX: &str = "-tmp";

/// What one finished plaintext build produced: the artifact's file name
/// inside the account's `plaintext-exports/` directory, its settled line and
/// byte counts, and the per-cause skip counters. Numbers only — content
/// never crosses into the task registry (red line 3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextBuildOutcome {
    pub file_name: String,
    pub lines: u64,
    pub bytes: u64,
    pub counters: SkipCounters,
}

/// The plaintext task's lifecycle states — the engine's export-task states
/// mirrored connector-side (`running` → `completed` | `failed`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextTaskState {
    Running,
    Completed,
    Failed,
}

impl PlaintextTaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// One account's latest plaintext task — the `backups.exportStatus`
/// projection source when the plaintext task is the account's most recent
/// export (§4.115). The error face is a content-free class literal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextTaskSnapshot {
    pub state: PlaintextTaskState,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub lines: Option<u64>,
    pub bytes: Option<u64>,
    pub error: Option<&'static str>,
    pub counters: Option<SkipCounters>,
}

/// Connector-local per-account plaintext task slots (§4.115): one task per
/// account at a time, in-memory like the engine's own registry (a connector
/// restart reads idle while the on-disk artifacts stay listed). Bounded by
/// the account ceiling; a fresh `begin` replaces the settled record.
#[derive(Default)]
pub struct PlaintextTaskRegistry {
    entries: StdMutex<HashMap<String, PlaintextTaskSnapshot>>,
}

impl PlaintextTaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim the account's slot for a new build; false while a build runs.
    /// A settled record (completed/failed) is replaced — the slot guards
    /// concurrency, not history.
    pub fn begin(&self, account_id: &str, started_at_ms: u64) -> bool {
        let mut entries = self.entries.lock().expect("plaintext task registry mutex");
        if entries
            .get(account_id)
            .is_some_and(|entry| entry.state == PlaintextTaskState::Running)
        {
            return false;
        }
        entries.insert(
            account_id.to_string(),
            PlaintextTaskSnapshot {
                state: PlaintextTaskState::Running,
                started_at_ms,
                finished_at_ms: None,
                lines: None,
                bytes: None,
                error: None,
                counters: None,
            },
        );
        true
    }

    /// Settle the running build as completed. Defensive no-op when the
    /// account holds no running entry — a settle can never invent a task.
    pub fn complete(&self, account_id: &str, finished_at_ms: u64, outcome: &PlaintextBuildOutcome) {
        let mut entries = self.entries.lock().expect("plaintext task registry mutex");
        let Some(entry) = entries.get_mut(account_id) else {
            return;
        };
        if entry.state != PlaintextTaskState::Running {
            return;
        }
        entry.state = PlaintextTaskState::Completed;
        entry.finished_at_ms = Some(finished_at_ms);
        entry.lines = Some(outcome.lines);
        entry.bytes = Some(outcome.bytes);
        entry.counters = Some(outcome.counters);
    }

    /// Settle the running build as failed with a content-free error class.
    pub fn fail(&self, account_id: &str, finished_at_ms: u64, error: &'static str) {
        let mut entries = self.entries.lock().expect("plaintext task registry mutex");
        let Some(entry) = entries.get_mut(account_id) else {
            return;
        };
        if entry.state != PlaintextTaskState::Running {
            return;
        }
        entry.state = PlaintextTaskState::Failed;
        entry.finished_at_ms = Some(finished_at_ms);
        entry.error = Some(error);
    }

    /// The account's latest task record, if any.
    pub fn latest(&self, account_id: &str) -> Option<PlaintextTaskSnapshot> {
        self.entries
            .lock()
            .expect("plaintext task registry mutex")
            .get(account_id)
            .cloned()
    }

    /// Drop the account's record — the account-delete path (a task record
    /// cannot outlive its account session).
    pub fn clear(&self, account_id: &str) {
        self.entries
            .lock()
            .expect("plaintext task registry mutex")
            .remove(account_id);
    }
}

/// The content-free error classes a failed plaintext build reports through
/// `backups.exportStatus` (red line 3: classes, never detail).
pub fn plaintext_error_class(error: &BuildError) -> &'static str {
    match error {
        // Unreachable: the plaintext build resolves no engine directory.
        BuildError::NoEngineDirectory => "io",
        BuildError::Store(_) => "store-read",
        BuildError::CapExceeded(_) => "cap-exceeded",
        BuildError::Io => "io",
    }
}

/// The class a panicked build reports — the blocking-pool join failure has
/// no [`BuildError`], and the slot must not stick `running`.
pub const PLAINTEXT_PANIC_ERROR_CLASS: &str = "internal";

/// The account's plaintext artifact directory (connector state dir, never
/// the engine's tree).
pub fn plaintext_export_root(state_dir: &Path, account_id: &str) -> PathBuf {
    state_dir.join(PLAINTEXT_DIR_NAME).join(account_id)
}

fn is_plaintext_file_name(name: &str) -> bool {
    name.starts_with(PLAINTEXT_FILE_PREFIX)
        && name.ends_with(PLAINTEXT_FILE_SUFFIX)
        && !name.ends_with(PLAINTEXT_TMP_SUFFIX)
}

/// One listed plaintext artifact: file name and byte size (a file that
/// vanished mid-listing reports 0 — the snapshot listing's damaged-entry
/// honesty).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextArtifactEntry {
    pub name: String,
    pub bytes: u64,
}

/// The account's plaintext artifacts, newest-first (name sort) — the §4.46
/// snapshot-listing discipline mirrored.
pub fn list_plaintext_artifacts(root: &Path) -> Vec<PlaintextArtifactEntry> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut artifacts: Vec<PlaintextArtifactEntry> = entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| is_plaintext_file_name(name))
        .map(|name| PlaintextArtifactEntry {
            bytes: std::fs::metadata(root.join(&name))
                .map(|metadata| metadata.len())
                .unwrap_or(0),
            name,
        })
        .collect();
    artifacts.sort_by(|a, b| b.name.cmp(&a.name));
    artifacts
}

/// The newest plaintext artifact's path, if any — the only file the
/// `plaintext_jsonl` arm of `backups.exportFile.open` can address.
pub fn latest_plaintext_artifact(root: &Path) -> Option<PathBuf> {
    list_plaintext_artifacts(root)
        .into_iter()
        .next()
        .map(|entry| root.join(entry.name))
}

fn current_plaintext_candidate_name() -> Option<String> {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!(
        "{PLAINTEXT_FILE_PREFIX}{}{PLAINTEXT_FILE_SUFFIX}",
        format_utc_timestamp_seconds(secs)
    ))
}

fn remove_file_best_effort(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(kind = %error.kind(), "plaintext export cleanup could not remove a file");
        }
    }
}

/// The pre-build cleanup (§4.115 — the §10.6 caretaker mirrored onto files):
/// remove `-tmp` residue, keep only the most recent artifact, and remove a
/// newest artifact whose name equals the second the next build will stamp
/// (the same-second collision preempted).
pub fn prepare_plaintext_dir_for_export(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(PLAINTEXT_TMP_SUFFIX) {
            remove_file_best_effort(&root.join(&name));
            continue;
        }
        if is_plaintext_file_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    names.reverse();
    let candidate = current_plaintext_candidate_name();
    for (index, name) in names.into_iter().enumerate() {
        if index == 0 && Some(&name) != candidate.as_ref() {
            continue;
        }
        remove_file_best_effort(&root.join(name));
    }
}

/// Remove the account's whole plaintext artifact directory — the
/// account-delete path (an export product never outlives its account
/// session). Best effort, like the snapshot caretaker: the store row delete
/// is the authoritative half.
pub fn clear_plaintext_artifacts(state_dir: &Path, account_id: &str) {
    let root = plaintext_export_root(state_dir, account_id);
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(kind = %error.kind(), "plaintext export artifacts could not be removed");
        }
    }
}

/// Build the §4.115 plaintext JSONL artifact for one account from the store
/// and return the settled outcome. Runs on the blocking pool — no service
/// lock, no engine lock, no engine contact at all (red line 1). The artifact
/// is written to a `-tmp` name and renamed into place atomically; a failed
/// build removes the partial file, so a partial product is never addressable
/// (red line 4).
pub fn build_plaintext_artifact(
    store: &Store,
    account_id: &str,
    signal_account: &str,
) -> Result<PlaintextBuildOutcome, BuildError> {
    let root = plaintext_export_root(store.state_dir(), account_id);
    std::fs::create_dir_all(&root).map_err(|_| BuildError::Io)?;
    // Windows-only hardening, the launcher's own pattern (main.rs): on unix
    // the artifact tree inherits the state directory's permissions.
    #[cfg(windows)]
    crate::ipc::harden_private_directory(&root).map_err(|_| BuildError::Io)?;
    prepare_plaintext_dir_for_export(&root);
    let Some(file_name) = current_plaintext_candidate_name() else {
        return Err(BuildError::Io);
    };
    let tmp_path = root.join(format!("{file_name}{PLAINTEXT_TMP_SUFFIX}"));
    match build_plaintext_into(store, account_id, signal_account, &tmp_path) {
        Ok(built) => {
            if std::fs::rename(&tmp_path, root.join(&file_name)).is_err() {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(BuildError::Io);
            }
            Ok(PlaintextBuildOutcome {
                file_name,
                lines: built.0,
                bytes: built.1,
                counters: built.2,
            })
        }
        Err(error) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(error)
        }
    }
}

/// One chat the plaintext artifact carries, with the self-describing keys an
/// independent JSONL parser needs (the §4.46 `PendingChat` widened by `kind`
/// and `title` — recipient id spaces are per-kind, so the line says which).
struct PlaintextChat {
    conversation_id: String,
    kind: &'static str,
    recipient: ChatRecipient,
    title: String,
}

/// The write pass's intermediate: settled line count, byte count, counters.
type PlaintextBuilt = (u64, u64, SkipCounters);

/// The collection + write pass behind [`build_plaintext_artifact`], split so
/// the error path (partial-file removal) has exactly one owner.
fn build_plaintext_into(
    store: &Store,
    account_id: &str,
    signal_account: &str,
    tmp_path: &Path,
) -> Result<PlaintextBuilt, BuildError> {
    let mut counters = SkipCounters::default();

    // -- Identity projection (the §4.46 machinery verbatim) ----------------
    let aci_by_peer: HashMap<String, String> = store
        .backup_peer_identity_rows(account_id)
        .map_err(BuildError::Store)?
        .into_iter()
        .collect();
    let mut contacts: BTreeMap<String, ContactEntry> = BTreeMap::new();
    // master key → first non-empty title the sync/conversation rows offered.
    let mut groups: BTreeMap<String, String> = BTreeMap::new();
    let mut merge_group_title = |master_key: String, title: &str| {
        let entry = groups.entry(master_key).or_default();
        if entry.is_empty() && !title.is_empty() {
            title.clone_into(entry);
        }
    };

    for row in store
        .backup_contact_rows(account_id)
        .map_err(BuildError::Store)?
    {
        match row.kind {
            "contact" => {
                if row.peer_key == signal_account {
                    continue;
                }
                let identity = peer_identity(&row.peer_key, &aci_by_peer);
                if record_contact(&mut contacts, identity, Some(row.title), &[&row.peer_key])
                    .is_none()
                {
                    counters.skipped_skeleton_chats += 1;
                }
            }
            "group" => match parse_group_master_key(&row.peer_key) {
                Some(master_key) => {
                    merge_group_title(master_key, &row.title);
                    record_roster_members(&row.extra, &aci_by_peer, signal_account, &mut contacts);
                }
                None => counters.skipped_skeleton_chats += 1,
            },
            _ => {}
        }
    }

    let mut chats: Vec<PlaintextChat> = Vec::new();
    for conversation in store
        .backup_conversation_rows(account_id)
        .map_err(BuildError::Store)?
    {
        let recipient = match conversation.kind {
            "direct" => {
                if conversation.peer_key == signal_account {
                    ChatRecipient::NoteToSelf
                } else {
                    let identity = peer_identity(&conversation.peer_key, &aci_by_peer);
                    match record_contact(
                        &mut contacts,
                        identity,
                        Some(conversation.title.clone()),
                        &[&conversation.peer_key],
                    ) {
                        Some(key) => ChatRecipient::Contact(key),
                        None => {
                            counters.skipped_skeleton_chats += 1;
                            continue;
                        }
                    }
                }
            }
            "group" => match parse_group_master_key(&conversation.peer_key) {
                Some(master_key) => {
                    merge_group_title(master_key.clone(), &conversation.title);
                    ChatRecipient::Group(master_key)
                }
                None => {
                    counters.skipped_skeleton_chats += 1;
                    continue;
                }
            },
            _ => continue,
        };
        chats.push(PlaintextChat {
            conversation_id: conversation.id,
            kind: conversation.kind,
            recipient,
            title: conversation.title,
        });
    }

    // -- Id allocation (deterministic, the §4.46 order) --------------------
    let next_id = 1_u64;
    for (i, entry) in (0_u64..).zip(contacts.values_mut()) {
        entry.id = next_id + i;
    }
    let group_ids: HashMap<&str, u64> = groups
        .keys()
        .enumerate()
        .map(|(i, master_key)| (master_key.as_str(), 1_u64 + i as u64))
        .collect();
    let mut sender_ids: HashMap<String, u64> = HashMap::new();
    for entry in contacts.values() {
        for form in &entry.forms {
            for namespace in ["direct", "group"] {
                sender_ids.insert(stable_hash_id(&[account_id, namespace, form]), entry.id);
            }
        }
    }

    // -- Write ---------------------------------------------------------------
    let display_name = store
        .account_summary(account_id)
        .map_err(BuildError::Store)?
        .and_then(|account| account.display_name)
        .filter(|name| !name.is_empty());
    let mut writer = ArtifactWriter::create(tmp_path)?;
    let write = write_plaintext_lines(
        &mut writer,
        signal_account,
        display_name.as_deref(),
        &contacts,
        &groups,
        &group_ids,
        &chats,
        &sender_ids,
        store,
        account_id,
        &mut counters,
    );
    let lines = writer.lines;
    let total_bytes = writer.total_bytes;
    let flush = writer.flush();
    match (write, flush) {
        (Ok(()), Ok(())) => Ok((lines, total_bytes, counters)),
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
    }
}

/// Resolve a quote's author to the artifact's contact id: 0 for the linked
/// account, the sender reverse map for a peer spelling, None when the
/// projection never met the author (the caller then omits the key or rides
/// the raw spelling — never a dangling reference). Reaction authors do not
/// ride this: `message_events.actor_id` is stored already in the sender-map
/// key form (or the store account id for self), so the reaction arm looks it
/// up directly.
fn resolve_plaintext_author(
    author: &str,
    account_id: &str,
    signal_account: &str,
    sender_ids: &HashMap<String, u64>,
) -> Option<u64> {
    if author == signal_account {
        return Some(0);
    }
    for namespace in ["direct", "group"] {
        if let Some(id) = sender_ids.get(&stable_hash_id(&[account_id, namespace, author])) {
            return Some(*id);
        }
    }
    None
}

/// Project the stored quote snapshot (NormalizedQuote verbatim: the quoted
/// message's upstream timestamp, the bounded preview, the quoted-attachment
/// metadata) plus the join keys — the resolved author id and, when the store
/// resolved the target row, `messageId`. An author the projection never met
/// rides `authorRaw` verbatim rather than dangling.
fn project_plaintext_quote(
    quote: &crate::engine::NormalizedQuote,
    quote_message_id: Option<&str>,
    account_id: &str,
    signal_account: &str,
    sender_ids: &HashMap<String, u64>,
) -> Value {
    let mut arm = json!({
        "id": quote.id,
        "text": quote.text,
    });
    if !quote.author.is_empty() {
        match resolve_plaintext_author(&quote.author, account_id, signal_account, sender_ids) {
            Some(id) => arm["author"] = json!(id),
            None => arm["authorRaw"] = Value::String(quote.author.clone()),
        }
    }
    if let Some(message_id) = quote_message_id {
        arm["messageId"] = Value::String(message_id.to_string());
    }
    if !quote.attachments.is_empty()
        && let Ok(value) = serde_json::to_value(&quote.attachments)
    {
        arm["attachments"] = value;
    }
    arm
}

/// Emit the §4.115 line set in reference order.
#[allow(clippy::too_many_arguments)]
fn write_plaintext_lines(
    writer: &mut ArtifactWriter,
    signal_account: &str,
    display_name: Option<&str>,
    contacts: &BTreeMap<String, ContactEntry>,
    groups: &BTreeMap<String, String>,
    group_ids: &HashMap<&str, u64>,
    chats: &[PlaintextChat],
    sender_ids: &HashMap<String, u64>,
    store: &Store,
    account_id: &str,
    counters: &mut SkipCounters,
) -> Result<(), BuildError> {
    // account — the first line, exactly once: the archive's owner, by its own
    // address spelling (the product is the user's own plaintext data; the
    // raw address never enters logs or error messages).
    let mut account_line = json!({
        "type": "account",
        "account": signal_account,
    });
    if let Some(name) = display_name {
        account_line["givenName"] = Value::String(name.to_string());
    }
    writer.write_line(&account_line)?;

    // contacts — canonical-key order (the allocation order).
    for entry in contacts.values() {
        let mut line = json!({ "type": "contact", "id": entry.id });
        if let Some(aci) = &entry.aci {
            line["aci"] = Value::String(aci.clone());
        }
        if let Some(e164) = &entry.e164
            && let Ok(number) = e164.trim_start_matches('+').parse::<u64>()
        {
            line["e164"] = json!(number);
        }
        if let Some(name) = &entry.given_name {
            line["givenName"] = Value::String(name.clone());
        }
        writer.write_line(&line)?;
    }

    // groups — master-key order.
    for (master_key, title) in groups {
        let mut line = json!({
            "type": "group",
            "id": group_ids[master_key.as_str()],
            "masterKey": master_key,
        });
        if !title.is_empty() {
            line["title"] = Value::String(title.clone());
        }
        writer.write_line(&line)?;
    }

    // chats — conversation store-id order, self-describing (kind + recipient
    // + title) so an independent parser never guesses an id space.
    for (index, chat) in chats.iter().enumerate() {
        let recipient = match &chat.recipient {
            ChatRecipient::NoteToSelf => 0_u64,
            ChatRecipient::Contact(key) => contacts[key].id,
            ChatRecipient::Group(master_key) => group_ids[master_key.as_str()],
        };
        let mut line = json!({
            "type": "chat",
            "id": index as u64 + 1,
            "kind": chat.kind,
            "recipient": recipient,
        });
        if !chat.title.is_empty() {
            line["title"] = Value::String(chat.title.clone());
        }
        writer.write_line(&line)?;
    }

    // messages — per chat in chat order, oldest first.
    for (index, chat) in chats.iter().enumerate() {
        let chat_id = index as u64 + 1;
        let reaction_page = store
            .plaintext_reaction_rows(account_id, &chat.conversation_id)
            .map_err(BuildError::Store)?;
        if reaction_page.truncated {
            let total = store
                .count_conversation_reactions(account_id, &chat.conversation_id)
                .map_err(BuildError::Store)?;
            counters.skipped_reactions += total.saturating_sub(reaction_page.rows.len() as u64);
        }
        let mut reactions: HashMap<u64, Vec<&crate::store::PlaintextReactionRow>> = HashMap::new();
        for row in &reaction_page.rows {
            reactions.entry(row.target_timestamp).or_default().push(row);
        }
        let mut reactions_projected = 0_u64;
        for row in store
            .plaintext_message_rows(account_id, &chat.conversation_id)
            .map_err(BuildError::Store)?
        {
            write_plaintext_message(
                writer,
                chat_id,
                &row,
                &reactions,
                &mut reactions_projected,
                sender_ids,
                account_id,
                signal_account,
                counters,
            )?;
        }
        // Reactions whose target row never emitted a line (skipped gates or
        // a target retention pruned) are counted, not silently dropped.
        let read = reaction_page.rows.len() as u64;
        counters.skipped_reactions += read.saturating_sub(reactions_projected);
    }
    Ok(())
}

/// Project one message row into its plaintext line — or count the skip cause
/// and move on. The row gates are §4.46's verbatim (system rows, tombstones,
/// unconfirmed outgoing rows never masquerade as delivered history; a
/// truncated preview never becomes export text); a row with neither body nor
/// quote nor sticker nor attachments carries no conversational content.
#[allow(clippy::too_many_arguments)]
fn write_plaintext_message(
    writer: &mut ArtifactWriter,
    chat_id: u64,
    row: &crate::store::PlaintextMessageRow,
    reactions: &HashMap<u64, Vec<&crate::store::PlaintextReactionRow>>,
    reactions_projected: &mut u64,
    sender_ids: &HashMap<String, u64>,
    account_id: &str,
    signal_account: &str,
    counters: &mut SkipCounters,
) -> Result<(), BuildError> {
    if row.status == "system"
        || row.direction == "system"
        || row.status == "remote-deleted"
        || row.admin_deleted
    {
        counters.skipped_rows += 1;
        return Ok(());
    }
    if row.direction == "outgoing" && !matches!(row.status, "sent" | "delivered" | "read") {
        counters.skipped_rows += 1;
        return Ok(());
    }
    if rich_has_view_once(row.rich_json.as_deref()) {
        counters.skipped_view_once += 1;
    }
    let author = if row.direction == "outgoing" {
        0_u64
    } else if let Some(id) = sender_ids.get(&row.sender_id) {
        *id
    } else {
        counters.skipped_rows += 1;
        return Ok(());
    };

    // The body arm: a truncated preview counts and never becomes text.
    let body = row.body.as_deref().filter(|body| !body.is_empty());
    if row.body_truncated && body.is_some() {
        counters.skipped_body_truncated += 1;
    }
    let export_body = body.filter(|_| !row.body_truncated);
    if let Some(body) = export_body
        && body.len() > MAX_ARTIFACT_BODY_BYTES
    {
        return Err(BuildError::CapExceeded("message body"));
    }

    // The quote arm: the snapshot verbatim plus the join keys; a resolved
    // target with no usable snapshot still rides `messageId` alone; a stored
    // snapshot that no longer parses counts and drops.
    let mut quote_arm: Option<Value> = None;
    if let Some(raw) = row.quote_snapshot.as_deref() {
        match serde_json::from_str::<crate::engine::NormalizedQuote>(raw) {
            Ok(quote) => {
                quote_arm = Some(project_plaintext_quote(
                    &quote,
                    row.quote_message_id.as_deref(),
                    account_id,
                    signal_account,
                    sender_ids,
                ));
            }
            Err(_) => counters.skipped_quotes += 1,
        }
    }
    if quote_arm.is_none()
        && let Some(target) = row.quote_message_id.as_deref()
    {
        quote_arm = Some(json!({ "messageId": target }));
    }

    // The sticker arm: NormalizedSticker metadata verbatim (bytes ride the
    // attachment face, which v1 never carries).
    let mut sticker_arm: Option<Value> = None;
    if let Some(raw) = row.sticker_json.as_deref() {
        match serde_json::from_str::<crate::engine::NormalizedSticker>(raw) {
            Ok(sticker) => sticker_arm = serde_json::to_value(&sticker).ok(),
            Err(_) => counters.skipped_stickers += 1,
        }
    }

    // The attachment arm: the metadata entries verbatim — the placeholder
    // face. Every row carrying descriptors counts `skippedAttachments` once:
    // the bytes-honest counter (v1 never ships bytes).
    let mut attachments_arm: Option<Value> = None;
    if let Some(raw) = row.attachments_json.as_deref() {
        counters.skipped_attachments += 1;
        attachments_arm = serde_json::from_str::<Vec<crate::engine::NormalizedAttachment>>(raw)
            .ok()
            .and_then(|attachments| serde_json::to_value(attachments).ok());
    }

    if export_body.is_none()
        && quote_arm.is_none()
        && sticker_arm.is_none()
        && attachments_arm.is_none()
    {
        counters.skipped_rows += 1;
        return Ok(());
    }

    let mut line = json!({
        "type": "message",
        "id": row.id,
        "chat": chat_id,
        "direction": row.direction,
        "author": author,
        "sentAt": row.sent_at,
        "status": row.status,
    });
    if let Some(received_at) = row.received_at {
        line["receivedAt"] = json!(received_at);
    }
    if let Some(delivered_at) = row.delivered_at {
        line["deliveredAt"] = json!(delivered_at);
    }
    if let Some(read_at) = row.read_at {
        line["readAt"] = json!(read_at);
    }
    if let Some(viewed_at) = row.viewed_at {
        line["viewedAt"] = json!(viewed_at);
    }
    if let Some(edited_at) = row.edited_at {
        line["editedAt"] = json!(edited_at);
    }
    if let Some(body) = export_body {
        line["body"] = Value::String(body.to_string());
    }
    if let Some(quote) = quote_arm {
        line["quote"] = quote;
    }
    if let Some(sticker) = sticker_arm {
        line["sticker"] = sticker;
    }
    if let Some(attachments) = attachments_arm {
        line["attachments"] = attachments;
    }
    if let Some(list) = reactions.get(&row.sent_at)
        && !list.is_empty()
    {
        let projected: Vec<Value> = list
            .iter()
            .map(|reaction| {
                let mut value = json!({
                    "emoji": reaction.emoji,
                    "reactedAt": reaction.updated_at,
                });
                if reaction.removed {
                    value["removed"] = json!(true);
                }
                // The reaction actor resolves in the ingest's own spelling:
                // `message_events.actor_id` is already the sender-map key
                // form (`stable_hash_id([account, kind, source])`) for a
                // peer, or the store account id for the linked account's own
                // reaction — both look up directly, exactly like a message
                // row's `sender_id`. The quote author is the only arm that
                // carries a raw spelling and re-hashes.
                let author = if reaction.actor_id == account_id {
                    Some(0_u64)
                } else {
                    sender_ids.get(&reaction.actor_id).copied()
                };
                if let Some(author) = author {
                    value["author"] = json!(author);
                }
                value
            })
            .collect();
        *reactions_projected += list.len() as u64;
        line["reactions"] = json!(projected);
    }
    writer.write_line(&line)
}

// -------------------------------------------------------------------------
// Snapshot caretaker (§10.6): the connector owns cleanup.
// -------------------------------------------------------------------------

/// One listed snapshot: directory name and the main file's byte size
/// (a missing main reports 0, the engine's damaged-snapshot honesty).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotEntry {
    pub name: String,
    pub main_bytes: u64,
}

fn snapshot_root(account_dir: &Path) -> PathBuf {
    account_dir.join(SNAPSHOT_ROOT)
}

fn is_snapshot_name(name: &str) -> bool {
    name.starts_with(SNAPSHOT_PREFIX) && !name.ends_with(SNAPSHOT_TMP_SUFFIX)
}

/// The snapshot directory list, newest-first (name sort), ≤
/// [`MAX_SNAPSHOT_ENTRIES`] — the same rules the engine's `exportStatus`
/// applies (§10.4), so the connector and the engine can never disagree about
/// what "the latest snapshot" is.
pub fn list_snapshots(account_dir: &Path) -> Vec<SnapshotEntry> {
    let root = snapshot_root(account_dir);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut snapshots: Vec<SnapshotEntry> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| is_snapshot_name(name))
        .map(|name| SnapshotEntry {
            main_bytes: std::fs::metadata(root.join(&name).join("main"))
                .map(|metadata| metadata.len())
                .unwrap_or(0),
            name,
        })
        .collect();
    snapshots.sort_by(|a, b| b.name.cmp(&a.name));
    snapshots.truncate(MAX_SNAPSHOT_ENTRIES);
    snapshots
}

/// The newest snapshot, if any.
pub fn latest_snapshot(account_dir: &Path) -> Option<SnapshotEntry> {
    list_snapshots(account_dir).into_iter().next()
}

/// UTC `yyyy-MM-dd-HH-mm-ss` — the engine's snapshot-name suffix shape
/// (export.rs `format_utc_timestamp`, civil-from-days algorithm), reproduced
/// here so the collision check names the exact second the next export will
/// stamp.
pub fn format_utc_timestamp_seconds(secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = (secs / SECS_PER_DAY) as i64;
    let secs_of_day = secs % SECS_PER_DAY;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}-{hour:02}-{minute:02}-{second:02}")
}

fn current_snapshot_candidate_name() -> Option<String> {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!(
        "{SNAPSHOT_PREFIX}{}",
        format_utc_timestamp_seconds(secs)
    ))
}

/// Best-effort deletion: `NotFound` races are success, real failures log by
/// class and keep the pass moving (a failed collision-candidate deletion
/// surfaces honestly as the engine's `BACKUP_SNAPSHOT_EXISTS`).
fn remove_dir_best_effort(path: &Path) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(kind = %error.kind(), "backup snapshot cleanup could not remove a directory");
        }
    }
}

/// The pre-export cleanup (§10.6): remove `-tmp` residue, keep only the most
/// recent snapshot, and also remove the newest snapshot when its name equals
/// the second the next export is about to stamp (the same-second collision
/// the engine fail-closes on — clearing it first is the connector's half of
/// the "clear and retry" contract).
pub fn prepare_snapshots_for_export(account_dir: &Path) {
    let root = snapshot_root(account_dir);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(SNAPSHOT_TMP_SUFFIX) {
            remove_dir_best_effort(&root.join(&name));
            continue;
        }
        if is_snapshot_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    names.reverse();
    let candidate = current_snapshot_candidate_name();
    for (index, name) in names.into_iter().enumerate() {
        if index == 0 && Some(&name) != candidate.as_ref() {
            continue;
        }
        remove_dir_best_effort(&root.join(name));
    }
}

// -------------------------------------------------------------------------
// File-handle table (the media three-chain shape, ADR 0004).
// -------------------------------------------------------------------------

/// Why a handle operation failed — mapped onto wire codes by the supervisor;
/// the variants stay log-safe (no ids, no paths).
#[derive(Debug, Eq, PartialEq)]
pub enum BackupHandleError {
    /// Unknown, expired, or early-released handle — one indistinguishable
    /// answer (`INVALID_REQUEST`) so handle space cannot be probed.
    NotFound,
    /// Offsets are strictly sequential; this one is not the next byte.
    NotSequential { expected: u64 },
    /// The account already holds the per-account live-handle ceiling.
    Exhausted,
    /// The chunk read failed for a reason other than the file being gone.
    Io,
}

/// One chunk of a snapshot file stream.
#[derive(Debug, Eq, PartialEq)]
pub struct BackupChunk {
    pub data: Vec<u8>,
    pub eof: bool,
}

struct BackupHandleEntry {
    account_id: String,
    path: PathBuf,
    size_bytes: u64,
    bytes_read: u64,
    expires_at: Instant,
}

/// Process-wide table of live snapshot-file streams. One instance serves
/// every proxy group (the registry hands the same `Arc` to all of them):
/// `readChunk`/`closeHandle` carry no accountId on the wire, so the table —
/// not the routing — is the single-origin authority.
#[derive(Default)]
pub struct BackupFileHandleTable {
    entries: StdMutex<HashMap<String, BackupHandleEntry>>,
}

impl BackupFileHandleTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a handle for one fixed snapshot file. Refuses at the per-account
    /// ceiling; expired entries are swept lazily first.
    pub fn open(
        &self,
        account_id: &str,
        path: PathBuf,
        size_bytes: u64,
    ) -> Result<String, BackupHandleError> {
        let mut entries = self.entries.lock().expect("backup handle table mutex");
        Self::sweep_expired(&mut entries);
        let live = entries
            .values()
            .filter(|entry| entry.account_id == account_id)
            .count();
        if live >= MAX_HANDLES_PER_ACCOUNT {
            return Err(BackupHandleError::Exhausted);
        }
        let handle = random_id();
        entries.insert(
            handle.clone(),
            BackupHandleEntry {
                account_id: account_id.to_string(),
                path,
                size_bytes,
                bytes_read: 0,
                expires_at: Instant::now() + HANDLE_TTL,
            },
        );
        Ok(handle)
    }

    /// Read the next sequential chunk. A file removed under the stream
    /// (connector cleanup) terminates the stream with a short chunk and
    /// `eof` instead of an error — the caller's loop must end, not retry; any
    /// other read failure is [`BackupHandleError::Io`].
    pub fn read_chunk(
        &self,
        backup_handle: &str,
        offset: u64,
    ) -> Result<BackupChunk, BackupHandleError> {
        let mut entries = self.entries.lock().expect("backup handle table mutex");
        Self::sweep_expired(&mut entries);
        let entry = entries
            .get_mut(backup_handle)
            .ok_or(BackupHandleError::NotFound)?;
        if entry.bytes_read != offset {
            return Err(BackupHandleError::NotSequential {
                expected: entry.bytes_read,
            });
        }
        let want = CHUNK_BYTES.min(entry.size_bytes - entry.bytes_read);
        let data = match read_exact_range(&entry.path, offset, want) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(BackupHandleError::Io),
        };
        let short = (data.len() as u64) < want;
        entry.bytes_read += data.len() as u64;
        let eof = short || entry.bytes_read >= entry.size_bytes;
        Ok(BackupChunk { data, eof })
    }

    /// Explicit early release; idempotent like the media chain.
    pub fn close(&self, backup_handle: &str) -> bool {
        let mut entries = self.entries.lock().expect("backup handle table mutex");
        entries.remove(backup_handle).is_some()
    }

    /// Drop every handle bound to one account — the account-delete path (a
    /// handle cannot outlive its account session); the TTL backstops the rest.
    pub fn clear_account(&self, account_id: &str) -> usize {
        let mut entries = self.entries.lock().expect("backup handle table mutex");
        let before = entries.len();
        entries.retain(|_, entry| entry.account_id != account_id);
        before - entries.len()
    }

    /// Live handles for tests.
    #[cfg(test)]
    pub fn live_count(&self) -> usize {
        self.entries
            .lock()
            .expect("backup handle table mutex")
            .len()
    }

    fn sweep_expired(entries: &mut HashMap<String, BackupHandleEntry>) {
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);
    }
}

/// Read `want` bytes starting at `offset`, opening the file for this one
/// chunk only. Returns short data when the file ends early.
fn read_exact_range(path: &Path, offset: u64, want: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0_u8; want as usize];
    let mut filled = 0;
    while filled < data.len() {
        match file.read(&mut data[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    data.truncate(filled);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e164_parsing_accepts_only_bare_plus_numbers() {
        assert_eq!(parse_e164("+15550000001").as_deref(), Some("+15550000001"));
        assert_eq!(parse_e164("+0"), None, "the zero number is not an identity");
        assert_eq!(parse_e164("15550000001"), None, "missing plus");
        assert_eq!(parse_e164("+1555 000"), None, "interior space");
        assert_eq!(parse_e164("+"), None);
        assert_eq!(
            parse_e164("+99999999999999999999999"),
            None,
            "overflow is not an identity"
        );
    }

    #[test]
    fn aci_parsing_accepts_uuid_and_raw_hex_and_canonicalizes() {
        assert_eq!(
            parse_aci("6e08f0b6-1c2d-4e5f-8a9b-0c1d2e3f4a5b").as_deref(),
            Some("6e08f0b61c2d4e5f8a9b0c1d2e3f4a5b")
        );
        assert_eq!(
            parse_aci("6E08F0B61C2D4E5F8A9B0C1D2E3F4A5B").as_deref(),
            Some("6e08f0b61c2d4e5f8a9b0c1d2e3f4a5b"),
            "hex canonicalizes to lowercase"
        );
        assert_eq!(parse_aci("6e08f0b6"), None, "wrong length");
        assert_eq!(
            parse_aci("6e08f0b6-1c2d-4e5f-8a9b-0c1d2e3f4a5z"),
            None,
            "non-hex"
        );
    }

    #[test]
    fn group_master_key_decode_mirrors_engine_base64() {
        // "fake-group-1" is 12 bytes — a legacy/other group id, not a master
        // key: the skeleton answer.
        assert_eq!(parse_group_master_key("ZmFrZS1ncm91cC0x"), None);
        let master_key = parse_group_master_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
        assert_eq!(
            master_key.as_deref(),
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[test]
    fn canonical_key_prefers_aci_over_e164() {
        let both = PeerIdentity {
            aci: Some("a".repeat(32)),
            e164: Some("+15550000001".to_string()),
        };
        assert_eq!(
            canonical_contact_key(&both).as_deref(),
            Some(&*format!("aci:{}", "a".repeat(32)))
        );
        let only_e164 = PeerIdentity {
            aci: None,
            e164: Some("+15550000001".to_string()),
        };
        assert_eq!(
            canonical_contact_key(&only_e164).as_deref(),
            Some("e164:+15550000001")
        );
        let skeleton = PeerIdentity {
            aci: None,
            e164: None,
        };
        assert_eq!(canonical_contact_key(&skeleton), None);
    }

    #[test]
    fn utc_timestamp_format_matches_the_engine_snapshot_shape() {
        // 2026-10-06T00:00:00Z.
        assert_eq!(
            format_utc_timestamp_seconds(1_791_244_800),
            "2026-10-06-00-00-00"
        );
        assert_eq!(format_utc_timestamp_seconds(0), "1970-01-01-00-00-00");
        // Leap-year day: 2024-02-29T12:34:56Z = 1709210096.
        assert_eq!(
            format_utc_timestamp_seconds(1_709_210_096),
            "2024-02-29-12-34-56"
        );
    }

    #[test]
    fn snapshot_listing_is_newest_first_and_ignores_tmp() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join(SNAPSHOT_ROOT);
        for name in [
            format!("{SNAPSHOT_PREFIX}2026-01-01-00-00-00"),
            format!("{SNAPSHOT_PREFIX}2026-01-02-00-00-00"),
            format!("{SNAPSHOT_PREFIX}2026-01-03-00-00-00{SNAPSHOT_TMP_SUFFIX}"),
            "unrelated".to_string(),
        ] {
            std::fs::create_dir_all(root.join(&name)).unwrap();
            std::fs::write(root.join(&name).join("main"), b"main-bytes").unwrap();
        }
        let snapshots = list_snapshots(temp.path());
        assert_eq!(snapshots.len(), 2, "-tmp and non-snapshot entries stay out");
        assert!(snapshots[0].name > snapshots[1].name, "newest first");
        assert_eq!(snapshots[0].main_bytes, 10);
        assert_eq!(latest_snapshot(temp.path()).unwrap(), snapshots[0]);
    }

    #[test]
    fn prepare_keeps_only_the_latest_snapshot_and_clears_collision_candidate() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join(SNAPSHOT_ROOT);
        let older = format!("{SNAPSHOT_PREFIX}2026-01-01-00-00-00");
        let newest = format!("{SNAPSHOT_PREFIX}2026-01-02-00-00-00");
        let residue = format!("{SNAPSHOT_PREFIX}2026-01-03-00-00-00{SNAPSHOT_TMP_SUFFIX}");
        for name in [&older, &newest, &residue] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        prepare_snapshots_for_export(temp.path());
        assert!(root.join(&newest).exists(), "the latest snapshot is kept");
        assert!(!root.join(&older).exists(), "older snapshots are cleared");
        assert!(!root.join(&residue).exists(), "-tmp residue is cleared");

        // A newest snapshot named for the current second is the collision
        // candidate the engine would fail-closed on: cleared too.
        let now = current_snapshot_candidate_name().unwrap();
        std::fs::create_dir_all(root.join(&now)).unwrap();
        prepare_snapshots_for_export(temp.path());
        assert!(!root.join(&now).exists(), "same-second candidate cleared");
    }

    #[test]
    fn handle_table_is_sequential_bounded_and_idempotent() {
        let table = BackupFileHandleTable::new();
        let temp = tempfile::TempDir::new().unwrap();
        let file = temp.path().join("main");
        std::fs::write(&file, vec![0xAB_u8; 700_000]).unwrap();

        let handle = table.open("acct", file.clone(), 700_000).unwrap();
        // Offsets strictly sequential.
        assert!(matches!(
            table.read_chunk(&handle, 10),
            Err(BackupHandleError::NotSequential { expected: 0 })
        ));
        let first = table.read_chunk(&handle, 0).unwrap();
        assert_eq!(first.data.len(), CHUNK_BYTES as usize);
        assert!(!first.eof);
        let second = table.read_chunk(&handle, CHUNK_BYTES).unwrap();
        assert_eq!(second.data.len(), CHUNK_BYTES as usize);
        assert!(!second.eof);
        let third = table.read_chunk(&handle, 2 * CHUNK_BYTES).unwrap();
        assert_eq!(third.data.len(), 700_000 - 2 * CHUNK_BYTES as usize);
        assert!(third.eof, "the stream terminates at the file end");

        // Idempotent close: the second release reports false.
        assert!(table.close(&handle));
        assert!(!table.close(&handle));
        assert!(matches!(
            table.read_chunk(&handle, 700_000),
            Err(BackupHandleError::NotFound)
        ));

        // Per-account ceiling: the ninth open for one account is refused.
        let handles: Vec<String> = (0..MAX_HANDLES_PER_ACCOUNT)
            .map(|_| table.open("acct2", file.clone(), 1).unwrap())
            .collect();
        assert!(matches!(
            table.open("acct2", file.clone(), 1),
            Err(BackupHandleError::Exhausted)
        ));
        assert_eq!(table.clear_account("acct2"), handles.len());
        assert_eq!(table.open("acct2", file, 1).unwrap().len(), 32);
    }

    #[test]
    fn short_file_terminates_the_stream_instead_of_erroring() {
        let table = BackupFileHandleTable::new();
        let temp = tempfile::TempDir::new().unwrap();
        let file = temp.path().join("main");
        std::fs::write(&file, b"tiny").unwrap();
        let handle = table.open("acct", file.clone(), 4).unwrap();
        let chunk = table.read_chunk(&handle, 0).unwrap();
        assert_eq!(chunk.data, b"tiny");
        assert!(chunk.eof);
        // The file vanishing under the stream (connector cleanup) is a short
        // chunk + eof, never an error.
        std::fs::remove_file(&file).unwrap();
        table.close(&handle);
        let handle = table.open("acct", file, 4).unwrap();
        let chunk = table.read_chunk(&handle, 0).unwrap();
        assert!(chunk.data.is_empty());
        assert!(chunk.eof);
    }

    #[test]
    fn counters_serialize_camel_case_and_merge() {
        let counters = SkipCounters {
            skipped_reactions: 1,
            skipped_body_truncated: 2,
            skipped_skeleton_chats: 3,
            ..SkipCounters::default()
        };
        let mut result = serde_json::json!({"state": "idle"});
        counters.merge_into(&mut result);
        assert_eq!(result["skippedReactions"], 1);
        assert_eq!(result["skippedBodyTruncated"], 2);
        assert_eq!(result["skippedSkeletonChats"], 3);
        assert_eq!(result["state"], "idle");
    }

    // ---------------------------------------------------------------------
    // §4.115 plaintext chat export (contract revision 1.132)
    // ---------------------------------------------------------------------

    /// The §4.115 store fixture key — the same bytes the store's own tests
    /// use, so every unit-test store exercises the keyed-open path.
    const PLAINTEXT_TEST_STORE_KEY: [u8; 32] = [0x5A; 32];

    fn plaintext_test_store() -> (tempfile::TempDir, crate::store::Store) {
        let temp = tempfile::TempDir::new().unwrap();
        let store = crate::store::Store::open(
            temp.path(),
            Some(crate::store::StoreKey::from_bytes(PLAINTEXT_TEST_STORE_KEY)),
        )
        .unwrap();
        (temp, store)
    }

    #[allow(clippy::too_many_arguments)]
    fn plaintext_message(
        account_id: &str,
        conversation_id: &str,
        id: &str,
        direction: &'static str,
        sender_id: &str,
        sent_at: u64,
        text: Option<String>,
        status: &'static str,
    ) -> crate::store::MessageRecord {
        crate::store::MessageRecord {
            is_erased: false,
            delete_failed: false,
            required_protocol_version: None,
            author_aci: None,
            id: id.to_string(),
            account_id: account_id.to_string(),
            conversation_id: conversation_id.to_string(),
            direction,
            sender_id: sender_id.to_string(),
            sender_name: None,
            mentions_self: false,
            sent_at,
            received_at: Some(sent_at + 10),
            text,
            text_bytes: None,
            text_truncated: false,
            text_retrievable: true,
            status,
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
        }
    }

    #[test]
    fn plaintext_registry_slot_is_exclusive_and_never_sticks_running() {
        let registry = PlaintextTaskRegistry::new();
        assert!(!registry.latest("acct").is_some(), "no task has ever run");

        assert!(registry.begin("acct", 100), "a fresh slot claims");
        assert!(!registry.begin("acct", 200), "a second start is refused");
        let running = registry.latest("acct").unwrap();
        assert_eq!(running.state, PlaintextTaskState::Running);
        assert_eq!(running.started_at_ms, 100);
        assert_eq!(running.finished_at_ms, None);

        let outcome = PlaintextBuildOutcome {
            file_name: "plaintext-export-x.jsonl".into(),
            lines: 7,
            bytes: 700,
            counters: SkipCounters::default(),
        };
        registry.complete("acct", 300, &outcome);
        let settled = registry.latest("acct").unwrap();
        assert_eq!(settled.state, PlaintextTaskState::Completed);
        assert_eq!(settled.finished_at_ms, Some(300));
        assert_eq!(settled.lines, Some(7));
        assert_eq!(settled.bytes, Some(700));
        // A settled record never blocks the next start.
        assert!(registry.begin("acct", 400));

        // A settle can never invent a task.
        registry.complete("ghost", 1, &outcome);
        assert!(registry.latest("ghost").is_none());

        // The new run fails; the failure replaces the running entry.
        registry.fail("acct", 500, "io");
        let failed = registry.latest("acct").unwrap();
        assert_eq!(failed.state, PlaintextTaskState::Failed);
        assert_eq!(failed.error, Some("io"));

        // A failure never overwrites a settled record: the next run
        // completes and a late fail is a no-op.
        assert!(registry.begin("acct", 600));
        registry.complete("acct", 700, &outcome);
        registry.fail("acct", 800, "io");
        let settled_again = registry.latest("acct").unwrap();
        assert_eq!(settled_again.state, PlaintextTaskState::Completed);
        assert_eq!(settled_again.error, None);

        registry.clear("acct");
        assert!(
            registry.latest("acct").is_none(),
            "delete clears the record"
        );
    }

    #[test]
    fn plaintext_listing_and_caretaker_mirror_the_snapshot_discipline() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join(PLAINTEXT_DIR_NAME).join("acct");
        std::fs::create_dir_all(&root).unwrap();
        let names = [
            format!("{PLAINTEXT_FILE_PREFIX}2026-01-01-00-00-00{PLAINTEXT_FILE_SUFFIX}"),
            format!("{PLAINTEXT_FILE_PREFIX}2026-01-02-00-00-00{PLAINTEXT_FILE_SUFFIX}"),
            format!(
                "{PLAINTEXT_FILE_PREFIX}2026-01-03-00-00-00{PLAINTEXT_FILE_SUFFIX}{PLAINTEXT_TMP_SUFFIX}"
            ),
            "unrelated.jsonl".to_string(),
        ];
        for (index, name) in names.iter().enumerate() {
            std::fs::write(root.join(name), vec![0xAB_u8; index + 1]).unwrap();
        }

        let listed = list_plaintext_artifacts(&root);
        assert_eq!(listed.len(), 2, "-tmp and foreign names stay out");
        assert!(listed[0].name > listed[1].name, "newest first");
        assert_eq!(listed[0].bytes, 2);
        assert_eq!(
            latest_plaintext_artifact(&root),
            Some(root.join(&listed[0].name))
        );

        // The pre-build caretaker: -tmp residue and every older same-family
        // artifact go, the newest stays, and foreign files are not the
        // build's business.
        prepare_plaintext_dir_for_export(&root);
        let mut remaining: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        // Directory iteration order is filesystem-dependent; this assertion
        // checks membership, not the host filesystem's enumeration order.
        remaining.sort();
        assert_eq!(
            remaining,
            vec![listed[0].name.clone(), "unrelated.jsonl".to_string()]
        );
        let candidate = current_plaintext_candidate_name().unwrap();
        std::fs::write(root.join(&candidate), b"collision").unwrap();
        prepare_plaintext_dir_for_export(&root);
        assert!(
            !root.join(&candidate).exists(),
            "the same-second candidate is cleared before the build"
        );

        // The account-delete path removes the whole directory.
        clear_plaintext_artifacts(temp.path(), "acct");
        assert!(!root.exists());
        clear_plaintext_artifacts(temp.path(), "acct");
    }

    #[test]
    fn plaintext_quote_author_resolves_through_the_sender_reverse_map() {
        let sender_ids: HashMap<String, u64> = [
            (stable_hash_id(&["acct", "direct", "+15555550101"]), 2_u64),
            (stable_hash_id(&["acct", "group", "0b7fca57"]), 5_u64),
        ]
        .into_iter()
        .collect();
        // Self, by the account's own address spelling.
        assert_eq!(
            resolve_plaintext_author("+15555550099", "acct", "+15555550099", &sender_ids),
            Some(0)
        );
        // Peer spellings through both namespaces.
        assert_eq!(
            resolve_plaintext_author("+15555550101", "acct", "+15555550099", &sender_ids),
            Some(2)
        );
        assert_eq!(
            resolve_plaintext_author("0b7fca57", "acct", "+15555550099", &sender_ids),
            Some(5)
        );
        // An author the projection never met: the caller omits or rides raw.
        assert_eq!(
            resolve_plaintext_author("+15555559999", "acct", "+15555550099", &sender_ids),
            None
        );
    }

    /// The §4.115 golden build: the admitted v1 faces (text, quotes with the
    /// join keys, sticker metadata, attachment metadata placeholders,
    /// reactions with resolved authors, receipt stamps) project; the §4.46
    /// row gates hold verbatim; a reaction on a gated row is counted, never
    /// dropped. Red line 1 is structural here — the builder touches only the
    /// store and the connector state dir.
    #[test]
    fn plaintext_build_projects_the_admitted_faces_and_holds_the_row_gates() {
        let (temp, store) = plaintext_test_store();
        let account = store
            .upsert_account_from_signal("+15555550099", Some(1), crate::DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let alice = "+15555550101";
        let aci_peer_uuid = "1b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10";
        let master_key_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

        // Contacts: an E.164 peer and a UUID-only peer; the group roster
        // merges Alice into the contact set by her number so her group items
        // resolve.
        store
            .upsert_contact(&account.id, "contact", alice, "Alice", None, 1)
            .unwrap();
        store
            .upsert_contact(&account.id, "contact", aci_peer_uuid, "Aci Peer", None, 1)
            .unwrap();
        store
            .upsert_contact(
                &account.id,
                "group",
                master_key_b64,
                "The Group",
                Some(&format!(r#"{{"members":[{{"id":"{alice}}}]}}"#)),
                1,
            )
            .unwrap();

        let direct = store
            .ensure_conversation(&account.id, "direct", alice, "Alice")
            .unwrap();
        let aci_chat = store
            .ensure_conversation(&account.id, "direct", aci_peer_uuid, "Aci Peer")
            .unwrap();
        let group = store
            .ensure_conversation(&account.id, "group", master_key_b64, "The Group")
            .unwrap();
        let note_to_self = store
            .ensure_conversation(&account.id, "direct", "+15555550099", "Self")
            .unwrap();

        let alice_direct_sender = stable_hash_id(&[&account.id, "direct", alice]);
        let alice_group_sender = stable_hash_id(&[&account.id, "group", alice]);
        let aci_sender = stable_hash_id(&[&account.id, "direct", aci_peer_uuid]);

        // -- direct chat rows: the admitted faces ---------------------------
        store
            .insert_message(
                &crate::store::MessageRecord {
                    quote_snapshot: Some(crate::engine::NormalizedQuote {
                        id: 40,
                        author: alice.to_string(),
                        text: "quoted preview".into(),
                        attachments: Vec::new(),
                    }),
                    quote_message_id: Some("m-quoted".into()),
                    ..plaintext_message(
                        &account.id,
                        &direct.id,
                        "m-quote",
                        "incoming",
                        &alice_direct_sender,
                        50,
                        Some("reply body".into()),
                        "delivered",
                    )
                },
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &crate::store::MessageRecord {
                    quote_snapshot: Some(crate::engine::NormalizedQuote {
                        id: 1,
                        author: "+15555559999".into(),
                        text: "stranger quote".into(),
                        attachments: Vec::new(),
                    }),
                    ..plaintext_message(
                        &account.id,
                        &direct.id,
                        "m-quote-raw",
                        "incoming",
                        &alice_direct_sender,
                        60,
                        None,
                        "delivered",
                    )
                },
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &crate::store::MessageRecord {
                    sticker: Some(crate::engine::NormalizedSticker {
                        pack_id: "aabb".into(),
                        pack_key: "c2V0".into(),
                        sticker_id: 3,
                        emoji: Some("🎉".into()),
                    }),
                    ..plaintext_message(
                        &account.id,
                        &direct.id,
                        "m-sticker",
                        "incoming",
                        &alice_direct_sender,
                        70,
                        None,
                        "delivered",
                    )
                },
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &crate::store::MessageRecord {
                    attachments: vec![crate::engine::NormalizedAttachment {
                        id: "att-1".into(),
                        content_type: Some("image/png".into()),
                        filename: Some("photo.png".into()),
                        size: Some(12_345),
                        width: Some(64),
                        height: Some(48),
                        is_voice_note: false,
                        caption: Some("a caption".into()),
                        blur_hash: None,
                        incremental_mac: None,
                        chunk_size: None,
                        is_borderless: false,
                        is_gif: false,
                        locator: None,
                        waveform: None,
                        duration: None,
                    }],
                    ..plaintext_message(
                        &account.id,
                        &direct.id,
                        "m-att",
                        "incoming",
                        &alice_direct_sender,
                        80,
                        Some("see photo".into()),
                        "delivered",
                    )
                },
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &direct.id,
                    "m-out",
                    "outgoing",
                    "self",
                    90,
                    Some("sent text".into()),
                    "sent",
                ),
                None,
                None,
                false,
            )
            .unwrap();

        // -- the §4.46 row gates, verbatim ----------------------------------
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &direct.id,
                    "m-system",
                    "system",
                    "system",
                    10,
                    Some("system marker".into()),
                    "system",
                ),
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &direct.id,
                    "m-admin-deleted",
                    "incoming",
                    &alice_direct_sender,
                    20,
                    Some("deleted".into()),
                    "delivered",
                ),
                None,
                None,
                false,
            )
            .unwrap();
        // The admin-delete mark rides the delete mirror's own write, not the
        // insert path — stamp the column the way the mirror leaves it.
        store
            .conn()
            .execute(
                "UPDATE messages SET admin_deleted=1 WHERE id='m-admin-deleted'",
                [],
            )
            .unwrap();
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &direct.id,
                    "m-unconfirmed",
                    "outgoing",
                    "self",
                    30,
                    Some("pending text".into()),
                    "pending",
                ),
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &crate::store::MessageRecord {
                    // A stored truncated preview: the body is a bounded
                    // preview the connector cannot re-fetch, so it is not
                    // retrievable — the insert persists body_truncated only
                    // for this pair.
                    text_truncated: true,
                    text_retrievable: false,
                    ..plaintext_message(
                        &account.id,
                        &direct.id,
                        "m-truncated-only",
                        "incoming",
                        &alice_direct_sender,
                        35,
                        Some("a truncated preview".into()),
                        "delivered",
                    )
                },
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &direct.id,
                    "m-empty",
                    "incoming",
                    &alice_direct_sender,
                    40,
                    None,
                    "delivered",
                ),
                None,
                None,
                false,
            )
            .unwrap();

        // -- the UUID-keyed chat and the group ------------------------------
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &aci_chat.id,
                    "m-aci",
                    "incoming",
                    &aci_sender,
                    100,
                    Some("uuid chat body".into()),
                    "delivered",
                ),
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &group.id,
                    "m-group",
                    "incoming",
                    &alice_group_sender,
                    110,
                    Some("group body".into()),
                    "delivered",
                ),
                None,
                None,
                false,
            )
            .unwrap();
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &note_to_self.id,
                    "m-nts",
                    "outgoing",
                    "self",
                    120,
                    Some("note to self".into()),
                    "read",
                ),
                None,
                None,
                false,
            )
            .unwrap();

        // -- reactions: self rides the account id, the peer the map key ------
        store
            .upsert_reaction_event(&account.id, &direct.id, "👍", 50, &account.id, false, None)
            .unwrap();
        store
            .upsert_reaction_event(
                &account.id,
                &direct.id,
                "🎉",
                90,
                &alice_direct_sender,
                false,
                None,
            )
            .unwrap();
        store
            .upsert_reaction_event(
                &account.id,
                &direct.id,
                "👎",
                50,
                &alice_direct_sender,
                true,
                None,
            )
            .unwrap();
        // A reaction whose target row the gates skipped: counted, never lost.
        store
            .upsert_reaction_event(&account.id, &direct.id, "😅", 40, &account.id, false, None)
            .unwrap();

        let outcome =
            build_plaintext_artifact(&store, &account.id, "+15555550099").expect("the build");

        // Red line 4: exactly one product, no -tmp residue.
        let root = plaintext_export_root(temp.path(), &account.id);
        let artifacts = list_plaintext_artifacts(&root);
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, outcome.file_name);
        assert!(outcome.file_name.starts_with(PLAINTEXT_FILE_PREFIX));
        assert!(outcome.file_name.ends_with(PLAINTEXT_FILE_SUFFIX));

        let raw = std::fs::read_to_string(root.join(&outcome.file_name)).unwrap();
        let lines: Vec<Value> = raw
            .lines()
            .map(|line| serde_json::from_str(line).expect("every line is one JSON object"))
            .collect();

        // Reference order: account, contacts, groups, chats, messages.
        assert_eq!(lines[0]["type"], "account");
        assert_eq!(lines[0]["account"], "+15555550099");
        assert!(
            lines[0].get("givenName").is_none(),
            "honest absence: no display name, no key"
        );
        let mut contacts: Vec<Value> = lines[1..]
            .iter()
            .filter(|line| line["type"] == "contact")
            .cloned()
            .collect();
        assert_eq!(contacts.len(), 2, "Alice and the UUID peer; never self");
        contacts.sort_by_key(|line| line["id"].as_u64().unwrap());
        let alice_row = contacts
            .iter()
            .find(|line| line["e164"] == 15555550101_u64)
            .expect("Alice projects with the bare-number e164 face");
        assert_eq!(alice_row["givenName"], "Alice");
        assert!(
            alice_row.get("aci").is_none(),
            "an E.164-only identity never invents an ACI"
        );
        let aci_row = contacts
            .iter()
            .find(|line| line.get("aci").is_some())
            .expect("the UUID peer projects with the canonical aci face");
        assert_eq!(
            aci_row["aci"], "1b7fca5712344d0e9b0f4f6c1f8a2e10",
            "dashes canonicalize away"
        );
        let aci_contact_id = aci_row["id"].as_u64().unwrap();
        let alice_contact_id = alice_row["id"].as_u64().unwrap();

        let groups: Vec<&Value> = lines
            .iter()
            .filter(|line| line["type"] == "group")
            .collect();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0]["masterKey"],
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(groups[0]["title"], "The Group");
        let group_id = groups[0]["id"].as_u64().unwrap();

        let chats: Vec<&Value> = lines.iter().filter(|line| line["type"] == "chat").collect();
        assert_eq!(chats.len(), 4, "direct, aci chat, group, note to self");
        let chat_by = |kind: &str, recipient: u64| {
            chats
                .iter()
                .find(|line| line["kind"] == kind && line["recipient"] == recipient)
                .map(|line| line["id"].as_u64().unwrap())
                .unwrap_or_else(|| panic!("chat {kind}/{recipient} missing"))
        };
        let direct_chat = chat_by("direct", alice_contact_id);
        let aci_chat_id = chat_by("direct", aci_contact_id);
        let group_chat = chat_by("group", group_id);
        let nts_chat = chat_by("direct", 0);
        for chat in &chats {
            assert!(
                chat.get("title").is_some(),
                "the chat line self-describes with its title"
            );
        }

        let messages: Vec<&Value> = lines
            .iter()
            .filter(|line| line["type"] == "message")
            .collect();
        assert_eq!(messages.len(), 8, "3 gated rows never masquerade");
        let by_id = |id: &str| {
            messages
                .iter()
                .find(|line| line["id"] == id)
                .copied()
                .unwrap_or_else(|| panic!("message {id} missing"))
        };

        // The quote face: resolved author + the join keys.
        let quote_line = by_id("m-quote");
        assert_eq!(quote_line["chat"], direct_chat);
        assert_eq!(quote_line["author"], alice_contact_id);
        assert_eq!(quote_line["body"], "reply body");
        assert_eq!(quote_line["quote"]["id"], 40);
        assert_eq!(quote_line["quote"]["text"], "quoted preview");
        assert_eq!(quote_line["quote"]["author"], alice_contact_id);
        assert_eq!(quote_line["quote"]["messageId"], "m-quoted");
        assert_eq!(quote_line["sentAt"], 50);
        assert_eq!(quote_line["receivedAt"], 60);
        // Reactions: self author 0, peer author resolved, removed kept,
        // targetless counted in the counters.
        let quote_reactions = quote_line["reactions"].as_array().unwrap();
        assert_eq!(quote_reactions.len(), 2);
        assert!(
            quote_reactions
                .iter()
                .any(|r| r["emoji"] == "👍" && r["author"] == 0 && r.get("removed").is_none()),
            "the self reaction resolves through the store account id"
        );
        assert!(
            quote_reactions.iter().any(|r| r["emoji"] == "👎"
                && r["removed"] == true
                && r["author"] == alice_contact_id),
            "the removal keeps its author and the auditable removed mark"
        );

        // The unresolvable quote author rides raw, never dangles.
        let raw_quote = by_id("m-quote-raw");
        assert_eq!(raw_quote["quote"]["authorRaw"], "+15555559999");
        assert!(raw_quote["quote"].get("author").is_none());
        assert_eq!(
            raw_quote["quote"]["text"], "stranger quote",
            "a quote-only row exports without a body"
        );

        // Sticker metadata verbatim.
        let sticker_line = by_id("m-sticker");
        assert_eq!(sticker_line["sticker"]["packId"], "aabb");
        assert_eq!(sticker_line["sticker"]["packKey"], "c2V0");
        assert_eq!(sticker_line["sticker"]["stickerId"], 3);
        assert_eq!(sticker_line["sticker"]["emoji"], "🎉");

        // Attachment metadata placeholder — the caption/filename ride, the
        // bytes never do.
        let att_line = by_id("m-att");
        let att = &att_line["attachments"][0];
        assert_eq!(att["id"], "att-1");
        assert_eq!(att["contentType"], "image/png");
        assert_eq!(att["filename"], "photo.png");
        assert_eq!(att["caption"], "a caption");
        assert_eq!(att_line["body"], "see photo");

        let out_line = by_id("m-out");
        assert_eq!(out_line["author"], 0);
        assert_eq!(out_line["direction"], "outgoing");
        assert_eq!(out_line["status"], "sent");

        assert_eq!(by_id("m-aci")["chat"], aci_chat_id);
        assert_eq!(by_id("m-aci")["author"], aci_contact_id);
        assert_eq!(by_id("m-group")["chat"], group_chat);
        let nts_line = by_id("m-nts");
        assert_eq!(nts_line["chat"], nts_chat);
        assert_eq!(nts_line["author"], 0);
        assert_eq!(nts_line["status"], "read");

        let counters = outcome.counters;
        // Gates: system + admin-deleted + unconfirmed outgoing; plus the
        // contentless skips — the empty row and the truncated-only row (its
        // only content is the non-exportable preview, so it counts both its
        // truncated cause and the contentless skip).
        assert_eq!(counters.skipped_rows, 5);
        assert_eq!(counters.skipped_body_truncated, 1);
        assert_eq!(counters.skipped_attachments, 1);
        // Four reaction rows read; three rode lines; the one targeting the
        // gated row (sentAt 40) is counted, never dropped.
        assert_eq!(counters.skipped_reactions, 1);
        assert_eq!(counters.skipped_quotes, 0);
        assert_eq!(counters.skipped_stickers, 0);
        assert_eq!(counters.skipped_skeleton_chats, 0);
        assert_eq!(
            outcome.lines as usize,
            lines.len(),
            "the writer's count is the file's line count"
        );
        assert_eq!(outcome.bytes as usize, raw.len());
    }

    /// Red line 4's failure path: a cap breach fails the build closed and
    /// leaves no addressable product — no partial artifact, no -tmp residue.
    #[test]
    fn plaintext_cap_breach_fails_closed_and_removes_the_partial_file() {
        let (temp, store) = plaintext_test_store();
        let account = store
            .upsert_account_from_signal("+15555550099", Some(1), crate::DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let conversation = store
            .ensure_conversation(&account.id, "direct", "+15555550101", "Alice")
            .unwrap();
        let sender = stable_hash_id(&[&account.id, "direct", "+15555550101"]);
        let oversized = "x".repeat(MAX_ARTIFACT_BODY_BYTES + 1);
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &conversation.id,
                    "m-big",
                    "incoming",
                    &sender,
                    10,
                    Some(oversized),
                    "delivered",
                ),
                None,
                None,
                false,
            )
            .unwrap();

        let error = build_plaintext_artifact(&store, &account.id, "+15555550099")
            .expect_err("the body cap fails the build closed");
        assert!(matches!(error, BuildError::CapExceeded("message body")));

        let root = plaintext_export_root(temp.path(), &account.id);
        let residue: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(residue.is_empty(), "no product, no residue: {residue:?}");
    }

    /// The idempotent rebuild: a second build after the first leaves exactly
    /// one artifact (the newest), and the caretaker never leaves the
    /// same-second candidate addressable mid-build.
    #[test]
    fn plaintext_rebuild_keeps_exactly_one_artifact() {
        let (temp, store) = plaintext_test_store();
        let account = store
            .upsert_account_from_signal("+15555550099", Some(1), crate::DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        let conversation = store
            .ensure_conversation(&account.id, "direct", "+15555550101", "Alice")
            .unwrap();
        let sender = stable_hash_id(&[&account.id, "direct", "+15555550101"]);
        store
            .insert_message(
                &plaintext_message(
                    &account.id,
                    &conversation.id,
                    "m1",
                    "incoming",
                    &sender,
                    10,
                    Some("body".into()),
                    "delivered",
                ),
                None,
                None,
                false,
            )
            .unwrap();
        let first = build_plaintext_artifact(&store, &account.id, "+15555550099").unwrap();
        let second = build_plaintext_artifact(&store, &account.id, "+15555550099").unwrap();
        let root = plaintext_export_root(temp.path(), &account.id);
        let artifacts = list_plaintext_artifacts(&root);
        assert_eq!(artifacts.len(), 1, "the caretaker keeps only the newest");
        assert_eq!(artifacts[0].name, second.file_name);
        // The timestamp stamp is seconds-granular: a same-second rebuild
        // reclaims the same name through the caretaker's collision
        // preemption — never two addressable products.
        assert_eq!(first.file_name, second.file_name);
    }
    // ------------------------------------------------------------------
    // S13 (contract 1.262): the section-4.46 v1 line set grows the
    // attachment rows - the pointer face is the section-4.38 v2 locator
    // shape verbatim (project_pointer_common isomorph), entries that
    // cannot build a valid official frame stay honest holes counted per
    // row, and a media-only row (empty body, projectable attachment) is
    // exported like the official standard_message validator allows.
    // ------------------------------------------------------------------

    #[test]
    fn artifact_lines_carry_the_pointer_face_and_honest_holes() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = std::sync::Arc::new(
            Store::open(
                &temp.path().join("store"),
                Some(crate::store::StoreKey::from_bytes([0x7A; 32])),
            )
            .unwrap(),
        );
        let account = store
            .upsert_account_from_signal("+15555550077", Some(1), crate::DEFAULT_PROXY_GROUP_ID)
            .unwrap();
        // The engine registry + account dir (the artifact lands beside the
        // engine's own history-import.ndjson, section-10.2 layout).
        let engine_dir = temp.path().join("engine-data");
        let account_dir = engine_dir.join("accounts").join("lk-z2");
        std::fs::create_dir_all(&account_dir).unwrap();
        std::fs::write(
            engine_dir.join("engine-state.json"),
            "{\"version\":2,\"accounts\":[{\"number\":\"+15555550077\",\"dir\":\"accounts/lk-z2\"}]}",
        )
        .unwrap();

        // Three imported rows through the real import pass: a mixed row
        // (one projectable pointer + one metadata-only descriptor = the
        // honest hole), a media-only row (empty body, projectable), and a
        // v1 row (metadata-only only).
        let archive = account_dir.join("history-import.ndjson");
        std::fs::write(
            &archive,
            format!(
                "{}\n{}\n{}\n{}\n{}\n",
                serde_json::json!({"type": "recipient", "id": 1, "kind": "contact",
                    "name": "Alice", "e164": "+15550000001"}),
                serde_json::json!({"type": "chat", "id": 10, "recipientId": 1}),
                serde_json::json!({"type": "message", "chatId": 10, "authorId": 1,
                "dateSent": 1000, "direction": "incoming", "text": "mix",
                "attachments": [
                    {"contentType": "image/png", "fileName": "p.png", "flag": 0,
                        "size": 64, "width": 320, "height": 240,
                        "locator": {"key": "MDEyMzQ1Njc4OWFiY2RlZg==",
                            "cdnKey": "ABCDEFG", "cdnNumber": 2,
                            "uploadTimestamp": 1760000000000u64,
                            "plaintextHash": "0123456789abcdef0123456789abcdef"}},
                    {"contentType": "video/mp4", "fileName": "v.mp4", "flag": 0,
                        "size": 12}
                ]}),
                serde_json::json!({"type": "message", "chatId": 10, "authorId": 1,
                "dateSent": 2000, "direction": "incoming",
                "attachments": [
                    {"contentType": "audio/aac", "fileName": "n.m4a", "flag": 1,
                        "size": 9,
                        "locator": {"key": "MDEyMzQ1Njc4OWFiY2RlZg==",
                            "cdnKey": "BBCDEFGH", "cdnNumber": 0,
                            "plaintextHash": "fedcba9876543210fedcba9876543210"}}
                ]}),
                serde_json::json!({"type": "message", "chatId": 10, "authorId": 1,
                    "dateSent": 3000, "direction": "incoming", "text": "v1",
                    "attachments": [
                        {"contentType": "application/pdf", "fileName": "d.pdf",
                            "flag": 0, "size": 7}]})
            ),
        )
        .unwrap();
        let counters = crate::history_import::run_import(
            &store,
            &account.id,
            "+15555550077",
            &archive,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            counters.imported, 3,
            "media-only rows land (attachment body class)"
        );

        let skip = build_artifact(&store, &engine_dir, &account.id, "+15555550077").unwrap();
        assert_eq!(
            skip.skipped_attachments, 2,
            "the mixed row and the v1 row each lost an entry - counted once per row"
        );
        assert_eq!(skip.skipped_rows, 0, "every row rode the line set");

        let artifact =
            std::fs::read_to_string(account_dir.join("backup-export-input.ndjson")).unwrap();
        let item_at = |sent_at: u64| {
            artifact
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .find(|value| value["type"] == "chat_item" && value["dateSent"] == sent_at)
                .expect("chat item line")
        };

        // The mixed row: the projectable entry rides the v2 locator face
        // verbatim; the metadata-only sibling is the honest absence.
        let mixed = item_at(1000);
        assert_eq!(mixed["body"], "mix");
        let entries = mixed["attachments"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "the pointer-less sibling dropped");
        let face = &entries[0];
        assert_eq!(face["contentType"], "image/png");
        assert_eq!(face["fileName"], "p.png");
        assert_eq!(face["size"], 64);
        assert_eq!(face["width"], 320);
        assert_eq!(face["height"], 240);
        let locator = &face["locator"];
        assert_eq!(locator["key"], "MDEyMzQ1Njc4OWFiY2RlZg==");
        assert_eq!(locator["cdnKey"], "ABCDEFG");
        assert_eq!(locator["cdnNumber"], 2);
        assert_eq!(locator["uploadTimestamp"], 1_760_000_000_000u64);
        assert_eq!(locator["plaintextHash"], "0123456789abcdef0123456789abcdef");

        // The media-only row: body empty, attachment complete - the
        // official StandardMessage shape (text absent, attachments present).
        let media_only = item_at(2000);
        assert_eq!(media_only["body"], "");
        let media_entries = media_only["attachments"].as_array().unwrap();
        assert_eq!(media_entries.len(), 1);
        assert_eq!(
            media_entries[0]["flag"], "voiceMessage",
            "the live flag booleans project as the official enum words"
        );
        assert_eq!(
            media_entries[0]["locator"]["cdnNumber"], 0,
            "cdn0 is a legal transit face and rides verbatim"
        );
        assert_eq!(
            media_entries[0]["locator"]["plaintextHash"],
            "fedcba9876543210fedcba9876543210"
        );
        assert!(
            media_entries[0]["locator"].get("uploadTimestamp").is_none(),
            "no stamp, no key - the official unexpected-timestamp rule"
        );

        // The v1 row: body intact, no attachments key at all (the honest
        // hole is the counter, never a fake placeholder line).
        let v1 = item_at(3000);
        assert_eq!(v1["body"], "v1");
        assert!(v1.get("attachments").is_none());
    }
}
