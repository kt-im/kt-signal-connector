// SPDX-License-Identifier: AGPL-3.0-only

//! The read-only `runtime.doctor` diagnostic face (contract revision 1.97,
//! implementation-plan §4.79; the Signal runtime-environment plan's
//! diagnostics layer 3). One call answers the whole chain in one payload:
//!
//! - full-chain versions: the connector itself plus, per proxy group, the
//!   engine's own `version` answer and the kt-engine
//!   `engine.protocolCapabilities` self-certification face (presage rev /
//!   libsignal version baseline) passed through verbatim — an engine that is
//!   not running answers `unreachable` with the state's classification, and
//!   an engine that does not carry a method answers honestly with the engine
//!   error class instead of a guessed value; since contract revision 1.133
//!   (§4.116) the face also carries the engine's `engine.perfMetrics`
//!   snapshot projected through the connector's pinned allowlist (unknown
//!   keys drop and count — deliberately not verbatim);
//! - data-directory status per group: path, existence, writability, and the
//!   filesystem's free space;
//! - occupancy-lock status per group: `.kt-signal-connector.lock` presence,
//!   the recorded holder pid, kernel-held state, and the holder's liveness;
//! - the recent error families: a bounded ring of the connector's most
//!   recent classified errors (host dispatch failures and protocol
//!   warnings), aggregated into counts;
//! - the store's own health (revision 1.282, §4.266): schema version next to
//!   its target, the last pre-migration integrity gate verdict, the database
//!   and WAL byte sizes, the snapshot count and outcome of the last upgrade,
//!   and the last recorded migration failure. Every value is a number or a
//!   fixed literal; the snapshot is named by its own file name, never a path;
//!   since revision 1.284 (§4.268) the same face carries `schemaNewer` — the
//!   last refused open this state directory recorded because the store was
//!   written by a newer connector, with both schema numbers. A newer store
//!   refuses to start (the launcher gets the fixed KT_FATAL line), so this
//!   marker is the only way a later doctor run can still say what blocked it;
//! - the event ledger's own face (revision 1.283, §4.267): the generation
//!   counter, the retention floor and head seq, rows and bytes, and the
//!   retention window they are held to. Numbers only — the token is never
//!   reported, because doctor payloads get pasted into bug reports;
//! - network reachability, reused from the existing connectivity surfaces:
//!   the per-group engine status plus the process-wide watchdog/receive-drop
//!   counters — no new instrumentation there;
//! - the Signal service plane (revision 1.97): the doctor's ONLY declared
//!   direct network probes — two read-only HTTPS GETs (chat, storage) through
//!   the launcher's SOCKS proxy environment, each folding into one fixed
//!   classification literal, plus (revision 1.163, §4.161) the system-trust
//!   leg: the same chat target through the same route riding the platform
//!   trust store with no custom anchor — the official desktop's own trust
//!   posture — answering the same literal family as an additive optional
//!   face key. The report never carries error text, request
//!   content, a URL, or a proxy endpoint.
//! - the per-group credential state (revision 1.101): one read-only
//!   `getUserStatus` ride through each group's own live engine — the
//!   doctor's only account-authenticated probe — folded into one fixed
//!   literal (`healthy` / `credentialsInvalid` / `indeterminate` /
//!   `unreachable` / `noAccount`). The account number rides only into the
//!   engine call params, never into the report.
//!
//! Read-only discipline (pinned by tests): the doctor never starts or stops
//! an engine, never cleans or deletes a lock, never writes anything
//! anywhere. The only lock interaction is a non-blocking exclusive `flock`
//! probe that is unlocked immediately — kernel state only, no file byte or
//! directory entry changes. The service-plane probes are read-only GETs
//! under the same 3-second diagnostic budget. Data-directory paths are
//! reported to the authenticated host on purpose (the launcher passed them
//! at spawn, so the peer already knows them); they never enter logs
//! (AGENTS.md discipline).

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};

use crate::datalock::LOCK_FILE_NAME;
use crate::engine::{CallClass, EngineError, EngineHandle, EngineState, EngineStatus, SocksProxy};
use crate::registry::ProxyGroupRuntime;
use crate::store::{EventLogHealth, StoreHealth};

/// Bounded engine-call budget for the three doctor probes (`version`,
/// `engine.protocolCapabilities`): a diagnostic must not sit on a wedged
/// engine anywhere near the ordinary 15 s request timeout.
const DOCTOR_ENGINE_CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// The launcher-injected SOCKS proxy environment variable (`host:port`) —
/// the same variable the engine child inherits and maps onto
/// `ALL_PROXY=socks5h://…`. The service-plane probes reuse it so the probe
/// validates exactly the route real traffic takes, and so does the
/// supervisor's CDN attachment-download client (§4.38 step 3).
pub(crate) const SOCKS_PROXY_ENV: &str = "KT_SIGNAL_SOCKS_PROXY";

/// Fixed service-plane probe targets (revision 1.97): HTTPS-only,
/// compile-time constants. They never enter logs and the report never
/// carries them — only the classification literal (plus a status code and a
/// latency for `http`) leaves this module.
const CHAT_SERVICE_PROBE_URL: &str = "https://chat.signal.org/v1/accounts/whoami";
const STORAGE_SERVICE_PROBE_URL: &str = "https://storage.signal.org/";

/// The bounded recent-error window (`recentErrors.window`).
const ERROR_RING_CAPACITY: usize = 64;

/// The lock-file content budget: the connector records exactly one decimal
/// pid; anything longer is not a pid this connector wrote.
const LOCK_PID_READ_BYTES: usize = 32;

// ---------------------------------------------------------------- report --

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub connector: ConnectorFace,
    /// The store's own health face (contract revision 1.282, §4.266): the
    /// schema version it landed on next to the target this binary migrates to,
    /// the last pre-migration integrity gate verdict, the database and WAL
    /// sizes, what the pre-migration snapshot pass did, and the last failed
    /// migration this state directory recorded. Read-only, taken without the
    /// writer lock — an upgrade that rolled back has to stay visible, not
    /// collapse into "unavailable".
    pub store: StoreHealth,
    /// The event ledger's own face (contract revision 1.283, §4.267): the
    /// generation counter, the retention floor, the head seq, how many rows and
    /// bytes the ledger holds, and the window they are held to. The token
    /// itself never appears — doctor payloads are pasted into bug reports.
    pub events: EventLogHealth,
    pub groups: Vec<GroupReport>,
    pub network: NetworkFace,
    pub recent_errors: ErrorRingReport,
    pub service: ServiceFace,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorFace {
    pub version: &'static str,
    pub api_version: &'static str,
    pub pid: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkFace {
    /// Existing metric (`metrics::record_watchdog_restart`): every engine
    /// restart the receive-liveness watchdog has executed this process.
    pub watchdog_restarts_total: u64,
    /// Existing metric (`metrics::record_receive_drop`): receives dropped
    /// because the persistence queue stayed saturated.
    pub receive_dropped_total: u64,
}

/// The Signal service-plane face (contract revision 1.97): the doctor's only
/// declared network probes. Everything here is a fixed literal or a number —
/// no error text, no URL, no proxy endpoint ever enters the report.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceFace {
    /// The launcher's `KT_SIGNAL_SOCKS_PROXY` process environment was
    /// present and well-formed. False ⇒ both probes answer `not_configured`
    /// and no network attempt happens. Per-group proxy plans are deliberately
    /// not consulted: the probe reflects the process-wide launch environment.
    pub proxy_configured: bool,
    /// `GET https://chat.signal.org/v1/accounts/whoami` (unauthenticated;
    /// the desktop reads the link healthy at the edge's own 401).
    pub chat: ServiceProbe,
    /// `GET https://storage.signal.org/` (any HTTP response is healthy).
    pub storage: ServiceProbe,
    /// The system-trust leg (contract revision 1.163, §4.161): the chat
    /// target through the same route, riding the platform trust store (the
    /// `rustls-tls-native-roots` chain — on macOS the Security.framework
    /// keychains, user-installed CAs included) with **no** custom anchor —
    /// the official desktop's own trust posture (Chromium + system store).
    /// Present exactly when `proxyConfigured` is true (the declared
    /// unconfigured path probes nothing); absent means "no probe ran", never
    /// "probe failed". `classification === "http"` ⇒ the system-trust plane
    /// is usable end to end — the verdict the desktop reads against a
    /// pinned-anchor `tls_failed` to conclude *official-equivalent usable*
    /// (a MITM proxy whose CA the user trusts breaks the engine-pinned leg
    /// but not this one). Strict and system legs are independent by
    /// construction: either can answer while the other fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_trust: Option<ServiceProbe>,
}

/// One service-plane probe's outcome, folded into exactly one fixed
/// classification literal. `status`/`latencyMs` ride only with `http`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProbe {
    /// `http` (the edge answered) | `timeout` | `socks_refused` |
    /// `tls_failed` | `not_configured` — never anything else.
    pub classification: &'static str,
    /// Only with `http`: the HTTP status code the edge answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Only with `http`: the whole-probe wall time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupReport {
    pub group_id: String,
    pub engine: EngineFace,
    pub data_dir: DataDirFace,
    pub lock: LockFace,
    /// The per-group credential-state face (contract revision 1.101, §4.82).
    pub credentials: CredentialsFace,
}

/// The per-group credential-state face (contract revision 1.101, §4.82): the
/// doctor's one account-authenticated probe — a single read-only
/// `getUserStatus` ride through the group's own engine for the watchdog's
/// ping-target account, folded into exactly one fixed literal. This is the
/// layer the unauthenticated service probes above cannot see: `chat`'s 401 is
/// the healthy edge answer for a probe with no credentials, while a dead
/// linked-device credential is only observable through an authenticated call.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsFace {
    /// `healthy` (the engine answered the registered face) |
    /// `credentialsInvalid` (the engine answered the credential-death face —
    /// the same classification the §4.17 unlink chain rides) |
    /// `indeterminate` (the engine answered a different error — e.g. a
    /// transport-layer failure folded content-free; the connector cannot
    /// tell a dead credential from a dead route on that face) |
    /// `unreachable` (no live engine to probe through) |
    /// `noAccount` (live engine, but the group has no account to probe) —
    /// never anything else.
    pub state: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineFace {
    pub state: EngineState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    pub resource_pressure: bool,
    pub reachable: bool,
    /// Present exactly when `reachable` is false: the honest reason the
    /// engine face cannot answer, classified from the observed state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreachable_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<EngineMethodFace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_capabilities: Option<EngineMethodFace>,
    /// The engine's read-only `engine.perfMetrics` snapshot (contract
    /// revision 1.133, §4.116), projected onto the connector's pinned
    /// engine allowlist — deliberately **not** the verbatim passthrough
    /// the two faces above use: a future engine may grow its metric
    /// vocabulary, and this face never forwards an unbounded key space
    /// (unknown keys drop and count into the face's
    /// `connectorDroppedKeys`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf_metrics: Option<EngineMethodFace>,
    /// O1: the engine's own `version` string (verbatim, never re-derived).
    /// Present when this diagnostic could read it live or a previous handshake
    /// recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// O1: the contract revision the engine states, verbatim. Absent for a
    /// legacy engine (one that predates the handshake face or states no
    /// revision) — absence stays absence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_contract_revision: Option<String>,
    /// O1: `match` | `legacy` | `mismatch` | `unverified` (`unreachable` when
    /// no live engine could be asked at all). The supervisor's verdict — the
    /// gate that actually decided whether the account pipeline may run.
    pub engine_contract_status: &'static str,
    /// O1: the fixed classification of a refused handshake
    /// (`version_missing` / `revision_out_of_range` / `revision_malformed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_contract_reason: Option<&'static str>,
}

/// One engine method probe's outcome: the engine's own answer passed through
/// verbatim, or the honest failure class — never a value the connector
/// invented.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineMethodFace {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub face: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl EngineMethodFace {
    fn answered(face: Value) -> Self {
        Self {
            present: true,
            face: Some(face),
            reason: None,
        }
    }

    fn failed(reason: &'static str) -> Self {
        Self {
            present: false,
            face: None,
            reason: Some(reason),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataDirFace {
    /// The launcher-configured path, reported to the authenticated host on
    /// purpose (the launcher already knows it); never logged.
    pub path: String,
    pub exists: bool,
    /// Access-based writability of the directory itself, checked without
    /// writing (POSIX access(2); Windows falls back to the read-only
    /// attribute — best effort there, pending a Windows test host).
    pub writable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

/// The three lock forms the contract pins, carried in `classification`:
/// `none` (no lock file), `held` (a kernel lock is held — the holder is
/// alive by construction, the kernel releases it on any exit), `stale`
/// (file present, no holder, and the recorded pid is dead — a remnant of a
/// crashed-and-since-replaced holder), `released` (file present, no holder,
/// pid alive or unknown — the designed post-release remnant; the lock file
/// is deliberately never deleted, so this is the normal state after a clean
/// connector exit).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockFace {
    pub present: bool,
    pub held: bool,
    /// The pid the connector wrote into the lock file at acquire time;
    /// absent for lock files written by pre-face connectors or corrupted
    /// content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// `Some(true)` whenever `held` (kernel guarantee), else the recorded
    /// pid's liveness when a pid is known; `None` when no pid is known.
    pub holder_alive: Option<bool>,
    pub classification: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorRingReport {
    /// The ring's fixed capacity: the newest `window` classified errors are
    /// the aggregation basis.
    pub window: usize,
    /// Every error ever recorded this process — when it exceeds `window`,
    /// the families below cover only the newest slice.
    pub recorded_total: u64,
    pub families: Vec<ErrorFamilyCount>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorFamilyCount {
    /// Where the classification came from: `host` (a host dispatch answered
    /// a structured error; `family` is the wire error code) or `protocol`
    /// (an engine protocol warning; `family` is the warning kind).
    pub source: &'static str,
    pub family: &'static str,
    pub retryable: bool,
    pub count: u64,
    pub last_at_unix_ms: u64,
}

// -------------------------------------------------------------- binding --

/// One group's read-only supervision snapshot, handed over by the supervisor
/// (`RuntimeSupervisor::doctor_face`): the launcher-config identity plus the
/// supervised engine status and a live engine handle when one exists.
pub(crate) struct DoctorGroupFace {
    pub data_dir: std::path::PathBuf,
    pub status: EngineStatus,
    pub engine: Option<EngineHandle>,
    /// The credentials probe target (the watchdog's any-account-of-this-group
    /// rule). Transient only — the number never enters the report.
    pub probe_account: Option<String>,
    /// O1: the supervisor's contract handshake verdict (last served engine or
    /// the latched refusal). The report's parsed fields prefer the live probe
    /// answers and fall back here when the engine cannot answer now.
    pub contract: crate::engine_contract::EngineContractState,
}

/// Assemble the whole doctor payload for the runtime: every launch-plan group
/// in launcher order plus the connector-wide faces. Read-only end to end.
pub async fn collect(runtime: &ProxyGroupRuntime) -> DoctorReport {
    let mut groups = Vec::with_capacity(8);
    for (group_id, supervisor) in runtime.doctor_supervisors() {
        let face = supervisor.doctor_face().await;
        let data_dir = probe_data_dir(&face.data_dir);
        let lock = probe_lock(&face.data_dir);
        let engine = engine_face(&face.status, face.engine.as_ref(), &face.contract).await;
        let credentials = credentials_face(
            &face.status,
            face.engine.as_ref(),
            face.probe_account.as_deref(),
        )
        .await;
        groups.push(GroupReport {
            group_id: group_id.to_string(),
            engine,
            data_dir,
            lock,
            credentials,
        });
    }
    DoctorReport {
        connector: ConnectorFace {
            version: env!("CARGO_PKG_VERSION"),
            api_version: crate::API_VERSION,
            pid: std::process::id(),
        },
        store: runtime.store().health(),
        events: runtime.store().event_log_health(),
        groups,
        network: NetworkFace {
            watchdog_restarts_total: crate::metrics::watchdog_restarts_total(),
            receive_dropped_total: crate::metrics::receive_dropped_total(),
        },
        recent_errors: error_ring_snapshot(),
        service: service_face().await,
    }
}

/// Per-group engine face: the supervised status verbatim plus, for a live
/// engine, the three read-only method probes (`version`,
/// `engine.protocolCapabilities`, `engine.perfMetrics`) under the bounded
/// diagnostic budget. A
/// non-running engine marks `unreachable` with the state classification and
/// answers all three probes `present: false` with that same reason.
async fn engine_face(
    status: &EngineStatus,
    engine: Option<&EngineHandle>,
    contract: &crate::engine_contract::EngineContractState,
) -> EngineFace {
    let reachable = status.state == EngineState::Running && engine.is_some();
    // A Running status with no live handle is a mid-transition race, not a
    // start failure; it gets its own honest classification.
    let degraded_reason = if status.state == EngineState::Running {
        "the engine is transitioning: the live handle vanished mid-probe"
    } else {
        unreachable_reason(status.state)
    };
    let (version, protocol_capabilities, perf_metrics) =
        if let Some(engine) = engine.filter(|_| reachable) {
            (
                Some(
                    probe_engine_method(
                        engine,
                        "version",
                        "the engine answered an error for the version method \
                         (an engine that does not carry it surfaces the upstream class)",
                    )
                    .await,
                ),
                Some(
                    probe_engine_method(
                        engine,
                        "engine.protocolCapabilities",
                        "the engine answered an error for the self-certification method \
                         (an engine without the kt-engine self-certification face)",
                    )
                    .await,
                ),
                Some(probe_engine_perf_metrics(engine).await),
            )
        } else {
            (
                Some(EngineMethodFace::failed(degraded_reason)),
                Some(EngineMethodFace::failed(degraded_reason)),
                Some(EngineMethodFace::failed(degraded_reason)),
            )
        };
    // O1: the parsed handshake facts. The live probe answers win (this is the
    // freshest truth); the supervisor's recorded verdict fills in when a probe
    // could not run (engine gone, mid-transition). Neither is invented.
    let engine_version = engine_version_from_face(version.as_ref())
        .or_else(|| contract.engine_version().map(str::to_owned));
    let engine_contract_revision =
        contract_revision_from_faces(version.as_ref(), protocol_capabilities.as_ref())
            .or_else(|| contract.contract_revision().map(str::to_owned));
    let engine_contract_status = if contract.fault.is_some() || reachable {
        // A latched refusal explains an unreachable engine; never hide it
        // behind the generic literal.
        contract.status()
    } else {
        "unreachable"
    };
    EngineFace {
        state: status.state,
        pid: status.pid,
        rss_bytes: status.rss_bytes,
        resource_pressure: status.resource_pressure,
        reachable,
        unreachable_reason: (!reachable).then_some(degraded_reason),
        version,
        protocol_capabilities,
        perf_metrics,
        engine_version,
        engine_contract_revision,
        engine_contract_status,
        engine_contract_reason: contract.fault.as_ref().map(|fault| fault.reason.as_str()),
    }
}

/// O1: the engine's own version string from a version probe face.
fn engine_version_from_face(face: Option<&EngineMethodFace>) -> Option<String> {
    face.and_then(|face| face.face.as_ref())
        .and_then(|answer| answer.get("version"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// O1: the stated contract revision, capabilities face first (authoritative),
/// the version answer as the additive fallback - the same precedence the
/// startup handshake uses.
fn contract_revision_from_faces(
    version: Option<&EngineMethodFace>,
    capabilities: Option<&EngineMethodFace>,
) -> Option<String> {
    fn from_face(face: Option<&EngineMethodFace>) -> Option<String> {
        face.and_then(|face| face.face.as_ref())
            .and_then(|answer| answer.get("contractRevision"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
    from_face(capabilities).or_else(|| from_face(version))
}

/// One read-only engine method probe under the diagnostic budget.
async fn probe_engine_method(
    engine: &EngineHandle,
    method: &'static str,
    upstream_reason: &'static str,
) -> EngineMethodFace {
    match engine
        .call_with_timeout(
            method,
            json!({}),
            CallClass::ReadOnly,
            DOCTOR_ENGINE_CALL_TIMEOUT,
        )
        .await
    {
        Ok(face) => EngineMethodFace::answered(face),
        Err(
            EngineError::Timeout
            | EngineError::NotRunning
            | EngineError::Exited
            | EngineError::Backpressure,
        ) => EngineMethodFace::failed("the engine stopped answering mid-probe"),
        Err(_) => EngineMethodFace::failed(upstream_reason),
    }
}

/// The `engine.perfMetrics` probe (contract revision 1.133, §4.116): the
/// same read-only budget, with the answer projected through the connector's
/// pinned engine allowlist (`perf_metrics::filter_engine_snapshot`) — the
/// connector never forwards a key space it does not know, and the face
/// carries `connectorDroppedKeys` so a lossy projection is visible to the
/// consumer. A stock signal-cli engine or an engine predating the
/// `engine.perfMetrics` face answers the upstream-error class, same
/// degradation family as the other probes.
async fn probe_engine_perf_metrics(engine: &EngineHandle) -> EngineMethodFace {
    match engine
        .call_with_timeout(
            "engine.perfMetrics",
            json!({}),
            CallClass::ReadOnly,
            DOCTOR_ENGINE_CALL_TIMEOUT,
        )
        .await
    {
        Ok(face) => {
            let (filtered, dropped) = crate::perf_metrics::filter_engine_snapshot(&face);
            crate::perf_metrics::add(crate::perf_metrics::keys::ENGINE_SNAPSHOT_DROPPED, dropped);
            EngineMethodFace::answered(filtered)
        }
        Err(
            EngineError::Timeout
            | EngineError::NotRunning
            | EngineError::Exited
            | EngineError::Backpressure,
        ) => EngineMethodFace::failed("the engine stopped answering mid-probe"),
        Err(_) => EngineMethodFace::failed(
            "the engine answered an error for the perf-metrics method \
             (an engine predating the engine.perfMetrics face surfaces the \
             upstream class)",
        ),
    }
}

/// The honest start/state failure classification for a non-running engine:
/// static, content-free state names only.
fn unreachable_reason(state: EngineState) -> &'static str {
    match state {
        EngineState::Running => "reachable",
        EngineState::Stopped => {
            "engine is stopped: not started since connector boot, or stopped by runtime.stop"
        }
        EngineState::Exited => {
            "engine exited: the process ended on its own; start it with runtime.start"
        }
        EngineState::Faulted => {
            "engine faulted: the process crashed or failed to start; the watchdog may restart it"
        }
    }
}

// ---------------------------------------------------------- credentials ----

/// The per-group credential-state probe (contract revision 1.101, §4.82):
/// one read-only `getUserStatus` ride through the group's own live engine —
/// the same read-only call the liveness watchdog pings with — under the
/// doctor's 3-second diagnostic budget. The gate is the same reachability
/// rule the engine face uses; a probe that cannot run degrades honestly
/// instead of guessing.
async fn credentials_face(
    status: &EngineStatus,
    engine: Option<&EngineHandle>,
    account: Option<&str>,
) -> CredentialsFace {
    let reachable = status.state == EngineState::Running && engine.is_some();
    match credentials_probe_gate(reachable, engine, account) {
        CredentialsProbe::Skip(state) => CredentialsFace { state },
        CredentialsProbe::Run(engine, account) => CredentialsFace {
            state: credentials_state_literal(
                &engine
                    .call_with_timeout(
                        "getUserStatus",
                        json!({ "account": account }),
                        CallClass::ReadOnly,
                        DOCTOR_ENGINE_CALL_TIMEOUT,
                    )
                    .await,
            ),
        },
    }
}

/// The probe gate, split pure so the unit suite pins every skip branch
/// without a live engine: the engine face's reachability rule first, then
/// the account requirement.
fn credentials_probe_gate<'a>(
    reachable: bool,
    engine: Option<&'a EngineHandle>,
    account: Option<&'a str>,
) -> CredentialsProbe<'a> {
    match (reachable, account) {
        (false, _) => CredentialsProbe::Skip("unreachable"),
        (true, None) => CredentialsProbe::Skip("noAccount"),
        (true, Some(account)) => {
            CredentialsProbe::Run(engine.expect("reachable implies a live handle"), account)
        }
    }
}

enum CredentialsProbe<'a> {
    Skip(&'static str),
    Run(&'a EngineHandle, &'a str),
}

/// The pure outcome half, split from the transport call so the unit suite
/// pins every literal without any engine. The classification rides the same
/// ladder the request path uses: the engine boundary has already folded the
/// raw upstream error, so `Unauthorized` here means the credential-death
/// face — the §4.17 anchors or the §4.82 plain-text 401 body — and any other
/// engine answer is honestly indistinguishable from a network failure at
/// this boundary (the engine-side websocket-upgrade gap, §4.82).
fn credentials_state_literal(result: &Result<Value, EngineError>) -> &'static str {
    match result {
        Ok(_) => "healthy",
        Err(EngineError::Unauthorized) => "credentialsInvalid",
        Err(
            EngineError::Timeout
            | EngineError::NotRunning
            | EngineError::Exited
            | EngineError::Backpressure,
        ) => "unreachable",
        Err(_) => "indeterminate",
    }
}

// ------------------------------------------------------------ data dir ----

/// Read-only data-directory status: existence, writability (access-based,
/// nothing written), and the filesystem's free space. Every failure degrades
/// to an absent optional field rather than a guessed value.
pub(crate) fn probe_data_dir(path: &Path) -> DataDirFace {
    let exists = path.is_dir();
    let writable = exists && path_is_writable(path);
    let (free_bytes, total_bytes) = if exists {
        filesystem_space(path)
    } else {
        (None, None)
    };
    DataDirFace {
        path: path.display().to_string(),
        exists,
        writable,
        free_bytes,
        total_bytes,
    }
}

/// POSIX `access(W_OK)`: the kernel answers for the real credentials without
/// a single byte touching the directory. Windows has no access(2) equivalent
/// in this crate's dependency set; the read-only attribute is the honest
/// best-effort signal there (pending a Windows test host).
fn path_is_writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok()
    }
    #[cfg(windows)]
    {
        std::fs::metadata(path)
            .map(|metadata| !metadata.permissions().readonly())
            .unwrap_or(false)
    }
}

/// Free/total bytes of the filesystem holding `path`; `None` when the
/// platform query fails (an absent field, never a zero guess).
fn filesystem_space(path: &Path) -> (Option<u64>, Option<u64>) {
    #[cfg(unix)]
    {
        match rustix::fs::statvfs(path) {
            Ok(stats) => {
                let free = stats.f_bavail.saturating_mul(stats.f_frsize);
                let total = stats.f_blocks.saturating_mul(stats.f_frsize);
                (Some(free), Some(total))
            }
            Err(_) => (None, None),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut free: u64 = 0;
        let mut total: u64 = 0;
        let mut _unused: u64 = 0;
        let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut _unused) };
        if ok != 0 {
            (Some(free), Some(total))
        } else {
            (None, None)
        }
    }
}

// ----------------------------------------------------------------- lock ----

/// Read-only occupancy-lock status for one data directory. The kernel lock —
/// not the file's existence — is the occupancy truth: the probed lock is
/// released immediately, and no file byte or directory entry changes.
pub(crate) fn probe_lock(data_dir: &Path) -> LockFace {
    let lock_path = data_dir.join(LOCK_FILE_NAME);
    let Some(content) = read_lock_file(&lock_path) else {
        return LockFace {
            present: false,
            held: false,
            pid: None,
            holder_alive: None,
            classification: "none",
        };
    };
    let pid = recorded_pid(&content);
    match probe_held(&lock_path) {
        Some(true) => LockFace {
            present: true,
            held: true,
            pid,
            // Kernel-owned lock: a holder that died for any reason — SIGKILL
            // included — releases it, so `held` proves a live holder.
            holder_alive: Some(true),
            classification: "held",
        },
        held @ Some(false) | held @ None => {
            let holder_alive = pid.map(pid_alive);
            // Dead recorded pid + no kernel holder = the stale remnant of a
            // crashed holder; anything else is the designed post-release
            // remnant (the file is deliberately never deleted).
            let stale = holder_alive == Some(false);
            LockFace {
                present: true,
                held: held.unwrap_or(false),
                pid,
                holder_alive,
                classification: if stale { "stale" } else { "released" },
            }
        }
    }
}

/// The lock file's first bytes, bounded — a corrupted or foreign file never
/// pulls unbounded data into the diagnostic.
fn read_lock_file(lock_path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(lock_path).ok()?;
    let mut buffer = [0u8; LOCK_PID_READ_BYTES];
    let mut read = 0;
    loop {
        let result = file.read(&mut buffer[read..]);
        match result {
            Ok(0) => break,
            Ok(count) => {
                read += count;
                if read == buffer.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8(buffer[..read].to_vec()).ok()
}

/// The decimal pid this connector writes at acquire time; anything else
/// parses to `None`.
fn recorded_pid(content: &str) -> Option<u32> {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed.len() > LOCK_PID_READ_BYTES {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

/// Non-blocking kernel-lock probe: `Some(true)` = a holder exists,
/// `Some(false)` = no holder (probed and released), `None` = the probe could
/// not run. The probe acquires nothing durably and changes no file byte.
fn probe_held(lock_path: &Path) -> Option<bool> {
    let file = std::fs::File::open(lock_path).ok()?;
    #[cfg(unix)]
    {
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                let _ = rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock);
                Some(false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Some(true),
            Err(_) => None,
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;
        let mut overlapped = OVERLAPPED::default();
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if locked != 0 {
            let mut overlapped = OVERLAPPED::default();
            unsafe {
                UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlapped);
            }
            Some(false)
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION as i32)
            {
                Some(true)
            } else {
                None
            }
        }
    }
}

/// Liveness of a recorded pid: signal 0 on Unix (delivers nothing, answers
/// existence), a zero-wait process handle on Windows. Never sends a real
/// signal, never terminates anything.
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
            if handle.is_null() {
                return false;
            }
            let result = WaitForSingleObject(handle, 0);
            CloseHandle(handle);
            result == WAIT_TIMEOUT
        }
    }
}

// ---------------------------------------------------------- error ring ----

/// One bounded ring entry: a classified error with its recording time. The
/// family is always a fixed literal (a wire error code or a protocol-warning
/// kind) — never message text, never request content.
#[derive(Clone, Debug)]
struct ErrorRecord {
    at_unix_ms: u64,
    source: &'static str,
    family: &'static str,
    retryable: bool,
}

static ERROR_RING: StdMutex<VecDeque<ErrorRecord>> = StdMutex::new(VecDeque::new());
static ERROR_RING_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Unix milliseconds for a ring entry; a pre-epoch clock degrades to zero.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Record one host dispatch failure (the wire error code is the family).
/// Bounded: the oldest entry leaves the ring when the window is full.
pub fn record_host_error(code: &'static str, retryable: bool) {
    record_error("host", code, retryable);
}

/// Record one engine protocol warning (the warning kind is the family).
pub fn record_protocol_warning(kind: &'static str) {
    record_error("protocol", kind, false);
}

fn record_error(source: &'static str, family: &'static str, retryable: bool) {
    ERROR_RING_TOTAL.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut ring) = ERROR_RING.lock() {
        if ring.len() == ERROR_RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(ErrorRecord {
            at_unix_ms: now_unix_ms(),
            source,
            family,
            retryable,
        });
    }
}

/// Aggregate the ring into per-family counts (count descending, then source
/// and family ascending for a deterministic answer).
pub fn error_ring_snapshot() -> ErrorRingReport {
    let mut aggregated: BTreeMap<(&'static str, &'static str), ErrorFamilyCount> = BTreeMap::new();
    if let Ok(ring) = ERROR_RING.lock() {
        for record in ring.iter() {
            let entry = aggregated
                .entry((record.source, record.family))
                .or_insert_with(|| ErrorFamilyCount {
                    source: record.source,
                    family: record.family,
                    retryable: record.retryable,
                    count: 0,
                    last_at_unix_ms: record.at_unix_ms,
                });
            entry.count += 1;
            entry.last_at_unix_ms = entry.last_at_unix_ms.max(record.at_unix_ms);
            entry.retryable = record.retryable;
        }
    }
    let mut families: Vec<ErrorFamilyCount> = aggregated.into_values().collect();
    families.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then(left.source.cmp(right.source))
            .then(left.family.cmp(right.family))
    });
    ErrorRingReport {
        window: ERROR_RING_CAPACITY,
        recorded_total: ERROR_RING_TOTAL.load(Ordering::Relaxed),
        families,
    }
}

// -------------------------------------------------------- service plane ----

/// Assemble the service-plane face. No proxy environment ⇒ both probes
/// answer `not_configured` and nothing touches the network — the only
/// not-probing path is the declared unconfigured one.
async fn service_face() -> ServiceFace {
    service_face_for(env_socks_proxy()).await
}

async fn service_face_for(proxy: Option<SocksProxy>) -> ServiceFace {
    let Some(proxy) = proxy else {
        let probe = ServiceProbe {
            classification: "not_configured",
            status: None,
            latency_ms: None,
        };
        return ServiceFace {
            proxy_configured: false,
            chat: probe.clone(),
            storage: probe,
            system_trust: None,
        };
    };
    // The §4.161 dual track: the strict pair and the system-trust leg are
    // independent verdicts — each builds its own client and either can
    // answer while the other fails. They run concurrently under the same
    // 3-second diagnostic budget.
    let ((chat, storage), system_trust) =
        tokio::join!(strict_service_pair(&proxy), system_trust_leg(&proxy),);
    ServiceFace {
        proxy_configured: true,
        chat,
        storage,
        system_trust: Some(system_trust),
    }
}

/// The strict pair (chat, storage) on the vendored-CA-pinned client. A
/// client build failure is a connector defect (static CA bytes, static
/// settings) or a broken TLS backend: both faces fold to the TLS-layer
/// literal rather than inventing a sixth one. No request is sent. The pair
/// shares one client, fresh per diagnostic — a wedged connection pool is
/// never reused across calls.
async fn strict_service_pair(proxy: &SocksProxy) -> (ServiceProbe, ServiceProbe) {
    let Some(client) = service_client(proxy) else {
        let probe = ServiceProbe {
            classification: "tls_failed",
            status: None,
            latency_ms: None,
        };
        return (probe.clone(), probe);
    };
    tokio::join!(
        probe_service_face(&client, CHAT_SERVICE_PROBE_URL),
        probe_service_face(&client, STORAGE_SERVICE_PROBE_URL),
    )
}

/// The system-trust leg (§4.161): the chat target through the same route on
/// its own client — the platform trust store, no custom anchor. Deliberately
/// independent of the strict pair (either verdict stands alone: a MITM proxy
/// whose CA the user trusts pins the strict leg to `tls_failed` while this
/// leg answers `http`), and a build failure here folds to the TLS-layer
/// literal exactly like the strict pair's does.
async fn system_trust_leg(proxy: &SocksProxy) -> ServiceProbe {
    match system_trust_client(proxy) {
        Some(client) => probe_service_face(&client, CHAT_SERVICE_PROBE_URL).await,
        None => ServiceProbe {
            classification: "tls_failed",
            status: None,
            latency_ms: None,
        },
    }
}

/// The launcher's proxy from the process environment, or `None`. The value
/// never reaches the report — the report carries `proxyConfigured` and
/// classification literals only.
pub(crate) fn env_socks_proxy() -> Option<SocksProxy> {
    parse_socks_proxy_env(&std::env::var(SOCKS_PROXY_ENV).ok()?)
}

/// The canonical variable form is `host:port`; an explicit `socks5(h)://`
/// scheme prefix is tolerated and normalized. Anything else is unconfigured.
pub(crate) fn parse_socks_proxy_env(raw: &str) -> Option<SocksProxy> {
    let bare = raw
        .strip_prefix("socks5h://")
        .or_else(|| raw.strip_prefix("socks5://"))
        .unwrap_or(raw);
    SocksProxy::parse(bare).ok()
}

/// The strict service-plane HTTPS client — the pinned-anchor leg of the
/// §4.161 dual track: the vendored Signal production root CA as the ONLY
/// trust anchor (the kt-engine's tls_certs_only attitude — the probe
/// validates exactly the TLS reality the engine's own traffic meets), the
/// launcher proxy as the only `socks5h://` route (remote DNS, matching the
/// engine's `ALL_PROXY` mapping), connect+overall budgets at the doctor's
/// 3-second diagnostic bound, redirects off. Built fresh per diagnostic — a
/// wedged connection pool is never reused across calls.
fn service_client(proxy: &SocksProxy) -> Option<reqwest::Client> {
    let certificate =
        reqwest::Certificate::from_pem(include_bytes!("../vendor/certs/production-root-ca.pem"))
            .ok()?;
    let socks_url = format!("socks5h://{}:{}", proxy.host, proxy.port);
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        .tls_built_in_root_certs(false)
        .proxy(reqwest::Proxy::all(&socks_url).ok()?)
        .connect_timeout(DOCTOR_ENGINE_CALL_TIMEOUT)
        .timeout(DOCTOR_ENGINE_CALL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("kt-signal-connector/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()
}

/// The system-trust leg's HTTPS client (§4.161): everything the strict
/// client is — the launcher proxy as the only `socks5h://` route, the
/// 3-second diagnostic budgets, redirects off, fresh per diagnostic — minus
/// the pinned anchor. The roots come from the platform trust store (the
/// `rustls-tls-native-roots` chain: on macOS the Security.framework
/// keychains, user-installed CAs included) — the official desktop's own
/// trust posture, and the same roots the supervisor's CDN
/// attachment-download client rides since contract revision 1.163. An
/// environment with no platform roots at all still builds the client; the
/// leg then answers `tls_failed` honestly (empty store — every handshake
/// fails), never a fabricated verdict.
fn system_trust_client(proxy: &SocksProxy) -> Option<reqwest::Client> {
    let socks_url = format!("socks5h://{}:{}", proxy.host, proxy.port);
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&socks_url).ok()?)
        .connect_timeout(DOCTOR_ENGINE_CALL_TIMEOUT)
        .timeout(DOCTOR_ENGINE_CALL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("kt-signal-connector/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()
}

/// One read-only GET probe: the wall time is measured around the whole call
/// but reported only with the `http` classification.
async fn probe_service_face(client: &reqwest::Client, url: &'static str) -> ServiceProbe {
    let started = std::time::Instant::now();
    let outcome = client.get(url).send().await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    service_outcome_probe(outcome, latency_ms)
}

/// The pure outcome half, split from the transport call so the unit suite
/// pins every literal without any network.
fn service_outcome_probe(
    outcome: Result<reqwest::Response, reqwest::Error>,
    latency_ms: u64,
) -> ServiceProbe {
    match outcome {
        Ok(response) => ServiceProbe {
            classification: "http",
            status: Some(response.status().as_u16()),
            latency_ms: Some(latency_ms),
        },
        Err(error) => ServiceProbe {
            classification: service_failure_literal(&error),
            status: None,
            latency_ms: None,
        },
    }
}

/// The pure classification half: fold the transport failure's primitive
/// discriminators into exactly one fixed report literal. `socks_marker` is
/// reqwest's own SOCKS-layer marker found in the error's source chain (see
/// `error_chain_names_socks`).
fn classify_failure(is_timeout: bool, is_connect: bool, socks_marker: bool) -> &'static str {
    if is_timeout {
        return "timeout";
    }
    if !is_connect || socks_marker {
        return "socks_refused";
    }
    "tls_failed"
}

/// The reqwest adapter onto the pure classifier. A residual failure that is
/// neither a timeout nor a TLS-layer event folds to `socks_refused`: with the
/// SOCKS route as the only configured path, a non-timeout transport failure
/// is the link refusing us — no sixth literal is invented.
fn service_failure_literal(error: &reqwest::Error) -> &'static str {
    classify_failure(
        error.is_timeout(),
        error.is_connect(),
        error_chain_names_socks(error),
    )
}

/// Whether the error's source chain carries reqwest's own SOCKS-layer marker
/// ("error connecting to socks proxy" / "error resolving for socks proxy" —
/// reqwest-owned static strings, never upstream content). Distinguishes a
/// failure inside the proxy hop from one above it (the TLS handshake).
fn error_chain_names_socks(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = error.source();
    while let Some(current) = source {
        if current.to_string().contains("socks") {
            return true;
        }
        source = current.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------ engine face --

    fn stopped_status(state: EngineState) -> EngineStatus {
        EngineStatus {
            state,
            pid: None,
            rss_bytes: None,
            resource_pressure: false,
        }
    }

    /// The doctor output structure: every contract key present with the
    /// contract type, degraded engine faces carrying the unreachable reason
    /// on both probes, and no fabricated version data anywhere.
    #[test]
    fn doctor_report_structure_matches_the_contract() {
        let report = DoctorReport {
            connector: ConnectorFace {
                version: env!("CARGO_PKG_VERSION"),
                api_version: crate::API_VERSION,
                pid: std::process::id(),
            },
            store: StoreHealth {
                schema_version: crate::store::SCHEMA_VERSION,
                schema_target: crate::store::SCHEMA_VERSION,
                integrity: "ok",
                db_bytes: 8192,
                wal_bytes: 1024,
                snapshots: crate::store::SnapshotHealth {
                    count: 1,
                    bytes: 8192,
                    last_result: "created",
                    last_at: Some(1_700_000_000_000),
                },
                last_migration_failure: Some(crate::store::MigrationFailureFace {
                    at: 1_700_000_000_000,
                    from: 20,
                    to: crate::store::SCHEMA_VERSION,
                    rollback: "restored".into(),
                    snapshot: Some(
                        "pre-migration-v020-to-v050-0000000001700000000000-1.sqlite3".into(),
                    ),
                }),
                schema_newer: Some(crate::store::SchemaNewerFace {
                    at: 1_700_000_000_000,
                    current: crate::store::SCHEMA_VERSION + 1,
                    supported: crate::store::SCHEMA_VERSION,
                }),
            },
            events: EventLogHealth {
                readable: true,
                token_generation: 3,
                trimmed_through_seq: 41,
                seq_max: 64,
                rows: 23,
                bytes: 1864,
                oldest_created_at: Some(1_700_000_000_000),
                newest_created_at: Some(1_700_000_060_000),
                retention: crate::store::EventLogRetentionHealth {
                    max_age_ms: crate::store::EVENT_LOG_RETENTION_MS,
                    max_rows: crate::store::EVENT_LOG_MAX_ROWS,
                    max_bytes: crate::store::EVENT_LOG_MAX_BYTES,
                },
            },
            groups: vec![GroupReport {
                group_id: "default".into(),
                engine: EngineFace {
                    state: EngineState::Faulted,
                    pid: None,
                    rss_bytes: None,
                    resource_pressure: false,
                    reachable: false,
                    unreachable_reason: Some(unreachable_reason(EngineState::Faulted)),
                    version: Some(EngineMethodFace::failed(unreachable_reason(
                        EngineState::Faulted,
                    ))),
                    protocol_capabilities: Some(EngineMethodFace::failed(unreachable_reason(
                        EngineState::Faulted,
                    ))),
                    perf_metrics: Some(EngineMethodFace::failed(unreachable_reason(
                        EngineState::Faulted,
                    ))),
                    engine_version: None,
                    engine_contract_revision: None,
                    engine_contract_status: "unreachable",
                    engine_contract_reason: None,
                },
                data_dir: DataDirFace {
                    path: "/tmp/never-logged".into(),
                    exists: true,
                    writable: true,
                    free_bytes: Some(4096),
                    total_bytes: Some(8192),
                },
                lock: LockFace {
                    present: true,
                    held: true,
                    pid: Some(7),
                    holder_alive: Some(true),
                    classification: "held",
                },
                credentials: CredentialsFace {
                    state: "credentialsInvalid",
                },
            }],
            network: NetworkFace {
                watchdog_restarts_total: 0,
                receive_dropped_total: 0,
            },
            recent_errors: ErrorRingReport {
                window: ERROR_RING_CAPACITY,
                recorded_total: 2,
                families: vec![ErrorFamilyCount {
                    source: "host",
                    family: "UPSTREAM_TIMEOUT",
                    retryable: true,
                    count: 2,
                    last_at_unix_ms: 1,
                }],
            },
            service: ServiceFace {
                proxy_configured: true,
                chat: ServiceProbe {
                    classification: "http",
                    status: Some(401),
                    latency_ms: Some(123),
                },
                storage: ServiceProbe {
                    classification: "socks_refused",
                    status: None,
                    latency_ms: None,
                },
                system_trust: Some(ServiceProbe {
                    classification: "http",
                    status: Some(200),
                    latency_ms: Some(7),
                }),
            },
        };
        let value = serde_json::to_value(&report).expect("serialize");
        let connector = value.get("connector").expect("connector face");
        assert!(connector.get("version").is_some_and(Value::is_string));
        assert_eq!(
            connector.get("apiVersion").and_then(Value::as_str),
            Some(crate::API_VERSION)
        );
        assert!(connector.get("pid").is_some_and(Value::is_u64));

        // Contract revision 1.282 (§4.266): the store face rides every doctor
        // payload with the upgrade facts the operator needs after a bad start.
        let store = value.get("store").expect("store face");
        assert_eq!(
            store.get("schemaVersion").and_then(Value::as_i64),
            Some(crate::store::SCHEMA_VERSION)
        );
        assert_eq!(
            store.get("schemaTarget").and_then(Value::as_i64),
            Some(crate::store::SCHEMA_VERSION)
        );
        assert_eq!(store.get("integrity").and_then(Value::as_str), Some("ok"));
        assert_eq!(store.get("dbBytes").and_then(Value::as_u64), Some(8192));
        assert_eq!(store.get("walBytes").and_then(Value::as_u64), Some(1024));
        let snapshots = store.get("snapshots").expect("snapshot face");
        assert_eq!(snapshots.get("count").and_then(Value::as_u64), Some(1));
        assert_eq!(
            snapshots.get("lastResult").and_then(Value::as_str),
            Some("created")
        );
        let failure = store.get("lastMigrationFailure").expect("failure face");
        assert_eq!(failure.get("from").and_then(Value::as_i64), Some(20));
        assert_eq!(
            failure.get("rollback").and_then(Value::as_str),
            Some("restored")
        );
        // Contract revision 1.284 (§4.268): a refused open because the store
        // belongs to a newer connector stays visible on the doctor's store
        // face, with both numbers and nothing else.
        let newer = store.get("schemaNewer").expect("schemaNewer face");
        assert_eq!(
            newer.get("current").and_then(Value::as_i64),
            Some(crate::store::SCHEMA_VERSION + 1)
        );
        assert_eq!(
            newer.get("supported").and_then(Value::as_i64),
            Some(crate::store::SCHEMA_VERSION)
        );
        assert!(newer.get("at").and_then(Value::as_u64).is_some());

        // Contract revision 1.283 (§4.267): the ledger's face rides the same
        // payload — generation, floor, head, rows, bytes, window — and never
        // the token itself (doctor output is pasted into bug reports).
        let events = value.get("events").expect("events face");
        assert_eq!(events.get("readable").and_then(Value::as_bool), Some(true));
        assert_eq!(
            events.get("tokenGeneration").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            events.get("trimmedThroughSeq").and_then(Value::as_i64),
            Some(41)
        );
        assert_eq!(events.get("seqMax").and_then(Value::as_i64), Some(64));
        assert_eq!(events.get("rows").and_then(Value::as_u64), Some(23));
        assert_eq!(events.get("bytes").and_then(Value::as_u64), Some(1864));
        assert!(
            events.get("token").is_none(),
            "the token never reaches doctor"
        );
        let retention = events.get("retention").expect("retention window");
        assert_eq!(
            retention.get("maxRows").and_then(Value::as_i64),
            Some(crate::store::EVENT_LOG_MAX_ROWS)
        );

        let group = &value["groups"][0];
        assert_eq!(group["groupId"], json!("default"));
        let engine = &group["engine"];
        assert_eq!(engine["state"], json!("faulted"));
        assert_eq!(engine["reachable"], json!(false));
        assert_eq!(
            engine["pid"],
            Value::Null,
            "absent optional keys stay absent"
        );
        assert!(
            engine["unreachableReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("faulted")),
            "the state classification names the fault"
        );
        for probe in ["version", "protocolCapabilities"] {
            assert_eq!(engine[probe]["present"], json!(false));
            assert!(
                engine[probe]["reason"].is_string(),
                "{probe} degrades with the honest reason"
            );
            assert!(
                engine[probe].get("face").is_none(),
                "{probe} invents nothing"
            );
        }

        let data_dir = &group["dataDir"];
        assert!(data_dir["path"].is_string());
        assert_eq!(data_dir["exists"], json!(true));
        assert_eq!(data_dir["writable"], json!(true));
        assert_eq!(data_dir["freeBytes"], json!(4096));
        assert_eq!(data_dir["totalBytes"], json!(8192));

        let lock = &group["lock"];
        assert_eq!(lock["present"], json!(true));
        assert_eq!(lock["held"], json!(true));
        assert_eq!(lock["pid"], json!(7));
        assert_eq!(lock["holderAlive"], json!(true));
        assert_eq!(lock["classification"], json!("held"));

        let credentials = &group["credentials"];
        assert_eq!(credentials["state"], json!("credentialsInvalid"));

        let recent = &value["recentErrors"];
        assert_eq!(recent["window"], json!(ERROR_RING_CAPACITY));
        assert!(recent["recordedTotal"].is_u64());
        let family = &recent["families"][0];
        assert_eq!(family["source"], json!("host"));
        assert_eq!(family["family"], json!("UPSTREAM_TIMEOUT"));
        assert_eq!(family["retryable"], json!(true));
        assert_eq!(family["count"], json!(2));
        assert!(family["lastAtUnixMs"].is_u64());

        let network = &value["network"];
        assert!(network["watchdogRestartsTotal"].is_u64());
        assert!(network["receiveDroppedTotal"].is_u64());

        let service = &value["service"];
        assert_eq!(service["proxyConfigured"], json!(true));
        assert_eq!(service["chat"]["classification"], json!("http"));
        assert_eq!(service["chat"]["status"], json!(401));
        assert_eq!(service["chat"]["latencyMs"], json!(123));
        assert_eq!(service["storage"]["classification"], json!("socks_refused"));
        assert_eq!(
            service["storage"]["status"],
            Value::Null,
            "status rides only with the http classification"
        );
        assert_eq!(
            service["storage"]["latencyMs"],
            Value::Null,
            "latencyMs rides only with the http classification"
        );

        // The system-trust leg (revision 1.163): present on the configured
        // face, riding the same probe shape as the strict legs.
        let system_trust = service
            .get("systemTrust")
            .expect("the configured face carries the 1.163 system-trust leg");
        assert_eq!(system_trust["classification"], json!("http"));
        assert_eq!(system_trust["status"], json!(200));
        assert_eq!(system_trust["latencyMs"], json!(7));
    }

    /// Engine-unreachable degradation: a non-running engine marks
    /// `reachable: false`, classifies the state into the reason, and answers
    /// both probes `present: false` with that reason — never a guessed
    /// version or baseline, and never an engine spawn attempt.
    #[tokio::test]
    async fn engine_unreachable_degrades_honestly() {
        for state in [
            EngineState::Stopped,
            EngineState::Exited,
            EngineState::Faulted,
        ] {
            let face = engine_face(
                &stopped_status(state),
                None,
                &crate::engine_contract::EngineContractState::default(),
            )
            .await;
            assert!(!face.reachable, "{state:?} is not reachable");
            assert_eq!(face.unreachable_reason, Some(unreachable_reason(state)));
            let version = face.version.expect("version face always present");
            let capabilities = face
                .protocol_capabilities
                .expect("capabilities face always present");
            assert!(!version.present);
            assert_eq!(version.reason, Some(unreachable_reason(state)));
            assert!(!capabilities.present);
            assert_eq!(capabilities.reason, Some(unreachable_reason(state)));
        }
    }

    /// A reachable engine's method faces: answers pass through verbatim and
    /// engine failures degrade to the honest failure classes.
    #[tokio::test]
    async fn engine_method_faces_answer_and_degrade_verbatim() {
        let status = EngineStatus {
            state: EngineState::Running,
            pid: Some(9),
            rss_bytes: None,
            resource_pressure: false,
        };
        // No engine handle despite Running status: the honest unreachable.
        let face = engine_face(
            &status,
            None,
            &crate::engine_contract::EngineContractState::default(),
        )
        .await;
        assert!(!face.reachable);
        assert_eq!(
            face.unreachable_reason,
            Some("the engine is transitioning: the live handle vanished mid-probe")
        );
        assert_eq!(
            face.version.and_then(|version| version.reason),
            face.unreachable_reason
        );

        // Answered probes ride verbatim, including unknown keys.
        let answered =
            EngineMethodFace::answered(json!({"baseline": {"presageRev": "a"}, "extra": 1}));
        assert!(answered.present);
        assert_eq!(answered.face.expect("face")["extra"], json!(1));
    }

    // ------------------------------------------------------ credentials --

    /// The credential face's fixed literal ladder (contract revision 1.101):
    /// every fold pinned from pure inputs with no engine and no network —
    /// the registered answer, the credential-death face, the four
    /// probe-impossible transport failures, and the honest indeterminate
    /// fold for every other engine answer (the upstream-error families the
    /// connector cannot separate from a dead route at this boundary).
    #[test]
    fn credentials_state_literal_maps_every_branch() {
        use EngineError as Error;
        let cases: [(Result<Value, EngineError>, &str); 9] = [
            (Ok(json!({ "isRegistered": true })), "healthy"),
            (Ok(json!({})), "healthy"),
            (Err(Error::Unauthorized), "credentialsInvalid"),
            (Err(Error::Timeout), "unreachable"),
            (Err(Error::NotRunning), "unreachable"),
            (Err(Error::Exited), "unreachable"),
            (Err(Error::Backpressure), "unreachable"),
            (
                Err(Error::Upstream {
                    cause: None,
                    code: None,
                }),
                "indeterminate",
            ),
            (Err(Error::Protocol), "indeterminate"),
        ];
        for (result, expected) in cases {
            assert_eq!(
                credentials_state_literal(&result),
                expected,
                "{result:?} must fold to {expected}"
            );
        }
    }

    /// The gate folds like the engine face's reachability rule: no live
    /// engine answers `unreachable` regardless of any account, a live engine
    /// without an account answers `noAccount`, and the probe target itself
    /// never enters the serialized face.
    #[tokio::test]
    async fn credentials_face_degrades_without_engine_or_account() {
        let running = EngineStatus {
            state: EngineState::Running,
            pid: Some(9),
            rss_bytes: None,
            resource_pressure: false,
        };
        let stopped = stopped_status(EngineState::Stopped);

        for (status, engine, account, expected) in [
            (&stopped, None, Some("+15555550100"), "unreachable"),
            // A Running status with no live handle is the transitioning race:
            // unreachable, not noAccount — the gate is reachability first.
            (&running, None, Some("+15555550100"), "unreachable"),
            (&running, None, None, "unreachable"),
        ] {
            let face = credentials_face(status, engine, account).await;
            assert_eq!(face.state, expected);
        }

        // A running engine with no group account skips to noAccount — the
        // pure gate covers the branch the suite cannot reach with a live
        // handle (no engine spawns in the unit suite).
        match credentials_probe_gate(true, None, None) {
            CredentialsProbe::Skip(state) => assert_eq!(state, "noAccount"),
            CredentialsProbe::Run(..) => panic!("no live handle must never reach the probe"),
        }

        let value = serde_json::to_value(CredentialsFace { state: "healthy" }).expect("serialize");
        assert_eq!(value, json!({ "state": "healthy" }));
        assert!(
            value.get("account").is_none(),
            "the probe target never enters the report"
        );
    }

    // ------------------------------------------------------------- lock --

    #[cfg(unix)]
    fn hold_flock(path: &Path) -> std::fs::File {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open lock file");
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).expect("flock");
        file
    }

    /// Lock form 1 — no lock file at all.
    #[test]
    fn lock_face_reports_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let face = probe_lock(dir.path());
        assert!(!face.present);
        assert!(!face.held);
        assert_eq!(face.pid, None);
        assert_eq!(face.holder_alive, None);
        assert_eq!(face.classification, "none");
    }

    /// Lock form 2 — a kernel-held lock: `held` proves a live holder by
    /// construction, the recorded pid surfaces, and the probe leaves the
    /// holder's lock in place.
    #[cfg(unix)]
    #[test]
    fn lock_face_reports_a_live_held_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(LOCK_FILE_NAME);
        std::fs::write(&lock_path, format!("{}", std::process::id())).expect("write pid");
        let _guard = hold_flock(&lock_path);
        let face = probe_lock(dir.path());
        assert!(face.present);
        assert!(face.held, "the probe must see the held kernel lock");
        assert_eq!(face.pid, Some(std::process::id()));
        assert_eq!(face.holder_alive, Some(true));
        assert_eq!(face.classification, "held");
    }

    /// Lock form 3 — a stale remnant: file present, no kernel holder, the
    /// recorded pid dead. Exactly the crashed-then-replaced holder shape.
    #[cfg(unix)]
    #[test]
    fn lock_face_reports_a_stale_dead_pid_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(LOCK_FILE_NAME);
        // A pid guaranteed dead: an exited child.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let dead_pid = child.id();
        child.wait().expect("reap");
        std::fs::write(&lock_path, format!("{dead_pid}")).expect("write pid");
        let face = probe_lock(dir.path());
        assert!(face.present);
        assert!(!face.held);
        assert_eq!(face.pid, Some(dead_pid));
        assert_eq!(face.holder_alive, Some(false));
        assert_eq!(face.classification, "stale");
    }

    /// The designed post-release remnant: file present, no holder, pid alive
    /// (or unknown) — classified `released`, never `stale`.
    #[cfg(unix)]
    #[test]
    fn lock_face_reports_a_released_lock_without_a_dead_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(LOCK_FILE_NAME);
        std::fs::write(&lock_path, format!("{}", std::process::id())).expect("write pid");
        let face = probe_lock(dir.path());
        assert!(face.present);
        assert!(!face.held);
        assert_eq!(face.pid, Some(std::process::id()));
        assert_eq!(face.holder_alive, Some(true));
        assert_eq!(face.classification, "released");

        // Pre-face connectors left empty lock files: pid unknown.
        std::fs::write(&lock_path, b"").expect("empty");
        let face = probe_lock(dir.path());
        assert_eq!(face.pid, None);
        assert_eq!(face.holder_alive, None);
        assert_eq!(face.classification, "released");
    }

    /// Corrupted lock content never parses into a pid and never panics.
    #[test]
    fn recorded_pid_rejects_non_pid_content() {
        assert_eq!(recorded_pid(""), None);
        assert_eq!(recorded_pid("not-a-pid"), None);
        assert_eq!(recorded_pid("-1"), None);
        assert_eq!(recorded_pid(&"9".repeat(LOCK_PID_READ_BYTES + 1)), None);
        assert_eq!(recorded_pid("4194304"), Some(4194304));
    }

    /// The read-only discipline, pinned: probing the lock and the data
    /// directory changes no file byte, no mtime, and no directory entry.
    #[cfg(unix)]
    #[test]
    fn probes_leave_the_data_directory_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(LOCK_FILE_NAME);
        std::fs::write(&lock_path, format!("{}", std::process::id())).expect("write pid");
        let _guard = hold_flock(&lock_path);

        let snapshot = |dir: &Path| -> Vec<(String, u64, std::time::SystemTime)> {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .expect("read dir")
                .map(|entry| entry.expect("entry"))
                .map(|entry| {
                    let metadata = entry.metadata().expect("metadata");
                    (
                        entry.file_name().to_string_lossy().into_owned(),
                        metadata.len(),
                        metadata.modified().expect("mtime"),
                    )
                })
                .collect();
            entries.sort();
            entries
        };
        let before = snapshot(dir.path());

        let _ = probe_lock(dir.path());
        let _ = probe_data_dir(dir.path());
        let _ = filesystem_space(dir.path());
        let _ = path_is_writable(dir.path());

        assert_eq!(
            snapshot(dir.path()),
            before,
            "no byte, size, or entry changed"
        );
        assert_eq!(
            std::fs::read(&lock_path).expect("lock content"),
            format!("{}", std::process::id()).into_bytes(),
            "lock file content untouched"
        );
        // The held lock is still held after the probe.
        assert!(probe_lock(dir.path()).held);
    }

    /// Data-dir status: existence, writability, and real free-space numbers.
    #[test]
    fn data_dir_face_reports_status_without_writing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let face = probe_data_dir(dir.path());
        assert!(face.exists);
        assert!(face.writable);
        assert!(face.free_bytes.is_some_and(|bytes| bytes > 0));
        assert!(face.total_bytes.is_some_and(|bytes| bytes > 0));
        assert!(face.path.contains(dir.path().to_string_lossy().as_ref()));

        let missing = probe_data_dir(&dir.path().join("absent-subdir"));
        assert!(!missing.exists);
        assert!(!missing.writable);
        assert_eq!(
            missing.free_bytes, None,
            "no guessed numbers for a missing dir"
        );
    }

    // -------------------------------------------------------- error ring --

    /// The ring stays bounded, aggregates per family, and carries the
    /// recorded total so a consumer can see truncation.
    #[test]
    fn error_ring_is_bounded_and_aggregates_families() {
        for _ in 0..(ERROR_RING_CAPACITY + 8) {
            record_host_error("UPSTREAM_TIMEOUT", true);
        }
        record_protocol_warning("unknownOrDuplicateResponseId");
        let snapshot = error_ring_snapshot();
        assert_eq!(snapshot.window, ERROR_RING_CAPACITY);
        assert!(snapshot.recorded_total >= ERROR_RING_CAPACITY as u64 + 9);
        let timeout = snapshot
            .families
            .iter()
            .find(|family| family.family == "UPSTREAM_TIMEOUT")
            .expect("timeout family present");
        // The ring is bounded: capacity entries total, so the last (different)
        // family squeezed the oldest timeout out — 63 timeouts + 1 warning.
        assert_eq!(
            timeout.count,
            (ERROR_RING_CAPACITY - 1) as u64,
            "oldest entries leave the ring when the window is full"
        );
        assert!(timeout.retryable);
        assert_eq!(timeout.source, "host");
        let warning = snapshot
            .families
            .iter()
            .find(|family| family.family == "unknownOrDuplicateResponseId")
            .expect("protocol family present");
        assert_eq!(warning.source, "protocol");
        assert!(!warning.retryable);
        // Deterministic ordering: count descending.
        let counts: Vec<u64> = snapshot
            .families
            .iter()
            .map(|family| family.count)
            .collect();
        let mut sorted = counts.clone();
        sorted.sort_unstable_by(|left, right| right.cmp(left));
        assert_eq!(counts, sorted);
    }

    // ----------------------------------------------------- service plane --

    /// The five fixed classification literals, mapped from pure inputs — no
    /// network anywhere. `http` rides the real `http::Response` conversion
    /// path; the failure literals come from the pure classifier truth table;
    /// `not_configured` is the unconfigured face. Each failure probe must
    /// omit `status`/`latencyMs` on the wire.
    #[tokio::test]
    async fn service_probe_classification_maps_every_literal() {
        let unauthorized = reqwest::Response::from(
            http::Response::builder()
                .status(401)
                .body("")
                .expect("response"),
        );
        let http = service_outcome_probe(Ok(unauthorized), 42);
        assert_eq!(http.classification, "http");
        assert_eq!(http.status, Some(401));
        assert_eq!(http.latency_ms, Some(42));

        for (is_timeout, is_connect, socks_marker, expected) in [
            (true, true, false, "timeout"),
            (false, true, true, "socks_refused"),
            // Residual transport failures fold to the refused literal — no
            // sixth literal is invented.
            (false, false, false, "socks_refused"),
            (false, true, false, "tls_failed"),
        ] {
            assert_eq!(
                classify_failure(is_timeout, is_connect, socks_marker),
                expected,
                "classifier truth table"
            );
        }

        let not_configured = service_face_for(None).await;
        assert!(!not_configured.proxy_configured);
        let value = serde_json::to_value(&not_configured).expect("serialize");
        assert_eq!(value["proxyConfigured"], json!(false));
        for probe in ["chat", "storage"] {
            assert_eq!(value[probe]["classification"], json!("not_configured"));
            assert_eq!(value[probe].get("status"), None);
            assert_eq!(value[probe].get("latencyMs"), None);
        }
        assert_eq!(
            value.get("systemTrust"),
            None,
            "the unconfigured face probes nothing: the 1.163 leg stays absent, never failed"
        );
    }

    /// The §4.161 dual track's two wire forms, pinned additively: the key
    /// absent keeps the pre-1.163 face key set exactly (chat, storage,
    /// proxyConfigured — nothing else), and the key present rides the same
    /// probe shape the strict legs use (classification always, status/
    /// latencyMs only with `http` — the literal mapping itself is shared
    /// code, pinned by `service_probe_classification_maps_every_literal`).
    #[test]
    fn system_trust_face_rides_both_forms_additively() {
        let absent = ServiceFace {
            proxy_configured: false,
            chat: ServiceProbe {
                classification: "not_configured",
                status: None,
                latency_ms: None,
            },
            storage: ServiceProbe {
                classification: "not_configured",
                status: None,
                latency_ms: None,
            },
            system_trust: None,
        };
        let value = serde_json::to_value(&absent).expect("serialize");
        let mut keys: Vec<_> = value
            .as_object()
            .expect("face object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["chat", "proxyConfigured", "storage"],
            "the absent form keeps the pre-1.163 key set byte-stable"
        );
        for probe in ["chat", "storage"] {
            assert_eq!(
                value[probe].as_object().map(|object| object.len()),
                Some(1),
                "{probe} carries exactly its classification here"
            );
        }

        let present = ServiceFace {
            proxy_configured: true,
            chat: ServiceProbe {
                classification: "tls_failed",
                status: None,
                latency_ms: None,
            },
            storage: ServiceProbe {
                classification: "tls_failed",
                status: None,
                latency_ms: None,
            },
            system_trust: Some(ServiceProbe {
                classification: "http",
                status: Some(401),
                latency_ms: Some(9),
            }),
        };
        let value = serde_json::to_value(&present).expect("serialize");
        assert_eq!(value["systemTrust"]["classification"], json!("http"));
        assert_eq!(value["systemTrust"]["status"], json!(401));
        assert_eq!(value["systemTrust"]["latencyMs"], json!(9));
        // The strict legs keep their own shape next to the new key — the
        // pinned-anchor face unchanged (status absent off-http).
        assert_eq!(value["chat"]["classification"], json!("tls_failed"));
        assert_eq!(
            value["chat"].as_object().map(|object| object.len()),
            Some(1)
        );
    }

    /// Both §4.161 clients build from static settings alone: the strict
    /// client keeps loading its vendored anchor, and the system-trust client
    /// builds on the platform store whatever it holds — an environment with
    /// no platform roots still builds (the leg then answers `tls_failed`
    /// honestly), so the two verdicts stand independently.
    #[test]
    fn dual_track_clients_build_independently() {
        let proxy = SocksProxy {
            host: "127.0.0.1".into(),
            port: 1080,
        };
        assert!(
            service_client(&proxy).is_some(),
            "the strict client keeps its static vendored anchor"
        );
        assert!(
            system_trust_client(&proxy).is_some(),
            "the system-trust client builds without any custom anchor"
        );
    }

    /// The SOCKS-layer marker survives reqwest's real error chain: a loopback
    /// SOCKS refusal (nothing listens on the port) classifies
    /// `socks_refused` — offline by construction, the refusal is immediate.
    #[tokio::test]
    async fn socks_layer_failures_carry_the_socks_marker_through_the_real_chain() {
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:1").expect("proxy url"))
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_millis(500))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let error = client
            .get("https://chat.signal.org/")
            .send()
            .await
            .expect_err("loopback socks connect must fail");
        assert_eq!(service_failure_literal(&error), "socks_refused");
        // The marker walk itself is what found the layer.
        assert!(error_chain_names_socks(&error));
    }

    /// The launcher variable is `host:port`; an explicit `socks5(h)://` prefix
    /// is tolerated and normalized. Anything else reads as unconfigured.
    #[test]
    fn env_proxy_parser_tolerates_the_socks5h_prefix() {
        assert_eq!(
            parse_socks_proxy_env("127.0.0.1:1080"),
            Some(SocksProxy {
                host: "127.0.0.1".into(),
                port: 1080,
            })
        );
        assert_eq!(
            parse_socks_proxy_env("socks5h://relay.example.com:7890"),
            Some(SocksProxy {
                host: "relay.example.com".into(),
                port: 7890,
            })
        );
        assert_eq!(
            parse_socks_proxy_env("socks5://127.0.0.1:1080"),
            parse_socks_proxy_env("127.0.0.1:1080")
        );
        for raw in ["", ":", "127.0.0.1", "http://127.0.0.1:1080", "::1:1080"] {
            assert_eq!(
                parse_socks_proxy_env(raw),
                None,
                "malformed proxy values read as unconfigured: {raw:?}"
            );
        }
    }
}
