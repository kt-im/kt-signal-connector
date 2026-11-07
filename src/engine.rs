// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncWriteExt, sink};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::time::timeout;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::groups::MAX_ACCOUNTS_PER_ENGINE;
use crate::resource::{
    DEFAULT_RSS_PRESSURE_BYTES, DEFAULT_RSS_PRESSURE_SAMPLES, DEFAULT_RSS_RECOVERY_BYTES,
    DEFAULT_RSS_RECOVERY_SAMPLES, ResourcePressureState, ResourcePressureTracker, sample_rss,
};
use crate::{DEFAULT_UPSTREAM_LINE_LIMIT, MAX_PENDING_UPSTREAM_REQUESTS};

const COMMAND_QUEUE_CAPACITY: usize = 128;
/// Bounded queue of framed requests waiting for the child's stdin (A7): the
/// actor hands whole encoded requests to a dedicated writer task, so a child
/// that stops reading its stdin parks only that task, never the actor loop.
/// Frames are the connector's own validated requests (tens of KiB at most),
/// so a full queue bounds to well under 2 MiB of in-flight bytes. A full
/// queue answers Backpressure, the same admission failure as the pending map
/// cap; the queue can only fill when the pipe itself is already full.
pub const STDIN_WRITE_QUEUE_CAPACITY: usize = 16;
/// Bounded queue of lines pumped from the child's stdout to the actor. The
/// pump is the pipe's only reader (A7, symmetric with the stdin writer), so a
/// burst of engine output parks the pump alone until the actor drains it;
/// capacity bounds the buffered lines (each capped at `line_limit`).
const STDOUT_LINE_QUEUE_CAPACITY: usize = 64;
/// A line pumped off the child's stdout. `FramingError` marks a codec failure
/// (oversized or malformed line); end-of-stream arrives as the channel
/// closing, the same EOF signal the inline arm used to observe.
#[derive(Debug, PartialEq)]
enum PumpedLine {
    Line(String),
    FramingError,
}
const EVENT_QUEUE_CAPACITY: usize = 1024;
const RECEIVE_QUEUE_CAPACITY: usize = 256;
const RECEIVE_QUEUE_BYTE_CAPACITY: usize = 2 * 1024 * 1024;
/// Per-account receive share (packet 1.196, internal): the global queue
/// bounds stay the outer contract, but a single account's flood must not
/// consume them all and crowd out a second account. 64 slots / 512 KiB is
/// the account's own in-flight ceiling; a burst past it drops under the
/// existing drop/warn semantics instead of parking the engine actor (the
/// per-account permits are tried without waiting, so the flooding account
/// cannot stall the line loop for everyone else). Four accounts can fill
/// the global 256/2 MiB caps, which remain unchanged.
const RECEIVE_QUEUE_PER_ACCOUNT_CAPACITY: usize = 64;
const RECEIVE_QUEUE_PER_ACCOUNT_BYTE_CAPACITY: usize = 512 * 1024;
/// How long receive admission may wait on the global queue capacity before
/// the receive is dropped instead of parking the engine actor. Healthy
/// persistence drains the queue in milliseconds; a queue that stays full for
/// this long means storage is not draining, and the actor must stay
/// responsive to its command lane (including shutdown) instead of
/// backpressuring forever. The per-account share does not wait: its permits
/// are tried once, so a flooded account drops immediately and never parks the
/// loop another account's receives need.
const RECEIVE_ENQUEUE_TIMEOUT: Duration = Duration::from_secs(30);
/// Slack over the child graceful-exit budget after which an unanswered
/// shutdown request is considered stuck and the child is killed directly.
const SHUTDOWN_TIMEOUT_MARGIN: Duration = Duration::from_secs(2);
/// Default graceful-exit budget handed to the engine before the connector
/// escalates to SIGKILL (the total wait is this plus the margin above). The
/// engine's own pipeline drain grace is 10 s, so the pre-pool 3 s budget
/// truncated a legitimate graceful stop into a hard kill under a slow disk or
/// a large receive backlog. Ten seconds aligns the two and yields the 12 s
/// connector-side budget the per-account engine pool documents (design
/// §6.2/§6.6); a single-slot stop still finishes in milliseconds in the
/// healthy case.
pub const DEFAULT_ENGINE_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const MAX_INBOUND_TEXT_BYTES: usize = 128 * 1024;
const MAX_INBOUND_TEXT_PREVIEW_BYTES: usize = 4 * 1024;
/// Receive routing ids (account, source, group id). These ids become stored
/// peer keys, which the schema bounds at 128 (opaqueId/peerKey family in
/// schemas/connector-api-v1.schema.json); accepting a longer one inbound would
/// create a conversation the host contract forbids addressing. `pub` since
/// the §4.83 delete-for-me author field mirrors the same bound (the
/// schema-pairing test pins the two together).
pub const MAX_RECEIVE_ID_CHARS: usize = 128;
/// The spam-report token's inbound bound (reportSpam data plane): the official
/// `reportSpamToken` is a small server-issued opaque blob (base64 on the
/// engine's envelope face); 128 chars is the opaqueId-family bound applied to
/// the stored copy — an oversized inbound token is truncated-away evidence of
/// a misbehaving engine, never a contract address, so a longer one folds to
/// `None` rather than truncating a credential.
const MAX_REPORTING_TOKEN_CHARS: usize = 128;
const STDERR_QUEUE_CAPACITY: usize = 64;
const STDERR_LINE_LIMIT: usize = 4 * 1024;

/// Receive-liveness restart backoff base. The first restart of a failure
/// episode is immediate; retries then wait `base`, `2 * base`, `4 * base`, …
/// capped at `WATCHDOG_LIVENESS_BACKOFF_CAP`. Ten seconds is the deliberate
/// difference between a dead receive WebSocket (retry while a user is still
/// waiting) and a genuinely dead network (back off). It must never borrow the
/// five-minute anti-storm window (`watchdog_min_restart_interval`): using that
/// as the retry base left users connected "once every five minutes".
pub const WATCHDOG_LIVENESS_BACKOFF_BASE: Duration = Duration::from_secs(10);
/// Ceiling on the receive-liveness restart backoff (three minutes): fast
/// enough to heal a wedged receive path, slow enough that an unreachable
/// upstream cannot turn the watchdog into a restart storm.
pub const WATCHDOG_LIVENESS_BACKOFF_CAP: Duration = Duration::from_secs(180);

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub executable: PathBuf,
    pub data_dir: PathBuf,
    /// Media ingest opt-in (ADR 0004). Launcher input only — never IPC
    /// input. Since contract 1.121 (§4.102) the decision passes through
    /// verbatim: armed ingest drops `--ignore-attachments` from the argv and
    /// arms the media governor (the §4.54 locator chain serves the bytes on
    /// demand); unarmed keeps the pre-ingest shape and every media method
    /// answers `CAPABILITY_UNAVAILABLE`.
    pub media_ingest: bool,
    pub line_limit: usize,
    pub request_timeout: Duration,
    pub shutdown_grace: Duration,
    pub receive_enqueue_timeout: Duration,
    pub resource_sample_interval: Duration,
    pub watchdog_interval: Duration,
    /// Anti-storm window between failure episodes: a trigger-free gap longer
    /// than this resets the watchdog's restart schedule, so only one fresh
    /// "immediate" restart can begin per window. It deliberately does NOT
    /// pace retries — receive-liveness retries use
    /// `watchdog_liveness_backoff_base`, so a dead receive path is retried in
    /// seconds rather than once every five minutes.
    pub watchdog_min_restart_interval: Duration,
    /// Receive-liveness retry backoff base (`WATCHDOG_LIVENESS_BACKOFF_BASE`):
    /// the first restart is immediate, later ones double from here up to
    /// `WATCHDOG_LIVENESS_BACKOFF_CAP`. A zero value (integration tests) keeps
    /// every retry immediate; production keeps the ten-second default.
    pub watchdog_liveness_backoff_base: Duration,
    /// Disappearing-message sweep cadence (contract 1.42, §4.41): how often
    /// each group's supervisor looks for rows whose timer ran out. The
    /// launcher may tighten it (integration tests); production keeps the
    /// default — a disappearing message legitimately outlives this by design.
    pub expire_sweep_interval: Duration,
    /// Transit-CDN base override for the §4.38 step-3 attachment download
    /// chain. `None` keeps the official production CDN map
    /// (`cdn.signal.org`/`cdn2`/`cdn3` per cdnNumber); `Some(base)` aims
    /// every history-attachment GET at one base instead — the same seam the
    /// official desktop carries as window config values, used by tests and
    /// never set by the production launcher.
    pub history_cdn_base: Option<String>,
}

impl EngineConfig {
    pub fn new(executable: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            executable,
            data_dir,
            media_ingest: false,
            line_limit: DEFAULT_UPSTREAM_LINE_LIMIT,
            history_cdn_base: None,
            request_timeout: Duration::from_secs(15),
            shutdown_grace: DEFAULT_ENGINE_SHUTDOWN_GRACE,
            receive_enqueue_timeout: RECEIVE_ENQUEUE_TIMEOUT,
            resource_sample_interval: Duration::from_secs(30),
            watchdog_interval: Duration::from_secs(30),
            watchdog_min_restart_interval: Duration::from_secs(300),
            watchdog_liveness_backoff_base: WATCHDOG_LIVENESS_BACKOFF_BASE,
            expire_sweep_interval: Duration::from_secs(30),
        }
    }
}

/// Optional SOCKS proxy for the engine child (the trusted launcher's
/// per-group plan input, ADR 0001). Proxy parity with the engine holds at
/// the environment level: the engine consumes the same
/// `KT_SIGNAL_SOCKS_PROXY` variable this process inherited (it maps it onto
/// reqwest's `ALL_PROXY`, which covers the libsignal-service HTTP and
/// WebSocket transport); nothing proxy-shaped is ever placed on the child
/// command line (the engine's argv parser is fail-closed on unknown
/// arguments).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksProxy {
    pub host: String,
    pub port: u16,
}

impl SocksProxy {
    /// Parse `host:port`. The host must be non-empty, at most 253 bytes, and
    /// free of whitespace and ':' (no IPv6 literals); the port must be
    /// 1-65535.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (host, port) = value
            .split_once(':')
            .ok_or_else(|| "proxy must use host:port".to_string())?;
        if host.is_empty()
            || host.len() > 253
            || host.chars().any(|c| c.is_whitespace() || c == ':')
        {
            return Err(
                "proxy host must be non-empty and contain no whitespace or ':'".to_string(),
            );
        }
        let port: u16 = port
            .parse()
            .map_err(|_| "proxy port must be a number between 1 and 65535".to_string())?;
        if port == 0 {
            return Err("proxy port must be a number between 1 and 65535".to_string());
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

impl std::str::FromStr for SocksProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Engine CLI arguments. `media_ingest` (ADR 0004) only decides whether
/// `--ignore-attachments` is present: with it the rest of the argv —
/// including `--ignore-stories` and `--ignore-stickers` — is unchanged, and
/// without it the argv is byte-identical to the pre-media-POC launcher.
fn engine_args(data_dir: &Path, media_ingest: bool) -> Vec<std::ffi::OsString> {
    // Explicit: pull server messages as soon as the daemon is up.
    let mut args: Vec<std::ffi::OsString> = vec![
        "--data-dir".into(),
        data_dir.as_os_str().into(),
        "jsonRpc".into(),
        "--receive-mode".into(),
        "on-start".into(),
    ];
    // ADR 0004: dropping --ignore-attachments is the entire media opt-in —
    // the engine then downloads inbound attachments into its data directory,
    // where the connector's media governor bounds retention. --ignore-stories
    // and --ignore-stickers stay in every shape for argv compatibility, but
    // they are no-ops on the engine side (engine f2ba462): stickers project
    // metadata-only and stories project transient regardless of the flags, so
    // this argument list does not discard them.
    if !media_ingest {
        args.push("--ignore-attachments".into());
    }
    args.push("--ignore-stories".into());
    args.push("--ignore-stickers".into());
    args
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EngineState {
    Running,
    Stopped,
    Exited,
    Faulted,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub state: EngineState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    pub resource_pressure: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallClass {
    ReadOnly,
    Mutating,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EngineError {
    #[error("engine process could not be started")]
    StartFailed,
    #[error("engine is not running")]
    NotRunning,
    #[error("engine request queue is full")]
    Backpressure,
    #[error("engine request timed out")]
    Timeout,
    #[error("engine mutating request has an unknown outcome")]
    UnknownOutcome,
    #[error("engine exited before completing the request")]
    Exited,
    #[error("engine produced invalid protocol output")]
    Protocol,
    #[error("engine returned an error")]
    Upstream {
        /// Contract 1.167 §4.165: the engine's embedded cause-class literal,
        /// extracted at the response classifier when the frozen §4.80/§4.95
        /// anchor set leaves the error unclassified — the tailmost
        /// parenthesized class-name token (letter-led `[A-Za-z0-9._]`),
        /// bounded to 120 bytes. Log-only observability: the
        /// `engine call failed` line carries it; the host wire answer
        /// (`UPSTREAM_ERROR`) stays byte for byte. `None` — including every
        /// shape-hostile message — keeps the pre-1.167 log shape.
        cause: Option<String>,
        /// The numeric JSON-RPC error code the engine answered (`-32603` for
        /// its plain internal-error face, `-1` for the generic upstream
        /// face). Internal attribution only: it reaches neither the host wire
        /// answer nor a log line. The receive-liveness probe uses it to tell
        /// the engine's unknown-account face (-32603) from an engine-wide
        /// failure, because that face's message text is not part of the
        /// pinned contract.
        code: Option<i64>,
    },
    #[error("engine rejected the device credentials")]
    Unauthorized,
    /// Contract 1.99 §4.80: the engine's send-chain transport families. The
    /// engine folds a transport-layer send failure into the plain
    /// internal_error JSON-RPC face (-32603) whose `message` embeds the cause
    /// class; these variants surface the family structurally so the host
    /// sees rate limiting, the proof challenge, and server unavailability as
    /// distinct codes instead of generic upstream noise. The variants stay
    /// content-free — the anchor literal is a fixed engine string, never
    /// user data — and the classification carries no event: a transport
    /// failure never touches account state.
    #[error("engine send was rate-limited upstream")]
    RateLimited {
        /// 契约 §4.222：服务端 429/413 给出的等待秒数（engine data 投影）。
        /// 缺席 = 引擎未带（旧版本），宿主回落固定 60 秒（官方 DEFAULT_RETRY_AFTER）。
        retry_after_secs: Option<u64>,
    },
    #[error("engine send requires an upstream proof challenge")]
    ProofRequired,
    #[error("engine server is unavailable")]
    ServerUnavailable,
    /// Contract 1.114 §4.95: the identity-trust gate family. The engine (P9)
    /// refuses a send when the recipient's identity key changed without
    /// confirmation — the same cause official desktop refuses the send for —
    /// and folds it into the plain internal_error face (-32603) whose
    /// `message` embeds the `(UntrustedIdentityException)` anchor, the same
    /// observation shape as the §4.80 transport families. It surfaces
    /// structurally so the host sees the safety-number gate as its own code
    /// instead of generic upstream noise. The variant stays content-free and
    /// the classification carries no event: a per-recipient trust refusal
    /// never touches account state.
    #[error("engine send was rejected: recipient identity is unverified")]
    IdentityUnverified,
    /// The engine answered a JSON-RPC error object with an upstream error
    /// code (contract 1.36 sticker/pin faces): the code string is carried
    /// structurally so the connector maps engine error codes onto the host
    /// contract without swallowing them, while the message text stays
    /// content-free (the code is a fixed literal, never user data).
    /// Contract 1.50: the engine's optional `error.data` object rides along
    /// verbatim (`profileKeyUpdate`-era partial-success facts such as
    /// PROFILE_UPLOAD_FAILED's `{retryable, textSaved}`); a missing data
    /// object serializes as None and older hosts see the 1.49 shape.
    #[error("engine returned a structured error")]
    UpstreamCode {
        code: &'static str,
        #[allow(dead_code)]
        data: Option<Value>,
    },
}

impl EngineError {
    /// Log-safe variant classification: the variants are deliberately
    /// content-free, and logs carry this class rather than any detail.
    /// Crate-visible so the supervisor's liveness probe can log the class of
    /// the error it attributes to a candidate account without any detail.
    pub(crate) fn class(&self) -> &'static str {
        match self {
            EngineError::StartFailed => "start_failed",
            EngineError::NotRunning => "not_running",
            EngineError::Backpressure => "backpressure",
            EngineError::Timeout => "timeout",
            EngineError::UnknownOutcome => "unknown_outcome",
            EngineError::Exited => "exited",
            EngineError::Protocol => "protocol",
            EngineError::Upstream { .. } => "upstream",
            EngineError::Unauthorized => "unauthorized",
            EngineError::RateLimited { .. } => "rate_limited",
            EngineError::ProofRequired => "proof_required",
            EngineError::ServerUnavailable => "server_unavailable",
            EngineError::IdentityUnverified => "identity_unverified",
            EngineError::UpstreamCode { .. } => "upstream_code",
        }
    }
}

fn call_class_label(class: CallClass) -> &'static str {
    match class {
        CallClass::ReadOnly => "read",
        CallClass::Mutating => "mutating",
    }
}

#[derive(Clone, Debug)]
pub enum EngineEvent {
    StateChanged(EngineStatus),
    ProtocolWarning {
        kind: &'static str,
    },
    ResourcePressure {
        state: ResourcePressureState,
        pid: u32,
        rss_bytes: u64,
    },
    /// The receive queue could not be drained for a full enqueue timeout, so
    /// receives are being dropped: local persistence is degraded even though
    /// the engine process itself is alive. `state` is `unavailable` on the
    /// first drop and `recovered` when admission succeeds again; the host
    /// serializes it as the existing `runtime.storageChanged` event.
    StorageChanged {
        state: &'static str,
    },
    /// The Signal server rejected a request because the account holder
    /// unlinked this device on their phone (contract 1.21). `account` is the
    /// signal-cli account number from the failed request's params; requests
    /// without one cannot be attributed and only fail with
    /// [`EngineError::Unauthorized`].
    AccountUnauthorized {
        account: String,
    },
    /// Engine receive-close classification. Invalidated is not an account
    /// terminal state; 4401 only reconnects. The supervisor keeps this on the
    /// health/connection axis, never on account state.
    ConnectionState {
        account: String,
        state: String,
        close_code: Option<u16>,
    },
    /// The engine's `receive.emptied` notification (contract 1.134, §4.117):
    /// the account's history queue drained (the official
    /// ApiEmptyQueue→EmptyEvent peer) — advisory receive-stream state the
    /// engine only reports; the account-domain transient lane (the
    /// supervisor's engine-event watcher) resolves the account and forwards
    /// the host frame. Edge-shaped: emitted once per drain.
    ReceiveEmptied {
        account: String,
    },
    /// The engine's `receive.clockskew` notification (contract 1.134,
    /// §4.117): the local clock sits more than the official 24h threshold
    /// from the server stamp — edge-triggered, so one alert per threshold
    /// crossing and sustained skew stays silent. `skew_ms` is signed
    /// (local − server: positive = the local clock runs fast) and forwards
    /// verbatim; `server_timestamp` is the observing envelope's server
    /// stamp when the engine projected one.
    ReceiveClockSkew {
        account: String,
        skew_ms: i64,
        server_timestamp: Option<u64>,
    },
    /// The engine's `receive.conversationState` notification (contract
    /// 1.134, §4.117): the account's conversation three-flag (muted /
    /// archived / marked-unread) inbound flips, differenced against the
    /// engine's per-account book after a storage merge. `conversations`
    /// is the engine's array verbatim — the connector is a pipe (the owner
    /// red line: a passthrough structure error corrupts every downstream
    /// consumer), never parsed, never trimmed, entries ride with any
    /// sibling key the engine carried; `overflow` is the engine's batch-cap
    /// tail marker. The engine bounds the book (8192/account) and the batch
    /// (256 entries + `overflow`) connector-independently.
    ConversationState {
        account: String,
        conversations: Value,
        overflow: bool,
    },
    /// The engine's `engine.storagePull` notification (contract 1.141,
    /// §4.137): the storage-manifest pull outcome — the engine's T-9b result
    /// event fired once per pull attempt (the login-time automatic pull and
    /// every `fetchLatest` leg), with the per-family legs answering
    /// truthfully (`contactsOk`/`groupsOk`) rather than a bare done bit.
    /// `trigger` forwards verbatim: the type is guaranteed (a string), the
    /// value domain is not — an engine trigger word this connector has not
    /// seen rides through unnamed, never guessed into a known one. The
    /// account-domain transient lane (the supervisor's engine-event watcher)
    /// resolves the account and forwards the host frame.
    StoragePull {
        account: String,
        trigger: String,
        contacts_ok: bool,
        groups_ok: bool,
    },
    /// The engine's `engine.initialSyncComplete` notification (contract
    /// 1.220, §4.230): the link-window post-registration sync set finished —
    /// the engine's initial three sync requests went up, and the login
    /// manifest pull and the first profile-refresh batch both settled (each
    /// with its own timeout face). The two boolean legs answer truthfully
    /// rather than a bare done bit (a false leg = that leg errored or timed
    /// out); the official "complete only fires on success" semantics stay
    /// the desktop's call (it settles its inbox gate on the ok face). The
    /// account-domain transient lane (the supervisor's engine-event watcher)
    /// resolves the account and forwards the host frame.
    InitialSyncComplete {
        account: String,
        manifest_ok: bool,
        profiles_ok: bool,
    },
    /// The engine's decryption-error receive envelope (contract 1.165,
    /// §4.163): a `receive` notification whose envelope carries the
    /// `decryptionError` marker (`{account, envelope: {sourceUuid,
    /// decryptionError: {}, timestamp?}}`) — the engine's structured report
    /// that an inbound envelope failed to decrypt (the 止血批① face; the
    /// official Android observer acks and records it, this connector only
    /// observes). The envelope carries no message row, so the receive
    /// ladder has nothing to project; the account-domain transient lane
    /// (the supervisor's engine-event watcher) counts it in the metrics
    /// snapshot, resolves the account, and forwards the host frame. No
    /// automatic reset action ever rides it — decryption failures self-heal
    /// through the engine's own DERM retry protocol, not through session
    /// resets.
    ReceiveDecryptionError {
        account: String,
    },
    /// 契约 §4.226：对端安全码（身份钥）变更信封。转发宿主用于时间线
    /// 系统行渲染；不自动重置会话——信任决定权在用户（sendAnyway /
    /// 会话信息确认，同 §4.223 语义）。
    ReceiveIdentityChanged {
        account: String,
        source_uuid: String,
        timestamp: Option<u64>,
    },
    /// 批 Z12（契约 1.267 §4.251 · S15）：引擎 `engine.sessionReset` 通知
    /// ——官方两类 session-reset 事件的收流投影（endSession = 对端
    /// END_SESSION 信封；chatSessionRefresh = 我方解密失败时刻，官方自动
    /// reset + refreshed 行语义）。账号域瞬态车道转发；落行面在 service。
    SessionReset {
        account: String,
        peer_aci: String,
        word: String,
        sent_at: Option<u64>,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedReceive {
    /// 契约 §4.220：engine 产出的 requiredProtocolVersion（service/mod.rs:9594）。
    /// 高于本端支持版本时对端可能无法完整解析该消息。缺席 = 未声明。
    #[serde(
        rename = "requiredProtocolVersion",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_protocol_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub content_kind: &'static str,
    /// incoming | outgoing | system | control | skip
    pub direction: &'static str,
    pub account_present: bool,
    #[serde(skip)]
    pub account: Option<String>,
    /// Peer: inbound source or multi-device sent destination.
    #[serde(skip)]
    pub source: Option<String>,
    /// Envelope `sourceUuid` (contract 1.38): the sender's ACI identity as
    /// the engine projects it — present on every engine inbound envelope even
    /// when the legacy `source` field is absent. The service layer records the
    /// ACI→peer-key mapping from it on ingest (§4.37 peer_identities).
    #[serde(skip)]
    pub source_uuid: Option<String>,
    /// Human label from signal-cli envelope.sourceName when present.
    #[serde(skip)]
    pub peer_name: Option<String>,
    #[serde(skip)]
    pub group_id: Option<String>,
    #[serde(skip)]
    pub text: Option<String>,
    #[serde(skip)]
    pub text_bytes: Option<u32>,
    #[serde(skip)]
    pub text_truncated: bool,
    /// Quoted message snapshot (upstream timestamp, author, bounded preview).
    #[serde(skip)]
    pub quote: Option<NormalizedQuote>,
    /// Bounded inbound attachment descriptors (metadata only, no bytes).
    #[serde(skip)]
    pub attachments: Vec<NormalizedAttachment>,
    /// Bounded rich-body payload (contract 1.25): link previews, @mentions,
    /// text-style ranges and the view-once marker. Absent on plain rows.
    #[serde(skip)]
    pub rich: Option<NormalizedRich>,
    /// Sticker metadata (contract revision 1.35). Absent on non-sticker rows;
    /// the sticker's byte pointer rides `attachments`.
    #[serde(skip)]
    pub sticker: Option<NormalizedSticker>,
    /// Serialized per-conversation control payload (reaction / remote delete /
    /// typing) for `direction == "control"`; shape mirrors the protocol field.
    #[serde(skip)]
    pub control: Option<ControlReceive>,
    /// Disappearing-message timer as the envelope stated it (contract 1.42,
    /// §4.41): `Some(0)` = stated off, `None` = no stated value. Both engine
    /// faces share this parse; only the engine face states a start stamp.
    #[serde(skip)]
    pub expire_seconds: Option<u64>,
    /// Engine-reported countdown start (>0 stamps only). signal-cli faces
    /// never carry it — the deadline then falls back to receive time.
    #[serde(skip)]
    pub expire_start_at: Option<u64>,
    /// Envelope `serverGuid` (contract revision 1.49, §4.48): the
    /// server-assigned message GUID — the upstream report API's path
    /// parameter, captured at receive and persisted on the row so
    /// `messages.reportSpam` resolves it later. Connector-internal, never
    /// serialized; absent on envelopes without the key.
    #[serde(skip)]
    pub server_guid: Option<String>,
    /// Envelope `serverTimestamp` (contract revision 1.128, §4.109): the
    /// server-recorded receive time in epoch milliseconds — the 48h edit
    /// window's judgment input on the engine face and the message row's
    /// server-time key. The engine projects it on every receive envelope
    /// (proto 缺省 0 = the official `?? 0n` unknown sentinel, stored as
    /// NULL); connector-internal, never serialized.
    #[serde(skip)]
    pub server_timestamp: Option<u64>,
    /// Envelope `reportingToken` (the reportSpam data plane, official
    /// `conversation.reportingToken` parity): the base64 spam-report token
    /// the engine projects from the envelope's `reportSpamToken` proto bit
    /// when present. The service layer records it on the conversation at
    /// ingest (latest-wins, the official `updateReportingToken` shape) so
    /// `messages.reportSpam` can attach it to the upstream POST body —
    /// official `jsonData={token}`; connector-internal, never serialized,
    /// absent on envelopes without the key.
    #[serde(skip)]
    pub reporting_token: Option<String>,
}

/// Inbound quote snapshot: the quoted message's upstream identity plus a
/// bounded preview the host renders without a history lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedQuote {
    /// Quoted message's Signal timestamp.
    pub id: u64,
    /// Quoted author's number (or UUID when the number is absent).
    pub author: String,
    /// Bounded quoted-body preview.
    pub text: String,
    /// Quoted attachment metadata (contract 1.100, §4.81 D4): the official
    /// QuotedAttachment wire entries — the engine projects
    /// `quote.attachments[]` (contentType/filename/thumbnail) and this face
    /// forwards it bounded beside the preview. Empty on rows quoting a
    /// text-only message and on every pre-1.100 row (never backfilled).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<NormalizedQuoteAttachment>,
}

/// One quoted-attachment metadata entry (contract 1.100, §4.81 D4): the
/// official QuotedAttachment three-key wire shape — key absence is protocol
/// absence (the engine projects what the wire carried, nothing else). The
/// `filename` key keeps the engine's attachment-face spelling (the
/// signal-cli wire key), not the official desktop's camelCase `fileName`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedQuoteAttachment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// The bounded thumbnail pointer — the engine's AttachmentPointer
    /// projection through the same bounded parser the message attachments
    /// run, so a pointer the bounds cannot carry (an id-less pointer)
    /// drops rather than rendering half a face. Metadata-only: the locator
    /// half stays internal and never serializes, so a quote thumbnail
    /// rides the wire and the store as pure metadata (the honest 1.98
    /// posture — the desktop renders the pill metadata-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<NormalizedAttachment>,
}

/// One inbound attachment descriptor: metadata only, never bytes (§4.13).
/// Since contract revision 1.61 the receive face also captures the
/// envelope's transit locator when the engine projects one (the §4.38
/// attachv2 pointer face, the same ingest caps as the 1.56 import parser);
/// the pinned 0.14.8 signal-cli and the kt-engine receive face project
/// metadata only today, so the field stays `None` until an engine ships the
/// receive-side projection — the download face then becomes live without a
/// further connector change. Since contract revision 1.107 (§4.88) the
/// descriptor also carries the engine's P14 metadata keys verbatim: the
/// render `caption`, the blur preview `blurHash`, the streaming-integrity
/// pair `incrementalMac` + `chunkSize` (both or neither — the official
/// filePointers discipline), and the always-boolean `isBorderless` / `isGif`
/// flag projections beside `isVoiceNote`. Since contract revision 1.150
/// (§4.149) it also carries the engine's voice-waveform pair verbatim: the
/// render `waveform` (standard base64, the engine's fixed 100-byte 0..255 dB
/// buckets, non-empty only) and the float-second `duration` — never decoded,
/// re-encoded, or pair-gated (the engine generates both or neither; a failed
/// generation ships neither and the connector forwards whatever is stated).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedAttachment {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    pub is_voice_note: bool,
    /// Sender-stated media caption (contract 1.107, §4.88): mirror material
    /// the desktop renders beside the bubble — the connector never merges it
    /// into the row body (the two texts are distinct upstream facts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// Blur preview string (contract 1.107, §4.88): passed through verbatim
    /// for the desktop's progressive media placeholder; never decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blur_hash: Option<String>,
    /// Streaming-integrity pair (contract 1.107, §4.88): the attachment's
    /// incremental MAC (standard base64) and chunk size, both present or
    /// both absent (the official filePointers.preload.ts:84-87 discipline —
    /// half a pair verifies nothing and is dropped, never forwarded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incremental_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
    /// The engine's borderless/GIF flag projections (contract 1.107, §4.88):
    /// always boolean on the live face (no flag bit = false, the isVoiceNote
    /// shape), so the three booleans share one consumption form and the
    /// media-type judgement (the official isGIF's contentType gate) stays
    /// the desktop's.
    #[serde(default)]
    pub is_borderless: bool,
    #[serde(default)]
    pub is_gif: bool,
    /// The engine's voice waveform (contract 1.150, §4.149): the outbound
    /// voice note's render buckets, standard base64 — forwarded verbatim for
    /// the desktop's playback bar, never decoded, charset-checked, or
    /// re-encoded (the §4.149 posture: the connector does not interpret the
    /// pair; the pairing itself is the engine's generation invariant).
    /// Absent on every face the engine ships without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waveform: Option<String>,
    /// The engine's voice duration (contract 1.150, §4.149): float seconds,
    /// forwarded verbatim beside `waveform` — positive-only is the ingest
    /// shape gate (the §4.88 zero-information posture), not interpretation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
    /// Ingest-side transit pointer face, internal only — it rides the store's
    /// schema-19 live locator column and never the host wire (the §4.13
    /// metadata-only discipline covers it too). `None` on every engine face
    /// that does not project a receive locator.
    #[serde(skip)]
    pub locator: Option<crate::store::HistoryAttachmentLocator>,
}

/// One inbound link-preview card (contract 1.25): bounded metadata only — the
/// image rides the same metadata-only attachment descriptor; bytes are never
/// fetched by the connector.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedPreview {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The engine's P14 preview date (contract 1.107, §4.88): the card's
    /// upstream publish stamp, forwarded verbatim when positive (the engine
    /// projects no key for a 0 — zero information, the official falsy
    /// posture).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<NormalizedAttachment>,
}

/// One inbound @mention range (contract 1.25; authorAci added in 1.40): the
/// author resolves to the mentioned peer; the styled range
/// [start, start+length) is already part of the received body text.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedMention {
    /// Mentioned peer's number, or UUID when the number is absent.
    pub author: String,
    /// The mentioned peer's ACI when the connector can honestly name it
    /// (contract 1.40, §4.40): the envelope `uuid` field, or the
    /// number-keyed value when it is UUID-shaped (the engine-mode receive
    /// face puts the ACI there). Absent keeps `author` the only identity,
    /// byte-identical to pre-1.40 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_aci: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start: u32,
    pub length: u32,
}

/// One inbound text-style range (contract 1.25). Only the styles the protocol
/// renders pass validation; `NONE` and unknown values drop individually.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedTextStyle {
    pub style: String,
    pub start: u32,
    pub length: u32,
}

/// Bounded rich-body payload (contract 1.25): link previews, @mentions and
/// text-style ranges off one dataMessage, plus the view-once marker. An
/// all-default shape collapses to `None` so plain messages carry nothing.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedRich {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previews: Vec<NormalizedPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<NormalizedMention>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub text_styles: Vec<NormalizedTextStyle>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub view_once: bool,
    /// Metadata-only view-once marker (contract 1.25 shape): the sender
    /// flagged the message view-once but the payload carried no renderable
    /// media. The row still burns on the §4.37 flow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub view_once_invalid: bool,
    /// Connector-set burn stamp (contract 1.38): wall-clock ms the row's
    /// bytes were erased. Never set by receive parsing — written by the
    /// service layer's markViewOnceOpened / viewOnceOpen consumption and read
    /// back off the row to gate media opens and replays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_once_opened_at: Option<u64>,
    /// Disappearing-message timer-change marker (contract 1.42, §4.41): the
    /// message announced a timer change for its conversation (`true` only
    /// when the envelope flagged `isExpirationUpdate`). Timer-notice rows
    /// carry it as their only rich content; a body message that happened to
    /// carry the flag keeps it beside the rest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_expiration_update: bool,
    /// Group-state-change marker (contract 1.45, §4.44): the dataMessage's
    /// `groupInfo.type` was `UPDATE`. Bodyless updates project as system rows
    /// (the pre-1.45 skip path swallowed them); a body-carrying update keeps
    /// its normal row and the marker rides beside the rest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_group_update: bool,
    /// The engine's post-change group title off the update's `groupInfo`
    /// (contract 1.45, §4.44): the receive face's `JsonGroupInfo` exposes only
    /// the resulting name — no actor, no before/after — so the desktop gets it
    /// as mirror material, not as a diff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    /// The structured group-state-change material (contract §4.227): the
    /// official `GroupV2ChangeType` detail vocabulary the desktop's
    /// GroupV2Change renderer consumes — the bounded verbatim `changes[]`
    /// (the GroupV2ChangeDetailType word list the engine already projects on
    /// the transient `groupChanged` event, §4.81), the resulting `revision`
    /// and the `editor` ACI when the producer named one. The disappearing-
    /// timer leg stays off this shape (the official keeps no timer detail
    /// type — that change rides its own §4.41 face). Today's live
    /// `groupInfo` projection carries none of the keys (`{groupId}` only,
    /// §4.44 mirror posture) — the face parses when a producer lands them;
    /// presence without material stays `None`, never an empty shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_change: Option<NormalizedGroupChange>,
    /// Safety-number (identity-key) change marker (contract §4.226): the
    /// peer's identity key changed and the connector landed the persisted
    /// timeline system row. Set only by the service layer's
    /// forward_identity_changed persist face — never by receive parsing
    /// (the engine's identityChanged notification carries no message row).
    /// The trust decision stays with the user (the §4.223 posture).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_identity_change: bool,
    /// 批 Z12（契约 1.267 §4.251 · S15）：会话重置系统行标记——官方
    /// ResetSessionNotification（Message.dom isResetSession 位）的行级键。
    /// 仅由 engine.sessionReset 通知的落行面铸造（endSession 词臂）；两键
    /// 互斥（一行一词臂）。仅真值出现；键缺席 = 非该族行，pre-1.267 宿主
    /// 读行零变化。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_reset_session: bool,
    /// 批 Z12（契约 1.267 §4.251 · S15）：会话已刷新系统行标记——官方
    /// ChatSessionRefreshedNotification（桌面 wire isChatSessionRefreshed，
    /// 契约 1.181 已在）的行级键。仅由 engine.sessionReset 通知的落行面
    /// 铸造（chatSessionRefresh 词臂）。仅真值出现。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_chat_session_refreshed: bool,
    /// 消息请求响应时间线系统行（契约 1.253 §4.239）：官方
    /// `MessageRequestResponseEvent` 词表成员（types/
    /// MessageRequestResponseEvent.std.ts:6-11 verbatim：ACCEPT / BLOCK /
    /// UNBLOCK / SPAM），钉在官方 `message-request-response-event` 行的
    /// `messageRequestResponseEvent` 属性位（models/conversations.preload.ts
    /// :2544 verbatim 键名；serde camelCase 投影同形）。只由服务层落行面铸造
    /// （§4.239 的 LOCAL 动作臂 + §4.58 镜像消费臂，双源同词表）——接收解析
    /// 永不产它（引擎不投影该面）。词表校验收在铸造点闭集上，wire 面不收
    /// 外来串。仅真值出现；键缺席 = 非该族行，pre-1.253 宿主读行零变化。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_request_response_event: Option<String>,
    /// 批 A · A2（connector §4.232；桌面契约 1.250）：「联系人加入 Signal」
    /// 系统行标记——官方 message.type `joined-signal-notification` 的行级
    /// 投影（官方 import 行源 import.preload.ts:3851-3854 的 simpleUpdate
    /// JOINED_SIGNAL 臂；engine §5 快照面 simpleUpdate{type}）。仅真值出现
    /// （serde 跳过假值）；键缺席 = 非该族行。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_joined_signal: bool,
    /// 批 A · A3（connector §4.233；桌面契约 1.250）：对方更改手机号码系统行
    /// 标记——官方 message.type `change-number-notification`（import 行源
    /// import.preload.ts:3837-3840 CHANGE_NUMBER 臂）。仅有 archive 面——
    /// live 面（官方 updateE164 本地通知链）本连接器无 e164 差分源，记档
    /// 另案。仅真值出现。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_change_number: bool,
    /// 批 A · A4（connector §4.234；桌面契约 1.250）：标题过渡系统行材料——
    /// 官方 message.type `title-transition-notification` 的
    /// `titleTransition.renderInfo` 经 getTitle 解析后的 oldTitle（官方
    /// import 行源 import.preload.ts:2957-2981 learnedProfileChange.previousName
    /// 的 e164/username 二选一）。解析在 connector 侧完成（我们手里的旧标题
    /// 即官方 getTitle 的输出）；缺材料整面缺席。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_transition: Option<NormalizedTitleTransition>,
    /// 批 A · A5（connector §4.235；桌面契约 1.251）：会话合并系统行材料——
    /// 官方 message.type `conversation-merge`（官方 import 行源
    /// import.preload.ts:2983-2997 threadMerge.previousE164 → renderInfo
    /// {type:'private', e164}）。官方 selector 的 conversationTitle 取自
    /// 渲染时会话自身，不在此面（桌面读会话行）；缺材料整面缺席。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_merge: Option<NormalizedConversationMerge>,
    /// Story-reply context (contract 1.76, §4.67): the dataMessage's
    /// `storyReply` face — {authorAci, sentTimestamp} verbatim, the story the
    /// reply answers. The reply itself is a normal DM/group row; absent on
    /// plain and pre-1.76 rows. A malformed face (missing/empty author,
    /// missing timestamp) drops the key, never the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub story_reply: Option<NormalizedStoryReply>,
    /// Backfill contact card (contract 1.78, §4.38): the archive's
    /// per-message `contact` face, bounded. The avatar byte pointer rides the
    /// descriptor list, never this shape. Absent on plain and pre-1.78 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<NormalizedContact>,
    /// Poll face (contract 1.81, §4.38 import chain; live chain contract
    /// 1.135 §4.118): the aggregated read-only render face — question,
    /// options, the aggregate flag, the per-voter projection and the ended
    /// bit. Two arrival chains land the exact same shape: the archive's
    /// per-message `poll` item folds through the §4.38 import, and the
    /// engine's live `dataMessage.poll` projection parses through
    /// [`normalized_live_poll`] (votes/termination arrive as their own
    /// envelopes and fold onto the landed row — §4.118). Absent on plain
    /// and pre-1.81 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll: Option<NormalizedPoll>,
    /// Poll-terminate notice face (contract 1.189, §4.189): the material of
    /// the standalone system row a live termination lands beside the poll
    /// row it folded — the official `poll-terminate` message's
    /// `pollTerminateNotification {question, pollTimestamp}` projection, with
    /// the terminator's self flag so the desktop picks the official
    /// you/other copy without guessing identities. Rides only the notice
    /// row the fold mints; absent everywhere else (the poll row keeps the
    /// `poll` face, the vote fold mints no row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_terminate: Option<NormalizedPollTerminate>,
    /// Backfill payment face (contract 1.81, §4.38): the desktop's
    /// consumable slice of the archive's per-message `payment` item — the
    /// note alone; amounts, fees and the transaction blob have no desktop
    /// render face. Absent on plain and pre-1.81 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<NormalizedPayment>,
    /// Backfill gift-badge face (contract 1.81, §4.38): the archive's
    /// per-message `giftBadge` item, lowercased onto the desktop's state
    /// vocabulary — the state alone, no credential material. Absent on plain
    /// and pre-1.81 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gift_badge: Option<NormalizedGiftBadge>,
    /// The engine's P14 dataMessage protocol-stamp (contract 1.107, §4.88):
    /// `dataMessage.expireTimerVersion` forwarded when positive — the
    /// disappearing-message protocol version the sender stated (the engine
    /// projects no key for 0). The timer value itself stays the row's
    /// `expireSeconds` face; this is the versioning fact beside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_timer_version: Option<u32>,
    /// Sent-transcript faces (contract 1.107, §4.88), the engine's P14 Sent
    /// batch verbatim off `syncMessage.sentMessage`: the recipient-update
    /// bit, the per-destination sealed-sender statuses and the story
    /// distribution state. Receive dataMessages never carry the keys, so
    /// inbound rows keep the defaults; only the sent mirror persists them.
    /// Transcript facts, never acted on connector-side — the desktop's
    /// transcript consumes them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_recipient_update: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unidentified_status: Vec<NormalizedUnidentifiedStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub story_message_recipients: Vec<NormalizedStoryRecipient>,
}

/// 批 A · A4（connector §4.234）：标题过渡材料。官方
/// `TitleTransitionNotification` 的 PropsData 只有 `oldTitle` 一键
/// （TitleTransitionNotification.dom.tsx:12-14）——renderInfo 的
/// type/e164/username 三键是解析输入，解析产物才是行材料，所以这里只携产物。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedTitleTransition {
    /// 旧标题逐字（官方 getTitle(renderInfo)：号码场 +E164 形、用户名场原值）。
    pub old_title: String,
}

/// 批 A · A5（connector §4.235）：会话合并材料——官方 selector
/// getPropsForConversationMerge 三 prop 中由被并壳行决定的两项
/// （message.preload.ts:2021-2045）。conversationTitle 不在此面（桌面读
/// 会话行，官方同一来源）。
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedConversationMerge {
    /// 壳行标题（官方 getTitleNoDefault(renderInfo)）；缺席 = 官方无标题臂。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obsolete_conversation_title: Option<String>,
    /// 壳行号码（官方 getNumber(renderInfo)）；缺席 = 官方无号码臂。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obsolete_conversation_number: Option<String>,
}

/// One story-reply context (contract 1.76, §4.67): the addressed story's
/// author ACI and its upstream timestamp, exactly the two keys the engine
/// projects off `dataMessage.storyContext`. The reply row is a normal
/// message; this face only names the story it answers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedStoryReply {
    pub author_aci: String,
    pub sent_timestamp: u64,
}

/// One structured group-state change (contract §4.227): the official
/// `GroupV2ChangeType` material — the bounded verbatim `changes[]` detail
/// list (the official `GroupV2ChangeDetailType` word list: title, avatar,
/// description, the access-*/group-link-* privilege family and the
/// member-*/pending-*/admin-approval-* membership family, exactly what the
/// engine's transient `groupChanged` event already carries, §4.81), the
/// resulting `revision` and the `editor` ACI when the producer named them.
/// The timer leg stays off (official: no timer detail type — §4.41's own
/// face); `from` rides as `editor`, the §4.81 wire name the connector
/// pinned for the same vocabulary.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedGroupChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<serde_json::Value>,
}

/// One sent-transcript sealed-sender entry (contract 1.107, §4.88): the
/// engine's `Sent.unidentifiedStatus[]` item forwarded verbatim — the
/// destination's service-id string (PNI-prefixed for a PNI destination, the
/// plain UUID for an ACI), the sealed-sender bit when the proto carried one,
/// and the destination PNI identity key (standard base64) when non-empty.
/// All three keys are optional: an entry the engine could not resolve rides
/// with only what it carried, and the connector drops nothing per-key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedUnidentifiedStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unidentified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_pni_identity_key: Option<String>,
}

/// One sent-transcript story-distribution entry (contract 1.107, §4.88): the
/// engine's `Sent.storyMessageRecipients[]` item verbatim — the destination
/// service-id string, the distribution (playlist) ids verbatim (an empty
/// list is the official's list-narrowed semantics and stays an empty list),
/// and the reply-permission bit only when the proto stated one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedStoryRecipient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_uuid: Option<String>,
    pub distribution_list_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_allowed_to_reply: Option<bool>,
}

impl NormalizedRich {
    fn is_empty(&self) -> bool {
        self.previews.is_empty()
            && self.mentions.is_empty()
            && self.text_styles.is_empty()
            && !self.view_once
            && !self.view_once_invalid
            && self.view_once_opened_at.is_none()
            && !self.is_expiration_update
            && !self.is_group_update
            && self.group_name.is_none()
            && self.group_change.is_none()
            && self.story_reply.is_none()
            && self.contact.is_none()
            && self.poll.is_none()
            && self.payment.is_none()
            && self.gift_badge.is_none()
            && self.expire_timer_version.is_none()
            && !self.is_recipient_update
            && !self.is_joined_signal
            && !self.is_change_number
            && self.title_transition.is_none()
            && self.conversation_merge.is_none()
            && self.unidentified_status.is_empty()
            && self.story_message_recipients.is_empty()
            && self.message_request_response_event.is_none()
    }
}

/// Inbound sticker metadata (contract revision 1.35): the official
/// `DataMessage.sticker` identity — pack id as hex, pack key as standard
/// base64 (the serialization conventions the engine projects), the pack-local
/// sticker id and the optional emoji label. The sticker's byte pointer is not
/// part of this shape: `data` rides the row's metadata-only attachment
/// descriptor list, so fetches go through the existing media channel and the
/// connector never downloads sticker bytes (§6.7).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedSticker {
    /// Sticker pack id, hex as the official client serializes it.
    pub pack_id: String,
    /// Sticker pack key, standard base64 as `Bytes.fromBase64` produces.
    pub pack_key: String,
    /// Pack-local sticker id.
    pub sticker_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
}

/// Backfill contact card (contract revision 1.78, §4.38): the bounded summary
/// of the engine archive's per-message `contact` face — the name parts, phone
/// numbers, emails and organization the official import maps onto its
/// ContactForm shape (`import.preload.ts:2620-2705`). The avatar byte pointer
/// is not part of this shape: it rides the row's metadata-only descriptor
/// list exactly like a sticker's `data`, so fetches go through the existing
/// media channel. Rides [`NormalizedRich`] (the §4.37/§4.40 additive
/// channel), so no store schema bump; absent on plain and pre-1.78 rows.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedContact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<NormalizedContactName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub number: Vec<NormalizedContactField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub email: Vec<NormalizedContactField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

/// One contact card's name parts (contract 1.78, §4.38): only the parts the
/// archive actually states ride the wire — an absent part stays absent (the
/// official `name.given || undefined` semantics).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedContactName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
}

/// One phone/email entry of a contact card (contract 1.78, §4.38): the value
/// plus the official ContactFormType vocabulary (HOME/MOBILE/WORK/CUSTOM —
/// unknown/absent coerce to HOME, the official `phoneToContactFormType`
/// parse face) and the optional free-form label.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NormalizedContactField {
    pub value: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Poll face (contract 1.81, §4.38 import chain; live chain §4.118): the
/// archive's per-message `poll` item folded onto the desktop's read-only
/// render face (engine 592b1d3 projects the official import's poll face
/// verbatim — options carry their votes nested as `{voterId, voteCount}` —
/// and the connector aggregates; behavior reference, zero code copied). The
/// fold is exactly the official import's: one entry per voter in first-seen
/// order with the option indexes they picked, a voter the §4.38 recipient
/// ladder cannot resolve dropping vote-level (the official unknown-voterId
/// warn-and-skip, never the row). The engine drops empty option entries, so
/// the projected option list is self-consistent for index addressing.
/// `terminated` is the desktop's boolean face of `hasEnded` — the official
/// `terminatedAt` stamp is the poll message's own timestamp (the row's
/// `sentAt`), so it is not repeated. The live chain lands the identical
/// shape off the engine's `dataMessage.poll` projection (the live parse in
/// this module), votes and termination folding onto the landed row as they
/// arrive (§4.118).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedPoll {
    /// Poll question; the face always carries the key (the official
    /// `poll.question ?? ''`), an unstated question rides empty.
    pub question: String,
    /// Option labels in archive order — positional integrity matters: votes
    /// address options by index, so the list always rides (the official
    /// `options` face is unconditionally serialized).
    pub options: Vec<String>,
    /// The official `allowMultiple`; serialized only when true (the
    /// desktop's optional-truthy face).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_multiple: bool,
    /// The official `hasEnded` as the desktop's boolean face; serialized
    /// only when true — the termination stamp is the row's own timestamp.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminated: bool,
    /// Aggregated per-voter projection; absent while no vote resolved (the
    /// official `votes.length > 0 ? votes : undefined`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub votes: Vec<NormalizedPollVote>,
}

/// One aggregated poll vote (contract 1.81, §4.38): the voter resolved
/// through the §4.38 author-resolution ladder and the option indexes they
/// picked in poll order. The official `voteCount` per-vote tally has no
/// desktop timeline face and is not transported (the projection gap the
/// desktop batch records).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedPollVote {
    pub voter_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub option_indexes: Vec<u32>,
}

/// Poll-terminate notice face (contract 1.189, §4.189): the material the
/// standalone notice row carries — the official timeline keeps the terminate
/// as its own `poll-terminate` system row beside the poll bubble
/// (`PollTerminateNotification.dom.tsx`, behavior reference, zero code
/// copied), so the connector's live fold mints the same row with the poll's
/// question, the poll row's own upstream timestamp (the desktop's scroll/
/// pairing anchor), and the terminator's self flag (the official
/// `isMeTerminating` read/unread split's KT projection: the desktop's
/// you/other copy branch). Rides [`NormalizedRich`] on the notice row only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedPollTerminate {
    /// The ended poll's question, verbatim from the folded poll face (the
    /// official notification row's `pollTerminateNotification.question`).
    pub poll_question: String,
    /// The ended poll row's own upstream timestamp (the official
    /// `pollTimestamp` — the row the fold addressed, i.e. the desktop's
    /// pairing key back to the poll bubble).
    pub poll_sent_at: u64,
    /// The terminator is the linked account itself (the official
    /// `isMeTerminating` — the account's own sent echo); serialized only
    /// when true. False/absent = a peer's terminate (the poll author — the
    /// official invariant the fold's author-keyed addressing enforces).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub self_terminated: bool,
}

/// Backfill payment face (contract revision 1.81, §4.38): the desktop's
/// consumable slice of the archive's `payment` item. The engine projects the
/// official import face — `{amountMob?, feeMob?, note?,
/// transactionDetailsBase64?}` — but only `note` crosses: the official
/// timeline renders a placeholder label plus the optional note, and amounts,
/// fees and the opaque TransactionDetails blob have no desktop render face
/// (KT carries no MobileCoin ledger), so the connector does not transport
/// them (the projection gap the desktop batch records). Rides
/// [`NormalizedRich`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedPayment {
    /// Free-form payment note; absent stays absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Backfill gift-badge face (contract revision 1.81, §4.38): the desktop's
/// state-only face of the archive's `giftBadge` item. The engine projects
/// the official capitalized `GiftBadgeStates` vocabulary (Unopened / Opened
/// / Redeemed / Failed); the connector lowercases onto the desktop's wire
/// vocabulary. The receipt-credential presentation (the engine's face on
/// every non-FAILED state) stays engine-side: it is zk credential material
/// with no desktop data face (the projection gap the desktop batch
/// records). Rides [`NormalizedRich`].
/// Contract 1.181 (§4.181) adds the countdown pair additively: the live
/// receive face's zkgroup-parsed `expiration` (wall-clock ms — the official
/// remaining days/hours/minutes material) and donation `level`. Absent-key
/// when the upstream face carries neither — archive rows keep both absent
/// (the engine's archive arm records it has no zk parse face).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedGiftBadge {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u64>,
}

/// Delivery tier of an inbound receipt (`envelope.receiptMessage`). Order is
/// the protocol's monotonic upgrade path: a later tier never downgrades an
/// earlier one (`read` over `delivered` over `sent`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptKind {
    Delivered,
    Read,
    Viewed,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptKind::Delivered => "delivered",
            ReceiptKind::Read => "read",
            ReceiptKind::Viewed => "read",
        }
    }
}

/// Control-plane receive payloads that are not messages: reaction add/remove,
/// remote delete of an earlier message, typing START/STOP, edit of an
/// earlier message (new body rides `NormalizedReceive.text`), and the poll
/// vote/terminate folds (§4.118 — they mutate the poll row they address;
/// a vote never mints a row, a termination's first flip mints the
/// standalone notice row beside the poll, §4.189).
#[derive(Clone, Debug)]
pub enum ControlReceive {
    Reaction {
        emoji: String,
        target_author: String,
        target_timestamp: u64,
        remove: bool,
    },
    RemoteDelete {
        target_timestamp: u64,
    },
    Typing {
        action: String,
    },
    Edit {
        target_timestamp: u64,
    },
    /// Peer receipt confirming earlier outgoing rows (bounded batch). `when`
    /// is the receipt envelope's own timestamp (contract 1.32) — when the
    /// peer sent the receipt — falling back to connector wall-clock at the
    /// service layer when the envelope carries none. `recipient` is the
    /// per-recipient identity (contract 1.190, §4.190): the ReceiptMessage
    /// proto names no recipient (SignalService.proto:451-460 — type + a
    /// repeated timestamp and nothing else), and the official receiver
    /// attributes the receipt by the envelope source
    /// (MessageReceiver.preload.ts:2849-2855). The routing copies the same
    /// `source`/`sourceNumber`/`sourceUuid` ladder `envelope_peer_source`
    /// answers, verbatim — the value rides inside the variant so every
    /// consumer that matches `ControlReceive::Receipt` (the §4.91-style
    /// early-receipt buffer included) holds the identity without reaching
    /// back for the receive context.
    Receipt {
        kind: ReceiptKind,
        timestamps: Vec<u64>,
        when: Option<u64>,
        recipient: Option<String>,
    },
    /// Pin of an earlier message (contract 1.33): the target identity plus
    /// the optional timed-pin duration — absent means the official forever
    /// pin.
    PinMessage {
        target_author: String,
        target_timestamp: u64,
        duration_seconds: Option<u32>,
    },
    /// Unpin of the earlier message it names (contract 1.33).
    UnpinMessage {
        target_author: String,
        target_timestamp: u64,
    },
    /// Group admin removed the earlier message it names (contract 1.33).
    AdminDelete {
        target_author: String,
        target_timestamp: u64,
    },
    /// A poll vote (live poll chain, §4.118): the engine's
    /// `dataMessage.pollVote {targetAuthor, targetSentTimestamp,
    /// optionIndexes, voteCount}` projection folds onto the poll row it
    /// addresses. `target_author` names the poll's author (E.164 when the
    /// engine resolved it, the ACI string otherwise), `target_timestamp`
    /// the poll row's upstream timestamp; `option_indexes` is the voter's
    /// full selection after this vote (empty = the official clear-vote
    /// action). The engine's `voteCount` per-vote tally has no desktop
    /// timeline face and is not transported — the same gap the §4.38
    /// import chain records. The voter is never carried here: the service
    /// layer attributes the envelope source (incoming) or the account
    /// itself (the multi-device sent echo).
    PollVote {
        target_author: String,
        target_timestamp: u64,
        option_indexes: Vec<u32>,
    },
    /// A poll termination (live poll chain, §4.118): the engine's
    /// `dataMessage.pollTerminate {targetSentTimestamp}` projection flips
    /// the addressed poll row's `terminated` bit — and, on the first flip,
    /// lands the standalone notice row beside the poll (§4.189, the
    /// official `poll-terminate` timeline row). The proto carries no
    /// author — the official terminate send is the poll author's own
    /// dataMessage, so the service layer addresses the row through the
    /// envelope's own sender identity (or the account on the sent echo).
    PollTerminate {
        target_timestamp: u64,
    },
    /// A peer's client notified us their view-once message was viewed on one
    /// of our own linked devices (contract 1.38): the official
    /// `syncMessage.viewOnceOpen {senderAci, timestamp}` mirror. `timestamp`
    /// normalizes to 0 when the envelope omits it (the official unknown
    /// marker); the service layer drops that shape warn-only.
    ViewOnceOpen {
        sender_aci: String,
        timestamp: u64,
    },
    /// The engine's `groupUpdated {groupId, revision, expireTimerSeconds,
    /// editor?}` projection (2026-10-06 engine batch, kt-signal-engine main
    /// @ 216a4c7): a decrypted group change carrying the expiration-timer
    /// action, envelope-replaced before it ever reaches the connector. The
    /// service layer mirrors `expireTimerSeconds` into the conversation row
    /// (0 = off), lands the official timer-notice system row (contract 1.92
    /// §4.75 — the row the official client shows, the §4.41 direct-face
    /// identity), and converges through `conversation.changed`. `editor` is
    /// the change author's ACI as the engine decrypted it — the attribution
    /// material the desktop joins its group roster against; absent (the
    /// projection could not name one) keeps the row unattributed, never
    /// invented.
    GroupTimerUpdate {
        expire_timer_seconds: u32,
        editor: Option<String>,
    },
    /// Call signaling (contract 1.51, §4.49): the engine's `callMessage`
    /// envelope projection — the official Content.callMessage=3 face. The
    /// connector is a signaling pipe: `call_id` is the 1:1 call identity the
    /// RingRTC frames share, `signal_type` mirrors the projected frame
    /// family (`offer` / `answer` / `ice` / `busy` / `hangup`, `opaque`
    /// when only the modern opaque payload rides), and `payload` is the
    /// bounded signaling material passed through byte-for-byte — never
    /// parsed or interpreted connector-side (the engine projects, the
    /// RingRTC state machine consumes).
    Call {
        call_id: u64,
        signal_type: &'static str,
        payload: Value,
    },
    /// 群通话 era 更新控制接收（契约 1.264，§4.248）：引擎 live 投影
    /// `dataMessage.groupCallUpdate {eraId}`。官方 handleGroupCallUpdateMessage
    /// 姿态（background.preload.ts:3534-3563）：非渲染行、零持久化，消费面 =
    /// peek 触发（`peekNotConnectedGroupCall`）。仅群上下文进本臂（官方闸
    /// `message.groupV2 && type===GROUP`）：eraId 非空且 ≤256 字符、group 键
    /// （32B 主键标准 base64）必在——era 缺席/超帽/无群键 = 整面掉落（官方
    /// warn-and-ignore 臂），信封原样走既有 fall-through，1:1 腿零变化。
    GroupCallUpdate {
        era_id: String,
    },
    /// The official `syncMessage.messageRequestResponse` mirror (contract
    /// 1.70, §4.58 consume batch): one of our own linked devices answered the
    /// conversation's message request. `response_type` is the protocol enum
    /// member 0..=6 (UNKNOWN/ACCEPT/DELETE/BLOCK/BLOCK_AND_DELETE/SPAM/
    /// BLOCK_AND_SPAM — the desktop's `isKnownProtoEnumMember` gate forces an
    /// out-of-enum value back to UNKNOWN before this connector ever sees it,
    /// and the shapes that survive the engine-side gates carry only 1..=6),
    /// `thread_aci` names the 1:1 thread (the ServiceId UUID string), and
    /// `group_id` the 32-byte group master key's standard base64 — exactly
    /// one of the two is present (the proto oneof). No message row exists for
    /// the notification; the service layer stamps the authoritative factor
    /// and the summary rides `conversation.changed`.
    ///
    /// Contract 1.258 (§4.58 additive, batch X · S7②): `timestamp` rides the
    /// engine's additive sync-moment projection (the sync envelope's own
    /// timestamp — the official MRR_SYNC row's `sent_at = sentAt` source,
    /// background.preload.ts:3803 → conversations.preload.ts:2513-2518). The
    /// proto member itself carries no time, so pre-1.258 engines answer no
    /// key and the mirror-row clock degrades to the local one exactly as
    /// before (the recorded §4.239 degradation); a malformed value reads as
    /// absent (an additive key never fails the face).
    MessageRequestResponse {
        response_type: u8,
        thread_aci: Option<String>,
        group_id: Option<String>,
        timestamp: Option<u64>,
    },
    /// Story receives (contract 1.76, §4.67): the engine's envelope-level
    /// `storyMessage` projection — the official Content.storyMessage=8 face.
    /// The connector is a story pipe like the call-signaling pipe: `message`
    /// is the bounded projection verbatim ({textAttachment{…}|
    /// fileAttachment, allowsReplies, profileKey?, group?}) — never parsed
    /// or re-shaped connector-side (the desktop owns the story timeline; the
    /// connector keeps no story row). The stories-disabled gate (the
    /// official getStoriesBlocked leg) is the service layer's.
    Story {
        message: Value,
    },
    /// Story-anchored reaction receive (contract 1.154 §4.153, group legs
    /// contract 1.158, §4.156): the engine's story-reaction discrimination
    /// face — a `dataMessage.reaction` whose envelope carries the
    /// `storyReply` (storyContext) projection is a reaction on a story,
    /// not on a message (the story batch S4's receive-side judgment,
    /// engine docs §3: the anchor is the storyReply, because the story has
    /// no conversation row for the reaction target to fold onto). The
    /// official receive routes by the target row's domain, and on the wire
    /// the group story reaction rides the ordinary group channel with the
    /// storyContext always present (reaction + storyReply + groupV2), so
    /// the co-presence is the judgment on the group leg exactly as on the
    /// 1:1 leg — the 1.154 group fold is overturned (§4.156). The group
    /// leg carries `group_id` (the group master key standard base64, the
    /// groupInfo caliber); the 1:1 leg carries none. A degraded storyReply
    /// (the engine projects the key only when the author resolves) stays a
    /// plain reaction — one authority, the shared helper. The reaction
    /// payload stays the parsed reaction (emoji, remove); the anchor is
    /// the storyReply face verbatim. The stories-disabled gate applies
    /// (contract 1.158 alignment with the official MessageReceiver:
    /// stories-blocked drops the whole isStoryReply envelope, reactions
    /// included — the 1.154 no-gate reading is overturned).
    StoryReaction {
        emoji: String,
        remove: bool,
        story_author: String,
        story_sent_at: u64,
        group_id: Option<String>,
    },
    /// Peer story deletion (contract 1.154 §4.153, group leg contract
    /// 1.158, §4.156): the story-channel DOE face —
    /// `dataMessage.remoteDelete` riding the envelope `isStory` bit (the
    /// story batch S5's receive leg ①, the E2 gate's
    /// is_delete_for_everyone exemption). The bit routes here on both
    /// legs: the 1:1 story channel, and — conservatively — the group
    /// envelope that carries the bit (officially legal, some clients may
    /// send it; §4.156). An unsigned group DOE keeps the plain
    /// remote-delete fold: the official group story deletion rides a
    /// regular group DOE with no bit and no storyContext, so the wire
    /// cannot tell it from an ordinary group delete and the §4.156
    /// `story.deleteCandidate` event owns that face. A plain message DOE
    /// never carries the bit. The stories-disabled gate does not apply
    /// (contract 1.158 alignment with the official MessageReceiver: the
    /// stories-blocked drop removes isStoryReply envelopes only and
    /// leaves the DOE faces ungated — the 1.154 gate is overturned).
    StoryDeleted {
        target_timestamp: u64,
        group_id: Option<String>,
    },
    /// The engine's `syncMessage.storyRecipientUpdate` projection (contract
    /// 1.154, §4.153): the account's own devices learned one of its stories'
    /// recipients changed — the story batch S5's receive leg ②, the
    /// `deleteStoryForEveryone` self-sync fan-out plus the multi-list story
    /// send's `isUpdate=true` sync shape (the official
    /// StoryRecipientUpdateEvent mirror). Own-story sync family like the
    /// §4.70 viewed receipts: the stories-disabled gate does not apply. The
    /// timestamp is the story's own Signal timestamp (the official envelope
    /// ts); the recipients ride verbatim.
    SyncStoryRecipientUpdate {
        timestamp: u64,
        recipients: Vec<NormalizedStoryRecipient>,
    },
    /// The engine's `syncMessage.sentMessage.storyMessage` projection
    /// (contract 1.160, §4.158): the account's own story posted from another
    /// linked device — the multi-device transcript the official
    /// `#handleStoryMessage` sent face lands as own story rows
    /// (MessageReceiver.preload.ts:3028-3036 → :2141; the group leg one
    /// SentEvent at :2246-2260, the per-list fan-out at :2262-2340). The
    /// bounded story face rides verbatim (the §4.67 3MiB bound — the
    /// same face the envelope-level `story.received` forwards, media
    /// locator full-face included); the service layer turns it into the
    /// outgoing row shape the desktop's message-upserted story intercept
    /// consumes and keeps no row. The engine's sync projection has already
    /// split the official storyRecipientUpdate gate into its own
    /// envelope-level key, so what reaches this variant is the plain story
    /// body — the first-send transcript's `storyMessageRecipients` rich
    /// material rides the sent object beside it and stays the recipient
    /// update event's job (contract 1.154), never the row's.
    SyncStoryMessage {
        message: Value,
    },
    /// The engine's `syncMessage.read[]` / `.viewed[]` projection (contract
    /// 1.100, §4.81): the account's own linked device marked upstream
    /// messages read (or viewed) — the official #handleRead/#handleViewed
    /// faces. Each entry names one message by its author's ACI and upstream
    /// timestamp; entries address conversations by their own sender, never
    /// by the envelope source (the envelope is our own account). Both faces
    /// ride one envelope (the proto carries the two repeated fields side by
    /// side); either list alone is fine. Unusable entries never reach this
    /// variant — the projection parser dropped them.
    SyncReadState {
        read: Vec<SyncReadEntry>,
        viewed: Vec<SyncReadEntry>,
    },
    /// The engine's `syncMessage.deleteForMe` projection (contract 1.102,
    /// §4.83; the attachment arm 1.196, §4.196): the account's own linked
    /// device deleted messages for itself ("delete for me") — the official
    /// #handleDeleteForMeSync face, the `SyncContent.deleteForMe=22` content
    /// arm. Each group carries one conversation's deletes: the proto
    /// ConversationIdentifier as the engine's conversation string (ACI/PNI
    /// ServiceId UUID, group master key standard base64, or e164 — absent
    /// when the proto carried none), and the (author, timestamp) entries
    /// naming the messages (the author an ACI/PNI string or e164, the
    /// timestamp the message's upstream sent stamp; the engine projects 0
    /// for an unstated stamp and the parser drops it). The fourth arm
    /// (`attachmentDeletes`, official MessageReceiver.preload.ts:3724-3790)
    /// names one attachment on one target message by its client UUID and/or
    /// its two fallback integrity faces. Groups whose entries all failed the
    /// bounds never reach this variant — the projection parser dropped them,
    /// and an envelope with nothing usable left keeps the plain syncMessage
    /// skip.
    SyncDeleteForMe {
        deletes: SyncDeleteForMeProjection,
    },
    /// The engine's `syncMessage.attachmentBackfillResponse` projection
    /// (contract revision 1.175, §4.175; entry states 1.193, §4.193): the
    /// primary device answered our backfill request (engine
    /// `requestAttachmentBackfill`, the official `AttachmentBackfill.request`
    /// chain) — it re-uploaded the attachment and returned fresh transit
    /// pointers for the target message. The connector consumes the pointer
    /// faces into the row's schema-19 live locator column (empty slots only;
    /// `status` entries and the error arm change nothing, the official
    /// `handleResponse` keep-as-is posture), so a later
    /// `attachments.download` walks the §4.54 transit CDN chain. Every entry
    /// keeps its official variant (`BackfillEntry`), and the service layer
    /// reports the whole index-aligned face once the target resolves
    /// (`message.attachmentBackfillSettled`). The target names the
    /// conversation in the official three-form shape (exactly one leg
    /// survives the parse) and the message by author + upstream sent stamp.
    /// A face whose target or conversation fails the shape gates never
    /// reaches this variant — the projection parser dropped it, and an
    /// envelope with nothing usable left keeps the plain syncMessage skip.
    /// The `longText` entry (contract 1.195, §4.195) rides typed as
    /// `long_text` and never joins the index-aligned list: KT long-text
    /// bodies ride the row's text column, so no body-attachment slot exists.
    /// The service reports its official `pendingCount` state as two optional
    /// booleans on the settled event.
    SyncAttachmentBackfillResponse {
        response: SyncAttachmentBackfillResponse,
    },
    /// The engine's `syncMessage.verified` projection (contract 1.103,
    /// §4.84): the account's own linked device settled one peer's safety-number
    /// trust state — the official SyncMessage.verified face, the engine's B4
    /// identity surface. The destination is the peer's ServiceId UUID string,
    /// the state one of the engine's lowercase trust words (`verified` /
    /// `unverified` / `default`); the optional number and hex identity key
    /// ride only when the projection resolved them. The engine has already
    /// applied the state to its authoritative sidecar store before projecting
    /// (`identity::apply_synced_trust`), so this is a pure notify face — the
    /// connector keeps no trust bit to mirror and forwards it to the host.
    /// A face whose destination or state word fails the shape gates never
    /// reaches this variant — the projection parser dropped it, and an
    /// envelope with nothing usable left keeps the plain syncMessage skip.
    SyncVerified {
        verified: SyncVerifiedState,
    },
    /// The engine's `syncMessage.callEvent` projection (contract 1.104,
    /// §4.85): the account's own linked device wrote one 1:1/group call's
    /// history entry — the official callEventSync face, the desktop's
    /// #handleCallEvent/#updateCallHistoryFromRemoteEvent consumer. The
    /// record carries the call's decimal id string (the official
    /// `longToString` form), the record's timestamp, the optional
    /// type/direction/outcome words (the engine projects its enum members as
    /// lowercase words, `unknown` for the UNKNOWN members), and the optional
    /// conversation identity in the official three-form shape (hex room id
    /// for ad-hoc, ServiceId UUID string for a 16-byte direct conversation,
    /// standard base64 group master key otherwise). The connector keeps no
    /// call-history store — the desktop's own call log is the authoritative
    /// store, so this is a pure transient notify. A face whose callId or
    /// timestamp fails the shape gates never reaches this variant — the
    /// projection parser dropped it, and an envelope with nothing usable left
    /// keeps the plain syncMessage skip.
    SyncCallEvent {
        event: SyncCallEvent,
    },
    /// The engine's `syncMessage.configuration` projection (contract 1.106,
    /// §4.87): the account's own linked device changed the account's four
    /// official settings flags — the official handleConfiguration face. The
    /// parser keeps only the bool-keyed faces that survive the per-key
    /// fail-closed read; a face with no surviving key never reaches this
    /// variant — the envelope keeps the plain syncMessage skip.
    SyncConfiguration {
        configuration: SyncConfigurationFlags,
    },
    /// The engine's `syncMessage.fetchLatest` projection (contract 1.106,
    /// §4.87): the account's own linked device asked the receiving client to
    /// refresh one named surface — the official handleFetchLatest trigger.
    /// The optional type word is the engine's SCREAMING projection whitelist
    /// member; the official fires the trigger even for an absent type (the
    /// UNKNOWN member is the downstream no-op), so the arm's presence alone
    /// is the signal and this variant carries no hard gate.
    SyncFetchLatest {
        kind: Option<&'static str>,
    },
    /// The engine's `syncMessage.callLinkUpdate` projection (contract 1.106,
    /// §4.87): the account's own linked device updated one call link's
    /// credential material — the official handleCallLinkUpdate face. The
    /// record hard-gates on the two facts the official handler throws over
    /// (the type word must be the projection's only known member UPDATE, and
    /// the rootKey the update is about must be present); the admin key rides
    /// per-key fail-closed. A face failing a hard gate never reaches this
    /// variant — the envelope keeps the plain syncMessage skip.
    SyncCallLinkUpdate {
        update: SyncCallLinkUpdate,
    },
    /// The engine's `syncMessage.callLogEvent` projection (contract 1.106,
    /// §4.87): the account's own linked device mutated one call-history
    /// record (clear / marked-as-read family) — the official
    /// handleCallLogEvent face. The type word is the record's verb and
    /// hard-gates on the engine's SCREAMING whitelist; the remaining keys are
    /// per-key optional exactly as the official loose parse carries them.
    SyncCallLogEvent {
        event: SyncCallLogEvent,
    },
    /// The engine's `syncMessage.deviceNameChange` projection (contract
    /// 1.106, §4.87): the account renamed one linked device — the official
    /// handleDeviceNameChangeSync face. The official handler drops the sync
    /// when the deviceId is absent (nothing to address), so the connector
    /// hard-gates on the same key; the local-device-id comparison stays the
    /// desktop's own decision.
    SyncDeviceNameChange {
        device_id: u32,
    },
    /// The engine's `syncMessage.usernameChange` projection (contract 1.106,
    /// §4.87): the account's own linked device changed the account username —
    /// the official handleUsernameChangeSync face, an empty pure-signal sync
    /// whose only consumption is a profile re-fetch. The arm's presence is
    /// the whole content.
    SyncUsernameChange,
    /// The engine's `syncMessage.pniChangeNumber` projection (contract
    /// 1.106, §4.87): the account's own number re-registration moved its PNI
    /// identity — the official handlePNIChangeNumber face. The engine
    /// guarantees the key material never crosses its boundary (the official
    /// re-keys from the same sync; the engine's non-consumption is its §5
    /// gap), so the connector forwards only the stripped `{registrationId?,
    /// newE164?}` face; a face with no surviving key is a zero-content sync
    /// and keeps the plain syncMessage skip.
    SyncPniChangeNumber {
        change: SyncPniChangeNumber,
    },
    /// The engine's `syncMessage.contacts` projection (contract 1.136,
    /// §4.122): the phone pushed its contact list to the linked devices —
    /// the official handleContacts consume face, the passive half of the
    /// connector's contacts cache. Each record is one bounded parsed contact
    /// (the identity + display name the cache holds; the
    /// expireTimer/inboxPosition family has no connector-cache home and
    /// stays on the engine face, the throttled `listContacts` enrich owns
    /// the richer trio). Records whose every field failed the bounds never
    /// reach this variant — the projection parser dropped them, and an
    /// envelope with nothing usable left keeps the plain syncMessage skip.
    /// The routing source stays None — the envelope is our own account and
    /// the records name their own subjects (the read/viewed precedent).
    SyncContacts {
        contacts: Vec<SyncContactRecord>,
    },
    /// The engine's `syncMessage.blocked` projection (contract 1.140,
    /// §4.136): the account's own linked device replaced its block list —
    /// the official `_handleBlocked` mirror (MessageReceiver.preload.ts:3988),
    /// which the engine projects in the official's modern/legacy family
    /// shapes (modern `blockedE164s`/`blockedAcis`/`blockedGroups` entry
    /// objects, legacy `numbers`/`acis`/`groupIds`/`acisBinary` string
    /// arrays; a fully-empty list projects the modern empty object). The
    /// connector unions whichever identities survived the engine's parse,
    /// deduped per class; the modern entries' advisory `timestamp` has no
    /// factor-stamp home and does not ride. A face whose every key failed
    /// the tolerant read keeps the plain syncMessage skip. The routing
    /// source stays None — the envelope is our own account and the
    /// identities name their own subjects (the read/viewed precedent).
    SyncBlocked {
        blocked: SyncBlocked,
    },
    /// The engine's `groupChanged {groupId, revision, changes[], editor?,
    /// expireTimerSeconds?}` projection (contract 1.100, §4.81 D3): the
    /// official GroupV2ChangeDetailType word list the engine decrypted out
    /// of one group update batch — every non-timer/terminate change rides
    /// here verbatim (the official-non-rendering classes the engine cannot
    /// name never reach the wire). The connector is a pipe like the story
    /// and call faces: `changes` is the bounded verbatim array — never
    /// parsed or re-shaped connector-side (the desktop renders the change
    /// notices). `expire_timer_seconds` rides only when the batch carried a
    /// timer change beside the others (pure timer batches stay on the
    /// `groupUpdated` face); the service layer mirrors it like that face.
    /// The routing group id is the projection's `groupId` (the master
    /// key's standard base64 — the listGroups id form).
    GroupChanged {
        revision: u64,
        changes: Value,
        editor: Option<String>,
        expire_timer_seconds: Option<u32>,
    },
    /// The engine's `groupTerminated {groupId, terminator?, timestamp}`
    /// projection (contract 1.134, §4.117): a decrypted group change named
    /// the group terminated and the engine replaced the whole envelope with
    /// the event (change-only projection). Conversation-less transient
    /// family like [`ControlReceive::Story`] — no row, nothing persisted —
    /// though the `groupId` names its subject: the service layer forwards
    /// it verbatim whether or not the group has a local conversation (a
    /// terminated group's row may already be gone; the event is the
    /// desktop's termination fact, not a row anchor). `terminator` is the
    /// change author's ACI when the engine decrypted one.
    GroupTerminated {
        group_id: String,
        terminator: Option<String>,
        timestamp: Option<u64>,
    },
    /// The engine's `contactProfileUpdated {aci}` projection (contract
    /// 1.134, §4.117): a peer's profileKeyUpdate batch landed a new profile
    /// key in the engine's store. Conversation-less (the `aci` names its
    /// subject); the actual profile/avatar re-fetch stays the desktop's
    /// on-demand pull through the existing read faces — this event only
    /// says the cached profile may be stale.
    ContactProfileUpdated {
        aci: String,
    },
}

/// One (sender, timestamp) pair off the engine's `syncMessage.read[]` /
/// `.viewed[]` projection (contract 1.100, §4.81): the author identity the
/// entry names plus the upstream timestamp of the message it marks.
/// `sender_number` rides only when the engine's contacts cache resolved the
/// author's number (the receive author-number discipline).
#[derive(Clone, Debug, PartialEq)]
pub struct SyncReadEntry {
    pub sender_uuid: String,
    pub sender_number: Option<String>,
    pub timestamp: u64,
}

/// One (author, timestamp) pair off the engine's `syncMessage.deleteForMe`
/// projection (contract 1.102, §4.83): the message's author identity (ACI/PNI
/// ServiceId string or e164) plus the upstream timestamp of the message the
/// account deleted for itself.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncDeleteEntry {
    pub author: String,
    pub timestamp: u64,
}

/// One conversation-scoped delete group off the engine's
/// `syncMessage.deleteForMe` projection (contract 1.102, §4.83): the
/// proto ConversationIdentifier as the engine's conversation string (an
/// ACI/PNI ServiceId UUID, a group master key's standard base64, or an e164)
/// when the projection carried one, plus that conversation's bounded delete
/// entries.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncDeleteGroup {
    pub conversation_id: Option<String>,
    pub messages: Vec<SyncDeleteEntry>,
}

/// One whole-conversation delete off the engine's `syncMessage.deleteForMe`
/// projection (contract 1.182, §4.182): the `conversationDeletes` arm — the
/// account cleared a whole chat on another linked device. `is_full_delete`
/// is the official `Boolean(item.isFullDelete)` verbatim (the engine
/// projects `false` for an unstated flag, the same default the official
/// consumer applies); `most_recent_messages` and
/// `most_recent_non_expiring_messages` are the official
/// `getMostRecentAddressableMessages` anchors — the upstream sends the
/// newest addressable rows so the receiver can bound the delete to
/// everything at or below the newest one it still holds. The engine
/// projection drops a group whose `mostRecentMessages` is empty (the
/// official warn-drop), so what reaches here always carries at least one
/// anchor.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncDeleteConversation {
    pub conversation_id: String,
    pub is_full_delete: bool,
    pub most_recent_messages: Vec<SyncDeleteEntry>,
    pub most_recent_non_expiring_messages: Vec<SyncDeleteEntry>,
}

/// One local-only conversation delete off the engine's
/// `syncMessage.deleteForMe` projection (contract 1.182, §4.182): the
/// `localOnlyConversationDeletes` arm — the account cleared a chat that had
/// no addressable rows left, so the upstream sends only the conversation
/// identity and the other devices clear their local copies without
/// pretending to bound the delete by a message position.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncLocalOnlyConversationDelete {
    pub conversation_id: String,
}

/// One single-attachment delete off the engine's `syncMessage.deleteForMe`
/// projection (contract 1.196, §4.196): the `attachmentDeletes` arm — the
/// official `handleDeleteForMeSync` fourth face
/// (MessageReceiver.preload.ts:3724-3790). The target message keeps the
/// official `AddressableMessage` address (author + upstream sent stamp, both
/// hard gates: the official target resolution at :3739-3755 calls
/// `processAddressableMessage` (:4415-4429), which refuses an author-less
/// or stamp-less target), and the attachment is
/// named one-of-or-more by its client UUID and the two integrity fallbacks
/// (:3754-3770): `client_uuid` a hyphenated UUID string, `fallback_digest`
/// standard base64, `fallback_plaintext_hash` lowercase hex. At least one
/// leg survives the parse; an entry with none drops whole.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncDeleteAttachment {
    pub conversation_id: String,
    pub target: SyncDeleteEntry,
    pub client_uuid: Option<String>,
    pub fallback_digest: Option<String>,
    pub fallback_plaintext_hash: Option<String>,
}

/// The engine's whole `syncMessage.deleteForMe` projection (contract
/// 1.182, §4.182; the attachment arm 1.196, §4.196): all four
/// consumer-facing arms in one record. The arms never mix per proto shape
/// (`messageDeletes` names rows, `conversationDeletes` names a conversation
/// with its newest-row anchors, `localOnlyConversationDeletes` names a
/// conversation alone, `attachmentDeletes` names one attachment on one
/// target row), but one envelope may carry several of them, so the routing
/// decision is "any arm survived the bounds" — the same any-entry-survives
/// rule the message arm already followed in 1.102.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncDeleteForMeProjection {
    pub groups: Vec<SyncDeleteGroup>,
    pub conversations: Vec<SyncDeleteConversation>,
    pub local_only_conversations: Vec<SyncLocalOnlyConversationDelete>,
    pub attachments: Vec<SyncDeleteAttachment>,
}

impl SyncDeleteForMeProjection {
    /// Whether no arm survived the projection bounds — the plain
    /// `syncMessage` skip.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
            && self.conversations.is_empty()
            && self.local_only_conversations.is_empty()
            && self.attachments.is_empty()
    }

    /// The entry-count budget the queue charges this face (contract 1.182):
    /// the §4.13 accounting counts heap strings entry-wise, and the
    /// conversation arms carry their anchors the same way the message
    /// groups carry their entries.
    pub fn budget_bytes(&self) -> usize {
        let groups = self
            .groups
            .iter()
            .map(|group| {
                std::mem::size_of::<SyncDeleteGroup>()
                    + group.conversation_id.as_ref().map_or(0, String::len)
                    + group.messages.len()
                        * (2 * MAX_RECEIVE_ID_CHARS + std::mem::size_of::<SyncDeleteEntry>())
            })
            .sum::<usize>();
        let conversations = self
            .conversations
            .iter()
            .map(|conversation| {
                std::mem::size_of::<SyncDeleteConversation>()
                    + conversation.conversation_id.len()
                    + (conversation.most_recent_messages.len()
                        + conversation.most_recent_non_expiring_messages.len())
                        * (2 * MAX_RECEIVE_ID_CHARS + std::mem::size_of::<SyncDeleteEntry>())
            })
            .sum::<usize>();
        let local_only = self
            .local_only_conversations
            .iter()
            .map(|conversation| {
                std::mem::size_of::<SyncLocalOnlyConversationDelete>()
                    + conversation.conversation_id.len()
            })
            .sum::<usize>();
        let attachments = self
            .attachments
            .iter()
            .map(|attachment| {
                std::mem::size_of::<SyncDeleteAttachment>()
                    + attachment.conversation_id.len()
                    + attachment.target.author.len()
                    + attachment.client_uuid.as_ref().map_or(0, String::len)
                    + attachment.fallback_digest.as_ref().map_or(0, String::len)
                    + attachment
                        .fallback_plaintext_hash
                        .as_ref()
                        .map_or(0, String::len)
            })
            .sum::<usize>();
        groups + conversations + local_only + attachments
    }
}

/// One safety-number trust sync off the engine's `syncMessage.verified`
/// projection (contract 1.103, §4.84): the destination peer's ServiceId UUID
/// string, the settled trust state as the engine's lowercase word
/// (`verified` / `unverified` / `default` — the parser's whitelist, so a
/// hostile word never reaches this struct), and the optional enrichment the
/// projection carried — the peer's e164 when the engine's contacts cache
/// resolved one, and the peer's hex identity key when the proto stated it.
/// `state` stays the `&'static str` whitelist member (the call-signaling
/// `signal_type` discipline): the word list is closed and the service/host
/// faces carry it verbatim.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncVerifiedState {
    pub destination_uuid: String,
    pub destination_number: Option<String>,
    pub identity_key: Option<String>,
    pub state: &'static str,
}

/// One call-history sync record off the engine's `syncMessage.callEvent`
/// projection (contract 1.104, §4.85): the call's decimal id string (the
/// official `longToString` wire form, kept verbatim — the connector is a
/// pipe for the desktop's call-log join), the record's positive timestamp,
/// the optional type/direction/outcome words (whitelist members the parser
/// resolved from the engine's lowercase projections — a hostile word answers
/// absent, never a mangled one), and the optional conversation identity in
/// the projection's verbatim form (hex room id / UUID string / base64 master
/// key — the service layer's resolution ladder reads the form, the connector
/// never re-encodes it).
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCallEvent {
    pub call_id: String,
    pub timestamp: u64,
    pub kind: Option<&'static str>,
    pub direction: Option<&'static str>,
    pub outcome: Option<&'static str>,
    pub conversation_id: Option<String>,
}

/// The four official settings flags off the engine's `syncMessage.
/// configuration` projection (contract 1.106, §4.87): each rides only when
/// the projection carried it (the engine projects its optional proto bools
/// key-for-key) and the parse's per-key fail-closed read kept it. A face
/// where no key survived never reaches the routing.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncConfigurationFlags {
    pub read_receipts: Option<bool>,
    pub unidentified_delivery_indicators: Option<bool>,
    pub typing_indicators: Option<bool>,
    pub link_previews: Option<bool>,
}

/// One call-link update off the engine's `syncMessage.callLinkUpdate`
/// projection (contract 1.106, §4.87): the update verb (the engine's only
/// known word — the parser hard-gates on it, so the field is the whitelist
/// member verbatim) plus the call link's root key and the optional admin
/// key, both standard-base64 strings the connector never decodes (the §4.73
/// call-link material discipline: zero parsing, zero logging — the desktop
/// owns the zkgroup chain).
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCallLinkUpdate {
    pub kind: &'static str,
    pub root_key: String,
    pub admin_key: Option<String>,
}

/// One call-history mutation off the engine's `syncMessage.callLogEvent`
/// projection (contract 1.106, §4.87): the verb word (the parser's SCREAMING
/// whitelist — CLEAR / MARKED_AS_READ / MARKED_AS_READ_IN_CONVERSATION /
/// CLEAR_IN_CONVERSATION — hard-gated, the record's whole meaning), the
/// target record's timestamp and call id in the engine's verbatim shapes
/// (the u64 number form — the desktop's own longToString join reads the
/// projection), and the optional conversation identity in the same three-form
/// shape the §4.85 call-event record carries (hex room id / ServiceId UUID /
/// standard-base64 group master key — the §4.85 resolution ladder reads the
/// form).
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCallLogEvent {
    pub kind: &'static str,
    pub timestamp: Option<u64>,
    pub conversation_id: Option<String>,
    pub call_id: Option<u64>,
}

/// One PNI change-number sync off the engine's `syncMessage.pniChangeNumber`
/// projection (contract 1.106, §4.87): the stripped face only — the engine
/// never projects the sync's key material (identityKeyPair / signed prekey /
/// last-resort kyber prekey stay inside the engine boundary, the backup-key
/// discipline), so the connector carries the registration id and the new
/// e164 when the projection stated them.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncPniChangeNumber {
    pub registration_id: Option<u32>,
    pub new_e164: Option<String>,
}

/// One passive contact record off the engine's `syncMessage.contacts`
/// projection (contract 1.136, §4.122): the parsed contact identity — the
/// ACI the engine always projects, the e164 when its cache resolved one —
/// plus the composed display name. These are the facts the connector's
/// contacts cache holds (the pull path's `peer_key`/`title` pair); the
/// expireTimer/inboxPosition family rides the engine face only.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncContactRecord {
    pub aci: String,
    pub number: Option<String>,
    pub name: Option<String>,
}

/// The engine's `syncMessage.blocked` projection (contract 1.140, §4.136):
/// the account's own linked device replaced its block list — the official
/// `_handleBlocked` mirror. One bounded identity set per subject class,
/// deduped: the e164s, the ACI ServiceId UUID strings, and the group master
/// keys in the engine's standard-base64 `groupId` form. The modern entries'
/// advisory `timestamp` has no home in the connector's factor stamp and does
/// not ride; the projection already dropped the identities it could not
/// resolve.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SyncBlocked {
    pub numbers: Vec<String>,
    pub acis: Vec<String>,
    pub group_ids: Vec<String>,
}

/// One status entry of the backfill response's attachment list (contract
/// 1.193, §4.193): the official `AttachmentData.Status` two-state split the
/// desktop acts on — `PENDING` keeps the attachment as is and leaves the
/// request timer armed (attachmentBackfill.preload.ts:291-293), while
/// `TERMINAL_ERROR` marks the attachment errored and raises the download
/// toast (:294-301). Pre-1.193 both folded into `None` beside unparseable
/// entries, so the connector could not tell "wait" from "the phone says
/// never" — the exact distinction the settle event reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackfillStatus {
    Pending,
    Terminal,
    /// A status word outside the pinned vocabulary (today the engine's
    /// `UNKNOWN` projection for an unmapped proto enum value). The official
    /// `missingCaseError` throw is a crash face KT does not copy: the
    /// settle event folds this into `pending`, the non-crash convergence.
    Unknown,
}

/// One index-aligned entry of the backfill response's attachment list
/// (contract 1.193, §4.193): the official `AttachmentData` oneof, kept as
/// two variants so the entry's whole meaning survives the parse. Index
/// alignment stays structural — one vector element per remote entry, never
/// a shifted row (the §4.175 posture).
#[derive(Clone, Debug, PartialEq)]
pub enum BackfillEntry {
    /// A pointer entry (the official `'status' in entry` false arm,
    /// attachmentBackfill.preload.ts:305-315). The locator face rides when
    /// the pointer carried locator material; a locator-less pointer is
    /// still an available attachment, so the variant keeps `None` instead
    /// of collapsing into a status entry.
    Locator(Option<crate::store::HistoryAttachmentLocator>),
    /// A status entry (the official `'status' in entry` arm, :291-303).
    Status(BackfillStatus),
}

/// The engine's `syncMessage.attachmentBackfillResponse` face (contract
/// revision 1.175, §4.175; entries re-typed 1.193, §4.193): the official
/// `SyncMessage.AttachmentBackfillResponse` projection, normalized. The
/// target message rides author + upstream sent stamp; the conversation in
/// the official three-form identity (exactly one leg set after the parse).
/// The data face is either the error word (`MESSAGE_NOT_FOUND`/`UNKNOWN`)
/// or the index-aligned entries — each entry keeps its official variant
/// (pointer vs `PENDING`/`TERMINAL_ERROR` status) and an unparseable entry
/// converges to `Status(Unknown)` rather than a shifted row. Beside the
/// list, `long_text` keeps the official sibling `AttachmentData` entry
/// (contract 1.195, §4.195).
#[derive(Clone, Debug, PartialEq)]
pub struct SyncAttachmentBackfillResponse {
    pub author: String,
    pub sent_timestamp: u64,
    pub conversation_service_id: Option<String>,
    pub conversation_group_id: Option<String>,
    pub conversation_e164: Option<String>,
    pub error: Option<String>,
    pub entries: Vec<BackfillEntry>,
    /// The official `response.longText` entry (contract 1.195, §4.195;
    /// attachmentBackfill.preload.ts:247-283). It keeps the same typed
    /// oneof face as an attachment entry and contributes to the official
    /// `pendingCount` (:257-259), but it never joins `entries`: KT
    /// long-text bodies ride the row's text column, so no body-attachment
    /// slot exists and the index-equals-attachment-position contract stays
    /// intact.
    pub long_text: Option<BackfillEntry>,
}

impl SyncAttachmentBackfillResponse {
    /// The pointer-face projection the §4.175 locator merge consumes
    /// (contract 1.193, §4.193): one slot per entry, `Some(face)` only for
    /// a pointer entry with locator material. Status entries project
    /// `None` — the merge's keep-as-is face — so index alignment survives
    /// the re-typing without changing what the store primitive sees.
    pub fn locator_faces(&self) -> Vec<Option<crate::store::HistoryAttachmentLocator>> {
        self.entries
            .iter()
            .map(|entry| match entry {
                BackfillEntry::Locator(face) => face.clone(),
                BackfillEntry::Status(_) => None,
            })
            .collect()
    }
}

/// Protocol-side bounds for inbound control-plane data (§4.13).
const MAX_QUOTE_TEXT_CHARS: usize = 128;
/// The per-message attachment ceiling, shared by the receive face and the
/// backfill entry list (contract 1.193, §4.193). `pub` since the
/// `message.attachmentBackfillSettled` array mirrors this parse bound (the
/// schema-pairing test pins the two together).
pub const MAX_INBOUND_ATTACHMENTS: usize = 32;
const MAX_ATTACHMENT_ID_CHARS: usize = 128;
/// The inbound filename bound (contract revision 1.184, §4.184): the sender's
/// name rides verbatim up to this clamp — the clamp is boundedness insurance,
/// not a rewrite rule. The budget is filesystem-name scale (255 UTF-16 units,
/// the common per-component cap, reach 1020 UTF-8 bytes), so every name a real
/// sender's filesystem can produce passes byte-exact and only a hostile
/// oversized face clamps. The previous 128-byte budget rewrote real names and
/// is retired (§4.184).
const MAX_ATTACHMENT_FILENAME_BYTES: usize = 1024;
const MAX_ATTACHMENT_CONTENT_TYPE_CHARS: usize = 64;
/// The voice waveform's base64 bound (contract 1.150, §4.149): the engine's
/// fixed shape is a 100-byte bucket vector (136 base64 chars); the cap is the
/// attachment pointer face's own base64 family bound (the 1.56 locator cap),
/// and an over-cap value is not the engine's shape — it drops whole (never
/// truncated: half a waveform is render material the desktop cannot use, the
/// incrementalMac posture rather than the lossy blurHash one).
const MAX_ATTACHMENT_WAVEFORM_CHARS: usize = 512;
const MAX_EMOJI_CHARS: usize = 16;
/// One receipt confirms at most this many earlier rows; a larger batch is
/// truncated (Signal Desktop batches receipts per conversation, so real
/// batches stay far below).
const MAX_RECEIPT_TIMESTAMPS: usize = 256;
/// One sync read/viewed face carries at most this many entries (contract
/// 1.100, §4.81): the same coarse batch guard the receipt family rides —
/// real multi-device read syncs stay far below it; entries past the cap
/// drop (the same truncate discipline as `MAX_RECEIPT_TIMESTAMPS`).
const MAX_SYNC_READ_ENTRIES: usize = 256;
/// One passive contacts face carries at most this many records (contract
/// 1.136, §4.122): the same coarse batch guard family the read sync rides —
/// the engine projects the phone's parsed contact set per envelope, and the
/// tail past the cap drops (the truncate discipline; the stragglers still
/// converge through the 60s-TTL pull path the passive face only accelerates).
const MAX_SYNC_CONTACT_RECORDS: usize = 512;
/// One blocked sync face carries at most this many identities per subject
/// class (contract 1.140, §4.136): the read-face truncate discipline again —
/// a real block list is user-scaled (tens), so the cap only ever bites on a
/// hostile face, and the tail past it drops (the block state still converges
/// through the §4.47 write face and the §4.45 pull's own `isBlocked`).
const MAX_SYNC_BLOCKED_ENTRIES: usize = 512;
/// One passive contact record's display-name cap (contract 1.136, §4.122):
/// the same 64-char title bound the pull path's contact composer applies —
/// the cache holds one bounded title, not the raw profile text.
const MAX_SYNC_CONTACT_NAME_CHARS: usize = 64;
/// One delete-for-me sync carries at most this many conversation groups
/// (contract 1.102, §4.83): the same coarse batch guard family the read
/// sync rides — real batches group per conversation and stay far below;
/// groups past the cap drop whole (the read-face truncate discipline).
/// `pub` since the §4.83 host-event data shape mirrors the bound (the
/// schema-pairing test pins the two together).
pub const MAX_SYNC_DELETE_GROUPS: usize = 64;
/// One delete group carries at most this many (author, timestamp) entries
/// (contract 1.102, §4.83): the read-face entry cap at group scale — real
/// per-conversation batches stay far below it; entries past the cap drop
/// (the same truncate discipline). `pub` since the §4.83 host-event data
/// shape mirrors the bound (the schema-pairing test pins the two together).
pub const MAX_SYNC_DELETE_GROUP_MESSAGES: usize = 256;
/// One delete-for-me sync carries at most this many whole-conversation
/// deletes (`conversationDeletes`) (contract 1.182, §4.182): the same coarse
/// batch guard as the message groups — the upstream fires one
/// `delete-conversation` per user action, so a real batch is one entry
/// (a device sweeping several chats stays in the low tens); entries past
/// the cap drop whole. `pub` since the §4.182 host-event data shape mirrors
/// the bound (the schema-pairing test pins the two together).
pub const MAX_SYNC_DELETE_CONVERSATIONS: usize = 32;
/// One `conversationDeletes` entry carries at most this many newest-row
/// anchors per list (contract 1.182, §4.182): the official sending side
/// slices both lists to `5` (`getMostRecentAddressableMessages(...).slice(0,
/// 5)` in conversations.preload.ts `destroyMessagesInner`), so the receiver
/// never needs more — the bound is generous on purpose (the official
/// receiver itself keeps whatever the peer sent) while still capping a
/// hostile face. Anchors past the cap drop (the truncate discipline).
pub const MAX_SYNC_DELETE_CONVERSATION_ANCHORS: usize = 16;
/// One delete-for-me sync carries at most this many local-only conversation
/// deletes (contract 1.182, §4.182): same batch guard as the
/// `conversationDeletes` arm. `pub` since the §4.182 host-event data shape
/// mirrors the bound.
pub const MAX_SYNC_LOCAL_ONLY_DELETE_CONVERSATIONS: usize = 32;
/// One verified sync's hex identity key carries at most this many characters
/// (contract 1.103, §4.84): the modern EC key projects 66 hex chars, so the
/// bound only ever bites on a hostile face — and it bites by dropping the
/// key, never truncating it (a truncated fingerprint is a lie; an absent key
/// is the honest missing-enrichment face). `pub` since the §4.84 host-event
/// data shape mirrors the bound (the schema-pairing test pins the two
/// together).
pub const MAX_SYNC_IDENTITY_KEY_CHARS: usize = 128;
/// One call-event sync's decimal call id carries at most this many
/// characters (contract 1.104, §4.85): the id is the engine's `u64`
/// `to_string()` output — 20 digits at the u64 ceiling — so the bound only
/// ever bites on a hostile face; the parser also demands every character be
/// an ASCII digit (the official decimal-string shape, kept verbatim). `pub`
/// since the §4.85 host-event data shape mirrors the bound (the
/// schema-pairing test pins the two together).
pub const MAX_SYNC_CALL_ID_CHARS: usize = 20;
/// One call-link update's base64 key material carries at most this many
/// characters (contract 1.106, §4.87): the root key's 32 bytes project 44
/// standard-base64 chars, so the bound only ever bites on a hostile face —
/// and on the root key it bites by dropping the whole record (the update
/// names nothing without its subject; a truncated key would address a
/// different call link), on the admin key by dropping the key (the §4.84
/// fingerprint discipline). `pub` since the §4.87 host-event data shape
/// mirrors the bound (the schema-pairing test pins the two together).
pub const MAX_SYNC_CALL_LINK_KEY_CHARS: usize = 128;
/// One quote carries at most this many attachment metadata entries (contract
/// 1.100, §4.81): real quoted-media batches are small and Signal Desktop
/// renders the pill metadata-only; entries past the cap drop (the same
/// truncate discipline as `MAX_INBOUND_ATTACHMENTS`).
const MAX_QUOTE_ATTACHMENTS: usize = 8;
/// `groupChanged.changes` serialized byte guard (contract 1.100, §4.81):
/// the coarse guard family the story/call faces ride — real change batches
/// are orders of magnitude smaller; only hostile material trips it, and an
/// oversized face drops whole (宁缺勿错, never a truncated lie).
const MAX_GROUP_CHANGED_BYTES: usize = 64 * 1024;
/// Rich-body bounds (contract 1.25, §4.13 parity): caps on card/range counts
/// and string sizes. Entries past a cap drop, oversized strings truncate — a
/// hostile payload can never fail the message itself.
const MAX_PREVIEWS: usize = 4;
const MAX_MENTIONS: usize = 64;
const MAX_TEXT_STYLES: usize = 64;
const MAX_PREVIEW_URL_CHARS: usize = 2048;
const MAX_PREVIEW_FIELD_BYTES: usize = 512;
const MAX_MENTION_NAME_BYTES: usize = 128;
/// Sent-transcript face bounds (contract 1.107, §4.88): the outer
/// sealed-sender/story-recipient lists share the sync receive family's 256
/// cap, each story entry's distribution-id list takes the 64-entry family
/// cap, and the blur preview string takes the preview-field budget.
/// `MAX_ATTACHMENT_BLUR_HASH_CHARS` is `pub` since 1.137 (§4.127): the
/// send face enforces the same bound connector-side — one constant, both
/// directions, pinned to the schema pair.
const MAX_SYNC_SENT_STATUS_ENTRIES: usize = 256;
const MAX_STORY_DISTRIBUTION_IDS: usize = 64;
pub const MAX_ATTACHMENT_BLUR_HASH_CHARS: usize = 128;
/// Sticker bounds (contract revision 1.35): the same face bounds the send
/// method enforces — pack id 64 hex chars, pack key 128 base64 chars, emoji
/// label 32 chars. `pub(crate)` since the §4.38 history import face parses
/// the same NDJSON `sticker` identity with these bounds (one source of truth
/// for the 1.35 face across live receive and import).
pub(crate) const MAX_STICKER_PACK_ID_CHARS: usize = 64;
pub(crate) const MAX_STICKER_PACK_KEY_CHARS: usize = 128;
pub(crate) const MAX_STICKER_EMOJI_CHARS: usize = 32;
/// Backfill contact card bounds (contract 1.78, §4.38): every string field is
/// char-truncated at parse and the number/email lists are capped — a hostile
/// line can never fail the import (the §4.13 discipline). The engine's export
/// face projects the official item shape verbatim, so these bounds only bind
/// hostile-line territory.
pub(crate) const MAX_CONTACT_NAME_CHARS: usize = 128;
pub(crate) const MAX_CONTACT_VALUE_CHARS: usize = 256;
pub(crate) const MAX_CONTACT_LABEL_CHARS: usize = 64;
pub(crate) const MAX_CONTACT_ORGANIZATION_CHARS: usize = 128;
pub(crate) const MAX_CONTACT_ENTRIES: usize = 8;
/// Group-update title mirror cap (contract 1.45, §4.44): the update's
/// resulting `groupName` truncates to the same 64-char budget the envelope's
/// `sourceName` peer-name material uses before it rides the rich payload.
const GROUP_UPDATE_TITLE_MIRROR_CHARS: usize = 64;
/// `groupUpdated.editor` bound (contract 1.92, §4.75): the change author's
/// ACI is a 36-char UUID string; the cap is the same coarse guard the peer
/// identity material rides — a hostile overlong shape reads as absent (the
/// row lands unattributed), never truncated into a fake id.
const GROUP_UPDATED_EDITOR_MAX_BYTES: usize = 64;
/// Call-signaling bounds (contract 1.50, §4.48): the engine's legacy-frame
/// projection (`offer`/`answer`/`iceUpdate`/`busy`/`hangup` id fields) and
/// the bounded opaque payloads the connector forwards without parsing. The
/// base64 cap is the same coarse guard the §4.12 attachment envelope rides
/// (a RingRTC SDP offer/ICE batch stays orders of magnitude below it); the
/// frame count caps the legacy `iceUpdate` list projection.
const MAX_CALL_ID: u64 = u32::MAX as u64;
const MAX_CALL_OPAQUE_CHARS: usize = 3 * 1024 * 1024;
const MAX_CALL_ICE_FRAMES: usize = 64;
/// 群通话 era 身份串帽（契约 1.264，§4.248）：与发送面
/// `prepare_calls_send_group_call_update` 的 eraId ≤256 闸同域——收侧同帽，
/// 超帽整面丢弃（宁缺勿错，不截断不发明）。
const MAX_GROUP_CALL_ERA_CHARS: usize = 256;
/// The official desktop's `GROUPV2_ID_LENGTH` (MessageReceiver.preload.ts
/// :3274-3309, contract 1.70 §4.58 consume batch): the group master key is a
/// 32-byte value carried on the wire as standard base64; any other decoded
/// length is not the protocol's face. `pub(crate)` since the §4.83
/// delete-for-me conversation resolution reads the same group-id form.
pub(crate) const GROUPV2_ID_LENGTH: usize = 32;
/// The highest `messageRequestResponseType` enum member this connector
/// consumes (UNKNOWN=0 … BLOCK_AND_SPAM=6; `SignalService.proto:666-678`).
const MRR_RESPONSE_TYPE_MAX: u8 = 6;

pub struct QueuedReceive {
    receive: NormalizedReceive,
    _byte_permit: OwnedSemaphorePermit,
    /// The account's own slot and byte permits, released when the receive is
    /// drained or dropped (packet 1.196: per-account isolation beside the
    /// global caps).
    _account_slot: OwnedSemaphorePermit,
    _account_byte_permit: OwnedSemaphorePermit,
}

impl QueuedReceive {
    pub fn receive(&self) -> &NormalizedReceive {
        &self.receive
    }
}

/// Outcome of one receive admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnqueueOutcome {
    Enqueued,
    /// The queue stayed full for the whole enqueue timeout, so the receive
    /// was dropped instead of parking the engine actor. This is the degraded
    /// path for a store that stopped draining the queue; the persistence
    /// loop reports `runtime.storageChanged` for the underlying failure.
    Dropped,
}

/// One account's receive share (packet 1.196): a slot semaphore (one permit
/// per in-flight receive) and a byte semaphore (the sum of their weights).
/// Both are process-local budgets; the permits ride [`QueuedReceive`], so
/// drainage and drop release them identically.
#[derive(Clone)]
struct AccountReceiveBudget {
    slots: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct ReceiveIngress {
    sender: mpsc::Sender<QueuedReceive>,
    byte_budget: Arc<Semaphore>,
    /// Per-account shares, bounded to the engine's account ceiling plus one
    /// anonymous overflow bucket (an unknown account string can never grow
    /// this map). Mutex-guarded briefly to fetch or create one share.
    account_budgets: Arc<Mutex<HashMap<String, AccountReceiveBudget>>>,
    enqueue_timeout: Duration,
}

impl ReceiveIngress {
    pub(crate) async fn enqueue(
        &self,
        receive: NormalizedReceive,
    ) -> Result<EnqueueOutcome, EngineError> {
        let weight = receive.estimated_bytes().max(1);
        if weight > RECEIVE_QUEUE_BYTE_CAPACITY {
            return Err(EngineError::Protocol);
        }
        // A single receive heavier than one account's whole share can never
        // be admitted; waiting the full enqueue timeout would park the actor
        // (and with it every other account) for nothing. Drop at once under
        // the normal overflow semantics.
        if weight > RECEIVE_QUEUE_PER_ACCOUNT_BYTE_CAPACITY {
            return Ok(EnqueueOutcome::Dropped);
        }
        let budget = self
            .account_budget(receive.account.as_deref().unwrap_or(""))
            .await;
        // The account's own permits are tried without waiting: a flooded
        // account drops its overflow immediately instead of stalling the
        // line loop, so another account's receive is never behind it.
        let Ok(slot_permit) = budget.slots.clone().try_acquire_owned() else {
            return Ok(EnqueueOutcome::Dropped);
        };
        let Ok(account_byte_permit) = budget.bytes.clone().try_acquire_many_owned(weight as u32)
        else {
            return Ok(EnqueueOutcome::Dropped);
        };
        // The global waits are bounded. While storage is down the
        // persistence loop keeps retrying the head of the queue, so an
        // unbounded wait here would park the engine actor and starve its
        // command lane (including shutdown). Both futures are cancel-safe,
        // so a timeout cannot lose a half-acquired permit; the permits taken
        // by a timed-out send drop with it and release their budgets.
        let acquire = self.byte_budget.clone().acquire_many_owned(weight as u32);
        let permit = match timeout(self.enqueue_timeout, acquire).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(EngineError::Exited),
            Err(_) => return Ok(EnqueueOutcome::Dropped),
        };
        match timeout(
            self.enqueue_timeout,
            self.sender.send(QueuedReceive {
                receive,
                _byte_permit: permit,
                _account_slot: slot_permit,
                _account_byte_permit: account_byte_permit,
            }),
        )
        .await
        {
            Ok(Ok(())) => {
                crate::metrics::receive_queue_enqueued();
                Ok(EnqueueOutcome::Enqueued)
            }
            Ok(Err(_)) => Err(EngineError::Exited),
            Err(_) => Ok(EnqueueOutcome::Dropped),
        }
    }

    /// The share for one account key (the raw account string, empty for an
    /// envelope without one). The map is capped at the per-engine account
    /// ceiling plus the anonymous bucket; a key arriving past the cap joins
    /// the anonymous bucket instead of growing the map.
    async fn account_budget(&self, key: &str) -> AccountReceiveBudget {
        let mut budgets = self.account_budgets.lock().await;
        if let Some(budget) = budgets.get(key) {
            return budget.clone();
        }
        let key = if budgets.len() < MAX_ACCOUNTS_PER_ENGINE + 1 {
            key
        } else {
            ""
        };
        budgets
            .entry(key.to_string())
            .or_insert_with(|| AccountReceiveBudget {
                slots: Arc::new(Semaphore::new(RECEIVE_QUEUE_PER_ACCOUNT_CAPACITY)),
                bytes: Arc::new(Semaphore::new(RECEIVE_QUEUE_PER_ACCOUNT_BYTE_CAPACITY)),
            })
            .clone()
    }
}

impl NormalizedReceive {
    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.account.as_ref().map_or(0, String::len)
            + self.source.as_ref().map_or(0, String::len)
            + self.source_uuid.as_ref().map_or(0, String::len)
            + self.peer_name.as_ref().map_or(0, String::len)
            + self.group_id.as_ref().map_or(0, String::len)
            + self.text.as_ref().map_or(0, String::len)
            // Attachment ids dominate descriptor size; the rest is fixed-width
            // except the bounded waveform (≤ 512 chars, §4.149), which counts.
            + self
                .attachments
                .iter()
                .map(|attachment| {
                    attachment.id.len()
                        + attachment.content_type.as_ref().map_or(0, String::len)
                        + attachment.filename.as_ref().map_or(0, String::len)
                        + attachment.waveform.as_ref().map_or(0, String::len)
                        + std::mem::size_of::<NormalizedAttachment>()
                })
                .sum::<usize>()
            // Quotes carry a bounded preview; control payloads are enum-sized —
            // except the sync read/viewed entry lists, whose heap Vecs count
            // here so the queue budget stays honest (§4.13).
            + self.quote.as_ref().map_or(0, |quote| {
                quote.author.len()
                    + quote.text.len()
                    + std::mem::size_of::<NormalizedQuote>()
                    + quote
                        .attachments
                        .iter()
                        .map(|entry| {
                            entry.content_type.as_ref().map_or(0, String::len)
                                + entry.filename.as_ref().map_or(0, String::len)
                                + entry
                                    .thumbnail
                                    .as_ref()
                                    .map_or(0, |thumb| {
                                        thumb.id.len()
                                            + thumb.content_type.as_ref().map_or(0, String::len)
                                            + thumb.filename.as_ref().map_or(0, String::len)
                                            + thumb.waveform.as_ref().map_or(0, String::len)
                                            + std::mem::size_of::<NormalizedAttachment>()
                                    })
                                + std::mem::size_of::<NormalizedQuoteAttachment>()
                        })
                        .sum::<usize>()
            })
            + match self.control.as_ref() {
                Some(ControlReceive::SyncReadState { read, viewed }) => {
                    (read.len() + viewed.len())
                        * (2 * MAX_RECEIVE_ID_CHARS + std::mem::size_of::<SyncReadEntry>())
                }
                // The delete arms carry heap Vecs like the read lists —
                // counted entry-wise so the queue budget stays honest (§4.13;
                // contract 1.182 charges the two conversation arms through
                // the same projection method).
                Some(ControlReceive::SyncDeleteForMe { deletes }) => deletes.budget_bytes(),
                // The verified sync carries one bounded record — the heap
                // strings count here so the queue budget stays honest (§4.13).
                Some(ControlReceive::SyncVerified { verified }) => {
                    std::mem::size_of::<SyncVerifiedState>()
                        + verified.destination_uuid.len()
                        + verified.destination_number.as_ref().map_or(0, String::len)
                        + verified.identity_key.as_ref().map_or(0, String::len)
                }
                // The call-event sync carries one bounded record — the heap
                // strings count here so the queue budget stays honest (§4.13).
                Some(ControlReceive::SyncCallEvent { event }) => {
                    std::mem::size_of::<SyncCallEvent>()
                        + event.call_id.len()
                        + event.conversation_id.as_ref().map_or(0, String::len)
                }
                // The configuration sync is fixed-width bools — nothing heap
                // to count beyond the struct (§4.13).
                Some(ControlReceive::SyncConfiguration { configuration }) => {
                    std::mem::size_of::<SyncConfigurationFlags>()
                        + std::mem::size_of_val(&configuration.read_receipts)
                        + std::mem::size_of_val(&configuration.unidentified_delivery_indicators)
                        + std::mem::size_of_val(&configuration.typing_indicators)
                        + std::mem::size_of_val(&configuration.link_previews)
                }
                // The fetch-latest trigger carries at most one word pointer —
                // the &'static str points at the binary's word table, no heap
                // (§4.13).
                Some(ControlReceive::SyncFetchLatest { .. }) => {
                    std::mem::size_of::<Option<&'static str>>()
                }
                // The call-link update carries bounded base64 material — the
                // heap strings count here (§4.13).
                Some(ControlReceive::SyncCallLinkUpdate { update }) => {
                    std::mem::size_of::<SyncCallLinkUpdate>()
                        + update.root_key.len()
                        + update.admin_key.as_ref().map_or(0, String::len)
                }
                // The call-log mutation carries one bounded conversation
                // identity — the heap string counts here (§4.13).
                Some(ControlReceive::SyncCallLogEvent { event }) => {
                    std::mem::size_of::<SyncCallLogEvent>()
                        + event.conversation_id.as_ref().map_or(0, String::len)
                }
                // The device-name/username triggers are fixed-width (the
                // word pointer is binary-resident) — nothing heap (§4.13).
                Some(ControlReceive::SyncDeviceNameChange { .. })
                | Some(ControlReceive::SyncUsernameChange) => 0,
                // The PNI change carries one bounded e164 — the heap string
                // counts here (§4.13).
                Some(ControlReceive::SyncPniChangeNumber { change }) => {
                    std::mem::size_of::<SyncPniChangeNumber>()
                        + change.new_e164.as_ref().map_or(0, String::len)
                }
                // The backfill response carries the bounded target identities
                // plus one locator face per pointer entry (each face bounded
                // by the 1.56 caps family; status entries carry no heap) —
                // counted entry-wise so the queue budget stays honest
                // (§4.13, §4.175, §4.193).
                Some(ControlReceive::SyncAttachmentBackfillResponse { response }) => {
                    std::mem::size_of::<SyncAttachmentBackfillResponse>()
                        + response.author.len()
                        + response.conversation_service_id.as_ref().map_or(0, String::len)
                        + response.conversation_group_id.as_ref().map_or(0, String::len)
                        + response.conversation_e164.as_ref().map_or(0, String::len)
                        + response
                            .entries
                            .iter()
                            .filter_map(|entry| match entry {
                                BackfillEntry::Locator(face) => face.as_ref(),
                                BackfillEntry::Status(_) => None,
                            })
                            .map(|face| {
                                face.key.as_ref().map_or(0, String::len)
                                    + face.cdn_key.as_ref().map_or(0, String::len)
                                    + face.digest.as_ref().map_or(0, String::len)
                                    + face
                                        .plaintext_hash
                                        .as_ref()
                                        .map_or(0, String::len)
                            })
                            .sum::<usize>()
                }
                // The contacts sync carries heap record Vecs like the read
                // lists — counted entry-wise so the queue budget stays
                // honest (§4.13).
                Some(ControlReceive::SyncContacts { contacts }) => contacts
                    .iter()
                    .map(|record| {
                        std::mem::size_of::<SyncContactRecord>()
                            + record.aci.len()
                            + record.number.as_ref().map_or(0, String::len)
                            + record.name.as_ref().map_or(0, String::len)
                    })
                    .sum(),
                // The story faces carry bounded identity/emoji strings —
                // the heap strings count here (§4.13); the 1.158 group
                // legs add the bounded group key to the count.
                Some(ControlReceive::StoryReaction {
                    emoji,
                    story_author,
                    group_id,
                    ..
                }) => {
                    std::mem::size_of::<ControlReceive>()
                        + emoji.len()
                        + story_author.len()
                        + group_id.as_ref().map_or(0, String::len)
                }
                Some(ControlReceive::StoryDeleted { group_id, .. }) => {
                    std::mem::size_of::<ControlReceive>()
                        + group_id.as_ref().map_or(0, String::len)
                }
                // The story recipient update carries heap entry Vecs like
                // the contacts list — counted entry-wise (§4.13).
                Some(ControlReceive::SyncStoryRecipientUpdate { recipients, .. }) => {
                    std::mem::size_of::<ControlReceive>()
                        + recipients
                            .iter()
                            .map(|entry| {
                                std::mem::size_of::<NormalizedStoryRecipient>()
                                    + entry
                                        .destination_uuid
                                        .as_ref()
                                        .map_or(0, String::len)
                                    + entry
                                        .distribution_list_ids
                                        .iter()
                                        .map(String::len)
                                        .sum::<usize>()
                            })
                            .sum::<usize>()
                }
                // The own-story transcript carries one bounded story face —
                // the serialized length counts here (§4.13).
                Some(ControlReceive::SyncStoryMessage { message }) => {
                    serde_json::to_vec(message).map_or(0, |bytes| bytes.len())
                }
                _ => 0,
            }
            // Rich bodies carry capped urls/titles/names, contact-card
            // entries and fixed-width ranges (§4.13, §4.132).
            + self.rich.as_ref().map_or(0, |rich| {
                std::mem::size_of::<NormalizedRich>()
                    + rich
                        .previews
                        .iter()
                        .map(|preview| {
                            preview.url.len()
                                + preview.title.as_ref().map_or(0, String::len)
                                + preview.description.as_ref().map_or(0, String::len)
                                + std::mem::size_of::<NormalizedPreview>()
                        })
                        .sum::<usize>()
                    + rich
                        .mentions
                        .iter()
                        .map(|mention| {
                            mention.author.len()
                                + mention.name.as_ref().map_or(0, String::len)
                                + std::mem::size_of::<NormalizedMention>()
                        })
                        .sum::<usize>()
                    + rich.contact.as_ref().map_or(0, |contact| {
                        std::mem::size_of::<NormalizedContact>()
                            + contact.name.as_ref().map_or(0, |name| {
                                std::mem::size_of::<NormalizedContactName>()
                                    + name.given_name.as_ref().map_or(0, String::len)
                                    + name.family_name.as_ref().map_or(0, String::len)
                                    + name.prefix.as_ref().map_or(0, String::len)
                                    + name.suffix.as_ref().map_or(0, String::len)
                                    + name.middle_name.as_ref().map_or(0, String::len)
                                    + name.nickname.as_ref().map_or(0, String::len)
                            })
                            + contact
                                .number
                                .iter()
                                .chain(contact.email.iter())
                                .map(|field| {
                                    field.value.len()
                                        + field.label.as_ref().map_or(0, String::len)
                                        + std::mem::size_of::<NormalizedContactField>()
                                })
                                .sum::<usize>()
                            + contact.organization.as_ref().map_or(0, String::len)
                    })
                    + rich.text_styles.len() * std::mem::size_of::<NormalizedTextStyle>()
            })
    }
}

pub fn receive_channel() -> (ReceiveIngress, mpsc::Receiver<QueuedReceive>) {
    let (sender, receiver) = mpsc::channel(RECEIVE_QUEUE_CAPACITY);
    (
        ReceiveIngress {
            sender,
            byte_budget: Arc::new(Semaphore::new(RECEIVE_QUEUE_BYTE_CAPACITY)),
            account_budgets: Arc::new(Mutex::new(HashMap::new())),
            enqueue_timeout: RECEIVE_ENQUEUE_TIMEOUT,
        },
        receiver,
    )
}

#[derive(Clone)]
pub struct EngineHandle {
    commands: mpsc::Sender<EngineCommand>,
    status: watch::Receiver<EngineStatus>,
    events: broadcast::Sender<EngineEvent>,
    next_id: Arc<AtomicU64>,
    request_timeout: Duration,
    /// Total budget for a graceful shutdown answer before the child is killed
    /// directly. Derived from the graceful-exit budget plus a fixed margin.
    shutdown_timeout: Duration,
    /// Shared with the actor so a stuck actor cannot veto killing the child:
    /// the actor only locks it briefly inside `stop_child`, never while
    /// parked on queue backpressure.
    child: Arc<Mutex<Child>>,
    resource_status: watch::Receiver<(Option<u64>, bool)>,
    stderr: broadcast::Sender<String>,
}

impl EngineHandle {
    pub async fn start(
        config: EngineConfig,
        events: broadcast::Sender<EngineEvent>,
        receive_ingress: ReceiveIngress,
    ) -> Result<Self, EngineError> {
        if !config.executable.is_absolute()
            || !std::fs::symlink_metadata(&config.executable)
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            || config.resource_sample_interval < Duration::from_secs(1)
        {
            return Err(EngineError::StartFailed);
        }
        prepare_data_dir(&config.data_dir).map_err(|_| EngineError::StartFailed)?;

        let mut command = Command::new(&config.executable);
        // The engine's stdout is an owned blocking pipe, not tokio's piped
        // stdio: the read end is consumed by the dedicated blocking pump
        // thread below, whose plain `read` cannot miss a readiness wakeup —
        // engine output drains no matter what the async side is doing.
        // Command holds the parent-side write end until dropped (end of this
        // function), so the reader sees EOF when the child exits.
        let (stdout_reader, stdout_writer) =
            std::io::pipe().map_err(|_| EngineError::StartFailed)?;
        command
            .args(engine_args(&config.data_dir, config.media_ingest))
            .stdin(Stdio::piped())
            .stdout(stdout_writer)
            .stderr(Stdio::piped())
            // The dev/test store-key override must never leak into the child's
            // environment (Phase 3: keys travel the bootstrap channel only).
            .env_remove(crate::store::STORE_KEY_ENV)
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| EngineError::StartFailed)?;

        let pid = child.id().ok_or(EngineError::StartFailed)?;
        let stdin = child.stdin.take().ok_or(EngineError::StartFailed)?;
        let stderr = child.stderr.take().ok_or(EngineError::StartFailed)?;
        let child = Arc::new(Mutex::new(child));
        // The configured enqueue timeout is authoritative for every engine
        // started from this config, regardless of how the ingress was built.
        let receive_ingress = ReceiveIngress {
            enqueue_timeout: config.receive_enqueue_timeout,
            ..receive_ingress
        };
        let initial_status = EngineStatus {
            state: EngineState::Running,
            pid: Some(pid),
            rss_bytes: None,
            resource_pressure: false,
        };
        let (status_tx, status_rx) = watch::channel(initial_status.clone());
        let (resource_tx, resource_rx) = watch::channel((None, false));
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (stderr_tx, _) = broadcast::channel::<String>(STDERR_QUEUE_CAPACITY);

        let _ = events.send(EngineEvent::StateChanged(initial_status));
        let actor_events = events.clone();
        let stderr_lines = stderr_tx.clone();
        let actor_child = Arc::clone(&child);
        // The stdout pump is a blocking OS thread: a blocking `read` cannot
        // miss a readiness wakeup, and the engine's output must keep draining
        // no matter what the async consumers of this pipe are doing. Lines
        // are handed to the actor through a bounded queue; end-of-stream
        // closes it, the same EOF signal the actor would observe inline.
        let (stdout_tx, stdout_rx) = mpsc::channel::<PumpedLine>(STDOUT_LINE_QUEUE_CAPACITY);
        let stdout_limit = config.line_limit;
        std::thread::Builder::new()
            .name(format!("engine-stdout-{pid}"))
            .spawn(move || run_stdout_pump(stdout_reader, stdout_limit, stdout_tx))
            .map_err(|_| EngineError::StartFailed)?;
        tokio::spawn(async move {
            let stderr_drain = tokio::spawn(async move {
                // Forward signal-cli stderr line by line (bounded) so the watchdog can
                // observe receive WebSocket failures. Send failures/lag are ignored;
                // the drain must never panic or block the actor. If framing fails the
                // remaining bytes are discarded so the child never blocks on a full pipe.
                let mut lines =
                    FramedRead::new(stderr, LinesCodec::new_with_max_length(STDERR_LINE_LIMIT));
                loop {
                    match lines.next().await {
                        Some(Ok(line)) => {
                            let _ = stderr_lines.send(line);
                        }
                        Some(Err(_)) => {
                            let mut rest = lines.into_inner();
                            let _ = tokio::io::copy(&mut rest, &mut sink()).await;
                            break;
                        }
                        None => break,
                    }
                }
            });
            run_actor(
                actor_child,
                stdin,
                stdout_rx,
                ActorChannels {
                    commands: command_rx,
                    status: status_tx,
                    events: actor_events,
                    receive_ingress,
                },
                ActorLimits {
                    shutdown_grace: config.shutdown_grace,
                },
            )
            .await;
            stderr_drain.abort();
        });
        let mut monitor_status = status_rx.clone();
        let monitor_events = events.clone();
        let sample_interval = config.resource_sample_interval;
        tokio::spawn(async move {
            let mut ticker = interval(sample_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            ticker.tick().await;
            let mut tracker = ResourcePressureTracker::new(
                DEFAULT_RSS_PRESSURE_BYTES,
                DEFAULT_RSS_RECOVERY_BYTES,
                DEFAULT_RSS_PRESSURE_SAMPLES,
                DEFAULT_RSS_RECOVERY_SAMPLES,
            )
            .expect("static resource policy is valid");
            loop {
                tokio::select! {
                    changed = monitor_status.changed() => {
                        if changed.is_err() || matches!(
                            monitor_status.borrow().state,
                            EngineState::Stopped | EngineState::Exited | EngineState::Faulted
                        ) {
                            let _ = resource_tx.send((None, false));
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let sample = tokio::task::spawn_blocking(move || sample_rss(pid)).await;
                        let Ok(Ok(rss_bytes)) = sample else {
                            continue;
                        };
                        let transition = tracker.observe(rss_bytes);
                        let elevated = match transition {
                            Some(ResourcePressureState::Elevated) => true,
                            Some(ResourcePressureState::Recovered) => false,
                            None => resource_tx.borrow().1,
                        };
                        let _ = resource_tx.send((Some(rss_bytes), elevated));
                        if let Some(state) = transition {
                            let _ = monitor_events.send(EngineEvent::ResourcePressure {
                                state,
                                pid,
                                rss_bytes,
                            });
                        }
                    }
                }
            }
        });

        tracing::info!(pid, "engine process started");
        Ok(Self {
            commands: command_tx,
            status: status_rx,
            events,
            next_id: Arc::new(AtomicU64::new(1)),
            request_timeout: config.request_timeout,
            shutdown_timeout: config.shutdown_grace + SHUTDOWN_TIMEOUT_MARGIN,
            child,
            resource_status: resource_rx,
            stderr: stderr_tx,
        })
    }

    pub fn status(&self) -> EngineStatus {
        let mut status = self.status.borrow().clone();
        let resource = *self.resource_status.borrow();
        status.rss_bytes = resource.0;
        status.resource_pressure = resource.1;
        status
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status().state,
            EngineState::Stopped | EngineState::Exited | EngineState::Faulted
        )
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.events.subscribe()
    }

    /// Line-based stream of the signal-cli stderr output (bounded, lossy under lag).
    pub fn subscribe_stderr(&self) -> broadcast::Receiver<String> {
        self.stderr.subscribe()
    }

    pub async fn call(
        &self,
        method: &'static str,
        params: Value,
        class: CallClass,
    ) -> Result<Value, EngineError> {
        self.call_with_timeout(method, params, class, self.request_timeout)
            .await
    }

    pub async fn call_with_timeout(
        &self,
        method: &'static str,
        params: Value,
        class: CallClass,
        request_timeout: Duration,
    ) -> Result<Value, EngineError> {
        let started = Instant::now();
        let (id, response_rx) = self.dispatch_call(method, params, class)?;
        let outcome = match timeout(request_timeout, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(EngineError::Exited),
            Err(_) => {
                let commands = self.commands.clone();
                tokio::spawn(async move {
                    let _ = commands.send(EngineCommand::Cancel { id }).await;
                });
                match class {
                    CallClass::ReadOnly => Err(EngineError::Timeout),
                    CallClass::Mutating => Err(EngineError::UnknownOutcome),
                }
            }
        };
        log_call_outcome(method, class, started, &outcome);
        outcome
    }

    /// Same dispatch as [`Self::call_with_timeout`], but a caller-side
    /// cancellation signal abandons the wait: the pending request is removed
    /// from the actor's map (its eventual response is then an ignored
    /// unknown-id warning) and `Ok(None)` is returned at once. The engine-side
    /// operation itself is not cancellable — the pinned JSON-RPC surface has
    /// no cancel verb — so a caller must treat `None` as "we stopped waiting;
    /// the operation may still land upstream", never as "it did not happen".
    /// This is the link-cancel path: the connector must not stop/restart a
    /// shared engine just to abandon one account's `finishLink` wait.
    pub async fn call_with_timeout_or_cancel(
        &self,
        method: &'static str,
        params: Value,
        class: CallClass,
        request_timeout: Duration,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<Option<Value>, EngineError> {
        let started = Instant::now();
        let (id, response_rx) = self.dispatch_call(method, params, class)?;
        let outcome = tokio::select! {
            biased;
            // A closed sender means the finish lane was torn down
            // (`stop`/`shutdown`); both arms abandon the wait the same way.
            _ = cancel.changed() => {
                let commands = self.commands.clone();
                tokio::spawn(async move {
                    let _ = commands.send(EngineCommand::Cancel { id }).await;
                });
                tracing::debug!(
                    upstream_method = method,
                    call_class = call_class_label(class),
                    duration_ms = started.elapsed().as_millis() as u64,
                    result = "cancelled",
                    "engine call abandoned by the caller"
                );
                return Ok(None);
            }
            timed = timeout(request_timeout, response_rx) => match timed {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(EngineError::Exited),
                Err(_) => {
                    let commands = self.commands.clone();
                    tokio::spawn(async move {
                        let _ = commands.send(EngineCommand::Cancel { id }).await;
                    });
                    match class {
                        CallClass::ReadOnly => Err(EngineError::Timeout),
                        CallClass::Mutating => Err(EngineError::UnknownOutcome),
                    }
                }
            },
        };
        log_call_outcome(method, class, started, &outcome);
        Ok(Some(outcome?))
    }

    /// Register one request in the actor's pending map. The caller owns the
    /// response receiver and the timeout/cancel decision.
    fn dispatch_call(
        &self,
        method: &'static str,
        params: Value,
        class: CallClass,
    ) -> Result<(String, oneshot::Receiver<Result<Value, EngineError>>), EngineError> {
        if self.is_terminal() {
            return Err(EngineError::NotRunning);
        }
        let id = format!("kt-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let (response_tx, response_rx) = oneshot::channel();
        match self.commands.try_send(EngineCommand::Request {
            id: id.clone(),
            method,
            params,
            class,
            response: response_tx,
        }) {
            Ok(()) => Ok((id, response_rx)),
            Err(mpsc::error::TrySendError::Full(_)) => Err(EngineError::Backpressure),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(EngineError::NotRunning),
        }
    }

    /// Graceful stop with a total timeout. The command lane can be starved
    /// when the actor is parked outside its `select!` (e.g. on receive-queue
    /// backpressure while storage is down), so an unanswered shutdown kills
    /// the child directly instead of waiting forever. The kill is the same
    /// forced-stop step `stop_child` falls back to after its grace period;
    /// the actor then observes the closed pipes and unwinds on its own.
    /// Forcefully kill the child without waiting for its graceful exit.
    /// Used at a pool budget deadline, where the shutdown future may still be
    /// parked in the actor/writer and a dropped future would leave the child
    /// alive through the actor's own handle clone.
    pub async fn force_kill(&self) -> std::io::Result<()> {
        // Never wait for the child mutex here: the actor may hold it while
        // parked on a stalled stdin write, which is exactly the state a pool
        // budget deadline has to break. The pid signal is lock-free.
        #[cfg(unix)]
        if let Some(pid) = self.status().pid {
            let result = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            if result == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let child = Arc::clone(&self.child);
            tokio::spawn(async move {
                let mut child = child.lock().await;
                let _ = child.start_kill();
            });
            return Ok(());
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), EngineError> {
        if self.is_terminal() {
            return Ok(());
        }
        let (response_tx, response_rx) = oneshot::channel();
        let graceful = async {
            self.commands
                .send(EngineCommand::Shutdown {
                    response: response_tx,
                })
                .await
                .map_err(|_| EngineError::Exited)?;
            response_rx.await.map_err(|_| EngineError::Exited)
        };
        match timeout(self.shutdown_timeout, graceful).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    timeout_ms = self.shutdown_timeout.as_millis() as u64,
                    "engine shutdown unanswered; killing the engine process"
                );
                // The actor only holds this lock briefly inside `stop_child`,
                // so a parked actor cannot block the kill.
                let _ = self.child.lock().await.start_kill();
                Ok(())
            }
        }
    }
}

/// The `engine call failed` log face (contract 1.167 §4.165): classified
/// fields only, never upstream error content. On the generic upstream face
/// the engine's embedded cause-class literal — the bounded fixed literal the
/// response classifier extracted, never free-form text — rides the line as
/// the trailing `cause` field; every other face (and a causeless upstream)
/// emits the pre-1.167 line byte for byte.
fn log_engine_call_failure(
    upstream_method: &'static str,
    call_class: &'static str,
    duration_ms: u64,
    error: &EngineError,
) {
    let cause = match error {
        EngineError::Upstream {
            cause: Some(cause), ..
        } => Some(cause.as_str()),
        _ => None,
    };
    match cause {
        Some(cause) => tracing::warn!(
            upstream_method,
            call_class,
            duration_ms,
            error_class = error.class(),
            cause,
            "engine call failed"
        ),
        None => tracing::warn!(
            upstream_method,
            call_class,
            duration_ms,
            error_class = error.class(),
            "engine call failed"
        ),
    }
}

/// The completion log for one engine call: signal-cli method names are fixed
/// crate-internal literals; only the classified error variant is logged, never
/// upstream error content.
fn log_call_outcome(
    upstream_method: &'static str,
    class: CallClass,
    started: Instant,
    outcome: &Result<Value, EngineError>,
) {
    match outcome {
        Ok(_) => tracing::debug!(
            upstream_method,
            call_class = call_class_label(class),
            duration_ms = started.elapsed().as_millis() as u64,
            result = "ok",
            "engine call completed"
        ),
        Err(error) => log_engine_call_failure(
            upstream_method,
            call_class_label(class),
            started.elapsed().as_millis() as u64,
            error,
        ),
    }
}

enum EngineCommand {
    Request {
        id: String,
        method: &'static str,
        params: Value,
        class: CallClass,
        response: oneshot::Sender<Result<Value, EngineError>>,
    },
    Cancel {
        id: String,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

struct PendingRequest {
    class: CallClass,
    /// signal-cli account param of the in-flight request, when present — used
    /// solely to attribute upstream authorization failures (contract 1.21).
    account: Option<String>,
    response: oneshot::Sender<Result<Value, EngineError>>,
}

struct ActorLimits {
    shutdown_grace: Duration,
}

struct ActorChannels {
    commands: mpsc::Receiver<EngineCommand>,
    status: watch::Sender<EngineStatus>,
    events: broadcast::Sender<EngineEvent>,
    receive_ingress: ReceiveIngress,
}

async fn run_actor(
    child: Arc<Mutex<Child>>,
    stdin: ChildStdin,
    mut lines: mpsc::Receiver<PumpedLine>,
    channels: ActorChannels,
    limits: ActorLimits,
) {
    let ActorChannels {
        mut commands,
        status: status_tx,
        events,
        receive_ingress,
    } = channels;
    let process_pid = child.lock().await.id();
    // The single stdin writer lives in its own task (A7): an inline write_all
    // parked the whole actor whenever the child stopped reading its stdin,
    // stalling the stdout pump and the command lane with it. The actor now
    // queues whole frames; the writer keeps writing them in order, and a
    // full queue or a dead writer is reported through the queue instead of
    // blocking the loop.
    let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(STDIN_WRITE_QUEUE_CAPACITY);
    let (writer_failed_tx, mut writer_failed_rx) = mpsc::channel::<()>(1);
    let writer = tokio::spawn(run_stdin_writer(stdin, write_rx, writer_failed_tx));
    let mut pending = HashMap::<String, PendingRequest>::new();
    // Whether dropped receives have been reported as degraded storage; reset
    // when admission succeeds again so a `recovered` state is emitted once.
    let mut receive_degraded = false;
    let terminal_state;
    let terminal_cause: &'static str;

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(EngineCommand::Request { id, method, params, class, response }) => {
                        if pending.len() >= MAX_PENDING_UPSTREAM_REQUESTS {
                            let _ = response.send(Err(EngineError::Backpressure));
                            continue;
                        }
                        let request = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "method": method,
                            "params": params,
                        });
                        let mut encoded = match serde_json::to_vec(&request) {
                            Ok(value) => value,
                            Err(_) => {
                                let _ = response.send(Err(EngineError::Protocol));
                                continue;
                            }
                        };
                        encoded.push(b'\n');
                        match write_tx.try_send(encoded) {
                            Ok(()) => {
                                let account = params
                                    .get("account")
                                    .and_then(Value::as_str)
                                    .map(str::to_string);
                                pending.insert(id, PendingRequest { class, account, response });
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                // The child's stdin pipe and the writer queue
                                // are both full: same admission failure as the
                                // pending cap, so the caller hears Backpressure
                                // instead of parking the actor.
                                let _ = response.send(Err(EngineError::Backpressure));
                                continue;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                let failure = match class {
                                    CallClass::ReadOnly => EngineError::Exited,
                                    CallClass::Mutating => EngineError::UnknownOutcome,
                                };
                                let _ = response.send(Err(failure));
                                terminal_state = EngineState::Exited;
                                terminal_cause = "stdin_writer_closed";
                                break;
                            }
                        }
                    }
                    Some(EngineCommand::Cancel { id }) => {
                        pending.remove(&id);
                    }
                    Some(EngineCommand::Shutdown { response }) => {
                        writer.abort();
                        stop_child(&child, limits.shutdown_grace).await;
                        let _ = response.send(());
                        terminal_state = EngineState::Stopped;
                        terminal_cause = "shutdown_requested";
                        break;
                    }
                    None => {
                        writer.abort();
                        stop_child(&child, limits.shutdown_grace).await;
                        terminal_state = EngineState::Stopped;
                        terminal_cause = "command_channel_closed";
                        break;
                    }
                }
            }
            // The writer could not deliver a frame (broken pipe: the child is
            // gone or closed its stdin). Drain pending with the class-correct
            // failures, exactly as an inline write error used to.
            _ = writer_failed_rx.recv() => {
                terminal_state = EngineState::Exited;
                terminal_cause = "stdin_writer_failed";
                break;
            }
            line = lines.recv() => {
                match line {
                    Some(PumpedLine::Line(line)) => {
                        if handle_upstream_line(
                            &line,
                            &mut pending,
                            &events,
                            &receive_ingress,
                            &mut receive_degraded,
                        ).await.is_err() {
                            terminal_state = EngineState::Faulted;
                            terminal_cause = "upstream_protocol_error";
                            break;
                        }
                    }
                    Some(PumpedLine::FramingError) => {
                        terminal_state = EngineState::Faulted;
                        terminal_cause = "stdout_framing_error";
                        break;
                    }
                    // The pump returned: the child's stdout hit EOF, so the
                    // child is gone or closed its output — same as the old
                    // inline `None` arm.
                    None => {
                        terminal_state = EngineState::Exited;
                        terminal_cause = "stdout_eof";
                        break;
                    }
                }
            }
        }
    }

    let terminal_class = match terminal_state {
        EngineState::Stopped => "stopped",
        EngineState::Exited => "exited",
        EngineState::Faulted => "faulted",
        // The loop only breaks on a terminal state; this arm is unreachable.
        EngineState::Running => "running",
    };
    let child_exit = {
        let mut guard = child.lock().await;
        guard.try_wait().ok().flatten()
    };
    if matches!(terminal_state, EngineState::Stopped) {
        tracing::info!(
            state = terminal_class,
            cause = terminal_cause,
            pid = process_pid,
            exit = ?child_exit,
            "engine process stopped"
        );
    } else {
        tracing::warn!(
            state = terminal_class,
            cause = terminal_cause,
            pid = process_pid,
            exit = ?child_exit,
            "engine terminated without a shutdown request"
        );
    }
    // Aborting the writer drops any half-written frame and closes the child's
    // stdin pipe immediately — the same close `stdin.take()` used to perform —
    // so a writer parked on a full pipe cannot delay the child's shutdown.
    // Aborting an already-finished writer is a no-op.
    writer.abort();
    if !matches!(terminal_state, EngineState::Stopped) {
        stop_child(&child, limits.shutdown_grace).await;
    }
    let readonly_failure = match terminal_state {
        EngineState::Faulted => EngineError::Protocol,
        _ => EngineError::Exited,
    };
    let status = EngineStatus {
        state: terminal_state,
        pid: None,
        rss_bytes: None,
        resource_pressure: false,
    };
    let _ = status_tx.send(status.clone());
    let _ = events.send(EngineEvent::StateChanged(EngineStatus {
        pid: process_pid,
        ..status
    }));
    for (_, request) in pending {
        let failure = match request.class {
            CallClass::ReadOnly => readonly_failure.clone(),
            CallClass::Mutating => EngineError::UnknownOutcome,
        };
        let _ = request.response.send(Err(failure));
    }
}

/// The engine's only stdin writer (A7): frames arrive pre-encoded from the
/// actor, in dispatch order, and leave one `write_all` + flush at a time —
/// one writer, one order. A child that stops reading its stdin parks this
/// task alone; the actor keeps pumping stdout and answering commands. On a
/// write failure the writer reports to the actor (which drains pending with
/// the class-correct failures) and exits; when the actor is already gone the
/// report is dropped and this task simply returns. Returning drops `stdin`,
/// closing the pipe, the same EOF a taken stdin used to deliver.
async fn run_stdin_writer(
    mut stdin: ChildStdin,
    mut frames: mpsc::Receiver<Vec<u8>>,
    failed: mpsc::Sender<()>,
) {
    while let Some(frame) = frames.recv().await {
        let bytes = frame.len();
        if let Err(error) = stdin.write_all(&frame).await {
            tracing::warn!(bytes, error = %error, "engine stdin writer failed");
            let _ = failed.try_send(());
            break;
        }
        if let Err(error) = stdin.flush().await {
            tracing::warn!(bytes, error = %error, "engine stdin flush failed");
            let _ = failed.try_send(());
            break;
        }
    }
}

/// The engine's only stdout reader: a blocking OS thread. A blocking `read`
/// delivers bytes regardless of any readiness-event machinery, so engine
/// output drains even when the async side never observes a wakeup; the
/// actor's queue arm (`PumpedLine`) is the only coupling. A full queue parks
/// this thread alone (the same backpressure an inline reader had), a codec
/// failure reports `FramingError` once, and end-of-stream closes the queue —
/// the actor's EOF signal.
fn run_stdout_pump(stdout: std::io::PipeReader, line_limit: usize, tx: mpsc::Sender<PumpedLine>) {
    let mut reader = std::io::BufReader::new(stdout);
    loop {
        match read_bounded_line(&mut reader, line_limit) {
            Ok(Some(line)) => {
                if tx.blocking_send(line).is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(BoundedLineError::Io(error)) => {
                tracing::warn!(error = %error, "engine stdout pump read failed");
                let _ = tx.blocking_send(PumpedLine::FramingError);
                return;
            }
            Err(_) => {
                let _ = tx.blocking_send(PumpedLine::FramingError);
                return;
            }
        }
    }
}

/// One newline-terminated line from a blocking reader, capped at `limit`
/// bytes with the same observable behavior as the line codec it replaces: a
/// partial final line at EOF is delivered, a trailing `\r` before the
/// newline is stripped, a longer line or invalid UTF-8 is `FramingError`,
/// and a clean EOF with nothing buffered is `None`.
fn read_bounded_line(
    reader: &mut impl std::io::BufRead,
    limit: usize,
) -> Result<Option<PumpedLine>, BoundedLineError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(BoundedLineError::Io(error)),
        };
        if available.is_empty() {
            // End of stream: an empty buffer ends the stream, a partial
            // final line is delivered the way the codec's EOF decode did.
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line_from_buffer(line)?))
            };
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(newline) => {
                if line.len() + newline > limit {
                    return Err(BoundedLineError::TooLong);
                }
                line.extend_from_slice(&available[..newline]);
                reader.consume(newline + 1);
                return Ok(Some(line_from_buffer(line)?));
            }
            None => {
                if line.len() + available.len() > limit {
                    return Err(BoundedLineError::TooLong);
                }
                line.extend_from_slice(available);
                let buffered = available.len();
                reader.consume(buffered);
            }
        }
    }
}

#[derive(Debug)]
enum BoundedLineError {
    TooLong,
    InvalidUtf8,
    Io(std::io::Error),
}

fn line_from_buffer(mut line: Vec<u8>) -> Result<PumpedLine, BoundedLineError> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    match String::from_utf8(line) {
        Ok(text) => Ok(PumpedLine::Line(text)),
        Err(_) => Err(BoundedLineError::InvalidUtf8),
    }
}

async fn handle_upstream_line(
    line: &str,
    pending: &mut HashMap<String, PendingRequest>,
    events: &broadcast::Sender<EngineEvent>,
    receive_ingress: &ReceiveIngress,
    receive_degraded: &mut bool,
) -> Result<(), EngineError> {
    let message: Value = serde_json::from_str(line).map_err(|_| EngineError::Protocol)?;
    let object = message.as_object().ok_or(EngineError::Protocol)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(EngineError::Protocol);
    }

    if let Some(method) = object.get("method").and_then(Value::as_str) {
        if object.contains_key("id") {
            return Err(EngineError::Protocol);
        }
        if method == "receive" {
            let params = object.get("params").ok_or(EngineError::Protocol)?;
            // Contract 1.165 §4.163: a decryption-error envelope (the
            // engine's structured report that an inbound envelope failed to
            // decrypt) never carries a message row, so the receive ladder
            // has nothing to project — the envelope routes to the
            // account-domain event lane instead (the watcher counts it in
            // the metrics snapshot and forwards the host frame). The
            // attribution discipline is the accountUnbound arm's: a
            // malformed or empty account carries no attributable identity
            // and falls back to the unknown-notification warning rather
            // than inventing one. No automatic reset action ever rides the
            // event — decryption failures self-heal through the engine's
            // DERM retry protocol.
            if params
                .get("envelope")
                .and_then(|envelope| envelope.get("identityChanged"))
                .is_some()
            {
                // 契约 §4.226：对端身份钥变更信封（engine
                // identity_changed_notification 投影，service/mod.rs:6539）。
                // 账号归因纪律同 decryptionError 臂：可归因才发事件，
                // 否则落 unknownNotification 警告。
                let attributed = params
                    .get("account")
                    .and_then(Value::as_str)
                    .filter(|account| !account.is_empty());
                if let Some(account) = attributed {
                    let source_uuid = params
                        .get("envelope")
                        .and_then(|envelope| envelope.get("sourceUuid"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let timestamp = params
                        .get("envelope")
                        .and_then(|envelope| envelope.get("timestamp"))
                        .and_then(Value::as_u64);
                    let _ = events.send(EngineEvent::ReceiveIdentityChanged {
                        account: account.to_string(),
                        source_uuid,
                        timestamp,
                    });
                } else {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
                return Ok(());
            }
            if params
                .get("envelope")
                .and_then(|envelope| envelope.get("decryptionError"))
                .is_some()
            {
                let attributed = params
                    .get("account")
                    .and_then(Value::as_str)
                    .filter(|account| !account.is_empty());
                if let Some(account) = attributed {
                    let _ = events.send(EngineEvent::ReceiveDecryptionError {
                        account: account.to_string(),
                    });
                } else {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
                return Ok(());
            }
            if let Some(normalized) = normalize_receive(params)? {
                match receive_ingress.enqueue(normalized).await? {
                    EnqueueOutcome::Enqueued => {
                        if *receive_degraded {
                            *receive_degraded = false;
                            tracing::info!(
                                state = "recovered",
                                "receive queue admission recovered"
                            );
                            let _ = events.send(EngineEvent::StorageChanged { state: "recovered" });
                        }
                    }
                    EnqueueOutcome::Dropped => {
                        // Storage is not draining the queue; drop the receive
                        // rather than park the actor. No payload or identity
                        // is logged. The persistence loop reports the
                        // underlying store failure on the same event; this
                        // transition covers a saturated queue whose head the
                        // store has not even failed on yet.
                        crate::metrics::record_receive_drop();
                        tracing::warn!("receive queue saturated; dropping a receive");
                        if !*receive_degraded {
                            *receive_degraded = true;
                            let _ = events.send(EngineEvent::StorageChanged {
                                state: "unavailable",
                            });
                        }
                    }
                }
            }
        } else if method == "connectionState" {
            let params = object.get("params");
            let account = params
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            let state = params
                .and_then(|params| params.get("state"))
                .and_then(Value::as_str)
                .filter(|state| !state.is_empty());
            let close_code = params
                .and_then(|params| params.get("closeCode"))
                .and_then(Value::as_u64)
                .map(|code| code as u16);
            if let (Some(account), Some(state)) = (account, state) {
                let _ = events.send(EngineEvent::ConnectionState {
                    account: account.to_string(),
                    state: state.to_string(),
                    close_code,
                });
            } else {
                let _ = events.send(EngineEvent::ProtocolWarning {
                    kind: "unknownNotification",
                });
            }
        } else if method == "accountUnbound" {
            // Contract 1.113 §4.94: the engine's unbound stop-ring (B4) pushes
            // a single `accountUnbound` notification when a 401 credential
            // rejection halts the receive loop — official linked-device
            // semantics, the account waits for a re-link instead of a
            // reconnect loop. The account-unlink watcher already consumes the
            // attributed event lane, so the notification replays onto
            // AccountUnauthorized with the account taken verbatim from
            // params. A malformed payload (missing params, missing, non-string
            // or empty account) carries no attributable identity and falls
            // back to the unknown-notification warning rather than inventing
            // an account.
            let attributed = object
                .get("params")
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            if let Some(account) = attributed {
                let _ = events.send(EngineEvent::AccountUnauthorized {
                    account: account.to_string(),
                });
            } else {
                let _ = events.send(EngineEvent::ProtocolWarning {
                    kind: "unknownNotification",
                });
            }
        } else if method == "receive.emptied" {
            // Contract 1.134 §4.117: the engine's history-queue-drained
            // notification (the official ApiEmptyQueue→EmptyEvent peer),
            // forwarded through the account-domain transient lane. The
            // attribution discipline is the accountUnbound arm's: a
            // malformed or empty account carries no attributable identity
            // and falls back to the unknown-notification warning rather
            // than inventing one; a well-formed account rides the event and
            // the watcher resolves it through the store (an unmatchable
            // account drops warn-only there — never silently forwarded).
            let attributed = object
                .get("params")
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            if let Some(account) = attributed {
                let _ = events.send(EngineEvent::ReceiveEmptied {
                    account: account.to_string(),
                });
            } else {
                let _ = events.send(EngineEvent::ProtocolWarning {
                    kind: "unknownNotification",
                });
            }
        } else if method == "receive.clockskew" {
            // Contract 1.134 §4.117: the engine's clock-skew alert
            // (edge-triggered, one alert per threshold crossing). `skewMs`
            // is the event's whole payload and fails closed — a missing or
            // non-numeric skew is a protocol error, not an unknown skew;
            // the signed value (positive = local clock fast) forwards
            // verbatim. `serverTimestamp` rides when the engine projected
            // it. The account attribution matches the receive.emptied arm.
            let params = object.get("params");
            let account = params
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            let skew_ms = params
                .and_then(|params| params.get("skewMs"))
                .and_then(Value::as_i64);
            match (account, skew_ms) {
                (Some(account), Some(skew_ms)) => {
                    let _ = events.send(EngineEvent::ReceiveClockSkew {
                        account: account.to_string(),
                        skew_ms,
                        server_timestamp: params
                            .and_then(|params| params.get("serverTimestamp"))
                            .and_then(Value::as_u64),
                    });
                }
                _ => {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
            }
        } else if method == "receive.conversationState" {
            // Contract 1.134 §4.117: the engine's conversation three-flag
            // inbound flips after a storage merge, forwarded through the
            // same account-domain lane. The `conversations` array is the
            // engine's projection verbatim — the connector is a pipe (the
            // owner red line: a passthrough structure error corrupts every
            // downstream consumer), so the array is carried and forwarded
            // as-is: no entry parsing, no trimming, sibling keys ride.
            // `overflow` is the engine's batch-cap tail marker, guaranteed
            // boolean by the engine contract; a non-array or empty
            // conversations face (the engine only notifies when the batch is
            // non-empty), a non-boolean overflow, or a missing account is a
            // protocol error and falls back to the unknown-notification
            // warning (never a guessed forward).
            let params = object.get("params");
            let account = params
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            let conversations = params
                .and_then(|params| params.get("conversations"))
                .filter(|value| value.is_array() && !value.as_array().unwrap().is_empty())
                .cloned();
            let overflow = params
                .and_then(|params| params.get("overflow"))
                .and_then(Value::as_bool);
            match (account, conversations, overflow) {
                (Some(account), Some(conversations), Some(overflow)) => {
                    let _ = events.send(EngineEvent::ConversationState {
                        account: account.to_string(),
                        conversations,
                        overflow,
                    });
                }
                _ => {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
            }
        } else if method == "engine.initialSyncComplete" {
            // Contract 1.220 §4.230: the engine's link-window
            // post-registration sync completion, forwarded through the same
            // account-domain lane. The parse guarantees the faces the engine
            // contract promises — the attribution account and the two
            // per-leg result bits — and a missing or wrong-typed face is a
            // protocol error answered by the unknown-notification warning,
            // never a guessed forward. The attribution discipline is the
            // storagePull arm's.
            let params = object.get("params");
            let account = params
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            let manifest_ok = params
                .and_then(|params| params.get("manifestOk"))
                .and_then(Value::as_bool);
            let profiles_ok = params
                .and_then(|params| params.get("profilesOk"))
                .and_then(Value::as_bool);
            match (account, manifest_ok, profiles_ok) {
                (Some(account), Some(manifest_ok), Some(profiles_ok)) => {
                    let _ = events.send(EngineEvent::InitialSyncComplete {
                        account: account.to_string(),
                        manifest_ok,
                        profiles_ok,
                    });
                }
                _ => {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
            }
        } else if method == "engine.sessionReset" {
            // Contract 1.267 §4.251 (batch Z12, S15): the engine's two-word
            // session-reset projection, forwarded through the same
            // account-domain lane. The parse pins the closed word list
            // (endSession | chatSessionRefresh) and the attribution faces;
            // a missing or wrong-typed face is a protocol error answered by
            // the unknown-notification warning, never a guessed forward.
            let params = object.get("params");
            let account = params
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            let peer_aci = params
                .and_then(|params| params.get("peerAci"))
                .and_then(Value::as_str)
                .filter(|peer| !peer.is_empty());
            let word = params
                .and_then(|params| params.get("word"))
                .and_then(Value::as_str)
                .filter(|word| *word == "endSession" || *word == "chatSessionRefresh");
            // sentAt = additive absent discipline (engine commit eba82d3
            // contract note): the endSession arm always carries it; the
            // chatSessionRefresh arm omits the whole key when the send-side
            // client timestamp is unknown — absence is a valid face, the
            // row clock degrades to the local one (the identityChanged
            // template), never a dropped event.
            let sent_at = params
                .and_then(|params| params.get("sentAt"))
                .and_then(Value::as_u64);
            match (account, peer_aci, word) {
                (Some(account), Some(peer_aci), Some(word)) => {
                    let _ = events.send(EngineEvent::SessionReset {
                        account: account.to_string(),
                        peer_aci: peer_aci.to_string(),
                        word: word.to_string(),
                        sent_at,
                    });
                }
                _ => {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
            }
        } else if method == "engine.storagePull" {
            // Contract 1.141 §4.137: the engine's storage-manifest pull
            // outcome event, forwarded through the same account-domain lane.
            // The parse guarantees the faces the engine contract promises —
            // the attribution account, the `trigger` word (a string whose
            // VALUE domain is deliberately unlocked: an engine trigger this
            // connector has not seen forwards verbatim, never guessed into a
            // known one), and the two per-family result bits — and a missing
            // or wrong-typed face is a protocol error answered by the
            // unknown-notification warning, never a guessed forward.
            let params = object.get("params");
            let account = params
                .and_then(|params| params.get("account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty());
            let trigger = params
                .and_then(|params| params.get("trigger"))
                .and_then(Value::as_str)
                .filter(|trigger| !trigger.is_empty());
            let contacts_ok = params
                .and_then(|params| params.get("contactsOk"))
                .and_then(Value::as_bool);
            let groups_ok = params
                .and_then(|params| params.get("groupsOk"))
                .and_then(Value::as_bool);
            match (account, trigger, contacts_ok, groups_ok) {
                (Some(account), Some(trigger), Some(contacts_ok), Some(groups_ok)) => {
                    let _ = events.send(EngineEvent::StoragePull {
                        account: account.to_string(),
                        trigger: trigger.to_string(),
                        contacts_ok,
                        groups_ok,
                    });
                }
                _ => {
                    let _ = events.send(EngineEvent::ProtocolWarning {
                        kind: "unknownNotification",
                    });
                }
            }
        } else {
            let _ = events.send(EngineEvent::ProtocolWarning {
                kind: "unknownNotification",
            });
        }
        return Ok(());
    }

    // A response without a string `id` is not fatal. Two real shapes reach
    // here: (a) the engine's own -32700 parse-error answer to an over-long
    // inbound frame, which carries `"id": null` by JSON-RPC convention; (b) a
    // malformed-but-valid-JSON line. Treating either as `EngineError::Protocol`
    // faults the whole engine (the read loop's `Err` arm) and collapses every
    // in-flight mutating request into `UnknownOutcome` — the 2026-10-19 4.4MB
    // video incident: the engine kept running, the connector killed it. A
    // single unroutable line must degrade to a warning; the request it might
    // have answered is settled by its own bounded timeout, never by killing
    // the engine.
    let Some(id) = object.get("id").and_then(Value::as_str) else {
        let _ = events.send(EngineEvent::ProtocolWarning {
            kind: "responseWithoutId",
        });
        return Ok(());
    };
    let Some(request) = pending.remove(id) else {
        let _ = events.send(EngineEvent::ProtocolWarning {
            kind: "unknownOrDuplicateResponseId",
        });
        return Ok(());
    };
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        let error = match request.class {
            CallClass::ReadOnly => EngineError::Protocol,
            CallClass::Mutating => EngineError::UnknownOutcome,
        };
        let _ = request.response.send(Err(error));
        return Err(EngineError::Protocol);
    }
    if has_error {
        if upstream_error_is_unauthorized(object.get("error"))
            || upstream_error_is_credential_invalid(object.get("error"))
        {
            if let Some(account) = &request.account {
                let _ = events.send(EngineEvent::AccountUnauthorized {
                    account: account.clone(),
                });
            }
            let _ = request.response.send(Err(EngineError::Unauthorized));
        } else if let Some(class) = upstream_error_send_class(object.get("error")) {
            // Contract 1.99 §4.80: the send-chain transport families (rate
            // limit, proof challenge, server unavailability) surface as
            // distinct error variants. No event: a transport failure never
            // touches account state. The arm sits after the authorization
            // classification and before the structured-code ladder — the
            // two cannot collide (an embedded anchor in a longer message
            // vs. an exact allowlist literal), so the order only documents
            // that the §4.17 recovery chain keeps precedence.
            let _ = request.response.send(Err(class));
        } else if let Some(code) = upstream_error_code(object.get("error")) {
            // Contract 1.36 faces: the engine answers structured errors with
            // a code field (STICKER_*, STORAGE_*, CONVERSATION_NOT_RESOLVED
            // families). The code is a fixed engine literal, carried as such;
            // unrecognized codes degrade to the plain upstream error so an
            // engine newer than this connector never invents host codes.
            // Contract 1.50: the engine's error.data object (structured
            // facts such as PROFILE_UPLOAD_FAILED's {retryable, textSaved})
            // rides along verbatim when present — pass-through only, no
            // key invention, no stripping.
            let data = object
                .get("error")
                .and_then(|error| error.get("data"))
                .filter(|data| data.is_object())
                .cloned();
            let _ = request
                .response
                .send(Err(EngineError::UpstreamCode { code, data }));
        } else {
            // Contract 1.167 §4.165: the frozen anchor set did not classify;
            // the embedded cause-class literal — if the message carries a
            // class-shaped one — rides the error log-only (bounded) so the
            // field can attribute the failure; the wire answer stays the
            // plain upstream face.
            let error_object = object.get("error");
            let cause = upstream_error_cause(error_object);
            let code = error_object
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64);
            let _ = request
                .response
                .send(Err(EngineError::Upstream { cause, code }));
        }
    } else {
        let result = object.get("result").cloned().unwrap_or(Value::Null);
        let _ = request.response.send(Ok(result));
    }
    Ok(())
}

/// signal-cli wraps transport failures as UnexpectedErrorException whose
/// message embeds the upstream cause class. A device unlinked on the phone
/// (contract 1.21) surfaces as AuthorizationFailedException / "Authorization
/// failed!" on the next network call, and this is the single observation
/// point that still sees the raw upstream error body — everything above the
/// engine boundary stays content-free. A local-only failure (e.g. listAccounts
/// never touches the network) cannot match, so the classification is safe to
/// trust as "the server rejected this device's credentials".
/// Upstream (signal-cli JSON-RPC) error shapes that mean the LOCAL account's
/// linked-device credential is dead — classified `EngineError::Unauthorized`
/// and attributed to the request's account (contract 1.21 §4.17). Two
/// surfaces, one root cause:
///
/// 1. live authorization failure: upstream wraps `AuthorizationFailedException`
///    in an UnexpectedErrorException (-32603) ("Authorization failed!").
/// 2. post-mortem short-circuit: after the first authorization failure
///    signal-cli persists `registered=false` (signal-cli
///    `AccountHelper.java:119`) and every later account-scoped command fails
///    LOCALLY with `UserErrorException("User <account> is not registered.")`
///    (`App.java:342` wrapping `NotRegisteredException`) before any network
///    call — the 0-17 ms instant-failure form. Matched by the strict prefix/
///    suffix pair; the recipient-level "The user <id> is not registered."
///    (unblock/updateContact/sendPoll* family) starts "The user " and must
///    NOT mark the account unlinked.
fn upstream_error_is_unauthorized(error: Option<&Value>) -> bool {
    error
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .is_some_and(|message| {
            message.contains("AuthorizationFailedException")
                || message.contains("Authorization failed")
                || (message.starts_with("User ") && message.ends_with(" is not registered."))
        })
}

/// The Signal chat service answers a dead linked-device credential with HTTP
/// 401 whose body is this exact plain-text sentence — never a JSON error
/// object, so the structural and exception-name matchers above cannot see it.
/// Contract 1.101 §4.82: matched as a standalone pure addition beside the
/// frozen §4.17 match set (the §4.80 boundary note applies verbatim), folding
/// into the same `EngineError::Unauthorized` arm — the credential is dead and
/// the recovery is the same relink.
const ENGINE_CREDENTIALS_401_BODY_ANCHOR: &str =
    "Credentials are required to access this resource.";

/// The raw 401-body anchor matcher (contract 1.101 §4.82): `true` when the
/// upstream error `message` carries the chat service's plain-text
/// credentials-required sentence. Deliberately narrow — one exact sentence,
/// case-sensitive — so incidental text (a recipient-level message, a storage
/// family code, a transport anchor) can never flip an account's state. The
/// engine contract at this revision folds credential death into the unbound
/// message the §4.17 matcher already answers; this matcher is the additive
/// net for faces that carry the upstream body verbatim.
fn upstream_error_is_credential_invalid(error: Option<&Value>) -> bool {
    error
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains(ENGINE_CREDENTIALS_401_BODY_ANCHOR))
}

/// Contract 1.99 §4.80 send-chain transport anchors (joined by the 1.114
/// §4.95 identity anchor): the engine folds a transport-layer send failure
/// into the plain internal_error JSON-RPC face (-32603) whose `message`
/// embeds the cause class. These fixed literals — supplied by the engine
/// contract verbatim, matched exactly — classify the family at this single
/// observation point, the same place the authorization matcher above reads
/// the raw upstream error body. Deliberately constants beside, not inside,
/// the authorization matcher: that matcher is a fragile route (strict
/// prefixes/suffixes tuned per message form) and its match set must not grow
/// to absorb transport families.
const ENGINE_SEND_RATE_LIMITED_ANCHOR: &str = "(RateLimitExceeded)";
const ENGINE_SEND_PROOF_REQUIRED_ANCHOR: &str = "(ProofRequiredException)";
const ENGINE_SEND_SERVER_UNAVAILABLE_ANCHOR: &str = "(ServerUnavailableException)";
const ENGINE_SEND_IDENTITY_UNVERIFIED_ANCHOR: &str = "(UntrustedIdentityException)";

/// Classify a send-chain error (contract 1.99 §4.80, joined by the 1.114
/// §4.95 identity gate) from the raw JSON-RPC error body: `Some` variant when
/// the error `message` embeds one of the fixed anchors, `None` otherwise. The
/// anchors are parenthesized exception names the engine emits verbatim, so a
/// substring match cannot pick up incidental text; a message is only ever
/// classified, never surfaced. This is a standalone pure function — it shares
/// no match set with [`upstream_error_is_unauthorized`], whose
/// `AccountUnauthorized` → `ACCOUNT_UNLINKED` chain keeps head-of-line
/// precedence at the call site.
fn upstream_error_send_class(error: Option<&Value>) -> Option<EngineError> {
    let error = error?;
    let message = error.get("message").and_then(Value::as_str)?;
    if message.contains(ENGINE_SEND_RATE_LIMITED_ANCHOR) {
        // 契约 §4.222：data.retryAfterSecs 随分类一并带回（服务端 429/413
        // 的等待秒数），宿主据此按服务端窗口等待，而非固定 60 秒撞限流。
        let retry_after_secs = error
            .get("data")
            .and_then(|data| data.get("retryAfterSecs"))
            .and_then(Value::as_u64);
        Some(EngineError::RateLimited { retry_after_secs })
    } else if message.contains(ENGINE_SEND_PROOF_REQUIRED_ANCHOR) {
        Some(EngineError::ProofRequired)
    } else if message.contains(ENGINE_SEND_SERVER_UNAVAILABLE_ANCHOR) {
        Some(EngineError::ServerUnavailable)
    } else if message.contains(ENGINE_SEND_IDENTITY_UNVERIFIED_ANCHOR) {
        Some(EngineError::IdentityUnverified)
    } else {
        None
    }
}

/// Contract 1.167 §4.165: the generic upstream face's bounded cause literal.
/// When the frozen §4.80/§4.95 anchor set leaves a JSON-RPC error
/// unclassified, the tailmost parenthesized class-name token in the error
/// `message` is surfaced log-only instead of being lost with the raw error
/// body — the official desktop behavior of carrying a send failure's cause
/// name. The shape gate mirrors the anchor family: a letter-led
/// `[A-Za-z0-9._]` token, so message text, phone numbers, contact data, and
/// digit-led timestamps cannot ride the field — a fixed engine class
/// literal, never user data. The value is bounded to 120 bytes including
/// the parenthesized wrapper (oversize truncates; the gate is ASCII-only,
/// so the slice stays on a char boundary). Missing, non-string, and
/// shape-hostile messages answer `None` and keep the pre-1.167 log shape.
fn upstream_error_cause(error: Option<&Value>) -> Option<String> {
    const ENGINE_ERROR_CAUSE_MAX_BYTES: usize = 120;
    let message = error?.get("message").and_then(Value::as_str)?;
    let mut rest = message;
    let mut cause: Option<&str> = None;
    while let Some(open) = rest.find('(') {
        let tail = &rest[open + 1..];
        let Some(close) = tail.find(')') else {
            break;
        };
        let inner = &tail[..close];
        let letter_led = matches!(inner.chars().next(), Some(first) if first.is_ascii_alphabetic());
        if letter_led
            && inner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
        {
            // The tailmost qualifying token wins: the contract pins the
            // cause class at the message tail.
            cause = Some(inner);
        }
        rest = tail;
    }
    let literal = cause?;
    let cap = ENGINE_ERROR_CAUSE_MAX_BYTES.saturating_sub(2);
    Some(format!("({})", &literal[..literal.len().min(cap)]))
}

/// Known engine error codes the connector maps onto structured host errors
/// (contract 1.36, §4.32/§4.33). The allowlist is the whole mapping surface:
/// an engine code outside it degrades to the plain upstream error, so the
/// host never sees a code this connector's schema does not declare, and a
/// future engine adding codes cannot silently widen the host contract.
const ENGINE_STRUCTURED_ERROR_CODES: &[&str] = &[
    // §4.32 sticker pack browsing (engine-owned: key check, CDN fetch,
    // decrypt/decode, image size budget).
    "STICKER_PACK_KEY_INVALID",
    "STICKER_PACK_FETCH_FAILED",
    "STICKER_PACK_MALFORMED",
    "STICKER_IMAGE_TOO_LARGE",
    // §4.47 avatar download (contract 1.48, engine alignment batch ③a:
    // honest no-avatar, download/decrypt failure, the 10 MiB decoded cap).
    "AVATAR_UNAVAILABLE",
    "AVATAR_FETCH_FAILED",
    "AVATAR_TOO_LARGE",
    // §4.33 conversation pin sync (engine-owned: cloud reference resolution,
    // storage-service failures surface under the engine's STORAGE_* family).
    "CONVERSATION_NOT_RESOLVED",
    "STORAGE_UNAVAILABLE",
    "STORAGE_WRITE_FAILED",
    "STORAGE_READ_FAILED",
    // §4.46 Android local-backup export (engine backup-export-contract
    // §10.7): the start-ladder and task-failure codes. ALREADY_RUNNING is
    // deliberately not retryable — the desktop polls backups.exportStatus
    // instead of re-starting; SNAPSHOT_EXISTS/IO_FAILED are transient disk
    // races/failures the desktop may retry after the connector clears.
    "BACKUP_EXPORT_ALREADY_RUNNING",
    "BACKUP_ARTIFACT_MISSING",
    "BACKUP_ARTIFACT_INVALID",
    "BACKUP_SNAPSHOT_EXISTS",
    "BACKUP_IO_FAILED",
    // §4.68 official-desktop snapshot import (engine backup contract): the
    // import-task faces. MISSING/METADATA_INVALID/KEY_MISMATCH and
    // ALREADY_RUNNING are deterministic answers (fix the path, check the
    // account, poll the status face); IO_FAILED is a transient disk
    // condition the caller may retry after the filesystem recovers.
    "BACKUP_IMPORT_ALREADY_RUNNING",
    "BACKUP_SNAPSHOT_MISSING",
    "BACKUP_SNAPSHOT_METADATA_INVALID",
    "BACKUP_SNAPSHOT_KEY_MISMATCH",
    "BACKUP_SNAPSHOT_IO_FAILED",
    // §4.69 cloud-backup restore passthrough (contract 1.83, engine
    // cloud-backup-contract §2): the seven-family `CloudRestoreError::rpc_code`
    // table, one mapping source engine-side, mirrored verbatim here.
    // NOT_PROVISIONED (never enabled cloud backups), AUTH_FAILED, and RUNNING
    // (the engine's own re-entry gate — poll backups.cloudStatus instead) are
    // deterministic refusals; TRANSPORT/DOWNLOAD may succeed on a later
    // attempt; DECRYPT/EXPORT are terminal. The four message-carrying
    // families ride the engine's `data.detail` verbatim (the promised
    // contract face — see the service-layer mapping).
    "BACKUP_NOT_PROVISIONED",
    "BACKUP_AUTH_FAILED",
    "BACKUP_RUNNING",
    "BACKUP_TRANSPORT_FAILED",
    "BACKUP_DOWNLOAD_FAILED",
    "BACKUP_DECRYPT_FAILED",
    "BACKUP_EXPORT_FAILED",
    // §4.72 cloud-backup upload passthrough (contract 1.87, engine
    // cloud-backup-contract §6.2): the two code positions the upload face
    // adds over the restore table, mirrored verbatim from the engine's
    // `CloudUploadError::rpc_code` single mapping source.
    // UPLOAD_ALREADY_RUNNING is the engine's process-wide single-slot
    // re-entry gate (poll backups.uploadStatus instead of re-starting), a
    // deterministic content-free refusal; UPLOAD_FAILED is the CDN uplink
    // message family (non-2xx / cdn≠3 / over-cap / uplink read failure) —
    // retryable=true, but a retry is always the caller's fresh
    // backups.uploadToCloud (a new form, a new artifact), never an
    // automatic retry of an unknown-outcome POST. The six codes the upload
    // face shares with restore/export stay registered at their original
    // sites above; the upload face's per-face divergence (BACKUP_IO_FAILED
    // retryable=false + detail, the transport family's upload message
    // text) is mapped at the upload call site — see service.rs
    // `cloud_upload_face_error`.
    "BACKUP_UPLOAD_ALREADY_RUNNING",
    "BACKUP_UPLOAD_FAILED",
    // §4.66 username write face (contract 1.75, engine username write-face
    // batch): the reserve/confirm/delete server-state ladder. TAKEN and
    // RESERVATION_GONE are deterministic refusals (a new name / a fresh
    // reserve is the only way forward); RATE_LIMITED and SERVER_FAILED may
    // succeed on a later attempt. The honest partial-success family rides
    // the STORAGE_* codes already above (the server confirmed but the
    // storage write failed).
    "USERNAME_TAKEN",
    "USERNAME_RESERVATION_GONE",
    "USERNAME_RATE_LIMITED",
    "USERNAME_SERVER_FAILED",
    // §4.48 report spam (engine-owned: the upstream report API refused the
    // batch — every id's serverGuid was rejected).
    "REPORT_SPAM_FAILED",
    // §4.45 profile write partial-success face (engine alignment batch ②):
    // the text face landed but the avatar upload chain failed; the engine's
    // data object carries {retryable, textSaved} verbatim (contract 1.50).
    "PROFILE_UPLOAD_FAILED",
    // §4.44 group-avatar upload partial-success face (contract 1.89, the
    // parallel engine group-avatar byte-face batch): the group change landed
    // but the avatar upload chain failed; the engine's data object carries
    // {retryable, textSaved} verbatim — the PROFILE_UPLOAD_FAILED shape,
    // group-faced.
    "GROUP_AVATAR_UPLOAD_FAILED",
    // §4.96 group-update write face (contract 1.115, the updateGroup/quit
    // wiring batch): the engine's server-rejection answer for the wired
    // updateGroup route — the change broadcast (title/member/link-access/
    // avatar) was refused by the Signal server. The `data.status?` rides
    // verbatim (the CALL_CREDENTIALS_FAILED channel); retryable=false —
    // a 409 revision race unblocks only after re-reading the group state.
    "GROUP_UPDATE_FAILED",
    // §4.98 group invite-link faces (contract 1.117, the link-family wiring
    // batch): UNAVAILABLE is the build face's server-rejection / link-not-set
    // family (the group has no invite link, or the server refused the read —
    // the engine's data.status? rides the CALL_CREDENTIALS_FAILED channel;
    // retryable=false — the same group state answers the same way);
    // PREVIEW_FAILED is the preview face's server-rejection family with the
    // same data.status? pass-through (retryable=false — deterministic). The
    // join/cancel writes fold their server rejections under the 1.115
    // GROUP_UPDATE_FAILED code already above.
    "GROUP_INVITE_LINK_UNAVAILABLE",
    "GROUP_INVITE_LINK_PREVIEW_FAILED",
    // §4.73 call-link credential material faces (contract 1.88, engine
    // a3ae39b, P4c slice 1 — the registration the engine's compat §3 calls
    // rows assign to this connector batch): FAILED is the server-rejection /
    // zkgroup-verification / day-credential-absent family with the engine's
    // `data.status?` honest HTTP pass-through (retryable=false — the same
    // material fails the same way); UNAVAILABLE is the network/transport
    // family (retryable=true — a later attempt may reach the server).
    "CALL_CREDENTIALS_FAILED",
    "CALL_CREDENTIALS_UNAVAILABLE",
    // §4.103 device-plane faces (contract 1.122, engine 窗D B13
    // getDevices/unlinkDevice): FAILED is the server-rejection family (the
    // GET/DELETE v1/devices call was refused upstream) with the engine's
    // `data.status?` honest HTTP pass-through riding the CALL_CREDENTIALS_
    // FAILED channel; retryable=false — the same server state refuses the
    // same way. UNAVAILABLE is the network/transport family; retryable=true —
    // a later attempt may reach the server.
    "DEVICES_FAILED",
    "DEVICES_UNAVAILABLE",
    // §4.104 group migration (contract 1.123, engine B8 migrateGroup): the
    // server-rejection family for the GV1→GV2 migration route with the
    // engine's `data.status?` honest HTTP pass-through (the CALL_CREDENTIALS_
    // FAILED channel); retryable=false — the same group state refuses the
    // same way, and a 409 race unblocks only after re-reading the group
    // state. The avatar partial-success family rides GROUP_AVATAR_UPLOAD_
    // FAILED and the transport family rides STORAGE_UNAVAILABLE, both
    // registered above.
    "GROUP_MIGRATION_FAILED",
    // §4.107 group create (contract 1.126, engine createGroup): the
    // server-rejection family for the new-group route with the engine's
    // `data.status?` honest HTTP pass-through (the CALL_CREDENTIALS_
    // FAILED channel); retryable=false — the same group state refuses the
    // same way. The avatar partial-success family rides GROUP_AVATAR_
    // UPLOAD_FAILED and the transport family rides STORAGE_UNAVAILABLE,
    // both registered above.
    "GROUP_CREATE_FAILED",
    // §4.162 phone lookup (contract 1.164, engine d088a59 phoneLookup): the
    // CDSI read faces. INVALID is the engine's deterministic E.164 grammar
    // refusal (the same shape never resolves; the connector mirrors the
    // grammar locally, so the arm is a drift net, not the working path) —
    // retryable=false. RATE_LIMITED carries the engine's promised
    // {retryAfterSeconds} backoff fact verbatim; retryable=true on the
    // USERNAME_RATE_LIMITED channel — a later attempt may succeed, the wait
    // is the caller's, and nothing retries automatically. SERVER_FAILED is
    // the remaining server/connection family, details withheld by the
    // engine — retryable=true, the same may-succeed-later channel.
    "PHONE_INVALID",
    "PHONE_RATE_LIMITED",
    "PHONE_SERVER_FAILED",
];

/// Extract a known structured engine error code from a JSON-RPC error object.
/// The real engine carries the literal in `message` with a numeric `code`
/// (-1; JSON-RPC 2.0 keeps error codes numeric), e.g. `{"code": -1,
/// "message": "STICKER_PACK_KEY_INVALID"}`. A string `code` field carrying
/// the literal is accepted as a fallback. The literal must match the
/// allowlist exactly; anything else (missing fields, unknown literals)
/// answers `None` and the caller falls back to the plain upstream error.
fn upstream_error_code(error: Option<&Value>) -> Option<&'static str> {
    let error = error?;
    let candidates = [
        error.get("message").and_then(Value::as_str),
        error.get("code").and_then(Value::as_str),
    ];
    for literal in candidates.into_iter().flatten() {
        if let Some(known) = ENGINE_STRUCTURED_ERROR_CODES
            .iter()
            .find(|known| **known == literal)
        {
            return Some(known);
        }
    }
    None
}

/// Test-only re-export of the allowlist so the service-layer mapping test can
/// prove the two sides stay total over the same set (the constant itself
/// stays private in normal builds).
#[cfg(test)]
pub(crate) const ENGINE_STRUCTURED_ERROR_CODES_FOR_TESTS: &[&str] = ENGINE_STRUCTURED_ERROR_CODES;

fn envelope_peer_source(envelope: &serde_json::Map<String, Value>) -> Option<String> {
    envelope
        .get("source")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            envelope
                .get("sourceNumber")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| {
            envelope
                .get("sourceUuid")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

fn data_message_group_id(message: &serde_json::Map<String, Value>) -> Option<String> {
    message
        .get("groupInfo")
        .and_then(|info| info.get("groupId"))
        .or_else(|| message.get("groupId"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The `syncMessage.messageRequestResponse` face (contract 1.70, §4.58
/// consume batch). The official desktop anchors: `SignalService.proto:865`
/// (SyncMessage.content oneof member 14), `:666-678` (the MessageRequestResponse
/// record: `threadAci` = the thread's ServiceId UUID string, `groupId` = the
/// 32-byte group master key's standard base64, `type` = the numbered enum
/// UNKNOWN=0 / ACCEPT=1 / DELETE=2 / BLOCK=3 / BLOCK_AND_DELETE=4 / SPAM=5 /
/// BLOCK_AND_SPAM=6), and the consumer's shape gates (`MessageReceiver
/// .preload.ts:3274-3309` — `GROUPV2_ID_LENGTH = 32`, the UUID shape, and
/// `isKnownProtoEnumMember` forcing an out-of-enum `type` to UNKNOWN).
///
/// The projection returns the parsed face only when the envelope carries a
/// well-formed one — a hostile or foreign shape (bad UUID / bad base64 /
/// wrong byte length / a `type` outside 1..=6 / neither or both thread legs)
/// fails closed here and the envelope falls through to the plain skip arm,
/// exactly like every other gateless drop (宁缺勿错). A `type` of UNKNOWN
/// (0, the enum default) carries no session-actionable information, so it is
/// dropped as skip rather than stamped: the desktop consumes the same face
/// only for the known member values.
fn normalized_message_request_response(
    face: &serde_json::Map<String, Value>,
) -> Option<ControlReceive> {
    let response_type = face
        .get("messageRequestResponseType")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| (1..=MRR_RESPONSE_TYPE_MAX).contains(value))?;
    let thread_aci = face.get("threadAci").and_then(Value::as_str);
    let group_id = face.get("groupId").and_then(Value::as_str);
    // The proto oneof: exactly one of the two thread legs. A shape carrying
    // neither, both, or a malformed leg is not the protocol's — dropped.
    let resolved = match (thread_aci, group_id) {
        (Some(aci), None) => {
            let aci = aci.trim();
            if !is_service_id_uuid(aci) {
                return None;
            }
            (Some(aci.to_string()), None)
        }
        (None, Some(group)) => {
            let group = group.trim();
            let mut decoded = Vec::new();
            crate::service::base64_decode_to_vec(group, &mut decoded).ok()?;
            if decoded.len() != GROUPV2_ID_LENGTH {
                return None;
            }
            (None, Some(group.to_string()))
        }
        _ => return None,
    };
    Some(ControlReceive::MessageRequestResponse {
        response_type,
        thread_aci: resolved.0,
        group_id: resolved.1,
        // Contract 1.258 (§4.58 additive): the sync-moment key rides when the
        // engine projected it and reads as absent otherwise (pre-1.258
        // engines) or when malformed (an additive key never fails the face).
        timestamp: face.get("timestamp").and_then(Value::as_u64),
    })
}

/// Bounded `syncMessage.read[]` / `.viewed[]` entry family (contract 1.100,
/// §4.81): the wire entry is `{senderUuid, senderNumber?, timestamp}` — the
/// engine projects the (senderAci, timestamp) pair the official entries
/// carry, plus the contacts-resolved number when its cache had one. The
/// identity caps mirror the receive id family, the per-face cap mirrors the
/// receipt batch; an entry without a sender or a positive timestamp drops
/// (宁缺勿错 — the engine already drops unparseable ones, so what survives
/// here is the bounds family's own guard).
fn normalized_sync_read_entries(value: Option<&Value>) -> Vec<SyncReadEntry> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .take(MAX_SYNC_READ_ENTRIES)
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let sender_uuid = object
                .get("senderUuid")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
            let timestamp = object
                .get("timestamp")
                .and_then(Value::as_u64)
                .filter(|timestamp| *timestamp > 0)?;
            let sender_number = object
                .get("senderNumber")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
            Some(SyncReadEntry {
                sender_uuid,
                sender_number,
                timestamp,
            })
        })
        .collect()
}

/// Bounded `syncMessage.attachmentBackfillResponse` face (contract revision
/// 1.175, §4.175; entry states 1.193, §4.193; `longText` state 1.195,
/// §4.195): the engine's projection of the official backfill response. The
/// parse is all-or-nothing on the target (author + positive sent stamp +
/// exactly one conversation leg — the official strictAssert-drop posture; a
/// malformed target answers None so the envelope keeps the plain
/// syncMessage skip, 宁缺勿错). The data face parses leniently per entry:
/// the error arm rides its bounded word; the attachments arm keeps index
/// alignment, and every entry keeps its official variant
/// ([`BackfillEntry`]) — the pointer face with or without locator material,
/// the `PENDING`/`TERMINAL_ERROR` status words, and an unparseable entry
/// converged to `Status(Unknown)` (never a shifted row). The sibling
/// `longText` entry (the official `response.longText` arm,
/// attachmentBackfill.preload.ts:247-283) parses through the same helper
/// into `long_text`; it never joins `entries` because KT long-text bodies
/// ride the row's text column, so no body-attachment slot exists and the
/// index-equals-position contract stays intact.
fn normalized_sync_attachment_backfill_response(
    value: Option<&Value>,
) -> Option<SyncAttachmentBackfillResponse> {
    const MAX_BACKFILL_ERROR_WORD_CHARS: usize = 64;
    let face = value?.as_object()?;
    let target_message = face.get("targetMessage")?.as_object()?;
    let author = target_message
        .get("author")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
    let sent_timestamp = target_message
        .get("sentTimestamp")
        .and_then(Value::as_u64)
        .filter(|timestamp| *timestamp > 0)?;
    let conversation = face.get("targetConversation")?.as_object()?;
    let bounded_identity = |key: &str| {
        conversation
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())
    };
    let conversation_service_id = bounded_identity("serviceId");
    let conversation_group_id = bounded_identity("groupId");
    let conversation_e164 = bounded_identity("e164");
    if conversation_service_id.is_none()
        && conversation_group_id.is_none()
        && conversation_e164.is_none()
    {
        return None;
    }
    if let Some(error) = face.get("error").and_then(Value::as_str) {
        return Some(SyncAttachmentBackfillResponse {
            author,
            sent_timestamp,
            conversation_service_id,
            conversation_group_id,
            conversation_e164,
            error: Some(
                error
                    .chars()
                    .take(MAX_BACKFILL_ERROR_WORD_CHARS)
                    .collect::<String>(),
            ),
            entries: Vec::new(),
            // The error arm carries no data face — the engine emits no
            // `longText` beside an `error` word, and the settled event never
            // fires on this arm (§4.192).
            long_text: None,
        });
    }
    let entries = face
        .get("attachments")
        .and_then(Value::as_array)?
        .iter()
        .take(MAX_INBOUND_ATTACHMENTS)
        .map(normalized_backfill_entry)
        .collect();
    // An explicit JSON null is absence, not an unparseable entry: the engine
    // omits the key when the phone sent no long-text body.
    let long_text = face
        .get("longText")
        .filter(|value| !value.is_null())
        .map(normalized_backfill_entry);
    Some(SyncAttachmentBackfillResponse {
        author,
        sent_timestamp,
        conversation_service_id,
        conversation_group_id,
        conversation_e164,
        error: None,
        entries,
        long_text,
    })
}

/// One index-aligned backfill entry (contract 1.193, §4.193): the engine
/// projects the official `AttachmentData` oneof as `{status: "<WORD>"}` or
/// `{attachment: {...}}` (kt-signal-engine `project_attachment_backfill_response`,
/// `src/service/mod.rs:9602-9703`). The split is what the desktop acts on —
/// a pointer merges CDN material, `PENDING` waits, `TERMINAL_ERROR` errors
/// the attachment (attachmentBackfill.preload.ts:291-303) — so the parse
/// never folds the two arms together. An entry outside the projection's
/// shape (non-object, an `attachment` that is not an object, or no
/// `status`/`attachment` key at all) converges to `Status(Unknown)`: the
/// official `missingCaseError` crash is not a face KT copies, and the
/// settle event maps `Unknown` to `pending` (the non-crash convergence).
fn normalized_backfill_entry(entry: &Value) -> BackfillEntry {
    let Some(object) = entry.as_object() else {
        return BackfillEntry::Status(BackfillStatus::Unknown);
    };
    if let Some(attachment) = object.get("attachment") {
        return match attachment.as_object() {
            Some(attachment) => {
                BackfillEntry::Locator(attachment.get("locator").and_then(normalized_locator_face))
            }
            None => BackfillEntry::Status(BackfillStatus::Unknown),
        };
    }
    let status = match object.get("status").and_then(Value::as_str) {
        Some("PENDING") => BackfillStatus::Pending,
        Some("TERMINAL_ERROR") => BackfillStatus::Terminal,
        _ => BackfillStatus::Unknown,
    };
    BackfillEntry::Status(status)
}

/// Bounded `syncMessage.deleteForMe` projection family (contract 1.102,
/// §4.83; extended 1.182, §4.182; attachment arm 1.196, §4.196): the wire
/// shape mirrors the official DeleteForMe face —
/// `{messageDeletes: [{conversationId?, messages: [{author, timestamp}]}],
/// conversationDeletes: [{conversationId, isFullDelete,
/// mostRecentMessages, mostRecentNonExpiringMessages}],
/// localOnlyConversationDeletes: [{conversationId}],
/// attachmentDeletes: [{conversationId, targetMessage: {author,
/// timestamp}, clientUuid?, fallbackDigest?, fallbackPlaintextHash?}]}` —
/// and the engine projects all four consumer-facing arms. The identity caps
/// mirror the
/// receive id family, the group/message caps the read-face batch guard; an
/// entry without an author or a positive timestamp drops (the engine
/// projects 0 for an unstated stamp — the read face's unknown-marker
/// discipline), a group whose entries all drop drops whole, and a face with
/// no usable arm at all answers empty (the plain syncMessage skip —
/// 宁缺勿错; the engine already dropped its own unparseable entries, so
/// what survives here is the bounds family's own guard).
///
/// The two conversation arms (1.182) carry the official sending-side
/// gates: a `conversationDeletes` entry without a conversation identity or
/// with every `mostRecentMessages` anchor failing the entry bounds drops
/// (the official MessageReceiver.preload.ts:3662-3681 warn-drop pair —
/// "No target conversation" / "No target messages"), while the
/// `mostRecentNonExpiringMessages` companion is optional and may honestly
/// be empty (the official consumer falls back to it only when the primary
/// anchor set matched nothing). A `localOnlyConversationDeletes` entry only
/// needs its conversation identity (:3703-3711 — "No target conversation"
/// is the official whole-entry drop).
fn normalized_sync_delete_for_me(value: Option<&Value>) -> SyncDeleteForMeProjection {
    SyncDeleteForMeProjection {
        groups: normalized_sync_delete_groups(value),
        conversations: normalized_sync_delete_conversations(value),
        local_only_conversations: normalized_sync_local_only_conversations(value),
        attachments: normalized_sync_delete_attachments(value),
    }
}

/// One bounded delete-for-me [`SyncDeleteEntry`] list (contract 1.182):
/// the shared per-entry gate of all three arms — the identity caps mirror
/// the receive id family, and an entry without an author or a positive
/// stamp drops (the engine projects 0 for an unstated stamp).
fn normalized_sync_delete_entries(entries: Option<&Value>, cap: usize) -> Vec<SyncDeleteEntry> {
    entries
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .take(cap)
                .filter_map(|entry| {
                    let object = entry.as_object()?;
                    let author = object
                        .get("author")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|author| !author.is_empty())
                        .map(|author| {
                            author
                                .chars()
                                .take(MAX_RECEIVE_ID_CHARS)
                                .collect::<String>()
                        })?;
                    let timestamp = object
                        .get("timestamp")
                        .and_then(Value::as_u64)
                        .filter(|timestamp| *timestamp > 0)?;
                    Some(SyncDeleteEntry { author, timestamp })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The bounded `conversationDeletes` arm (contract 1.182, §4.182): each
/// entry names one conversation and its newest-row anchors. A group with no
/// conversation identity, or with every primary anchor failing the entry
/// bounds, drops whole — the official two warn-drops
/// (MessageReceiver.preload.ts:3662-3681) that make a delete-with-no-
/// position unrepresentable. The non-expiring companion is optional: an
/// absent key and an all-junk key both answer the empty list, which is the
/// official "no fallback position" state (the consumer only consults it
/// when the primary anchors matched nothing).
fn normalized_sync_delete_conversations(value: Option<&Value>) -> Vec<SyncDeleteConversation> {
    let Some(conversations) = value
        .and_then(|face| face.get("conversationDeletes"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    conversations
        .iter()
        .take(MAX_SYNC_DELETE_CONVERSATIONS)
        .filter_map(|group| {
            let object = group.as_object()?;
            let conversation_id = object
                .get("conversationId")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(|id| id.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
            let most_recent_messages = normalized_sync_delete_entries(
                object.get("mostRecentMessages"),
                MAX_SYNC_DELETE_CONVERSATION_ANCHORS,
            );
            if most_recent_messages.is_empty() {
                return None;
            }
            let most_recent_non_expiring_messages = normalized_sync_delete_entries(
                object.get("mostRecentNonExpiringMessages"),
                MAX_SYNC_DELETE_CONVERSATION_ANCHORS,
            );
            Some(SyncDeleteConversation {
                conversation_id,
                // The official `Boolean(item.isFullDelete)`: anything but a
                // literal `true` reads false, so an absent or hostile flag
                // degrades to the bounded-clear arm (the safe direction —
                // the full-delete arm deletes more).
                is_full_delete: object.get("isFullDelete").and_then(Value::as_bool) == Some(true),
                most_recent_messages,
                most_recent_non_expiring_messages,
            })
        })
        .collect()
}

/// The bounded `localOnlyConversationDeletes` arm (contract 1.182,
/// §4.182): the conversation identity alone. An entry without one drops
/// whole (the official "No target conversation" warn-drop at
/// MessageReceiver.preload.ts:3703-3711).
fn normalized_sync_local_only_conversations(
    value: Option<&Value>,
) -> Vec<SyncLocalOnlyConversationDelete> {
    let Some(conversations) = value
        .and_then(|face| face.get("localOnlyConversationDeletes"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    conversations
        .iter()
        .take(MAX_SYNC_LOCAL_ONLY_DELETE_CONVERSATIONS)
        .filter_map(|group| {
            let object = group.as_object()?;
            let conversation_id = object
                .get("conversationId")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(|id| id.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
            Some(SyncLocalOnlyConversationDelete { conversation_id })
        })
        .collect()
}

/// The bounded `attachmentDeletes` arm (contract 1.196, §4.196): the
/// official `handleDeleteForMeSync` fourth face (MessageReceiver.preload
/// .ts:3724-3790). Each entry names its conversation (the engine projects
/// the ConversationIdentifier as its conversation string), the target
/// message (author + upstream stamp — both hard gates: the official
/// `processAddressableMessage` refuses a target without either, :4415-4429,
/// and this destructive single-attachment arm does not inherit the
/// messageDeletes arm's zero-defaulted stamp tolerance), and at least one
/// attachment leg: clientUuid, fallbackDigest, or fallbackPlaintextHash
/// (:3754-3770). An entry with no conversation, no usable target, or all
/// three legs absent drops whole (the official three warn-drops); the leg
/// caps mirror the receive-id family and an over-bound leg drops rather
/// than truncates (a shortened digest/hash is a wrong fingerprint).
/// Entries are capped at the message-arm batch ceiling (the engine projects
/// at most the same 256).
fn normalized_sync_delete_attachments(value: Option<&Value>) -> Vec<SyncDeleteAttachment> {
    let Some(attachments) = value
        .and_then(|face| face.get("attachmentDeletes"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    // A leg is useful only verbatim: trim, bound, and drop anything that
    // would have to be shortened or guesses a non-string shape.
    let bounded_leg = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|leg| !leg.is_empty() && leg.chars().count() <= MAX_RECEIVE_ID_CHARS)
            .map(str::to_string)
    };
    attachments
        .iter()
        .take(MAX_SYNC_DELETE_GROUP_MESSAGES)
        .filter_map(|attachment| {
            let object = attachment.as_object()?;
            let conversation_id = object
                .get("conversationId")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(|id| id.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
            let target = object.get("targetMessage")?.as_object()?;
            let author = target
                .get("author")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|author| !author.is_empty())
                .map(|author| {
                    author
                        .chars()
                        .take(MAX_RECEIVE_ID_CHARS)
                        .collect::<String>()
                })?;
            let timestamp = target
                .get("timestamp")
                .and_then(Value::as_u64)
                .filter(|timestamp| *timestamp > 0)?;
            let client_uuid = bounded_leg(object.get("clientUuid"));
            let fallback_digest = bounded_leg(object.get("fallbackDigest"));
            // The engine projects lowercase hex; normalize a hostile
            // uppercase face instead of storing a non-matching spelling.
            let fallback_plaintext_hash = object
                .get("fallbackPlaintextHash")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|hash| {
                    !hash.is_empty()
                        && hash.chars().count() <= MAX_RECEIVE_ID_CHARS
                        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .map(str::to_ascii_lowercase);
            if client_uuid.is_none()
                && fallback_digest.is_none()
                && fallback_plaintext_hash.is_none()
            {
                return None;
            }
            Some(SyncDeleteAttachment {
                conversation_id,
                target: SyncDeleteEntry { author, timestamp },
                client_uuid,
                fallback_digest,
                fallback_plaintext_hash,
            })
        })
        .collect()
}

/// Bounded `syncMessage.deleteForMe` message group family (contract 1.102,
/// §4.83): kept as its own reader for the arm's own semantics — the group
/// optionally naming its conversation (key absent when the proto carried
/// none) and every entry naming one message by its author identity plus
/// upstream timestamp.
fn normalized_sync_delete_groups(value: Option<&Value>) -> Vec<SyncDeleteGroup> {
    let Some(groups) = value
        .and_then(|face| face.get("messageDeletes"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    groups
        .iter()
        .take(MAX_SYNC_DELETE_GROUPS)
        .filter_map(|group| {
            let object = group.as_object()?;
            let conversation_id = object
                .get("conversationId")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(|id| id.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
            let messages: Vec<SyncDeleteEntry> = object
                .get("messages")
                .and_then(Value::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .take(MAX_SYNC_DELETE_GROUP_MESSAGES)
                        .filter_map(|entry| {
                            let object = entry.as_object()?;
                            let author = object
                                .get("author")
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|author| !author.is_empty())
                                .map(|author| {
                                    author
                                        .chars()
                                        .take(MAX_RECEIVE_ID_CHARS)
                                        .collect::<String>()
                                })?;
                            let timestamp = object
                                .get("timestamp")
                                .and_then(Value::as_u64)
                                .filter(|timestamp| *timestamp > 0)?;
                            Some(SyncDeleteEntry { author, timestamp })
                        })
                        .collect()
                })
                .unwrap_or_default();
            if messages.is_empty() {
                return None;
            }
            Some(SyncDeleteGroup {
                conversation_id,
                messages,
            })
        })
        .collect()
}

/// The engine's `syncMessage.verified` face (contract 1.103, §4.84): the
/// wire shape is `{destinationUuid, destinationNumber?, identityKey?, state}`
/// — the settled trust state as the engine's lowercase word, everything else
/// enrichment. Entirely fail-closed: the state must be one of the engine's
/// three trust words (`verified` / `unverified` / `default` — the projection
/// maps its `TrustState::word()` output, so anything else is a hostile face)
/// and the destination must survive the ServiceId UUID shape gate verbatim
/// (the engine projects `service_id_string()`, never a number here; a
/// non-UUID is not the protocol's face — the whole record drops and the
/// envelope falls back to the plain syncMessage skip). The optional keys are
/// per-key fail-closed: a hostile shape answers absent, never a truncated
/// lie — an identity key is a fingerprint, and shortening one would mint a
/// wrong safety number.
fn normalized_sync_verified(value: Option<&Value>) -> Option<SyncVerifiedState> {
    let object = value?.as_object()?;
    let state = match object.get("state").and_then(Value::as_str)? {
        "verified" => "verified",
        "unverified" => "unverified",
        "default" => "default",
        _ => return None,
    };
    let destination_uuid = object
        .get("destinationUuid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|uuid| is_service_id_uuid(uuid))?;
    let destination_number = optional_bounded_string(object.get("destinationNumber"));
    let identity_key = object
        .get("identityKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.chars().count() <= MAX_SYNC_IDENTITY_KEY_CHARS)
        .map(str::to_string);
    Some(SyncVerifiedState {
        destination_uuid: destination_uuid.to_string(),
        destination_number,
        identity_key,
        state,
    })
}

/// One optional string key's fail-closed read (the §4.84 verified face's
/// number and the §4.85 call-event conversation identity share it): a string,
/// trimmed, non-empty, and bounded at the receive-id cap — anything else (the
/// wrong JSON type, an empty survivor, an over-bound face) answers absent.
fn optional_bounded_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())
}

/// The engine's `syncMessage.callEvent` face (contract 1.104, §4.85): the
/// wire shape is `{callId, timestamp, type?, direction?, event?,
/// conversationId?}` — the call's decimal id string, the record timestamp,
/// and the optional projection words. Fail-closed at two hard gates: the
/// callId must be a non-empty all-ASCII-digit string at the u64 ceiling (the
/// engine projects `u64::to_string()`, the official `longToString` form —
/// anything else is not the record's primary key) and the timestamp must be
/// strictly positive (the engine projects 0 for an unstated stamp — the
/// read-face unknown-marker discipline; a record with no timestamp is not a
/// history record). Either gate failing drops the whole face and the
/// envelope falls back to the plain syncMessage skip. The word keys fail
/// per-key: each must be exactly one of the engine's lowercase projection
/// words (a non-member answers absent — the desktop renders its own word for
/// a missing leg, never a mangled one), and the conversation identity rides
/// verbatim in whatever form the projection chose (hex / UUID / base64 — the
/// service ladder reads the form).
fn normalized_sync_call_event(value: Option<&Value>) -> Option<SyncCallEvent> {
    let object = value?.as_object()?;
    let call_id = object
        .get("callId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= MAX_SYNC_CALL_ID_CHARS
                && id.bytes().all(|byte| byte.is_ascii_digit())
        })?;
    let timestamp = object
        .get("timestamp")
        .and_then(Value::as_u64)
        .filter(|timestamp| *timestamp > 0)?;
    let word_key = |key: &str, words: &[&'static str]| {
        object
            .get(key)
            .and_then(Value::as_str)
            .and_then(|word| words.iter().copied().find(|member| *member == word))
    };
    Some(SyncCallEvent {
        call_id: call_id.to_string(),
        timestamp,
        kind: word_key("type", &["audio", "video", "group", "ad-hoc", "unknown"]),
        direction: word_key("direction", &["outgoing", "incoming", "unknown"]),
        outcome: word_key(
            "event",
            &["accepted", "not-accepted", "delete", "observed", "unknown"],
        ),
        conversation_id: optional_bounded_string(object.get("conversationId")),
    })
}

/// The engine's `syncMessage.configuration` face (contract 1.106, §4.87):
/// the wire shape is `{readReceipts?, unidentifiedDeliveryIndicators?,
/// typingIndicators?, linkPreviews?}` — the official
/// SyncMessage.Configuration flags, the engine projects its optional proto
/// bools key-for-key. Per-key fail-closed: a non-bool shape answers absent
/// (a mangled flag is never forwarded); a face where no key survived is a
/// zero-content sync and answers None — the envelope keeps the plain
/// syncMessage skip.
fn normalized_sync_configuration(value: Option<&Value>) -> Option<SyncConfigurationFlags> {
    let object = value?.as_object()?;
    let flag = |key: &str| object.get(key).and_then(Value::as_bool);
    let configuration = SyncConfigurationFlags {
        read_receipts: flag("readReceipts"),
        unidentified_delivery_indicators: flag("unidentifiedDeliveryIndicators"),
        typing_indicators: flag("typingIndicators"),
        link_previews: flag("linkPreviews"),
    };
    let SyncConfigurationFlags {
        read_receipts,
        unidentified_delivery_indicators,
        typing_indicators,
        link_previews,
    } = configuration;
    if read_receipts.is_none()
        && unidentified_delivery_indicators.is_none()
        && typing_indicators.is_none()
        && link_previews.is_none()
    {
        return None;
    }
    Some(configuration)
}

/// The engine's `syncMessage.fetchLatest` face (contract 1.106, §4.87): the
/// wire shape is `{type?}` — the SCREAMING word the engine projects from its
/// enum members (UNKNOWN / LOCAL_PROFILE / STORAGE_MANIFEST /
/// SUBSCRIPTION_STATUS; an absent or unknown i32 projects no key). The
/// per-key read is fail-closed (a hostile word answers absent); the arm's
/// presence alone is the trigger — the official fires FetchLatestEvent even
/// with the type unset (the UNKNOWN member is the downstream no-op), so
/// this face hard-gates nothing and routes on presence.
fn normalized_sync_fetch_latest(value: Option<&Value>) -> Option<Option<&'static str>> {
    let object = value?.as_object()?;
    Some(object.get("type").and_then(Value::as_str).and_then(|word| {
        [
            "UNKNOWN",
            "LOCAL_PROFILE",
            "STORAGE_MANIFEST",
            "SUBSCRIPTION_STATUS",
        ]
        .iter()
        .copied()
        .find(|member| *member == word)
    }))
}

/// The engine's `syncMessage.callLinkUpdate` face (contract 1.106, §4.87):
/// the wire shape is `{type?, rootKey?, adminKey?}` — the official
/// handleCallLinkUpdate face. Two hard gates, exactly the facts the official
/// handler throws over: the type must be present and the projection's only
/// known word (`UPDATE` — the official throws on a null type and on any
/// unknown member alike) and the rootKey must be present within the bound
/// (the update's subject; absent/over-bound = the record names nothing and
/// is dropped whole — a truncated key would address a different call link).
/// The keys are material, never parsed: the connector carries the base64
/// strings verbatim (the §4.73 call-link zero-parsing discipline); the
/// admin key is per-key fail-closed (a hostile or over-bound shape answers
/// absent — the §4.84 fingerprint discipline).
fn normalized_sync_call_link_update(value: Option<&Value>) -> Option<SyncCallLinkUpdate> {
    let object = value?.as_object()?;
    let kind = match object.get("type").and_then(Value::as_str)? {
        "UPDATE" => "UPDATE",
        _ => return None,
    };
    let root_key = object
        .get("rootKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.chars().count() <= MAX_SYNC_CALL_LINK_KEY_CHARS)
        .map(str::to_string)?;
    let admin_key = object
        .get("adminKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.chars().count() <= MAX_SYNC_CALL_LINK_KEY_CHARS)
        .map(str::to_string);
    Some(SyncCallLinkUpdate {
        kind,
        root_key,
        admin_key,
    })
}

/// The engine's `syncMessage.callLogEvent` face (contract 1.106, §4.87):
/// the wire shape is `{type?, timestamp?, conversationId?, callId?}` — the
/// official handleCallLogEvent mutation of one call-history record. One hard
/// gate: the type is the record's verb (CLEAR / MARKED_AS_READ /
/// MARKED_AS_READ_IN_CONVERSATION / CLEAR_IN_CONVERSATION — the engine's
/// SCREAMING projections) and must be a whitelist member; a hostile or
/// absent word is not a call-log mutation and drops the record whole (the
/// official zod enum parse fails the same face). The remaining keys are
/// per-key fail-closed optionals exactly as the official loose parse carries
/// them: the timestamp and call id ride the engine's verbatim u64 shapes,
/// the conversation identity rides the §4.85 three-form ladder input.
fn normalized_sync_call_log_event(value: Option<&Value>) -> Option<SyncCallLogEvent> {
    let object = value?.as_object()?;
    let kind = match object.get("type").and_then(Value::as_str)? {
        "CLEAR" => "CLEAR",
        "MARKED_AS_READ" => "MARKED_AS_READ",
        "MARKED_AS_READ_IN_CONVERSATION" => "MARKED_AS_READ_IN_CONVERSATION",
        "CLEAR_IN_CONVERSATION" => "CLEAR_IN_CONVERSATION",
        _ => return None,
    };
    Some(SyncCallLogEvent {
        kind,
        timestamp: object.get("timestamp").and_then(Value::as_u64),
        conversation_id: optional_bounded_string(object.get("conversationId")),
        call_id: object.get("callId").and_then(Value::as_u64),
    })
}

/// The engine's `syncMessage.deviceNameChange` face (contract 1.106, §4.87):
/// the wire shape is `{deviceId?}` — the linked device the rename addresses.
/// One hard gate: the deviceId must be present in u32 range (the official
/// handler warns and drops the sync when the key is absent — nothing to
/// address); the local-device-id comparison stays the desktop's own
/// decision, so the forwarded id is verbatim.
fn normalized_sync_device_name_change(value: Option<&Value>) -> Option<u32> {
    let object = value?.as_object()?;
    object
        .get("deviceId")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
}

/// The engine's `syncMessage.pniChangeNumber` face (contract 1.106, §4.87):
/// the wire shape is `{registrationId?, newE164?}` — the stripped face the
/// engine projects after keeping its key material inside its boundary. The
/// keys are per-key fail-closed (a hostile shape answers absent); a face
/// where neither key survived is a zero-content sync (the official's own
/// empty-sync warning face) and answers None — the envelope keeps the plain
/// syncMessage skip.
fn normalized_sync_pni_change_number(value: Option<&Value>) -> Option<SyncPniChangeNumber> {
    let object = value?.as_object()?;
    let change = SyncPniChangeNumber {
        registration_id: object
            .get("registrationId")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok()),
        new_e164: optional_bounded_string(object.get("newE164")),
    };
    if change.registration_id.is_none() && change.new_e164.is_none() {
        return None;
    }
    Some(change)
}

/// Bounded `syncMessage.contacts` record family (contract 1.136, §4.122):
/// the wire shape is `{complete, records: [{aci, number?, name?, …}]}` — the
/// engine projects the phone's parsed contact set (the official handleContacts
/// blob consume, the blob itself stays engine-side). Each record normalizes to
/// the identity + display name the connector's contacts cache holds: the ACI
/// is the record's hard gate (the engine always projects it — its absence is
/// a hostile shape, the record drops, 宁缺勿错), the e164 and the composed
/// name ride optional and per-key bounded (the receive id family caps and the
/// contact title cap the pull path applies). The expireTimer/inboxPosition
/// family has no connector-cache home and is not read. A face with no usable
/// record at all answers empty — the envelope keeps the plain syncMessage
/// skip (the delete-for-me sibling discipline).
fn normalized_sync_contact_records(value: Option<&Value>) -> Vec<SyncContactRecord> {
    let Some(records) = value
        .and_then(|face| face.get("records"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    records
        .iter()
        .take(MAX_SYNC_CONTACT_RECORDS)
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let aci = object
                .get("aci")?
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
            let number = object
                .get("number")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.chars()
                        .take(MAX_SYNC_CONTACT_NAME_CHARS)
                        .collect::<String>()
                });
            Some(SyncContactRecord { aci, number, name })
        })
        .collect()
}

/// The engine's `syncMessage.blocked` face (contract 1.140, §4.136): a
/// tolerant read of both families the engine projects — the official
/// `areModernFieldsUsed` selection is the engine's business, so the
/// connector unions whichever keys survive. Modern entries are objects
/// (`blockedE164s[{e164, timestamp?}]` / `blockedAcis[{aci, timestamp?}]` /
/// `blockedGroups[{groupId, timestamp?}]`), legacy entries are string arrays
/// (`numbers` / `acis` / `groupIds` / `acisBinary` — the last already the
/// engine-resolved UUID strings). Unknown keys and unknown entry fields are
/// not fatal (the official parse is loose the same way); an entry whose
/// identity read fails drops per-entry. None when no identity survived — the
/// envelope keeps the plain syncMessage skip.
fn normalized_sync_blocked(value: Option<&Value>) -> Option<SyncBlocked> {
    let face = value?.as_object()?;
    let mut blocked = SyncBlocked::default();
    let mut push_identity = |class: &str, raw: &Value| {
        let identity = match class {
            // Modern entry objects carry the identity in a per-class key.
            "modern-e164" => raw.get("e164"),
            "modern-aci" => raw.get("aci"),
            "modern-group" => raw.get("groupId"),
            // Legacy string arrays carry it directly.
            _ => Some(raw),
        }?
        .as_str()
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
        .map(|identity| {
            identity
                .chars()
                .take(MAX_RECEIVE_ID_CHARS)
                .collect::<String>()
        })?;
        let slot = match class {
            "modern-e164" | "legacy-number" => &mut blocked.numbers,
            "modern-aci" | "legacy-aci" => &mut blocked.acis,
            _ => &mut blocked.group_ids,
        };
        slot.push(identity);
        Some(())
    };
    for (class, keys) in [
        ("modern-e164", ["blockedE164s"].as_slice()),
        ("modern-aci", ["blockedAcis"].as_slice()),
        ("modern-group", ["blockedGroups"].as_slice()),
        ("legacy-number", ["numbers"].as_slice()),
        ("legacy-aci", ["acis", "acisBinary"].as_slice()),
        ("legacy-group", ["groupIds"].as_slice()),
    ] {
        for key in keys {
            let Some(entries) = face.get(*key).and_then(Value::as_array) else {
                continue;
            };
            for entry in entries.iter().take(MAX_SYNC_BLOCKED_ENTRIES) {
                let _ = push_identity(class, entry);
            }
        }
    }
    blocked.numbers.sort();
    blocked.numbers.dedup();
    blocked.numbers.truncate(MAX_SYNC_BLOCKED_ENTRIES);
    blocked.acis.sort();
    blocked.acis.dedup();
    blocked.acis.truncate(MAX_SYNC_BLOCKED_ENTRIES);
    blocked.group_ids.sort();
    blocked.group_ids.dedup();
    blocked.group_ids.truncate(MAX_SYNC_BLOCKED_ENTRIES);
    if blocked.numbers.is_empty() && blocked.acis.is_empty() && blocked.group_ids.is_empty() {
        None
    } else {
        Some(blocked)
    }
}

/// The ServiceId UUID shape gate (the desktop's UUID regex,
/// MessageReceiver.preload.ts:3274-3309): 8-4-4-4-12 hex groups.
fn is_service_id_uuid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(part, len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

#[derive(Clone, Debug)]
struct NormalizedText {
    value: String,
    bytes: u32,
    truncated: bool,
}

pub(crate) fn truncate_utf8_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// One inbound attachment filename (contract revision 1.184, §4.184): the
/// sender's name rides verbatim — long names, Unicode, spaces, multi-
/// extensions — the official receive posture
/// (`processDataMessage.preload.ts:128` `fileName: fileName ?? undefined`,
/// the quote face `:236` alike). The only rewrites are the official's own
/// safety filters, pulled forward to this one connector face:
///
/// - **Path components flatten** (basename semantics, both separators — the
///   official save layer joins `basename(name)`
///   (`attachments.preload.ts:257`); the connector never exposes arbitrary
///   file paths, so the host face cannot carry a path fragment at all). A
///   name that flattens to nothing, `.` or `..` says nothing usable and
///   answers empty — the caller's empty filter turns that into protocol
///   absence, never a made-up name.
/// - **Bidi-override controls map to U+FFFD**, the official schema-v9
///   `replaceUnicodeV2` set verbatim (`Attachment.std.ts:123-143`:
///   U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C). No C0/C1 sweep,
///   no extension verdict (`isFileDangerous` is the official's own save-time
///   warning, not a protocol filter) — filtering beyond the official family
///   would rewrite names the official renders as sent.
///
/// The result is clamped to [`MAX_ATTACHMENT_FILENAME_BYTES`] — boundedness
/// insurance at filesystem-name scale, not a rewrite rule (real names never
/// reach it, §4.184).
pub(crate) fn sanitize_inbound_filename(name: &str) -> String {
    let flattened = name
        .rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
        .unwrap_or_default();
    if flattened.is_empty() || flattened == "." || flattened == ".." {
        return String::new();
    }
    let un_bidi: String = flattened
        .chars()
        .map(|c| match c {
            '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}' => '\u{FFFD}',
            _ => c,
        })
        .collect();
    truncate_utf8_bytes(&un_bidi, MAX_ATTACHMENT_FILENAME_BYTES)
}

fn normalized_text(text: &str) -> Option<NormalizedText> {
    if text.is_empty() {
        return None;
    }
    let bytes = text.len().min(u32::MAX as usize) as u32;
    let truncated = text.len() > MAX_INBOUND_TEXT_BYTES;
    Some(NormalizedText {
        value: if truncated {
            truncate_utf8_bytes(text, MAX_INBOUND_TEXT_PREVIEW_BYTES)
        } else {
            text.to_string()
        },
        bytes,
        truncated,
    })
}

fn data_message_text(message: &serde_json::Map<String, Value>) -> Option<NormalizedText> {
    message
        .get("message")
        .and_then(Value::as_str)
        .and_then(normalized_text)
}

/// Bounded inbound quote snapshot (§4.13): upstream timestamp, author, and a
/// short preview. Malformed or oversized quotes drop the preview rather than
/// the whole message.
fn normalized_quote(value: &Value) -> Option<NormalizedQuote> {
    let object = value.as_object()?;
    let id = object.get("id").and_then(Value::as_u64)?;
    let author = ["authorNumber", "authorUuid", "author"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
    let text = object
        .get("text")
        .and_then(Value::as_str)
        .map(|text| text.chars().take(MAX_QUOTE_TEXT_CHARS).collect::<String>())
        .unwrap_or_default();
    let attachments = object
        .get("attachments")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .take(MAX_QUOTE_ATTACHMENTS)
                .filter_map(|entry| entry.as_object().and_then(normalized_quote_attachment))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(NormalizedQuote {
        id,
        author,
        text,
        attachments,
    })
}

/// One bounded quoted-attachment entry off a QuotedAttachment-shaped object
/// (contract 1.100, §4.81 D4). Key absence is protocol absence; an entry
/// carrying none of the three keys says nothing and drops whole. The
/// thumbnail rides the same bounded attachment parser the message face runs,
/// so an id-less pointer drops rather than rendering half a face; the
/// filename rides the same §4.184 face (the official filters only, never a
/// length rewrite — the D4-era ≤128-byte bound is retired).
fn normalized_quote_attachment(
    object: &serde_json::Map<String, Value>,
) -> Option<NormalizedQuoteAttachment> {
    let content_type = object
        .get("contentType")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.chars()
                .take(MAX_ATTACHMENT_CONTENT_TYPE_CHARS)
                .collect::<String>()
        });
    let filename = object
        .get("filename")
        .and_then(Value::as_str)
        .map(sanitize_inbound_filename)
        .filter(|s| !s.is_empty());
    let thumbnail = object
        .get("thumbnail")
        .and_then(Value::as_object)
        .and_then(normalized_attachment);
    let face = NormalizedQuoteAttachment {
        content_type,
        filename,
        thumbnail,
    };
    (face.content_type.is_some() || face.filename.is_some() || face.thumbnail.is_some())
        .then_some(face)
}

/// Bounded inbound attachment descriptors (§4.13): metadata only, entries past
/// the cap are dropped; the filename rides the §4.184 verbatim posture (the
/// official safety filters only — never a length rewrite), the remaining
/// strings truncate to their bound.
fn normalized_attachments(value: &Value) -> Vec<NormalizedAttachment> {
    let Some(entries) = value.as_array() else {
        return Vec::new();
    };
    entries
        .iter()
        .take(MAX_INBOUND_ATTACHMENTS)
        .filter_map(|entry| {
            entry
                .as_object()
                .and_then(|object| normalized_attachment_inner(object, false))
        })
        .collect()
}

/// One bounded attachment descriptor off an attachment-shaped object (§4.13,
/// reused by message attachments and link-preview images alike). The transit
/// locator face (contract revision 1.61) parses with the 1.56 import caps —
/// wrong-shaped keys drop, never guess (the §4.38 ingest discipline). The
/// P14 metadata keys (contract 1.107, §4.88) parse per-key fail-closed:
/// the caption is text material (the inbound-text budget), the blur preview
/// a bounded verbatim string, the integrity pair survives only all-or-nothing
/// (the official filePointers discipline — half a pair verifies nothing),
/// and the two flag booleans answer false on any non-bool shape (the
/// isVoiceNote posture: no flag bit = false). The voice-waveform pair
/// (contract 1.150, §4.149) parses per-key verbatim: the waveform is a
/// bounded base64 string the connector never decodes or re-encodes (empty or
/// over-cap drops whole, never truncated), the duration any positive float —
/// and the two stay independent (pairing is the engine's generation
/// invariant, not a connector gate: the connector forwards what is stated).
/// The filename rides the §4.184 face: the sender's name verbatim through
/// [`sanitize_inbound_filename`] — the official's own two filters only, the
/// length rewrite retired.
fn normalized_attachment(object: &serde_json::Map<String, Value>) -> Option<NormalizedAttachment> {
    normalized_attachment_inner(object, true)
}

/// The shared attachment parser. `require_id` is the strict face for
/// metadata-only pointer slots (quote thumbnails, sticker data, contact
/// avatars) — an id-less pointer there has nothing addressable and drops. The
/// message-attachment list parses relaxed: the engine's live projection always
/// emits an `id` key but leaves it empty when the pointer carries no
/// `client_uuid`, and the archive export omits the key entirely. Dropping the
/// whole descriptor over a missing synthetic id would discard contentType /
/// size / locator metadata the engine did give, so the receive arm assigns a
/// deterministic id after the row identity is known
/// (`fill_missing_attachment_ids`).
fn normalized_attachment_inner(
    object: &serde_json::Map<String, Value>,
    require_id: bool,
) -> Option<NormalizedAttachment> {
    const MAX_LOCATOR_BASE64_CHARS: usize = 512;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .map(|s| s.chars().take(MAX_ATTACHMENT_ID_CHARS).collect::<String>())
        .unwrap_or_default();
    if require_id && id.is_empty() {
        return None;
    }
    let content_type = object
        .get("contentType")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.chars()
                .take(MAX_ATTACHMENT_CONTENT_TYPE_CHARS)
                .collect::<String>()
        });
    let filename = object
        .get("filename")
        .and_then(Value::as_str)
        .map(sanitize_inbound_filename)
        .filter(|s| !s.is_empty());
    let caption = object
        .get("caption")
        .and_then(Value::as_str)
        .map(|s| truncate_utf8_bytes(s, MAX_INBOUND_TEXT_BYTES))
        .filter(|s| !s.is_empty());
    let blur_hash = object
        .get("blurHash")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.chars()
                .take(MAX_ATTACHMENT_BLUR_HASH_CHARS)
                .collect::<String>()
        });
    let mac = object
        .get("incrementalMac")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= MAX_LOCATOR_BASE64_CHARS);
    let chunk_size = object
        .get("chunkSize")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0 && *size <= u32::MAX as u64)
        .map(|size| size as u32);
    // 同进同退: the pair survives only together — the engine projects it
    // that way and the official keeps both-or-neither alike.
    let (incremental_mac, chunk_size) = match (mac, chunk_size) {
        (Some(mac), Some(chunk_size)) => (Some(mac.to_string()), Some(chunk_size)),
        _ => (None, None),
    };
    let locator = object.get("locator").and_then(normalized_locator_face);
    Some(NormalizedAttachment {
        id,
        content_type,
        filename,
        caption,
        blur_hash,
        incremental_mac,
        chunk_size,
        size: object.get("size").and_then(Value::as_u64),
        width: object
            .get("width")
            .and_then(Value::as_u64)
            .map(|value| value.min(u32::MAX as u64) as u32),
        height: object
            .get("height")
            .and_then(Value::as_u64)
            .map(|value| value.min(u32::MAX as u64) as u32),
        is_voice_note: object
            .get("isVoiceNote")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        is_borderless: object
            .get("isBorderless")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        is_gif: object
            .get("isGif")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        waveform: object
            .get("waveform")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty() && text.len() <= MAX_ATTACHMENT_WAVEFORM_CHARS)
            .map(str::to_string),
        duration: object
            .get("duration")
            .and_then(Value::as_f64)
            .filter(|seconds| *seconds > 0.0),
        locator,
    })
}

/// One transit locator face off an attachment-shaped object (contract
/// revision 1.61): the 1.56 import caps, per-key fail-closed — wrong-shaped
/// keys drop, never guess (the §4.38 ingest discipline). An all-default face
/// answers None (no locator material at all, indistinguishable on the read
/// face from a metadata-only pointer). Single source of truth for both the
/// live-receive descriptor parse ([`normalized_attachment`]) and the
/// backfill-response entry parse (contract 1.175, §4.175).
fn normalized_locator_face(raw: &Value) -> Option<crate::store::HistoryAttachmentLocator> {
    const MAX_LOCATOR_BASE64_CHARS: usize = 512;
    const MAX_LOCATOR_HEX_CHARS: usize = 128;
    let raw = raw.as_object()?;
    let bounded_b64 = |name: &str| {
        raw.get(name)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty() && text.len() <= MAX_LOCATOR_BASE64_CHARS)
            .map(str::to_string)
    };
    let plaintext_hash = raw
        .get("plaintextHash")
        .and_then(Value::as_str)
        .filter(|text| {
            !text.is_empty()
                && text.len() <= MAX_LOCATOR_HEX_CHARS
                && text.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map(|text| text.to_ascii_lowercase());
    let face = crate::store::HistoryAttachmentLocator {
        key: bounded_b64("key"),
        cdn_key: bounded_b64("cdnKey"),
        cdn_number: raw
            .get("cdnNumber")
            .and_then(Value::as_u64)
            .filter(|number| *number <= u32::MAX as u64)
            .map(|number| number as u32),
        upload_timestamp: raw
            .get("uploadTimestamp")
            .and_then(Value::as_u64)
            .filter(|timestamp| *timestamp > 0),
        digest: bounded_b64("digest"),
        plaintext_hash,
    };
    (face != crate::store::HistoryAttachmentLocator::default()).then_some(face)
}

/// One inbound sticker (contract revision 1.35): bounded pack identity beside
/// the message plus the `data` pointer as a regular metadata-only attachment
/// descriptor. A sticker missing any identity field or a usable data pointer
/// answers None so the envelope keeps its plain routing instead of carrying
/// half a sticker.
fn normalized_sticker(
    sticker: &serde_json::Map<String, Value>,
) -> Option<(NormalizedSticker, NormalizedAttachment)> {
    let pack_id = sticker
        .get("packId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.chars()
                .take(MAX_STICKER_PACK_ID_CHARS)
                .collect::<String>()
        })?;
    let pack_key = sticker
        .get("packKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.chars()
                .take(MAX_STICKER_PACK_KEY_CHARS)
                .collect::<String>()
        })?;
    let sticker_id = bounded_range_u32(sticker, "stickerId")?;
    let emoji = sticker
        .get("emoji")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_STICKER_EMOJI_CHARS).collect::<String>());
    let data = sticker
        .get("data")
        .and_then(Value::as_object)
        .and_then(normalized_attachment)?;
    Some((
        NormalizedSticker {
            pack_id,
            pack_key,
            sticker_id,
            emoji,
        },
        data,
    ))
}

/// One live contact card (contract 1.139, §4.132): the bounded face the
/// §4.38 import chain lands, read through the same
/// [`crate::history_import::import_contact`] authority — its bounds
/// (`MAX_CONTACT_*`, the type vocabulary, the whole-card discipline) are the
/// contract's, never re-stated here. The only live-shape difference is the
/// avatar wrap (`{avatar: <pointer>, isProfile}`): the pointer unwraps to
/// the plain archive shape and rides [`normalized_attachment`] like any
/// descriptor, and `isProfile` — the engine's address-book fact, not the
/// message's — never rides the row. A card with no usable content answers
/// None so the envelope keeps its plain routing (never a placeholder card);
/// a wrapped avatar whose pointer is absent unwraps to no avatar face.
fn normalized_live_contact(
    raw: Option<&Value>,
) -> Option<(NormalizedContact, Option<NormalizedAttachment>)> {
    let object = raw?.as_object()?;
    let mut unwrapped = object.clone();
    if let Some(wrap) = unwrapped.remove("avatar") {
        let pointer = wrap
            .as_object()
            .and_then(|wrap| wrap.get("avatar"))
            .filter(|value| value.is_object())
            .cloned();
        if let Some(pointer) = pointer {
            unwrapped.insert("avatar".to_string(), pointer);
        }
    }
    let (card, avatar) = crate::history_import::import_contact(Some(&Value::Object(unwrapped)))?;
    let avatar = avatar.and_then(|avatar| normalized_attachment(&avatar));
    Some((card, avatar))
}

/// Strict UUID grammar (8-4-4-4-12 hex, case-insensitive) — the §4.40
/// promotion test before an identity string is treated as an ACI. A phone
/// number never matches, and neither does a truncated or decorated value.
pub(crate) fn is_uuid_shaped(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// Bounded rich-body payload (contract 1.25) off a dataMessage-shaped object:
/// link previews, @mentions, text-style ranges and the view-once marker.
/// Malformed or oversized entries drop individually; an all-default result is
/// None so plain messages carry nothing.
fn normalized_rich(message: &serde_json::Map<String, Value>) -> Option<NormalizedRich> {
    let mut rich = NormalizedRich::default();
    if let Some(previews) = message.get("previews").and_then(Value::as_array) {
        rich.previews = previews
            .iter()
            .take(MAX_PREVIEWS)
            .filter_map(|entry| {
                let object = entry.as_object()?;
                let url = object
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.chars().take(MAX_PREVIEW_URL_CHARS).collect::<String>())?;
                Some(NormalizedPreview {
                    url,
                    title: object
                        .get("title")
                        .and_then(Value::as_str)
                        .map(|s| truncate_utf8_bytes(s, MAX_PREVIEW_FIELD_BYTES))
                        .filter(|s| !s.is_empty()),
                    description: object
                        .get("description")
                        .and_then(Value::as_str)
                        .map(|s| truncate_utf8_bytes(s, MAX_PREVIEW_FIELD_BYTES))
                        .filter(|s| !s.is_empty()),
                    // The engine projects the card's publish stamp only when
                    // positive (a 0 is the official's falsy no-information
                    // form); the same >0 filter runs here.
                    date: object
                        .get("date")
                        .and_then(Value::as_u64)
                        .filter(|date| *date > 0),
                    image: object
                        .get("image")
                        .and_then(Value::as_object)
                        .and_then(normalized_attachment),
                })
            })
            .collect();
    }
    if let Some(mentions) = message.get("mentions").and_then(Value::as_array) {
        rich.mentions = mentions
            .iter()
            .take(MAX_MENTIONS)
            .filter_map(|entry| {
                let object = entry.as_object()?;
                let number = object
                    .get("number")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
                let uuid = object
                    .get("uuid")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
                // Contract 1.40 (§4.40): the author keeps the pre-1.40
                // number-first ladder; the ACI is promoted only when the
                // upstream actually supplied one — the envelope `uuid`
                // field, or a UUID-shaped number key (the engine-mode
                // receive face puts the ACI there).
                let author = number.clone().or_else(|| uuid.clone())?;
                let author_aci = uuid.or_else(|| number.filter(|value| is_uuid_shaped(value)));
                Some(NormalizedMention {
                    author,
                    author_aci,
                    name: object
                        .get("name")
                        .and_then(Value::as_str)
                        .map(|s| truncate_utf8_bytes(s, MAX_MENTION_NAME_BYTES))
                        .filter(|s| !s.is_empty()),
                    start: bounded_range_u32(object, "start")?,
                    length: bounded_range_u32(object, "length")?,
                })
            })
            .collect();
    }
    if let Some(styles) = message.get("textStyles").and_then(Value::as_array) {
        rich.text_styles = styles
            .iter()
            .take(MAX_TEXT_STYLES)
            .filter_map(|entry| {
                let object = entry.as_object()?;
                let style = match object.get("style").and_then(Value::as_str) {
                    Some("BOLD") => "BOLD",
                    Some("ITALIC") => "ITALIC",
                    Some("STRIKETHROUGH") => "STRIKETHROUGH",
                    Some("MONOSPACE") => "MONOSPACE",
                    Some("SPOILER") => "SPOILER",
                    _ => return None,
                };
                Some(NormalizedTextStyle {
                    style: style.to_string(),
                    start: bounded_range_u32(object, "start")?,
                    length: bounded_range_u32(object, "length")?,
                })
            })
            .collect();
    }
    // Story-reply context (contract 1.76, §4.67): `dataMessage.storyReply` →
    // {authorAci, sentTimestamp}, both keys required — the engine projects the
    // face only when the author resolves, and a degraded shape here drops the
    // key (never the row), the §4.20 per-entry discipline.
    rich.story_reply = normalized_story_reply(message);
    // Live poll face (§4.118): `dataMessage.poll {question, options,
    // allowMultiple}` — the engine's Q3 projection — parses onto the same
    // NormalizedPoll the §4.38 import chain lands. The live face carries no
    // votes and no terminated bit: they arrive as their own vote/terminate
    // envelopes and fold onto the landed row at the service layer. A
    // non-object face is no face; a structurally valid one always answers
    // (the official bare-poll posture: `question ?? ''`, `options ?? []`).
    if let Some(poll) = message.get("poll").and_then(Value::as_object) {
        rich.poll = normalized_live_poll(poll);
    }
    // Live gift-badge face (contract 1.181, §4.181): the engine's P14
    // receive projection `{state, expiration, level,
    // receiptCredentialPresentation}` — the official processGiftBadge
    // posture (processDataMessage.preload.ts:476) — parses onto the §4.38
    // archive twin's `NormalizedGiftBadge`, now with the countdown pair.
    // The zk credential presentation stays engine-side (the recorded 1.81
    // gap, unchanged); a degraded shape (non-object, no state word) drops
    // the key and never the row.
    if let Some(badge) = message.get("giftBadge").and_then(Value::as_object) {
        rich.gift_badge = normalized_live_gift_badge(badge);
    }
    rich.view_once = message
        .get("viewOnce")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    rich.view_once_invalid = message
        .get("viewOnceInvalid")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    rich.is_expiration_update = message
        .get("isExpirationUpdate")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Group-state change (contract 1.45, §4.44): `JsonGroupInfo.type == UPDATE`
    // marks a group edit; the resulting title is mirror material only. DELIVER
    // (every normal group message) and the absent key leave both fields off.
    if let Some(info) = message.get("groupInfo").and_then(Value::as_object) {
        rich.is_group_update = info
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind == "UPDATE");
        rich.group_name = info
            .get("groupName")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.chars()
                    .take(GROUP_UPDATE_TITLE_MIRROR_CHARS)
                    .collect::<String>()
            });
        // Structured material (§4.227): only an UPDATE row carries the
        // change vocabulary — a DELIVER face with stray keys is a hostile or
        // malformed shape and keeps no face (the marker is the gate, the
        // §4.44 posture).
        if rich.is_group_update {
            rich.group_change = normalized_group_change(info);
        }
    }
    // The engine's P14 dataMessage protocol stamp and Sent-transcript faces
    // (contract 1.107, §4.88): `expireTimerVersion` forwards when positive
    // (the engine projects no key for 0); the three Sent faces parse per-key
    // (receive dataMessages never carry them, so inbound rows keep the
    // defaults; the keys ride only the sent mirror). Every identity string
    // takes the receive-id family bound, the outer lists the sync receive
    // family cap, and each story entry's distribution ids the 64-entry list
    // cap — a hostile or oversized face degrades per-key, never the row.
    rich.expire_timer_version = message
        .get("expireTimerVersion")
        .and_then(Value::as_u64)
        .filter(|version| *version > 0)
        .and_then(|version| u32::try_from(version).ok());
    rich.is_recipient_update =
        message.get("isRecipientUpdate").and_then(Value::as_bool) == Some(true);
    if let Some(entries) = message.get("unidentifiedStatus").and_then(Value::as_array) {
        rich.unidentified_status = entries
            .iter()
            .take(MAX_SYNC_SENT_STATUS_ENTRIES)
            .filter_map(|entry| {
                let object = entry.as_object()?;
                Some(NormalizedUnidentifiedStatus {
                    destination_uuid: object
                        .get("destinationUuid")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>()),
                    unidentified: object.get("unidentified").and_then(Value::as_bool),
                    destination_pni_identity_key: object
                        .get("destinationPniIdentityKey")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && s.len() <= MAX_SYNC_IDENTITY_KEY_CHARS)
                        .map(str::to_string),
                })
            })
            .collect();
    }
    if let Some(entries) = message
        .get("storyMessageRecipients")
        .and_then(Value::as_array)
    {
        rich.story_message_recipients = entries
            .iter()
            .take(MAX_SYNC_SENT_STATUS_ENTRIES)
            .filter_map(|entry| entry.as_object().map(normalized_story_recipient))
            .collect();
    }
    if rich.is_empty() {
        return None;
    }
    Some(rich)
}

/// Ingest caps for the live poll faces (§4.118): the §4.38 import family's
/// values verbatim, so a poll renders identically no matter which chain
/// landed it. String faces truncate at the cap (renderable-prefix honesty);
/// option entries past the cap drop whole (their votes would dangle — the
/// index addressing must stay self-consistent).
const MAX_LIVE_POLL_QUESTION_CHARS: usize = 256;
const MAX_LIVE_POLL_OPTION_CHARS: usize = 256;
const MAX_LIVE_POLL_OPTIONS: usize = 32;
const MAX_LIVE_POLL_VOTE_INDEXES: usize = 32;

/// The engine's live poll-create face (§4.118): `dataMessage.poll
/// {question, options, allowMultiple}` — the Q3 projection, proto-verbatim —
/// parses onto the exact NormalizedPoll the §4.38 import chain lands:
/// `terminated` false (a termination arrives as its own envelope and folds
/// later) and no votes yet. The face is structural — an object answers a
/// poll even when every field is absent or mistyped (the official
/// bare-poll posture: `question ?? ''`, `options ?? []`); option entries
/// keep their position so vote indexes stay addressable (a mistyped label
/// rides empty, never shifts the list).
fn normalized_live_poll(poll: &serde_json::Map<String, Value>) -> Option<NormalizedPoll> {
    let options: Vec<String> = poll
        .get("options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_LIVE_POLL_OPTIONS)
        .map(|option| {
            option
                .as_str()
                .map(|text| {
                    text.chars()
                        .take(MAX_LIVE_POLL_OPTION_CHARS)
                        .collect::<String>()
                })
                .unwrap_or_default()
        })
        .collect();
    Some(NormalizedPoll {
        question: poll
            .get("question")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(MAX_LIVE_POLL_QUESTION_CHARS)
            .collect(),
        options,
        allow_multiple: poll
            .get("allowMultiple")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        terminated: false,
        votes: Vec::new(),
    })
}

/// The engine's live gift-badge face (contract 1.181, §4.181): the P14
/// receive projection `{state, expiration, level,
/// receiptCredentialPresentation}` onto the §4.38 archive twin — the state
/// word lowercased onto the desktop vocabulary (the engine's live face
/// spells it uppercase, the archive face capitalized; both land the same
/// wire word), the countdown pair bounded to positive stamps (a zero or
/// missing expiration is no countdown, an absent level no tier). The zk
/// credential presentation is never captured — engine-side material, the
/// recorded 1.81 gap. A missing or non-string state drops the face.
fn normalized_live_gift_badge(
    badge: &serde_json::Map<String, Value>,
) -> Option<NormalizedGiftBadge> {
    let state = badge.get("state")?.as_str()?.to_ascii_lowercase();
    Some(NormalizedGiftBadge {
        state,
        expiration_ms: badge
            .get("expiration")
            .and_then(Value::as_u64)
            .filter(|stamp| *stamp > 0),
        level: badge.get("level").and_then(Value::as_u64),
    })
}

/// The engine's live poll-vote face (§4.118): `dataMessage.pollVote
/// {targetAuthor, targetSentTimestamp, optionIndexes}` — `voteCount` has no
/// desktop face and is ignored, the §4.38 gap verbatim. The guaranteed
/// faces gate fail-closed (a missing or blank targetAuthor, a 0 target
/// timestamp — the proto-absent sentinel — or a non-array optionIndexes
/// answers None, the envelope falls to the plain skip); the selection
/// entries cap at the §4.38 bound and entries past u32 drop the face (an
/// index that cannot render is not a vote). The engine dedups the
/// selection upstream; a hostile duplicate still folds harmlessly.
fn normalized_poll_vote(vote: &serde_json::Map<String, Value>) -> Option<ControlReceive> {
    let target_author = vote
        .get("targetAuthor")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
    let target_timestamp = vote.get("targetSentTimestamp").and_then(Value::as_u64)?;
    if target_timestamp == 0 {
        return None;
    }
    let entries = vote.get("optionIndexes").and_then(Value::as_array)?;
    if entries.len() > MAX_LIVE_POLL_VOTE_INDEXES {
        return None;
    }
    // The selection is a set (the official replace-on-vote semantics): a
    // repeated index carries no extra state, and the §4.38 import chain can
    // never emit one — dedupe preserving poll order so both chains land the
    // identical face.
    let mut option_indexes = Vec::with_capacity(entries.len());
    for index in entries {
        let index = index.as_u64()?;
        let index = u32::try_from(index).ok()?;
        if !option_indexes.contains(&index) {
            option_indexes.push(index);
        }
    }
    Some(ControlReceive::PollVote {
        target_author,
        target_timestamp,
        option_indexes,
    })
}

/// One protocol range coordinate: missing, non-numeric or out-of-u32 values
/// drop the entry rather than clamp into a wrong rendered range.
fn bounded_range_u32(object: &serde_json::Map<String, Value>, key: &str) -> Option<u32> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= u32::MAX as u64)
        .map(|value| value as u32)
}

/// Story receive material bound (contract 1.76, §4.67): the coarse guard
/// family the call-signaling opaque face rides (one host frame discipline) —
/// real story projections are far smaller; only hostile or absurd material
/// trips it, and an oversized face drops the whole envelope. The projection
/// itself passes through verbatim — the connector neither re-shapes nor
/// prunes it.
const MAX_STORY_MATERIAL_BYTES: usize = 3 * 1024 * 1024;

fn bounded_story_material(story: &serde_json::Map<String, Value>) -> Option<Value> {
    let value = Value::Object(story.clone());
    let serialized = serde_json::to_string(&value).ok()?;
    (serialized.len() <= MAX_STORY_MATERIAL_BYTES).then_some(value)
}

/// Story-reply context (contract 1.76, §4.67): `dataMessage.storyReply` →
/// {authorAci, sentTimestamp}, both keys required — the engine projects the
/// face only when the author resolves, and a degraded shape here drops the
/// face (never the row), the §4.20 per-entry discipline. One authority for
/// both consumers: the rich row face and the §4.153 story-reaction routing
/// read the same helper, so a shape the row ladder degraded is exactly the
/// shape the control ladder declines.
fn normalized_story_reply(
    message: &serde_json::Map<String, Value>,
) -> Option<NormalizedStoryReply> {
    let reply = message.get("storyReply")?.as_object()?;
    reply
        .get("authorAci")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())
        .zip(reply.get("sentTimestamp").and_then(Value::as_u64))
        .map(|(author_aci, sent_timestamp)| NormalizedStoryReply {
            author_aci,
            sent_timestamp,
        })
}

/// One `storyMessageRecipients[]` entry (contract 1.107, §4.88): the
/// destination service id, the distribution (playlist) ids verbatim, and the
/// reply-permission bit only when the proto stated one. One authority for
/// both consumers: the sent transcript's rich face and the §4.153 story
/// recipient-update sync parse the same helper, so both chains land the
/// identical entry shape.
fn normalized_story_recipient(object: &serde_json::Map<String, Value>) -> NormalizedStoryRecipient {
    NormalizedStoryRecipient {
        destination_uuid: object
            .get("destinationUuid")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>()),
        distribution_list_ids: object
            .get("distributionListIds")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .take(MAX_STORY_DISTRIBUTION_IDS)
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        is_allowed_to_reply: object.get("isAllowedToReply").and_then(Value::as_bool),
    }
}

/// The engine's `syncMessage.storyRecipientUpdate` face (contract 1.154,
/// §4.153): the story's own Signal timestamp plus the recipients array the
/// recipients' story views converge to. The timestamp is the story anchor —
/// zero or absent has no story to address and drops the face (the
/// SyncCallEvent positive-stamp gate); an entry the engine could not resolve
/// forwards with only its carried keys (the NormalizedStoryRecipient
/// tolerance), and an array with no entry at all is no face — the engine's
/// own gate never projects one, so what survives here is the bounds
/// family's own guard.
fn normalized_sync_story_recipient_update(
    face: Option<&Value>,
) -> Option<(u64, Vec<NormalizedStoryRecipient>)> {
    let face = face?.as_object()?;
    let timestamp = face
        .get("timestamp")
        .and_then(Value::as_u64)
        .filter(|timestamp| *timestamp > 0)?;
    let entries = face
        .get("storyMessageRecipients")
        .and_then(Value::as_array)?;
    let recipients = entries
        .iter()
        .take(MAX_SYNC_SENT_STATUS_ENTRIES)
        .filter_map(|entry| entry.as_object().map(normalized_story_recipient))
        .collect::<Vec<_>>();
    (!recipients.is_empty()).then_some((timestamp, recipients))
}

/// Bounded reaction payload: emoji shortened, author bounded, malformed shapes
/// answer None so the envelope skips instead of inventing protocol state.
fn normalized_reaction(value: &Value) -> Option<ControlReceive> {
    let object = value.as_object()?;
    let emoji = object
        .get("emoji")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_EMOJI_CHARS).collect::<String>())?;
    let target_author = ["targetAuthorNumber", "targetAuthorUuid", "targetAuthor"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
    let target_timestamp = object.get("targetSentTimestamp").and_then(Value::as_u64)?;
    let remove = object
        .get("isRemove")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(ControlReceive::Reaction {
        emoji,
        target_author,
        target_timestamp,
        remove,
    })
}

/// The pin-family target identity (contract 1.33), bounded like the reaction
/// target: the author as the upstream resolved it (E.164 on a contacts hit,
/// ACI string otherwise) and the pinned message's upstream timestamp.
fn normalized_pin_target(value: &Value) -> Option<(String, u64)> {
    let object = value.as_object()?;
    let target_author = ["targetAuthorNumber", "targetAuthorUuid", "targetAuthor"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>())?;
    let target_timestamp = object.get("targetSentTimestamp").and_then(Value::as_u64)?;
    Some((target_author, target_timestamp))
}

/// `dataMessage.pinMessage`: `{targetAuthor, targetSentTimestamp,
/// pinDurationSeconds?}` — absent/null duration is the official forever pin,
/// an out-of-u32 duration drops the field rather than inventing a wrong
/// expiry.
fn normalized_pin_message(value: &Value) -> Option<ControlReceive> {
    let object = value.as_object()?;
    let (target_author, target_timestamp) = normalized_pin_target(value)?;
    let duration_seconds = object
        .get("pinDurationSeconds")
        .and_then(Value::as_u64)
        .filter(|value| *value <= u32::MAX as u64)
        .map(|value| value as u32);
    Some(ControlReceive::PinMessage {
        target_author,
        target_timestamp,
        duration_seconds,
    })
}

/// `dataMessage.unpinMessage`: `{targetAuthor, targetSentTimestamp}` —
/// target identity only.
fn normalized_unpin_message(value: &Value) -> Option<ControlReceive> {
    normalized_pin_target(value).map(|(target_author, target_timestamp)| {
        ControlReceive::UnpinMessage {
            target_author,
            target_timestamp,
        }
    })
}

/// `dataMessage.adminDelete`: `{targetAuthor, targetSentTimestamp}` —
/// target identity only.
fn normalized_admin_delete(value: &Value) -> Option<ControlReceive> {
    normalized_pin_target(value).map(|(target_author, target_timestamp)| {
        ControlReceive::AdminDelete {
            target_author,
            target_timestamp,
        }
    })
}

/// Call signaling (contract 1.50, §4.48): the engine's `callMessage` face —
/// the official Content.callMessage=3 projection. The modern line rides
/// `opaque` (base64 + urgency); the legacy 1:1 frames project when present.
/// A blank CallMessage (nothing projectable) routes nothing — the envelope
/// falls through to the plain skip like any other unclaimed face, never
/// invented into content.
fn normalized_call_message(call: &serde_json::Map<String, Value>) -> Option<ControlReceive> {
    // The modern wire face first: the opaque signaling payload is the
    // framing the current desktop ships; the engine already dropped a blank
    // one (宁缺勿错), so an `opaque` key here always carries material.
    if let Some(data) = call.get("opaque").and_then(Value::as_str) {
        if data.is_empty() || data.chars().count() > MAX_CALL_OPAQUE_CHARS {
            return None;
        }
        return Some(ControlReceive::Call {
            call_id: 0,
            signal_type: "opaque",
            payload: json!({
                "opaque": data,
                "urgency": call.get("urgency").and_then(Value::as_str).unwrap_or("droppable"),
                "destinationDeviceId": call.get("destinationDeviceId").cloned().unwrap_or(Value::Null),
            }),
        });
    }
    // The legacy 1:1 frames, present-keyed: the id is the frame's call
    // identity, the payload is the projected face verbatim. An unparseable
    // id fails the whole face (宁缺勿错 — a frame without a call id has no
    // state machine to address).
    let call_id = |key: &str| -> Option<u64> {
        call.get(key)
            .and_then(Value::as_object)
            .and_then(|frame| frame.get("id"))
            .and_then(Value::as_u64)
            .filter(|id| *id > 0 && *id <= MAX_CALL_ID)
    };
    for (key, signal_type) in [
        ("offer", "offer"),
        ("answer", "answer"),
        ("busy", "busy"),
        ("hangup", "hangup"),
    ] {
        if let Some(id) = call_id(key) {
            let payload = json!({ key: call.get(key) });
            return Some(ControlReceive::Call {
                call_id: id,
                signal_type,
                payload,
            });
        }
    }
    // The legacy ICE list: the first frame names the call, the whole bounded
    // list rides the payload.
    if let Some(ice) = call.get("iceUpdate").and_then(Value::as_array) {
        let first = ice.first().and_then(Value::as_object).and_then(|frame| {
            frame
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0 && *id <= MAX_CALL_ID)
        });
        if let Some(id) = first {
            let mut frames = ice.to_vec();
            frames.truncate(MAX_CALL_ICE_FRAMES);
            return Some(ControlReceive::Call {
                call_id: id,
                signal_type: "ice",
                payload: json!({ "iceUpdate": frames }),
            });
        }
    }
    None
}

fn normalize_receive(params: &Value) -> Result<Option<NormalizedReceive>, EngineError> {
    let normalized = normalize_receive_fields(params)?;
    // Identifier fields route conversations; an oversized one would exhaust the receive
    // queue byte budget and fault the engine. Drop the notification instead of
    // truncating the id (which would misroute) or killing the engine.
    if normalized
        .account
        .iter()
        .chain(normalized.source.iter())
        .chain(normalized.source_uuid.iter())
        .chain(normalized.group_id.iter())
        .any(|id| id.chars().count() > MAX_RECEIVE_ID_CHARS)
    {
        return Ok(None);
    }
    Ok(Some(normalized))
}

/// A receive that routes to a conversation but carries no message row of its
/// own (reaction / remote delete / typing). The service layer resolves the
/// conversation the same way it does for messages.
struct ControlRouting {
    direction: &'static str,
    source: Option<String>,
    group_id: Option<String>,
    control: ControlReceive,
}

fn control_routing(envelope: &serde_json::Map<String, Value>) -> Option<ControlRouting> {
    // Peer reaction / remote delete riding a dataMessage without a body.
    if let Some(data_message) = envelope.get("dataMessage").and_then(Value::as_object) {
        let group_id = data_message_group_id(data_message);
        if let Some(reaction) = data_message.get("reaction").and_then(normalized_reaction) {
            // Story-anchored reaction (contract 1.154 §4.153, group legs
            // contract 1.158, §4.156): the reaction + storyReply co-presence
            // is the engine's story discrimination face on the group leg
            // exactly as on the 1:1 leg — the official group story reaction
            // rides the ordinary group channel with the storyContext always
            // present (reaction + storyReply + groupV2), so the wire
            // judgment is one judgment and the group leg carries the group
            // key (the §4.156 翻案 of the 1.154 group fold). A degraded
            // storyReply (the engine projects the key only when the author
            // resolves) stays a plain reaction. The anchor is the
            // storyReply face; the reaction target face is the same
            // author/timestamp by the official dual-anchor alignment and is
            // not transported twice.
            let ControlReceive::Reaction {
                emoji,
                target_author,
                target_timestamp,
                remove,
            } = reaction
            else {
                unreachable!("normalized_reaction only answers the Reaction variant");
            };
            if let Some(story) = normalized_story_reply(data_message) {
                return Some(ControlRouting {
                    direction: "incoming",
                    source: envelope_peer_source(envelope),
                    group_id: group_id.clone(),
                    control: ControlReceive::StoryReaction {
                        emoji,
                        remove,
                        story_author: story.author_aci,
                        story_sent_at: story.sent_timestamp,
                        group_id: group_id.clone(),
                    },
                });
            }
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: ControlReceive::Reaction {
                    emoji,
                    target_author,
                    target_timestamp,
                    remove,
                },
            });
        }
        if let Some(target) = data_message
            .get("remoteDelete")
            .and_then(Value::as_object)
            .and_then(|object| object.get("timestamp"))
            .and_then(Value::as_u64)
        {
            // Story-channel DOE (contract 1.154 §4.153, group leg contract
            // 1.158, §4.156): the envelope `isStory` bit marks the deletion
            // riding the story channel — the story batch S5's receive leg
            // ①. The bit routes here on both legs: the 1:1 story channel
            // and, conservatively, the group envelope that carries the bit
            // (officially legal, some clients may send it). An unsigned
            // group DOE keeps the plain remote-delete fold: the official
            // group story deletion rides a regular group DOE with no bit
            // and no storyContext, so the wire cannot tell it from an
            // ordinary group delete and the §4.156 candidate event owns
            // that face.
            if envelope.get("isStory").and_then(Value::as_bool) == Some(true) {
                return Some(ControlRouting {
                    direction: "incoming",
                    source: envelope_peer_source(envelope),
                    group_id: group_id.clone(),
                    control: ControlReceive::StoryDeleted {
                        target_timestamp: target,
                        group_id: group_id.clone(),
                    },
                });
            }
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: ControlReceive::RemoteDelete {
                    target_timestamp: target,
                },
            });
        }
        // 群通话 era 更新（契约 1.264，§4.248）：官方 handleGroupCallUpdateMessage
        // 臂（background.preload.ts:3534-3563）——非渲染行零持久化，控制事件面
        // 即 peek 触发。群闸在先（官方 `message.groupV2 && GROUP`）：eraId 非空
        // ≤256、group 键必在；era 缺席/超帽/无群键 = 官方 warn-and-ignore，整面
        // 掉落（不路由、不铸行变化——信封走下方既有 fall-through，1:1 腿字节级
        // 不变）。
        if let Some(update) = data_message
            .get("groupCallUpdate")
            .and_then(Value::as_object)
        {
            let era_id = update
                .get("eraId")
                .and_then(Value::as_str)
                .filter(|era| !era.is_empty() && era.chars().count() <= MAX_GROUP_CALL_ERA_CHARS);
            if let (Some(era_id), true) = (era_id, group_id.is_some()) {
                return Some(ControlRouting {
                    direction: "incoming",
                    source: envelope_peer_source(envelope),
                    group_id,
                    control: ControlReceive::GroupCallUpdate {
                        era_id: era_id.to_string(),
                    },
                });
            }
        }
        // Pin family (contract 1.33): per-conversation pin state and the
        // admin-delete tombstone, projected by the service layer.
        if let Some(pin) = data_message
            .get("pinMessage")
            .and_then(normalized_pin_message)
        {
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: pin,
            });
        }
        if let Some(unpin) = data_message
            .get("unpinMessage")
            .and_then(normalized_unpin_message)
        {
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: unpin,
            });
        }
        if let Some(admin_delete) = data_message
            .get("adminDelete")
            .and_then(normalized_admin_delete)
        {
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: admin_delete,
            });
        }
        // Poll vote / terminate (§4.118): the two bodyless poll-control
        // envelopes fold onto the poll row they address. The create face is
        // deliberately absent here — it is a message row, routed by the
        // message ladder below (the fold targets it through the vote's own
        // anchor). A malformed face falls through to the plain skip arm.
        if let Some(vote) = data_message
            .get("pollVote")
            .and_then(Value::as_object)
            .and_then(normalized_poll_vote)
        {
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: vote,
            });
        }
        if let Some(target) = data_message
            .get("pollTerminate")
            .and_then(Value::as_object)
            .and_then(|object| object.get("targetSentTimestamp"))
            .and_then(Value::as_u64)
            .filter(|target| *target > 0)
        {
            return Some(ControlRouting {
                direction: "incoming",
                source: envelope_peer_source(envelope),
                group_id,
                control: ControlReceive::PollTerminate {
                    target_timestamp: target,
                },
            });
        }
        // A body-less editUpdate rides editMessage at the envelope level; a
        // dataMessage with only editUpdate content has no local meaning.
    }
    // The engine's `groupUpdated` projection (2026-10-06 engine batch): a
    // decrypted group expiration-timer change envelope-replaced before it
    // reaches the connector. It routes as a control receive addressed by the
    // group master key; the missing-`expireTimerSeconds`/non-u32 shapes fail
    // closed (the projection guarantees the key, so its absence is a protocol
    // error, not an unknown-timer state). `editor` — the change author's ACI
    // (contract 1.92 §4.75 row attribution material) — rides when the
    // projection named one: trimmed, bounded to the ACI form the engine
    // emits, and treated as absent when the shape is hostile (宁缺勿错, the
    // row lands unattributed, never mis-attributed). `groupId` absence routes
    // warn-only drop at the service layer like every unresolvable group
    // reference.
    if let Some(update) = envelope.get("groupUpdated").and_then(Value::as_object) {
        let expire_timer_seconds = update
            .get("expireTimerSeconds")
            .and_then(Value::as_u64)
            .and_then(|seconds| u32::try_from(seconds).ok())?;
        let group_id = update
            .get("groupId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let editor = update
            .get("editor")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|aci| !aci.is_empty() && aci.len() <= GROUP_UPDATED_EDITOR_MAX_BYTES)
            .map(str::to_string);
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id,
            control: ControlReceive::GroupTimerUpdate {
                expire_timer_seconds,
                editor,
            },
        });
    }
    // The engine's `groupChanged` projection (contract 1.100, §4.81 D3): a
    // decrypted group change batch with non-timer/terminate changes,
    // envelope-replaced before it reaches the connector. The guaranteed
    // faces fail closed (the projection always names a revision and a
    // non-empty change list — their absence is a protocol error, not an
    // unknown shape, and the envelope falls to the plain skip);
    // `groupId` absence still routes so the service layer keeps its
    // warn-only drop (the groupUpdated precedent). `editor` rides when the
    // projection named one — the same bounded form the groupUpdated arm
    // reads; the timer leg rides only beside other changes (pure timer
    // batches stay on the groupUpdated face) and a non-u32 shape reads as
    // absent (the mirror skips, the event still forwards). The `changes`
    // array passes bounded and verbatim: entries past the cap truncate,
    // material over the coarse byte guard drops the whole face (宁缺勿错,
    // never a truncated lie).
    if let Some(change) = envelope.get("groupChanged").and_then(Value::as_object) {
        let revision = change.get("revision").and_then(Value::as_u64)?;
        let changes = change.get("changes").and_then(Value::as_array)?;
        if changes.is_empty() {
            return None;
        }
        let mut bounded = changes.clone();
        bounded.truncate(crate::service::GROUP_CHANGED_MAX_CHANGES);
        let changes = Value::Array(bounded);
        if serde_json::to_string(&changes)
            .is_ok_and(|material| material.len() > MAX_GROUP_CHANGED_BYTES)
        {
            return None;
        }
        let group_id = change
            .get("groupId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let editor = change
            .get("editor")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|aci| !aci.is_empty() && aci.len() <= GROUP_UPDATED_EDITOR_MAX_BYTES)
            .map(str::to_string);
        let expire_timer_seconds = change
            .get("expireTimerSeconds")
            .and_then(Value::as_u64)
            .and_then(|seconds| u32::try_from(seconds).ok());
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id,
            control: ControlReceive::GroupChanged {
                revision,
                changes,
                editor,
                expire_timer_seconds,
            },
        });
    }
    // The engine's `groupTerminated` projection (contract 1.134, §4.117): a
    // decrypted group change named the group terminated, the whole envelope
    // replaced with the event. It routes by its own groupId — the
    // conversation-less transient family like the story face, though the
    // groupId names its subject, so the routing address carries it and the
    // service layer forwards the event verbatim without any conversation
    // resolution (a terminated group's row may already be gone). The
    // guaranteed subject fails closed like the groupUpdated arm: a face
    // with no groupId is a protocol error and falls to the plain skip;
    // `terminator` rides the same bounded ACI form the group projections
    // read, absent stays absent (宁缺勿错, never a mangled one).
    if let Some(terminated) = envelope.get("groupTerminated").and_then(Value::as_object) {
        let group_id = terminated
            .get("groupId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)?;
        let terminator = terminated
            .get("terminator")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|aci| !aci.is_empty() && aci.len() <= GROUP_UPDATED_EDITOR_MAX_BYTES)
            .map(str::to_string);
        let timestamp = terminated.get("timestamp").and_then(Value::as_u64);
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: Some(group_id.clone()),
            control: ControlReceive::GroupTerminated {
                group_id,
                terminator,
                timestamp,
            },
        });
    }
    // The engine's `contactProfileUpdated` projection (contract 1.134,
    // §4.117): a peer's profileKeyUpdate batch landed a new profile key.
    // Conversation-less — the `aci` names its subject and the routing
    // carries no conversation at all; the face forwards as the transient
    // notify and the desktop re-pulls the profile on demand. The subject
    // fails closed like the groupTerminated arm above (no aci = protocol
    // error = plain skip); the envelope's own timestamp rides the
    // NormalizedReceive as on every face.
    if let Some(updated) = envelope
        .get("contactProfileUpdated")
        .and_then(Value::as_object)
    {
        let aci = updated
            .get("aci")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|aci| !aci.is_empty() && aci.len() <= MAX_RECEIVE_ID_CHARS)
            .map(str::to_string)?;
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::ContactProfileUpdated { aci },
        });
    }
    // The official `syncMessage.messageRequestResponse` mirror (contract
    // 1.70, §4.58 consume batch): our own linked device answered a
    // conversation's message request — the ACCEPT stamp the §4.58 read
    // derivation previously recorded as having no honest source. It routes as
    // a control receive (the groupUpdated projection precedent) addressed by
    // the thread leg; a malformed or UNKNOWN-shaped face returns None and the
    // envelope falls through to the plain syncMessage skip.
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(face) = sync
            .get("messageRequestResponse")
            .and_then(Value::as_object)
        && let Some(control) = normalized_message_request_response(face)
    {
        // The ControlReceive carries the thread leg twice by design (the
        // routing group id and the stamped payload); one clone keeps both.
        let ControlReceive::MessageRequestResponse { group_id, .. } = &control else {
            unreachable!("the projection only answers this variant");
        };
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: group_id.clone(),
            control,
        });
    }
    // The engine's `syncMessage.read[]` / `.viewed[]` projection (contract
    // 1.100, §4.81): the account's own linked device marked upstream
    // messages read (or viewed). The face is intercepted before the plain
    // syncMessage skip like its messageRequestResponse sibling; an envelope
    // whose entries all failed the bounds falls through to that skip. The
    // routing source stays None — the envelope is our own account, the
    // entries name their own senders (the view-once open precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object) {
        let read = normalized_sync_read_entries(sync.get("read"));
        let viewed = normalized_sync_read_entries(sync.get("viewed"));
        if !read.is_empty() || !viewed.is_empty() {
            return Some(ControlRouting {
                direction: "incoming",
                source: None,
                group_id: None,
                control: ControlReceive::SyncReadState { read, viewed },
            });
        }
    }
    // The engine's `syncMessage.deleteForMe` projection (contract 1.102,
    // §4.83; the two conversation arms added by contract 1.182, §4.182):
    // the account's own linked device deleted messages for itself — the
    // official #handleDeleteForMeSync face. Intercepted before the plain
    // syncMessage skip like its read/viewed sibling; an envelope whose
    // every arm failed the bounds falls through to that skip. The routing
    // source stays None — the envelope is our own account; the groups name
    // their own conversations and the entries their own authors (the
    // read/viewed precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object) {
        let deletes = normalized_sync_delete_for_me(sync.get("deleteForMe"));
        if !deletes.is_empty() {
            return Some(ControlRouting {
                direction: "incoming",
                source: None,
                group_id: None,
                control: ControlReceive::SyncDeleteForMe { deletes },
            });
        }
    }
    // The engine's `syncMessage.verified` projection (contract 1.103,
    // §4.84): the account's own linked device settled one peer's
    // safety-number trust state. Intercepted before the plain syncMessage
    // skip like its read/viewed/delete-for-me siblings; an envelope whose
    // face failed the shape gates falls through to that skip. The routing
    // source stays None — the envelope is our own account and the record
    // names its own destination (the read/viewed precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(verified) = normalized_sync_verified(sync.get("verified"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncVerified { verified },
        });
    }
    // The engine's `syncMessage.callEvent` projection (contract 1.104,
    // §4.85): the account's own linked device wrote one call-history entry —
    // the official callEventSync face. Intercepted before the plain
    // syncMessage skip like its verified sibling; an envelope whose face
    // failed the shape gates falls through to that skip. The routing source
    // stays None — the envelope is our own account and the record names its
    // own conversation (the read/viewed precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(event) = normalized_sync_call_event(sync.get("callEvent"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncCallEvent { event },
        });
    }
    // The engine's `syncMessage.configuration` projection (contract 1.106,
    // §4.87): the account's own linked device changed the four official
    // settings flags — the official handleConfiguration face. Intercepted
    // before the plain syncMessage skip like its verified/callEvent
    // siblings; a face whose flags all failed the per-key reads falls
    // through to that skip. The routing source stays None — the envelope is
    // our own account (the read/viewed precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(configuration) = normalized_sync_configuration(sync.get("configuration"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncConfiguration { configuration },
        });
    }
    // The engine's `syncMessage.fetchLatest` projection (contract 1.106,
    // §4.87): the account's own linked device asked this client to refresh
    // one named surface — the official handleFetchLatest trigger. The arm's
    // presence is the signal (the official fires the event even with the
    // type unset); the optional word rides the SCREAMING whitelist
    // per-key-fail-closed. The routing source stays None (the same own-
    // account precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(kind) = normalized_sync_fetch_latest(sync.get("fetchLatest"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncFetchLatest { kind },
        });
    }
    // The engine's `syncMessage.callLinkUpdate` projection (contract 1.106,
    // §4.87): the account's own linked device updated one call link's
    // credential material — the official handleCallLinkUpdate face. The
    // verb/rootKey hard gates drop a face that names nothing; the routing
    // source stays None (the own-account precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(update) = normalized_sync_call_link_update(sync.get("callLinkUpdate"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncCallLinkUpdate { update },
        });
    }
    // The engine's `syncMessage.callLogEvent` projection (contract 1.106,
    // §4.87): the account's own linked device mutated one call-history
    // record — the official handleCallLogEvent face. The verb hard gate
    // drops a face that is no mutation; the routing source stays None (the
    // own-account precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(event) = normalized_sync_call_log_event(sync.get("callLogEvent"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncCallLogEvent { event },
        });
    }
    // The engine's `syncMessage.deviceNameChange` projection (contract
    // 1.106, §4.87): the account renamed one linked device — the official
    // handleDeviceNameChangeSync face. The deviceId hard gate mirrors the
    // official's own absent-key drop; the local-device-id comparison stays
    // the desktop's decision. The routing source stays None (the own-account
    // precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(device_id) = normalized_sync_device_name_change(sync.get("deviceNameChange"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncDeviceNameChange { device_id },
        });
    }
    // The engine's `syncMessage.usernameChange` projection (contract 1.106,
    // §4.87): the account's own linked device changed the username — the
    // official handleUsernameChangeSync face, an empty pure-signal sync whose
    // consumption is one profile re-fetch. The arm's presence is the whole
    // content; the routing source stays None (the own-account precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(_face) = sync.get("usernameChange").and_then(Value::as_object)
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncUsernameChange,
        });
    }
    // The engine's `syncMessage.attachmentBackfillResponse` projection
    // (contract revision 1.175, §4.175): the primary device answered our
    // backfill request with fresh transit pointers — the official
    // #handleAttachmentBackfillResponse face. Intercepted before the plain
    // syncMessage skip like its read/viewed/delete-for-me siblings; a face
    // whose target or conversation failed the shape gates falls through to
    // that skip. The routing source stays None — the envelope is our own
    // account and the target names its own conversation (the read/viewed
    // precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(response) =
            normalized_sync_attachment_backfill_response(sync.get("attachmentBackfillResponse"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncAttachmentBackfillResponse { response },
        });
    }
    // The engine's `syncMessage.pniChangeNumber` projection (contract
    // 1.106, §4.87): the account's own number re-registration moved its PNI
    // identity — the official handlePNIChangeNumber face, forwarded as the
    // engine's stripped `{registrationId?, newE164?}` face (the key material
    // never crosses the engine boundary). A face with no surviving key is a
    // zero-content sync and falls through to the plain skip. The routing
    // source stays None (the own-account precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(change) = normalized_sync_pni_change_number(sync.get("pniChangeNumber"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncPniChangeNumber { change },
        });
    }
    // The engine's `syncMessage.contacts` projection (contract 1.136,
    // §4.122): the phone pushed its contact set to the linked devices — the
    // official handleContacts consume face. Intercepted before the plain
    // syncMessage skip like its read/viewed/delete-for-me siblings; an
    // envelope whose records all failed the bounds (or carried none) falls
    // through to that skip — the `complete` flag alone is the pull path's
    // concern, not a cache write. The routing source stays None — the
    // envelope is our own account and the records name their own subjects
    // (the read/viewed precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object) {
        let contacts = normalized_sync_contact_records(sync.get("contacts"));
        if !contacts.is_empty() {
            return Some(ControlRouting {
                direction: "incoming",
                source: None,
                group_id: None,
                control: ControlReceive::SyncContacts { contacts },
            });
        }
    }
    // The engine's `syncMessage.blocked` projection (contract 1.140,
    // §4.136): the account's own linked device replaced its block list — the
    // official _handleBlocked mirror. Intercepted before the plain
    // syncMessage skip like its contacts sibling; an envelope whose every
    // key failed the tolerant read (or carried no identity at all — the
    // fully-empty list projects an empty object) falls through to that
    // skip. The routing source stays None — the envelope is our own
    // account and the identities name their own subjects (the read/viewed
    // precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some(blocked) = normalized_sync_blocked(sync.get("blocked"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncBlocked { blocked },
        });
    }
    // The engine's `syncMessage.storyRecipientUpdate` projection (contract
    // 1.154, §4.153): the account's own devices learned one of its stories'
    // recipients changed — the story batch S5's receive leg ② (the
    // deleteStoryForEveryone self-sync fan-out plus the multi-list story
    // send's isUpdate sync shape, the official StoryRecipientUpdateEvent
    // mirror). Intercepted before the plain syncMessage skip like its
    // verified/callEvent siblings; a face whose timestamp failed the gate or
    // whose entries all failed the shapes falls through to that skip. The
    // routing source stays None — the envelope is our own account (the
    // read/viewed precedent).
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object)
        && let Some((timestamp, recipients)) =
            normalized_sync_story_recipient_update(sync.get("storyRecipientUpdate"))
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: None,
            group_id: None,
            control: ControlReceive::SyncStoryRecipientUpdate {
                timestamp,
                recipients,
            },
        });
    }
    // Call signaling (contract 1.51, §4.49): the engine's callMessage
    // projection routes like every body-less control face — an empty or
    // out-of-budget face returns None and the envelope falls through to the
    // plain skip.
    if let Some(call) = envelope
        .get("callMessage")
        .and_then(Value::as_object)
        .and_then(normalized_call_message)
    {
        return Some(ControlRouting {
            direction: "incoming",
            source: envelope_peer_source(envelope),
            group_id: None,
            control: call,
        });
    }
    // Ephemeral typing indicator.
    if let Some(typing) = envelope.get("typingMessage").and_then(Value::as_object) {
        let action = typing
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("START")
            .to_string();
        let group_id = typing
            .get("groupId")
            .and_then(Value::as_str)
            .map(str::to_string);
        return Some(ControlRouting {
            direction: "incoming",
            source: envelope_peer_source(envelope),
            group_id,
            control: ControlReceive::Typing { action },
        });
    }
    // Peer receipt confirming our outgoing rows (delivery / read / viewed).
    // Viewed maps to `read` on the wire: the desktop's status ladder is
    // sent → delivered → read; there is no fourth tier to surface.
    if let Some(receipt) = envelope.get("receiptMessage").and_then(Value::as_object) {
        let kind = if receipt.get("isViewed").and_then(Value::as_bool) == Some(true) {
            ReceiptKind::Viewed
        } else if receipt.get("isRead").and_then(Value::as_bool) == Some(true) {
            ReceiptKind::Read
        } else {
            ReceiptKind::Delivered
        };
        let mut timestamps: Vec<u64> = receipt
            .get("timestamp")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        timestamps.truncate(MAX_RECEIPT_TIMESTAMPS);
        timestamps.dedup();
        if timestamps.is_empty() {
            return None;
        }
        return Some(ControlRouting {
            direction: "incoming",
            source: envelope_peer_source(envelope),
            // Contract 1.190 (§4.190): the proto carries no recipient — the
            // envelope source IS the per-recipient identity (the official
            // receiver's own attribution, MessageReceiver.preload.ts:2849-2855).
            // The group key stays None: a receipt addresses our outgoing rows
            // by timestamp, never a conversation (the account-level find).
            group_id: None,
            control: ControlReceive::Receipt {
                kind,
                timestamps,
                // Contract 1.32: the receipt's own envelope timestamp backs the
                // desktop's delivered/read timeline.
                when: envelope.get("timestamp").and_then(Value::as_u64),
                recipient: envelope_peer_source(envelope),
            },
        });
    }
    None
}

/// The disappearing-message keys one dataMessage face carries (contract
/// 1.42, §4.41). Both engine faces share the shape: `expiresInSeconds` is the
/// stated timer — every signal-cli `JsonDataMessage` carries it (0 = the
/// sender's timer is off), the engine face omits the key when it has nothing
/// to say — and `expirationStartTimestamp` (>0) is the engine-only countdown
/// start the signal-cli face never exposes.
fn envelope_expire_keys(message: &serde_json::Map<String, Value>) -> (Option<u64>, Option<u64>) {
    let seconds = message.get("expiresInSeconds").and_then(Value::as_u64);
    let start_at = message
        .get("expirationStartTimestamp")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    (seconds, start_at)
}

/// Decorate a normalized receive with the face's expire keys.
fn with_expire(
    mut receive: NormalizedReceive,
    seconds: Option<u64>,
    start_at: Option<u64>,
) -> NormalizedReceive {
    receive.expire_seconds = seconds;
    receive.expire_start_at = start_at;
    receive
}

/// The timer-notice system row's text material (contract 1.42, §4.41): the
/// announced value rides the text so the desktop renders the change without
/// parsing protocol state; `0` and the absent-key close form both read as
/// off. Localized copy is the desktop's job — this is the raw material.
fn timer_change_text(seconds: Option<u64>) -> Option<NormalizedText> {
    let text = match seconds {
        Some(value) if value > 0 => format!("已更新消息定时消失：{value} 秒"),
        _ => "已更新消息定时消失：已关闭".to_string(),
    };
    normalized_text(&text)
}

/// The string form of the timer-notice material, for a service-layer row
/// assembly that fills its own text columns (the bounded triple stays the
/// engine receive face's shape).
pub(crate) fn timer_change_material(seconds: Option<u64>) -> Option<String> {
    timer_change_text(seconds).map(|text| text.value)
}

/// The rich marker a timer-notice row carries (its only rich content).
pub(crate) fn timer_change_rich() -> NormalizedRich {
    NormalizedRich {
        is_expiration_update: true,
        ..Default::default()
    }
}

/// The group-update system row's text material (contract 1.45, §4.44): the
/// receive face's `JsonGroupInfo` carries no actor and no before/after, so
/// the copy is one generic line the desktop localizes — the resulting title
/// rides `rich.group_name` as mirror material, never as rendered text.
fn group_update_text() -> Option<NormalizedText> {
    normalized_text("群聊信息已更新")
}

/// The structured group-change face off one `groupInfo` object (§4.227):
/// the bounded verbatim `changes[]` — entries past the
/// `GROUP_CHANGED_MAX_CHANGES` cap truncate, material over the coarse
/// `MAX_GROUP_CHANGED_BYTES` guard drops the whole face (宁缺勿错, never a
/// truncated lie — the §4.81 posture) — the resulting `revision` when it
/// names a real u32, and the `editor` ACI under the shared bounded form.
/// Presence without material (`changes` missing/empty) is no face — the
/// §4.38 import chain's `details` posture; a face without `changes` can
/// never exist.
fn normalized_group_change(info: &serde_json::Map<String, Value>) -> Option<NormalizedGroupChange> {
    let raw_changes = info.get("changes")?.as_array()?;
    if raw_changes.is_empty() {
        return None;
    }
    let mut bounded = raw_changes.clone();
    bounded.truncate(crate::service::GROUP_CHANGED_MAX_CHANGES);
    if serde_json::to_string(&bounded)
        .is_ok_and(|material| material.len() > MAX_GROUP_CHANGED_BYTES)
    {
        return None;
    }
    let revision = info
        .get("revision")
        .and_then(Value::as_u64)
        .and_then(|revision| u32::try_from(revision).ok());
    let editor = info
        .get("editor")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|aci| !aci.is_empty() && aci.len() <= GROUP_UPDATED_EDITOR_MAX_BYTES)
        .map(str::to_string);
    Some(NormalizedGroupChange {
        revision,
        editor,
        changes: bounded,
    })
}

/// The rich marker a group-update row carries (§4.44): the flag plus the
/// engine's post-change title when the update supplied one, and the
/// structured §4.227 change vocabulary when the update carried it.
fn group_update_rich(
    group_name: Option<String>,
    group_change: Option<NormalizedGroupChange>,
) -> NormalizedRich {
    NormalizedRich {
        is_group_update: true,
        group_name,
        group_change,
        ..Default::default()
    }
}

/// Our own multi-device control echo inside `syncMessage.sentMessage`: edit /
/// remote delete / pin / unpin / admin delete / reaction of an earlier message
/// we sent from the phone. The pin family rides the same normalized shapes the
/// peer `dataMessage` faces use (engine projection
/// `project_data_message`@`src/service/mod.rs:9204-9231`).
fn sync_sent_control(sent: &serde_json::Map<String, Value>) -> Option<ControlReceive> {
    if let Some(edit) = sent.get("editMessage").and_then(Value::as_object)
        && let Some(target) = edit.get("targetSentTimestamp").and_then(Value::as_u64)
    {
        return Some(ControlReceive::Edit {
            target_timestamp: target,
        });
    }
    if let Some(target) = sent
        .get("remoteDelete")
        .and_then(Value::as_object)
        .and_then(|object| object.get("timestamp"))
        .and_then(Value::as_u64)
    {
        return Some(ControlReceive::RemoteDelete {
            target_timestamp: target,
        });
    }
    if let Some(pin) = sent.get("pinMessage").and_then(normalized_pin_message) {
        return Some(pin);
    }
    if let Some(unpin) = sent.get("unpinMessage").and_then(normalized_unpin_message) {
        return Some(unpin);
    }
    if let Some(admin_delete) = sent.get("adminDelete").and_then(normalized_admin_delete) {
        return Some(admin_delete);
    }
    if let Some(target) = sent
        .get("pollTerminate")
        .and_then(Value::as_object)
        .and_then(|object| object.get("targetSentTimestamp"))
        .and_then(Value::as_u64)
        .filter(|target| *target > 0)
    {
        return Some(ControlReceive::PollTerminate {
            target_timestamp: target,
        });
    }
    if let Some(vote) = sent
        .get("pollVote")
        .and_then(Value::as_object)
        .and_then(normalized_poll_vote)
    {
        return Some(vote);
    }
    sent.get("reaction").and_then(normalized_reaction)
}

fn normalize_receive_fields(params: &Value) -> Result<NormalizedReceive, EngineError> {
    let payload = params.get("result").unwrap_or(params);
    let envelope = payload
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or(EngineError::Protocol)?;
    let account = payload
        .get("account")
        .and_then(Value::as_str)
        .map(str::to_string);
    let account_present = payload.get("account").is_some();
    let timestamp = envelope.get("timestamp").and_then(Value::as_u64);
    let peer_source = envelope_peer_source(envelope);
    let peer_name = envelope
        .get("sourceName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect::<String>());
    let source_uuid = envelope
        .get("sourceUuid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // The reportSpam companion bit (contract revision 1.49, §4.48): the
    // engine projects the server-assigned message GUID on the envelope's
    // public metadata when present (proto only projects, never invents).
    let server_guid = envelope
        .get("serverGuid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
    // The server-time key (contract revision 1.128, §4.109): the engine
    // projects `serverTimestamp` on every receive envelope — the
    // server-recorded receive time (P15c 项5, the official event face's
    // same-position key). The proto-absent envelope still projects 0 (the
    // official `?? 0n` sentinel), so 0 folds to None here — an unknown
    // server time stores as NULL, never as the epoch.
    let server_timestamp = envelope
        .get("serverTimestamp")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    // The spam-report token (reportSpam data plane): the engine projects the
    // envelope's `reportingToken` (base64 std of the proto `reportSpamToken`)
    // when present — the official `Bytes.isNotEmpty` non-empty gate mirrors
    // here (empty string folds to None). Latest-wins onto the conversation at
    // ingest; the report face attaches it to the POST body verbatim. An
    // over-bound token folds to None — a credential is never truncated
    // (silently corrupting it would mis-address the report upstream).
    let reporting_token = envelope
        .get("reportingToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.chars().count() <= MAX_REPORTING_TOKEN_CHARS)
        .map(str::to_string);

    // 契约 §4.220：engine 在接收信封上投影 `requiredProtocolVersion`
    //（service/mod.rs:9594）。高于本端支持版本时对端可能无法完整解析该消息。
    // 解析纪律与紧邻的 serverTimestamp 同形：只认有限正整数，0 与越界折 None
    //（缺席 = 未声明，不发明值）。
    let required_protocol_version = envelope
        .get("requiredProtocolVersion")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= u64::from(u32::MAX))
        .map(|value| value as u32);

    let make = |timestamp: Option<u64>,
                content_kind: &'static str,
                direction: &'static str,
                source: Option<String>,
                group_id: Option<String>,
                text: Option<NormalizedText>,
                quote: Option<NormalizedQuote>,
                attachments: Vec<NormalizedAttachment>,
                rich: Option<NormalizedRich>,
                control: Option<ControlReceive>| NormalizedReceive {
        required_protocol_version,
        timestamp,
        content_kind,
        direction,
        account_present,
        account: account.clone(),
        source,
        source_uuid: source_uuid.clone(),
        peer_name: peer_name.clone(),
        group_id,
        text: text.as_ref().map(|value| value.value.clone()),
        text_bytes: text.as_ref().map(|value| value.bytes),
        text_truncated: text.is_some_and(|value| value.truncated),
        quote,
        attachments,
        rich,
        sticker: None,
        control,
        expire_seconds: None,
        expire_start_at: None,
        server_guid: server_guid.clone(),
        server_timestamp,
        reporting_token: reporting_token.clone(),
    };

    // Typing and body-less reaction / remote-delete receives carry no message
    // row; they route as control events and never persist.
    if let Some(routing) = control_routing(envelope) {
        let ControlRouting {
            direction,
            source,
            group_id,
            control,
        } = routing;
        return Ok(make(
            timestamp,
            "control",
            direction,
            source,
            group_id,
            None,
            None,
            Vec::new(),
            None,
            Some(control),
        ));
    }

    // Story receives (contract 1.76, §4.67): the envelope-level `storyMessage`
    // face. The story body is not a conversation message — it routes as
    // control-plane material (the call-signaling posture): no row, the
    // bounded projection forwards verbatim, and the stories-disabled gate is
    // the service layer's. The envelope `isStory` bit is the same fact and
    // rides story sends and group story replies alike; the bit alone never
    // routes (a remote delete under a story bit was already consumed by the
    // control ladder above — the official exempt leg). An oversized or
    // otherwise unusable face drops the whole envelope (宁缺勿错).
    if let Some(story_message) = envelope.get("storyMessage").and_then(Value::as_object) {
        return Ok(match bounded_story_material(story_message) {
            Some(message) => make(
                timestamp,
                "storyMessage",
                "incoming",
                peer_source,
                None,
                None,
                None,
                Vec::new(),
                None,
                Some(ControlReceive::Story { message }),
            ),
            None => make(
                timestamp,
                "storyMessage",
                "skip",
                peer_source,
                None,
                None,
                None,
                Vec::new(),
                None,
                None,
            ),
        });
    }

    // Multi-device: phone/other linked device sent a text → show as our outgoing.
    if let Some(sync) = envelope.get("syncMessage").and_then(Value::as_object) {
        // Our own linked device received a peer's view-once open notification
        // (contract 1.38): the service layer resolves the target row across
        // conversations, so no session routing applies. A missing senderAci
        // has no resolvable target — drop as skip rather than invent one.
        if let Some(open) = sync.get("viewOnceOpen").and_then(Value::as_object) {
            let sender_aci = open
                .get("senderAci")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(MAX_RECEIVE_ID_CHARS).collect::<String>());
            let Some(sender_aci) = sender_aci else {
                return Ok(make(
                    timestamp,
                    "syncMessage",
                    "skip",
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                    None,
                ));
            };
            let open_timestamp = open.get("timestamp").and_then(Value::as_u64).unwrap_or(0);
            return Ok(make(
                timestamp,
                "control",
                "incoming",
                None,
                None,
                None,
                None,
                Vec::new(),
                None,
                Some(ControlReceive::ViewOnceOpen {
                    sender_aci,
                    timestamp: open_timestamp,
                }),
            ));
        }
        if let Some(sent) = sync.get("sentMessage").and_then(Value::as_object) {
            // JsonUnwrapped dataMessage fields sit on sentMessage itself.
            // A sticker transcript carries no body (official DataMessage
            // .Sticker semantics — the sticker is the whole content and
            // official clients send the body empty): cut a stale/non-empty
            // body at the normalization authority so it never reaches the
            // row's text column (the desktop would render it as a phantom
            // body line under the sticker block). The shape probe runs
            // before the state faces below; the full sticker face still
            // parses at its ladder position further down.
            let sticker_present = sent.get("sticker").and_then(Value::as_object).is_some();
            let text = data_message_text(sent).filter(|_| !sticker_present);
            let group_id = data_message_group_id(sent);
            let quote = sent.get("quote").and_then(normalized_quote);
            let mut attachments = sent
                .get("attachments")
                .map(normalized_attachments)
                .unwrap_or_default();
            let mut rich = normalized_rich(sent);
            let (expire_seconds, expire_start_at) = envelope_expire_keys(sent);
            let destination = sent
                .get("destinationNumber")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    sent.get("destinationUuid")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .or_else(|| {
                    sent.get("destination")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                });
            // Our own multi-device edit / delete / reaction of an earlier
            // message mirrors as a control receive keyed by its target.
            if text.is_none()
                && quote.is_none()
                && attachments.is_empty()
                && rich.is_none()
                && let Some(control) = sync_sent_control(sent)
            {
                return Ok(make(
                    sent.get("timestamp").and_then(Value::as_u64).or(timestamp),
                    "control",
                    "outgoing",
                    destination,
                    group_id,
                    None,
                    None,
                    Vec::new(),
                    None,
                    Some(control),
                ));
            }
            let sent_ts = sent.get("timestamp").and_then(Value::as_u64).or(timestamp);
            // The own-story multi-device transcript (contract 1.160, §4.158):
            // the account posted a story from another linked device — the
            // engine's `sentMessage.storyMessage` projection riding home.
            // The official ladder sits the story face after the edit arm and
            // the storyRecipientUpdate gate (which the engine's sync
            // projection has already split into its own envelope-level key),
            // before the ordinary sent-message material — the same order
            // here, right after the control ladder. The bounded story face
            // forwards verbatim (the §4.67 bound; an oversized or otherwise
            // unusable face keeps the plain skip, 宁缺勿错), and a sync
            // with no anchor timestamp has no story to date and keeps the
            // skip too. The direction is the 自发同步 posture — the self
            // send's own timestamp, never an unread.
            if let Some(story) = sent.get("storyMessage").and_then(Value::as_object) {
                return Ok(match sent_ts.zip(bounded_story_material(story)) {
                    Some((story_ts, message)) => make(
                        Some(story_ts),
                        "storyMessage",
                        "outgoing",
                        destination,
                        group_id,
                        None,
                        None,
                        Vec::new(),
                        None,
                        Some(ControlReceive::SyncStoryMessage { message }),
                    ),
                    None => make(
                        sent_ts,
                        "storyMessage",
                        "skip",
                        destination,
                        group_id,
                        None,
                        None,
                        Vec::new(),
                        None,
                        None,
                    ),
                });
            }
            // Our own device set the conversation's disappearing timer (the
            // phone-side toggle): the mirror is the same timer-notice system
            // row a peer's change lands as (§4.41), addressed by destination.
            if text.is_none()
                && quote.is_none()
                && attachments.is_empty()
                && rich.as_ref().is_some_and(|rich| rich.is_expiration_update)
            {
                return Ok(with_expire(
                    make(
                        sent_ts,
                        "syncMessage",
                        "system",
                        destination,
                        group_id,
                        timer_change_text(expire_seconds),
                        None,
                        Vec::new(),
                        Some(timer_change_rich()),
                        None,
                    ),
                    expire_seconds,
                    expire_start_at,
                ));
            }
            // Our own device edited the group from the phone (contract 1.45,
            // §4.44): the bodyless mirror lands as the same generic system row
            // a peer's change does — the title mirror is the service layer's
            // job off the rich material. A timer flag outranks it.
            if text.is_none()
                && quote.is_none()
                && attachments.is_empty()
                && rich.as_ref().is_some_and(|rich| rich.is_group_update)
            {
                return Ok(make(
                    sent_ts,
                    "syncMessage",
                    "system",
                    destination,
                    group_id,
                    group_update_text(),
                    None,
                    Vec::new(),
                    Some(group_update_rich(
                        rich.as_ref().and_then(|rich| rich.group_name.clone()),
                        rich.as_ref().and_then(|rich| rich.group_change.clone()),
                    )),
                    None,
                ));
            }
            // Our own poll create (§4.118): the group-send transcript's
            // `poll` face rides the bodyless mirror — the same outgoing
            // row a peer's create lands as, in the account's own direction
            // (the 自发同步 posture: never an unread, the self send's own
            // timestamp). The face is the identical §4.38 shape; votes and
            // termination fold onto it as they arrive.
            if text.is_none()
                && quote.is_none()
                && attachments.is_empty()
                && rich.as_ref().is_some_and(|rich| rich.poll.is_some())
            {
                return Ok(with_expire(
                    make(
                        sent_ts,
                        "syncMessage",
                        "outgoing",
                        destination,
                        group_id,
                        None,
                        None,
                        Vec::new(),
                        rich,
                        None,
                    ),
                    expire_seconds,
                    expire_start_at,
                ));
            }
            // The sent transcript's sticker face (contract 1.136, §4.121):
            // the mirror parses beside the message exactly like the incoming
            // arm's (§4.32) — the `data` pointer joins the attachment list as
            // a regular metadata-only descriptor and the pack identity rides
            // the row's sticker face, so a phone-originated sticker renders
            // from the same outgoing row shape the connector's own
            // `messages.sendSticker` lands. Parsed after the control ladder
            // (a sticker + remoteDelete/edit/reaction echo keeps its control
            // routing) and after the state-face arms, so the rich faces keep
            // their precedence exactly like the text face's does; a sticker
            // with no usable data pointer has nothing renderable and keeps
            // the plain skip routing.
            let sticker = sent
                .get("sticker")
                .and_then(Value::as_object)
                .and_then(normalized_sticker);
            if let Some((_, sticker_image)) = sticker.as_ref() {
                attachments.push(sticker_image.clone());
            }
            // The sent transcript's contact card (contract 1.139, §4.132):
            // parsed beside the message exactly like the incoming arm's —
            // the same bounded face through the §4.38 authority, the wrapped
            // avatar pointer unwrapping onto the descriptor list. Parsed
            // after the control ladder (a contact + remoteDelete/edit/
            // reaction echo keeps its control routing — the merge below
            // happens after that ladder read) and after the state-face arms,
            // so the rich faces keep their precedence exactly like the text
            // face's does.
            let contact = normalized_live_contact(sent.get("contact"));
            if let Some((_, Some(avatar))) = contact.as_ref() {
                attachments.push(avatar.clone());
            }
            if let Some((card, _)) = contact.as_ref() {
                rich.get_or_insert_with(NormalizedRich::default).contact = Some(card.clone());
            }
            let with_sticker = |mut outgoing: NormalizedReceive| {
                if let Some((sticker_meta, _)) = sticker.as_ref() {
                    outgoing.sticker = Some(sticker_meta.clone());
                }
                outgoing
            };
            if let Some(text) = text {
                return Ok(with_expire(
                    with_sticker(make(
                        sent_ts,
                        "syncMessage",
                        "outgoing",
                        destination,
                        group_id,
                        Some(text),
                        quote,
                        attachments,
                        rich,
                        None,
                    )),
                    expire_seconds,
                    expire_start_at,
                ));
            }
            // Attachment-only multi-device send: no body but real descriptors.
            // A sticker-only send lands here through its data descriptor.
            if !attachments.is_empty() {
                return Ok(with_expire(
                    with_sticker(make(
                        sent_ts,
                        "syncMessage",
                        "outgoing",
                        destination,
                        group_id,
                        None,
                        quote,
                        attachments,
                        rich,
                        None,
                    )),
                    expire_seconds,
                    expire_start_at,
                ));
            }
            // Bodyless pure-quote send (§4.121): the quote is the whole
            // content — the same outgoing row the quoted-text send lands as,
            // the self send's own timestamp, never an unread.
            if let Some(quote) = quote {
                return Ok(with_expire(
                    make(
                        sent_ts,
                        "syncMessage",
                        "outgoing",
                        destination,
                        group_id,
                        None,
                        Some(quote),
                        attachments,
                        rich,
                        None,
                    ),
                    expire_seconds,
                    expire_start_at,
                ));
            }
            // Bodyless contact-only send (contract 1.139, §4.132): the
            // shared contact is the whole content — the same outgoing row a
            // peer's card lands as, the self send's own timestamp, never an
            // unread (the 自发同步 posture). A card with no usable content
            // answered no face above and keeps the plain skip.
            if rich.as_ref().is_some_and(|rich| rich.contact.is_some()) {
                return Ok(with_expire(
                    make(
                        sent_ts,
                        "syncMessage",
                        "outgoing",
                        destination,
                        group_id,
                        None,
                        None,
                        attachments,
                        rich,
                        None,
                    ),
                    expire_seconds,
                    expire_start_at,
                ));
            }
            // sent without body (other control sync) — skip for now
            return Ok(make(
                sent_ts,
                "syncMessage",
                "skip",
                destination,
                group_id,
                None,
                None,
                Vec::new(),
                rich,
                None,
            ));
        }
        // contacts/groups/read sync — ignore
        return Ok(make(
            timestamp,
            "syncMessage",
            "skip",
            peer_source,
            None,
            None,
            None,
            Vec::new(),
            None,
            None,
        ));
    }

    if let Some(data_message) = envelope.get("dataMessage").and_then(Value::as_object) {
        let group_id = data_message_group_id(data_message);
        let text = data_message_text(data_message);
        let quote = data_message.get("quote").and_then(normalized_quote);
        let mut attachments = data_message
            .get("attachments")
            .map(normalized_attachments)
            .unwrap_or_default();
        // Sticker (contract revision 1.35): the metadata normalizes beside the
        // message, and the `data` pointer joins the attachment descriptor list
        // as a regular metadata-only descriptor — byte fetches stay on the
        // existing media channel. A sticker with no usable data pointer has
        // nothing renderable and keeps the plain skip routing.
        let sticker = data_message
            .get("sticker")
            .and_then(Value::as_object)
            .and_then(normalized_sticker);
        // A sticker envelope carries no body (official DataMessage.Sticker
        // semantics — official clients send the body empty and the sticker
        // block is the whole row): cut a stale/non-empty body at the
        // normalization authority so it never reaches the row's text column
        // (the desktop would render it as a phantom body line under the
        // sticker block). Cut after the sticker probe, before every text
        // consumer below, so the sticker face wins and the body is dropped.
        let text = text.filter(|_| sticker.is_none());
        if let Some((_, sticker_image)) = sticker.as_ref() {
            attachments.push(sticker_image.clone());
        }
        // Live contact card (contract 1.139, §4.132): the bounded face
        // normalizes beside the message and the unwrapped avatar pointer
        // joins the descriptor list exactly like a sticker's `data` — byte
        // fetches stay on the existing media channel. A card with no usable
        // content answers no face (the import whole-card discipline); the
        // card rides the rich additive channel, so no store schema bump.
        let contact = normalized_live_contact(data_message.get("contact"));
        if let Some((_, Some(avatar))) = contact.as_ref() {
            attachments.push(avatar.clone());
        }
        let mut rich = normalized_rich(data_message);
        if let Some((card, _)) = contact.as_ref() {
            rich.get_or_insert_with(NormalizedRich::default).contact = Some(card.clone());
        }
        let (expire_seconds, expire_start_at) = envelope_expire_keys(data_message);
        let with_sticker =
            |mut receive: NormalizedReceive,
             sticker: Option<(NormalizedSticker, NormalizedAttachment)>| {
                receive.sticker = sticker.map(|(meta, _)| meta);
                receive
            };
        if let Some(text) = text {
            return Ok(with_expire(
                with_sticker(
                    make(
                        timestamp,
                        "dataMessage",
                        "incoming",
                        peer_source,
                        group_id,
                        Some(text),
                        quote,
                        attachments,
                        rich,
                        None,
                    ),
                    sticker,
                ),
                expire_seconds,
                expire_start_at,
            ));
        }
        // Attachment-only message: real descriptors, no body — a sticker row
        // lands here through its data descriptor.
        if !attachments.is_empty() {
            return Ok(with_expire(
                with_sticker(
                    make(
                        timestamp,
                        "dataMessage",
                        "incoming",
                        peer_source,
                        group_id,
                        None,
                        quote,
                        attachments,
                        rich,
                        None,
                    ),
                    sticker,
                ),
                expire_seconds,
                expire_start_at,
            ));
        }
        // Empty body: map a few control shapes to system rows; drop the rest.
        // A timer change is one of them (contract 1.42, §4.41): the
        // announced value rides the text material and the receive's
        // expire_seconds so the service layer mirrors the conversation state.
        if rich.as_ref().is_some_and(|rich| rich.is_expiration_update) {
            return Ok(with_expire(
                make(
                    timestamp,
                    "dataMessage",
                    "system",
                    peer_source,
                    group_id,
                    timer_change_text(expire_seconds),
                    None,
                    Vec::new(),
                    Some(timer_change_rich()),
                    None,
                ),
                expire_seconds,
                expire_start_at,
            ));
        }
        // Bodyless group-state change (contract 1.45, §4.44): the pre-1.45
        // shape fell through to the skip below and was swallowed. It projects
        // as a generic system row; the rich marker carries the resulting
        // title for the service layer's conversation-title mirror.
        if rich.as_ref().is_some_and(|rich| rich.is_group_update) {
            return Ok(make(
                timestamp,
                "dataMessage",
                "system",
                peer_source,
                group_id,
                group_update_text(),
                None,
                Vec::new(),
                Some(group_update_rich(
                    rich.as_ref().and_then(|rich| rich.group_name.clone()),
                    rich.as_ref().and_then(|rich| rich.group_change.clone()),
                )),
                None,
            ));
        }
        // Live poll create (§4.118): the bodyless `dataMessage.poll`
        // envelope is a real message row — the poll bubble the official
        // timeline renders — carrying the same NormalizedPoll face the
        // §4.38 import chain lands (votes/termination fold in later).
        // Anything else bodyless keeps the skip.
        if rich.as_ref().is_some_and(|rich| rich.poll.is_some()) {
            return Ok(with_expire(
                make(
                    timestamp,
                    "dataMessage",
                    "incoming",
                    peer_source,
                    group_id,
                    None,
                    quote,
                    attachments,
                    rich,
                    None,
                ),
                expire_seconds,
                expire_start_at,
            ));
        }
        // Bodyless live contact (contract 1.139, §4.132): the shared-contact
        // bubble is a real message row — the same NormalizedContact face the
        // §4.38 import chain lands, the unwrapped avatar already riding the
        // descriptor list above. Checked after the state faces so their
        // precedence is untouched (a state marker never coexists with a
        // card); anything else bodyless keeps the skip.
        if rich.as_ref().is_some_and(|rich| rich.contact.is_some()) {
            return Ok(with_expire(
                make(
                    timestamp,
                    "dataMessage",
                    "incoming",
                    peer_source,
                    group_id,
                    None,
                    quote,
                    attachments,
                    rich,
                    None,
                ),
                expire_seconds,
                expire_start_at,
            ));
        }
        // Bodyless live gift badge (contract 1.181, §4.181): the official
        // gift-badge message carries no body — the badge is the whole row
        // (processDataMessage.preload.ts:476 lands it on the message model
        // with no text arm). The same NormalizedGiftBadge face the §4.38
        // import chain lands, checked beside the poll/contact bodyless
        // arms; anything else bodyless keeps the skip.
        if rich.as_ref().is_some_and(|rich| rich.gift_badge.is_some()) {
            return Ok(with_expire(
                make(
                    timestamp,
                    "dataMessage",
                    "incoming",
                    peer_source,
                    group_id,
                    None,
                    quote,
                    attachments,
                    rich,
                    None,
                ),
                expire_seconds,
                expire_start_at,
            ));
        }
        return Ok(make(
            timestamp,
            "dataMessage",
            "skip",
            peer_source,
            group_id,
            None,
            None,
            Vec::new(),
            None,
            None,
        ));
    }

    // Top-level editMessage envelope: a peer edited an earlier message.
    if let Some(edit) = envelope.get("editMessage").and_then(Value::as_object) {
        if let Some(target) = edit.get("targetSentTimestamp").and_then(Value::as_u64) {
            let new_text = edit
                .get("dataMessage")
                .and_then(Value::as_object)
                .and_then(|data| data.get("message"))
                .and_then(Value::as_str)
                .and_then(normalized_text);
            if let Some(new_text) = new_text {
                return Ok(make(
                    timestamp,
                    "editMessage",
                    "incoming",
                    peer_source,
                    data_message_group_id(
                        edit.get("dataMessage")
                            .and_then(Value::as_object)
                            .unwrap_or(&serde_json::Map::new()),
                    ),
                    Some(new_text),
                    None,
                    Vec::new(),
                    None,
                    Some(ControlReceive::Edit {
                        target_timestamp: target,
                    }),
                ));
            }
        }
        return Ok(make(
            timestamp,
            "editMessage",
            "skip",
            peer_source,
            None,
            None,
            None,
            Vec::new(),
            None,
            None,
        ));
    }

    let content_kind = if envelope.contains_key("receiptMessage") {
        "receiptMessage"
    } else {
        "other"
    };
    Ok(make(
        timestamp,
        content_kind,
        "skip",
        peer_source,
        None,
        None,
        None,
        Vec::new(),
        None,
        None,
    ))
}

async fn stop_child(child: &Mutex<Child>, grace: Duration) {
    let mut child = child.lock().await;
    if timeout(grace, child.wait()).await.is_err() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

fn prepare_data_dir(path: &Path) -> std::io::Result<()> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signal data directory must be absolute",
        ));
    }
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signal data directory must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "signal data directory must belong to the current user",
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn event_channel() -> (
    broadcast::Sender<EngineEvent>,
    broadcast::Receiver<EngineEvent>,
) {
    broadcast::channel(EVENT_QUEUE_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn socks_proxy_parse_accepts_host_port() {
        assert_eq!(
            SocksProxy::parse("127.0.0.1:1080").unwrap(),
            SocksProxy {
                host: "127.0.0.1".into(),
                port: 1080,
            }
        );
        assert_eq!(SocksProxy::parse("proxy.local:7890").unwrap().port, 7890);
    }

    #[test]
    fn socks_proxy_parse_rejects_malformed_values() {
        for value in [
            "",
            "127.0.0.1",
            "127.0.0.1:",
            ":1080",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:abc",
            "127. 0.0.1:1080",
            "127.0.0.1:1080 ",
            "::1:1080",
            "fe80::1:1080",
        ] {
            assert!(
                SocksProxy::parse(value).is_err(),
                "proxy value must be rejected: {value:?}"
            );
        }
    }

    #[test]
    fn config_defaults_to_opt_out_media_ingest() {
        let config = EngineConfig::new(PathBuf::from("/bin/kt-engine"), PathBuf::from("/data"));
        assert!(!config.media_ingest);
    }

    /// Design §6.2/§6.6 (F6): the connector's graceful-stop wait must cover
    /// the engine's 10 s pipeline drain, or a legitimate shutdown is truncated
    /// into SIGKILL. The total budget is grace + margin = 12 s.
    #[test]
    fn default_shutdown_budget_covers_the_engine_pipeline_grace() {
        let config = EngineConfig::new(PathBuf::from("/bin/kt-engine"), PathBuf::from("/data"));
        assert_eq!(config.shutdown_grace, Duration::from_secs(10));
        assert_eq!(
            config.shutdown_grace + SHUTDOWN_TIMEOUT_MARGIN,
            Duration::from_secs(12)
        );
    }

    #[test]
    fn engine_args_match_the_launcher_shape() {
        let expected: Vec<std::ffi::OsString> = [
            "--data-dir",
            "/data",
            "jsonRpc",
            "--receive-mode",
            "on-start",
            "--ignore-attachments",
            "--ignore-stories",
            "--ignore-stickers",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert_eq!(engine_args(Path::new("/data"), false), expected);
    }

    /// Media opt-in (ADR 0004 gate 5): enabling `--media-ingest` changes the
    /// spawn argv by exactly one line — `--ignore-attachments` disappears;
    /// stories and stickers stay ignored and every other byte is unchanged.
    #[test]
    fn media_ingest_only_drops_ignore_attachments_from_the_argv() {
        let baseline = engine_args(Path::new("/data"), false);
        let media = engine_args(Path::new("/data"), true);
        let dropped: Vec<_> = baseline
            .iter()
            .filter(|arg| !media.contains(arg))
            .cloned()
            .collect();
        let added: Vec<_> = media
            .iter()
            .filter(|arg| !baseline.contains(arg))
            .cloned()
            .collect();
        assert_eq!(
            dropped,
            vec![std::ffi::OsString::from("--ignore-attachments")]
        );
        assert!(added.is_empty());
        // Stories and stickers are outside the media PoC in both shapes.
        assert!(baseline.contains(&std::ffi::OsString::from("--ignore-stories")));
        assert!(baseline.contains(&std::ffi::OsString::from("--ignore-stickers")));
        assert!(media.contains(&std::ffi::OsString::from("--ignore-stories")));
        assert!(media.contains(&std::ffi::OsString::from("--ignore-stickers")));
        // The config default stays opt-out.
        let config = EngineConfig::new(PathBuf::from("/bin/kt-engine"), PathBuf::from("/data"));
        assert!(!config.media_ingest);
    }

    #[test]
    fn receive_normalization_does_not_expose_message_or_identity() {
        let input = json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 42,
                "dataMessage": { "message": "private text" }
            }
        });
        let normalized = normalize_receive(&input).unwrap().unwrap();
        let encoded = serde_json::to_string(&normalized).unwrap();
        assert_eq!(normalized.timestamp, Some(42));
        assert_eq!(normalized.content_kind, "dataMessage");
        assert_eq!(normalized.direction, "incoming");
        assert_eq!(normalized.text.as_deref(), Some("private text"));
        assert_eq!(normalized.account.as_deref(), Some("+15555550100"));
        assert_eq!(normalized.source.as_deref(), Some("+15555550101"));
        // Host-facing serialization must not include identity or body fields.
        assert!(!encoded.contains("private text"));
        assert!(!encoded.contains("+155"));
        assert!(!encoded.contains("source"));
        assert!(!encoded.contains("\"text\""));
        assert!(encoded.contains("accountPresent"));
        assert!(encoded.contains("incoming"));
    }

    #[test]
    fn oversized_receive_text_is_projected_before_queueing() {
        let input = json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 42,
                "dataMessage": { "message": "a".repeat(MAX_INBOUND_TEXT_BYTES + 1) }
            }
        });
        let normalized = normalize_receive(&input).unwrap().unwrap();
        assert_eq!(
            normalized.text.as_ref().map(String::len),
            Some(MAX_INBOUND_TEXT_PREVIEW_BYTES)
        );
        assert_eq!(
            normalized.text_bytes,
            Some((MAX_INBOUND_TEXT_BYTES + 1) as u32)
        );
        assert!(normalized.text_truncated);
    }

    #[tokio::test]
    async fn receive_queue_enforces_byte_budget_and_releases_it_on_consume() {
        let (ingress, mut receives) = receive_channel();
        let receive = || NormalizedReceive {
            required_protocol_version: None,
            timestamp: Some(42),
            content_kind: "dataMessage",
            direction: "incoming",
            account_present: true,
            account: Some("+15555550100".into()),
            source: Some("+15555550101".into()),
            source_uuid: None,
            peer_name: None,
            group_id: None,
            text: Some("a".repeat(MAX_INBOUND_TEXT_BYTES)),
            text_bytes: Some(MAX_INBOUND_TEXT_BYTES as u32),
            text_truncated: false,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            sticker: None,
            control: None,
            expire_seconds: None,
            expire_start_at: None,
            server_guid: None,
            reporting_token: None,
            server_timestamp: None,
        };

        let mut admitted = 0;
        while matches!(
            timeout(Duration::from_millis(10), ingress.enqueue(receive())).await,
            Ok(Ok(EnqueueOutcome::Enqueued))
        ) {
            admitted += 1;
        }
        assert!(admitted > 1);
        assert!(admitted < RECEIVE_QUEUE_CAPACITY);

        drop(receives.recv().await.unwrap());
        timeout(Duration::from_secs(1), ingress.enqueue(receive()))
            .await
            .unwrap()
            .unwrap();
    }

    /// Packet 1.196: the per-account share. One account filling its own
    /// 64-slot budget drops its next receive immediately (never parking the
    /// actor), while a second account's share is untouched and its receive
    /// still admits. Draining one queued receive frees exactly one slot.
    #[tokio::test]
    async fn receive_queue_per_account_budget_isolates_a_flooding_account() {
        let (mut ingress, mut receives) = receive_channel();
        ingress.enqueue_timeout = Duration::from_millis(50);
        let receive = |account: &str| NormalizedReceive {
            required_protocol_version: None,
            timestamp: Some(42),
            content_kind: "dataMessage",
            direction: "incoming",
            account_present: true,
            account: Some(account.into()),
            source: Some("+15555550101".into()),
            source_uuid: None,
            peer_name: None,
            group_id: None,
            text: None,
            text_bytes: None,
            text_truncated: false,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            sticker: None,
            control: None,
            expire_seconds: None,
            expire_start_at: None,
            server_guid: None,
            reporting_token: None,
            server_timestamp: None,
        };

        let mut admitted = 0;
        while matches!(
            ingress.enqueue(receive("+15555550100")).await,
            Ok(EnqueueOutcome::Enqueued)
        ) {
            admitted += 1;
        }
        assert_eq!(admitted, RECEIVE_QUEUE_PER_ACCOUNT_CAPACITY);
        // The flooded account's overflow is an immediate drop, not a wait.
        assert_eq!(
            timeout(
                Duration::from_millis(50),
                ingress.enqueue(receive("+15555550100"))
            )
            .await
            .expect("per-account overflow must not wait")
            .unwrap(),
            EnqueueOutcome::Dropped
        );
        // The second account's own share is untouched.
        assert_eq!(
            ingress.enqueue(receive("+15555550101")).await.unwrap(),
            EnqueueOutcome::Enqueued
        );
        // One drained slot admits exactly one more receive for the flooded
        // account.
        drop(receives.recv().await.unwrap());
        assert_eq!(
            ingress.enqueue(receive("+15555550100")).await.unwrap(),
            EnqueueOutcome::Enqueued
        );
    }

    /// Packet 1.196: the global caps remain the outer bound. Four accounts
    /// fill their own 512 KiB shares (five 100 KiB receives each) and the
    /// 2 MiB global byte budget runs out; a fifth account, whose own share is
    /// empty, is then dropped — proving the per-account split did not turn
    /// the global ceiling into a per-account one.
    #[tokio::test]
    async fn receive_queue_global_budget_still_caps_the_sum_of_accounts() {
        let (mut ingress, _receives) = receive_channel();
        ingress.enqueue_timeout = Duration::from_millis(50);
        let text = "a".repeat(100 * 1024);
        let receive = |account: &str| NormalizedReceive {
            required_protocol_version: None,
            timestamp: Some(42),
            content_kind: "dataMessage",
            direction: "incoming",
            account_present: true,
            account: Some(account.into()),
            source: Some("+15555550101".into()),
            source_uuid: None,
            peer_name: None,
            group_id: None,
            text: Some(text.clone()),
            text_bytes: Some(text.len() as u32),
            text_truncated: false,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            sticker: None,
            control: None,
            expire_seconds: None,
            expire_start_at: None,
            server_guid: None,
            reporting_token: None,
            server_timestamp: None,
        };

        for account in [
            "+15555550100",
            "+15555550101",
            "+15555550102",
            "+15555550103",
        ] {
            for _ in 0..5 {
                assert_eq!(
                    ingress.enqueue(receive(account)).await.unwrap(),
                    EnqueueOutcome::Enqueued
                );
            }
        }
        // The fifth account has its whole per-account share free, but the
        // global byte budget has less than one receive left.
        assert_eq!(
            ingress.enqueue(receive("+15555550104")).await.unwrap(),
            EnqueueOutcome::Dropped
        );
    }

    #[test]
    fn receive_normalization_accepts_source_uuid_and_result_wrapper() {
        let input = json!({
            "subscription": 0,
            "result": {
                "envelope": {
                    "sourceUuid": "11111111-1111-1111-1111-111111111111",
                    "timestamp": 99,
                    "dataMessage": { "message": "uuid only" }
                }
            }
        });
        let normalized = normalize_receive(&input).unwrap().unwrap();
        assert_eq!(normalized.content_kind, "dataMessage");
        assert_eq!(normalized.direction, "incoming");
        assert_eq!(normalized.text.as_deref(), Some("uuid only"));
        assert_eq!(
            normalized.source.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(normalized.account.is_none());
    }

    #[test]
    fn receive_normalization_sync_sent_is_outgoing() {
        let input = json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 100,
                "syncMessage": {
                    "sentMessage": {
                        "destinationNumber": "+15555550101",
                        "timestamp": 101,
                        "message": "from phone"
                    }
                }
            }
        });
        let normalized = normalize_receive(&input).unwrap().unwrap();
        assert_eq!(normalized.direction, "outgoing");
        assert_eq!(normalized.text.as_deref(), Some("from phone"));
        assert_eq!(normalized.source.as_deref(), Some("+15555550101"));
        assert_eq!(normalized.timestamp, Some(101));
    }

    #[test]
    fn receive_normalization_captures_source_name() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "source": "uuid-peer",
                "sourceName": "林菲菲",
                "timestamp": 1,
                "dataMessage": { "message": "hi" }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.peer_name.as_deref(), Some("林菲菲"));
        assert_eq!(normalized.direction, "incoming");
    }

    #[test]
    fn receive_normalization_only_marks_explicit_controls_as_system() {
        let empty = normalize_receive(&json!({
            "envelope": {
                "source": "+15555550101",
                "timestamp": 50,
                "dataMessage": { "timestamp": 50 }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(empty.direction, "skip");
        assert!(empty.text.is_none());

        let system = normalize_receive(&json!({
            "envelope": {
                "source": "+15555550101",
                "timestamp": 51,
                "dataMessage": { "isExpirationUpdate": true }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(system.direction, "system");
        // Close form: the flag without a stated value reads as off (§4.41).
        assert_eq!(system.text.as_deref(), Some("已更新消息定时消失：已关闭"));
        assert_eq!(system.expire_seconds, None);
        assert_eq!(
            system.rich.as_ref().map(|rich| rich.is_expiration_update),
            Some(true)
        );

        let skip_sticker = normalize_receive(&json!({
            "envelope": {
                "source": "+15555550101",
                "timestamp": 52,
                "dataMessage": { "sticker": { "packId": "x" } }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(skip_sticker.direction, "skip");
    }

    /// Sticker receive projection (contract revision 1.35): a sticker with a
    /// usable `data` pointer lands as an incoming row carrying the pack
    /// identity beside a metadata-only descriptor (the byte pointer rides the
    /// attachment list); a sticker without one keeps the plain skip routing,
    /// and absent sticker keys stay absent on the wire.
    #[test]
    fn receive_normalization_projects_sticker_metadata_and_data_descriptor() {
        let with_data = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 54,
                "dataMessage": {
                    "sticker": {
                        "packId": "abcdef01",
                        "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                        "stickerId": 7,
                        "emoji": "🎉",
                        "data": {
                            "id": "att-1",
                            "contentType": "image/webp",
                            "size": 8192,
                            "width": 512,
                            "height": 512
                        }
                    }
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(with_data.direction, "incoming");
        let sticker = with_data.sticker.as_ref().expect("sticker metadata");
        assert_eq!(sticker.pack_id, "abcdef01");
        assert_eq!(sticker.pack_key, "AAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(sticker.sticker_id, 7);
        assert_eq!(sticker.emoji.as_deref(), Some("🎉"));
        assert_eq!(with_data.attachments.len(), 1);
        let descriptor = &with_data.attachments[0];
        assert_eq!(descriptor.id, "att-1");
        assert_eq!(descriptor.content_type.as_deref(), Some("image/webp"));
        assert_eq!(descriptor.size, Some(8192));
        assert_eq!(descriptor.width, Some(512));
        assert_eq!(descriptor.height, Some(512));
        assert!(!descriptor.is_voice_note);
        // The metadata-only engines project no locator: the ingest face stays
        // the honest hole (contract revision 1.61).
        assert_eq!(descriptor.locator, None);

        // A receive envelope that does project the transit locator parses it
        // under the 1.56 ingest caps, index-aligned with its descriptor.
        let with_locator = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 57,
                "dataMessage": {
                    "attachments": [{
                        "id": "att-loc",
                        "contentType": "image/jpeg",
                        "size": 4096,
                        "locator": {
                            "key": crate::service::base64_encode(&[0x33_u8; 64]),
                            "cdnKey": "live-cdn-key",
                            "cdnNumber": 2,
                            "digest": crate::service::base64_encode(&[0x44_u8; 32]),
                            "plaintextHash": "AABBCCDD"
                        }
                    }]
                }
            }
        }))
        .unwrap()
        .unwrap();
        let face = with_locator.attachments[0]
            .locator
            .as_ref()
            .expect("a projected locator parses");
        assert_eq!(face.cdn_key.as_deref(), Some("live-cdn-key"));
        assert_eq!(face.cdn_number, Some(2));
        assert!(face.key.is_some());
        assert!(face.digest.is_some());
        assert_eq!(face.plaintext_hash.as_deref(), Some("aabbccdd"));
        // A locator whose every field is missing or wrong-shaped collapses to
        // the hole, never a half-face.
        let hostile = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 58,
                "dataMessage": {
                    "attachments": [{
                        "id": "att-bad",
                        "locator": { "key": 7, "cdnNumber": -1, "plaintextHash": "zzz" }
                    }]
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(hostile.attachments[0].locator, None);

        // The pack identity does not ride the engine-side normalization wire
        // shape (the service layer projects it onto MessageRecord, asserted in
        // the store round-trip test); it is reachable programmatically here.
        let plain = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 55,
                "dataMessage": { "message": "plain" }
            }
        }))
        .unwrap()
        .unwrap();
        assert!(plain.sticker.is_none());
        assert!(plain.attachments.is_empty());

        // No usable data pointer → nothing renderable: the plain skip
        // routing, no half-carried sticker state.
        let without_data = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 56,
                "dataMessage": {
                    "sticker": {
                        "packId": "abcdef01",
                        "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                        "stickerId": 7
                    }
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(without_data.direction, "skip");
        assert!(without_data.sticker.is_none());
        assert!(without_data.attachments.is_empty());
    }

    /// Sticker rows carry no body (official DataMessage.Sticker semantics —
    /// official clients send the body empty and the sticker block is the
    /// whole row). A stale/non-empty body riding a sticker envelope (written
    /// by an old projection face — observed in the wild as a packId/hash-shaped
    /// hex line under the sticker block) is cut at the normalization
    /// authority: the sticker face wins, the body never reaches the row's
    /// text column. Live arm and multi-device sent mirror both.
    #[test]
    fn sticker_envelope_never_carries_body_text() {
        let inbound = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 59,
                "dataMessage": {
                    "message": "stale-body-sample",
                    "sticker": {
                        "packId": "abcdef01",
                        "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                        "stickerId": 7,
                        "emoji": "🎉",
                        "data": {
                            "id": "att-1",
                            "contentType": "image/webp",
                            "size": 8192,
                        }
                    }
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(inbound.direction, "incoming");
        assert!(
            inbound.sticker.is_some(),
            "sticker face survives the body cut"
        );
        assert!(inbound.text.is_none(), "sticker row never stores a body");
        assert!(inbound.text_bytes.is_none());
        assert_eq!(inbound.attachments.len(), 1);

        let mirror = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000001000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1727000001000u64,
                        "destinationNumber": "+15555550101",
                        "message": "stale-body-sample",
                        "sticker": {
                            "packId": "abcdef01",
                            "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                            "stickerId": 7,
                            "data": { "id": "att-1", "contentType": "image/webp" },
                        },
                    }
                },
            },
        }))
        .unwrap();
        assert_eq!(mirror.direction, "outgoing");
        assert!(
            mirror.sticker.is_some(),
            "mirror sticker face survives the body cut"
        );
        assert!(mirror.text.is_none(), "sticker mirror never stores a body");
        assert!(mirror.text_bytes.is_none());
        assert_eq!(mirror.attachments.len(), 1);
    }

    #[test]
    fn receive_normalization_preserves_text_whitespace() {
        let normalized = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 53,
                "dataMessage": { "message": "  exact body\n" }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.text.as_deref(), Some("  exact body\n"));
        assert_eq!(normalized.text_bytes, Some(13));
    }

    #[test]
    fn receive_normalization_drops_oversized_identifier_fields() {
        let with_group = |group_id: String| {
            json!({
                "account": "+15555550100",
                "envelope": {
                    "source": "+15555550101",
                    "timestamp": 42,
                    "dataMessage": {
                        "message": "group text",
                        "groupInfo": { "groupId": group_id }
                    }
                }
            })
        };
        assert!(
            normalize_receive(&with_group("g".repeat(MAX_RECEIVE_ID_CHARS + 1)))
                .unwrap()
                .is_none()
        );
        assert!(
            normalize_receive(&with_group("g".repeat(MAX_RECEIVE_ID_CHARS)))
                .unwrap()
                .is_some()
        );

        let oversized_source = json!({
            "account": "+15555550100",
            "envelope": {
                "source": "s".repeat(MAX_RECEIVE_ID_CHARS + 1),
                "timestamp": 42,
                "dataMessage": { "message": "hi" }
            }
        });
        assert!(normalize_receive(&oversized_source).unwrap().is_none());

        let oversized_account = json!({
            "account": "a".repeat(MAX_RECEIVE_ID_CHARS + 1),
            "envelope": {
                "source": "+15555550101",
                "timestamp": 42,
                "dataMessage": { "message": "hi" }
            }
        });
        assert!(normalize_receive(&oversized_account).unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_receive_notification_is_dropped_without_faulting() {
        let (events, _unused) = event_channel();
        let (ingress, mut receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;

        let oversized = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "account": "+15555550100",
                "envelope": {
                    "source": "+15555550101",
                    "timestamp": 1,
                    "dataMessage": {
                        "message": "oversized group",
                        "groupInfo": { "groupId": "g".repeat(MAX_RECEIVE_ID_CHARS + 1) }
                    }
                }
            }
        }))
        .unwrap();
        handle_upstream_line(&oversized, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        let well_formed = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "account": "+15555550100",
                "envelope": {
                    "source": "+15555550101",
                    "timestamp": 2,
                    "dataMessage": { "message": "after oversized" }
                }
            }
        }))
        .unwrap();
        handle_upstream_line(&well_formed, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        let queued = receiver.recv().await.unwrap();
        assert_eq!(queued.receive().text.as_deref(), Some("after oversized"));
        assert!(receiver.try_recv().is_err());
        assert!(!degraded);
    }

    /// The regression at the heart of the liveness fix: a receive queue that
    /// never drains must turn admission into a bounded wait plus a drop, not
    /// into a permanently parked engine actor.
    #[tokio::test]
    async fn receive_enqueue_drops_instead_of_blocking_when_the_queue_stays_full() {
        let (mut ingress, mut receives) = receive_channel();
        ingress.enqueue_timeout = Duration::from_millis(50);
        let receive = || NormalizedReceive {
            required_protocol_version: None,
            timestamp: Some(42),
            content_kind: "dataMessage",
            direction: "incoming",
            account_present: true,
            account: Some("+15555550100".into()),
            source: Some("+15555550101".into()),
            source_uuid: None,
            peer_name: None,
            group_id: None,
            text: Some("a".repeat(MAX_INBOUND_TEXT_BYTES)),
            text_bytes: Some(MAX_INBOUND_TEXT_BYTES as u32),
            text_truncated: false,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            sticker: None,
            control: None,
            expire_seconds: None,
            expire_start_at: None,
            server_guid: None,
            reporting_token: None,
            server_timestamp: None,
        };

        let mut admitted = 0;
        while matches!(
            ingress.enqueue(receive()).await,
            Ok(EnqueueOutcome::Enqueued)
        ) {
            admitted += 1;
        }
        assert!(admitted > 1);

        // Once the budget frees up, admission works again.
        drop(receives.recv().await.unwrap());
        assert_eq!(
            ingress.enqueue(receive()).await.unwrap(),
            EnqueueOutcome::Enqueued
        );
    }

    /// A dropped receive flips the engine-side degraded storage signal to
    /// `unavailable` once; the next admitted receive reports `recovered`.
    #[tokio::test]
    async fn receive_backpressure_reports_storage_degraded_and_recovers() {
        let (events, mut event_rx) = event_channel();
        let (mut ingress, mut receiver) = receive_channel();
        ingress.enqueue_timeout = Duration::from_millis(50);
        let mut pending = HashMap::new();
        let mut degraded = false;

        // Fill the byte budget so the next receive cannot be admitted.
        let filler = NormalizedReceive {
            required_protocol_version: None,
            timestamp: Some(42),
            content_kind: "dataMessage",
            direction: "incoming",
            account_present: true,
            account: Some("+15555550100".into()),
            source: Some("+15555550101".into()),
            source_uuid: None,
            peer_name: None,
            group_id: None,
            text: Some("a".repeat(MAX_INBOUND_TEXT_BYTES)),
            text_bytes: Some(MAX_INBOUND_TEXT_BYTES as u32),
            text_truncated: false,
            quote: None,
            attachments: Vec::new(),
            rich: None,
            sticker: None,
            control: None,
            expire_seconds: None,
            expire_start_at: None,
            server_guid: None,
            reporting_token: None,
            server_timestamp: None,
        };

        while matches!(
            ingress.enqueue(filler.clone()).await,
            Ok(EnqueueOutcome::Enqueued)
        ) {}

        // The probe receives must be as heavy as the filler: the fill loop
        // stops as soon as one filler no longer fits, leaving up to one
        // filler-weight of byte budget free — a small message would still be
        // admitted and never exercise the drop path.
        let heavy = "a".repeat(MAX_INBOUND_TEXT_BYTES);
        let line = |timestamp: u64| {
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive",
                "params": {
                    "account": "+15555550100",
                    "envelope": {
                        "source": "+15555550101",
                        "timestamp": timestamp,
                        "dataMessage": { "message": heavy.as_str() }
                    }
                }
            }))
            .unwrap()
        };

        handle_upstream_line(&line(1), &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();
        assert!(degraded);
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::StorageChanged {
                state: "unavailable"
            }
        ));

        // Drain the queue: admission succeeds again and reports recovery once.
        while receiver.try_recv().is_ok() {}
        handle_upstream_line(&line(2), &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();
        assert!(!degraded);
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::StorageChanged { state: "recovered" }
        ));
    }

    /// contract 1.21: an upstream error carrying the unlink signature is
    /// classified as Unauthorized and attributed to the request's account.
    #[tokio::test]
    async fn unauthorized_error_response_is_classified_and_attributed() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-1".to_string(),
            PendingRequest {
                class: CallClass::ReadOnly,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-1",
            "error": {
                "code": -32603,
                "message": "Failed to send message: Authorization failed! (AuthorizationFailedException)"
            }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert_eq!(response_rx.await.unwrap(), Err(EngineError::Unauthorized));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::AccountUnauthorized { ref account } if account == "+15555550100"
        ));
    }

    /// The post-mortem short-circuit form ("User <account> is not
    /// registered.", signal-cli App.java:342 after persisted
    /// `registered=false`) classifies as Unauthorized and is attributed to
    /// the account exactly like the live authorization-failure form.
    #[tokio::test]
    async fn unregistered_post_mortem_error_is_classified_and_attributed() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-1".to_string(),
            PendingRequest {
                class: CallClass::ReadOnly,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-1",
            "error": {
                "code": -1,
                "message": "User +15555550100 is not registered."
            }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert_eq!(response_rx.await.unwrap(), Err(EngineError::Unauthorized));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::AccountUnauthorized { ref account } if account == "+15555550100"
        ));
    }

    /// The recipient-level form ("The user <id> is not registered.",
    /// unblock/updateContact/sendPoll* family) targets a CONTACT, not the
    /// local account: it must stay a generic upstream error and must not
    /// emit an account-unauthorized event.
    #[tokio::test]
    async fn recipient_not_registered_error_stays_unclassified() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-1".to_string(),
            PendingRequest {
                class: CallClass::ReadOnly,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-1",
            "error": {
                "code": -1,
                "message": "The user +15555550200 is not registered."
            }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert_eq!(
            response_rx.await.unwrap(),
            Err(EngineError::Upstream {
                cause: None,
                code: Some(-1)
            })
        );
        assert!(event_rx.try_recv().is_err());
    }

    /// Any other upstream error keeps the generic Upstream classification and
    /// must not emit an account event. Contract 1.167 §4.165: the embedded
    /// cause-class literal rides the error log-only — the class-shaped
    /// wrapper in this fixture message is carried verbatim.
    #[tokio::test]
    async fn generic_upstream_error_stays_unclassified() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-2".to_string(),
            PendingRequest {
                class: CallClass::ReadOnly,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-2",
            "error": { "code": -1, "message": "User input error (UserErrorException)" }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert_eq!(
            response_rx.await.unwrap(),
            Err(EngineError::Upstream {
                cause: Some("(UserErrorException)".to_string()),
                code: Some(-1)
            })
        );
        assert!(event_rx.try_recv().is_err());
    }

    /// In-memory capture for log-face assertions (the metrics.rs pattern).
    #[derive(Clone, Default)]
    struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_log(log: impl FnOnce()) -> String {
        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, log);
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    /// Contract 1.167 §4.165: the extraction unit — the tailmost qualifying
    /// token wins, the dotted FQN literal rides, and the shape-hostile ladder
    /// answers `None` (no parens, space-bearing prose, a `+`-led phone token,
    /// a digit-led token, an unclosed paren, an empty wrapper, missing and
    /// non-string messages). The bound: a class token past the cap truncates
    /// inside the 120-byte wrapper.
    #[test]
    fn upstream_error_cause_extracts_the_tail_class_literal_bounded() {
        let cause = |message: &str| {
            upstream_error_cause(Some(&json!({ "code": -32603, "message": message })))
        };
        // The tailmost token wins over an earlier incidental one.
        assert_eq!(
            cause("prefix (incidental) then failed (UnregisteredUserException)"),
            Some("(UnregisteredUserException)".to_string())
        );
        // The dotted FQN form rides.
        assert_eq!(
            cause(
                "Failed to send message: connection reset (org.whispersystems.signalservice.api.PushNetworkException)"
            ),
            Some("(org.whispersystems.signalservice.api.PushNetworkException)".to_string())
        );
        // Shape-hostile ladder: none of these can be a class literal.
        assert_eq!(cause("no parentheses at all"), None);
        assert_eq!(cause("failed (user note with spaces)"), None);
        assert_eq!(cause("failed (+15555550200)"), None);
        assert_eq!(cause("failed (20261016)"), None);
        assert_eq!(cause("failed (UnregisteredUserException"), None);
        assert_eq!(cause("failed ()"), None);
        // Missing and non-string messages answer None.
        assert_eq!(upstream_error_cause(None), None);
        assert_eq!(upstream_error_cause(Some(&json!({ "code": -32603 }))), None);
        assert_eq!(
            upstream_error_cause(Some(&json!({ "code": -32603, "message": 42 }))),
            None
        );
        // The bound: an oversize class token truncates inside the 120-byte
        // wrapper cap.
        let oversize = format!("{}Exception", "A".repeat(200));
        let truncated = cause(&format!("Failed to send message: timed out ({oversize})")).unwrap();
        assert_eq!(truncated.len(), 120);
        assert!(truncated.starts_with("(AAAAAAAA"));
        assert!(!truncated.contains("Exception"));
    }

    /// Contract 1.167 §4.165: the cause-bearing face — the upstream class
    /// with an extracted literal logs `cause=` after `error_class`, and the
    /// 120-byte bound rides whole at the emitter (the extraction enforces
    /// the cap; the line carries whatever the classifier bounded).
    #[test]
    fn engine_call_failed_log_carries_the_upstream_cause() {
        let output = captured_log(|| {
            log_engine_call_failure(
                "send",
                "mutating",
                2480,
                &EngineError::Upstream {
                    cause: Some("(UnregisteredUserException)".to_string()),
                    code: None,
                },
            )
        });
        assert!(output.contains("engine call failed"));
        assert!(output.contains("upstream_method=\"send\""));
        assert!(output.contains("error_class=\"upstream\""));
        assert!(output.contains("cause=\"(UnregisteredUserException)\""));

        let bounded_cause = format!("({})", "A".repeat(118));
        assert_eq!(bounded_cause.len(), 120);
        let output = captured_log(|| {
            log_engine_call_failure(
                "send",
                "mutating",
                2480,
                &EngineError::Upstream {
                    cause: Some(bounded_cause.clone()),
                    code: None,
                },
            )
        });
        assert!(output.contains(&format!("cause=\"{bounded_cause}\"")));
    }

    /// Contract 1.167 §4.165 regression pin: every other face keeps the
    /// pre-1.167 line byte for byte — a non-upstream class and a causeless
    /// upstream (a shape-hostile message) emit no `cause=` field at all.
    #[test]
    fn engine_call_failed_log_stays_byte_identical_outside_the_cause() {
        for error in [
            EngineError::Timeout,
            EngineError::UnknownOutcome,
            EngineError::Upstream {
                cause: None,
                code: None,
            },
        ] {
            let output = captured_log(|| log_engine_call_failure("send", "mutating", 2500, &error));
            assert!(output.contains("engine call failed"));
            assert!(output.contains("error_class="));
            assert!(!output.contains("cause="));
        }
    }

    /// Contract 1.167 §4.165: the generic upstream arm carries the extracted
    /// cause literal on the error (log-only); a shape-hostile message stays
    /// causeless; neither emits an account event.
    #[tokio::test]
    async fn generic_upstream_error_carries_the_embedded_cause_literal() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-1".to_string(),
            PendingRequest {
                class: CallClass::Mutating,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-1",
            "error": {
                "code": -32603,
                "message": "Failed to send message: Timed out waiting for a response (UnregisteredUserException)"
            }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert_eq!(
            response_rx.await.unwrap(),
            Err(EngineError::Upstream {
                cause: Some("(UnregisteredUserException)".to_string()),
                code: Some(-32603)
            })
        );
        assert!(event_rx.try_recv().is_err());

        // A shape-hostile message stays causeless.
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-2".to_string(),
            PendingRequest {
                class: CallClass::Mutating,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-2",
            "error": { "code": -32603, "message": "fixture send failed" }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert_eq!(
            response_rx.await.unwrap(),
            Err(EngineError::Upstream {
                cause: None,
                code: Some(-32603)
            })
        );
        assert!(event_rx.try_recv().is_err());
    }

    /// §4.166 regression pin: resolution is strictly per request id — a
    /// response completes only its own waiting call, the other pending call
    /// stays waiting, and an id with no waiting request warns and completes
    /// nothing (the id-map remove is the only resolution path).
    #[tokio::test]
    async fn response_for_another_request_cannot_resolve_the_waiting_call() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (first_tx, first_rx) = oneshot::channel();
        let (second_tx, second_rx) = oneshot::channel();
        for (id, response) in [("kt-1", first_tx), ("kt-2", second_tx)] {
            pending.insert(
                id.to_string(),
                PendingRequest {
                    class: CallClass::Mutating,
                    account: Some("+15555550100".to_string()),
                    response,
                },
            );
        }

        // kt-2's success resolves kt-2 and nothing else.
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-2",
            "result": {}
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();
        assert!(second_rx.await.unwrap().is_ok());
        assert!(
            pending.contains_key("kt-1"),
            "kt-1 must still be waiting: another id's answer resolves nothing"
        );

        // An id with no waiting request is a protocol warning; no pending
        // call moves.
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-9",
            "result": {}
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();
        assert!(pending.contains_key("kt-1"));
        assert!(matches!(
            event_rx.try_recv().unwrap(),
            EngineEvent::ProtocolWarning {
                kind: "unknownOrDuplicateResponseId"
            }
        ));
        assert!(
            event_rx.try_recv().is_err(),
            "the warning is the only trace"
        );

        // kt-1's own answer still resolves kt-1 afterwards.
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-1",
            "result": {}
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();
        assert!(first_rx.await.unwrap().is_ok());
        assert!(pending.is_empty());
        assert!(event_rx.try_recv().is_err());
    }

    /// 2026-10-19 incident pin: the engine answers an over-long inbound frame
    /// with a JSON-RPC -32700 parse error carrying `"id": null` and keeps
    /// running. That line must degrade to a warning — never `EngineError::
    /// Protocol`, which faults the read loop and collapses every in-flight
    /// mutating call to `UnknownOutcome` (the 4.4MB video send became
    /// SEND_OUTCOME_UNKNOWN this way while the engine was healthy).
    #[tokio::test]
    async fn response_without_a_string_id_warns_instead_of_faulting_the_engine() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, mut response_rx) = oneshot::channel();
        pending.insert(
            "kt-1".to_string(),
            PendingRequest {
                class: CallClass::Mutating,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": -32700, "message": "Parse error" }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .expect("a null-id response must not fault the read loop");

        assert!(matches!(
            event_rx.try_recv().unwrap(),
            EngineEvent::ProtocolWarning {
                kind: "responseWithoutId"
            }
        ));
        assert!(
            pending.contains_key("kt-1"),
            "the unroutable line resolves nothing; the call settles by its own timeout"
        );
        assert!(
            response_rx.try_recv().is_err(),
            "no failure is injected into the waiting call"
        );
    }

    /// Contract 1.113 §4.94: the engine's unbound stop-ring notification
    /// replays onto the attributed AccountUnauthorized lane the unlink
    /// watcher already consumes — exactly one event, no warning.
    #[tokio::test]
    async fn account_unbound_notification_marks_the_account() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;

        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "accountUnbound",
            "params": { "account": "+15555550100" }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::AccountUnauthorized { ref account } if account == "+15555550100"
        ));
        assert!(event_rx.try_recv().is_err());
    }

    /// Contract 1.113 §4.94: a malformed accountUnbound payload — missing
    /// params, missing, non-string or empty account — carries no attributable
    /// identity and degrades to the unknown-notification warning instead of
    /// inventing an account.
    #[tokio::test]
    async fn malformed_account_unbound_notifications_stay_unattributed() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;

        let lines = [
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "accountUnbound"
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "accountUnbound",
                "params": {}
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "accountUnbound",
                "params": { "account": 401 }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "accountUnbound",
                "params": { "account": "" }
            }))
            .unwrap(),
        ];
        for line in &lines {
            handle_upstream_line(line, &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
        }

        for _ in 0..lines.len() {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::ProtocolWarning {
                    kind: "unknownNotification"
                }
            ));
        }
        assert!(event_rx.try_recv().is_err());
    }

    /// Contract 1.99 §4.80: the send-chain transport classifier is a pure
    /// function over the raw JSON-RPC error body — each fixed anchor maps to
    /// its variant, both embedded in a realistic engine message and as the
    /// bare literal.
    #[test]
    fn send_chain_classifier_maps_the_three_transport_anchors() {
        let classify = |error: serde_json::Value| upstream_error_send_class(Some(&error));
        // Realistic engine wire shape: the cause class embedded at the tail
        // of the internal_error message (-32603).
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "Failed to send message: Timed out waiting for a response (RateLimitExceeded)"
            })),
            Some(EngineError::RateLimited {
                retry_after_secs: None
            })
        );
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "Failed to send message: Proof required (ProofRequiredException)"
            })),
            Some(EngineError::ProofRequired)
        );
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "Failed to send message: Bad gateway (ServerUnavailableException)"
            })),
            Some(EngineError::ServerUnavailable)
        );
        // The bare literal (the whole message IS the anchor) classifies too:
        // the contract fixes the anchor as a contained literal, not a
        // trailing suffix.
        assert_eq!(
            classify(json!({ "code": -32603, "message": "(RateLimitExceeded)" })),
            Some(EngineError::RateLimited {
                retry_after_secs: None
            })
        );
    }

    /// Contract 1.114 §4.95: the identity gate joins the send-chain
    /// classifier as the fourth anchor — the engine's exact P9 wire literal
    /// classifies, the bare anchor literal classifies, and the gate never
    /// fires on identity wording without the parenthesized exception name.
    #[test]
    fn send_chain_classifier_maps_the_identity_anchor() {
        let classify = |error: serde_json::Value| upstream_error_send_class(Some(&error));
        // Realistic engine wire shape (P9, methods.rs IDENTITY_UNVERIFIED_MESSAGE).
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "Failed to send message: Identity unverified. (UntrustedIdentityException)"
            })),
            Some(EngineError::IdentityUnverified)
        );
        // The bare literal classifies: contained literal, not a trailing
        // suffix.
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "(UntrustedIdentityException)"
            })),
            Some(EngineError::IdentityUnverified)
        );
        // Identity wording without the parenthesized anchor is not a
        // classification.
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "Failed to send message: Identity unverified."
            })),
            None
        );
        // The anchor only in the `code` slot is not a classification.
        assert_eq!(
            classify(json!({
                "code": "(UntrustedIdentityException)",
                "message": "fixture send failed"
            })),
            None
        );
    }

    /// Contract 1.99 §4.80: everything outside the anchor contract answers
    /// `None` and keeps the generic upstream answer — a missing error
    /// object, a missing or non-string `message`, an anchor only in the
    /// `code` slot (the classifier reads the message text, exactly like the
    /// authorization matcher), near-miss literals without the parenthesized
    /// exception name, and ordinary unrelated errors.
    #[test]
    fn send_chain_classifier_answers_none_outside_the_anchor_contract() {
        let classify = |error: serde_json::Value| upstream_error_send_class(Some(&error));
        // No error object at all / no message field / a non-string message.
        assert_eq!(upstream_error_send_class(None), None);
        assert_eq!(classify(json!({ "code": -32603 })), None);
        assert_eq!(classify(json!({ "code": -32603, "message": 42 })), None);
        // An anchor only in the `code` slot is not a classification: the
        // message is the only classification surface.
        assert_eq!(
            classify(json!({
                "code": "(RateLimitExceeded)",
                "message": "fixture send failed"
            })),
            None
        );
        // Near misses: the exception name without its parenthesized anchor
        // wrapper, or a truncated/wrong name, must not classify.
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "RateLimitExceeded without the wrapper"
            })),
            None
        );
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "ProofRequiredException without the wrapper"
            })),
            None
        );
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "ServerUnavailable without the wrapper"
            })),
            None
        );
        // Ordinary engine errors stay unclassified (the ladder's else arm).
        assert_eq!(
            classify(json!({
                "code": -1,
                "message": "User input error (UserErrorException)"
            })),
            None
        );
        // The §4.17 authorization signatures are not send-chain anchors.
        assert_eq!(
            classify(json!({
                "code": -32603,
                "message": "Failed to send message: Authorization failed! (AuthorizationFailedException)"
            })),
            None
        );
    }

    /// Red line (audit conclusion): the §4.17 authorization matcher's match
    /// set is frozen — a message carrying only a transport anchor never
    /// trips it, so the AccountUnauthorized → ACCOUNT_UNLINKED chain cannot
    /// be widened through the send-classification batch.
    #[test]
    fn upstream_match_set_stays_clear_of_send_anchors() {
        for message in [
            "Failed to send message: Timed out waiting for a response (RateLimitExceeded)",
            "Failed to send message: Proof required (ProofRequiredException)",
            "Failed to send message: Bad gateway (ServerUnavailableException)",
        ] {
            assert!(
                !upstream_error_is_unauthorized(Some(&json!({ "message": message }))),
                "authorization matcher must not match {message}"
            );
        }
    }

    /// Contract 1.101 §4.82: the chat service's plain-text 401 body — the
    /// credential-death face the exception-name matchers cannot see —
    /// classifies to `EngineError::Unauthorized` through the real line
    /// handler and drives the §4.17 event chain (the credential is dead; the
    /// recovery is the same relink), attributed to the request's account.
    #[tokio::test]
    async fn credentials_401_body_anchor_classifies_as_unauthorized() {
        for message in [
            // The raw upstream body, bare and inside an engine-style wrapper.
            "Credentials are required to access this resource.",
            "Failed to send message: Credentials are required to access this \
             resource. (Unauthorized)",
        ] {
            let (events, mut event_rx) = event_channel();
            let (ingress, _receiver) = receive_channel();
            let mut pending = HashMap::new();
            let mut degraded = false;
            let (response_tx, response_rx) = oneshot::channel();
            pending.insert(
                "kt-5".to_string(),
                PendingRequest {
                    class: CallClass::ReadOnly,
                    account: Some("+15555550100".to_string()),
                    response: response_tx,
                },
            );
            let line = serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": "kt-5",
                "error": { "code": -32603, "message": message }
            }))
            .unwrap();
            handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
            assert_eq!(
                response_rx.await.unwrap(),
                Err(EngineError::Unauthorized),
                "{message}"
            );
            assert!(
                matches!(
                    event_rx.recv().await.unwrap(),
                    EngineEvent::AccountUnauthorized { ref account } if account == "+15555550100"
                ),
                "{message} drives the unlink chain"
            );
        }
    }

    /// The credential anchor's match set stays narrow: only the exact
    /// upstream sentence classifies — case variants, partial sentences, the
    /// §4.17 signatures, the §4.80 transport anchors, structured codes, and
    /// ordinary engine errors all answer false, so incidental text can never
    /// flip an account's state through this matcher.
    #[test]
    fn credentials_anchor_match_set_stays_narrow() {
        let matches = |message: &str| {
            upstream_error_is_credential_invalid(Some(&json!({ "message": message })))
        };
        assert!(matches("Credentials are required to access this resource."));
        for message in [
            "credentials are required to access this resource.",
            "Credentials are required to access this resource",
            "Credentials required to access this resource.",
            "Failed to send message: Authorization failed! (AuthorizationFailedException)",
            "User +15555550100 is not registered.",
            "The user +15555550100 is not registered.",
            "Failed to send message: Timed out waiting for a response (RateLimitExceeded)",
            "Failed to send message: Proof required (ProofRequiredException)",
            "Failed to send message: Bad gateway (ServerUnavailableException)",
            "Internal error",
            "STORAGE_UNAVAILABLE",
        ] {
            assert!(
                !matches(message),
                "credential matcher must not match {message}"
            );
        }
        // Structure: no error object, or a non-string message, answers false.
        assert!(!upstream_error_is_credential_invalid(None));
        assert!(!upstream_error_is_credential_invalid(Some(&json!({}))));
        assert!(!upstream_error_is_credential_invalid(Some(&json!({
            "message": 401
        }))));
    }

    /// Contract 1.99 §4.80 wire shape: an upstream send error embedding one
    /// of the three transport anchors classifies to its EngineError variant
    /// through the real line handler, with no account event — a transport
    /// failure never touches account state.
    #[tokio::test]
    async fn send_chain_anchor_errors_classify_without_account_events() {
        for (message, expected) in [
            (
                "Failed to send message: Timed out waiting for a response (RateLimitExceeded)",
                EngineError::RateLimited {
                    retry_after_secs: None,
                },
            ),
            (
                "Failed to send message: Proof required (ProofRequiredException)",
                EngineError::ProofRequired,
            ),
            (
                "Failed to send message: Bad gateway (ServerUnavailableException)",
                EngineError::ServerUnavailable,
            ),
        ] {
            let (events, mut event_rx) = event_channel();
            let (ingress, _receiver) = receive_channel();
            let mut pending = HashMap::new();
            let mut degraded = false;
            let (response_tx, response_rx) = oneshot::channel();
            pending.insert(
                "kt-3".to_string(),
                PendingRequest {
                    class: CallClass::Mutating,
                    account: Some("+15555550100".to_string()),
                    response: response_tx,
                },
            );
            let line = serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": "kt-3",
                "error": { "code": -32603, "message": message }
            }))
            .unwrap();
            handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
            assert_eq!(
                response_rx.await.unwrap(),
                Err(expected.clone()),
                "{message}"
            );
            assert!(
                event_rx.try_recv().is_err(),
                "{message} must not emit an event"
            );
        }
    }

    /// Head-of-line precedence: a hypothetical message carrying both the
    /// unlink signature and a transport anchor still classifies Unauthorized
    /// and emits the account event — the §4.17 recovery chain does not
    /// regress behind the new classification.
    #[tokio::test]
    async fn authorization_classification_precedes_send_chain_anchors() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let (response_tx, response_rx) = oneshot::channel();
        pending.insert(
            "kt-4".to_string(),
            PendingRequest {
                class: CallClass::ReadOnly,
                account: Some("+15555550100".to_string()),
                response: response_tx,
            },
        );
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "kt-4",
            "error": {
                "code": -32603,
                "message": "Authorization failed! (RateLimitExceeded)"
            }
        }))
        .unwrap();
        handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
            .await
            .unwrap();
        assert_eq!(response_rx.await.unwrap(), Err(EngineError::Unauthorized));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::AccountUnauthorized { ref account } if account == "+15555550100"
        ));
    }

    /// Structured engine errors (contract 1.36): the real engine carries the
    /// allowlisted literal in the error `message` with a numeric `code` (-1,
    /// JSON-RPC 2.0 numeric slot); it surfaces as UpstreamCode with the
    /// allowlisted code. A string `code` carrying the literal is accepted as
    /// a fallback. An unknown literal degrades to the plain Upstream
    /// classification so an engine newer than this connector cannot widen
    /// the host contract; an unrelated message stays plain as before.
    #[tokio::test]
    async fn structured_engine_errors_carry_the_allowlisted_code() {
        let classify = |error: serde_json::Value| async move {
            let (events, mut event_rx) = event_channel();
            let (ingress, _receiver) = receive_channel();
            let mut pending = HashMap::new();
            let mut degraded = false;
            let (response_tx, response_rx) = oneshot::channel();
            pending.insert(
                "kt-9".to_string(),
                PendingRequest {
                    class: CallClass::ReadOnly,
                    account: None,
                    response: response_tx,
                },
            );
            let line = serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": "kt-9",
                "error": error
            }))
            .unwrap();
            handle_upstream_line(&line, &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
            assert!(event_rx.try_recv().is_err());
            response_rx.await.unwrap()
        };
        // Real engine wire shape: numeric code, allowlisted literal in
        // `message`.
        assert_eq!(
            classify(json!({
                "code": -1,
                "message": "STICKER_PACK_FETCH_FAILED"
            }))
            .await,
            Err(EngineError::UpstreamCode {
                code: "STICKER_PACK_FETCH_FAILED",
                data: None,
            })
        );
        assert_eq!(
            classify(json!({
                "code": -1,
                "message": "CONVERSATION_NOT_RESOLVED"
            }))
            .await,
            Err(EngineError::UpstreamCode {
                code: "CONVERSATION_NOT_RESOLVED",
                data: None,
            })
        );
        // Fallback shape: string `code` carrying the literal directly.
        assert_eq!(
            classify(json!({
                "code": "STORAGE_WRITE_FAILED",
                "message": "fixture write failed"
            }))
            .await,
            Err(EngineError::UpstreamCode {
                code: "STORAGE_WRITE_FAILED",
                data: None,
            })
        );
        // Contract 1.50: the engine's error.data object rides along verbatim
        // on an allowlisted literal (the PROFILE_UPLOAD_FAILED
        // partial-success facts).
        assert_eq!(
            classify(json!({
                "code": -1,
                "message": "PROFILE_UPLOAD_FAILED",
                "data": { "retryable": true, "textSaved": true }
            }))
            .await,
            Err(EngineError::UpstreamCode {
                code: "PROFILE_UPLOAD_FAILED",
                data: Some(json!({ "retryable": true, "textSaved": true })),
            })
        );
        // A non-object data member is dropped rather than passed through.
        assert_eq!(
            classify(json!({
                "code": -1,
                "message": "PROFILE_UPLOAD_FAILED",
                "data": "garbage"
            }))
            .await,
            Err(EngineError::UpstreamCode {
                code: "PROFILE_UPLOAD_FAILED",
                data: None,
            })
        );
        // Unknown literal: degrades to plain Upstream.
        assert_eq!(
            classify(json!({
                "code": -1,
                "message": "SOME_FUTURE_ENGINE_CODE"
            }))
            .await,
            Err(EngineError::Upstream {
                cause: None,
                code: Some(-1)
            })
        );
        // Ordinary JSON-RPC error shape (unrelated message): plain Upstream.
        assert_eq!(
            classify(json!({ "code": -1, "message": "fixture malformed" })).await,
            Err(EngineError::Upstream {
                cause: None,
                code: Some(-1)
            })
        );
    }

    /// A peer receiptMessage envelope routes to `ControlReceive::Receipt`:
    /// tier selection follows the isViewed > isRead > isDelivery flags, the
    /// confirmed timestamps ride through bounded and de-duplicated, and an
    /// empty batch is not routed at all.
    #[test]
    fn receipt_message_envelope_routes_to_receipt_control() {
        let envelope_of = |flags: serde_json::Value| -> serde_json::Value {
            serde_json::from_value(json!({
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "sourceDevice": 1,
                "receiptMessage": flags,
            }))
            .unwrap()
        };
        let routing = |flags| {
            control_routing(envelope_of(flags).as_object().unwrap()).map(|routing| routing.control)
        };

        let delivered = routing(json!({
            "timestamp": [1726999000000u64, 1726999000000u64, 1726999001000u64],
            "when": 1727000000000u64,
            "isDelivery": true,
        }))
        .expect("delivery receipt routes");
        match delivered {
            ControlReceive::Receipt {
                kind,
                timestamps,
                when,
                recipient,
            } => {
                assert!(matches!(kind, ReceiptKind::Delivered));
                assert_eq!(timestamps, vec![1726999000000, 1726999001000]);
                // Contract 1.32: the envelope's own timestamp backs the
                // delivered/read timeline.
                assert_eq!(when, Some(1727000000000));
                // Contract 1.190 (§4.190): the per-recipient identity rides
                // the variant — the envelope source verbatim.
                assert_eq!(recipient.as_deref(), Some("+15555550101"));
            }
            other => panic!("unexpected control: {other:?}"),
        }

        let read = routing(json!({
            "timestamp": [1726999000000u64],
            "isDelivery": true,
            "isRead": true,
        }))
        .expect("read receipt routes");
        assert!(matches!(
            read,
            ControlReceive::Receipt {
                kind: ReceiptKind::Read,
                ..
            }
        ));

        let viewed = routing(json!({
            "timestamp": [1726999000000u64],
            "isRead": true,
            "isViewed": true,
        }))
        .expect("viewed receipt routes");
        assert!(matches!(
            viewed,
            ControlReceive::Receipt {
                kind: ReceiptKind::Viewed,
                ..
            }
        ));

        assert!(routing(json!({ "timestamp": [], "isDelivery": true })).is_none());
        assert!(routing(json!({ "isDelivery": true })).is_none());
    }

    /// The pin family (contract 1.33) routes off `dataMessage` with the
    /// reaction targetAuthor resolution: pin carries the optional duration
    /// (absent = forever), unpin and adminDelete carry the target identity
    /// only, and a malformed payload is not routed at all.
    #[test]
    fn pin_family_envelopes_route_to_pin_controls() {
        let routing = |data: serde_json::Value| {
            let envelope: serde_json::Value = serde_json::from_value(json!({
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "sourceDevice": 1,
                "dataMessage": data,
            }))
            .unwrap();
            control_routing(envelope.as_object().unwrap()).map(|routing| routing.control)
        };

        let pin = routing(json!({
            "pinMessage": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
                "pinDurationSeconds": 604800u64,
            },
        }))
        .expect("timed pin routes");
        assert!(matches!(
            pin,
            ControlReceive::PinMessage {
                ref target_author,
                target_timestamp,
                duration_seconds: Some(604800),
            } if target_author == "+15555550101" && target_timestamp == 1726999000000
        ));

        let forever = routing(json!({
            "pinMessage": {
                "targetAuthor": "9d7762bb-1fb5-4cfd-9b15-aef4f8ef9c14",
                "targetSentTimestamp": 1726999000000u64,
            },
        }))
        .expect("forever pin routes");
        assert!(matches!(
            forever,
            ControlReceive::PinMessage {
                duration_seconds: None,
                ..
            }
        ));

        let unpin = routing(json!({
            "unpinMessage": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
            },
        }))
        .expect("unpin routes");
        assert!(matches!(unpin, ControlReceive::UnpinMessage { .. }));

        let admin_delete = routing(json!({
            "adminDelete": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
            },
        }))
        .expect("adminDelete routes");
        assert!(matches!(admin_delete, ControlReceive::AdminDelete { .. }));

        // Malformed shapes drop instead of inventing protocol state.
        assert!(routing(json!({ "pinMessage": { "targetSentTimestamp": 1 } })).is_none());
        assert!(routing(json!({ "pinMessage": { "targetAuthor": "+15555550101" } })).is_none());
        assert!(routing(json!({ "unpinMessage": { "targetAuthor": "+15555550101" } })).is_none());
        assert!(routing(json!({ "adminDelete": { "targetSentTimestamp": 1 } })).is_none());
    }

    /// Our own multi-device pin / unpin / admin delete echoes ride
    /// `syncMessage.sentMessage` (official `background.preload.ts:3281-3295`
    /// pin, `:3468-3476` unpin, `:3373-3389` admin delete). The engine
    /// projects the same DataMessage faces under `sentMessage`; they must
    /// route as outgoing control receives, not fall through to the skip.
    #[test]
    fn sync_sent_pin_family_routes_to_pin_controls() {
        let route = |family: serde_json::Value| {
            let mut sent = json!({
                "timestamp": 1726999997000u64,
                "destinationNumber": "+15555550101",
                "destinationDevice": 2,
            });
            let object = sent.as_object_mut().unwrap();
            for (key, value) in family.as_object().unwrap() {
                object.insert(key.clone(), value.clone());
            }
            normalize_receive_fields(&json!({
                "account": "+15555550100",
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": { "sentMessage": sent }
                }
            }))
            .unwrap()
        };

        let pin = route(json!({
            "pinMessage": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
                "pinDurationSeconds": 604800u64,
            }
        }));
        assert_eq!(pin.direction, "outgoing");
        assert_eq!(pin.content_kind, "control");
        assert_eq!(pin.timestamp, Some(1726999997000));
        assert!(matches!(
            pin.control,
            Some(ControlReceive::PinMessage {
                ref target_author,
                target_timestamp: 1726999000000,
                duration_seconds: Some(604800),
            }) if target_author == "+15555550101"
        ));

        let forever = route(json!({
            "pinMessage": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
            }
        }));
        assert!(matches!(
            forever.control,
            Some(ControlReceive::PinMessage {
                duration_seconds: None,
                ..
            })
        ));

        let unpin = route(json!({
            "unpinMessage": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
            }
        }));
        assert_eq!(unpin.content_kind, "control");
        assert!(matches!(
            unpin.control,
            Some(ControlReceive::UnpinMessage {
                target_timestamp: 1726999000000,
                ..
            })
        ));

        let admin_delete = route(json!({
            "adminDelete": {
                "targetAuthor": "+15555550101",
                "targetSentTimestamp": 1726999000000u64,
            }
        }));
        assert_eq!(admin_delete.content_kind, "control");
        assert!(matches!(
            admin_delete.control,
            Some(ControlReceive::AdminDelete {
                target_timestamp: 1726999000000,
                ..
            })
        ));

        // Malformed echoes fall through to the ordinary sent-message ladder
        // (no text here → plain skip), never a fabricated pin control.
        let malformed = route(json!({
            "pinMessage": { "targetSentTimestamp": 1726999000000u64 }
        }));
        assert!(malformed.control.is_none());
    }

    /// The engine's `groupUpdated` projection (2026-10-06 engine batch,
    /// kt-signal-engine main @ 216a4c7) routes as a control receive off the
    /// envelope-level key: the timer value normalizes through the u32 face,
    /// 0 = off rides verbatim, and the shapes the projection never produces —
    /// missing or non-u32 `expireTimerSeconds` — drop instead of inventing
    /// timer state.
    #[test]
    fn group_updated_projection_routes_to_a_control_receive() {
        let routing = |envelope: serde_json::Value| {
            control_routing(envelope.as_object().unwrap())
                .map(|routing| (routing.control, routing.group_id, routing.direction))
        };

        let (control, group_id, direction) = routing(json!({
            "timestamp": 1727000000000u64,
            "groupUpdated": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "revision": 5,
                "expireTimerSeconds": 3600,
                "editor": "9d7762bb-1fb5-4cfd-9b15-aef4f8ef9c14",
            },
        }))
        .expect("groupUpdated routes");
        let ControlReceive::GroupTimerUpdate { editor, .. } = &control else {
            panic!("the projection routes the timer control");
        };
        assert_eq!(
            editor.as_deref(),
            Some("9d7762bb-1fb5-4cfd-9b15-aef4f8ef9c14")
        );
        assert!(matches!(
            control,
            ControlReceive::GroupTimerUpdate {
                expire_timer_seconds: 3600,
                ..
            }
        ));
        assert_eq!(group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
        assert_eq!(direction, "incoming");

        // 0 = off rides verbatim (the projection guarantees the key); the
        // envelope named no editor here, so the attribution stays absent.
        let (control, _, _) = routing(json!({
            "timestamp": 1727000000000u64,
            "groupUpdated": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "revision": 6,
                "expireTimerSeconds": 0,
            },
        }))
        .expect("the off form routes");
        let ControlReceive::GroupTimerUpdate { editor, .. } = &control else {
            panic!("the off form routes the timer control");
        };
        assert!(editor.is_none(), "no editor on the envelope stays absent");
        assert!(matches!(
            control,
            ControlReceive::GroupTimerUpdate {
                expire_timer_seconds: 0,
                ..
            }
        ));

        // A hostile editor shape (overlong, whitespace-only) reads as absent —
        // the attribution material never truncates into a fake id and never
        // blocks the row.
        let (control, _, _) = routing(json!({
            "timestamp": 1727000000000u64,
            "groupUpdated": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "revision": 6,
                "expireTimerSeconds": 60,
                "editor": " ".repeat(80),
            },
        }))
        .expect("a hostile editor still routes the value");
        let ControlReceive::GroupTimerUpdate { editor, .. } = control else {
            panic!("the hostile-editor form routes the timer control");
        };
        assert!(editor.is_none(), "a hostile editor reads as absent");
        let (control, _, _) = routing(json!({
            "timestamp": 1727000000000u64,
            "groupUpdated": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "revision": 6,
                "expireTimerSeconds": 60,
                "editor": "e".repeat(80),
            },
        }))
        .expect("an overlong editor still routes the value");
        let ControlReceive::GroupTimerUpdate { editor, .. } = control else {
            panic!("the overlong-editor form routes the timer control");
        };
        assert!(editor.is_none(), "an overlong editor reads as absent");

        // Shapes the projection never produces drop (fail closed): the key is
        // guaranteed present, so its absence is a protocol error, and no timer
        // state is invented from a malformed value.
        assert!(
            routing(json!({
                "timestamp": 1727000000000u64,
                "groupUpdated": { "groupId": "ZmFrZS1ncm91cC0x", "revision": 7 },
            }))
            .is_none()
        );
        assert!(
            routing(json!({
                "timestamp": 1727000000000u64,
                "groupUpdated": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "revision": 7,
                    "expireTimerSeconds": 4294967296u64,
                },
            }))
            .is_none()
        );

        // A missing groupId still routes the control (the value is honest);
        // the service layer drops it warn-only when nothing resolves.
        let (control, group_id, _) = routing(json!({
            "timestamp": 1727000000000u64,
            "groupUpdated": { "revision": 8, "expireTimerSeconds": 60 },
        }))
        .expect("the value survives a missing group reference");
        assert!(matches!(
            control,
            ControlReceive::GroupTimerUpdate {
                expire_timer_seconds: 60,
                ..
            }
        ));
        assert!(group_id.is_none());
    }

    /// Rich-body fields (contract 1.25) ride a dataMessage through
    /// normalization bounded: cards/ranges capped, strings truncated, invalid
    /// styles dropped — and a plain message carries no rich payload at all.
    #[test]
    fn data_message_rich_fields_normalize_bounded() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let rich = normalize(json!({
            "message": "hello @peer check this link",
            "viewOnce": true,
            "previews": [{
                "url": "https://example.com/article",
                "title": "An article",
                "description": "Readable summary",
                "image": { "id": "att-1", "contentType": "image/jpeg",
                           "filename": "card.jpg", "size": 2048,
                           "width": 64, "height": 32 },
            }],
            "mentions": [{ "number": "+15555550101", "name": "Peer",
                           "start": 6, "length": 4 }],
            "textStyles": [
                { "style": "BOLD", "start": 0, "length": 5 },
                { "style": "SPOILER", "start": 6, "length": 4 },
            ],
        }))
        .rich
        .expect("rich payload");
        assert_eq!(rich.previews.len(), 1);
        assert_eq!(rich.previews[0].url, "https://example.com/article");
        assert_eq!(rich.previews[0].title.as_deref(), Some("An article"));
        assert_eq!(
            rich.previews[0]
                .image
                .as_ref()
                .map(|image| image.id.as_str()),
            Some("att-1")
        );
        assert_eq!(rich.mentions.len(), 1);
        assert_eq!(rich.mentions[0].author, "+15555550101");
        assert_eq!(rich.mentions[0].name.as_deref(), Some("Peer"));
        assert_eq!(rich.mentions[0].start, 6);
        assert_eq!(rich.mentions[0].length, 4);
        // Contract 1.40 (§4.40): a number-only envelope has no honest ACI.
        assert_eq!(rich.mentions[0].author_aci, None);
        assert_eq!(
            rich.text_styles
                .iter()
                .map(|style| style.style.as_str())
                .collect::<Vec<_>>(),
            ["BOLD", "SPOILER"]
        );
        assert!(rich.view_once);

        // A plain message carries nothing.
        let plain = normalize(json!({ "message": "hello" }));
        assert!(plain.rich.is_none());
    }

    /// Live gift-badge face (contract 1.181, §4.181): the engine's P14
    /// receive projection `{state, expiration, level,
    /// receiptCredentialPresentation}` parses onto the §4.38 archive twin —
    /// state lowercased onto the desktop wire vocabulary, the countdown pair
    /// kept (a zero expiration is no countdown), the zk credential
    /// presentation never captured, and degraded shapes dropping the key
    /// without dropping the row.
    #[test]
    fn live_gift_badge_parses_the_countdown_pair_and_drops_degraded_shapes() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let rich = normalize(json!({
            "message": "",
            "giftBadge": {
                "state": "UNOPENED",
                "expiration": 1767225600000u64,
                "level": 1,
                "receiptCredentialPresentation": "cHJlc2VudGF0aW9u",
            },
        }))
        .rich
        .expect("the gift badge alone is rich");
        let badge = rich.gift_badge.expect("gift badge face");
        assert_eq!(badge.state, "unopened");
        assert_eq!(badge.expiration_ms, Some(1767225600000u64));
        assert_eq!(badge.level, Some(1));
        // The zk credential material never rides the row.
        let wire = serde_json::to_value(&badge).unwrap();
        assert_eq!(
            wire,
            json!({"state": "unopened", "expirationMs": 1767225600000u64, "level": 1})
        );

        // A FAILED badge with no countdown pair keeps the state alone.
        let rich = normalize(json!({ "message": "", "giftBadge": {"state": "Failed"} }))
            .rich
            .expect("rich payload");
        assert_eq!(
            serde_json::to_value(rich.gift_badge.unwrap()).unwrap(),
            json!({"state": "failed"})
        );

        // A zero expiration is no countdown; a missing level stays absent.
        let rich = normalize(json!({
            "message": "",
            "giftBadge": {"state": "OPENED", "expiration": 0, "level": 2},
        }))
        .rich
        .expect("rich payload");
        let badge = rich.gift_badge.unwrap();
        assert_eq!(badge.state, "opened");
        assert_eq!(badge.expiration_ms, None);
        assert_eq!(badge.level, Some(2));

        // Degraded shapes drop the key, never the row.
        for degraded in [
            json!({"state": 7}),
            json!({"expiration": 1767225600000u64}),
            json!("not-an-object"),
        ] {
            let face = normalize(json!({ "message": "", "giftBadge": degraded }));
            assert!(
                face.rich.is_none(),
                "a degraded gift badge carries no rich payload"
            );
        }
    }

    /// Rich bounds (§4.20): entries past a cap drop, oversized strings
    /// truncate, malformed entries and unknown styles drop individually.
    #[test]
    fn rich_fields_enforce_bounds() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let previews = (0..8)
            .map(|index| json!({ "url": format!("https://example.com/{index}"), "title": "t" }))
            .collect::<Vec<_>>();
        let mentions = (0..70)
            .map(
                |index| json!({ "number": format!("+1555555010{index}"), "start": 0, "length": 1 }),
            )
            .collect::<Vec<_>>();
        let long_url = "https://example.com/".repeat(300);
        let rich = normalize(json!({
            "message": "rich",
            "previews": previews,
            "mentions": mentions,
            "textStyles": [
                { "style": "NONE", "start": 0, "length": 1 },
                { "style": "MAGIC", "start": 0, "length": 1 },
                { "style": "MONOSPACE", "start": 0, "length": 1 },
                { "style": "BOLD", "start": 0 },
                { "style": "BOLD" },
            ],
        }))
        .rich
        .expect("rich payload");
        assert_eq!(rich.previews.len(), MAX_PREVIEWS);
        assert_eq!(rich.mentions.len(), MAX_MENTIONS);
        assert_eq!(
            rich.text_styles.len(),
            1,
            "only the valid MONOSPACE range survives"
        );
        assert_eq!(rich.text_styles[0].style, "MONOSPACE");

        let truncated = normalize(json!({
            "message": "long",
            "previews": [{ "url": long_url, "title": "x".repeat(2000) }],
        }))
        .rich
        .expect("rich payload");
        assert_eq!(
            truncated.previews[0].url.chars().count(),
            MAX_PREVIEW_URL_CHARS
        );
        assert!(
            truncated.previews[0].title.as_ref().unwrap().len() <= MAX_PREVIEW_FIELD_BYTES,
            "title truncates to its byte bound"
        );

        // All-default shapes collapse to None, malformed entries never fail
        // the message.
        let none = normalize(json!({
            "message": "plain",
            "previews": [{ "title": "no url" }],
            "mentions": [{ "name": "no author", "start": 0, "length": 1 }],
            "textStyles": [{ "style": "MAGIC", "start": 0, "length": 1 }],
            "viewOnce": false,
        }));
        assert!(none.rich.is_none());
    }

    /// The engine's P14 attachment metadata keys (contract 1.107, §4.88)
    /// parse per-key fail-closed: caption/blurHash verbatim when non-empty,
    /// the integrity pair all-or-nothing, the two flag booleans answering
    /// false on any hostile shape — and a legacy face without the keys keeps
    /// the exact pre-1.107 descriptor.
    #[test]
    fn attachment_p14_metadata_keys_parse_per_key() {
        let attachments = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": { "attachments": [data] },
                },
            }))
            .unwrap()
            .attachments
        };
        let full = &attachments(json!({
            "id": "att-1",
            "contentType": "image/png",
            "filename": "shot.png",
            "size": 2048,
            "caption": "a sunset",
            "blurHash": "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
            "incrementalMac": "AQIDBA==",
            "chunkSize": 8192,
            "isVoiceNote": false,
            "isBorderless": true,
            "isGif": true,
        }))[0];
        assert_eq!(full.caption.as_deref(), Some("a sunset"));
        assert_eq!(
            full.blur_hash.as_deref(),
            Some("LEHV6nWB2yk8pyo0adR*.7kCMdnj")
        );
        assert_eq!(full.incremental_mac.as_deref(), Some("AQIDBA=="));
        assert_eq!(full.chunk_size, Some(8192));
        assert!(full.is_borderless);
        assert!(full.is_gif);

        // 同进同退: half a pair verifies nothing — both keys drop together.
        let half = &attachments(json!({
            "id": "att-2",
            "incrementalMac": "AQIDBA==",
            "chunkSize": 0,
        }))[0];
        assert_eq!(half.incremental_mac, None);
        assert_eq!(half.chunk_size, None);
        let other_half = &attachments(json!({ "id": "att-3", "chunkSize": 8 }))[0];
        assert_eq!(other_half.incremental_mac, None);
        assert_eq!(other_half.chunk_size, None);

        // Zero-information and hostile shapes answer absent/false — never a
        // mangled key.
        let hostile = &attachments(json!({
            "id": "att-4",
            "caption": "",
            "blurHash": 42,
            "isBorderless": "yes",
            "isGif": 1,
        }))[0];
        assert_eq!(hostile.caption, None);
        assert_eq!(hostile.blur_hash, None);
        assert!(!hostile.is_borderless);
        assert!(!hostile.is_gif);

        // A legacy face keeps the pre-1.107 descriptor byte-identical.
        let legacy = &attachments(json!({ "id": "att-5", "size": 7 }))[0];
        assert_eq!(legacy.caption, None);
        assert_eq!(legacy.blur_hash, None);
        assert_eq!(legacy.incremental_mac, None);
        assert_eq!(legacy.chunk_size, None);
        assert!(!legacy.is_borderless);
        assert!(!legacy.is_gif);
    }

    /// The inbound filename face (contract 1.184, §4.184): the sender's name
    /// rides verbatim — long Unicode names, spaces, multi-extensions — where
    /// the retired 128-byte budget rewrote real names. The only rewrites are
    /// the official's own filters: path components flatten (basename, both
    /// separators), the schema-v9 bidi set maps to U+FFFD — and nothing else
    /// is touched (no C0 sweep, no extension verdict), the pure-traversal and
    /// flatten-to-nothing faces answering absent rather than invented, the
    /// filesystem-scale clamp bounding only hostile oversized faces.
    #[test]
    fn inbound_filename_rides_verbatim_and_official_filters_only() {
        let attachments = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": { "attachments": [data] },
                },
            }))
            .unwrap()
            .attachments
        };
        let filename = |raw: &str| {
            attachments(json!({ "id": "att-1", "filename": raw }))[0]
                .filename
                .clone()
        };

        // A 200-CJK-char name (600+ bytes) with spaces and multi-extensions —
        // every byte of it filesystem-legal and, since 1.184, wire-exact (the
        // old 128-byte budget truncated this to a quarter).
        let long_unicode = format!("{}项目 报告 草稿.backup.final.pdf", "文".repeat(200));
        assert_eq!(filename(&long_unicode), Some(long_unicode.clone()));
        // Far past the retired 128-byte budget — the rewrite this batch removes.
        assert!(long_unicode.len() > 128);

        // The official filter family: path components flatten, both
        // separators, basename semantics.
        assert_eq!(filename("a/b.txt").as_deref(), Some("b.txt"));
        assert_eq!(filename("..\\..\\win.txt").as_deref(), Some("win.txt"));
        assert_eq!(filename("报告/合同.docx").as_deref(), Some("合同.docx"));
        assert_eq!(filename("a//b.txt").as_deref(), Some("b.txt"));
        assert_eq!(filename("a/b/.txt").as_deref(), Some(".txt"));
        // Dots that are not traversal ride: "..." is a legal name.
        assert_eq!(filename("...").as_deref(), Some("..."));
        assert_eq!(filename("..a").as_deref(), Some("..a"));

        // Pure traversal or flatten-to-nothing faces answer absent — never a
        // made-up or half-safe name.
        assert_eq!(filename(".."), None);
        assert_eq!(filename("."), None);
        assert_eq!(filename("dir/.."), None);
        assert_eq!(filename("/"), None);
        assert_eq!(filename(""), None);

        // The official schema-v9 bidi set maps to U+FFFD (replaceUnicodeV2),
        // every other byte riding untouched.
        assert_eq!(
            filename("invoice\u{202E}fdp.exe").as_deref(),
            Some("invoice\u{FFFD}fdp.exe")
        );
        assert_eq!(
            filename("\u{200E}note\u{2066}x\u{061C}").as_deref(),
            Some("\u{FFFD}note\u{FFFD}x\u{FFFD}")
        );

        // 仅限官方同款: the official has no C0 filter and no extension
        // verdict at the protocol layer — newlines, tabs and the
        // isFileDangerous family ride exactly as sent.
        assert_eq!(
            filename("line1\nline2\treport.vbs").as_deref(),
            Some("line1\nline2\treport.vbs")
        );

        // The clamp is boundedness insurance at filesystem-name scale (1024
        // bytes = the 255-UTF-16-unit per-component cap's UTF-8 worst case):
        // ASCII clamps to the budget, CJK clamps on a char boundary.
        let ascii_herd = "F".repeat(2000);
        let clamped = filename(&ascii_herd).unwrap();
        assert_eq!(clamped.len(), 1024);
        let cjk_herd = "長".repeat(400);
        let clamped = filename(&cjk_herd).unwrap();
        assert_eq!(clamped, "長".repeat(341));
        assert_eq!(clamped.len(), 1023);

        // The quote face shares the one parser: a long quoted name rides
        // verbatim too.
        let quote = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {
                    "message": "replying to media",
                    "quote": {
                        "id": 7,
                        "authorNumber": "+15555550102",
                        "attachments": [{ "filename": long_unicode }],
                    },
                },
            },
        }))
        .unwrap()
        .unwrap()
        .quote
        .unwrap();
        assert_eq!(
            quote.attachments[0].filename.as_deref(),
            Some(long_unicode.as_str())
        );
    }

    /// The engine's voice-waveform pair (contract 1.150, §4.149) parses
    /// per-key verbatim: the 100-byte waveform rides its standard base64
    /// spelling byte-for-byte and the duration its float seconds, the keys
    /// stay independent (pairing is the engine's generation invariant, not a
    /// connector gate), a voice and a plain attachment coexist with their own
    /// faces, zero-information and hostile shapes answer absent, and a
    /// pre-1.150 face keeps the exact descriptor (the wire round-trip never
    /// grows the keys).
    #[test]
    fn attachment_voice_waveform_pair_parses_verbatim() {
        // The engine's fixed shape: 100 dB buckets (bytes 0..=99), 136 base64
        // chars — pinned whole so a re-encode or trim can never slip through.
        const WAVEFORM_100B_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw==";
        assert_eq!(WAVEFORM_100B_B64.len(), 136);
        let attachments = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": { "attachments": data },
                },
            }))
            .unwrap()
            .attachments
        };

        // Voice note beside a plain attachment: each descriptor carries its
        // own face, and the plain one never grows the keys.
        let pair = attachments(json!([
            {
                "id": "voice-1",
                "contentType": "audio/aac",
                "size": 2048,
                "isVoiceNote": true,
                "waveform": WAVEFORM_100B_B64,
                "duration": 3.7,
            },
            {
                "id": "img-1",
                "contentType": "image/png",
                "size": 12,
            },
        ]));
        assert_eq!(pair.len(), 2);
        let voice = &pair[0];
        assert!(voice.is_voice_note);
        assert_eq!(voice.waveform.as_deref(), Some(WAVEFORM_100B_B64));
        assert_eq!(voice.duration, Some(3.7));
        let plain = &pair[1];
        assert!(!plain.is_voice_note);
        assert_eq!(plain.waveform, None);
        assert_eq!(plain.duration, None);

        // The keys are independent — the connector forwards what is stated
        // and never gates on the engine's pairing invariant.
        let halves = attachments(json!([
            { "id": "w-only", "waveform": WAVEFORM_100B_B64 },
            { "id": "d-only", "duration": 12.5 },
        ]));
        assert_eq!(halves[0].waveform.as_deref(), Some(WAVEFORM_100B_B64));
        assert_eq!(halves[0].duration, None);
        assert_eq!(halves[1].waveform, None);
        assert_eq!(halves[1].duration, Some(12.5));

        // Zero-information and hostile shapes answer absent — never a
        // mangled key. An over-cap "waveform" is not the engine's fixed
        // shape and drops whole (never truncated into unusable render
        // material).
        let hostile = attachments(json!([
            { "id": "h1", "waveform": "" },
            { "id": "h2", "waveform": 42 },
            { "id": "h3", "waveform": "QUJD".repeat(129) },
            { "id": "h4", "duration": 0 },
            { "id": "h5", "duration": -1.5 },
            { "id": "h6", "duration": "3.7" },
        ]));
        assert!(hostile.iter().all(|face| face.waveform.is_none()));
        assert!(hostile.iter().all(|face| face.duration.is_none()));

        // A pre-1.150 face keeps the exact descriptor, and the wire
        // round-trip never grows the keys.
        let legacy = attachments(json!([
            { "id": "old-1", "contentType": "audio/aac", "isVoiceNote": true },
        ]));
        let legacy = &legacy[0];
        assert!(legacy.is_voice_note);
        assert_eq!(legacy.waveform, None);
        assert_eq!(legacy.duration, None);
        let round_trip = serde_json::to_value(legacy).unwrap();
        assert!(round_trip.get("waveform").is_none());
        assert!(round_trip.get("duration").is_none());
    }

    /// A message attachment without a usable engine id keeps its metadata
    /// and locator (the live projection emits an empty id when the pointer
    /// has no client_uuid; the archive export omits the key entirely). The
    /// strict id requirement stays for metadata-only pointer slots — an
    /// id-less quote thumbnail / sticker pointer still drops whole.
    #[test]
    fn message_attachments_without_engine_ids_keep_metadata() {
        let parsed = normalize_receive_fields(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {
                    "attachments": [{
                        "contentType": "image/png",
                        "filename": "restored.png",
                        "size": 12,
                        "locator": {
                            "key": "q83vLNoechoM6CiZ+hr3P5ePE3YGAibLE4bAl1jv20Y=",
                            "cdnKey": "restored",
                            "cdnNumber": 0,
                            "uploadTimestamp": 1_700_000_000_000u64,
                            "plaintextHash": "a".repeat(64),
                        }
                    }]
                },
            },
        }))
        .unwrap();
        assert_eq!(parsed.attachments.len(), 1, "metadata survives an empty id");
        let descriptor = &parsed.attachments[0];
        assert_eq!(descriptor.id, "", "the receive arm fills the synthetic id");
        assert_eq!(descriptor.content_type.as_deref(), Some("image/png"));
        assert_eq!(descriptor.filename.as_deref(), Some("restored.png"));
        assert_eq!(descriptor.size, Some(12));
        assert!(
            descriptor.locator.is_some(),
            "the transit face survives with the metadata"
        );

        // The strict face is unchanged: an id-less metadata-only pointer has
        // no addressable handle and still answers None.
        assert!(
            normalized_attachment(
                json!({"contentType": "image/png", "size": 12})
                    .as_object()
                    .unwrap()
            )
            .is_none()
        );
    }

    /// The engine's P14 rich faces (contract 1.107, §4.88) parse per-key:
    /// `expireTimerVersion` only when positive and in u32 range, the preview
    /// date only when positive, the recipient-update bit only on `true`, and
    /// the two Sent lists bounded with per-key degradation — while a face
    /// carrying none of them stays an all-default (None) rich.
    #[test]
    fn rich_p14_faces_parse_per_key() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let rich = normalize(json!({
            "message": "p14 carrier",
            "expireTimerVersion": 3,
            "previews": [{ "url": "https://example.com/a", "date": 1_600_000_000_000u64 }],
            "isRecipientUpdate": true,
            "unidentifiedStatus": [
                {
                    "destinationUuid": "PNI:00000000-0000-0000-0000-000000000001",
                    "unidentified": true,
                    "destinationPniIdentityKey": "iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
                },
                { "unidentified": false },
            ],
            "storyMessageRecipients": [
                {
                    "destinationUuid": "11111111-2222-4333-8444-555555555555",
                    "distributionListIds": ["00000000-0000-0000-0000-000000000000"],
                    "isAllowedToReply": false,
                },
                { "destinationUuid": "22222222-2222-4333-8444-555555555555" },
            ],
        }))
        .rich
        .expect("p14 rich payload");
        assert_eq!(rich.expire_timer_version, Some(3));
        assert_eq!(rich.previews[0].date, Some(1_600_000_000_000));
        assert!(rich.is_recipient_update);
        assert_eq!(rich.unidentified_status.len(), 2);
        assert_eq!(
            rich.unidentified_status[0].destination_uuid.as_deref(),
            Some("PNI:00000000-0000-0000-0000-000000000001")
        );
        assert_eq!(rich.unidentified_status[0].unidentified, Some(true));
        assert_eq!(
            rich.unidentified_status[0]
                .destination_pni_identity_key
                .as_deref(),
            Some("iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=")
        );
        assert_eq!(rich.unidentified_status[1].destination_uuid, None);
        assert_eq!(rich.unidentified_status[1].unidentified, Some(false));
        assert_eq!(rich.story_message_recipients.len(), 2);
        assert_eq!(
            rich.story_message_recipients[0].distribution_list_ids,
            ["00000000-0000-0000-0000-000000000000"]
        );
        assert_eq!(
            rich.story_message_recipients[0].is_allowed_to_reply,
            Some(false)
        );
        assert!(
            rich.story_message_recipients[1]
                .distribution_list_ids
                .is_empty()
        );
        assert_eq!(rich.story_message_recipients[1].is_allowed_to_reply, None);

        // Zero-information and hostile shapes degrade per-key: 0 / absent
        // version stamps, a false recipient-update bit, an over-bound PNI
        // key, a version past the u32 ceiling.
        let hostile = normalize(json!({
            "message": "degraded carrier",
            "expireTimerVersion": 4294967296u64,
            "previews": [{ "url": "https://example.com/b", "date": 0 }],
            "isRecipientUpdate": false,
            "unidentifiedStatus": [{
                "destinationPniIdentityKey": "x".repeat(200),
            }],
        }))
        .rich
        .expect("degraded rich payload");
        assert_eq!(hostile.expire_timer_version, None);
        assert_eq!(hostile.previews[0].date, None);
        assert!(!hostile.is_recipient_update);
        assert_eq!(
            hostile.unidentified_status[0].destination_pni_identity_key,
            None
        );

        // A plain dataMessage carries none of the faces — and the key-absent
        // rich still collapses to None (the plain-row discipline holds).
        let plain = normalize(json!({ "message": "hello" }));
        assert!(plain.rich.is_none());
    }

    /// Old-row discipline (contract 1.107, §4.88): persisted pre-1.107
    /// attachment and rich JSON — no P14 keys — deserializes cleanly and
    /// re-serializes without the new keys, so historical rows read
    /// byte-identical and the store read-back never invents defaults.
    #[test]
    fn legacy_attachment_and_rich_json_round_trip_without_p14_keys() {
        let legacy_attachment =
            r#"{"id":"att-1","contentType":"image/png","size":12,"isVoiceNote":false}"#;
        let parsed: NormalizedAttachment = serde_json::from_str(legacy_attachment).unwrap();
        assert_eq!(parsed.id, "att-1");
        assert_eq!(parsed.caption, None);
        assert_eq!(parsed.blur_hash, None);
        assert_eq!(parsed.incremental_mac, None);
        assert_eq!(parsed.chunk_size, None);
        assert!(!parsed.is_borderless);
        assert!(!parsed.is_gif);
        let round = serde_json::to_string(&parsed).unwrap();
        assert!(!round.contains("caption"));
        assert!(!round.contains("blurHash"));
        assert!(!round.contains("incrementalMac"));
        assert!(!round.contains("chunkSize"));
        // The two flag booleans share the isVoiceNote always-boolean shape:
        // they serialize even when false, so the trio reads without key
        // probing on every face.
        assert!(round.contains("\"isBorderless\":false"));
        assert!(round.contains("\"isGif\":false"));

        let legacy_rich = r#"{"previews":[{"url":"https://example.com/a"}]}"#;
        let rich: NormalizedRich = serde_json::from_str(legacy_rich).unwrap();
        assert_eq!(rich.expire_timer_version, None);
        assert!(!rich.is_recipient_update);
        assert!(rich.unidentified_status.is_empty());
        assert!(rich.story_message_recipients.is_empty());
        let rich_round = serde_json::to_string(&rich).unwrap();
        assert!(!rich_round.contains("expireTimerVersion"));
        assert!(!rich_round.contains("isRecipientUpdate"));
        assert!(!rich_round.contains("unidentifiedStatus"));
        assert!(!rich_round.contains("storyMessageRecipients"));
    }

    /// The §4.40 authorAci promotion (contract 1.40): the ACI appears only
    /// when the upstream honestly supplies one — the signal-cli `uuid` field,
    /// or a UUID-shaped number key (the engine-mode receive face puts the
    /// ACI there). The author value itself never moves off the pre-1.40
    /// number-first ladder, and a phone number never promotes.
    #[test]
    fn mention_author_aci_promotes_only_from_honest_sources() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        // signal-cli shape: number + uuid — author keeps the number, the ACI
        // rides authorAci.
        let rich = normalize(json!({
            "message": "hi",
            "mentions": [{
                "number": "+15555550101",
                "uuid": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                "name": "Peer",
                "start": 0,
                "length": 2,
            }],
        }))
        .rich
        .expect("rich payload");
        assert_eq!(rich.mentions[0].author, "+15555550101");
        assert_eq!(
            rich.mentions[0].author_aci.as_deref(),
            Some("0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10")
        );

        // signal-cli shape with an unknown number: only the uuid — the author
        // is the uuid and the ACI is the same value.
        let rich = normalize(json!({
            "message": "hi",
            "mentions": [{
                "uuid": "0B7FCA57-1234-4D0E-9B0F-4F6C1F8A2E10",
                "start": 0,
                "length": 2,
            }],
        }))
        .rich
        .expect("rich payload");
        assert_eq!(
            rich.mentions[0].author,
            "0B7FCA57-1234-4D0E-9B0F-4F6C1F8A2E10"
        );
        assert_eq!(
            rich.mentions[0].author_aci.as_deref(),
            Some("0B7FCA57-1234-4D0E-9B0F-4F6C1F8A2E10"),
            "the grammar is case-insensitive"
        );

        // Engine-mode receive face: the ACI under the number key — promoted
        // by shape, author unchanged.
        let rich = normalize(json!({
            "message": "hi",
            "mentions": [{
                "number": "d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df1",
                "start": 0,
                "length": 2,
            }],
        }))
        .rich
        .expect("rich payload");
        assert_eq!(
            rich.mentions[0].author,
            "d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df1"
        );
        assert_eq!(
            rich.mentions[0].author_aci.as_deref(),
            Some("d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df1")
        );

        // Phone numbers, truncated and decorated values never promote.
        let rich = normalize(json!({
            "message": "hi",
            "mentions": [
                { "number": "+15555550101", "start": 0, "length": 2 },
                { "number": "d43e8ea0-3f6c-4a57-8a5c-51f83f8e5df", "start": 0, "length": 2 },
                { "number": "not-a-uuid-at-all-00000000000000", "start": 0, "length": 2 },
            ],
        }))
        .rich
        .expect("rich payload");
        assert!(
            rich.mentions
                .iter()
                .all(|mention| mention.author_aci.is_none()),
            "no entry in this envelope carries an honest ACI"
        );
    }

    /// The multi-device sentMessage mirror carries the same rich payload as a
    /// direct dataMessage (contract 1.25), so our own phone-originated rich
    /// sends render identically after a restart.
    #[test]
    fn sync_sent_message_mirror_carries_rich_fields() {
        let normalized = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1727000000000u64,
                        "destinationNumber": "+15555550101",
                        "message": "from my phone",
                        "previews": [{ "url": "https://example.com" }],
                    },
                },
            },
        }))
        .unwrap();
        assert_eq!(normalized.direction, "outgoing");
        let rich = normalized.rich.expect("rich payload");
        assert_eq!(rich.previews[0].url, "https://example.com");
    }

    /// Contract 1.38 (§4.37): a peer's view-once open notification mirrors to
    /// our own devices as `syncMessage.viewOnceOpen` — projected as an
    /// incoming control addressed to no conversation (the service layer
    /// resolves the target row by (author ACI, timestamp)).
    #[test]
    fn sync_view_once_open_projects_as_incoming_control() {
        let normalized = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "viewOnceOpen": {
                        "senderAci": "11111111-1111-1111-1111-111111111111",
                        "timestamp": 1726999999000u64,
                    },
                },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.content_kind, "control");
        assert_eq!(normalized.direction, "incoming");
        assert!(normalized.source.is_none());
        let Some(ControlReceive::ViewOnceOpen {
            sender_aci,
            timestamp,
        }) = normalized.control
        else {
            panic!("expected a view-once open control");
        };
        assert_eq!(sender_aci, "11111111-1111-1111-1111-111111111111");
        assert_eq!(timestamp, 1726999999000);
    }

    /// Contract 1.38: an open sync without a resolvable author has no target
    /// the service layer could name — dropped as skip before persistence.
    #[test]
    fn sync_view_once_open_without_sender_aci_is_skip() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": { "viewOnceOpen": { "timestamp": 1726999999000u64 } },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.content_kind, "syncMessage");
        assert_eq!(normalized.direction, "skip");
        assert!(normalized.control.is_none());
    }

    /// Contract 1.38: the open sync's timestamp is the official unknown
    /// marker (0) when the engine omits it — the service layer drops those.
    #[test]
    fn sync_view_once_open_defaults_missing_timestamp_to_zero() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "viewOnceOpen": { "senderAci": "11111111-1111-1111-1111-111111111111" },
                },
            },
        }))
        .unwrap()
        .unwrap();
        let Some(ControlReceive::ViewOnceOpen { timestamp, .. }) = normalized.control else {
            panic!("expected a view-once open control");
        };
        assert_eq!(timestamp, 0);
    }

    /// Contract 1.100 (§4.81): the engine's `syncMessage.read[]` /
    /// `.viewed[]` projection routes as a control receive addressed by the
    /// entries' own senders; unusable entries drop before the variant;
    /// a face with no usable entry at all falls through to the plain
    /// syncMessage skip.
    #[test]
    fn sync_read_viewed_routes_bounded_control_entries() {
        let entry = |uuid: &str, timestamp: u64, number: Option<&str>| {
            let mut object = json!({ "senderUuid": uuid, "timestamp": timestamp });
            if let Some(number) = number {
                object["senderNumber"] = json!(number);
            }
            object
        };
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "sourceUuid": "99999999-9999-9999-9999-999999999999",
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncReadState { read, viewed }, source)) = routing(json!({
            "read": [
                entry("11111111-1111-1111-1111-111111111111", 1726999999000, Some("+15555550101")),
                // Unusable: no timestamp, no sender — both drop.
                { "senderUuid": "22222222-2222-2222-2222-222222222222" },
                { "timestamp": 1726999998000u64 },
            ],
            "viewed": [
                entry("11111111-1111-1111-1111-111111111111", 1726999997000, None),
            ],
        })) else {
            panic!("expected a sync read control routing");
        };
        assert_eq!(read.len(), 1, "{read:?}");
        assert_eq!(read[0].sender_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(read[0].sender_number.as_deref(), Some("+15555550101"));
        assert_eq!(read[0].timestamp, 1726999999000);
        assert_eq!(viewed.len(), 1);
        assert_eq!(viewed[0].timestamp, 1726999997000);
        assert!(source.is_none(), "the envelope is our own account");

        // Both faces empty (or absent) → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "read": [], "viewed": [] }),
            json!({ "read": [{ "timestamp": 1726999999000u64 }] }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.102 (§4.83): the engine's `syncMessage.deleteForMe`
    /// projection routes as a control receive carrying the bounded groups —
    /// unusable entries drop, a group whose entries all drop drops whole,
    /// the conversation identity rides optional, and a face with no usable
    /// group at all falls through to the plain syncMessage skip.
    #[test]
    fn sync_delete_for_me_routes_bounded_groups() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncDeleteForMe { deletes }, source)) = routing(json!({
            "deleteForMe": {
                "messageDeletes": [
                    {
                        "conversationId": "11111111-1111-1111-1111-111111111111",
                        "messages": [
                            {
                                "author": "22222222-2222-2222-2222-222222222222",
                                "timestamp": 1726999999000u64,
                            },
                            // Unusable: no author, no timestamp — both drop.
                            { "timestamp": 1726999998000u64 },
                            { "author": "+15555550101" },
                            // The engine's unknown marker: timestamp 0 drops.
                            { "author": "+15555550103", "timestamp": 0u64 },
                        ],
                    },
                    {
                        // No conversation identity — the entries still ride.
                        "messages": [
                            { "author": "+15555550102", "timestamp": 1726999997000u64 },
                        ],
                    },
                    // Unusable group: every entry drops → the group drops.
                    { "conversationId": "abc", "messages": [{ "author": "x" }] },
                ],
            },
        })) else {
            panic!("expected a sync delete control routing");
        };
        assert_eq!(deletes.groups.len(), 2, "{deletes:?}");
        assert_eq!(
            deletes.groups[0].conversation_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(deletes.groups[0].messages.len(), 1);
        assert_eq!(
            deletes.groups[0].messages[0].author,
            "22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(deletes.groups[0].messages[0].timestamp, 1726999999000);
        assert!(deletes.groups[1].conversation_id.is_none());
        assert_eq!(deletes.groups[1].messages[0].author, "+15555550102");
        assert_eq!(deletes.groups[1].messages[0].timestamp, 1726999997000);
        assert!(deletes.conversations.is_empty(), "no conversation arm");
        assert!(deletes.local_only_conversations.is_empty());
        assert!(source.is_none(), "the envelope is our own account");

        // No usable group at all → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "deleteForMe": {} }),
            json!({ "deleteForMe": { "messageDeletes": [] } }),
            json!({ "deleteForMe": { "messageDeletes": [{ "messages": [] }] } }),
            json!({ "deleteForMe": { "messageDeletes": [{ "messages": [{ "author": "a" }] }] } }),
            json!({ "deleteForMe": { "messageDeletes": [{ "messages": [{ "timestamp": 1726999999000u64 }] }] } }),
            json!({ "deleteForMe": { "messageDeletes": [{ "conversationId": "c", "messages": [{ "author": "a", "timestamp": 0u64 }] }] } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.182 (§4.182): the two whole-conversation arms route on
    /// their own (a conversation arm alone is not the plain skip), carry the
    /// official gates — a `conversationDeletes` entry without an identity or
    /// with every primary anchor dropped drops whole, its non-expiring
    /// companion is optional and may be empty, and `isFullDelete` folds to
    /// the official `Boolean()` (only a literal true reads true) — while a
    /// `localOnlyConversationDeletes` entry needs only its identity.
    #[test]
    fn sync_delete_for_me_conversation_arms_route_and_gate() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncDeleteForMe { deletes }, source)) = routing(json!({
            "deleteForMe": {
                "conversationDeletes": [
                    {
                        "conversationId": "11111111-1111-1111-1111-111111111111",
                        "isFullDelete": true,
                        "mostRecentMessages": [
                            { "author": "+15555550101", "timestamp": 1726999999000u64 },
                        ],
                        "mostRecentNonExpiringMessages": [
                            { "author": "+15555550102", "timestamp": 1726999998000u64 },
                            // Unusable anchors drop like message-delete entries.
                            { "author": "+15555550103", "timestamp": 0u64 },
                            { "timestamp": 1726999997000u64 },
                        ],
                    },
                    {
                        // The flag is absent: the official Boolean() reads false.
                        "conversationId": "22222222-2222-2222-2222-222222222222",
                        "mostRecentMessages": [
                            { "author": "+15555550104", "timestamp": 1726999996000u64 },
                        ],
                    },
                    {
                        // Companion absent: the empty list is honest.
                        "conversationId": "33333333-3333-3333-3333-333333333333",
                        "isFullDelete": false,
                        "mostRecentMessages": [
                            { "author": "+15555550105", "timestamp": 1726999995000u64 },
                        ],
                    },
                    // No conversation identity → drop whole.
                    {
                        "isFullDelete": true,
                        "mostRecentMessages": [
                            { "author": "+15555550106", "timestamp": 1726999994000u64 },
                        ],
                    },
                    // Every primary anchor drops → drop whole (the official
                    // "No target messages" gate).
                    {
                        "conversationId": "44444444-4444-4444-4444-444444444444",
                        "mostRecentMessages": [{ "author": "+15555550107" }],
                    },
                    {
                        "conversationId": "   ",
                        "mostRecentMessages": [
                            { "author": "+15555550108", "timestamp": 1726999993000u64 },
                        ],
                    },
                ],
                "localOnlyConversationDeletes": [
                    { "conversationId": "55555555-5555-5555-5555-555555555555" },
                    // No identity → drop whole.
                    {},
                    { "conversationId": "" },
                ],
            },
        })) else {
            panic!("expected a sync delete control routing");
        };
        assert!(source.is_none(), "the envelope is our own account");
        assert!(deletes.groups.is_empty(), "no message arm");

        assert_eq!(deletes.conversations.len(), 3, "{deletes:?}");
        assert!(deletes.conversations[0].is_full_delete);
        assert_eq!(
            deletes.conversations[0].conversation_id,
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(deletes.conversations[0].most_recent_messages.len(), 1);
        assert_eq!(
            deletes.conversations[0].most_recent_messages[0].timestamp,
            1726999999000
        );
        // The junk anchors dropped; the usable one survived.
        assert_eq!(
            deletes.conversations[0]
                .most_recent_non_expiring_messages
                .len(),
            1
        );
        assert_eq!(
            deletes.conversations[0].most_recent_non_expiring_messages[0].author,
            "+15555550102"
        );
        assert!(!deletes.conversations[1].is_full_delete, "absent flag");
        assert!(
            deletes.conversations[1]
                .most_recent_non_expiring_messages
                .is_empty()
        );
        assert!(
            deletes.conversations[2]
                .most_recent_non_expiring_messages
                .is_empty()
        );

        assert_eq!(deletes.local_only_conversations.len(), 1, "{deletes:?}");
        assert_eq!(
            deletes.local_only_conversations[0].conversation_id,
            "55555555-5555-5555-5555-555555555555"
        );

        // A conversation arm alone routes; every arm failing falls through to
        // the plain skip.
        assert!(
            routing(json!({
                "deleteForMe": {
                    "localOnlyConversationDeletes": [{ "conversationId": "c" }],
                },
            }))
            .is_some()
        );
        for sync in [
            json!({ "deleteForMe": { "conversationDeletes": [] } }),
            json!({ "deleteForMe": { "conversationDeletes": [{}] } }),
            json!({ "deleteForMe": { "conversationDeletes": [
                { "conversationId": "c", "mostRecentMessages": [] },
            ] } }),
            json!({ "deleteForMe": { "localOnlyConversationDeletes": [{}] } }),
            json!({ "deleteForMe": { "localOnlyConversationDeletes": [] } }),
        ] {
            assert!(
                routing(sync.clone()).is_none(),
                "expected the plain skip: {sync}"
            );
        }

        // The caps bite by dropping the tail, never by truncating an entry.
        let too_many_anchors = (0..(MAX_SYNC_DELETE_CONVERSATION_ANCHORS + 4))
            .map(|index| {
                json!({
                    "author": "+15555550110",
                    "timestamp": 1726999990000u64 + index as u64,
                })
            })
            .collect::<Vec<_>>();
        let Some((ControlReceive::SyncDeleteForMe { deletes }, _)) = routing(json!({
            "deleteForMe": {
                "conversationDeletes": [{
                    "conversationId": "c",
                    "mostRecentMessages": too_many_anchors,
                }],
            },
        })) else {
            panic!("expected a sync delete control routing");
        };
        assert_eq!(
            deletes.conversations[0].most_recent_messages.len(),
            MAX_SYNC_DELETE_CONVERSATION_ANCHORS
        );
    }

    /// Contract 1.196 (§4.196): the `attachmentDeletes` arm routes on its
    /// own — conversation identity plus the target's (author, positive stamp)
    /// are hard gates (the official "No target conversation" / "No target
    /// message" warn-drops), the target stamp is stricter than the message
    /// arm (no zero default), at least one of clientUuid / fallbackDigest /
    /// fallbackPlaintextHash must survive, empty and over-bound legs drop
    /// individually, and the batch takes the message-arm 256 cap.
    #[test]
    fn sync_delete_for_me_attachment_arm_routes_and_gates() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };
        let entry =
            |conversation_id: &str, author: &str, timestamp: u64, legs: serde_json::Value| {
                let mut value = json!({
                    "conversationId": conversation_id,
                    "targetMessage": { "author": author, "timestamp": timestamp },
                });
                for (key, leg) in legs.as_object().unwrap() {
                    value[key.as_str()] = leg.clone();
                }
                value
            };

        let Some((ControlReceive::SyncDeleteForMe { deletes }, source)) = routing(json!({
            "deleteForMe": {
                "attachmentDeletes": [
                    // Each of the three legs alone.
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        1726999999000,
                        json!({ "clientUuid": "33333333-3333-3333-3333-333333333333" }),
                    ),
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        1726999998000,
                        json!({ "fallbackDigest": "ZGlnZXN0" }),
                    ),
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        1726999997000,
                        json!({ "fallbackPlaintextHash": "AABBCCDD" }),
                    ),
                    // All three legs.
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        1726999996000,
                        json!({
                            "clientUuid": "44444444-4444-4444-4444-444444444444",
                            "fallbackDigest": "ZGlnZXN0",
                            "fallbackPlaintextHash": "deadbeef",
                        }),
                    ),
                    // No conversation identity → drop.
                    {
                        "targetMessage": {
                            "author": "22222222-2222-2222-2222-222222222222",
                            "timestamp": 1726999995000u64,
                        },
                        "clientUuid": "55555555-5555-5555-5555-555555555555",
                    },
                    // No target message → drop.
                    {
                        "conversationId": "11111111-1111-1111-1111-111111111111",
                        "fallbackDigest": "ZGlnZXN0",
                    },
                    // Target author absent / stamp zero → drop (the
                    // official processAddressableMessage double gate).
                    {
                        "conversationId": "11111111-1111-1111-1111-111111111111",
                        "targetMessage": { "timestamp": 1726999994000u64 },
                        "fallbackDigest": "ZGlnZXN0",
                    },
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        0,
                        json!({ "fallbackDigest": "ZGlnZXN0" }),
                    ),
                    // All legs absent or empty → drop.
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        1726999993000,
                        json!({ "clientUuid": "  ", "fallbackDigest": "" }),
                    ),
                    // A non-hex plaintext hash drops that leg (the only
                    // leg here), so the entry drops whole.
                    entry(
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        1726999992000,
                        json!({ "fallbackPlaintextHash": "zzzz" }),
                    ),
                ],
            },
        })) else {
            panic!("expected a sync delete control routing");
        };
        assert!(source.is_none(), "the envelope is our own account");
        assert!(deletes.groups.is_empty(), "no message arm");
        assert!(deletes.conversations.is_empty(), "no conversation arm");
        assert!(deletes.local_only_conversations.is_empty());
        assert_eq!(deletes.attachments.len(), 4, "{deletes:?}");
        assert_eq!(
            deletes.attachments[0].client_uuid.as_deref(),
            Some("33333333-3333-3333-3333-333333333333")
        );
        assert!(deletes.attachments[0].fallback_digest.is_none());
        assert_eq!(
            deletes.attachments[1].fallback_digest.as_deref(),
            Some("ZGlnZXN0")
        );
        assert_eq!(
            deletes.attachments[2].fallback_plaintext_hash.as_deref(),
            Some("aabbccdd"),
            "the hash is normalized lowercase"
        );
        assert_eq!(
            deletes.attachments[3].target.author,
            "22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(deletes.attachments[3].target.timestamp, 1726999996000);
        assert!(deletes.attachments[3].client_uuid.is_some());
        assert!(deletes.attachments[3].fallback_digest.is_some());
        assert!(deletes.attachments[3].fallback_plaintext_hash.is_some());

        // The attachment arm alone routes; an empty/all-bad face falls back
        // to the plain syncMessage skip.
        assert!(
            routing(json!({
                "deleteForMe": {
                    "attachmentDeletes": [entry(
                        "c",
                        "a",
                        1,
                        json!({ "clientUuid": "u" }),
                    )],
                },
            }))
            .is_some()
        );
        for sync in [
            json!({ "deleteForMe": { "attachmentDeletes": [] } }),
            json!({ "deleteForMe": { "attachmentDeletes": [{}] } }),
            json!({ "deleteForMe": { "attachmentDeletes": [{
                "conversationId": "c",
                "targetMessage": { "author": "a", "timestamp": 1 },
            }] } }),
        ] {
            assert!(
                routing(sync.clone()).is_none(),
                "expected the plain skip: {sync}"
            );
        }

        // The batch cap mirrors the message arm: the tail drops.
        let too_many = (0..(MAX_SYNC_DELETE_GROUP_MESSAGES + 4))
            .map(|index| {
                entry(
                    "c",
                    "a",
                    1726999990000 + index as u64,
                    json!({ "clientUuid": format!("uuid-{index}") }),
                )
            })
            .collect::<Vec<_>>();
        let Some((ControlReceive::SyncDeleteForMe { deletes }, _)) = routing(json!({
            "deleteForMe": { "attachmentDeletes": too_many },
        })) else {
            panic!("expected a sync delete control routing");
        };
        assert_eq!(deletes.attachments.len(), MAX_SYNC_DELETE_GROUP_MESSAGES);
    }

    /// The engine's `syncMessage.attachmentBackfillResponse` projection
    /// (contract revision 1.175, §4.175; entry states 1.193, §4.193; the
    /// `longText` sibling 1.195, §4.195) routes as the backfill control with
    /// the target identities and the index-aligned entries: every entry
    /// keeps its official variant — pointer (with or without locator
    /// material) vs the `PENDING`/`TERMINAL_ERROR` status words — an unknown
    /// status word and an unparseable entry converge to `Status(Unknown)`
    /// without shifting the row, the error arm rides its word with no
    /// entries, and a target missing its author/stamp/conversation falls
    /// through to the plain skip. The sibling `longText` entry keeps the
    /// same typed oneof in its own slot, never joining the index-aligned
    /// list.
    #[test]
    fn sync_attachment_backfill_response_routes_target_and_entries() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncAttachmentBackfillResponse { response }, source)) =
            routing(json!({
                "attachmentBackfillResponse": {
                    "targetMessage": {
                        "author": "22222222-2222-2222-2222-222222222222",
                        "sentTimestamp": 1726999999000u64,
                    },
                    "targetConversation": { "groupId": "Z3JvdXA=" },
                    "attachments": [
                        { "status": "PENDING" },
                        {
                            "attachment": {
                                "id": "att-a",
                                "contentType": "image/png",
                                "locator": {
                                    "key": "a2F0LWtleQ==",
                                    "cdnKey": "cdn-a",
                                    "cdnNumber": 3,
                                    "uploadTimestamp": 1700000000000u64,
                                },
                            },
                        },
                        { "attachment": { "id": "att-b", "contentType": "image/png" } },
                        { "status": "TERMINAL_ERROR" },
                        { "status": "SOME_FUTURE_WORD" },
                        "not-an-entry",
                    ],
                    // Contract 1.195 (§4.195): the sibling longText entry.
                    "longText": { "status": "PENDING" },
                },
            }))
        else {
            panic!("expected a backfill-response control routing");
        };
        assert_eq!(response.author, "22222222-2222-2222-2222-222222222222");
        assert_eq!(response.sent_timestamp, 1726999999000);
        assert_eq!(response.conversation_group_id.as_deref(), Some("Z3JvdXA="));
        assert!(response.conversation_service_id.is_none());
        assert!(response.conversation_e164.is_none());
        assert!(response.error.is_none());
        // Contract 1.195 (§4.195): the longText sibling keeps its typed state
        // in its own slot and contributes no array position (the entry count
        // below stays six).
        assert_eq!(
            response.long_text,
            Some(BackfillEntry::Status(BackfillStatus::Pending))
        );
        // Index alignment, one entry per remote position: PENDING keeps its
        // status word (never folded into the pointer face), the pointers keep
        // their locator material (a locator-less pointer stays a pointer),
        // TERMINAL_ERROR keeps its own word, and the unknown/unparseable
        // faces converge to Unknown in place.
        assert_eq!(response.entries.len(), 6);
        assert_eq!(
            response.entries[0],
            BackfillEntry::Status(BackfillStatus::Pending)
        );
        let BackfillEntry::Locator(Some(face)) = &response.entries[1] else {
            panic!("pointer entry keeps its locator face");
        };
        assert_eq!(face.key.as_deref(), Some("a2F0LWtleQ=="));
        assert_eq!(face.cdn_key.as_deref(), Some("cdn-a"));
        assert_eq!(face.cdn_number, Some(3));
        assert_eq!(response.entries[2], BackfillEntry::Locator(None));
        assert_eq!(
            response.entries[3],
            BackfillEntry::Status(BackfillStatus::Terminal)
        );
        assert_eq!(
            response.entries[4],
            BackfillEntry::Status(BackfillStatus::Unknown)
        );
        assert_eq!(
            response.entries[5],
            BackfillEntry::Status(BackfillStatus::Unknown)
        );
        // The store-facing projection keeps the §4.175 shape: only the
        // locator-bearing pointer contributes a face.
        let faces = response.locator_faces();
        assert_eq!(faces.len(), 6);
        assert!(faces[1].is_some());
        assert!(
            faces
                .iter()
                .enumerate()
                .all(|(index, face)| index == 1 || face.is_none()),
            "status and locator-less entries project None: {faces:?}"
        );
        assert!(source.is_none(), "the envelope is our own account");

        // The error arm: word rides, no entries.
        let Some((ControlReceive::SyncAttachmentBackfillResponse { response }, _)) =
            routing(json!({
                "attachmentBackfillResponse": {
                    "targetMessage": {
                        "author": "+15555550101",
                        "sentTimestamp": 1726999999000u64,
                    },
                    "targetConversation": { "serviceId": "11111111-1111-1111-1111-111111111111" },
                    "error": "MESSAGE_NOT_FOUND",
                },
            }))
        else {
            panic!("expected an error-arm backfill routing");
        };
        assert_eq!(response.error.as_deref(), Some("MESSAGE_NOT_FOUND"));
        assert!(response.entries.is_empty());
        assert!(
            response.long_text.is_none(),
            "the error arm has no data face"
        );
        assert_eq!(
            response.conversation_service_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );

        // Contract 1.195 (§4.195): the longText sibling parses through the
        // same oneof — TERMINAL_ERROR keeps its word, an unknown word
        // converges to Unknown, a pointer keeps its (possibly locator-less)
        // face, and an explicit null is absence. An empty attachment list
        // beside a longText state is the arm the service must still settle.
        let long_text_routing = |long_text: serde_json::Value| {
            let Some((ControlReceive::SyncAttachmentBackfillResponse { response }, _)) =
                routing(json!({
                    "attachmentBackfillResponse": {
                        "targetMessage": {
                            "author": "22222222-2222-2222-2222-222222222222",
                            "sentTimestamp": 1726999999000u64,
                        },
                        "targetConversation": { "groupId": "Z3JvdXA=" },
                        "attachments": [],
                        "longText": long_text,
                    },
                }))
            else {
                panic!("expected a longText backfill routing");
            };
            response
        };
        assert_eq!(
            long_text_routing(json!({ "status": "TERMINAL_ERROR" })).long_text,
            Some(BackfillEntry::Status(BackfillStatus::Terminal))
        );
        assert_eq!(
            long_text_routing(json!({ "status": "SOME_FUTURE_WORD" })).long_text,
            Some(BackfillEntry::Status(BackfillStatus::Unknown))
        );
        assert_eq!(
            long_text_routing(json!({ "attachment": { "id": "body" } })).long_text,
            Some(BackfillEntry::Locator(None))
        );
        assert!(long_text_routing(json!(null)).long_text.is_none());
        let Some((ControlReceive::SyncAttachmentBackfillResponse { response }, _)) =
            routing(json!({
                "attachmentBackfillResponse": {
                    "targetMessage": {
                        "author": "22222222-2222-2222-2222-222222222222",
                        "sentTimestamp": 1726999999000u64,
                    },
                    "targetConversation": { "groupId": "Z3JvdXA=" },
                    "attachments": [],
                },
            }))
        else {
            panic!("expected a no-longText backfill routing");
        };
        assert!(response.long_text.is_none(), "an absent key is no state");

        // Malformed targets fall through to the plain skip: no author, no
        // stamp, no conversation leg.
        for face in [
            json!({ "targetMessage": { "sentTimestamp": 1u64 }, "targetConversation": { "groupId": "Z3JvdXA=" }, "attachments": [] }),
            json!({ "targetMessage": { "author": "a", "sentTimestamp": 0u64 }, "targetConversation": { "groupId": "Z3JvdXA=" }, "attachments": [] }),
            json!({ "targetMessage": { "author": "a", "sentTimestamp": 1u64 }, "targetConversation": {}, "attachments": [] }),
        ] {
            assert!(
                routing(json!({ "attachmentBackfillResponse": face })).is_none(),
                "malformed target keeps the plain skip: {face}"
            );
        }
    }

    /// Contract 1.103 (§4.84): the engine's `syncMessage.verified` projection
    /// routes as one control receive — the trust word rides the whitelist,
    /// the destination must survive the ServiceId UUID gate, the optional
    /// number/key keys are per-key fail-closed (a hostile key drops, the
    /// record survives), and a face with a hostile state word or destination
    /// falls through to the plain syncMessage skip.
    #[test]
    fn sync_verified_routes_the_whitelisted_state() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncVerified { verified }, source)) = routing(json!({
            "verified": {
                "destinationUuid": "11111111-1111-1111-1111-111111111111",
                "destinationNumber": "+15555550101",
                "identityKey": "05ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
                "state": "verified",
            },
        })) else {
            panic!("expected a verified control routing");
        };
        assert_eq!(
            verified.destination_uuid,
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(verified.destination_number.as_deref(), Some("+15555550101"));
        assert!(verified.identity_key.is_some());
        assert_eq!(verified.state, "verified");
        assert!(source.is_none(), "the envelope is our own account");

        // The optional keys fail per-key: a hostile number/key shape answers
        // absent while the record itself survives.
        let Some((ControlReceive::SyncVerified { verified }, _)) = routing(json!({
            "verified": {
                "destinationUuid": "22222222-2222-2222-2222-222222222222",
                "destinationNumber": 1727000000u64,
                "identityKey": "",
                "state": "unverified",
            },
        })) else {
            panic!("expected the verified routing to survive hostile optionals");
        };
        assert_eq!(verified.state, "unverified");
        assert!(verified.destination_number.is_none());
        assert!(verified.identity_key.is_none());

        // The default word is the third whitelist member.
        let Some((ControlReceive::SyncVerified { verified }, _)) = routing(json!({
            "verified": {
                "destinationUuid": "33333333-3333-3333-3333-333333333333",
                "state": "default",
            },
        })) else {
            panic!("expected the default-word routing");
        };
        assert_eq!(verified.state, "default");

        // No usable face at all → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "verified": {} }),
            // The state word whitelist is closed.
            json!({ "verified": { "destinationUuid": "11111111-1111-1111-1111-111111111111", "state": "TRANSLATED" } }),
            json!({ "verified": { "destinationUuid": "11111111-1111-1111-1111-111111111111", "state": 1u64 } }),
            // The destination must be a ServiceId UUID — a number or a
            // malformed UUID is not the face.
            json!({ "verified": { "destinationUuid": "+15555550101", "state": "verified" } }),
            json!({ "verified": { "destinationUuid": "not-a-uuid", "state": "verified" } }),
            json!({ "verified": { "state": "verified" } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.104 (§4.85): the engine's `syncMessage.callEvent`
    /// projection routes as one control receive — the callId must be a
    /// decimal string at the u64 ceiling, the timestamp strictly positive,
    /// the word keys ride the per-key whitelists (a non-member drops, the
    /// record survives), the conversation identity rides verbatim, and a
    /// face failing a hard gate falls through to the plain syncMessage skip.
    #[test]
    fn sync_call_event_routes_the_shape_gated_record() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncCallEvent { event }, source)) = routing(json!({
            "callEvent": {
                "callId": "18446744073709551615",
                "timestamp": 1726999999000u64,
                "type": "audio",
                "direction": "outgoing",
                "event": "accepted",
                "conversationId": "11111111-1111-1111-1111-111111111111",
            },
        })) else {
            panic!("expected a call-event control routing");
        };
        assert_eq!(event.call_id, "18446744073709551615");
        assert_eq!(event.timestamp, 1726999999000);
        assert_eq!(event.kind, Some("audio"));
        assert_eq!(event.direction, Some("outgoing"));
        assert_eq!(event.outcome, Some("accepted"));
        assert_eq!(
            event.conversation_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(source.is_none(), "the envelope is our own account");

        // The word keys fail per-key: a hostile word answers absent while
        // the record survives.
        let Some((ControlReceive::SyncCallEvent { event }, _)) = routing(json!({
            "callEvent": {
                "callId": "42",
                "timestamp": 1726999998000u64,
                "type": "TELEPORT",
                "direction": 3u64,
                "event": "ringing",
            },
        })) else {
            panic!("expected the routing to survive hostile words");
        };
        assert!(event.kind.is_none());
        assert!(event.direction.is_none());
        assert!(event.outcome.is_none());
        assert!(event.conversation_id.is_none());

        // No usable face at all → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "callEvent": {} }),
            // The callId shape gate: non-numeric, over-bound, missing.
            json!({ "callEvent": { "callId": "12x34", "timestamp": 1726999999000u64 } }),
            json!({ "callEvent": { "callId": "184467440737095516155", "timestamp": 1726999999000u64 } }),
            json!({ "callEvent": { "callId": 42u64, "timestamp": 1726999999000u64 } }),
            json!({ "callEvent": { "timestamp": 1726999999000u64 } }),
            // The timestamp gate: the engine's zero marker is not a record.
            json!({ "callEvent": { "callId": "42", "timestamp": 0u64 } }),
            json!({ "callEvent": { "callId": "42" } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.configuration`
    /// projection routes as one control receive — the bool flags ride the
    /// per-key fail-closed read (a hostile shape answers absent, the record
    /// survives), and a face with no surviving key falls through to the
    /// plain syncMessage skip.
    #[test]
    fn sync_configuration_routes_the_flag_face() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncConfiguration { configuration }, source)) = routing(json!({
            "configuration": {
                "readReceipts": true,
                "unidentifiedDeliveryIndicators": false,
                "typingIndicators": true,
                "linkPreviews": false,
            },
        })) else {
            panic!("expected a configuration control routing");
        };
        assert_eq!(configuration.read_receipts, Some(true));
        assert_eq!(configuration.unidentified_delivery_indicators, Some(false));
        assert_eq!(configuration.typing_indicators, Some(true));
        assert_eq!(configuration.link_previews, Some(false));
        assert!(source.is_none(), "the envelope is our own account");

        // The flags fail per-key: a hostile shape answers absent while the
        // surviving flags carry the record.
        let Some((ControlReceive::SyncConfiguration { configuration }, _)) = routing(json!({
            "configuration": {
                "readReceipts": "yes",
                "typingIndicators": 1u64,
                "linkPreviews": false,
            },
        })) else {
            panic!("expected the routing to survive hostile flags");
        };
        assert_eq!(configuration.read_receipts, None);
        assert_eq!(configuration.typing_indicators, None);
        assert_eq!(configuration.link_previews, Some(false));

        // No surviving flag at all → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "configuration": {} }),
            json!({ "configuration": { "readReceipts": null } }),
            json!({ "configuration": { "typingIndicators": "on" } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.fetchLatest`
    /// projection routes on the arm's presence — the type word rides the
    /// SCREAMING whitelist per-key fail-closed (a hostile word answers
    /// absent, the trigger still fires; the official fires the same
    /// type-less event), and a non-object face falls through to the plain
    /// syncMessage skip.
    #[test]
    fn sync_fetch_latest_routes_on_presence() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncFetchLatest { kind }, source)) = routing(json!({
            "fetchLatest": { "type": "STORAGE_MANIFEST" },
        })) else {
            panic!("expected a fetch-latest control routing");
        };
        assert_eq!(kind, Some("STORAGE_MANIFEST"));
        assert!(source.is_none(), "the envelope is our own account");

        // The type-less face still routes (the official's own shape).
        let Some((ControlReceive::SyncFetchLatest { kind }, _)) = routing(json!({
            "fetchLatest": {},
        })) else {
            panic!("expected the type-less routing");
        };
        assert!(kind.is_none());

        // A hostile word answers absent while the trigger survives.
        let Some((ControlReceive::SyncFetchLatest { kind }, _)) = routing(json!({
            "fetchLatest": { "type": "EVERYTHING" },
        })) else {
            panic!("expected the routing to survive a hostile word");
        };
        assert!(kind.is_none());

        // A non-object face is not the projection → the plain skip.
        for sync in [json!({}), json!({ "fetchLatest": "STORAGE_MANIFEST" })] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.callLinkUpdate`
    /// projection routes as one control receive — the type word hard-gates
    /// on the projection's only known member, the rootKey hard-gates present
    /// within its bound (the update's subject; an over-bound key drops the
    /// record whole), the admin key fails per-key, and any hard-gate failure
    /// falls through to the plain syncMessage skip.
    #[test]
    fn sync_call_link_update_routes_the_root_keyed_record() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncCallLinkUpdate { update }, source)) = routing(json!({
            "callLinkUpdate": {
                "type": "UPDATE",
                "rootKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "adminKey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            },
        })) else {
            panic!("expected a call-link-update control routing");
        };
        assert_eq!(update.kind, "UPDATE");
        assert_eq!(
            update.root_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(
            update.admin_key.as_deref(),
            Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        );
        assert!(source.is_none(), "the envelope is our own account");

        // The admin key fails per-key: a hostile shape answers absent while
        // the record survives.
        let Some((ControlReceive::SyncCallLinkUpdate { update }, _)) = routing(json!({
            "callLinkUpdate": {
                "type": "UPDATE",
                "rootKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "adminKey": 42u64,
            },
        })) else {
            panic!("expected the routing to survive a hostile admin key");
        };
        assert!(update.admin_key.is_none());

        // Hard-gate failures drop the record whole → the plain skip: a
        // missing/hostile type word, a missing/over-bound root key.
        for sync in [
            json!({}),
            json!({ "callLinkUpdate": {} }),
            json!({ "callLinkUpdate": { "rootKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } }),
            json!({ "callLinkUpdate": { "type": "DELETE", "rootKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } }),
            json!({ "callLinkUpdate": { "type": 0u64, "rootKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } }),
            json!({ "callLinkUpdate": { "type": "UPDATE" } }),
            json!({ "callLinkUpdate": { "type": "UPDATE", "rootKey": "" } }),
            json!({ "callLinkUpdate": { "type": "UPDATE", "rootKey": 42u64 } }),
            json!({ "callLinkUpdate": { "type": "UPDATE", "rootKey": "A".repeat(129) } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.callLogEvent`
    /// projection routes as one control receive — the verb hard-gates on the
    /// SCREAMING whitelist (the record's whole meaning), the remaining keys
    /// ride per-key optional in the engine's verbatim shapes, and a verb
    /// failure falls through to the plain syncMessage skip.
    #[test]
    fn sync_call_log_event_routes_the_gated_record() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncCallLogEvent { event }, source)) = routing(json!({
            "callLogEvent": {
                "type": "MARKED_AS_READ",
                "timestamp": 1726999999000u64,
                "conversationId": "11111111-1111-1111-1111-111111111111",
                "callId": 18446744073709551615u64,
            },
        })) else {
            panic!("expected a call-log-event control routing");
        };
        assert_eq!(event.kind, "MARKED_AS_READ");
        assert_eq!(event.timestamp, Some(1726999999000));
        assert_eq!(
            event.conversation_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(event.call_id, Some(u64::MAX));
        assert!(source.is_none(), "the envelope is our own account");

        // The keys fail per-key: hostile shapes answer absent while the
        // verb carries the record.
        let Some((ControlReceive::SyncCallLogEvent { event }, _)) = routing(json!({
            "callLogEvent": {
                "type": "CLEAR",
                "timestamp": "recently",
                "conversationId": 42u64,
                "callId": "18446744073709551615",
            },
        })) else {
            panic!("expected the routing to survive hostile keys");
        };
        assert_eq!(event.kind, "CLEAR");
        assert!(event.timestamp.is_none());
        assert!(event.conversation_id.is_none());
        assert!(event.call_id.is_none());

        // The other whitelist members resolve verbatim.
        for (word, expected) in [
            ("CLEAR", "CLEAR"),
            (
                "MARKED_AS_READ_IN_CONVERSATION",
                "MARKED_AS_READ_IN_CONVERSATION",
            ),
            ("CLEAR_IN_CONVERSATION", "CLEAR_IN_CONVERSATION"),
        ] {
            let Some((ControlReceive::SyncCallLogEvent { event }, _)) = routing(json!({
                "callLogEvent": { "type": word },
            })) else {
                panic!("expected the {word} routing");
            };
            assert_eq!(event.kind, expected);
        }

        // No usable verb at all → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "callLogEvent": {} }),
            json!({ "callLogEvent": { "timestamp": 1726999999000u64 } }),
            json!({ "callLogEvent": { "type": "DELETE_ALL" } }),
            json!({ "callLogEvent": { "type": 1u64 } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.deviceNameChange`
    /// projection routes as one control receive — the deviceId hard-gates
    /// present in u32 range (the official's own absent-key drop), and a face
    /// without it falls through to the plain syncMessage skip.
    #[test]
    fn sync_device_name_change_routes_the_device_id() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncDeviceNameChange { device_id }, source)) = routing(json!({
            "deviceNameChange": { "deviceId": 2u64 },
        })) else {
            panic!("expected a device-name-change control routing");
        };
        assert_eq!(device_id, 2);
        assert!(source.is_none(), "the envelope is our own account");

        // The u32 ceiling routes; out of range does not.
        let Some((ControlReceive::SyncDeviceNameChange { device_id }, _)) = routing(json!({
            "deviceNameChange": { "deviceId": 4294967295u64 },
        })) else {
            panic!("expected the u32-ceiling routing");
        };
        assert_eq!(device_id, u32::MAX);

        // No addressable device → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "deviceNameChange": {} }),
            json!({ "deviceNameChange": { "deviceId": 4294967296u64 } }),
            json!({ "deviceNameChange": { "deviceId": "2" } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.usernameChange`
    /// projection routes on the arm's presence — the empty pure-signal face
    /// is the whole content, a non-object face falls through to the plain
    /// syncMessage skip.
    #[test]
    fn sync_username_change_routes_the_bare_signal() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncUsernameChange, source)) = routing(json!({
            "usernameChange": {},
        })) else {
            panic!("expected a username-change control routing");
        };
        assert!(source.is_none(), "the envelope is our own account");

        // A non-object face is not the projection → the plain skip.
        for sync in [json!({}), json!({ "usernameChange": "renamed" })] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.140 (§4.136): the engine's `syncMessage.blocked` projection
    /// routes as a control addressed by its own identities — both family
    /// shapes union, unknown fields tolerated, identities deduped and capped,
    /// and a face with no surviving identity (the fully-empty list's empty
    /// object included) kept on the plain syncMessage skip.
    #[test]
    fn sync_blocked_routes_both_families_and_tolerates_unknown_fields() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        // Modern + legacy keys union into one identity set; unknown face keys
        // and unknown entry fields are not fatal; the advisory timestamps do
        // not ride; wrong-typed entries drop per-entry.
        let Some((ControlReceive::SyncBlocked { blocked }, source)) = routing(json!({
            "blocked": {
                "blockedE164s": [
                    {"e164": "+15555550101", "timestamp": 1727000000000u64, "junk": true},
                    {"nope": 1},
                    "not-an-object",
                ],
                "blockedAcis": [
                    {"aci": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10", "timestamp": 7u64},
                ],
                "blockedGroups": [
                    {"groupId": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
                ],
                "numbers": ["+15555550101", "+15555550102"],
                "acis": ["0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10"],
                "acisBinary": ["33333333-3333-3333-3333-333333333333"],
                "groupIds": ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="],
                "unknownFutureKey": {"whatever": 1},
            },
        })) else {
            panic!("expected a blocked control routing");
        };
        assert!(source.is_none(), "the envelope is our own account");
        assert_eq!(blocked.numbers, ["+15555550101", "+15555550102"]);
        assert_eq!(
            blocked.acis,
            [
                "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                "33333333-3333-3333-3333-333333333333",
            ]
        );
        assert_eq!(
            blocked.group_ids,
            ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]
        );

        // The identity cap truncates per class (the read-face discipline).
        let flood: Vec<Value> = (0..520)
            .map(|index| json!({"e164": format!("+1555556{index:04}")}))
            .collect();
        let Some((ControlReceive::SyncBlocked { blocked }, _)) = routing(json!({
            "blocked": { "blockedE164s": flood },
        })) else {
            panic!("expected the flooded face to route");
        };
        assert_eq!(blocked.numbers.len(), 512);

        // Nothing usable — the fully-empty modern object, a hostile face, a
        // non-object face — keeps the plain syncMessage skip.
        for sync in [
            json!({ "blocked": {} }),
            json!({ "blocked": {"blockedE164s": [], "numbers": []} }),
            json!({ "blocked": {"blockedE164s": "nope"} }),
            json!({ "blocked": "nope" }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.106 (§4.87): the engine's `syncMessage.pniChangeNumber`
    /// projection routes as one control receive carrying only the stripped
    /// face — the keys fail per-key, a face with no surviving key falls
    /// through to the plain syncMessage skip, and no key material can exist
    /// on the struct (the engine never projects it).
    #[test]
    fn sync_pni_change_number_routes_the_stripped_projection() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncPniChangeNumber { change }, source)) = routing(json!({
            "pniChangeNumber": {
                "registrationId": 2718u64,
                "newE164": "+15555550199",
            },
        })) else {
            panic!("expected a pni-change-number control routing");
        };
        assert_eq!(change.registration_id, Some(2718));
        assert_eq!(change.new_e164.as_deref(), Some("+15555550199"));
        assert!(source.is_none(), "the envelope is our own account");

        // The keys fail per-key: a hostile shape answers absent while the
        // survivor carries the record.
        let Some((ControlReceive::SyncPniChangeNumber { change }, _)) = routing(json!({
            "pniChangeNumber": {
                "registrationId": 4294967296u64,
                "newE164": "+15555550199",
            },
        })) else {
            panic!("expected the routing to survive a hostile id");
        };
        assert_eq!(change.registration_id, None);
        assert_eq!(change.new_e164.as_deref(), Some("+15555550199"));

        // No surviving key at all → the plain syncMessage skip.
        for sync in [
            json!({}),
            json!({ "pniChangeNumber": {} }),
            json!({ "pniChangeNumber": { "registrationId": 4294967296u64 } }),
            json!({ "pniChangeNumber": { "newE164": 15555550199u64 } }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.136 (§4.122): the engine's `syncMessage.contacts`
    /// projection routes as a bounded control batch — each record's identity
    /// survives with the optional e164/display name, hostile records drop
    /// per-record, and a face with nothing usable (or no records at all —
    /// the completion-only envelope) falls through to the plain syncMessage
    /// skip. The routing source stays None: the envelope is our own account.
    #[test]
    fn sync_contacts_routes_bounded_records() {
        let routing = |sync: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "sourceUuid": "99999999-9999-9999-9999-999999999999",
                    "syncMessage": sync,
                })
                .as_object()
                .unwrap(),
            )
            .map(|routing| (routing.control, routing.source))
        };

        let Some((ControlReceive::SyncContacts { contacts }, source)) = routing(json!({
            "contacts": {
                "complete": true,
                "records": [
                    {
                        "aci": "6a2cb17f-ef7c-4a5d-9c69-6f8b2b1f88ae",
                        "number": "+15551234567",
                        "name": "Alice",
                    },
                    // No number, no name — the ACI-only record survives.
                    { "aci": "0b1c2d3e-4f50-4a1b-8c2d-3e4f50617283" },
                    // Hostile shapes drop per-record, the batch rides on.
                    {},
                    { "number": "+15551234568" },
                    { "aci": "" },
                    { "aci": 42 },
                ],
            },
        })) else {
            panic!("expected a contacts control routing");
        };
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].aci, "6a2cb17f-ef7c-4a5d-9c69-6f8b2b1f88ae");
        assert_eq!(contacts[0].number.as_deref(), Some("+15551234567"));
        assert_eq!(contacts[0].name.as_deref(), Some("Alice"));
        assert_eq!(contacts[1].aci, "0b1c2d3e-4f50-4a1b-8c2d-3e4f50617283");
        assert!(contacts[1].number.is_none());
        assert!(contacts[1].name.is_none());
        assert!(source.is_none(), "the envelope is our own account");

        // The optional faces bound per key: a 200-char name truncates to the
        // 64-char cache-title cap the pull path applies.
        let Some((ControlReceive::SyncContacts { contacts }, _)) = routing(json!({
            "contacts": {
                "records": [{ "aci": "a", "name": "長".repeat(200) }],
            },
        })) else {
            panic!("expected the long-name record to survive");
        };
        assert_eq!(contacts[0].name.as_deref(), Some("長".repeat(64).as_str()));

        // A completion-only envelope (the `complete` flag alone) and a face
        // whose every record dropped are no cache write — the plain skip.
        for sync in [
            json!({ "contacts": { "complete": true, "records": [] } }),
            json!({ "contacts": { "records": [{ "number": "+15551234568" }] } }),
            json!({ "contacts": {} }),
        ] {
            let routing = control_routing(
                json!({ "timestamp": 1727000000000u64, "syncMessage": sync })
                    .as_object()
                    .unwrap(),
            );
            assert!(routing.is_none(), "expected the plain skip: {sync}");
        }
    }

    /// Contract 1.100 (§4.81 D3): the engine's `groupChanged` projection
    /// routes with the verbatim change batch (bounded verbatim — the
    /// connector never re-shapes the word list); the guaranteed faces fail
    /// closed; the timer leg parses beside the other changes.
    #[test]
    fn group_changed_routes_bounded_verbatim_changes() {
        let routing = |change: serde_json::Value| {
            control_routing(
                json!({
                    "timestamp": 1727000000000u64,
                    "groupChanged": change,
                })
                .as_object()
                .unwrap(),
            )
        };
        let Some(routing) = routing(json!({
            "groupId": "ZmFrZS1ncm91cC0x",
            "revision": 10u64,
            "editor": "33333333-3333-3333-3333-333333333333",
            "expireTimerSeconds": 60u64,
            "changes": [
                { "type": "title", "newTitle": "renamed" },
                { "type": "member-add", "aci": "11111111-1111-1111-1111-111111111111" },
                { "type": "group-link-reset" },
            ],
        })) else {
            panic!("expected a groupChanged routing");
        };
        assert_eq!(routing.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
        assert!(routing.source.is_none(), "the envelope has no peer source");
        let ControlReceive::GroupChanged {
            revision,
            changes,
            editor,
            expire_timer_seconds,
        } = routing.control
        else {
            panic!("expected a GroupChanged control: {:?}", routing.control);
        };
        assert_eq!(revision, 10);
        assert_eq!(
            changes,
            json!([
                { "type": "title", "newTitle": "renamed" },
                { "type": "member-add", "aci": "11111111-1111-1111-1111-111111111111" },
                { "type": "group-link-reset" },
            ]),
            "the batch rides verbatim"
        );
        assert_eq!(
            editor.as_deref(),
            Some("33333333-3333-3333-3333-333333333333")
        );
        assert_eq!(expire_timer_seconds, Some(60));

        // The guaranteed faces fail closed: no revision, no change list, an
        // empty batch — all skip (a protocol error, not an unknown shape).
        for change in [
            json!({ "groupId": "ZmFrZS1ncm91cC0x", "changes": [{ "type": "group-link-reset" }] }),
            json!({ "groupId": "ZmFrZS1ncm91cC0x", "revision": 10u64 }),
            json!({ "groupId": "ZmFrZS1ncm91cC0x", "revision": 10u64, "changes": [] }),
        ] {
            assert!(
                routing_shape_none(&change),
                "expected the fail-closed skip: {change}"
            );
        }
    }

    fn routing_shape_none(change: &serde_json::Value) -> bool {
        control_routing(json!({ "groupChanged": change }).as_object().unwrap()).is_none()
    }

    /// 群通话 era 更新收面（契约 1.264，§4.248）：群 face 路由为控制接收——\n    /// eraId 逐字、群键随路；era 缺席/超帽/无群键 = 官方 warn-and-ignore，\n    /// 整面掉落（信封走既有 fall-through，1:1 腿不路由钉形）。\n    #[test]\n    fn group_call_update_routes_group_face_and_drops_the_rest() {\n        let routed = control_routing(\n            json!({\n                "timestamp": 1727000000000u64,\n                "source": "+15555550101",\n                "dataMessage": {\n                    "groupCallUpdate": { "eraId": "era-1" },\n                    "groupInfo": { "groupId": "ZmFrZS1ncm91cC0x" },\n                },\n            })\n            .as_object()\n            .unwrap(),\n        )\n        .expect("group face routes as control");\n        assert_eq!(routed.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));\n        assert_eq!(routed.direction, "incoming");\n        assert_eq!(routed.source.as_deref(), Some("+15555550101"));\n        assert!(matches!(\n            routed.control,\n            ControlReceive::GroupCallUpdate { ref era_id } if era_id == "era-1"\n        ));\n\n        // era 缺席（引擎空串整键缺席的同域防御）= 官方 warn-and-ignore。\n        assert!(control_routing(\n            json!({\n                "timestamp": 1727000000000u64,\n                "dataMessage": {\n                    "groupCallUpdate": {},\n                    "groupInfo": { "groupId": "ZmFrZS1ncm91cC0x" },\n                },\n            })\n            .as_object()\n            .unwrap(),\n        )\n        .is_none());\n\n        // 超帽 era = 整面掉落（不截断不发明；帽 = §4.108 发送闸同域 256）。\n        let oversized = "e".repeat(257);\n        assert!(control_routing(\n            json!({\n                "timestamp": 1727000000000u64,\n                "dataMessage": {\n                    "groupCallUpdate": { "eraId": oversized },\n                    "groupInfo": { "groupId": "ZmFrZS1ncm91cC0x" },\n                },\n            })\n            .as_object()\n            .unwrap(),\n        )\n        .is_none());\n\n        // 无群键 = 官方群闸挡住（信封走 fall-through；1:1 腿零变化钉形）。\n        assert!(control_routing(\n            json!({\n                "timestamp": 1727000000000u64,\n                "dataMessage": { "groupCallUpdate": { "eraId": "era-1" } },\n            })\n            .as_object()\n            .unwrap(),\n        )\n        .is_none());\n    }\n    /// Contract 1.134 (§4.117): the engine's `groupTerminated` projection
    /// routes as a conversation-less transient control addressed by its own
    /// groupId; a face with no subject fails closed to the plain skip.
    #[test]
    fn group_terminated_routes_conversation_less_transient() {
        let routing = control_routing(
            json!({
                "timestamp": 1727000000000u64,
                "groupTerminated": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                    "terminator": "33333333-3333-3333-3333-333333333333",
                    "timestamp": 1726999999000u64,
                },
            })
            .as_object()
            .unwrap(),
        )
        .expect("expected a groupTerminated routing");
        assert_eq!(routing.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
        assert!(
            routing.source.is_none(),
            "the replaced envelope has no peer source"
        );
        let ControlReceive::GroupTerminated {
            group_id,
            terminator,
            timestamp,
        } = routing.control
        else {
            panic!("expected a GroupTerminated control: {:?}", routing.control);
        };
        assert_eq!(group_id, "ZmFrZS1ncm91cC0x");
        assert_eq!(
            terminator.as_deref(),
            Some("33333333-3333-3333-3333-333333333333")
        );
        assert_eq!(timestamp, Some(1726999999000));

        // The guaranteed subject fails closed: no groupId (or an empty one)
        // is a protocol error and falls to the plain skip — never a routing
        // that names nothing.
        for face in [
            json!({ "terminator": "33333333-3333-3333-3333-333333333333" }),
            json!({ "groupId": "" }),
            json!({ "groupId": 42 }),
        ] {
            assert!(
                control_routing(json!({ "groupTerminated": face }).as_object().unwrap()).is_none(),
                "expected the fail-closed skip: {face}"
            );
        }

        // The optional faces degrade to absence, never to invented values.
        let bare = control_routing(
            json!({ "groupTerminated": { "groupId": "ZmFrZS1ncm91cC0x" } })
                .as_object()
                .unwrap(),
        )
        .expect("expected the bare routing");
        let ControlReceive::GroupTerminated {
            terminator,
            timestamp,
            ..
        } = bare.control
        else {
            panic!("expected a GroupTerminated control");
        };
        assert!(terminator.is_none() && timestamp.is_none());
    }

    /// Contract 1.134 (§4.117): the engine's `contactProfileUpdated`
    /// projection routes as a conversation-less transient control naming its
    /// subject by aci; a face with no aci fails closed to the plain skip.
    #[test]
    fn contact_profile_updated_routes_by_aci() {
        let routing = control_routing(
            json!({
                "timestamp": 1727000000000u64,
                "sourceUuid": "11111111-1111-1111-1111-111111111111",
                "contactProfileUpdated": { "aci": "11111111-1111-1111-1111-111111111111" },
            })
            .as_object()
            .unwrap(),
        )
        .expect("expected a contactProfileUpdated routing");
        assert!(routing.group_id.is_none() && routing.source.is_none());
        let ControlReceive::ContactProfileUpdated { aci } = routing.control else {
            panic!(
                "expected a ContactProfileUpdated control: {:?}",
                routing.control
            );
        };
        assert_eq!(aci, "11111111-1111-1111-1111-111111111111");

        for face in [json!({}), json!({ "aci": "" }), json!({ "aci": 42 })] {
            assert!(
                control_routing(
                    json!({ "contactProfileUpdated": face })
                        .as_object()
                        .unwrap()
                )
                .is_none(),
                "expected the fail-closed skip: {face}"
            );
        }
    }

    /// Contract 1.134 (§4.117): the engine's standalone account-domain
    /// notifications parse into their attributed events — the queue-drained
    /// advisory, the signed clock-skew alert, and the conversation-state
    /// batch whose array rides verbatim (no entry parsing, sibling keys
    /// stay).
    #[tokio::test]
    async fn account_transient_notifications_parse_to_events() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;

        let line = |value: serde_json::Value| serde_json::to_string(&value).unwrap();
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "receive.emptied",
                "params": { "account": "+15555550100" },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::ReceiveEmptied { ref account } if account == "+15555550100"
            ),
            "expected the ReceiveEmptied event"
        );

        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "receive.clockskew",
                "params": {
                    "account": "+15555550100",
                    "skewMs": -86_400_001_i64,
                    "serverTimestamp": 1727000000000u64,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::ReceiveClockSkew {
            account,
            skew_ms,
            server_timestamp,
        } = event_rx.recv().await.unwrap()
        else {
            panic!("expected the ReceiveClockSkew event");
        };
        assert_eq!(account, "+15555550100");
        assert_eq!(skew_ms, -86_400_001, "the signed skew forwards verbatim");
        assert_eq!(server_timestamp, Some(1727000000000));

        let conversations = json!([
            {
                "conversationId": "11111111-1111-1111-1111-111111111111",
                "kind": "contact",
                "mutedUntilTimestamp": 1727000000000u64,
                "archived": true,
                "markedUnread": false,
                "unnamedSibling": { "rides": true },
            },
            {
                "conversationId": "ZmFrZS1ncm91cC0x",
                "kind": "group",
                "mutedUntilTimestamp": 0u64,
                "archived": false,
                "markedUnread": true,
            },
        ]);
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "receive.conversationState",
                "params": {
                    "account": "+15555550100",
                    "conversations": conversations,
                    "overflow": false,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::ConversationState {
            account,
            conversations: carried,
            overflow,
        } = event_rx.recv().await.unwrap()
        else {
            panic!("expected the ConversationState event");
        };
        assert_eq!(account, "+15555550100");
        assert_eq!(carried, conversations, "the array rides verbatim");
        assert!(!overflow);

        // Contract 1.141 (§4.137): the storage-pull outcome rides the same
        // lane. The engine's current trigger vocabulary is login/fetchLatest;
        // the parse types the word but does not pin the domain — the unseen
        // value below forwards verbatim, never rewritten into a known one.
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
                "params": {
                    "account": "+15555550100",
                    "trigger": "login",
                    "contactsOk": true,
                    "groupsOk": false,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::StoragePull {
            account,
            trigger,
            contacts_ok,
            groups_ok,
        } = event_rx.recv().await.unwrap()
        else {
            panic!("expected the StoragePull event");
        };
        assert_eq!(account, "+15555550100");
        assert_eq!(trigger, "login");
        assert!(contacts_ok);
        assert!(!groups_ok);

        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
                "params": {
                    "account": "+15555550100",
                    "trigger": "someFutureEngineTrigger",
                    "contactsOk": false,
                    "groupsOk": true,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::StoragePull { trigger, .. } = event_rx.recv().await.unwrap() else {
            panic!("expected the StoragePull event");
        };
        assert_eq!(
            trigger, "someFutureEngineTrigger",
            "an unseen trigger word forwards verbatim, never guessed"
        );
    }

    /// Contract 1.220 (§4.230): the engine's link-window
    /// post-registration sync completion parses into the attributed event
    /// with both per-leg bits verbatim; a missing, empty, or wrong-typed
    /// face falls back to the unknown-notification warning (never a guessed
    /// forward) — the storagePull arm's attribution discipline.
    #[tokio::test]
    async fn initial_sync_complete_notification_routes_by_account() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let line = |value: serde_json::Value| serde_json::to_string(&value).unwrap();

        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "engine.initialSyncComplete",
                "params": {
                    "account": "+15555550100",
                    "manifestOk": true,
                    "profilesOk": false,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::InitialSyncComplete {
            account,
            manifest_ok,
            profiles_ok,
        } = event_rx.recv().await.unwrap()
        else {
            panic!("expected the InitialSyncComplete event");
        };
        assert_eq!(account, "+15555550100");
        assert!(manifest_ok);
        assert!(!profiles_ok, "a false leg forwards verbatim, never folded");

        for bad in [
            json!({
                "jsonrpc": "2.0",
                "method": "engine.initialSyncComplete",
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "engine.initialSyncComplete",
                "params": { "account": "" }
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "engine.initialSyncComplete",
                "params": {
                    "account": "+15555550100",
                    "manifestOk": "yes",
                    "profilesOk": true,
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "engine.initialSyncComplete",
                "params": {
                    "account": "+15555550100",
                    "manifestOk": true,
                }
            }),
        ] {
            handle_upstream_line(&line(bad), &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
        }
        for _ in 0..4 {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::ProtocolWarning {
                    kind: "unknownNotification"
                }
            ));
        }
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn session_reset_notification_pins_the_word_grammar() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;
        let line = |value: serde_json::Value| serde_json::to_string(&value).unwrap();

        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "engine.sessionReset",
                "params": {
                    "account": "+15555550100",
                    "peerAci": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                    "word": "endSession",
                    "sentAt": 1700000000000u64,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::SessionReset {
            account,
            peer_aci,
            word,
            sent_at,
        } = event_rx.recv().await.unwrap()
        else {
            panic!("expected the SessionReset event");
        };
        assert_eq!(account, "+15555550100");
        assert_eq!(peer_aci, "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10");
        assert_eq!(word, "endSession");
        assert_eq!(sent_at, Some(1_700_000_000_000));

        // The refreshed word arm rides the same grammar.
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "engine.sessionReset",
                "params": {
                    "account": "+15555550100",
                    "peerAci": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                    "word": "chatSessionRefresh",
                    "sentAt": 1700000000001u64,
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::SessionReset { word, .. } = event_rx.recv().await.unwrap() else {
            panic!("expected the SessionReset event");
        };
        assert_eq!(word, "chatSessionRefresh");

        // The refreshed word arm's additive absent face (eba82d3 contract
        // note): sentAt omitted whole-key when the send-side timestamp is
        // unknown — the event rides, the row clock degrades to the local one.
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "engine.sessionReset",
                "params": {
                    "account": "+15555550100",
                    "peerAci": "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10",
                    "word": "chatSessionRefresh",
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        let EngineEvent::SessionReset { word, sent_at, .. } = event_rx.recv().await.unwrap() else {
            panic!("expected the SessionReset event");
        };
        assert_eq!(word, "chatSessionRefresh");
        assert!(
            sent_at.is_none(),
            "absent sentAt rides as None, never a guessed clock"
        );

        // Bad shapes（词表越界/必要四面缺失 → unknownNotification，绝不猜发；
        // extra 键 additive 安全不入清单——strict 词表在发射端，
        // initialSyncComplete 臂同款消费姿态。）:
        for bad in [
            json!({
                "jsonrpc": "2.0",
                "method": "engine.sessionReset",
                "params": {
                    "account": "+15555550100",
                    "peerAci": "aci",
                    "word": "resetEverything",
                    "sentAt": 1u64,
                },
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "engine.sessionReset",
            }),
        ] {
            handle_upstream_line(&line(bad), &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
            let EngineEvent::ProtocolWarning { kind } = event_rx.recv().await.unwrap() else {
                panic!("expected the unknown-notification warning");
            };
            assert_eq!(kind, "unknownNotification");
        }
    }

    /// Contract 1.134 (§4.117): the account-domain notifications follow the
    /// accountUnbound attribution discipline — a malformed or empty account,
    /// a non-array conversations face, a non-boolean overflow marker, or a
    /// missing skew all carry no attributable forward and fall back to the
    /// unknown-notification warning.
    #[tokio::test]
    async fn malformed_account_transient_notifications_stay_unattributed() {
        let (events, mut event_rx) = event_channel();
        let (ingress, _receiver) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;

        let lines = [
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.emptied",
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.emptied",
                "params": { "account": "" }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.clockskew",
                "params": { "account": "+15555550100" }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.clockskew",
                "params": { "account": "+15555550100", "skewMs": "huge" }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.conversationState",
                "params": { "account": "+15555550100", "conversations": [], "overflow": false }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.conversationState",
                "params": {
                    "account": "+15555550100",
                    "conversations": [{ "conversationId": "x" }],
                }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "receive.conversationState",
                "params": {
                    "account": "+15555550100",
                    "conversations": [{ "conversationId": "x" }],
                    "overflow": "yes",
                }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
                "params": { "account": "" }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
                "params": {
                    "account": "+15555550100",
                    "trigger": 7,
                    "contactsOk": true,
                    "groupsOk": true,
                }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
                "params": {
                    "account": "+15555550100",
                    "trigger": "login",
                    "contactsOk": "yes",
                    "groupsOk": true,
                }
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "engine.storagePull",
                "params": {
                    "account": "+15555550100",
                    "trigger": "login",
                    "contactsOk": true,
                }
            }))
            .unwrap(),
        ];
        for line_text in &lines {
            handle_upstream_line(line_text, &mut pending, &events, &ingress, &mut degraded)
                .await
                .unwrap();
        }

        for _ in 0..lines.len() {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::ProtocolWarning {
                    kind: "unknownNotification"
                }
            ));
        }
        assert!(event_rx.try_recv().is_err());
    }

    /// Contract revision 1.165 (§4.163): the engine's decryption-error report
    /// rides as a `receive` notification whose envelope carries the
    /// `decryptionError` marker — the connector diverts it to the
    /// account-domain event lane instead of the receive ladder (the envelope
    /// carries no message row), the attribution follows the accountUnbound
    /// discipline (a missing, empty, or non-string account falls back to the
    /// unknown-notification warning), and a marker-free receive envelope
    /// still queues normally.
    #[tokio::test]
    async fn receive_decryption_error_envelope_routes_to_the_event_lane() {
        let (events, mut event_rx) = event_channel();
        let (ingress, mut queue_rx) = receive_channel();
        let mut pending = HashMap::new();
        let mut degraded = false;

        let line = |value: serde_json::Value| serde_json::to_string(&value).unwrap();

        // The structured report: marker envelope with an optional timestamp —
        // one attributed event, nothing enqueued.
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "receive",
                "params": {
                    "account": "+15555550100",
                    "envelope": {
                        "sourceUuid": "11111111-1111-1111-1111-111111111111",
                        "timestamp": 1727000000000u64,
                        "decryptionError": {},
                    },
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::ReceiveDecryptionError { ref account }
                    if account == "+15555550100"
            ),
            "expected the ReceiveDecryptionError event"
        );
        assert!(
            queue_rx.try_recv().is_err(),
            "the marker envelope never enters the receive ladder"
        );
        assert!(!degraded, "the diversion leaves the queue posture alone");

        // The attribution discipline: no account, an empty account, and a
        // non-string account all stay unattributed.
        for params in [
            json!({ "envelope": { "decryptionError": {} } }),
            json!({ "account": "", "envelope": { "decryptionError": {} } }),
            json!({ "account": 42, "envelope": { "decryptionError": {} } }),
        ] {
            handle_upstream_line(
                &line(json!({
                    "jsonrpc": "2.0",
                    "method": "receive",
                    "params": params,
                })),
                &mut pending,
                &events,
                &ingress,
                &mut degraded,
            )
            .await
            .unwrap();
            assert!(
                matches!(
                    event_rx.recv().await.unwrap(),
                    EngineEvent::ProtocolWarning {
                        kind: "unknownNotification"
                    }
                ),
                "expected the unattributed warning: {params}"
            );
        }
        assert!(queue_rx.try_recv().is_err());

        // A receive envelope without the marker keeps the ordinary ladder:
        // it queues (and never emits a decryption event).
        handle_upstream_line(
            &line(json!({
                "jsonrpc": "2.0",
                "method": "receive",
                "params": {
                    "account": "+15555550100",
                    "envelope": {
                        "sourceUuid": "11111111-1111-1111-1111-111111111111",
                        "timestamp": 1727000000001u64,
                        "dataMessage": { "message": "plain text" },
                    },
                },
            })),
            &mut pending,
            &events,
            &ingress,
            &mut degraded,
        )
        .await
        .unwrap();
        assert!(
            queue_rx.try_recv().is_ok(),
            "the marker-free envelope queues normally"
        );
        assert!(event_rx.try_recv().is_err());
    }

    /// Contract 1.100 (§4.81 D4): the quote's `attachments[]` rides the same
    /// bounded parser the message face runs — entries pass verbatim (the
    /// three-key QuotedAttachment shape), an entry that says nothing drops,
    /// an id-less thumbnail drops before it renders half a face, and a batch
    /// past the cap truncates. The sent-sync face shares the parser.
    #[test]
    fn quote_attachments_ride_bounded_metadata_entries() {
        let thumbnail = json!({
            "id": "thumb-1",
            "contentType": "image/jpeg",
            "size": 1024,
            "width": 64,
            "height": 64,
        });
        let normalized = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 61,
                "dataMessage": {
                    "message": "replying to media",
                    "quote": {
                        "id": 60u64,
                        "author": "+15555550102",
                        "text": "look at this",
                        "attachments": [
                            {
                                "contentType": "image/png",
                                "filename": "shot.png",
                                "thumbnail": thumbnail,
                            },
                            // Says nothing on the wire → drops whole.
                            {},
                            // Wrong-shaped keys are absence, not values.
                            { "contentType": 7, "filename": [], "thumbnail": "nope" },
                            // An id-less thumbnail drops; the entry survives
                            // on its own keys.
                            {
                                "contentType": "video/mp4",
                                "thumbnail": { "contentType": "image/jpeg" },
                            },
                        ],
                    },
                },
            },
        }))
        .unwrap()
        .unwrap();
        let quote = normalized.quote.as_ref().expect("quote snapshot");
        assert_eq!(quote.attachments.len(), 2, "{:?}", quote.attachments);
        let first = &quote.attachments[0];
        assert_eq!(first.content_type.as_deref(), Some("image/png"));
        assert_eq!(first.filename.as_deref(), Some("shot.png"));
        let thumb = first.thumbnail.as_ref().expect("thumbnail pointer");
        assert_eq!(thumb.id, "thumb-1");
        assert_eq!(thumb.content_type.as_deref(), Some("image/jpeg"));
        assert_eq!(thumb.size, Some(1024));
        assert_eq!(thumb.width, Some(64));
        assert_eq!(thumb.height, Some(64));
        assert_eq!(thumb.locator, None, "the quote face projects no locator");
        assert_eq!(
            quote.attachments[1].content_type.as_deref(),
            Some("video/mp4")
        );
        assert_eq!(quote.attachments[1].thumbnail, None);

        // A batch past the cap truncates (the `MAX_INBOUND_ATTACHMENTS`
        // discipline at quote scale).
        let entries: Vec<_> = (0..MAX_QUOTE_ATTACHMENTS + 1)
            .map(|index| json!({ "contentType": format!("application/x-{index}") }))
            .collect();
        let truncated = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "source": "+15555550101",
                "timestamp": 62,
                "dataMessage": {
                    "message": "replying to a lot",
                    "quote": {
                        "id": 61u64,
                        "author": "+15555550102",
                        "attachments": entries,
                    },
                },
            },
        }))
        .unwrap()
        .unwrap();
        let quote = truncated.quote.as_ref().expect("quote snapshot");
        assert_eq!(quote.attachments.len(), MAX_QUOTE_ATTACHMENTS);
        assert_eq!(
            quote.attachments[MAX_QUOTE_ATTACHMENTS - 1]
                .content_type
                .as_deref(),
            Some("application/x-7"),
        );

        // The sent-sync face runs the same parser.
        let sent = normalize_receive(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 63,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 63u64,
                        "message": "sent from another device",
                        "quote": {
                            "id": 60u64,
                            "author": "+15555550102",
                            "attachments": [{ "filename": "clip.mp4" }],
                        },
                    },
                },
            },
        }))
        .unwrap()
        .unwrap();
        let quote = sent.quote.as_ref().expect("sent quote snapshot");
        assert_eq!(quote.attachments.len(), 1);
        assert_eq!(quote.attachments[0].filename.as_deref(), Some("clip.mp4"));

        // Pre-1.100 store rows carry no attachments key — the snapshot
        // deserializes with the empty face (the serde default discipline).
        let legacy: NormalizedQuote =
            serde_json::from_value(json!({ "id": 60u64, "author": "+15555550102", "text": "hi" }))
                .expect("legacy snapshot");
        assert!(legacy.attachments.is_empty());
    }

    /// Call signaling (contract 1.50, §4.48): the engine's `callMessage`
    /// envelope face routes as a body-less control receive — the modern
    /// opaque payload first, the legacy frames keyed by presence, ICE by
    /// its list head. An out-of-budget or blank face routes nothing and the
    /// envelope falls through to the plain skip.
    #[test]
    fn call_message_envelopes_route_to_call_controls() {
        let routing = |envelope: serde_json::Value| {
            control_routing(envelope.as_object().unwrap()).map(|routing| routing.control)
        };
        let envelope = |call: serde_json::Value| {
            json!({
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "sourceDevice": 1,
                "callMessage": call,
            })
        };

        // The modern opaque face: id-less by design — the RingRTC payload
        // carries its own call identity; urgency defaults to the official
        // droppable when the engine leaves it out.
        let Some(ControlReceive::Call {
            call_id,
            signal_type,
            payload,
        }) = routing(envelope(json!({ "opaque": "c2RwLW9mZmVy" })))
        else {
            panic!("expected a call control");
        };
        assert_eq!(call_id, 0);
        assert_eq!(signal_type, "opaque");
        assert_eq!(payload["opaque"], "c2RwLW9mZmVy");
        assert_eq!(payload["urgency"], "droppable");
        assert_eq!(payload["destinationDeviceId"], Value::Null);

        // urgency + destinationDeviceId pass through verbatim when present.
        let Some(ControlReceive::Call { payload, .. }) = routing(envelope(json!({
            "opaque": "c2RwLWFuc3dlcg==",
            "urgency": "handleImmediately",
            "destinationDeviceId": 2u64,
        }))) else {
            panic!("expected a call control");
        };
        assert_eq!(payload["urgency"], "handleImmediately");
        assert_eq!(payload["destinationDeviceId"], 2u64);

        // The legacy frames: the id is the frame's call identity, the
        // projected face rides verbatim under its own key.
        for (key, signal_type, id) in [
            ("offer", "offer", 7u64),
            ("answer", "answer", 7u64),
            ("busy", "busy", 7u64),
            ("hangup", "hangup", 7u64),
        ] {
            let Some(ControlReceive::Call {
                call_id,
                signal_type: kind,
                payload,
            }) = routing(envelope(json!({ key: { "id": id, "opaque": "eA==" } })))
            else {
                panic!("expected a call control for {key}");
            };
            assert_eq!(call_id, id);
            assert_eq!(kind, signal_type);
            assert_eq!(payload[key]["id"], id);
            assert_eq!(payload[key]["opaque"], "eA==");
        }

        // The legacy ICE list: the first frame names the call, the list
        // rides bounded.
        let Some(ControlReceive::Call {
            call_id,
            signal_type,
            payload,
        }) = routing(envelope(json!({
            "iceUpdate": [
                { "id": 7u64, "opaque": "aWNlLTE=" },
                { "id": 7u64, "opaque": "aWNlLTI=" },
            ],
        })))
        else {
            panic!("expected a call control");
        };
        assert_eq!(call_id, 7);
        assert_eq!(signal_type, "ice");
        assert_eq!(payload["iceUpdate"].as_array().unwrap().len(), 2);

        // Blank / unaddressable faces route nothing: no opaque, frames
        // without a parsable id, an id beyond the u32 call-id face, and an
        // over-budget opaque payload.
        assert!(routing(envelope(json!({}))).is_none());
        assert!(routing(envelope(json!({ "offer": { "opaque": "eA==" } }))).is_none());
        assert!(routing(envelope(json!({ "offer": { "id": "x" } }))).is_none());
        assert!(
            routing(envelope(json!({ "offer": { "id": 4294967296u64 } }))).is_none(),
            "the call-id face is u32 — beyond it the frame is unaddressable"
        );
        let oversized = "A".repeat(3 * 1024 * 1024 + 1);
        assert!(routing(envelope(json!({ "opaque": oversized }))).is_none());
    }

    /// Story receives (contract 1.76, §4.67): the envelope-level
    /// `storyMessage` face routes as a body-less control receive — the
    /// bounded projection forwards verbatim (identities ride along), an
    /// oversized face drops the whole envelope into the skip routing (the
    /// coarse one-frame discipline the call-signaling opaque face rides),
    /// and the `isStory` bit alone never routes (it rides story sends and
    /// story replies alike; the plain dataMessage ladder keeps them).
    #[test]
    fn story_envelopes_route_verbatim_and_oversized_skip() {
        let normalize = |envelope: serde_json::Value| {
            normalize_receive(&json!({ "envelope": envelope }))
                .unwrap()
                .unwrap()
        };
        let base = json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "sourceUuid": "11111111-1111-1111-1111-111111111111",
            "sourceName": "Peer",
            "isStory": true,
        });

        // The text-attachment projection: every key rides verbatim.
        let normalized = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "sourceUuid": "11111111-1111-1111-1111-111111111111",
            "sourceName": "Peer",
            "storyMessage": {
                "textAttachment": {
                    "text": "story body",
                    "textStyle": "BOLD",
                },
                "allowsReplies": true,
                "profileKey": "cHJvZmlsZQ==",
            },
        }));
        assert_eq!(normalized.content_kind, "storyMessage");
        assert_eq!(normalized.direction, "incoming");
        assert_eq!(normalized.source.as_deref(), Some("+15555550101"));
        assert_eq!(normalized.timestamp, Some(1727000000000));
        let Some(ControlReceive::Story { message }) = normalized.control else {
            panic!("expected a story control");
        };
        assert_eq!(message["textAttachment"]["text"], "story body");
        assert_eq!(message["textAttachment"]["textStyle"], "BOLD");
        assert_eq!(message["allowsReplies"], true);
        assert_eq!(message["profileKey"], "cHJvZmlsZQ==");
        let _ = &base;

        // The file-attachment shape routes the same way (no text key).
        let Some(ControlReceive::Story { message }) = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "storyMessage": { "fileAttachment": {} },
        }))
        .control
        else {
            panic!("expected a story control");
        };
        assert!(message.get("fileAttachment").is_some());

        // Oversized material drops the whole envelope: the skip routing,
        // no control, no row material.
        let mut giant_attachment = String::from("data:image/png;base64,");
        giant_attachment.push_str(&"A".repeat(3 * 1024 * 1024));
        let oversized = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "storyMessage": {
                "fileAttachment": { "data": giant_attachment },
            },
        }));
        assert_eq!(oversized.content_kind, "storyMessage");
        assert_eq!(oversized.direction, "skip");
        assert!(oversized.control.is_none());

        // The bit alone never routes: a plain dataMessage under `isStory`
        // keeps the normal message ladder (no story control).
        let plain = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "isStory": true,
            "dataMessage": { "message": "hello" },
        }));
        assert_eq!(plain.direction, "incoming");
        assert!(plain.control.is_none());
        assert!(plain.rich.is_none() || !plain.rich.as_ref().unwrap().is_group_update);
    }

    /// Story preview metadata rides verbatim (contract 1.91, §4.74): the
    /// engine's `textAttachment.preview` projection — the 1.91
    /// `url`/`title` keys and any key projected after them — forwards into
    /// the story control receive untouched. The bounded story material is a
    /// whole-object clone, never a reshape: this pin fails if a future
    /// projection or bound starts whitelisting keys.
    #[test]
    fn story_preview_metadata_routes_verbatim() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "storyMessage": {
                    "textAttachment": {
                        "text": "story body",
                        "preview": {
                            "url": "https://example.com/a",
                            "title": "Example",
                            "someLaterKey": {"rides": true},
                        },
                    },
                    "allowsReplies": true,
                },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.content_kind, "storyMessage");
        assert_eq!(normalized.direction, "incoming");
        let Some(ControlReceive::Story { message }) = normalized.control else {
            panic!("expected a story control");
        };
        let preview = &message["textAttachment"]["preview"];
        assert_eq!(preview["url"], json!("https://example.com/a"));
        assert_eq!(preview["title"], json!("Example"));
        // No whitelist: keys the 1.91 contract never named ride the same
        // object — the face is a bounded clone, not a reshape.
        assert_eq!(preview["someLaterKey"], json!({ "rides": true }));
        assert_eq!(message["textAttachment"]["text"], "story body");
        assert_eq!(message["allowsReplies"], true);
    }

    /// Story replies (contract 1.76, §4.67): `dataMessage.storyReply`
    /// parses onto the rich payload as {authorAci, sentTimestamp}; a
    /// degraded face (missing timestamp, blank author) drops the key and
    /// never the row — the reply stays a normal message without story
    /// context.
    #[test]
    fn story_reply_parses_onto_rich_and_malformed_drops_key() {
        let normalize = |data: serde_json::Value| {
            normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
            .unwrap()
        };

        // The well-formed face: both keys ride verbatim.
        let rich = normalize(json!({
            "message": "nice story",
            "storyReply": {
                "authorAci": "22222222-2222-2222-2222-222222222222",
                "sentTimestamp": 1726999999000u64,
            },
        }))
        .rich
        .expect("rich payload");
        assert_eq!(
            rich.story_reply,
            Some(crate::engine::NormalizedStoryReply {
                author_aci: "22222222-2222-2222-2222-222222222222".to_string(),
                sent_timestamp: 1726999999000,
            })
        );

        // Missing timestamp: the key drops, the row stays.
        let degraded = normalize(json!({
            "message": "nice story",
            "storyReply": { "authorAci": "22222222-2222-2222-2222-222222222222" },
        }));
        assert_eq!(degraded.direction, "incoming");
        assert!(
            degraded
                .rich
                .as_ref()
                .and_then(|rich| rich.story_reply.as_ref())
                .is_none(),
            "a degraded storyReply drops the key, never the row"
        );

        // Blank author: same drop.
        let blank = normalize(json!({
            "message": "nice story",
            "storyReply": { "authorAci": "  ", "sentTimestamp": 1726999999000u64 },
        }));
        assert!(
            blank
                .rich
                .as_ref()
                .and_then(|rich| rich.story_reply.as_ref())
                .is_none()
        );
    }

    /// The §4.153 story receive faces route to their transients (contract
    /// 1.154; the group legs contract 1.158, §4.156): the reaction +
    /// storyReply co-presence is the story face on the 1:1 leg and — the
    /// 1.158 翻案 — on the group leg with its group key; a degraded
    /// storyReply (the engine projects the key only when the author
    /// resolves) keeps its plain fold; the envelope `isStory` remote-delete
    /// is the story DOE on the 1:1 leg and on the group envelope that
    /// carries the bit (the conservative leg) while an unsigned group DOE
    /// stays plain; and the `syncMessage.storyRecipientUpdate` self-sync
    /// rides its positive-stamp and non-empty-recipients gates.
    #[test]
    fn story_receive_faces_route_to_their_transients() {
        let normalize = |envelope: serde_json::Value| {
            normalize_receive(&json!({ "envelope": envelope }))
                .unwrap()
                .unwrap()
        };
        let story_reaction = json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "sourceUuid": "11111111-1111-1111-1111-111111111111",
            "dataMessage": {
                "reaction": {
                    "emoji": "❤️",
                    "targetAuthor": "22222222-2222-2222-2222-222222222222",
                    "targetSentTimestamp": 1726999999000u64,
                    "isRemove": true,
                },
                "storyReply": {
                    "authorAci": "22222222-2222-2222-2222-222222222222",
                    "sentTimestamp": 1726999999000u64,
                },
            },
        });
        let Some(ControlReceive::StoryReaction {
            emoji,
            remove,
            story_author,
            story_sent_at,
            group_id,
        }) = normalize(story_reaction).control
        else {
            panic!("a 1:1 story reaction routes to the story face");
        };
        assert_eq!(emoji, "❤️");
        assert!(remove, "the isRemove bit rides the story face");
        assert_eq!(story_author, "22222222-2222-2222-2222-222222222222");
        assert_eq!(story_sent_at, 1726999999000);
        assert_eq!(group_id, None, "the 1:1 leg carries no group key");

        // The degraded shape — storyReply without its timestamp (the engine
        // projects the key only when the author resolves) — stays a plain
        // reaction: one authority, the row ladder's degradation.
        let degraded = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "dataMessage": {
                "reaction": {
                    "emoji": "❤️",
                    "targetAuthor": "22222222-2222-2222-2222-222222222222",
                    "targetSentTimestamp": 1726999999000u64,
                },
                "storyReply": {
                    "authorAci": "22222222-2222-2222-2222-222222222222",
                },
            },
        }));
        assert!(matches!(
            degraded.control,
            Some(ControlReceive::Reaction { .. })
        ));

        // The group shape — reaction + storyReply + groupV2, the official
        // group-channel wire — routes the story face with its group key
        // (contract 1.158, §4.156: the co-presence judgment is one
        // judgment; the 1.154 group fold is overturned).
        let group_shape = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "dataMessage": {
                "reaction": {
                    "emoji": "❤️",
                    "targetAuthor": "22222222-2222-2222-2222-222222222222",
                    "targetSentTimestamp": 1726999999000u64,
                },
                "storyReply": {
                    "authorAci": "22222222-2222-2222-2222-222222222222",
                    "sentTimestamp": 1726999999000u64,
                },
                "groupInfo": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                },
            },
        }));
        let Some(ControlReceive::StoryReaction { group_id, .. }) = group_shape.control else {
            panic!("a group story reaction routes to the story face with its group key");
        };
        assert_eq!(group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));

        // The 1:1 story DOE: envelope isStory + remoteDelete.
        let Some(ControlReceive::StoryDeleted {
            target_timestamp,
            group_id,
        }) = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "isStory": true,
            "dataMessage": {
                "remoteDelete": { "timestamp": 1726999999000u64 },
            },
        }))
        .control
        else {
            panic!("a 1:1 story DOE routes to the story face");
        };
        assert_eq!(target_timestamp, 1726999999000);
        assert_eq!(group_id, None, "the 1:1 leg carries no group key");

        // The conservative leg (contract 1.158, §4.156): a group envelope
        // that carries the isStory bit routes the story face with its group
        // key (officially legal, some clients may send it).
        let group_bit_doe = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "isStory": true,
            "dataMessage": {
                "remoteDelete": { "timestamp": 1726999999000u64 },
                "groupInfo": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                },
            },
        }));
        let Some(ControlReceive::StoryDeleted {
            target_timestamp,
            group_id,
        }) = group_bit_doe.control
        else {
            panic!("a bit-carrying group DOE routes to the story face");
        };
        assert_eq!(target_timestamp, 1726999999000);
        assert_eq!(group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));

        // An unsigned group DOE (no isStory bit on the group leg) keeps the
        // plain remote-delete fold — the official group story deletion is
        // wire-indistinguishable and owns the §4.156 candidate event.
        let group_doe = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550101",
            "dataMessage": {
                "remoteDelete": { "timestamp": 1726999999000u64 },
                "groupInfo": {
                    "groupId": "ZmFrZS1ncm91cC0x",
                },
            },
        }));
        match group_doe.control {
            Some(ControlReceive::RemoteDelete { target_timestamp }) => {
                assert_eq!(target_timestamp, 1726999999000);
                assert_eq!(group_doe.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
            }
            other => panic!("an unsigned group DOE keeps the plain fold: {other:?}"),
        }

        // The self-sync face: storyRecipientUpdate rides with its
        // recipients; source stays None (our own account).
        let recipient_update = normalize(json!({
            "timestamp": 1727000000000u64,
            "source": "+15555550100",
            "syncMessage": {
                "storyRecipientUpdate": {
                    "timestamp": 1726999999000u64,
                    "storyMessageRecipients": [
                        {
                            "destinationUuid": "33333333-3333-3333-3333-333333333333",
                            "distributionListIds": ["00000000-0000-0000-0000-000000000000"],
                            "isAllowedToReply": true,
                        },
                        {
                            "distributionListIds": [],
                        },
                    ],
                },
            },
        }));
        let Some(ControlReceive::SyncStoryRecipientUpdate {
            timestamp,
            recipients,
        }) = recipient_update.control
        else {
            panic!("a storyRecipientUpdate routes to the sync face");
        };
        assert_eq!(timestamp, 1726999999000);
        assert_eq!(recipients.len(), 2);
        assert_eq!(
            recipients[0].destination_uuid.as_deref(),
            Some("33333333-3333-3333-3333-333333333333")
        );
        assert_eq!(
            recipients[0].distribution_list_ids,
            vec!["00000000-0000-0000-0000-000000000000"]
        );
        assert_eq!(recipients[0].is_allowed_to_reply, Some(true));
        assert_eq!(recipients[1].destination_uuid, None);
        assert!(recipients[1].distribution_list_ids.is_empty());
        assert_eq!(recipients[1].is_allowed_to_reply, None);

        // The gates: a zero timestamp (no story to address) and an
        // entry-less array (no face) fall through to the plain sync skip.
        for broken in [
            json!({
                "storyRecipientUpdate": {
                    "timestamp": 0u64,
                    "storyMessageRecipients": [
                        { "distributionListIds": ["00000000-0000-0000-0000-000000000000"] },
                    ],
                },
            }),
            json!({
                "storyRecipientUpdate": {
                    "timestamp": 1726999999000u64,
                    "storyMessageRecipients": [],
                },
            }),
            json!({
                "storyRecipientUpdate": {
                    "timestamp": 1726999999000u64,
                },
            }),
        ] {
            let fallen = normalize(json!({
                "timestamp": 1727000000000u64,
                "source": "+15555550100",
                "syncMessage": broken,
            }));
            assert!(
                fallen.control.is_none(),
                "a gated storyRecipientUpdate falls through: {broken}"
            );
        }
    }

    /// Contract 1.38 (§4.36): a metadata-only view-once marker
    /// (`viewOnceInvalid`) parses onto the rich payload and marks the row
    /// burnable even without renderable media. A dataMessage whose every
    /// other payload is default keeps the §4.20 skip routing — the marker
    /// alone does not manufacture a row.
    #[test]
    fn data_message_view_once_invalid_parses() {
        let normalize = |data: serde_json::Value| {
            normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
            .unwrap()
        };
        let rich = normalize(json!({ "message": "gone", "viewOnceInvalid": true }))
            .rich
            .expect("rich payload");
        assert!(!rich.view_once);
        assert!(rich.view_once_invalid);
        assert!(rich.view_once_opened_at.is_none());

        let bare = normalize(json!({ "viewOnceInvalid": true }));
        assert_eq!(bare.direction, "skip");
        assert!(bare.rich.is_none());
    }

    /// Live poll create (§4.118): the engine's `dataMessage.poll` face
    /// parses onto the exact NormalizedPoll the §4.38 import chain lands —
    /// terminated false, no votes yet — and the bodyless envelope lands as
    /// a real incoming message row (never the skip). The wire JSON of the
    /// face is byte-identical to the history chain's: same struct, same
    /// serde skips.
    #[test]
    fn live_poll_create_lands_a_message_row_in_the_history_shape() {
        let normalize = |mut data: serde_json::Value| {
            if let Some(object) = data.as_object_mut() {
                object.insert("groupInfo".into(), json!({ "groupId": "group-key" }));
            }
            normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
            .unwrap()
        };
        let row = normalize(json!({
            "poll": {
                "question": "Lunch?",
                "options": ["Ramen", "Sushi"],
                "allowMultiple": true,
            },
        }));
        assert_eq!(row.direction, "incoming", "a poll create is a message row");
        assert_eq!(row.content_kind, "dataMessage");
        assert_eq!(row.group_id.as_deref(), Some("group-key"));
        assert!(row.text.is_none(), "poll creates carry no body");
        let poll = row
            .rich
            .as_ref()
            .and_then(|rich| rich.poll.as_ref())
            .expect("poll");
        assert_eq!(poll.question, "Lunch?");
        assert_eq!(poll.options, vec!["Ramen", "Sushi"]);
        assert!(poll.allow_multiple);
        assert!(!poll.terminated, "termination arrives as its own envelope");
        assert!(poll.votes.is_empty(), "votes fold in later");
        // The wire face equals the history chain's exact keys — the two
        // chains land one struct, so the desktop renders both identically.
        // (The row-level flatten happens on the store record; the receive's
        // rich skips serialization, so the face asserts off the rich.)
        let wire = serde_json::to_value(row.rich.as_ref().expect("rich")).expect("wire");
        assert_eq!(
            wire["poll"],
            json!({ "question": "Lunch?", "options": ["Ramen", "Sushi"], "allowMultiple": true })
        );

        // The bare face (single-selection, defaults folded): allowMultiple
        // and terminated stay absent, exactly like an import row without
        // them.
        let bare = normalize(json!({
            "poll": { "question": "Tea?", "options": ["yes", "no"] },
        }));
        let wire = serde_json::to_value(bare.rich.as_ref().expect("rich")).expect("wire");
        assert_eq!(
            wire["poll"],
            json!({ "question": "Tea?", "options": ["yes", "no"] })
        );
    }

    /// Live poll face degradation (§4.118): the face is structural (the
    /// official bare-poll posture) — absent or mistyped fields ride
    /// defaults, a non-object face is no face and the envelope keeps the
    /// skip. Option entries keep their position so vote indexes stay
    /// addressable (a mistyped label rides empty, never shifts the list).
    #[test]
    fn live_poll_face_degrades_without_losing_the_row_shape() {
        let normalize = |data: serde_json::Value| {
            normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
            .unwrap()
        };
        let defaults = normalize(json!({ "poll": {} }));
        assert_eq!(defaults.direction, "incoming");
        let poll = defaults
            .rich
            .as_ref()
            .and_then(|rich| rich.poll.as_ref())
            .expect("a structural poll face always answers");
        assert_eq!(poll.question, "");
        assert!(poll.options.is_empty());
        assert!(!poll.allow_multiple);

        let shifted = normalize(json!({
            "poll": { "question": 7, "options": ["a", 3, "c"], "allowMultiple": "yes" },
        }));
        let poll = shifted
            .rich
            .as_ref()
            .and_then(|rich| rich.poll.as_ref())
            .expect("poll");
        assert_eq!(poll.question, "", "a mistyped question rides empty");
        assert_eq!(
            poll.options,
            vec!["a".to_string(), String::new(), "c".to_string()],
            "positions survive; the mistyped label rides empty"
        );
        assert!(!poll.allow_multiple);

        let foreign = normalize(json!({ "poll": "not-an-object" }));
        assert_eq!(foreign.direction, "skip");
        assert!(foreign.rich.is_none(), "a non-object face is no face");
    }

    /// Live poll vote / terminate (§4.118): the two bodyless envelopes
    /// route as control receives; every degraded shape fails closed to the
    /// plain skip (the guaranteed faces gate).
    #[test]
    fn live_poll_vote_and_terminate_route_as_control() {
        let normalize = |mut data: serde_json::Value| {
            if let Some(object) = data.as_object_mut() {
                object.insert("groupInfo".into(), json!({ "groupId": "group-key" }));
            }
            normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
            .unwrap()
        };
        let vote = normalize(json!({
            "pollVote": {
                "targetAuthor": "+15555550102",
                "targetSentTimestamp": 1726999999000u64,
                "optionIndexes": [2, 1, 2, 3],
                "voteCount": 4,
            },
        }));
        assert_eq!(vote.direction, "incoming");
        assert_eq!(vote.content_kind, "control");
        assert_eq!(vote.group_id.as_deref(), Some("group-key"));
        match vote.control.expect("vote control") {
            ControlReceive::PollVote {
                target_author,
                target_timestamp,
                option_indexes,
            } => {
                assert_eq!(target_author, "+15555550102");
                assert_eq!(target_timestamp, 1726999999000);
                assert_eq!(
                    option_indexes,
                    vec![2, 1, 3],
                    "the selection is a set: dedupe keeps poll order"
                );
            }
            other => panic!("expected a poll vote: {other:?}"),
        }

        let terminate = normalize(json!({
            "pollTerminate": { "targetSentTimestamp": 1726999999000u64 },
        }));
        match terminate.control.expect("terminate control") {
            ControlReceive::PollTerminate { target_timestamp } => {
                assert_eq!(target_timestamp, 1726999999000);
            }
            other => panic!("expected a poll terminate: {other:?}"),
        }

        let mut degraded_faces = vec![
            json!({ "pollVote": { "targetSentTimestamp": 5u64, "optionIndexes": [] } }),
            json!({ "pollVote": { "targetAuthor": "  ", "targetSentTimestamp": 5u64, "optionIndexes": [] } }),
            json!({ "pollVote": { "targetAuthor": "+15555550102", "optionIndexes": [] } }),
            json!({ "pollVote": { "targetAuthor": "+15555550102", "targetSentTimestamp": 0u64, "optionIndexes": [] } }),
            json!({ "pollVote": { "targetAuthor": "+15555550102", "targetSentTimestamp": 5u64, "optionIndexes": "no" } }),
            json!({ "pollVote": { "targetAuthor": "+15555550102", "targetSentTimestamp": 5u64, "optionIndexes": [0, "9"] } }),
            json!({ "pollTerminate": { "targetSentTimestamp": 0u64 } }),
            json!({ "pollTerminate": {} }),
        ];
        degraded_faces.push(json!({
            "pollVote": {
                "targetAuthor": "+15555550102",
                "targetSentTimestamp": 5u64,
                "optionIndexes": vec![0u64; 33],
            },
        }));
        for face in degraded_faces {
            let degraded = normalize(face.clone());
            assert_eq!(
                degraded.direction, "skip",
                "a degraded poll control face fails closed: {face}"
            );
            assert!(degraded.control.is_none(), "{face}");
        }
    }

    /// Live contact card (contract 1.139, §4.132): the engine's
    /// `dataMessage.contact` face parses through the §4.38 import
    /// authority's exact bounds — the wrapped avatar pointer
    /// (`{avatar, isProfile}`) unwraps onto the descriptor list, `isProfile`
    /// never rides, and the bodyless card lands as a real incoming row in
    /// the history chain's wire shape. Degenerate faces (no usable content,
    /// non-object, wrapped avatar without its pointer) fail closed per the
    /// whole-card discipline; the queue budget counts the card's heap
    /// strings entry-wise.
    #[test]
    fn live_contact_card_lands_a_message_row_in_the_history_shape() {
        let avatar = json!({
            "avatar": {
                "id": "att-card",
                "contentType": "image/jpeg",
                "size": 55,
            },
            "isProfile": true,
        });
        let full = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {
                    "contact": {
                        "name": {"givenName": "Ada", "familyName": "Lovelace", "middleName": "Byron"},
                        "number": [
                            {"value": "+15550000003", "type": "HOME"},
                            {"value": "+15550000004", "type": "MOBILE", "label": "cell"},
                        ],
                        "email": [{"value": "ada@example.org", "type": "WORK"}],
                        "organization": "Analytical Engines Ltd",
                        "avatar": avatar,
                    }
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(
            full.direction, "incoming",
            "a contact card is a message row"
        );
        assert_eq!(full.content_kind, "dataMessage");
        assert!(full.text.is_none(), "cards carry no body");
        let contact = full
            .rich
            .as_ref()
            .and_then(|rich| rich.contact.as_ref())
            .expect("card");
        let name = contact.name.as_ref().expect("name parts");
        assert_eq!(name.given_name.as_deref(), Some("Ada"));
        assert_eq!(name.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(name.middle_name.as_deref(), Some("Byron"));
        assert_eq!(contact.number[0].kind, "HOME");
        assert_eq!(contact.number[1].kind, "MOBILE");
        assert_eq!(contact.number[1].label.as_deref(), Some("cell"));
        assert_eq!(contact.email[0].value, "ada@example.org");
        assert_eq!(
            contact.organization.as_deref(),
            Some("Analytical Engines Ltd")
        );
        assert_eq!(
            full.attachments.len(),
            1,
            "the unwrapped avatar joined the descriptor list"
        );
        assert_eq!(full.attachments[0].id, "att-card");
        assert_eq!(
            full.attachments[0].content_type.as_deref(),
            Some("image/jpeg")
        );
        assert_eq!(full.attachments[0].locator, None);
        // The wire face equals the history chain's exact keys, and the
        // address-book wrap fact stays off the row.
        let wire = serde_json::to_value(full.rich.as_ref().expect("rich")).expect("wire");
        assert_eq!(wire["contact"]["name"]["givenName"], "Ada");
        assert_eq!(wire["contact"]["number"][0]["value"], "+15550000003");
        assert_eq!(wire["contact"]["organization"], "Analytical Engines Ltd");
        assert!(
            !wire.to_string().contains("isProfile"),
            "isProfile is the engine's address-book fact, not the message's"
        );
        // The queue budget counts the card's heap strings entry-wise
        // (§4.13): the same bodyless envelope without the card is strictly
        // lighter, and the delta covers the card's own accounting.
        let bare = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {},
            }
        }))
        .unwrap()
        .unwrap();
        assert!(bare.rich.is_none());
        let delta = full.estimated_bytes() - bare.estimated_bytes();
        assert!(
            delta
                >= std::mem::size_of::<NormalizedRich>()
                    + std::mem::size_of::<NormalizedContact>()
                    + std::mem::size_of::<NormalizedContactName>()
                    + "Ada".len()
                    + "Lovelace".len()
                    + "Byron".len()
                    + 3 * std::mem::size_of::<NormalizedContactField>()
                    + 2 * "+15550000003".len()
                    + "ada@example.org".len()
                    + "Analytical Engines Ltd".len(),
            "the card's heap strings count in the queue budget"
        );

        // A body message keeps its row and the card rides beside the text.
        let with_text = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000001u64,
                "source": "+15555550101",
                "dataMessage": {
                    "message": "here is Ada",
                    "contact": {"name": {"givenName": "Ada"}},
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(with_text.direction, "incoming");
        assert_eq!(with_text.text.as_deref(), Some("here is Ada"));
        assert!(
            with_text
                .rich
                .as_ref()
                .and_then(|rich| rich.contact.as_ref())
                .is_some(),
            "the card rides beside the body"
        );
        assert!(with_text.attachments.is_empty(), "no avatar, no descriptor");

        // A wrapped avatar without its pointer unwraps to no avatar face —
        // the card lands, the descriptor list stays empty.
        let pointerless = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000002u64,
                "source": "+15555550101",
                "dataMessage": {
                    "contact": {
                        "name": {"givenName": "Grace"},
                        "avatar": {"isProfile": false},
                    }
                }
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(pointerless.direction, "incoming");
        assert!(
            pointerless
                .rich
                .as_ref()
                .and_then(|rich| rich.contact.as_ref())
                .is_some()
        );
        assert!(pointerless.attachments.is_empty());

        // Degenerate faces fail closed to the plain skip: an empty card, a
        // non-object face.
        for face in [json!({}), json!("not-an-object")] {
            let degraded = normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000003u64,
                    "source": "+15555550101",
                    "dataMessage": { "contact": face.clone() },
                }
            }))
            .unwrap()
            .unwrap();
            assert_eq!(
                degraded.direction, "skip",
                "a card with no usable content keeps plain routing: {face}"
            );
            assert!(degraded.rich.is_none(), "{face}");
        }
    }

    /// The sent transcript's contact card (contract 1.139, §4.132): a
    /// phone-originated share lands as the same outgoing row a peer's card
    /// does — the self send's own timestamp, the wrapped avatar on the
    /// descriptor list. A card beside a control echo (remoteDelete) keeps
    /// its control routing, the card never riding that row (the sticker
    /// precedence discipline).
    #[test]
    fn sync_sent_contact_card_lands_outgoing_row_and_keeps_control_precedence() {
        let normalized = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "destinationNumber": "+15555550101",
                        "contact": {
                            "name": {"givenName": "Ada", "familyName": "Lovelace"},
                            "number": [{"value": "+15550000003", "type": "MOBILE"}],
                            "organization": "Analytical Engines Ltd",
                            "avatar": {
                                "avatar": {"id": "att-card", "contentType": "image/jpeg"},
                                "isProfile": false,
                            }
                        }
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(normalized.direction, "outgoing");
        assert_eq!(normalized.timestamp, Some(1726999997000));
        assert!(normalized.text.is_none());
        let contact = normalized
            .rich
            .as_ref()
            .and_then(|rich| rich.contact.as_ref())
            .expect("card");
        assert_eq!(
            contact.name.as_ref().unwrap().family_name.as_deref(),
            Some("Lovelace")
        );
        assert_eq!(contact.number[0].kind, "MOBILE");
        assert_eq!(normalized.attachments.len(), 1);
        assert_eq!(normalized.attachments[0].id, "att-card");

        // A card + remoteDelete echo from the phone keeps its control
        // routing — the merge happens after the ladder read, exactly like
        // the sticker's descriptor push does.
        let echo = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "destinationNumber": "+15555550101",
                        "contact": {"name": {"givenName": "Ada"}},
                        "remoteDelete": {"timestamp": 1726999990000u64},
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(echo.direction, "outgoing");
        assert_eq!(echo.content_kind, "control");
        match echo.control.expect("the delete is the row's content") {
            ControlReceive::RemoteDelete { target_timestamp } => {
                assert_eq!(target_timestamp, 1726999990000);
            }
            other => panic!("expected a remote delete: {other:?}"),
        }
        assert!(echo.rich.is_none(), "the card does not ride a control echo");
        assert!(echo.attachments.is_empty());
    }

    /// The own-story multi-device transcript (contract 1.160, §4.158): the
    /// account's own story posted from another linked device rides the
    /// `syncMessage.sentMessage.storyMessage` projection into the
    /// `SyncStoryMessage` control face — the bounded face forwards
    /// verbatim (the media locator's full face included), the first-send
    /// `storyMessageRecipients` mirror beside it changes nothing (the
    /// audience state is the `story.recipientUpdate` event's job, contract
    /// 1.154), a group face keeps its group key on the normalized receive,
    /// and an oversized face or a sync with no anchor timestamp keeps the
    /// plain skip (宁缺勿错).
    #[test]
    fn sync_sent_story_routes_the_own_transcript_face() {
        // The locator full-face forwards verbatim: the story face rides the
        // control receive untouched, and the anchor timestamp is the self
        // send's own ts, never the envelope's.
        let normalized = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "storyMessage": {
                            "text": "story body",
                            "allowsReplies": true,
                            "fileAttachment": {
                                "id": "att-story-1",
                                "contentType": "image/jpeg",
                                "size": 12345,
                                "key": "a2V5",
                                "cdnKey": "Y2RuLWtleQ==",
                                "cdnNumber": 3,
                                "uploadTimestamp": 1726999996000u64,
                                "digest": "ZGlnZXN0",
                                "plaintextHash": "cGxhaW50ZXh0aGFzaA==",
                            },
                        },
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(normalized.content_kind, "storyMessage");
        assert_eq!(normalized.direction, "outgoing");
        assert_eq!(normalized.timestamp, Some(1726999997000));
        let Some(ControlReceive::SyncStoryMessage { message }) = normalized.control else {
            panic!("the own story transcript routes to the sync story face");
        };
        assert_eq!(
            message,
            json!({
                "text": "story body",
                "allowsReplies": true,
                "fileAttachment": {
                    "id": "att-story-1",
                    "contentType": "image/jpeg",
                    "size": 12345,
                    "key": "a2V5",
                    "cdnKey": "Y2RuLWtleQ==",
                    "cdnNumber": 3,
                    "uploadTimestamp": 1726999996000u64,
                    "digest": "ZGlnZXN0",
                    "plaintextHash": "cGxhaW50ZXh0aGFzaA==",
                },
            }),
            "the bounded story face forwards verbatim"
        );

        // The first-send mirror: storyMessage + storyMessageRecipients ride
        // the sent object side by side; the story arm takes the body and
        // the audience state stays the recipient-update event's job — the
        // face never carries it.
        let first_send = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "storyMessage": { "text": "story body" },
                        "storyMessageRecipients": [{
                            "destinationUuid": "33333333-3333-3333-3333-333333333333",
                            "distributionListIds": [
                                "00000000-0000-0000-0000-000000000000"
                            ],
                            "allowReplies": true,
                        }],
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(first_send.content_kind, "storyMessage");
        assert_eq!(first_send.direction, "outgoing");
        assert!(matches!(
            first_send.control,
            Some(ControlReceive::SyncStoryMessage { .. })
        ));

        // A group face keeps its group key on the normalized receive and
        // routes the same story face (the group story rides the same
        // transcript; the desktop's group-story boundary is its own shape
        // gate's call).
        let group_face = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "groupInfo": { "groupId": "ZmFrZS1ncm91cC0x" },
                        "storyMessage": { "text": "group story" },
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(group_face.content_kind, "storyMessage");
        assert_eq!(group_face.direction, "outgoing");
        assert_eq!(group_face.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
        assert!(matches!(
            group_face.control,
            Some(ControlReceive::SyncStoryMessage { .. })
        ));

        // Oversized material keeps the plain skip: no control, no face.
        let oversized = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "storyMessage": { "text": "x".repeat(3 * 1024 * 1024 + 1) },
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(oversized.content_kind, "storyMessage");
        assert_eq!(oversized.direction, "skip");
        assert!(oversized.control.is_none());

        // No anchor timestamp anywhere (sent + envelope both absent): no
        // story to date, the plain skip again.
        let timeless = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "syncMessage": {
                    "sentMessage": {
                        "storyMessage": { "text": "story body" },
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(timeless.content_kind, "storyMessage");
        assert_eq!(timeless.direction, "skip");
        assert!(timeless.timestamp.is_none());
        assert!(timeless.control.is_none());
    }

    /// The self-send transcript echoes (§4.118): the engine's own group
    /// send (including the connector's `messages.sendPoll*` calls)
    /// transcribes the full dataMessage, so the create echo lands as the
    /// account's own outgoing mirror row and the vote/terminate echoes as
    /// outgoing control receives — the 自发同步 posture (never an unread).
    #[test]
    fn sent_poll_echoes_land_outgoing() {
        let normalize = |sent: serde_json::Value| {
            normalize_receive(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": { "sentMessage": sent },
                },
            }))
            .unwrap()
            .unwrap()
        };
        let create = normalize(json!({
            "timestamp": 1726999998000u64,
            "groupInfo": { "groupId": "group-key" },
            "poll": { "question": "Lunch?", "options": ["Ramen", "Sushi"] },
        }));
        assert_eq!(
            create.direction, "outgoing",
            "the create echo is the own row"
        );
        assert_eq!(create.content_kind, "syncMessage");
        assert!(create.control.is_none());
        assert!(
            create
                .rich
                .as_ref()
                .and_then(|rich| rich.poll.as_ref())
                .is_some(),
            "the face rides the mirror row"
        );

        let vote = normalize(json!({
            "timestamp": 1726999999000u64,
            "groupInfo": { "groupId": "group-key" },
            "pollVote": {
                "targetAuthor": "+15555550102",
                "targetSentTimestamp": 1726999998000u64,
                "optionIndexes": [0],
                "voteCount": 1,
            },
        }));
        assert_eq!(vote.direction, "outgoing");
        assert_eq!(vote.content_kind, "control");
        match vote.control.expect("vote echo control") {
            ControlReceive::PollVote {
                target_author,
                target_timestamp,
                option_indexes,
            } => {
                assert_eq!(target_author, "+15555550102");
                assert_eq!(target_timestamp, 1726999998000);
                assert_eq!(option_indexes, vec![0]);
            }
            other => panic!("expected a poll vote echo: {other:?}"),
        }

        let terminate = normalize(json!({
            "timestamp": 1726999999500u64,
            "groupInfo": { "groupId": "group-key" },
            "pollTerminate": { "targetSentTimestamp": 1726999998000u64 },
        }));
        assert_eq!(terminate.direction, "outgoing");
        assert!(matches!(
            terminate.control,
            Some(ControlReceive::PollTerminate { .. })
        ));
    }

    /// Contract 1.38 (§4.37): every receive envelope's `sourceUuid` is
    /// captured — the raw author identity the service layer records into
    /// `peer_identities` so later open syncs can resolve their target.
    #[test]
    fn receive_captures_source_uuid() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "sourceUuid": "11111111-1111-1111-1111-111111111111",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(
            normalized.source_uuid.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        // A normalized receive projected before contract 1.38 (or from an
        // envelope without one) leaves the field empty.
        let bare = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert!(bare.source_uuid.is_none());
    }

    /// Contract 1.49 (§4.48): every receive envelope's `serverGuid` is
    /// captured — the server-assigned message GUID the reportSpam face
    /// persists row-level and addresses the upstream report API with. It is
    /// connector-internal (never serialized), trimmed, capped at the id
    /// budget, and an envelope without one normalizes to None.
    #[test]
    fn receive_captures_server_guid() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "serverGuid": "  guid-abc  ",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.server_guid.as_deref(), Some("guid-abc"));
        let bare = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert!(bare.server_guid.is_none());
        let blank = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "serverGuid": "   ",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert!(blank.server_guid.is_none());
    }

    /// The spam-report token (reportSpam data plane): the envelope's
    /// `reportingToken` (the engine's base64 projection of the proto
    /// `reportSpamToken`) is captured connector-internal — trimmed, bounded,
    /// never serialized. An absent key, a blank value, and an over-bound
    /// value all fold to None (a credential is never truncated: silently
    /// corrupting it would mis-address the upstream report).
    #[test]
    fn receive_captures_reporting_token() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "reportingToken": "  dG9rZW4tYWJj  ",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.reporting_token.as_deref(), Some("dG9rZW4tYWJj"));
        let bare = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert!(bare.reporting_token.is_none());
        let blank = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "reportingToken": "   ",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert!(blank.reporting_token.is_none());
        let oversized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "reportingToken": "x".repeat(MAX_REPORTING_TOKEN_CHARS + 1),
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert!(oversized.reporting_token.is_none());
    }

    /// Contract 1.128 (§4.109): the envelope `serverTimestamp` key (P15c
    /// 项5, the engine projects it on every receive envelope) lands on the
    /// normalized receive as the row's server-time key. A positive value
    /// rides verbatim; the proto-absent projection's 0 (the official `?? 0n`
    /// unknown sentinel) folds to None — an unknown server time stores as
    /// NULL, never as the epoch; an absent key stores None the same way.
    #[test]
    fn receive_captures_server_timestamp() {
        let normalized = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "serverTimestamp": 1_700_000_004_321u64,
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(normalized.server_timestamp, Some(1_700_000_004_321));
        let zero = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "serverTimestamp": 0,
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(zero.server_timestamp, None);
        let absent = normalize_receive(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": { "message": "hi" },
            },
        }))
        .unwrap()
        .unwrap();
        assert_eq!(absent.server_timestamp, None);
    }

    /// Contract 1.42 (§4.41): a dataMessage states its conversation's
    /// disappearing timer with `expiresInSeconds` (absent = no value,
    /// 0 = stated off) and may carry the engine-reported countdown start
    /// `expirationStartTimestamp`; both ride the normalized receive
    /// unchanged, and a stated start stamp of 0 is treated as absent.
    #[test]
    fn data_message_expire_metadata_normalizes() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let live = normalize(json!({
            "message": "vanishing soon",
            "expiresInSeconds": 86400u64,
            "expirationStartTimestamp": 1726999900000u64,
        }));
        assert_eq!(live.expire_seconds, Some(86400));
        assert_eq!(live.expire_start_at, Some(1726999900000));
        assert!(!live.rich.is_some_and(|rich| rich.is_expiration_update));
        assert_eq!(live.direction, "incoming");

        let stated_off = normalize(json!({
            "message": "plain",
            "expiresInSeconds": 0u64,
        }));
        assert_eq!(stated_off.expire_seconds, Some(0));
        assert_eq!(stated_off.expire_start_at, None);

        let silent = normalize(json!({ "message": "plain" }));
        assert_eq!(silent.expire_seconds, None);
        assert_eq!(silent.expire_start_at, None);

        let zero_start = normalize(json!({
            "message": "plain",
            "expiresInSeconds": 60u64,
            "expirationStartTimestamp": 0u64,
        }));
        assert_eq!(zero_start.expire_seconds, Some(60));
        assert_eq!(zero_start.expire_start_at, None);
    }

    /// Contract 1.42 (§4.41): a peer's timer change lands as a bodyless
    /// dataMessage flagged `isExpirationUpdate` — projected as a system row
    /// whose text material carries the announced value (0 and the absent
    /// close form both read as off), with the rich marker as the row's only
    /// rich content. A body message never carries the marker.
    #[test]
    fn peer_timer_change_projects_system_row() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let open = normalize(json!({
            "isExpirationUpdate": true,
            "expiresInSeconds": 86400u64,
        }));
        assert_eq!(open.direction, "system");
        assert_eq!(open.text.as_deref(), Some("已更新消息定时消失：86400 秒"));
        assert!(open.rich.is_some_and(|rich| rich.is_expiration_update));
        assert_eq!(open.expire_seconds, Some(86400));

        let close = normalize(json!({
            "isExpirationUpdate": true,
            "expiresInSeconds": 0u64,
        }));
        assert_eq!(close.direction, "system");
        assert_eq!(close.text.as_deref(), Some("已更新消息定时消失：已关闭"));
        assert_eq!(close.expire_seconds, Some(0));

        let body = normalize(json!({
            "message": "hello",
            "isExpirationUpdate": false,
        }));
        assert_eq!(body.direction, "incoming");
        assert!(!body.rich.is_some_and(|rich| rich.is_expiration_update));
    }

    /// Contract 1.42 (§4.41): our own phone-side timer toggle mirrors through
    /// `syncMessage.sentMessage` (`isExpirationUpdate`, no body) as the same
    /// system row a peer's change lands as, addressed by the sent
    /// destination — so every linked device's history agrees.
    #[test]
    fn sync_sent_timer_change_projects_system_row() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "account": "+15555550100",
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": { "sentMessage": data },
                },
            }))
            .unwrap()
        };
        let open = normalize(json!({
            "timestamp": 1727000000000u64,
            "destinationNumber": "+15555550101",
            "isExpirationUpdate": true,
            "expiresInSeconds": 604800u64,
        }));
        assert_eq!(open.direction, "system");
        assert_eq!(open.content_kind, "syncMessage");
        assert_eq!(open.text.as_deref(), Some("已更新消息定时消失：604800 秒"));
        assert!(open.rich.is_some_and(|rich| rich.is_expiration_update));
        assert_eq!(open.expire_seconds, Some(604800));

        // A real sent body keeps flowing as outgoing with the timer keys.
        let sent = normalize(json!({
            "timestamp": 1727000000000u64,
            "destinationNumber": "+15555550101",
            "message": "from my phone",
            "expiresInSeconds": 3600u64,
        }));
        assert_eq!(sent.direction, "outgoing");
        assert_eq!(sent.expire_seconds, Some(3600));
    }

    /// Contract 1.136 (§4.121): a phone-originated sticker mirrors through
    /// `syncMessage.sentMessage` as the same outgoing row the connector's own
    /// `messages.sendSticker` lands — the pack identity rides the row's
    /// sticker face and the `data` pointer joins the attachment list as a
    /// metadata-only descriptor; a sticker sent with a quote keeps the quote
    /// beside the face. The pre-1.136 shape dropped the whole envelope as
    /// skip, so the desktop never learned the phone's sticker sends.
    #[test]
    fn sync_sent_sticker_lands_outgoing_row() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "account": "+15555550100",
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": { "sentMessage": data },
                },
            }))
            .unwrap()
        };
        let sent = normalize(json!({
            "timestamp": 1726999999000u64,
            "destinationNumber": "+15555550101",
            "sticker": {
                "packId": "abcdef01",
                "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                "stickerId": 7,
                "emoji": "🎉",
                "data": {
                    "id": "att-1",
                    "contentType": "image/webp",
                    "size": 8192,
                    "width": 512,
                    "height": 512,
                },
            },
        }));
        assert_eq!(sent.direction, "outgoing");
        assert_eq!(sent.timestamp, Some(1726999999000));
        assert_eq!(sent.source.as_deref(), Some("+15555550101"));
        let sticker = sent.sticker.as_ref().expect("sticker metadata");
        assert_eq!(sticker.pack_id, "abcdef01");
        assert_eq!(sticker.sticker_id, 7);
        assert_eq!(sticker.emoji.as_deref(), Some("🎉"));
        assert_eq!(sent.attachments.len(), 1);
        assert_eq!(sent.attachments[0].id, "att-1");
        assert_eq!(
            sent.attachments[0].content_type.as_deref(),
            Some("image/webp")
        );

        // A quoted sticker keeps both faces on the one outgoing row.
        let quoted = normalize(json!({
            "timestamp": 1726999998000u64,
            "destinationUuid": "11111111-1111-1111-1111-111111111111",
            "quote": {
                "id": 1726999990000u64,
                "author": "+15555550101",
                "text": "look at this",
            },
            "sticker": {
                "packId": "abcdef02",
                "packKey": "BBBBBBBBBBBBBBBBBBBBBB==",
                "stickerId": 3,
                "data": {
                    "id": "att-2",
                    "contentType": "image/webp",
                },
            },
        }));
        assert_eq!(quoted.direction, "outgoing");
        assert!(quoted.sticker.is_some());
        let quote = quoted.quote.expect("quoted sticker keeps the quote");
        assert_eq!(quote.id, 1726999990000);
        assert_eq!(quoted.attachments.len(), 1);
        assert_eq!(quoted.attachments[0].id, "att-2");
    }

    /// Contract 1.136 (§4.121): the sticker face never outranks the faces
    /// the sent ladder already prioritizes — a mirror whose sticker has no
    /// usable `data` pointer keeps the plain skip (nothing renderable), and
    /// a sticker beside a remote-delete echo keeps its control routing (the
    /// delete must fold onto the row the sticker landed earlier, never spawn
    /// a second one).
    #[test]
    fn sync_sent_sticker_keeps_prior_routing_precedence() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "account": "+15555550100",
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": { "sentMessage": data },
                },
            }))
            .unwrap()
        };
        // No usable data pointer → the plain skip routing.
        let dataless = normalize(json!({
            "timestamp": 1726999999000u64,
            "destinationNumber": "+15555550101",
            "sticker": {
                "packId": "abcdef01",
                "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                "stickerId": 7,
            },
        }));
        assert_eq!(dataless.direction, "skip");
        assert!(dataless.sticker.is_none());

        // Sticker + remoteDelete echo → the control face wins.
        let deleted = normalize(json!({
            "timestamp": 1726999999000u64,
            "destinationNumber": "+15555550101",
            "remoteDelete": { "timestamp": 1726999990000u64 },
            "sticker": {
                "packId": "abcdef01",
                "packKey": "AAAAAAAAAAAAAAAAAAAAAA==",
                "stickerId": 7,
                "data": { "id": "att-1", "contentType": "image/webp" },
            },
        }));
        assert_eq!(deleted.direction, "outgoing");
        assert_eq!(deleted.content_kind, "control");
        let Some(ControlReceive::RemoteDelete { target_timestamp }) = deleted.control else {
            panic!("expected the remote-delete control to win");
        };
        assert_eq!(target_timestamp, 1726999990000);
    }

    /// Contract 1.136 (§4.121): a bodyless pure-quote send — no body, no
    /// descriptor, the quote the whole content — lands as the same outgoing
    /// row the quoted-text send does. The pre-1.136 shape fell through every
    /// arm to skip, so the desktop never saw the phone's quote-only sends.
    #[test]
    fn sync_sent_bodyless_quote_lands_outgoing_row() {
        let normalized = normalize_receive_fields(&json!({
            "account": "+15555550100",
            "envelope": {
                "timestamp": 1727000000000u64,
                "syncMessage": {
                    "sentMessage": {
                        "timestamp": 1726999997000u64,
                        "destinationNumber": "+15555550101",
                        "quote": {
                            "id": 1726999990000u64,
                            "author": "+15555550101",
                            "text": "the quoted body",
                        },
                    },
                },
            },
        }))
        .unwrap();
        assert_eq!(normalized.direction, "outgoing");
        assert_eq!(normalized.timestamp, Some(1726999997000));
        assert!(normalized.text.is_none());
        assert!(normalized.attachments.is_empty());
        let quote = normalized.quote.expect("the quote is the row's content");
        assert_eq!(quote.id, 1726999990000);
        assert_eq!(quote.text, "the quoted body");
    }

    /// Contract 1.45 (§4.44): a bodyless group-state change
    /// (`groupInfo.type == UPDATE`) projects as a generic system row — the
    /// pre-1.45 shape fell to skip and was swallowed. The resulting title
    /// rides `rich.groupName` (camelCase on the wire) capped at 64 chars; a
    /// DELIVER envelope (every normal group message) stays marker-free and a
    /// body-carrying UPDATE keeps its ordinary row with the marker beside it.
    #[test]
    fn peer_group_update_projects_system_row() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": data,
                },
            }))
            .unwrap()
        };
        let update = normalize(json!({
            "groupInfo": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "type": "UPDATE",
                "groupName": "Fixture Group",
                "revision": 7u64,
            },
        }));
        assert_eq!(update.direction, "system");
        assert_eq!(update.content_kind, "dataMessage");
        assert_eq!(update.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
        assert_eq!(update.text.as_deref(), Some("群聊信息已更新"));
        let rich = update.rich.expect("group-update row carries rich");
        assert!(rich.is_group_update);
        assert_eq!(rich.group_name.as_deref(), Some("Fixture Group"));
        assert!(!rich.is_expiration_update);

        // The title mirrors the engine's post-change value, capped at 64.
        let long = normalize(json!({
            "groupInfo": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "type": "UPDATE",
                "groupName": "長".repeat(80),
            },
        }));
        let rich = long.rich.expect("long title still projects");
        assert_eq!(rich.group_name.as_deref(), Some("長".repeat(64).as_str()));

        // A bodyless DELIVER stays a skip — only UPDATE marks a group edit.
        let deliver = normalize(json!({
            "groupInfo": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "type": "DELIVER",
            },
        }));
        assert_eq!(deliver.direction, "skip");
        assert!(deliver.rich.is_none());

        // A body-carrying UPDATE is an ordinary message row; the marker and
        // title ride beside the body instead of replacing it.
        let body = normalize(json!({
            "message": "renamed us",
            "groupInfo": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "type": "UPDATE",
                "groupName": "New Name",
            },
        }));
        assert_eq!(body.direction, "incoming");
        assert_eq!(body.text.as_deref(), Some("renamed us"));
        let rich = body.rich.expect("body row carries the marker");
        assert!(rich.is_group_update);
        assert_eq!(rich.group_name.as_deref(), Some("New Name"));
    }

    /// Contract 1.45 (§4.44): our own phone-side group edit mirrors through
    /// `syncMessage.sentMessage` as the same generic system row a peer's
    /// change lands as, keyed by the sent group — every linked device's
    /// history agrees.
    #[test]
    fn sync_sent_group_update_projects_system_row() {
        let normalize = |data: serde_json::Value| {
            normalize_receive_fields(&json!({
                "account": "+15555550100",
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": { "sentMessage": data },
                },
            }))
            .unwrap()
        };
        let update = normalize(json!({
            "timestamp": 1727000000000u64,
            "groupInfo": {
                "groupId": "ZmFrZS1ncm91cC0x",
                "type": "UPDATE",
                "groupName": "Fixture Group",
            },
        }));
        assert_eq!(update.direction, "system");
        assert_eq!(update.content_kind, "syncMessage");
        assert_eq!(update.group_id.as_deref(), Some("ZmFrZS1ncm91cC0x"));
        assert_eq!(update.text.as_deref(), Some("群聊信息已更新"));
        let rich = update.rich.expect("group-update mirror carries rich");
        assert!(rich.is_group_update);
        assert_eq!(rich.group_name.as_deref(), Some("Fixture Group"));
    }

    /// Contract 1.45 (§4.44): a timer change outranks a group update — the
    /// §4.41 timer notice keeps its row when the envelope happens to carry
    /// both markers.
    #[test]
    fn timer_change_outranks_group_update() {
        let normalize = normalize_receive_fields(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {
                    "isExpirationUpdate": true,
                    "expiresInSeconds": 3600u64,
                    "groupInfo": {
                        "groupId": "ZmFrZS1ncm91cC0x",
                        "type": "UPDATE",
                        "groupName": "Fixture Group",
                    },
                },
            },
        }))
        .unwrap();
        assert_eq!(normalize.direction, "system");
        assert_eq!(
            normalize.text.as_deref(),
            Some("已更新消息定时消失：3600 秒")
        );
        let rich = normalize.rich.expect("timer row carries rich");
        assert!(rich.is_expiration_update);
        assert!(!rich.is_group_update);
    }

    /// Contract §4.227: a structured `groupInfo.changes[]` face rides the
    /// group-update row verbatim — the official detail vocabulary the
    /// desktop's GroupV2Change renderer consumes — beside the resulting
    /// `revision` and the bounded `editor`. The wire key is the camelCase
    /// `groupChange`; a marker-only rich serializes no such key (the serde
    /// skip discipline every rich face keeps).
    #[test]
    fn group_change_structured_face_rides_the_update_row() {
        let changes = json!([
            { "type": "title", "newTitle": "Renamed" },
            {
                "type": "member-add",
                "aci": "22222222-3333-4444-8555-666666666666",
            },
        ]);
        let normalized = normalize_receive_fields(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {
                    "groupInfo": {
                        "groupId": "ZmFrZS1ncm91cC0x",
                        "type": "UPDATE",
                        "revision": 7u64,
                        "editor": "11111111-2222-4333-8444-555555555555",
                        "changes": changes,
                    },
                },
            },
        }))
        .unwrap();
        assert_eq!(normalized.direction, "system");
        assert_eq!(normalized.text.as_deref(), Some("群聊信息已更新"));
        let rich = normalized.rich.expect("update row carries rich");
        assert!(rich.is_group_update);
        let face = rich.group_change.as_ref().expect("structured face parses");
        assert_eq!(face.revision, Some(7));
        assert_eq!(
            face.editor.as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );
        assert_eq!(Value::Array(face.changes.clone()), changes);

        // The wire face is the camelCase `groupChange` object, the changes
        // verbatim; a marker-only rich carries no such key at all.
        let wire = serde_json::to_value(&rich).unwrap();
        assert_eq!(wire["groupChange"]["revision"], json!(7));
        assert_eq!(
            wire["groupChange"]["editor"],
            json!("11111111-2222-4333-8444-555555555555")
        );
        assert_eq!(wire["groupChange"]["changes"], changes);
        let bare = serde_json::to_value(NormalizedRich {
            is_group_update: true,
            ..Default::default()
        })
        .unwrap();
        assert!(
            bare.get("groupChange").is_none(),
            "an absent face stays off the wire"
        );

        // A body-carrying update keeps the face beside the body row.
        let body = normalize_receive_fields(&json!({
            "envelope": {
                "timestamp": 1727000000000u64,
                "source": "+15555550101",
                "dataMessage": {
                    "message": "renamed us",
                    "groupInfo": {
                        "groupId": "ZmFrZS1ncm91cC0x",
                        "type": "UPDATE",
                        "changes": [{ "type": "title", "newTitle": "New Name" }],
                    },
                },
            },
        }))
        .unwrap();
        assert_eq!(body.direction, "incoming");
        let rich = body.rich.expect("body row carries the marker");
        assert!(rich.is_group_update);
        let face = rich.group_change.expect("body row carries the face");
        assert_eq!(face.revision, None);
        assert_eq!(face.editor, None);
        assert_eq!(
            Value::Array(face.changes.clone()),
            json!([{ "type": "title", "newTitle": "New Name" }])
        );
    }

    /// Contract §4.227 degradation arms: entries past the §4.81 change cap
    /// truncate, material over the coarse byte guard drops the whole face
    /// (宁缺勿错), presence without material (`changes` missing/empty) is no
    /// face, a DELIVER face with stray keys keeps nothing (the marker is the
    /// gate), and per-key hostile shapes (oversized editor, out-of-range
    /// revision) drop the key and never the face.
    #[test]
    fn group_change_face_degrades_per_guard() {
        let normalize = |info: serde_json::Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "source": "+15555550101",
                    "dataMessage": { "groupInfo": info },
                },
            }))
            .unwrap()
        };
        let update = |info: serde_json::Value| {
            let mut object = info;
            object["groupId"] = json!("ZmFrZS1ncm91cC0x");
            object["type"] = json!("UPDATE");
            object
        };

        // Entries past the cap truncate to the §4.81 ceiling.
        let many: Vec<serde_json::Value> = (0..crate::service::GROUP_CHANGED_MAX_CHANGES + 1)
            .map(|_| json!({ "type": "summary" }))
            .collect();
        let rich = normalize(update(json!({ "changes": many })))
            .rich
            .expect("truncation keeps the row");
        let face = rich.group_change.expect("capped face stays a face");
        assert_eq!(
            face.changes.len(),
            crate::service::GROUP_CHANGED_MAX_CHANGES
        );
        assert_eq!(face.revision, None);
        assert_eq!(face.editor, None);

        // Material over the coarse byte guard drops the whole face — the row
        // and its marker survive.
        let huge = json!([{ "type": "description", "description": "x".repeat(70_000) }]);
        let rich = normalize(update(json!({ "changes": huge })))
            .rich
            .expect("the byte guard drops the face, never the row");
        assert!(rich.is_group_update);
        assert!(rich.group_change.is_none(), "宁缺勿错: no truncated lie");

        // Presence without material: no changes key, or an empty one — no
        // face, even with revision/editor material beside.
        for info in [
            json!({ "revision": 3u64, "editor": "11111111-2222-4333-8444-555555555555" }),
            json!({ "changes": [], "revision": 3u64 }),
            json!({ "changes": "not-an-array" }),
        ] {
            let rich = normalize(update(info)).rich.expect("marker-only row");
            assert!(
                rich.group_change.is_none(),
                "presence without material is no face"
            );
        }

        // A DELIVER face with stray keys keeps nothing — the UPDATE marker is
        // the face's gate, and a bodyless DELIVER stays a plain skip.
        let deliver = normalize(json!({
            "groupId": "ZmFrZS1ncm91cC0x",
            "type": "DELIVER",
            "changes": [{ "type": "title", "newTitle": "nope" }],
        }));
        assert_eq!(deliver.direction, "skip");
        assert!(deliver.rich.is_none());

        // Per-key hostile shapes drop the key and never the face.
        let rich = normalize(update(json!({
            "changes": [{ "type": "summary" }],
            "editor": "e".repeat(65),
            "revision": u64::from(u32::MAX) + 1,
        })))
        .rich
        .expect("hostile keys never sink the face");
        let face = rich.group_change.expect("the face survives");
        assert_eq!(face.editor, None, "oversized editor drops");
        assert_eq!(face.revision, None, "out-of-range revision drops");
        assert_eq!(
            Value::Array(face.changes.clone()),
            json!([{ "type": "summary" }])
        );
    }

    #[test]
    fn stdout_pump_reader_frames_lines_strips_cr_and_delivers_eof_partial() {
        let (pipe_reader, writer) = std::io::pipe().unwrap();
        let mut reader = std::io::BufReader::new(pipe_reader);
        {
            let mut writer = writer;
            writer.write_all(b"alpha\nbeta\r\ngamma-partial").unwrap();
        }
        assert_eq!(
            read_bounded_line(&mut reader, 1024).unwrap(),
            Some(PumpedLine::Line("alpha".into()))
        );
        // A `\r` before the newline is transport padding, not content.
        assert_eq!(
            read_bounded_line(&mut reader, 1024).unwrap(),
            Some(PumpedLine::Line("beta".into()))
        );
        // A partial final line at EOF is delivered, then the stream ends.
        assert_eq!(
            read_bounded_line(&mut reader, 1024).unwrap(),
            Some(PumpedLine::Line("gamma-partial".into()))
        );
        assert_eq!(read_bounded_line(&mut reader, 1024).unwrap(), None);
    }

    #[test]
    fn stdout_pump_reader_allows_line_up_to_the_cap_and_rejects_longer() {
        let (pipe_reader, writer) = std::io::pipe().unwrap();
        let mut reader = std::io::BufReader::new(pipe_reader);
        {
            let mut writer = writer;
            writer.write_all(b"12345678\n12345678901234\n").unwrap();
        }
        assert_eq!(
            read_bounded_line(&mut reader, 8).unwrap(),
            Some(PumpedLine::Line("12345678".into()))
        );
        assert!(matches!(
            read_bounded_line(&mut reader, 8),
            Err(BoundedLineError::TooLong)
        ));
    }

    #[test]
    fn stdout_pump_reader_rejects_invalid_utf8_as_framing_error() {
        let (pipe_reader, writer) = std::io::pipe().unwrap();
        let mut reader = std::io::BufReader::new(pipe_reader);
        {
            let mut writer = writer;
            writer.write_all(&[0xff, 0xfe, b'\n']).unwrap();
        }
        assert!(matches!(
            read_bounded_line(&mut reader, 1024),
            Err(BoundedLineError::InvalidUtf8)
        ));
    }

    /// The `syncMessage.messageRequestResponse` face (contract 1.70, §4.58
    /// consume batch): a well-formed direct-thread ACCEPT mirror routes as a
    /// control receive carrying the thread ACI, and every hostile or foreign
    /// shape falls through to the plain syncMessage skip — the fail-closed
    /// discipline. The enum family (DELETE/BLOCK/…), the group thread leg,
    /// and the shape gates all ride the same normalize face.
    #[test]
    fn message_request_response_normalize_routes_and_gates_the_face() {
        const THREAD_ACI: &str = "0b7fca57-1234-4d0e-9b0f-4f6c1f8a2e10";
        // 32 raw bytes = the group master key; standard base64 (44 chars).
        const GROUP_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

        let normalize = |sync: Value| {
            normalize_receive_fields(&json!({
                "envelope": {
                    "timestamp": 1727000000000u64,
                    "syncMessage": sync,
                },
            }))
            .unwrap()
        };

        // ACCEPT on a direct thread: the authoritative stamp material.
        let direct = normalize(json!({
            "messageRequestResponse": {
                "threadAci": THREAD_ACI,
                "messageRequestResponseType": 1,
            }
        }));
        assert_eq!(direct.content_kind, "control");
        assert_eq!(direct.direction, "incoming");
        assert!(direct.source.is_none());
        match direct.control.expect("direct face") {
            ControlReceive::MessageRequestResponse {
                response_type,
                thread_aci,
                group_id,
                timestamp,
            } => {
                assert_eq!(response_type, 1);
                assert_eq!(thread_aci.as_deref(), Some(THREAD_ACI));
                assert!(group_id.is_none());
                // Pre-1.258 engine posture: no additive key rides, the mirror
                // clock stays the recorded local-clock degradation.
                assert!(timestamp.is_none());
            }
            other => panic!("unexpected control: {other:?}"),
        }

        // Contract 1.258 (§4.58 additive): the engine's sync-moment key rides
        // verbatim; a malformed value reads as absent (an additive key never
        // fails the face).
        let stamped = normalize(json!({
            "messageRequestResponse": {
                "threadAci": THREAD_ACI,
                "messageRequestResponseType": 1,
                "timestamp": 1727000000123u64,
            }
        }));
        match stamped.control.expect("stamped face") {
            ControlReceive::MessageRequestResponse {
                response_type,
                timestamp,
                ..
            } => {
                assert_eq!(response_type, 1);
                assert_eq!(timestamp, Some(1_727_000_000_123));
            }
            other => panic!("unexpected control: {other:?}"),
        }
        let malformed = normalize(json!({
            "messageRequestResponse": {
                "threadAci": THREAD_ACI,
                "messageRequestResponseType": 1,
                "timestamp": "not-a-number",
            }
        }));
        match malformed.control.expect("malformed-timestamp face") {
            ControlReceive::MessageRequestResponse { timestamp, .. } => {
                assert!(timestamp.is_none(), "malformed additive key reads absent");
            }
            other => panic!("unexpected control: {other:?}"),
        }

        // DELETE and BLOCK ride the same face with the enum's numeric value.
        for response_type in [2u8, 3] {
            let face = normalize(json!({
                "messageRequestResponse": {
                    "threadAci": THREAD_ACI,
                    "messageRequestResponseType": response_type,
                }
            }));
            assert_eq!(face.content_kind, "control");
            assert!(
                matches!(
                    face.control,
                    Some(ControlReceive::MessageRequestResponse {
                        response_type: got,
                        ..
                    }) if got == response_type
                ),
                "member {response_type} must keep its numeric value"
            );
        }

        // The group thread leg: the 32-byte standard-base64 group id, no ACI.
        let group = normalize(json!({
            "messageRequestResponse": {
                "groupId": GROUP_B64,
                "messageRequestResponseType": 1,
            }
        }));
        match group.control.expect("group face") {
            ControlReceive::MessageRequestResponse {
                thread_aci,
                group_id,
                ..
            } => {
                assert!(thread_aci.is_none());
                assert_eq!(group_id.as_deref(), Some(GROUP_B64));
            }
            other => panic!("unexpected control: {other:?}"),
        }

        // Upper-case hex UUID is the same ServiceId shape.
        let upper = normalize(json!({
            "messageRequestResponse": {
                "threadAci": THREAD_ACI.to_uppercase(),
                "messageRequestResponseType": 1,
            }
        }));
        assert!(matches!(
            upper.control,
            Some(ControlReceive::MessageRequestResponse { .. })
        ));

        // The gates, every one falling through to the plain skip arm:
        // UNKNOWN (0) and past-enum values, a bad UUID, a wrong-byte-length
        // group id, non-base64 group material, neither thread leg, and both
        // legs at once.
        for (why, sync) in [
            (
                "UNKNOWN (0) carries no actionable state",
                json!({
                    "messageRequestResponse": {
                        "threadAci": THREAD_ACI,
                        "messageRequestResponseType": 0,
                    }
                }),
            ),
            (
                "past-enum value",
                json!({
                    "messageRequestResponse": {
                        "threadAci": THREAD_ACI,
                        "messageRequestResponseType": 7,
                    }
                }),
            ),
            (
                "bad UUID shape",
                json!({
                    "messageRequestResponse": {
                        "threadAci": "not-a-service-id",
                        "messageRequestResponseType": 1,
                    }
                }),
            ),
            (
                "wrong decoded group length",
                json!({
                    "messageRequestResponse": {
                        "groupId": "ZmFrZS1ncm91cC0x",
                        "messageRequestResponseType": 1,
                    }
                }),
            ),
            (
                "non-base64 group material",
                json!({
                    "messageRequestResponse": {
                        "groupId": "not base64!!",
                        "messageRequestResponseType": 1,
                    }
                }),
            ),
            (
                "neither thread leg",
                json!({
                    "messageRequestResponse": {
                        "messageRequestResponseType": 1,
                    }
                }),
            ),
            (
                "both thread legs",
                json!({
                    "messageRequestResponse": {
                        "threadAci": THREAD_ACI,
                        "groupId": GROUP_B64,
                        "messageRequestResponseType": 1,
                    }
                }),
            ),
        ] {
            let face = normalize(sync);
            assert_eq!(face.content_kind, "syncMessage", "{why}");
            assert_eq!(face.direction, "skip", "{why}");
            assert!(face.control.is_none(), "{why}");
        }
    }
}
