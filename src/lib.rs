// SPDX-License-Identifier: AGPL-3.0-only

pub mod auth;
pub mod backup_export;
pub mod datalock;
pub mod doctor;
pub mod engine;
pub(crate) mod event_publisher;
pub mod groups;
pub mod history_attachment;
pub mod history_import;
pub mod host;
pub mod ids;
pub mod ipc;
pub mod link;
pub mod lkg;
pub mod manifest;
pub mod media;
pub mod methods;
pub mod metrics;
pub mod migrate;
pub mod parent;
pub mod perf_metrics;
pub mod pool;
pub mod protocol;
pub mod registry;
pub mod resource;
pub mod service;
pub mod store;
pub mod supervisor;

pub const API_VERSION: &str = "1.0";
/// One ≤16 MiB inbound line per host connection (attachment base64 payloads,
/// implementation-plan §4.12). Matches the desktop client's connector frame
/// budget; the desktop is the only local peer on a private, handshake-
/// authenticated socket.
pub const DEFAULT_HOST_FRAME_LIMIT: usize = 160 * 1024 * 1024;
pub const DEFAULT_UPSTREAM_LINE_LIMIT: usize = 160 * 1024 * 1024;
pub const MAX_PENDING_UPSTREAM_REQUESTS: usize = 128;
/// The reserved, always-present proxy group (ADR 0001 R2). The legacy global
/// `--socks-proxy` / `KT_SIGNAL_SOCKS_PROXY` configures this group; the group
/// list must not redefine it. Accounts linked before Phase 4 read as members
/// of this group.
pub const DEFAULT_PROXY_GROUP_ID: &str = "default";

/// Advertised capability list, derived from the single method table
/// (`methods::METHOD_NAMES`) and never hand-written (optimization-plan §5.2
/// B1).
pub const PHASE2_CAPABILITIES: &[&str] = &methods::METHOD_NAMES;

/// The handshake `capabilities` payload: every dispatchable method name in
/// table order followed by the feature capability tags (contract revision
/// 1.34: `send-receipts`; contract revision 1.35: `send-sticker`; contract
/// revision 1.36: `sticker-pack-browse`, `conversation-pin-sync`; contract
/// revision 1.37: `sticker-pack-sync`; contract revision 1.38: `view-once`).
///
/// Contract revision 1.98: `attachment-download` joins the payload only when
/// `media_ingest` is armed — the effective launcher decision (passed through
/// verbatim since 1.121, §4.102) and the exact gate every media method
/// answers. A runtime without the media table omits the tag, so the desktop
/// takes the honest metadata-only path instead of calling a face that
/// answers `CAPABILITY_UNAVAILABLE` for every download; with the table
/// armed, the payload is unchanged from the pre-1.98 advertisement.
pub fn advertised_capabilities(media_ingest: bool) -> Vec<&'static str> {
    let mut capabilities = [&methods::METHOD_NAMES[..], methods::FEATURE_CAPABILITIES].concat();
    if !media_ingest {
        capabilities.retain(|capability| *capability != methods::ATTACHMENT_DOWNLOAD_CAPABILITY);
    }
    capabilities
}
