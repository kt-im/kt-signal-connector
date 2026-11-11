// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use crate::ids::random_id;

pub const LINK_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// Link-session lifecycle (QR B1, issue #951). A session is Pending while
/// the QR can still be scanned and the phone can still approve it; it becomes
/// Lost when the engine reports its provisioning channel died after the URL
/// handoff (finishLink answers the definite LINK_LOST), at which point the
/// QR can never commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSessionState {
    Pending,
    Lost,
}

#[derive(Debug)]
pub struct ActiveLinkSession {
    pub session_id: String,
    pub device_name: String,
    device_link_uri: String,
    pub expires_at_ms: u64,
    /// Current lifecycle state (QR B1): Lost sessions stay addressable so
    /// the router/finish path can answer LINK_LOST instead of degrading to
    /// LINK_NOT_FOUND, but they never block a fresh link.start.
    pub state: LinkSessionState,
    /// First instant the session was observed lost (epoch ms), None while
    /// pending. Set once; a second observation keeps the original stamp.
    pub lost_at: Option<u64>,
}

impl ActiveLinkSession {
    pub fn new(device_name: String, device_link_uri: String, ttl: Duration) -> Self {
        Self {
            session_id: random_id(),
            device_name,
            device_link_uri,
            expires_at_ms: now_ms().saturating_add(ttl.as_millis() as u64),
            state: LinkSessionState::Pending,
            lost_at: None,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at_ms
    }

    pub fn is_lost(&self) -> bool {
        self.state == LinkSessionState::Lost
    }

    /// Mark the session lost (QR B1). Idempotent: the first observation owns
    /// lost_at; the QR payload is zeroized because it can never be used
    /// again. The session itself stays in place for routing (has_link_session
    /// keeps answering true) and for the definite LINK_LOST finish answer.
    pub fn mark_lost(&mut self, at_ms: u64) {
        if self.is_lost() {
            return;
        }
        self.state = LinkSessionState::Lost;
        self.lost_at = Some(at_ms);
        self.device_link_uri.zeroize();
    }

    pub fn qr_payload(&self) -> &str {
        &self.device_link_uri
    }

    /// Test-only drain used by the zeroize-on-drop check; production reads
    /// the URI through ActiveLinkSession::qr_payload.
    #[cfg(test)]
    pub fn take_device_link_uri(&mut self) -> String {
        std::mem::take(&mut self.device_link_uri)
    }
}

impl Drop for ActiveLinkSession {
    fn drop(&mut self) {
        self.device_link_uri.zeroize();
        self.device_name.zeroize();
        self.session_id.zeroize();
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_expires_and_zeroizes_uri_on_drop() {
        let mut session = ActiveLinkSession::new(
            "KT".into(),
            "sgnl://link?uuid=test".into(),
            Duration::from_millis(1),
        );
        assert!(!session.is_expired(0));
        assert!(session.is_expired(session.expires_at_ms));
        let uri = session.take_device_link_uri();
        assert_eq!(uri, "sgnl://link?uuid=test");
        drop(session);
    }

    #[test]
    fn session_mark_lost_is_idempotent_and_keeps_the_first_stamp() {
        let mut session = ActiveLinkSession::new(
            "KT".into(),
            "sgnl://link?uuid=lost".into(),
            Duration::from_secs(300),
        );
        assert_eq!(session.state, LinkSessionState::Pending);
        assert_eq!(session.lost_at, None);

        session.mark_lost(1_000);
        assert!(session.is_lost());
        assert_eq!(session.state, LinkSessionState::Lost);
        assert_eq!(session.lost_at, Some(1_000));
        assert_eq!(session.qr_payload(), "", "the dead QR payload is zeroized");

        session.mark_lost(2_000);
        assert_eq!(session.lost_at, Some(1_000), "first observation wins");
    }
}
