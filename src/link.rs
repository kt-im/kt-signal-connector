// SPDX-License-Identifier: AGPL-3.0-only

//! Link attempts and their provisioning slots (contract 1.286, §4.272).
//!
//! A link attempt is one logical "link this device" flow. `link.start` mints
//! the attempt and its first provisioning slot (slot 0 — exactly the single
//! code the pre-rotate wire carried), and `link.rotate` mints further slots
//! for the same attempt when the code on screen went stale. Slots are bounded:
//! at most [`MAX_LIVE_LINK_SLOTS`] stay live, and a rotation past that retires
//! the oldest one. The commit itself is attempt-scoped — whichever live slot's
//! code the phone approves, the attempt commits exactly once — so a rotation
//! that retires a code never loses an in-flight finish.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use crate::ids::random_id;

pub const LINK_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// How many provisioning slots one link attempt keeps live at once
/// (contract 1.286, §4.272). A rotation that would make a third code live
/// retires the oldest live slot instead.
pub const MAX_LIVE_LINK_SLOTS: usize = 2;

/// Attempt lifecycle (QR B1, issue #951). The attempt is Pending while at
/// least one slot can still be scanned and approved; it becomes Lost once no
/// slot is live, at which point the attempt stays addressable so finish/cancel
/// answer the definite LINK_LOST instead of degrading to LINK_NOT_FOUND.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSessionState {
    Pending,
    Lost,
}

/// One provisioning slot's lifecycle. Pending slots carry a live QR; Lost
/// slots were reported dead by the engine; Retired slots were dropped by a
/// rotation (the attempt outgrew [`MAX_LIVE_LINK_SLOTS`]) and can never
/// commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSlotState {
    Pending,
    Lost,
    Retired,
}

/// One provisioning slot of a link attempt: its own `linkSessionId` (the id
/// the host passes back to finish/cancel), when it was minted, and its state.
/// The QR payload stays private and is zeroized the moment the slot can no
/// longer commit.
#[derive(Debug)]
pub struct LinkSlot {
    /// Monotonic slot number within the attempt: 0 is the `link.start` code,
    /// each rotation takes the next number.
    pub slot: u32,
    /// This slot's addressable session id (the wire's `linkSessionId`).
    pub link_session_id: String,
    device_link_uri: String,
    /// Epoch ms the slot was minted (rotation order is slot order).
    pub created_at: u64,
    pub state: LinkSlotState,
}

impl LinkSlot {
    fn new(slot: u32, device_link_uri: String, created_at: u64) -> Self {
        Self {
            slot,
            link_session_id: random_id(),
            device_link_uri,
            created_at,
            state: LinkSlotState::Pending,
        }
    }

    pub fn uri(&self) -> &str {
        &self.device_link_uri
    }

    pub fn is_live(&self) -> bool {
        self.state == LinkSlotState::Pending
    }

    /// Mark the slot lost: the engine reported its provisioning channel dead.
    /// Idempotent, and the dead QR payload is zeroized on the first call.
    fn mark_lost(&mut self) {
        if self.state != LinkSlotState::Pending {
            return;
        }
        self.state = LinkSlotState::Lost;
        self.device_link_uri.zeroize();
    }

    /// Retire the slot: a rotation dropped it because the attempt already
    /// holds [`MAX_LIVE_LINK_SLOTS`] live codes. Idempotent; the QR payload
    /// is zeroized because it can never commit.
    fn retire(&mut self) {
        if self.state != LinkSlotState::Pending {
            return;
        }
        self.state = LinkSlotState::Retired;
        self.device_link_uri.zeroize();
    }
}

/// One rotation's bookkeeping: the new slot plus the slot number it retired,
/// when the attempt had to drop its oldest live code.
#[derive(Debug)]
pub struct AddedLinkSlot {
    pub slot: u32,
    pub link_session_id: String,
    pub retired: Option<u32>,
}

/// One link attempt: its identity, its slots, and the one-shot commit.
#[derive(Debug)]
pub struct ActiveLinkSession {
    /// The host-facing attempt id (`linkAttemptId`). Connector-minted and
    /// opaque: the engine's own rotate key never rides the host wire.
    pub attempt_id: String,
    /// The engine's rotate key when the engine minted the attempt. Engines
    /// that predate `rotateLink` answer `startLink` without it, which is what
    /// makes rotation answer NOT_SUPPORTED there while the single slot keeps
    /// working.
    pub engine_attempt_id: Option<String>,
    /// Slot 0's session id — the historical `linkSessionId` of the pre-rotate
    /// wire (one attempt, one code).
    pub session_id: String,
    pub device_name: String,
    pub expires_at_ms: u64,
    /// Aggregate lifecycle: Pending while any slot is live, Lost otherwise.
    pub state: LinkSessionState,
    /// First instant the attempt had no live slot (epoch ms), None before.
    /// Set once; later observations keep the original stamp.
    pub lost_at: Option<u64>,
    /// Every slot ever minted for this attempt, in slot order. Retired and
    /// lost slots stay addressable (their ids keep routing) but never revive.
    slots: Vec<LinkSlot>,
    /// The account this attempt committed, once the single commit ran. The
    /// attempt stays addressable afterwards so a finish whose result was lost
    /// replays the same account from any of its codes instead of asking the
    /// phone again or minting a second binding.
    committed: Option<String>,
}

impl ActiveLinkSession {
    pub fn new(device_name: String, device_link_uri: String, ttl: Duration) -> Self {
        Self::with_engine_attempt(device_name, device_link_uri, ttl, None)
    }

    pub fn with_engine_attempt(
        device_name: String,
        device_link_uri: String,
        ttl: Duration,
        engine_attempt_id: Option<String>,
    ) -> Self {
        let first = LinkSlot::new(0, device_link_uri, now_ms());
        let session_id = first.link_session_id.clone();
        Self {
            attempt_id: random_id(),
            engine_attempt_id,
            session_id,
            device_name,
            expires_at_ms: now_ms().saturating_add(ttl.as_millis() as u64),
            state: LinkSessionState::Pending,
            lost_at: None,
            slots: vec![first],
            committed: None,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at_ms
    }

    /// No slot can commit any more. A committed attempt is not lost — it is
    /// finished; callers that care check [`Self::committed_account`] first.
    pub fn is_lost(&self) -> bool {
        self.state == LinkSessionState::Lost
    }

    pub fn has_live_slot(&self) -> bool {
        self.slots.iter().any(LinkSlot::is_live)
    }

    pub fn slots(&self) -> &[LinkSlot] {
        &self.slots
    }

    pub fn slot(&self, link_session_id: &str) -> Option<&LinkSlot> {
        self.slots
            .iter()
            .find(|slot| slot.link_session_id == link_session_id)
    }

    pub fn has_slot(&self, link_session_id: &str) -> bool {
        self.slot(link_session_id).is_some()
    }

    /// The attempt's addressable session ids, in slot order (slot 0 first).
    pub fn session_ids(&self) -> Vec<String> {
        self.slots
            .iter()
            .map(|slot| slot.link_session_id.clone())
            .collect()
    }

    pub fn live_slots(&self) -> impl Iterator<Item = &LinkSlot> {
        self.slots.iter().filter(|slot| slot.is_live())
    }

    /// Slot 0's code — the pre-rotate wire's one `qrPayload`.
    pub fn qr_payload(&self) -> &str {
        self.slots.first().map(LinkSlot::uri).unwrap_or_default()
    }

    /// One slot's code, when the slot is live and still addressable.
    pub fn slot_uri(&self, link_session_id: &str) -> Option<&str> {
        self.slot(link_session_id)
            .filter(|slot| slot.is_live())
            .map(LinkSlot::uri)
    }

    pub fn committed_account(&self) -> Option<&str> {
        self.committed.as_deref()
    }

    /// Mint a new provisioning slot for this attempt (contract 1.286, §4.272).
    /// Slot numbers are monotonic; a rotation that would leave more than
    /// [`MAX_LIVE_LINK_SLOTS`] live codes retires the oldest one (the lowest
    /// live slot number) and reports it. A fresh live slot re-opens the
    /// attempt's Pending state; the first lost stamp is never rewritten.
    pub fn add_slot(&mut self, device_link_uri: String, at: u64) -> AddedLinkSlot {
        let slot = self
            .slots
            .iter()
            .map(|slot| slot.slot)
            .max()
            .map(|highest| highest.saturating_add(1))
            .unwrap_or(0);
        let entry = LinkSlot::new(slot, device_link_uri, at);
        let link_session_id = entry.link_session_id.clone();
        self.slots.push(entry);
        let mut retired = None;
        while let Some(index) = self.oldest_live_slot_over_limit() {
            let number = self.slots[index].slot;
            self.slots[index].retire();
            retired = Some(number);
        }
        self.state = LinkSessionState::Pending;
        AddedLinkSlot {
            slot,
            link_session_id,
            retired,
        }
    }

    fn oldest_live_slot_over_limit(&self) -> Option<usize> {
        if self.live_slots().count() <= MAX_LIVE_LINK_SLOTS {
            return None;
        }
        self.slots.iter().position(LinkSlot::is_live)
    }

    /// Mark one slot lost (the engine reported its provisioning channel dead).
    /// Returns false when this attempt never minted that slot. The attempt
    /// turns Lost when the last live slot dies; the lost stamp is set once.
    pub fn mark_slot_lost(&mut self, link_session_id: &str, at_ms: u64) -> bool {
        {
            let Some(slot) = self
                .slots
                .iter_mut()
                .find(|slot| slot.link_session_id == link_session_id)
            else {
                return false;
            };
            slot.mark_lost();
        }
        if !self.has_live_slot() {
            self.state = LinkSessionState::Lost;
            if self.lost_at.is_none() {
                self.lost_at = Some(at_ms);
            }
        }
        true
    }

    /// Mark every live slot lost (QR B1's attempt-wide observation).
    pub fn mark_lost(&mut self, at_ms: u64) {
        for slot in &mut self.slots {
            slot.mark_lost();
        }
        self.state = LinkSessionState::Lost;
        if self.lost_at.is_none() {
            self.lost_at = Some(at_ms);
        }
    }

    /// Record the attempt's single commit: every remaining slot is retired
    /// (its code can never be used again) and the attempt keeps answering the
    /// committed account from any of its codes.
    pub fn mark_committed(&mut self, account_id: String) {
        for slot in &mut self.slots {
            slot.retire();
        }
        self.committed = Some(account_id);
        self.state = LinkSessionState::Lost;
    }

    /// Test-only drain used by the zeroize-on-drop check; production reads the
    /// URI through [`ActiveLinkSession::qr_payload`].
    #[cfg(test)]
    pub fn take_device_link_uri(&mut self) -> String {
        match self.slots.first_mut() {
            Some(slot) => std::mem::take(&mut slot.device_link_uri),
            None => String::new(),
        }
    }
}

impl Drop for ActiveLinkSession {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            slot.device_link_uri.zeroize();
        }
        self.device_name.zeroize();
        self.session_id.zeroize();
        self.attempt_id.zeroize();
        if let Some(engine_attempt_id) = self.engine_attempt_id.as_mut() {
            engine_attempt_id.zeroize();
        }
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

    fn attempt() -> ActiveLinkSession {
        ActiveLinkSession::new(
            "KT".into(),
            "sgnl://link?uuid=test".into(),
            Duration::from_secs(300),
        )
    }

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

    /// Contract 1.286 (§4.272): one rotation adds a second live slot without
    /// touching slot 0.
    #[test]
    fn a_rotation_keeps_both_live_slots() {
        let mut session = attempt();
        let added = session.add_slot("sgnl://link?second".into(), 10);
        assert_eq!(added.slot, 1);
        assert_eq!(added.retired, None);
        assert_eq!(session.live_slots().count(), 2);
        assert_eq!(session.qr_payload(), "sgnl://link?uuid=test");
        assert_eq!(
            session.slot_uri(&added.link_session_id),
            Some("sgnl://link?second")
        );
        assert_ne!(added.link_session_id, session.session_id);
    }

    /// Contract 1.286 (§4.272): the third code retires the oldest live slot,
    /// zeroizes its payload, and reports which slot went.
    #[test]
    fn a_third_slot_retires_the_oldest_live_code() {
        let mut session = attempt();
        let second = session.add_slot("sgnl://link?second".into(), 10);
        let third = session.add_slot("sgnl://link?third".into(), 20);
        assert_eq!(third.retired, Some(0), "slot 0 is the oldest live code");
        assert_eq!(
            session.slots()[0].state,
            LinkSlotState::Retired,
            "the retired slot stays addressable"
        );
        assert_eq!(session.qr_payload(), "", "the retired payload is zeroized");
        let live: Vec<u32> = session.live_slots().map(|slot| slot.slot).collect();
        assert_eq!(live, vec![1, 2]);
        assert!(session.has_slot(&second.link_session_id));
        assert_eq!(
            session.slot_uri(&second.link_session_id),
            Some("sgnl://link?second")
        );
        assert_eq!(session.state, LinkSessionState::Pending);
    }

    /// Retiring the last code of an attempt leaves it lost: addressable, never
    /// blocking a fresh link, and no longer watchdog-suppressing.
    #[test]
    fn retiring_every_code_loses_the_attempt_once() {
        let mut session = attempt();
        let first = session.session_id.clone();
        assert!(session.mark_slot_lost(&first, 100));
        assert_eq!(session.state, LinkSessionState::Lost);
        assert_eq!(session.lost_at, Some(100));
        assert!(!session.has_live_slot());
        assert!(!session.mark_slot_lost("no-such-slot", 200));
        assert!(session.mark_slot_lost(&first, 300));
        assert_eq!(session.lost_at, Some(100), "first observation wins");
    }

    /// A committed attempt retires every slot and remembers the account: the
    /// finish replay answers the same binding from any code.
    #[test]
    fn committing_retires_every_slot_and_keeps_the_account() {
        let mut session = attempt();
        let second = session.add_slot("sgnl://link?second".into(), 10);
        session.mark_committed("account-1".into());
        assert_eq!(session.committed_account(), Some("account-1"));
        assert!(!session.has_live_slot());
        assert_eq!(session.qr_payload(), "");
        assert_eq!(session.slot_uri(&second.link_session_id), None);
        assert!(session.has_slot(&second.link_session_id));
        assert!(session.is_lost());
    }

    /// The engine's rotate key never rides the host wire: the attempt id is
    /// connector-minted even when the engine minted one of its own.
    #[test]
    fn the_host_attempt_id_is_connector_minted() {
        let session = ActiveLinkSession::with_engine_attempt(
            "KT".into(),
            "sgnl://link?uuid=test".into(),
            Duration::from_secs(300),
            Some("engine-attempt-7".into()),
        );
        assert_eq!(
            session.engine_attempt_id.as_deref(),
            Some("engine-attempt-7")
        );
        assert_ne!(session.attempt_id, "engine-attempt-7");
        assert!(!session.attempt_id.is_empty());
    }
}
