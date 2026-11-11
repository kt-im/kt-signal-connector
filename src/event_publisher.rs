//! Signal Core B: single durable event publication point.
//!
//! Product writes and their event_log row must share one SQLite transaction;
//! callers use Store::write_transaction + append_event_log_on for that. This
//! publisher is the post-commit broadcast face: it appends the event first,
//! then broadcasts the already-committed HostSideEvent. A failed append must
//! never broadcast.

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::service::HostSideEvent;
use crate::store::{Store, StoreError, append_event_log_on};

#[derive(Clone)]
pub(crate) struct EventPublisher {
    store: Arc<Store>,
    events: broadcast::Sender<HostSideEvent>,
}

impl EventPublisher {
    pub(crate) fn new(store: Arc<Store>, events: broadcast::Sender<HostSideEvent>) -> Self {
        Self { store, events }
    }

    /// Read committed events after a cursor. Main/renderer replay uses this
    /// Append the event row and then broadcast it. Returns the assigned seq.
    /// This is not a substitute for product-write atomicity: the caller that
    /// needs atomicity must wrap its product write and append_event_log_on in
    /// Store::write_transaction.
    ///
    /// Contract 1.283 (§4.267): the row is a thin change pointer — the ledger
    /// no longer stores a payload, so replaying it means "re-read the entity",
    /// not "reconstruct the frame from the log".
    pub(crate) fn publish(
        &self,
        epoch: u64,
        account_id: Option<&str>,
        event_type: &str,
        event: HostSideEvent,
    ) -> Result<i64, StoreError> {
        let seq = self
            .store
            .write_transaction(|tx| append_event_log_on(tx, epoch, account_id, event_type))?;
        let _ = self.events.send(event);
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreKey;

    #[test]
    fn publish_appends_before_broadcast() {
        let temp = tempfile::TempDir::new().unwrap();
        let key = StoreKey::from_bytes([0x5A; 32]);
        let store = Arc::new(Store::open(temp.path(), Some(key)).unwrap());
        let (tx, mut rx) = broadcast::channel(8);
        let publisher = EventPublisher::new(Arc::clone(&store), tx);
        let seq = publisher
            .publish(
                1,
                Some("a"),
                "storage.changed",
                HostSideEvent::StorageChanged { state: "recovered" },
            )
            .unwrap();
        assert_eq!(seq, 1);
        assert!(matches!(
            rx.try_recv().unwrap(),
            HostSideEvent::StorageChanged { state: "recovered" }
        ));
        // Contract 1.283 (§4.267): the row is a thin pointer, and it is what
        // the host's events.list replays.
        let page = store.events_page(Some(0), None, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].seq, 1);
        assert_eq!(page.events[0].event_type, "storage.changed");
        assert!(
            store
                .events_page(Some(1), None, 10)
                .unwrap()
                .events
                .is_empty()
        );
    }
}
