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
    /// when a broadcast frame was missed; the caller advances its own cursor
    /// only after applying the returned rows.
    #[allow(dead_code)] // consumed by D's host replay in the next slice
    pub(crate) fn replay(
        &self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<crate::store::EventLogRow>, StoreError> {
        self.store.list_events_since(after_seq, limit)
    }

    /// Append the event row and then broadcast it. Returns the assigned seq.
    /// This is not a substitute for product-write atomicity: the caller that
    /// needs atomicity must wrap its product write and append_event_log_on in
    /// Store::write_transaction.
    pub(crate) fn publish(
        &self,
        epoch: u64,
        account_id: Option<&str>,
        event_type: &str,
        payload: &str,
        event: HostSideEvent,
    ) -> Result<i64, StoreError> {
        let seq = self.store.write_transaction(|tx| {
            append_event_log_on(tx, epoch, account_id, event_type, payload)
        })?;
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
                "{\"state\":\"recovered\"}",
                HostSideEvent::StorageChanged { state: "recovered" },
            )
            .unwrap();
        assert_eq!(seq, 1);
        assert!(matches!(
            rx.try_recv().unwrap(),
            HostSideEvent::StorageChanged { state: "recovered" }
        ));
        let rows = publisher.replay(0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 1);
        assert!(publisher.replay(1, 10).unwrap().is_empty());
    }
}
