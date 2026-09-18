use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use net_lattice_core::{Error, Result};

/// Default number of ordinary events buffered for one synchronous watcher.
pub const DEFAULT_EVENT_QUEUE_CAPACITY: usize = 256;

/// Non-blocking backend producer for a bounded event receiver.
#[derive(Clone)]
pub struct EventSender<E> {
    sender: mpsc::SyncSender<Result<E>>,
    pending_resync: Arc<Mutex<Option<E>>>,
}

impl<E> EventSender<E> {
    /// Never blocks a native callback. On overflow, records one resync event
    /// that is delivered before a later ordinary event.
    pub fn send(&self, event: E, resync: E) -> bool {
        let mut pending = self.pending_resync.lock().expect("event sender poisoned");
        if let Some(resync) = pending.take() {
            match self.sender.try_send(Ok(resync)) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(event)) => {
                    let _ = event.ok().map(|event| *pending = Some(event));
                    return true;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
        match self.sender.try_send(Ok(event)) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                *pending = Some(resync);
                true
            }
            Err(mpsc::TrySendError::Disconnected(_)) => false,
        }
    }
    /// Delivers a terminal error to the receiver, returning `false` if it has
    /// already disconnected.
    pub fn send_error(&self, error: Error) -> bool {
        self.sender.send(Err(error)).is_ok()
    }
}

/// A bounded synchronous receiver of network change events.
///
/// Receivers are normally created through the facade's `Lattice::watch` or
/// `Lattice::watch_filtered` methods.
///
/// [`Self::recv`] blocks, while [`Self::try_recv`] and
/// [`Self::recv_timeout`] do not wait indefinitely. Dropping the receiver
/// also drops any backend-owned subscription guard, allowing its native
/// watcher to stop. If its producer shuts down, receive methods return
/// [`Error::Disconnected`]. When a slow consumer fills the bounded queue,
/// multiple dropped events are coalesced into one resynchronization event
/// delivered before a later ordinary event.
///
/// The receiver preserves the order in which its backend producer enqueues
/// events, but makes no cross-domain ordering, causality, initial-snapshot,
/// or self-mutation-delivery guarantee. Re-read state after any event when a
/// coherent snapshot is required.
///
/// `EventReceiver<E>` is `Send` when `E` is `Send`; it is not cloneable, so a
/// watcher has one consuming receiver. It is not guaranteed to be [`Sync`].
///
/// Also implements [`Iterator`], yielding the same [`Result`] values as
/// [`Self::recv`]. Iteration ends only after the watcher disconnects.
pub struct EventReceiver<E> {
    receiver: mpsc::Receiver<Result<E>>,
    // Owns backend-specific cancellation state (for example, a Windows IP
    // Helper registration or a route-socket reader). It is intentionally
    // opaque: consumers only receive events, while dropping the receiver
    // reliably tears down the native subscription.
    _subscription: Option<Box<dyn Send>>,
}

impl<E> EventReceiver<E> {
    /// Creates a bounded event channel using the default capacity.
    ///
    /// This constructor is intended for backend implementations. Applications
    /// normally obtain an `EventReceiver` through `Lattice::watch` or
    /// `Lattice::watch_filtered`. The returned sender applies Net Lattice's
    /// bounded-delivery and overflow semantics.
    pub fn bounded() -> (EventSender<E>, Self) {
        Self::bounded_with_capacity(DEFAULT_EVENT_QUEUE_CAPACITY)
    }

    /// Creates a bounded event channel with the requested capacity.
    ///
    /// This constructor is intended for backend implementations. Applications
    /// normally obtain an `EventReceiver` through `Lattice::watch` or
    /// `Lattice::watch_filtered`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn bounded_with_capacity(capacity: usize) -> (EventSender<E>, Self) {
        assert!(capacity > 0, "event queue capacity must be non-zero");
        let (sender, receiver) = mpsc::sync_channel(capacity);
        (
            EventSender {
                sender,
                pending_resync: Arc::new(Mutex::new(None)),
            },
            Self {
                receiver,
                _subscription: None,
            },
        )
    }
    /// Wraps a channel receiver that a backend watcher thread or task sends
    /// events into.
    ///
    /// This constructor is intended for backend implementations. Applications
    /// normally obtain an `EventReceiver` through `Lattice::watch` or
    /// `Lattice::watch_filtered`.
    pub fn from_channel_receiver(receiver: mpsc::Receiver<Result<E>>) -> Self {
        Self {
            receiver,
            _subscription: None,
        }
    }

    /// Wraps a channel receiver and attaches a backend-owned subscription
    /// guard.
    ///
    /// The guard is retained for the lifetime of the returned receiver.
    /// Dropping the receiver drops the guard, allowing the associated native
    /// subscription to stop.
    ///
    /// This constructor is intended for backend implementations. Applications
    /// normally obtain an `EventReceiver` through `Lattice::watch` or
    /// `Lattice::watch_filtered`.
    pub fn from_receiver_with_subscription<S>(
        receiver: mpsc::Receiver<Result<E>>,
        subscription: S,
    ) -> Self
    where
        S: Send + 'static,
    {
        Self {
            receiver,
            _subscription: Some(Box::new(subscription)),
        }
    }

    /// Attaches a backend-owned subscription guard to this receiver.
    ///
    /// The guard is retained for the lifetime of the receiver and dropped
    /// when the receiver is dropped. If a guard is already attached, it is
    /// dropped and replaced by the new guard.
    ///
    /// This method is intended for backend implementations.
    pub fn with_subscription<S>(mut self, subscription: S) -> Self
    where
        S: Send + 'static,
    {
        self._subscription = Some(Box::new(subscription));
        self
    }

    /// Blocks until the next event is available.
    ///
    /// A temporarily empty queue does not cause this method to return. The
    /// receiver retains any attached subscription guard throughout the wait.
    /// Returns [`Error::Disconnected`] after the backend watcher has stopped
    /// and no further events can arrive. Other producer errors are propagated
    /// unchanged.
    pub fn recv(&self) -> Result<E> {
        match self.receiver.recv() {
            Ok(Ok(event)) => Ok(event),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(Error::Disconnected),
        }
    }

    /// Attempts to receive an event without blocking.
    ///
    /// Returns `Ok(Some(event))` when an event is already queued, `Ok(None)`
    /// when no event is currently available, or [`Error::Disconnected`] when
    /// the watcher has stopped and no further events can arrive. A temporarily
    /// empty queue is not an error. Other producer errors are propagated
    /// unchanged.
    pub fn try_recv(&self) -> Result<Option<E>> {
        match self.receiver.try_recv() {
            Ok(Ok(event)) => Ok(Some(event)),
            Ok(Err(error)) => Err(error),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(Error::Disconnected),
        }
    }

    /// Waits for an event for at most `timeout`.
    ///
    /// Returns `Ok(Some(event))` when an event arrives before the timeout,
    /// `Ok(None)` when the timeout expires, or [`Error::Disconnected`] when
    /// the watcher has stopped and no further events can arrive. A timeout is
    /// not an error. Other producer errors are propagated unchanged.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<E>> {
        match self.receiver.recv_timeout(timeout) {
            Ok(Ok(event)) => Ok(Some(event)),
            Ok(Err(error)) => Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(Error::Disconnected),
        }
    }
}

/// Iterates over events until the backend watcher disconnects.
///
/// Calling [`Iterator::next`] blocks in the same way as [`Self::recv`].
/// Receiver errors are yielded to the caller as `Err` values.
impl<E> Iterator for EventReceiver<E> {
    type Item = Result<E>;

    fn next(&mut self) -> Option<Result<E>> {
        match self.recv() {
            Ok(event) => Some(Ok(event)),
            Err(Error::Disconnected) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Subscribes to filtered change notifications for the domains and objects a
/// backend supports.
///
/// Generic over an associated `Event` type rather than naming
/// `net_lattice_model::event::Event` directly — `net-lattice-platform` does
/// not depend on `net-lattice-model` (see ARCHITECTURE.md). The facade
/// crate (`net-lattice`) is what constrains `Event` to the concrete model
/// type.
///
/// Unlike the other provider traits, this one is inherently push-based:
/// `watch` starts a backend-owned background watcher (a Netlink multicast
/// subscription, a BSD routing-socket reader, a Windows
/// `NotifyRouteChange2`-style callback, ...) and returns an
/// [`EventReceiver`] fed by it. The watcher runs for as long as the
/// returned `EventReceiver` (and whatever the backend keeps alive to feed
/// it) is alive.
///
/// A backend must reject a filter that selects a domain it cannot deliver;
/// returning a watcher that silently omits selected events violates the
/// monitoring capability contract. The facade maps its concrete event-domain
/// filter to the matching runtime capability before calling this trait.
pub trait EventProvider {
    /// The backend's observed change-event type.
    type Event;
    /// The backend's event-domain/object filter type.
    type EventFilter;

    /// Starts watching every modeled event domain, returning a receiver fed
    /// as native changes occur.
    fn watch(&self) -> Result<EventReceiver<Self::Event>>;
    /// Starts watching only the domains/objects selected by `filter`,
    /// returning a receiver fed as matching native changes occur.
    fn watch_filtered(&self, filter: Self::EventFilter) -> Result<EventReceiver<Self::Event>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    struct DropGuard(Arc<AtomicUsize>);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn recv_returns_disconnected_once_the_sender_is_dropped() {
        let (sender, receiver) = EventReceiver::<u32>::bounded();
        drop(sender);
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn recv_reports_disconnect_after_the_sender_is_dropped() {
        let (sender, receiver) = EventReceiver::<u32>::bounded();
        drop(sender);
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn pending_resync_preserves_a_queued_producer_error() {
        let (sender, receiver) = EventReceiver::bounded_with_capacity(1);
        assert!(sender.send(1, 99));
        assert!(sender.send(2, 99));
        assert_eq!(receiver.recv().unwrap(), 1);
        assert!(sender.send_error(Error::InvalidState));
        assert!(sender.send(3, 99));
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn try_recv_returns_none_when_empty_but_still_connected() {
        let (_sender, receiver) = EventReceiver::<u32>::bounded();
        assert!(receiver.try_recv().unwrap().is_none());
    }

    #[test]
    fn iterator_ends_when_the_sender_is_dropped() {
        let (sender, receiver) = EventReceiver::<u32>::bounded();
        thread::spawn(move || {
            assert!(sender.send(1, 0));
            assert!(sender.send(2, 0));
        });
        let received: Vec<Result<u32>> = receiver.collect();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].as_ref().unwrap(), &1);
        assert_eq!(received[1].as_ref().unwrap(), &2);
    }

    #[test]
    fn iterator_yields_a_producer_error() {
        let (sender, mut receiver) = EventReceiver::<u32>::bounded();
        assert!(sender.send_error(Error::InvalidState));
        assert!(receiver.next().unwrap().is_err());
    }

    #[test]
    fn dropping_receiver_drops_subscription_guard() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (_sender, receiver) = EventReceiver::<u32>::bounded();
        drop(receiver.with_subscription(DropGuard(Arc::clone(&drops))));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn replacing_subscription_drops_the_previous_guard() {
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let (_sender, receiver) = EventReceiver::<u32>::bounded();
        let receiver = receiver.with_subscription(DropGuard(Arc::clone(&first)));
        let receiver = receiver.with_subscription(DropGuard(Arc::clone(&second)));
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 0);
        drop(receiver);
        assert_eq!(second.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[should_panic(expected = "event queue capacity must be non-zero")]
    fn zero_capacity_is_rejected() {
        let _ = EventReceiver::<u32>::bounded_with_capacity(0);
    }

    #[test]
    fn recv_timeout_returns_none_on_timeout_without_disconnecting() {
        let (sender, receiver) = EventReceiver::<u32>::bounded();
        assert!(
            receiver
                .recv_timeout(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        assert!(sender.send(7, 0));
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Some(7)
        );
    }

    #[test]
    fn overflow_delivers_resync_before_a_later_event() {
        let (sender, receiver) = EventReceiver::bounded_with_capacity(1);
        assert!(sender.send(1, 99));
        assert!(sender.send(2, 99));
        assert_eq!(receiver.recv().unwrap(), 1);
        assert!(sender.send(3, 99));
        assert_eq!(receiver.recv().unwrap(), 99);
    }

    #[test]
    fn background_error_is_returned() {
        let (sender, receiver) = EventReceiver::<u32>::bounded();
        assert!(sender.send_error(Error::InvalidState));
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn backend_channel_constructors_preserve_events_and_guards() {
        let (sender, raw_receiver) = mpsc::channel();
        assert!(sender.send(Ok(7_u32)).is_ok());
        let receiver = EventReceiver::from_channel_receiver(raw_receiver);
        assert_eq!(receiver.recv().unwrap(), 7);

        let drops = Arc::new(AtomicUsize::new(0));
        let (_sender, raw_receiver) = mpsc::channel::<Result<u32>>();
        drop(EventReceiver::from_receiver_with_subscription(
            raw_receiver,
            DropGuard(Arc::clone(&drops)),
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sender_reports_disconnected_consumer() {
        let (sender, receiver) = EventReceiver::<u32>::bounded_with_capacity(1);
        drop(receiver);
        assert!(!sender.send(1, 0));
        assert!(!sender.send_error(Error::InvalidState));
    }

    #[test]
    fn sender_reports_disconnected_string_consumer() {
        let (sender, receiver) = EventReceiver::<String>::bounded_with_capacity(1);
        drop(receiver);
        assert!(!sender.send("event".to_owned(), "resync".to_owned()));
    }

    #[test]
    fn string_sender_covers_pending_and_error_paths() {
        let (sender, receiver) = EventReceiver::<String>::bounded_with_capacity(1);
        assert!(sender.send("first".into(), "resync".into()));
        assert!(sender.send("second".into(), "resync".into()));
        assert!(sender.send("third".into(), "resync".into()));
        assert_eq!(receiver.recv().unwrap(), "first");
        assert!(sender.send("fourth".into(), "resync".into()));
        assert_eq!(receiver.recv().unwrap(), "resync");
        assert!(sender.send_error(Error::InvalidState));
        assert!(receiver.recv().is_err());

        let (sender, receiver) = EventReceiver::<String>::bounded();
        drop(sender);
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn default_integer_sender_covers_pending_full_and_disconnect() {
        let (sender, receiver) = EventReceiver::bounded_with_capacity(1);
        assert!(sender.send(1, 99));
        assert!(sender.send(2, 99));
        assert!(sender.send(3, 99));
        drop(receiver);
        assert!(!sender.send(4, 99));

        let (sender, receiver) = EventReceiver::<i32>::bounded();
        drop(sender);
        assert!(receiver.recv().is_err());
    }

    fn exercise_sender_paths<E: Clone>(event: E, resync: E) {
        let (sender, receiver) = EventReceiver::bounded_with_capacity(1);
        assert!(sender.send(event.clone(), resync.clone()));
        assert!(sender.send(event.clone(), resync.clone()));
        assert!(sender.send(event.clone(), resync.clone()));
        assert!(receiver.recv().is_ok());
        assert!(sender.send(event.clone(), resync.clone()));
        assert!(receiver.recv().is_ok());
        drop(receiver);
        assert!(!sender.send(event, resync));
    }

    #[test]
    fn sender_paths_cover_common_generic_instantiations() {
        exercise_sender_paths::<u8>(1, 9);
        exercise_sender_paths::<u16>(1, 9);
        exercise_sender_paths::<u32>(1, 9);
        exercise_sender_paths::<u64>(1, 9);
        exercise_sender_paths::<i32>(1, 9);
        exercise_sender_paths::<usize>(1, 9);
        exercise_sender_paths::<()>((), ());
    }

    #[test]
    fn receive_methods_propagate_queued_errors_and_disconnects() {
        let (sender, receiver) = EventReceiver::<u32>::bounded();
        assert!(sender.send_error(Error::InvalidState));
        assert!(receiver.try_recv().is_err());
        drop(sender);
        assert!(receiver.try_recv().is_err());

        let (sender, receiver) = EventReceiver::<u32>::bounded();
        assert!(sender.send_error(Error::InvalidState));
        assert!(receiver.recv_timeout(Duration::from_secs(1)).is_err());
        drop(sender);
        assert!(receiver.recv_timeout(Duration::ZERO).is_err());
    }

    #[test]
    fn pending_resync_handles_full_and_disconnected_channels() {
        let (sender, receiver) = EventReceiver::bounded_with_capacity(1);
        assert!(sender.send(1, 99));
        assert!(sender.send(2, 99));
        assert!(sender.send(3, 99));
        drop(receiver);
        assert!(!sender.send(4, 99));
    }

    #[test]
    fn try_recv_returns_an_already_queued_event() {
        let (sender, receiver) = EventReceiver::bounded();
        assert!(sender.send(7_u32, 0));
        assert_eq!(receiver.try_recv().unwrap(), Some(7));
    }

    #[test]
    #[should_panic(expected = "event sender poisoned")]
    fn poisoned_event_sender_mutex_is_reported() {
        let (sender, _receiver) = EventReceiver::<u32>::bounded();
        let pending = Arc::clone(&sender.pending_resync);
        let _ = std::thread::spawn(move || {
            let _guard = pending.lock().unwrap();
            panic!("poison event sender");
        })
        .join();
        let _ = sender.send(1, 0);
    }
}
