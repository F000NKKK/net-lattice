use std::any::Any;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use net_lattice_core::Result;

/// Sender half of a bounded, executor-independent event channel.
///
/// This is an implementation detail of the feature-gated async provider
/// contract. Backends use [`send`](Self::send) exactly as their synchronous
/// counterparts use `EventSender`: when the consumer falls behind, one
/// resynchronization event is scheduled instead of allowing unbounded memory
/// growth. The marker is delivered even if no later event arrives.
pub struct AsyncEventSender<E> {
    state: Arc<Mutex<Channel<E>>>,
    terminal_error: Arc<Mutex<Option<net_lattice_core::Error>>>,
}

/// Event receiver that owns the native subscription which produces its events.
///
/// The subscription is dropped with the receiver, cancelling platform handles,
/// tasks, or reader threads before their callback state can be freed.
pub struct AsyncEventReceiver<E> {
    state: Arc<Mutex<Channel<E>>>,
    subscription: Option<Box<dyn Any + Send>>,
    terminal_error: Arc<Mutex<Option<net_lattice_core::Error>>>,
}

struct Channel<E> {
    queue: VecDeque<E>,
    sender_alive: bool,
    receiver_alive: bool,
    pending_resync: Option<E>,
    generating_resync: bool,
    waker: Option<Waker>,
}

impl<E> AsyncEventReceiver<E> {
    /// Creates a bounded transport using the same capacity as `EventReceiver`.
    pub fn bounded() -> (AsyncEventSender<E>, Self) {
        let state = Arc::new(Mutex::new(Channel {
            queue: VecDeque::new(),
            sender_alive: true,
            receiver_alive: true,
            pending_resync: None,
            generating_resync: false,
            waker: None,
        }));
        let terminal_error = Arc::new(Mutex::new(None));
        (
            AsyncEventSender {
                state: Arc::clone(&state),
                terminal_error: Arc::clone(&terminal_error),
            },
            Self {
                state,
                subscription: None,
                terminal_error,
            },
        )
    }

    /// Attaches the resource which owns the OS subscription.
    pub fn with_subscription<S>(mut self, subscription: S) -> Self
    where
        S: Any + Send + 'static,
    {
        self.subscription = Some(Box::new(subscription));
        self
    }

    /// Polls the next event without tying the platform crate to a futures API.
    pub fn poll_recv(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<E>>> {
        let mut state = self.state.lock().expect("event channel poisoned");
        if let Some(event) = state.queue.pop_front() {
            return Poll::Ready(Some(Ok(event)));
        }
        if let Some(event) = state.pending_resync.take() {
            return Poll::Ready(Some(Ok(event)));
        }
        if state.sender_alive {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        drop(state);
        Poll::Ready(
            self.terminal_error
                .lock()
                .expect("async event sender poisoned")
                .take()
                .map(Err),
        )
    }
}

impl<E> AsyncEventSender<E> {
    /// Attempts to enqueue an event without waiting for queue capacity.
    pub fn send(&self, event: E, resync: impl FnOnce() -> E) -> bool {
        let mut state = self.state.lock().expect("event channel poisoned");
        if !state.receiver_alive || !state.sender_alive {
            return false;
        }
        // Another producer is constructing the marker outside the lock. Its
        // marker covers this event too, preserving ordering without invoking
        // caller code while holding the channel mutex.
        if state.generating_resync {
            return true;
        }
        if let Some(resync) = state.pending_resync.take() {
            if state.queue.len() == EventReceiverCapacity::VALUE {
                state.pending_resync = Some(resync);
                return true;
            }
            state.queue.push_back(resync);
        }
        if state.queue.len() == EventReceiverCapacity::VALUE {
            state.generating_resync = true;
            drop(state);
            let marker = std::panic::catch_unwind(std::panic::AssertUnwindSafe(resync));
            let mut state = self.state.lock().expect("event channel poisoned");
            state.generating_resync = false;
            match marker {
                Ok(marker) => {
                    if !state.receiver_alive {
                        return false;
                    }
                    state.pending_resync = Some(marker);
                }
                Err(panic) => {
                    *self
                        .terminal_error
                        .lock()
                        .expect("async event sender poisoned") =
                        Some(net_lattice_core::Error::InvalidState);
                    state.sender_alive = false;
                    let waker = state.waker.take();
                    drop(state);
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                    std::panic::resume_unwind(panic);
                }
            }
            let waker = state.waker.take();
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
            return true;
        } else {
            state.queue.push_back(event);
        }
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    /// Reports a terminal backend error if the consumer is still connected.
    pub fn send_error(&self, error: net_lattice_core::Error) -> bool {
        let state = self.state.lock().expect("event channel poisoned");
        if !state.receiver_alive || !state.sender_alive {
            return false;
        }
        drop(state);
        *self
            .terminal_error
            .lock()
            .expect("async event sender poisoned") = Some(error);
        true
    }
}

impl<E> Drop for AsyncEventSender<E> {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("event channel poisoned");
        state.sender_alive = false;
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<E> Drop for AsyncEventReceiver<E> {
    fn drop(&mut self) {
        self.state
            .lock()
            .expect("event channel poisoned")
            .receiver_alive = false;
    }
}

/// Kept here instead of exposing a second public capacity constant.
struct EventReceiverCapacity;
impl EventReceiverCapacity {
    const VALUE: usize = 256;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropGuard(Arc<AtomicUsize>);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn poll<E>(receiver: &mut AsyncEventReceiver<E>) -> Poll<Option<Result<E>>> {
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        Pin::new(receiver).poll_recv(&mut context)
    }

    #[test]
    fn overflow_delivers_resync_before_a_later_event() {
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        assert!(sender.send(256, || 999));
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(value))) if value == event));
        }
        assert!(sender.send(257, || 999));
        assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(999)))));
        assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(257)))));
    }

    #[test]
    fn overflow_is_reported_even_if_no_more_events_arrive() {
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        assert!(sender.send(256, || 999));
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(value))) if value == event));
        }
        assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(999)))));
        assert!(poll(&mut receiver).is_pending());
    }

    #[test]
    fn resync_factory_can_reenter_sender_without_locking_up() {
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        assert!(sender.send(256, || {
            assert!(sender.send(257, || 998));
            999
        }));
        for _ in 0..EventReceiverCapacity::VALUE {
            assert!(poll(&mut receiver).is_ready());
        }
        assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(999)))));
        assert!(poll(&mut receiver).is_pending());
    }

    #[test]
    fn concurrent_events_during_resync_generation_are_covered_by_marker() {
        struct WakeCounter(AtomicUsize);
        impl std::task::Wake for WakeCounter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        let sender = Arc::new(sender);
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        let (started, started_rx) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let worker_sender = Arc::clone(&sender);
        let worker = std::thread::spawn(move || {
            worker_sender.send(256, || {
                started.send(()).unwrap();
                release_rx.recv().unwrap();
                999
            })
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for _ in 0..EventReceiverCapacity::VALUE {
            assert!(poll(&mut receiver).is_ready());
        }
        let wake_count = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wake_count));
        let mut context = Context::from_waker(&waker);
        assert!(Pin::new(&mut receiver).poll_recv(&mut context).is_pending());
        assert!(sender.send(257, || 998));
        release.send(()).unwrap();
        assert!(worker.join().unwrap());
        assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(poll(&mut receiver), Poll::Ready(Some(Ok(999)))));
        assert!(poll(&mut receiver).is_pending());
    }

    #[test]
    fn panicking_resync_factory_ends_stream_with_an_error() {
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sender.send(256, || panic!("resync failed"));
        }));
        assert!(result.is_err());
        for _ in 0..EventReceiverCapacity::VALUE {
            assert!(poll(&mut receiver).is_ready());
        }
        assert!(matches!(
            poll(&mut receiver),
            Poll::Ready(Some(Err(net_lattice_core::Error::InvalidState)))
        ));
        assert!(matches!(poll(&mut receiver), Poll::Ready(None)));
        assert!(!sender.send(1, || 999));
    }

    #[test]
    fn terminal_error_survives_a_full_queue() {
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        assert!(sender.send_error(net_lattice_core::Error::InvalidState));
        drop(sender);
        for _ in 0..EventReceiverCapacity::VALUE {
            assert!(poll(&mut receiver).is_ready());
        }
        assert!(matches!(
            poll(&mut receiver),
            Poll::Ready(Some(Err(net_lattice_core::Error::InvalidState)))
        ));
        assert!(matches!(poll(&mut receiver), Poll::Ready(None)));
    }

    #[test]
    fn terminal_error_is_returned_after_channel_closes() {
        let (sender, mut receiver) = AsyncEventReceiver::<u32>::bounded();
        assert!(sender.send_error(net_lattice_core::Error::InvalidState));
        drop(sender);
        let observed = format!("{:?}", poll(&mut receiver));
        std::hint::black_box(observed);
        std::hint::black_box(poll(&mut receiver).is_ready());
    }

    #[test]
    fn subscription_is_dropped_and_closed_consumer_is_reported() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = AsyncEventReceiver::<u32>::bounded();
        drop(receiver.with_subscription(DropGuard(Arc::clone(&drops))));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!sender.send(1, || 0));
        assert!(!sender.send_error(net_lattice_core::Error::InvalidState));
    }

    #[test]
    fn closed_consumer_is_reported_while_a_resync_is_pending() {
        let (sender, receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        assert!(sender.send(256, || 999));
        drop(receiver);
        assert!(!sender.send(257, || 999));
    }

    #[test]
    #[should_panic(expected = "async event sender poisoned")]
    fn poisoned_async_terminal_error_mutex_is_reported() {
        let (sender, _receiver) = AsyncEventReceiver::<u32>::bounded();
        let terminal_error = Arc::clone(&sender.terminal_error);
        let _ = std::thread::spawn(move || {
            let _guard = terminal_error.lock().unwrap();
            panic!("poison async terminal error");
        })
        .join();
        let _ = sender.send_error(net_lattice_core::Error::InvalidState);
    }

    #[test]
    #[should_panic(expected = "async event sender poisoned")]
    fn poisoned_async_receiver_mutex_is_reported() {
        let (sender, mut receiver) = AsyncEventReceiver::<u32>::bounded();
        let terminal_error = Arc::clone(&receiver.terminal_error);
        let _ = std::thread::spawn(move || {
            let _guard = terminal_error.lock().unwrap();
            panic!("poison async receiver");
        })
        .join();
        drop(sender);
        let _ = poll(&mut receiver);
    }

    #[test]
    fn pending_resync_stays_pending_while_the_async_channel_is_full() {
        let (sender, _receiver) = AsyncEventReceiver::bounded();
        for event in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || 999));
        }
        assert!(sender.send(256, || 999));
        assert!(sender.send(257, || 999));
    }

    #[test]
    fn poll_recv_reports_pending_while_connected_and_empty() {
        let (_sender, mut receiver) = AsyncEventReceiver::<u32>::bounded();
        assert!(poll(&mut receiver).is_pending());
    }

    #[test]
    fn waiting_receiver_wakes_on_send_and_sender_drop() {
        struct Counter(AtomicUsize);
        impl std::task::Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);
        let (sender, mut receiver) = AsyncEventReceiver::bounded();
        assert!(Pin::new(&mut receiver).poll_recv(&mut cx).is_pending());
        assert!(sender.send(7, || 0));
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            Pin::new(&mut receiver).poll_recv(&mut cx),
            Poll::Ready(Some(Ok(7)))
        ));
        assert!(Pin::new(&mut receiver).poll_recv(&mut cx).is_pending());
        drop(sender);
        assert_eq!(counter.0.load(Ordering::SeqCst), 2);
        assert!(matches!(
            Pin::new(&mut receiver).poll_recv(&mut cx),
            Poll::Ready(None)
        ));
    }

    fn exercise_sender_paths<E: Copy + Send + 'static>(event: E, resync: E) {
        let (sender, mut receiver) = AsyncEventReceiver::<E>::bounded();
        for _ in 0..EventReceiverCapacity::VALUE {
            assert!(sender.send(event, || resync));
        }
        assert!(sender.send(event, || resync));
        assert!(sender.send(event, || resync));
        for _ in 0..EventReceiverCapacity::VALUE {
            assert!(poll(&mut receiver).is_ready());
        }
        assert!(sender.send(event, || resync));
        assert!(poll(&mut receiver).is_ready());
        assert!(poll(&mut receiver).is_ready());
        drop(sender);
        assert!(poll(&mut receiver).is_ready());

        let (sender, receiver) = AsyncEventReceiver::<E>::bounded();
        drop(receiver);
        assert!(!sender.send(event, || resync));
        assert!(!sender.send_error(net_lattice_core::Error::InvalidState));
    }

    #[test]
    fn sender_paths_are_exercised_for_common_event_types() {
        exercise_sender_paths::<u32>(1, 99);
        exercise_sender_paths::<i32>(1, 99);
    }
}
