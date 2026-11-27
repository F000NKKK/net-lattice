//! Runtime-agnostic async adapters for Net Lattice.
//!
//! [`from_receiver`] bridges the synchronous, blocking
//! [`net_lattice_platform::EventReceiver`] onto a `futures::Stream`. It
//! deliberately creates one worker thread: `std::sync::mpsc::Receiver` has no
//! waker-registration mechanism, so a direct `Stream` implementation would
//! block an executor thread. The adapter does not select an executor, and
//! the platform event channel does not depend on an async runtime.

#![warn(missing_docs)]

use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use futures_channel::mpsc::{Receiver, Sender, channel};
use futures_core::Stream;
pub use net_lattice_core::{Error, Result};
use net_lattice_platform::{AsyncEventReceiver, EventReceiver};

/// A runtime-agnostic asynchronous stream of network change events.
///
/// Depending on the connected backend, events may be delivered through a
/// native asynchronous watcher or adapted from a synchronous
/// [`EventReceiver`]. Applications normally obtain this stream through
/// `Lattice::watch_async` with Net Lattice's `async` feature.
///
/// Implements [`Stream`].
pub struct EventStream<E> {
    receiver: EventStreamReceiver<E>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
enum EventStreamReceiver<E> {
    Futures(Receiver<Result<E>>),
    Native(AsyncEventReceiver<E>),
}

/// Bridges a synchronous event receiver to a waker-aware stream.
///
/// The returned stream owns the receiver. Dropping it requests worker shutdown
/// and joins the thread; shutdown latency is at most 50 ms, after which the
/// receiver is dropped and its backend subscription is cancelled.
///
/// The intermediate queue is bounded. When it is full, the worker waits for
/// the consumer; the source receiver's own overflow policy then applies.
pub fn from_receiver<E>(receiver: EventReceiver<E>) -> EventStream<E>
where
    E: Send + 'static,
{
    let (sender, async_receiver) = channel(256);
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || forward_receiver(receiver, sender, worker_stop));
    EventStream {
        receiver: EventStreamReceiver::Futures(async_receiver),
        stop,
        worker: Some(worker),
    }
}

/// Runs the blocking side of a synchronous-to-async adapter.
///
/// Kept separate from [`from_receiver`] so its terminal-channel behaviour is
/// directly regression-tested without exposing another public API surface.
fn forward_receiver<E>(
    receiver: EventReceiver<E>,
    mut sender: Sender<Result<E>>,
    stop: Arc<AtomicBool>,
) where
    E: Send + 'static,
{
    while !stop.load(Ordering::Acquire) {
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Some(event)) => {
                if !forward_item(&mut sender, Ok(event), &stop) {
                    break;
                }
            }
            Ok(None) => {}
            Err(error) => {
                let _ = forward_item(&mut sender, Err(error), &stop);
                break;
            }
        }
    }
}

fn forward_item<E>(sender: &mut Sender<Result<E>>, mut item: Result<E>, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        match sender.try_send(item) {
            Ok(()) => return true,
            Err(error) if error.is_full() => {
                item = error.into_inner();
                thread::park_timeout(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

/// Wraps a backend-native event receiver in the same public stream.
pub fn from_async_receiver<E>(receiver: AsyncEventReceiver<E>) -> EventStream<E> {
    EventStream {
        receiver: EventStreamReceiver::Native(receiver),
        stop: Arc::new(AtomicBool::new(false)),
        worker: None,
    }
}

impl<E> Stream for EventStream<E> {
    type Item = Result<E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = match &mut self.receiver {
            EventStreamReceiver::Futures(receiver) => Pin::new(receiver).poll_next(cx),
            EventStreamReceiver::Native(receiver) => Pin::new(receiver).poll_recv(cx),
        };
        if result.is_ready()
            && let Some(worker) = &self.worker
        {
            worker.thread().unpark();
        }
        result
    }
}

impl<E> Drop for EventStream<E> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[test]
    fn worker_forwards_events_to_the_stream() {
        let (sender, receiver) = EventReceiver::bounded();
        let mut events = from_receiver(receiver);
        assert!(sender.send(7_u8, 0));
        assert_eq!(
            futures::executor::block_on(events.next()).unwrap().unwrap(),
            7
        );
    }

    #[test]
    fn worker_forwards_receiver_errors() {
        let (sender, receiver) = EventReceiver::<u8>::bounded();
        let mut events = from_receiver(receiver);
        assert!(sender.send_error(Error::InvalidState));
        assert!(futures::executor::block_on(events.next()).unwrap().is_err());
    }

    #[test]
    fn native_async_receiver_uses_the_same_stream_surface() {
        let (sender, receiver) = AsyncEventReceiver::bounded();
        let mut events = from_async_receiver(receiver);
        assert!(sender.send(7_u8, || 0));
        drop(sender);
        assert_eq!(
            futures::executor::block_on(events.next()).unwrap().unwrap(),
            7
        );
        assert!(futures::executor::block_on(events.next()).is_none());
    }

    #[test]
    fn dropping_a_sync_stream_joins_its_adapter_worker() {
        let (_sender, receiver) = EventReceiver::<u8>::bounded();
        drop(from_receiver(receiver));
    }

    #[test]
    fn dropping_a_full_stream_stops_a_blocked_worker() {
        let (mut sender, receiver) = channel::<Result<u8>>(1);
        while sender.try_send(Ok(1)).is_ok() {}
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let _ = forward_item(&mut sender, Ok(2), &worker_stop);
        });
        let stream = EventStream {
            receiver: EventStreamReceiver::Futures(receiver),
            stop,
            worker: Some(worker),
        };
        drop(stream);
    }

    #[test]
    fn full_queue_retains_the_event_until_the_consumer_drains_it() {
        let (mut sender, mut receiver) = channel::<Result<u8>>(1);
        while sender.try_send(Ok(1)).is_ok() {}
        let stop = Arc::new(AtomicBool::new(false));
        let worker = thread::spawn(move || forward_item(&mut sender, Ok(2), &stop));
        assert_eq!(receiver.try_recv().unwrap().unwrap(), 1);
        worker.thread().unpark();
        assert!(worker.join().unwrap());
        let remaining: Vec<_> = futures::executor::block_on(receiver.collect());
        assert!(remaining.into_iter().any(|event| matches!(event, Ok(2))));
    }

    #[test]
    fn worker_stops_when_its_async_consumer_is_already_gone() {
        let (input, receiver) = EventReceiver::bounded();
        let (output, async_receiver) = channel::<Result<u8>>(1);
        drop(async_receiver);
        assert!(input.send(7, 0));
        forward_receiver(receiver, output, Arc::new(AtomicBool::new(false)));
    }

    #[test]
    fn worker_rechecks_an_empty_receiver_until_shutdown_is_requested() {
        let (_sender, receiver) = EventReceiver::<u8>::bounded();
        let (output, _async_receiver) = channel::<Result<u8>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_later = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            stop_later.store(true, Ordering::Release);
        });
        forward_receiver(receiver, output, stop);
    }

    #[test]
    fn adapter_handles_immediate_shutdown_and_native_stream_without_worker() {
        let (_sender, receiver) = EventReceiver::<u8>::bounded();
        let (output, _async_receiver) = channel::<Result<u8>>(1);
        forward_receiver(receiver, output, Arc::new(AtomicBool::new(true)));

        let (_sender, receiver) = AsyncEventReceiver::<u8>::bounded();
        drop(from_async_receiver(receiver));
    }

    #[test]
    fn native_stream_drop_does_not_attempt_to_join_a_worker() {
        let (_sender, receiver) = AsyncEventReceiver::<u8>::bounded();
        drop(from_async_receiver(receiver));
    }

    #[test]
    fn dropping_a_stream_ignores_a_worker_join_error() {
        let (_sender, receiver) = AsyncEventReceiver::<u8>::bounded();
        let worker = std::thread::spawn(|| panic!("worker terminated unexpectedly"));
        let stream = EventStream {
            receiver: EventStreamReceiver::Native(receiver),
            stop: Arc::new(AtomicBool::new(false)),
            worker: Some(worker),
        };
        drop(stream);
    }
}
