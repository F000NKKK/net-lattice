//! Runtime-independent Netlink multicast monitoring with explicit cancellation.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use net_lattice_core::{Error, PlatformErrorCode, Result};
use net_lattice_model::event::{Event, EventFilter};
#[cfg(feature = "async")]
use net_lattice_platform::AsyncEventSender;
use net_lattice_platform::EventSender;
use netlink_sys::{Socket, protocols::NETLINK_ROUTE};
use rtnetlink::packet_core::{NetlinkBuffer, NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;

use crate::route_netlink_message_to_event;

pub(crate) enum Sink {
    Sync(EventSender<Event>),
    #[cfg(feature = "async")]
    Async(AsyncEventSender<Event>),
}

impl Sink {
    fn send(&self, event: Event) -> bool {
        match self {
            Self::Sync(sender) => sender.send(event, Event::resync_all()),
            #[cfg(feature = "async")]
            Self::Async(sender) => sender.send(event, Event::resync_all),
        }
    }

    fn error(&self, error: Error) {
        match self {
            Self::Sync(sender) => {
                let _ = sender.send_error(error);
            }
            #[cfg(feature = "async")]
            Self::Async(sender) => {
                let _ = sender.send_error(error);
            }
        }
    }
}

pub(crate) struct Watch {
    stop: Arc<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Watch {
    fn drop(&mut self) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: eventfd is live and one has the required eight-byte layout.
        loop {
            let written =
                unsafe { libc::write(self.stop.as_raw_fd(), one.as_ptr().cast(), one.len()) };
            if written >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

fn platform(error: io::Error) -> Error {
    Error::Platform(PlatformErrorCode::Linux(error.raw_os_error().unwrap_or(0)))
}

pub(crate) fn start(filter: EventFilter, sink: Sink) -> Result<Watch> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(platform)?;
    socket.bind_auto().map_err(platform)?;
    for group in [
        libc::RTNLGRP_LINK,
        libc::RTNLGRP_NEIGH,
        libc::RTNLGRP_IPV4_ROUTE,
        libc::RTNLGRP_IPV6_ROUTE,
        libc::RTNLGRP_IPV4_IFADDR,
        libc::RTNLGRP_IPV6_IFADDR,
    ] {
        socket.add_membership(group).map_err(platform)?;
    }
    // SAFETY: eventfd has no pointer arguments and yields a new descriptor.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(platform(io::Error::last_os_error()));
    }
    // SAFETY: fd is a newly created, uniquely owned descriptor.
    let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
    let worker_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("net-lattice-netlink".into())
        .spawn(move || {
            if let Err(error) = run(socket, &worker_stop, filter, &sink) {
                sink.error(error);
            }
        })
        .map_err(platform)?;
    Ok(Watch {
        stop,
        thread: Some(thread),
    })
}

fn run(socket: Socket, stop: &OwnedFd, filter: EventFilter, sink: &Sink) -> Result<()> {
    let mut descriptors = [
        libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: descriptors contains two valid pollfd entries.
        let ready = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                -1,
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(platform(error));
        }
        if descriptors[1].revents != 0 {
            return Ok(());
        }
        if descriptors[0].revents & (libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::Disconnected);
        }
        if descriptors[0].revents & (libc::POLLIN | libc::POLLERR) == 0 {
            continue;
        }
        let mut data = Vec::new();
        let (size, _) = match socket.recv_from(&mut data, libc::MSG_PEEK | libc::MSG_TRUNC) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                if !sink.send(Event::resync_all()) {
                    return Ok(());
                }
                continue;
            }
            Err(error) => return Err(platform(error)),
        };
        data.clear();
        data.reserve(size);
        let (read, from) = match socket.recv_from(&mut data, libc::MSG_TRUNC) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                if !sink.send(Event::resync_all()) {
                    return Ok(());
                }
                continue;
            }
            Err(error) => return Err(platform(error)),
        };
        if read == 0 || read > data.len() {
            if !sink.send(Event::resync_all()) {
                return Ok(());
            }
            continue;
        }
        if from.port_number() != 0 {
            continue;
        }
        if !deliver(&data, &filter, sink) {
            return Ok(());
        }
    }
}

fn deliver(mut data: &[u8], filter: &EventFilter, sink: &Sink) -> bool {
    while !data.is_empty() {
        let Ok(buffer) = NetlinkBuffer::new_checked(data) else {
            return sink.send(Event::resync_all());
        };
        let len = buffer.length() as usize;
        if len < 16 || len > data.len() {
            return sink.send(Event::resync_all());
        }
        let Ok(message) = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&data[..len]) else {
            return sink.send(Event::resync_all());
        };
        match message.payload {
            NetlinkPayload::InnerMessage(message) => {
                if let Some(event) = route_netlink_message_to_event(message)
                    && filter.matches(event)
                    && !sink.send(event)
                {
                    return false;
                }
            }
            NetlinkPayload::Overrun(_) if !sink.send(Event::resync_all()) => return false,
            _ => {}
        }
        let Some(aligned) = len.checked_add(3).map(|value| value & !3) else {
            return sink.send(Event::resync_all());
        };
        if aligned > data.len() {
            return sink.send(Event::resync_all());
        }
        data = &data[aligned..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_platform::EventReceiver;
    use rtnetlink::packet_core::NetlinkHeader;
    use rtnetlink::packet_route::link::LinkMessage;

    #[test]
    fn malformed_notifications_request_resynchronization() {
        let (sender, receiver) = EventReceiver::bounded();
        assert!(deliver(&[1, 2, 3], &EventFilter::ALL, &Sink::Sync(sender)));
        assert!(matches!(
            receiver.try_recv(),
            Ok(Some(Event::ResyncRequired { .. }))
        ));
    }

    #[test]
    fn notification_filter_is_applied_before_delivery() {
        let mut link = LinkMessage::default();
        link.header.index = 7;
        let mut packet = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
        );
        packet.finalize();
        let mut bytes = vec![0; packet.buffer_len()];
        packet.serialize(&mut bytes);
        let (sender, receiver) = EventReceiver::bounded();
        let sink = Sink::Sync(sender);
        assert!(deliver(&bytes, &EventFilter::none().routes(), &sink));
        assert!(matches!(receiver.try_recv(), Ok(None)));
        assert!(deliver(&bytes, &EventFilter::ALL, &sink));
        assert!(matches!(
            receiver.try_recv(),
            Ok(Some(Event::Interface { .. }))
        ));
    }

    #[test]
    fn dropping_idle_watcher_stops_its_thread() {
        let (sender, _receiver) = EventReceiver::bounded();
        let watch = start(EventFilter::ALL, Sink::Sync(sender)).expect("open multicast watcher");
        drop(watch);
    }
}
