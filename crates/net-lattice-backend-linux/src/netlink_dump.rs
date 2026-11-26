//! Synchronous multipart Netlink dumps for the Linux backend.
//!
//! The socket is created with the backend in its network namespace and is
//! serialized by its owner. It is not shared with the event subscription.

use std::io;

use net_lattice_core::{Error, PlatformErrorCode, Result};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use rtnetlink::packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkBuffer, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use rtnetlink::packet_route::RouteNetlinkMessage;

pub(crate) struct DumpSocket {
    socket: Socket,
    sequence: u32,
}

fn io_error(err: io::Error) -> Error {
    Error::Platform(PlatformErrorCode::Linux(err.raw_os_error().unwrap_or(0)))
}

fn malformed() -> Error {
    Error::Platform(PlatformErrorCode::Linux(0))
}

fn retry<T>(mut operation: impl FnMut() -> io::Result<T>) -> Result<T> {
    loop {
        match operation() {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => return result.map_err(io_error),
        }
    }
}

impl DumpSocket {
    pub(crate) fn open() -> Result<Self> {
        let socket = retry(|| Socket::new(NETLINK_ROUTE))?;
        retry(|| socket.connect(&SocketAddr::new(0, 0)))?;
        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    pub(crate) fn dump(
        &mut self,
        request: RouteNetlinkMessage,
    ) -> Result<Vec<RouteNetlinkMessage>> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        header.sequence_number = self.sequence;
        let mut packet = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(request));
        packet.finalize();
        let mut bytes = vec![0; packet.buffer_len()];
        packet.serialize(&mut bytes);
        if retry(|| self.socket.send(&bytes, 0))? != bytes.len() {
            return Err(malformed());
        }
        let mut messages = Vec::new();
        let mut interrupted = false;
        loop {
            let mut datagram = Vec::new();
            let (size, _) = retry(|| {
                self.socket
                    .recv_from(&mut datagram, libc::MSG_PEEK | libc::MSG_TRUNC)
            })?;
            datagram.clear();
            datagram.reserve(size);
            let (read, from) = retry(|| self.socket.recv_from(&mut datagram, libc::MSG_TRUNC))?;
            if read > datagram.len() || read == 0 {
                return Err(malformed());
            }
            if from.port_number() != 0 {
                continue;
            }
            if decode(&datagram, self.sequence, &mut interrupted, &mut messages)? {
                return Ok(messages);
            }
        }
    }
}

fn decode(
    data: &[u8],
    sequence: u32,
    interrupted: &mut bool,
    messages: &mut Vec<RouteNetlinkMessage>,
) -> Result<bool> {
    let mut remaining = data;
    while !remaining.is_empty() {
        let buffer = NetlinkBuffer::new_checked(remaining).map_err(|_| malformed())?;
        let len = buffer.length() as usize;
        if len < 16 || len > remaining.len() {
            return Err(malformed());
        }
        let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&remaining[..len])
            .map_err(|_| malformed())?;
        if message.header.sequence_number == sequence {
            *interrupted |= message.header.flags & NLM_F_DUMP_INTR != 0;
            match message.payload {
                NetlinkPayload::InnerMessage(value) => messages.push(value),
                NetlinkPayload::Done(done) => {
                    if done.code != 0 {
                        return Err(Error::Platform(PlatformErrorCode::Linux(done.code)));
                    }
                    if *interrupted {
                        return Err(malformed());
                    }
                    return Ok(true);
                }
                NetlinkPayload::Error(error) => {
                    if let Some(code) = error.code {
                        return Err(Error::Platform(PlatformErrorCode::Linux(code.into())));
                    }
                }
                NetlinkPayload::Noop => {}
                _ => return Err(malformed()),
            }
        }
        let aligned = len.checked_add(3).ok_or_else(malformed)? & !3;
        if aligned > remaining.len() {
            return Err(malformed());
        }
        remaining = &remaining[aligned..];
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_core::DoneMessage;
    use rtnetlink::packet_route::link::LinkMessage;

    fn encode(payload: NetlinkPayload<RouteNetlinkMessage>, sequence: u32, flags: u16) -> Vec<u8> {
        let mut header = NetlinkHeader::default();
        header.sequence_number = sequence;
        header.flags = flags;
        let mut message = NetlinkMessage::new(header, payload);
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    }

    #[test]
    fn multipart_dump_skips_other_sequences_and_finishes_on_done() {
        let mut data = encode(
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(LinkMessage::default())),
            9,
            0,
        );
        data.extend(encode(
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(LinkMessage::default())),
            7,
            0,
        ));
        data.extend(encode(NetlinkPayload::Done(DoneMessage::default()), 7, 0));
        let mut messages = Vec::new();
        assert!(decode(&data, 7, &mut false, &mut messages).unwrap());
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn interrupted_and_truncated_dumps_are_rejected() {
        let done = encode(
            NetlinkPayload::Done(DoneMessage::default()),
            7,
            NLM_F_DUMP_INTR,
        );
        assert!(decode(&done, 7, &mut false, &mut Vec::new()).is_err());
        assert!(decode(&done[..done.len() - 1], 7, &mut false, &mut Vec::new()).is_err());
    }

    #[test]
    fn reads_real_loopback_link() {
        let mut socket = DumpSocket::open().expect("open route socket");
        let links = socket
            .dump(RouteNetlinkMessage::GetLink(LinkMessage::default()))
            .expect("dump links");
        assert!(links.iter().any(|message| matches!(message, RouteNetlinkMessage::NewLink(link) if link.attributes.iter().any(|attribute| matches!(attribute, rtnetlink::packet_route::link::LinkAttribute::IfName(name) if name == "lo")))));
    }
}
