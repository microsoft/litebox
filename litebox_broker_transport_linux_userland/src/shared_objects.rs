// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Out-of-band delivery of host shared objects from the broker to a runner.
//!
//! Some broker responses refer to a host object that the runner must hold itself, such as a
//! memfd that the runner maps. During setup, the broker sends the
//! runner one end of a `SOCK_SEQPACKET` socket pair (see
//! [`UnixStreamHostSetupChannel::send_shared_object_channel`](crate::unix_socket::UnixStreamHostSetupChannel::send_shared_object_channel)).
//! To deliver an object, the broker sends its descriptor over the socket in a message holding an
//! 8-byte little-endian token, then answers the request with the token. The runner takes the
//! descriptor with that token.
//!
//! Sends never block: a runner that does not take its objects only makes later deliveries to it
//! fail, rather than stalling the broker worker serving it. The socket's small send buffer bounds
//! how many descriptors such a runner can leave in flight, which the host charges to the broker.

use std::io::{Error, ErrorKind, IoSlice, Result as IoResult};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::io::Errno;
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
    sendmsg, socketpair,
};

/// The send buffer size requested for the broker's end, which bounds the descriptors in flight
/// to one runner to a few dozen. Linux doubles it and counts each message's whole buffer.
const SEND_BUFFER_SIZE: usize = 16 * 1024;

/// The broker's end of a runner's shared-object socket.
#[derive(Debug)]
pub struct SharedObjectSender {
    socket: OwnedFd,
    next_token: AtomicU64,
}

impl SharedObjectSender {
    /// Creates a socket pair, returning the broker's sender and the runner's end, which the
    /// broker sends during setup.
    pub fn pair() -> IoResult<(Self, OwnedFd)> {
        let (broker, runner) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        rustix::net::sockopt::set_socket_send_buffer_size(&broker, SEND_BUFFER_SIZE)?;
        Ok((
            Self {
                socket: broker,
                next_token: AtomicU64::new(1),
            },
            runner,
        ))
    }

    /// Sends `object` to the runner, returning the token it takes the object with.
    ///
    /// # Panics
    ///
    /// Panics if the control buffer is too small for one descriptor, which cannot happen.
    pub fn send(&self, object: BorrowedFd<'_>) -> IoResult<u64> {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let bytes = token.to_le_bytes();
        let io = [IoSlice::new(&bytes)];
        let fds = [object];
        let mut control_space = crate::control_space::<{ rustix::cmsg_space!(ScmRights(1)) }>();
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(
            control.push(SendAncillaryMessage::ScmRights(&fds)),
            "SCM_RIGHTS control buffer is correctly sized"
        );
        loop {
            match sendmsg(
                self.socket.as_fd(),
                &io,
                &mut control,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            ) {
                Ok(sent) if sent == bytes.len() => return Ok(token),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "failed to send a shared object",
                    ));
                }
                Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
    use std::io::IoSliceMut;
    use std::os::fd::AsRawFd as _;

    fn receive(socket: &OwnedFd) -> (u64, OwnedFd) {
        let mut bytes = [0; 8];
        let mut io = [IoSliceMut::new(&mut bytes)];
        let mut control_space = crate::control_space::<{ rustix::cmsg_space!(ScmRights(1)) }>();
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let received = recvmsg(socket, &mut io, &mut control, RecvFlags::CMSG_CLOEXEC).unwrap();
        assert_eq!(received.bytes, 8);
        let mut fds = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = message {
                fds.extend(received);
            }
        }
        assert_eq!(fds.len(), 1);
        (u64::from_le_bytes(bytes), fds.pop().unwrap())
    }

    #[test]
    fn delivers_distinct_tokens_with_their_objects() {
        let (sender, runner) = SharedObjectSender::pair().unwrap();
        let first = std::fs::File::open("/").unwrap();
        let second = std::fs::File::open("/proc").unwrap();
        let first_token = sender.send(first.as_fd()).unwrap();
        let second_token = sender.send(second.as_fd()).unwrap();
        assert_ne!(first_token, second_token);

        let (token, fd) = receive(&runner);
        assert_eq!(token, first_token);
        assert_ne!(fd.as_raw_fd(), first.as_raw_fd());
        assert_eq!(receive(&runner).0, second_token);
    }

    #[test]
    fn full_socket_fails_instead_of_blocking() {
        let (sender, _runner) = SharedObjectSender::pair().unwrap();
        let object = std::fs::File::open("/").unwrap();
        // Fails once the socket is full, without blocking, and only a bounded number of
        // descriptors are ever in flight.
        let mut sent = 0;
        while sender.send(object.as_fd()).is_ok() {
            sent += 1;
        }
        assert!((8..=128).contains(&sent), "{sent} descriptors in flight");
    }
}
