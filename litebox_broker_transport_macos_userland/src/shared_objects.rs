// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Out-of-band delivery of host shared objects from the broker to a runner.
//!
//! Some broker responses refer to a host object that the runner must hold itself, such as the
//! control connection of a native fork child. During setup, the broker sends the runner one end
//! of a socket pair (see
//! [`UnixStreamHostSetupChannel::send_shared_object_channel`](crate::unix_socket::UnixStreamHostSetupChannel::send_shared_object_channel)).
//! To deliver an object, the broker sends its descriptor over the socket in a message holding an
//! 8-byte little-endian token, then answers the request with the token. The runner takes the
//! descriptor with that token.
//!
//! macOS has no `SOCK_SEQPACKET`, so the pair is `SOCK_DGRAM`, which also keeps each token with
//! its descriptor.
//!
//! Sends never block: a runner that does not take its objects only makes later deliveries to it
//! fail, rather than stalling the broker worker serving it. macOS charges in-flight datagrams to
//! the receiving socket's buffer, which the broker sizes small when it creates the pair, bounding
//! the descriptors in flight to one runner to a few dozen. A runner can enlarge its own buffer,
//! up to `kern.ipc.maxsockbuf`, to hold more.

use std::io::{Error, ErrorKind, IoSlice, Result as IoResult};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
    sendmsg, socketpair,
};

/// The receive buffer size set on the runner's end, which bounds the descriptors in flight to one
/// runner to a few dozen. macOS counts each message's whole buffer against it.
const RECEIVE_BUFFER_SIZE: usize = 4 * 1024;

/// The broker's end of a runner's shared-object socket.
#[derive(Debug)]
pub struct SharedObjectSender {
    socket: OwnedFd,
    next_token: AtomicU64,
}

impl SharedObjectSender {
    /// Creates a socket pair, returning the broker's sender and the runner's end, which the
    /// broker sends during setup.
    ///
    /// macOS has no `SOCK_CLOEXEC`, so both ends are marked close-on-exec after they are
    /// created; a process that spawns others must keep spawns from running in between.
    pub fn pair() -> IoResult<(Self, OwnedFd)> {
        let (broker, runner) = socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::empty(),
            None,
        )?;
        fcntl_setfd(&broker, FdFlags::CLOEXEC)?;
        fcntl_setfd(&runner, FdFlags::CLOEXEC)?;
        // macOS has no `MSG_NOSIGNAL`.
        rustix::net::sockopt::set_socket_nosigpipe(&broker, true)?;
        rustix::net::sockopt::set_socket_recv_buffer_size(&runner, RECEIVE_BUFFER_SIZE)?;
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
    /// A full socket fails with `ENOBUFS`, and a closed runner end with `ECONNRESET`.
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
            match sendmsg(self.socket.as_fd(), &io, &mut control, SendFlags::DONTWAIT) {
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
        let received = recvmsg(socket, &mut io, &mut control, RecvFlags::empty()).unwrap();
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
        let second = std::fs::File::open("/dev").unwrap();
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
        let error = loop {
            match sender.send(object.as_fd()) {
                Ok(_) => sent += 1,
                Err(error) => break error,
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
        assert!((8..=128).contains(&sent), "{sent} descriptors in flight");
    }

    #[test]
    fn closed_runner_end_fails_as_reset() {
        let (sender, runner) = SharedObjectSender::pair().unwrap();
        drop(runner);
        let object = std::fs::File::open("/").unwrap();
        assert_eq!(
            sender.send(object.as_fd()).unwrap_err().kind(),
            ErrorKind::ConnectionReset
        );
    }
}
