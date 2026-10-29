// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Receiving host shared objects that the broker delivers out of band.
//!
//! The broker answers a request for a host object that this process must hold itself, such as a
//! memfd, with a token, after it has sent the object's descriptor tagged with the same token over
//! a dedicated `SOCK_SEQPACKET` socket. Concurrent requests may complete in any order, so
//! descriptors that arrive for other tokens wait here until their requester takes them.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::Mutex;

/// Descriptors received ahead of their requester are dropped beyond this many, oldest first, so
/// that a broker cannot make this process hold descriptors without bound.
const MAX_PENDING: usize = 64;

/// Tokens whose descriptors were dropped are remembered up to this many, oldest forgotten first,
/// so that taking one fails instead of waiting for a descriptor that will not come.
const MAX_EVICTED: usize = 4096;

/// The receiving end of the broker's shared-object socket.
pub struct SharedObjectChannel {
    state: Mutex<State>,
}

struct State {
    socket: OwnedFd,
    pending: BTreeMap<u64, OwnedFd>,
    evicted: BTreeSet<u64>,
}

impl SharedObjectChannel {
    /// Receives shared objects over `socket`, the runner's end of the broker's socket pair.
    pub fn new(socket: OwnedFd) -> Self {
        Self {
            state: Mutex::new(State {
                socket,
                pending: BTreeMap::new(),
                evicted: BTreeSet::new(),
            }),
        }
    }

    /// Takes the descriptor that the broker sent under `token`, waiting for it if it has not
    /// been received yet.
    ///
    /// Fails with [`ErrorKind::NotFound`] if the descriptor was received but dropped, as too
    /// many others were waiting for their requesters, and with [`ErrorKind::InvalidData`] if its
    /// message arrived without exactly one descriptor, as when this process is out of
    /// descriptors.
    pub fn take(&self, token: u64) -> Result<OwnedFd> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(fd) = state.pending.remove(&token) {
                return Ok(fd);
            }
            if state.evicted.remove(&token) {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "the shared object was dropped before it was taken",
                ));
            }
            let (received, fd) = receive(&state.socket)?;
            if received == token {
                return fd;
            }
            // A message whose descriptor was lost still names its requester, which must fail
            // rather than wait for a descriptor that will not come.
            let Ok(fd) = fd else {
                state.evict(received);
                continue;
            };
            if state.pending.len() >= MAX_PENDING
                && let Some((dropped, _)) = state.pending.pop_first()
            {
                state.evict(dropped);
            }
            state.pending.insert(received, fd);
        }
    }
}

impl State {
    /// Remembers that the descriptor sent under `token` will never be taken.
    fn evict(&mut self, token: u64) {
        if self.evicted.len() >= MAX_EVICTED {
            self.evicted.pop_first();
        }
        self.evicted.insert(token);
    }
}

/// Receives one message: an 8-byte token, and the result of taking exactly one descriptor
/// from it.
///
/// Fails outright only if the message has no token.
fn receive(socket: &OwnedFd) -> Result<(u64, Result<OwnedFd>)> {
    let mut token = [0u8; 8];
    let mut iov = libc::iovec {
        iov_base: token.as_mut_ptr().cast(),
        iov_len: token.len(),
    };
    // Room for a few descriptors, so that a message carrying more than one is still drained and
    // its extra descriptors closed rather than left in the socket.
    let mut control = [0u64; 8];
    // SAFETY: `msghdr` is plain data, for which all-zero bytes are valid.
    let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
    header.msg_iov = &raw mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = core::mem::size_of_val(&control) as _;
    let received = loop {
        // SAFETY: `header` describes buffers that live across the call.
        let result =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut header, libc::MSG_CMSG_CLOEXEC) };
        if result >= 0 {
            break result;
        }
        let error = Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    };
    if received == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed its shared-object socket",
        ));
    }

    let mut fds = Vec::new();
    // SAFETY: `header` was filled in by `recvmsg`, so the first control message, if any, lies
    // within `control`.
    let mut message = unsafe { libc::CMSG_FIRSTHDR(&raw const header) };
    while !message.is_null() {
        // SAFETY: `message` is a control message within `control`, which `recvmsg` filled in.
        let (level, kind, length) = unsafe {
            (
                (*message).cmsg_level,
                (*message).cmsg_type,
                (*message).cmsg_len as usize,
            )
        };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            // SAFETY: `CMSG_LEN` and `CMSG_DATA` only compute sizes and addresses.
            let (header_len, data) = unsafe {
                (
                    libc::CMSG_LEN(0) as usize,
                    libc::CMSG_DATA(message).cast::<libc::c_int>(),
                )
            };
            let count = length.saturating_sub(header_len) / size_of::<libc::c_int>();
            for index in 0..count {
                // SAFETY: The message holds `count` descriptors after its header, each a new
                // descriptor that the kernel installed for this process alone.
                fds.push(unsafe { OwnedFd::from_raw_fd(data.add(index).read_unaligned()) });
            }
        }
        // SAFETY: `message` lies within the control buffer that `header` describes.
        message = unsafe { libc::CMSG_NXTHDR(&raw const header, message) };
    }
    if received.cast_unsigned() != token.len() || header.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "malformed shared-object message from the broker",
        ));
    }
    let token = u64::from_le_bytes(token);
    if header.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() != 1 {
        return Ok((
            token,
            Err(Error::new(
                ErrorKind::InvalidData,
                "a shared-object message arrived without exactly one descriptor",
            )),
        ));
    }
    Ok((token, Ok(fds.pop().unwrap())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;
    use std::os::fd::AsFd as _;

    fn inode(fd: &OwnedFd) -> u64 {
        std::fs::File::from(fd.try_clone().unwrap())
            .metadata()
            .map(|metadata| std::os::unix::fs::MetadataExt::ino(&metadata))
            .unwrap()
    }

    #[test]
    fn takes_descriptors_by_token_in_any_order() {
        let (sender, receiver) = SharedObjectSender::pair().unwrap();
        let channel = SharedObjectChannel::new(receiver);
        let first = std::fs::File::open("/").unwrap();
        let second = std::fs::File::open("/proc").unwrap();
        let first_token = sender.send(first.as_fd()).unwrap();
        let second_token = sender.send(second.as_fd()).unwrap();

        let second_received = channel.take(second_token).unwrap();
        let first_received = channel.take(first_token).unwrap();
        assert_eq!(inode(&second_received), inode(&OwnedFd::from(second)));
        assert_eq!(inode(&first_received), inode(&OwnedFd::from(first)));
    }

    #[test]
    fn dropped_descriptors_fail_instead_of_blocking() {
        let (sender, receiver) = SharedObjectSender::pair().unwrap();
        let channel = SharedObjectChannel::new(receiver);
        let file = std::fs::File::open("/").unwrap();
        // The broker's send buffer holds fewer descriptors than may wait here, so send them in
        // batches, taking the last of each, which queues the others.
        let mut tokens = Vec::new();
        while tokens.len() <= MAX_PENDING + 1 {
            let batch: Vec<u64> = (0..16)
                .map(|_| sender.send(file.as_fd()).unwrap())
                .collect();
            channel.take(*batch.last().unwrap()).unwrap();
            tokens.extend(&batch[..batch.len() - 1]);
        }
        // Beyond the limit, the oldest were dropped.
        assert_eq!(
            channel.take(tokens[0]).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        channel.take(*tokens.last().unwrap()).unwrap();
    }

    #[test]
    fn descriptors_lost_in_transit_fail_their_requester() {
        let mut pair = [0; 2];
        // SAFETY: `pair` has room for the two new descriptors.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
        // SAFETY: `socketpair` created both descriptors for this test alone.
        let (broker, receiver) =
            unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        let channel = SharedObjectChannel::new(receiver);
        let file = std::fs::File::open("/").unwrap();
        let send = |token: u64, fd: Option<i32>| {
            let mut bytes = token.to_le_bytes();
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut control = [0u64; 4];
            // SAFETY: `msghdr` is plain data, for which all-zero bytes are valid.
            let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
            header.msg_iov = &raw mut iov;
            header.msg_iovlen = 1;
            if let Some(fd) = fd {
                let fd_size = u32::try_from(size_of::<i32>()).unwrap();
                header.msg_control = control.as_mut_ptr().cast();
                // SAFETY: `CMSG_SPACE` only computes a size.
                header.msg_controllen = unsafe { libc::CMSG_SPACE(fd_size) } as _;
                // SAFETY: The control buffer has room for one descriptor's message.
                unsafe {
                    let message = libc::CMSG_FIRSTHDR(&raw const header);
                    (*message).cmsg_level = libc::SOL_SOCKET;
                    (*message).cmsg_type = libc::SCM_RIGHTS;
                    (*message).cmsg_len = libc::CMSG_LEN(fd_size) as _;
                    libc::CMSG_DATA(message).cast::<i32>().write_unaligned(fd);
                }
            }
            // SAFETY: `header` describes buffers that live across the call.
            let sent = unsafe { libc::sendmsg(broker.as_raw_fd(), &raw const header, 0) };
            assert_eq!(sent, 8);
        };
        // Messages whose descriptors were lost, as when this process ran out of them, fail
        // their requesters whether they wait for them or not, and later ones still arrive.
        send(1, None);
        send(2, None);
        send(3, Some(file.as_raw_fd()));
        assert_eq!(channel.take(1).unwrap_err().kind(), ErrorKind::InvalidData);
        channel.take(3).unwrap();
        assert_eq!(channel.take(2).unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn closed_socket_fails_instead_of_blocking() {
        let (sender, receiver) = SharedObjectSender::pair().unwrap();
        let channel = SharedObjectChannel::new(receiver);
        drop(sender);
        assert_eq!(
            channel.take(1).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}
