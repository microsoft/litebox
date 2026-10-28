// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Receiving host shared objects that the broker delivers out of band.
//!
//! The broker answers a request for a shared object, such as the memfd backing a shared file,
//! with a token, after it has sent the object's descriptor tagged with the same token over a
//! dedicated `SOCK_SEQPACKET` socket. Concurrent requests may complete in any order, so
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
    /// many others were waiting for their requesters.
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
                return Ok(fd);
            }
            if state.pending.len() >= MAX_PENDING
                && let Some((dropped, _)) = state.pending.pop_first()
            {
                if state.evicted.len() >= MAX_EVICTED {
                    state.evicted.pop_first();
                }
                state.evicted.insert(dropped);
            }
            state.pending.insert(received, fd);
        }
    }
}

/// Receives one message: an 8-byte token with exactly one descriptor.
fn receive(socket: &OwnedFd) -> Result<(u64, OwnedFd)> {
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
    if received.cast_unsigned() != token.len()
        || header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || fds.len() != 1
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "malformed shared-object message from the broker",
        ));
    }
    Ok((u64::from_le_bytes(token), fds.pop().unwrap()))
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
        let tokens: Vec<u64> = (0..=MAX_PENDING + 1)
            .map(|_| sender.send(file.as_fd()).unwrap())
            .collect();
        // Taking the last one queues the others, dropping the oldest beyond the limit.
        channel.take(*tokens.last().unwrap()).unwrap();
        assert_eq!(
            channel.take(tokens[0]).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        channel.take(tokens[2]).unwrap();
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
