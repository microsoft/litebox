// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Receiving host shared objects that the broker delivers out of band.
//!
//! The broker answers a request for a shared object, such as the memfd backing a shared file,
//! with a token, after it has sent the object's descriptor tagged with the same token over a
//! dedicated `SOCK_SEQPACKET` socket. Concurrent requests may complete in any order, so
//! descriptors that arrive for other tokens wait here until their requester takes them.

use std::collections::BTreeMap;
use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::Mutex;

/// Descriptors received ahead of their requester are dropped beyond this many, oldest first, so
/// that a broker cannot make this process hold descriptors without bound.
const MAX_PENDING: usize = 64;

/// The receiving end of the broker's shared-object socket.
pub(crate) struct SharedObjectChannel {
    state: Mutex<State>,
}

struct State {
    socket: OwnedFd,
    pending: BTreeMap<u64, OwnedFd>,
}

impl SharedObjectChannel {
    pub(crate) fn new(socket: OwnedFd) -> Self {
        Self {
            state: Mutex::new(State {
                socket,
                pending: BTreeMap::new(),
            }),
        }
    }

    /// Takes the descriptor that the broker sent under `token`, waiting for it if it has not
    /// been received yet.
    pub(crate) fn take(&self, token: u64) -> Result<OwnedFd> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(fd) = state.pending.remove(&token) {
                return Ok(fd);
            }
            let (received, fd) = receive(&state.socket)?;
            if received == token {
                return Ok(fd);
            }
            if state.pending.len() >= MAX_PENDING {
                state.pending.pop_first();
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
    // SAFETY: `header` was filled in by `recvmsg`, and each control message lies within
    // `control`.
    unsafe {
        let mut message = libc::CMSG_FIRSTHDR(&raw const header);
        while !message.is_null() {
            if (*message).cmsg_level == libc::SOL_SOCKET && (*message).cmsg_type == libc::SCM_RIGHTS
            {
                let data = libc::CMSG_DATA(message).cast::<libc::c_int>();
                let header_len = libc::CMSG_LEN(0) as usize;
                let count = ((*message).cmsg_len as usize - header_len) / size_of::<libc::c_int>();
                for index in 0..count {
                    let fd = data.add(index).read_unaligned();
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            message = libc::CMSG_NXTHDR(&raw const header, message);
        }
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
    use std::os::fd::AsFd as _;

    #[expect(
        clippy::cast_possible_truncation,
        reason = "a descriptor is four bytes"
    )]
    const FD_SIZE: u32 = size_of::<libc::c_int>() as u32;

    fn send(socket: &OwnedFd, token: u64, fd: std::os::fd::BorrowedFd<'_>) {
        let token = token.to_le_bytes();
        let mut iov = libc::iovec {
            iov_base: token.as_ptr().cast_mut().cast(),
            iov_len: token.len(),
        };
        let mut control = [0u64; 4];
        // SAFETY: `msghdr` is plain data, for which all-zero bytes are valid.
        let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
        header.msg_iov = &raw mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast();
        // SAFETY: `CMSG_SPACE` only computes a size.
        header.msg_controllen = unsafe { libc::CMSG_SPACE(FD_SIZE) } as _;
        // SAFETY: `control` is large enough for one descriptor.
        unsafe {
            let message = libc::CMSG_FIRSTHDR(&raw const header);
            (*message).cmsg_level = libc::SOL_SOCKET;
            (*message).cmsg_type = libc::SCM_RIGHTS;
            (*message).cmsg_len = libc::CMSG_LEN(FD_SIZE) as _;
            libc::CMSG_DATA(message)
                .cast::<libc::c_int>()
                .write_unaligned(fd.as_raw_fd());
        }
        // SAFETY: `header` describes live buffers.
        let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &raw const header, 0) };
        assert_eq!(sent, 8);
    }

    fn socket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for both ends.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
        // SAFETY: `socketpair` returned two new descriptors.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn inode(fd: &OwnedFd) -> u64 {
        std::fs::File::from(fd.try_clone().unwrap())
            .metadata()
            .map(|metadata| std::os::unix::fs::MetadataExt::ino(&metadata))
            .unwrap()
    }

    #[test]
    fn takes_descriptors_by_token_in_any_order() {
        let (sender, receiver) = socket_pair();
        let channel = SharedObjectChannel::new(receiver);
        let first = std::fs::File::open("/").unwrap();
        let second = std::fs::File::open("/proc").unwrap();
        send(&sender, 1, first.as_fd());
        send(&sender, 2, second.as_fd());

        let second_received = channel.take(2).unwrap();
        let first_received = channel.take(1).unwrap();
        assert_eq!(inode(&second_received), inode(&OwnedFd::from(second)));
        assert_eq!(inode(&first_received), inode(&OwnedFd::from(first)));
    }

    #[test]
    fn closed_socket_fails_instead_of_blocking() {
        let (sender, receiver) = socket_pair();
        let channel = SharedObjectChannel::new(receiver);
        drop(sender);
        assert_eq!(
            channel.take(1).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}
