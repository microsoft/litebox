// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket I/O directly between a socket and a buffer's [`RawBytes`], with no
//! bounce buffer.
//!
//! A socket call gets its bytes as [`RawParts`]: the buffer's own raw bytes,
//! which the kernel copies with one system call, or, for a buffer without
//! them, such as a guest's memory, a copy staged in a `Vec`. A buffer with
//! more than [`MAX_RAW_PARTS`] parts is staged too, so a datagram still moves
//! whole in one call. A send stages before its socket is locked and a receive
//! copies out after, so the socket's lock is never held across a copy that
//! may fault.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsFd, AsRawFd};
use std::ptr;

use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::shared_buffer::MAX_SHARED_BUFFER_SEQUENCE_SLOTS;
use litebox_broker_protocol::socket::SocketOutcome;
use litebox_platform::buffer::{RawBytes, ReadBuffer, WriteBuffer};
use rustix::io::Errno;
use rustix::net::{RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags};

use super::zeroed_vec;

/// The most parts a socket transfers directly: as many as a shared buffer
/// has, so its bytes always transfer directly.
pub(super) const MAX_RAW_PARTS: usize = MAX_SHARED_BUFFER_SEQUENCE_SLOTS;

/// The bytes a socket call sends from or receives into: at most
/// [`MAX_RAW_PARTS`] parts of [`RawBytes`], in order.
#[derive(Clone, Copy)]
pub(super) struct RawParts<'a> {
    parts: &'a [RawBytes<'a>],
}

impl RawParts<'static> {
    /// No bytes.
    pub(super) const EMPTY: Self = Self { parts: &[] };
}

impl<'a> RawParts<'a> {
    /// Returns `parts`, or `None` if there are more than [`MAX_RAW_PARTS`].
    fn new(parts: &'a [RawBytes<'a>]) -> Option<Self> {
        (parts.len() <= MAX_RAW_PARTS).then_some(Self { parts })
    }

    /// Returns the length in bytes.
    pub(super) fn len(self) -> usize {
        self.parts.iter().map(RawBytes::len).sum()
    }

    /// Returns the parts.
    pub(super) fn parts(self) -> &'a [RawBytes<'a>] {
        self.parts
    }

    /// Copies `source` into the start of the bytes.
    ///
    /// # Panics
    ///
    /// Panics if `source` is longer than the bytes.
    pub(super) fn copy_from_slice(self, source: &[u8]) {
        copy_into_parts(self.parts, source);
    }

    /// Copies the bytes into `destination`, which must be the same length.
    ///
    /// # Panics
    ///
    /// Panics if the lengths differ.
    pub(super) fn copy_to_slice(self, destination: &mut [u8]) {
        copy_from_parts(self.parts, destination);
    }

    /// Returns an iovec for each part, followed by empty ones.
    fn iovecs(self) -> [libc::iovec; MAX_RAW_PARTS] {
        let mut iovecs = [libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        }; MAX_RAW_PARTS];
        for (iovec, part) in iovecs.iter_mut().zip(self.parts) {
            *iovec = libc::iovec {
                iov_base: part.as_ptr().cast(),
                iov_len: part.len(),
            };
        }
        iovecs
    }

    /// Returns the address and length of the bytes, if they are in at most
    /// one part.
    fn contiguous(self) -> Option<(*mut libc::c_void, usize)> {
        match self.parts {
            [] => Some((ptr::null_mut(), 0)),
            [part] => Some((part.as_ptr().cast(), part.len())),
            _ => None,
        }
    }
}

impl<'a> From<&'a [RawBytes<'a>; 1]> for RawParts<'a> {
    fn from(part: &'a [RawBytes<'a>; 1]) -> Self {
        Self { parts: part }
    }
}

/// Copies `source` into the start of `parts`, in order.
///
/// # Panics
///
/// Panics if `source` is longer than the parts.
fn copy_into_parts(parts: &[RawBytes<'_>], mut source: &[u8]) {
    for part in parts {
        if source.is_empty() {
            return;
        }
        let (head, rest) = source.split_at(part.len().min(source.len()));
        part.subrange(0..head.len()).copy_from_slice(head);
        source = rest;
    }
    assert!(source.is_empty(), "source exceeds the raw parts");
}

/// Copies `parts`, in order, into `destination`, which must be as long as
/// they are.
///
/// # Panics
///
/// Panics if the lengths differ.
fn copy_from_parts(parts: &[RawBytes<'_>], mut destination: &mut [u8]) {
    for part in parts {
        let (head, rest) = destination.split_at_mut(part.len());
        part.copy_to_slice(head);
        destination = rest;
    }
    assert!(destination.is_empty(), "destination exceeds the raw parts");
}

/// Sends `data` with `send`, which returns how many bytes it sent.
///
/// `send` gets `data`'s own raw bytes if it has them in at most
/// [`MAX_RAW_PARTS`] parts, and otherwise a copy, made before `send` runs.
pub(super) fn send_from(
    data: &dyn WriteBuffer,
    send: impl FnOnce(RawParts<'_>) -> BrokerResult<SocketOutcome<usize>>,
) -> BrokerResult<SocketOutcome<usize>> {
    let mut send = Some(send);
    let mut result = None;
    data.write_direct_at(0, data.len(), &mut |parts| {
        let Some(send) = send.take() else { return 0 };
        let outcome = match RawParts::new(parts) {
            Some(parts) => send(parts),
            None => zeroed_vec(parts.iter().map(RawBytes::len).sum()).and_then(|mut staged| {
                copy_from_parts(parts, &mut staged);
                send(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))
            }),
        };
        let count = match outcome {
            Ok(SocketOutcome::Completed(count)) => count,
            _ => 0,
        };
        result = Some(outcome);
        count
    });
    if let Some(result) = result {
        return result;
    }
    let send = send.ok_or(BrokerError::Internal)?;
    let mut staged = zeroed_vec(data.len())?;
    data.copy_to_slice_at(0, &mut staged)?;
    send(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))
}

/// Receives into `output` with `receive`; `received` returns how many bytes
/// an outcome received into the start of the parts.
///
/// `receive` gets `output`'s own raw bytes if it has them in at most
/// [`MAX_RAW_PARTS`] parts, and otherwise a staged buffer, copied into
/// `output` after `receive` returns.
pub(super) fn receive_into<T>(
    output: &mut dyn ReadBuffer,
    received: impl Fn(&T) -> usize,
    receive: impl FnOnce(RawParts<'_>) -> BrokerResult<T>,
) -> BrokerResult<T> {
    let length = output.len();
    let mut receive = Some(receive);
    let mut result = None;
    output.read_direct_at(0, length, &mut |parts| {
        let Some(receive) = receive.take() else {
            return 0;
        };
        let outcome = match RawParts::new(parts) {
            Some(parts) => receive(parts),
            None => zeroed_vec(length).and_then(|mut staged| {
                let outcome = receive(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))?;
                copy_into_parts(parts, &staged[..received(&outcome)]);
                Ok(outcome)
            }),
        };
        let count = outcome.as_ref().map_or(0, &received);
        result = Some(outcome);
        count
    });
    if let Some(result) = result {
        return result;
    }
    let receive = receive.ok_or(BrokerError::Internal)?;
    let mut staged = zeroed_vec(length)?;
    let outcome = receive(RawParts::from(&[RawBytes::from(staged.as_mut_slice())]))?;
    output.copy_from_slice_at(0, &staged[..received(&outcome)])?;
    Ok(outcome)
}

/// Sends `data` on `socket` with one system call, to `destination` if set,
/// and returns how many bytes it sent.
///
/// Bytes in at most one part go with `sendto`, which costs less per call
/// than `sendmsg`.
pub(super) fn send_parts(
    socket: impl AsFd,
    data: RawParts<'_>,
    destination: Option<SocketAddrV4>,
    flags: LinuxSendFlags,
) -> Result<usize, Errno> {
    let socket = socket.as_fd().as_raw_fd();
    let flags = flags.bits().cast_signed();
    let mut address = destination.map(sockaddr_in);
    let (name, name_length) = match address.as_mut() {
        Some(address) => (ptr::from_mut(address), SOCKADDR_IN_LENGTH),
        None => (ptr::null_mut(), 0),
    };
    let sent = if let Some((bytes, length)) = data.contiguous() {
        // SAFETY: `address` outlives the call, and the `length` bytes at
        // `bytes` are raw bytes that are readable for the call and that the
        // kernel reads without Rust references to them.
        unsafe { libc::sendto(socket, bytes, length, flags, name.cast(), name_length) }
    } else {
        let mut iovecs = data.iovecs();
        let message = libc::msghdr {
            msg_name: name.cast(),
            msg_namelen: name_length,
            msg_iov: iovecs.as_mut_ptr(),
            msg_iovlen: data.parts.len(),
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: The message refers to `address` and `iovecs`, which outlive
        // the call. Each iovec covers raw bytes that are readable for the call
        // and that the kernel reads without Rust references to them.
        unsafe { libc::sendmsg(socket, &raw const message, flags) }
    };
    usize::try_from(sent).map_err(|_| last_errno())
}

/// Receives into `output` from `socket` with one system call.
///
/// Returns what the call returned, which with `TRUNC` on a datagram socket is
/// the datagram's full length, and the source address, if the socket reports
/// an IPv4 one. An `output` in at most one part is received with `recvfrom`,
/// which costs less per call than `recvmsg`.
pub(super) fn receive_parts(
    socket: impl AsFd,
    output: RawParts<'_>,
    flags: LinuxRecvFlags,
) -> Result<(usize, Option<SocketAddrV4>), Errno> {
    let socket = socket.as_fd().as_raw_fd();
    let flags = flags.bits().cast_signed();
    let mut address = libc::sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut address_length = SOCKADDR_IN_LENGTH;
    let received = if let Some((bytes, length)) = output.contiguous() {
        // SAFETY: `address` and `address_length` outlive the call, and the
        // `length` bytes at `bytes` are raw bytes that are writable for the
        // call and that the kernel fills without Rust references to them.
        unsafe {
            libc::recvfrom(
                socket,
                bytes,
                length,
                flags,
                ptr::from_mut(&mut address).cast(),
                &raw mut address_length,
            )
        }
    } else {
        let mut iovecs = output.iovecs();
        let mut message = libc::msghdr {
            msg_name: ptr::from_mut(&mut address).cast(),
            msg_namelen: address_length,
            msg_iov: iovecs.as_mut_ptr(),
            msg_iovlen: output.parts.len(),
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: The message refers to `address` and `iovecs`, which outlive
        // the call. Each iovec covers raw bytes that are writable for the call
        // and that the kernel fills without Rust references to them.
        let received = unsafe { libc::recvmsg(socket, &raw mut message, flags) };
        address_length = message.msg_namelen;
        received
    };
    let received = usize::try_from(received).map_err(|_| last_errno())?;
    let source =
        (address_length == SOCKADDR_IN_LENGTH && address.sin_family == AF_INET).then(|| {
            SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )
        });
    Ok((received, source))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const AF_INET: libc::sa_family_t = libc::AF_INET as libc::sa_family_t;

#[allow(clippy::cast_possible_truncation)]
const SOCKADDR_IN_LENGTH: libc::socklen_t = size_of::<libc::sockaddr_in>() as libc::socklen_t;

fn sockaddr_in(address: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

/// Returns the error of the last failed system call.
fn last_errno() -> Errno {
    Errno::from_raw_os_error(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}
