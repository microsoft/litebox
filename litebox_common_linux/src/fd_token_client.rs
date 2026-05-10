// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Worker-side client for the broker fd-token control socket.
//!
//! A worker connects to the broker once at startup (typically alongside
//! the existing `connect_to_broker_ipc` / `connect_nine_p_channel`
//! handshakes) and keeps the resulting `FdTokenClient` for the lifetime
//! of the worker. Each cross-worker `SCM_RIGHTS` send / receive uses
//! the client to round-trip with the broker:
//!
//! - **Send path**: for each host fd in `Message.passed_fds`, call
//!   [`FdTokenClient::register`] to obtain a token id; encode the token
//!   ids into an [`fd_transfer_frame::FdTransferFrame`]; write the frame
//!   onto the smoltcp byte stream.
//!
//! - **Recv path**: decode an [`fd_transfer_frame::FdTransferFrame`] off
//!   the smoltcp byte stream; for each token id, call
//!   [`FdTokenClient::materialize`] to obtain a fresh host fd; install
//!   each fd into the receiver's `PassedFd` list.
//!
//! - **Lifecycle**: the *receiver* invokes [`FdTokenClient::release`]
//!   after materialization; the *sender* never has to release because
//!   the broker takes ownership of the registered fd via SCM_RIGHTS.
//!   Concretely the broker registers with refcount=1, the materialize
//!   returns a fresh dup; release brings refcount back to 0 and closes
//!   the broker's host fd.
//!
//! # Concurrency
//!
//! [`FdTokenClient`] holds the underlying [`std::os::unix::net::UnixStream`]
//! behind a [`std::sync::Mutex`]. The protocol is strictly request /
//! response, so concurrent callers serialize through the mutex. A worker
//! that needs throughput beyond a single round-trip per call can hold
//! multiple `FdTokenClient` instances bound to multiple control sockets
//! on the broker.
//!
//! # Phase boundary
//!
//! This module is **Phase 3c-i** of the cross-worker fd transport plan:
//! the worker-side counterpart to [`crate::fd_token_protocol`] and (in
//! the broker crate) `fd_token_socket`. It does not yet plumb into
//! `litebox_shim_linux`; that wiring lives in Phase 3c-ii.
//!
//! [`fd_transfer_frame::FdTransferFrame`]: crate::fd_transfer_frame::FdTransferFrame

use crate::fd_token_protocol::{CTRL_FRAME_LEN, Frame, Opcode, ProtocolError, StatusCode, decode};
use std::format;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

/// Errors returned by [`FdTokenClient`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io error talking to broker control socket: {0}")]
    Io(#[from] io::Error),

    #[error("protocol error from broker: {0}")]
    Protocol(ProtocolError),

    #[error("broker returned unexpected response opcode {actual:?} (expected {expected:?})")]
    UnexpectedOpcode { expected: Opcode, actual: Opcode },

    #[error("broker returned StatusCode::Protocol — this client violated the protocol")]
    BrokerRejectedProtocol,

    #[error("broker returned StatusCode::UnknownToken for id {token_id}")]
    UnknownToken { token_id: u64 },

    #[error("broker returned StatusCode::Internal for opcode {opcode:?}")]
    BrokerInternal { opcode: Opcode },

    #[error("broker returned StatusCode {status:?} for opcode {opcode:?}")]
    OtherStatus { opcode: Opcode, status: StatusCode },

    #[error("broker response carried unexpected fd attachment for opcode {opcode:?}")]
    UnexpectedFdAttachment { opcode: Opcode },

    #[error("broker response missing required fd attachment for opcode {opcode:?}")]
    MissingFdAttachment { opcode: Opcode },

    #[error("broker control socket short-read: got {got} bytes, expected {CTRL_FRAME_LEN}")]
    ShortRead { got: usize },

    #[error("broker SCM_RIGHTS payload was truncated by the kernel")]
    CmsgTruncated,
}

/// A connected, ready-to-use client for the broker's fd-token control socket.
pub struct FdTokenClient {
    stream: Mutex<UnixStream>,
}

impl FdTokenClient {
    /// Connects to the broker control socket at `path` and returns a
    /// ready-to-use client. The socket is held for the lifetime of the
    /// returned value; dropping the client closes it (the broker side
    /// will see EOF and tear down the per-connection thread).
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }

    /// Registers `fd` with the broker and returns its token id. The fd
    /// is consumed and passed via `SCM_RIGHTS`; the broker takes
    /// ownership and the worker no longer holds a reference.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex was poisoned by a prior panicking
    /// caller. Recovery from a poisoned client is not supported; callers
    /// should drop the client and reconnect.
    pub fn register(&self, fd: OwnedFd) -> Result<u64, ClientError> {
        let stream = self.stream.lock().expect("FdTokenClient mutex poisoned");
        send_frame(&stream, Frame::register_request(), Some(&fd))?;
        // Drop our reference now that the broker holds one. (sendmsg
        // already duplicated the fd into the broker; closing here is
        // the worker giving up its own fd.)
        drop(fd);
        let (resp, attached) = recv_frame(&stream)?;
        check_opcode(resp, Opcode::RegisterResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(resp.payload),
            StatusCode::Protocol => Err(ClientError::BrokerRejectedProtocol),
            StatusCode::Internal | StatusCode::RegisterFailed => Err(ClientError::BrokerInternal {
                opcode: resp.opcode,
            }),
            other => Err(ClientError::OtherStatus {
                opcode: resp.opcode,
                status: other,
            }),
        }
    }

    /// Materializes a fresh host fd for `token_id`. The returned fd
    /// aliases the same kernel object as the original registered fd.
    /// Caller is responsible for closing (drop) the returned fd when
    /// done; calling [`Self::release`] is a *separate* refcount
    /// decrement on the broker registry, not an fd close.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex was poisoned by a prior panicking
    /// caller.
    pub fn materialize(&self, token_id: u64) -> Result<OwnedFd, ClientError> {
        let stream = self.stream.lock().expect("FdTokenClient mutex poisoned");
        send_frame(&stream, Frame::materialize_request(token_id), None)?;
        let (resp, attached) = recv_frame(&stream)?;
        check_opcode(resp, Opcode::MaterializeResponse)?;
        match resp.status {
            StatusCode::Ok => attached.ok_or(ClientError::MissingFdAttachment {
                opcode: resp.opcode,
            }),
            StatusCode::UnknownToken => Err(ClientError::UnknownToken { token_id }),
            StatusCode::Protocol => Err(ClientError::BrokerRejectedProtocol),
            StatusCode::MaterializeFailed | StatusCode::Internal => {
                Err(ClientError::BrokerInternal {
                    opcode: resp.opcode,
                })
            }
            other @ StatusCode::RegisterFailed => Err(ClientError::OtherStatus {
                opcode: resp.opcode,
                status: other,
            }),
        }
    }

    /// Decrements the broker registry's refcount for `token_id`. When
    /// the refcount reaches zero the broker closes the underlying host
    /// fd (which it has held since [`Self::register`]).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex was poisoned by a prior panicking
    /// caller.
    pub fn release(&self, token_id: u64) -> Result<(), ClientError> {
        let stream = self.stream.lock().expect("FdTokenClient mutex poisoned");
        send_frame(&stream, Frame::release_request(token_id), None)?;
        let (resp, attached) = recv_frame(&stream)?;
        check_opcode(resp, Opcode::ReleaseResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownToken => Err(ClientError::UnknownToken { token_id }),
            StatusCode::Protocol => Err(ClientError::BrokerRejectedProtocol),
            StatusCode::Internal => Err(ClientError::BrokerInternal {
                opcode: resp.opcode,
            }),
            other => Err(ClientError::OtherStatus {
                opcode: resp.opcode,
                status: other,
            }),
        }
    }
}

fn check_opcode(resp: Frame, expected: Opcode) -> Result<(), ClientError> {
    if resp.opcode == expected {
        Ok(())
    } else {
        Err(ClientError::UnexpectedOpcode {
            expected,
            actual: resp.opcode,
        })
    }
}

fn send_frame(stream: &UnixStream, frame: Frame, fd: Option<&OwnedFd>) -> Result<(), ClientError> {
    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let bytes = frame.encode_to_array();
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: CTRL_FRAME_LEN,
    };
    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    if let Some(f) = fd {
        // SAFETY: zero-init union, reading buf field is sound.
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = CMSG_SPACE as _;
        }
        // SAFETY: cmsg_buf has CMSG_SPACE for one fd.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        debug_assert!(!cmsg.is_null());
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
            }
            // SAFETY: CMSG_DATA returns a pointer immediately after a
            // `cmsghdr`, which on every supported Linux ABI is aligned
            // to at least 4 bytes (the alignment of `i32`). The same
            // pattern is used in `litebox_broker::net_proxy::recv_ring_fds`
            // and `litebox_broker::fd_token_socket::write_response`.
            #[allow(clippy::cast_ptr_alignment)]
            let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
            std::ptr::write_unaligned(data_ptr, f.as_raw_fd());
        }
    }

    // SAFETY: stream is open; msg points at properly initialised buffers.
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    if (n as usize) != CTRL_FRAME_LEN {
        return Err(ClientError::Io(io::Error::other(format!(
            "short sendmsg on broker control socket: wrote {n}/{CTRL_FRAME_LEN} bytes",
        ))));
    }
    Ok(())
}

fn recv_frame(stream: &UnixStream) -> Result<(Frame, Option<OwnedFd>), ClientError> {
    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let mut frame_buf = [0u8; CTRL_FRAME_LEN];
    let mut iov = libc::iovec {
        iov_base: frame_buf.as_mut_ptr().cast(),
        iov_len: CTRL_FRAME_LEN,
    };
    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: zero-init union; reading the `buf` field is sound.
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    // SAFETY: stream open, msg points at owned local buffers.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    let n_usize = n as usize;
    if n_usize == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    if n_usize != CTRL_FRAME_LEN {
        return Err(ClientError::ShortRead { got: n_usize });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(ClientError::CmsgTruncated);
    }

    let mut received_fd: Option<OwnedFd> = None;
    // SAFETY: msg filled by successful recvmsg.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: kernel-validated pointer.
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: kernel-placed fd array.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            // SAFETY: produced by kernel into our process.
            let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
            // SAFETY: this fd is freshly owned by us.
            received_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        // SAFETY: standard cmsg iteration.
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    let frame = decode(&frame_buf).map_err(ClientError::Protocol)?;
    Ok((frame, received_fd))
}

// -- Process-global client accessor ------------------------------------------
//
// The cross-worker fd-transport path needs a single FdTokenClient per worker
// process, established once at runner bootstrap and referenced from any
// `UnixTransport::Tcp` send/recv site. A `OnceLock<Arc<FdTokenClient>>` is
// the simplest fit: the runner sets it once before any guest code runs;
// the shim reads it on demand.
//
// Returning `None` means "fd-token transport is not enabled in this
// configuration" — for example when the runner was started without a
// broker control socket. Callers MUST handle that case explicitly:
// either fall back to legacy behaviour (drop passed_fds, matching the
// pre-3c behaviour) or refuse the operation. The shim integration in
// Phase 3c-ii will choose fall-back so that a partial rollout doesn't
// regress any tests that don't depend on cross-worker SCM_RIGHTS.

static GLOBAL_CLIENT: OnceLock<Arc<FdTokenClient>> = OnceLock::new();

/// Sets the process-global [`FdTokenClient`]. Intended to be called
/// exactly once during runner bootstrap. Returns `Err(client)` if a
/// client was already set; callers can choose whether to log+drop or
/// panic on that case (in practice it indicates a bootstrap bug).
pub fn set_global_client(client: Arc<FdTokenClient>) -> Result<(), Arc<FdTokenClient>> {
    GLOBAL_CLIENT.set(client)
}

/// Returns the process-global [`FdTokenClient`] if one has been set.
/// Returns `None` if the runner did not initialise the fd-token
/// transport for this process.
pub fn global_client() -> Option<Arc<FdTokenClient>> {
    GLOBAL_CLIENT.get().cloned()
}

#[cfg(test)]
mod global_tests {
    use super::*;

    /// We can't directly test set/get because OnceLock is process-global
    /// and other tests in this binary may have already initialised it.
    /// This test validates only that calling `global_client()` does not
    /// panic on an uninitialised state, and the documented contract holds:
    /// returning `None` is the unset case.
    ///
    /// Real coverage of set+get round trips lives in integration tests
    /// in `litebox_broker::fd_token_socket::tests` where each test
    /// constructs its own client; the global is only exercised from the
    /// shim integration in Phase 3c-ii.
    #[test]
    fn global_client_is_none_or_some_without_panic() {
        // Either Some (already set by another test) or None — both fine.
        let _ = global_client();
    }
}
