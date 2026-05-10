// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker control-socket plumbing for the fd-token protocol.
//!
//! This module bridges:
//!
//! - the wire-format codec ([`litebox_common_linux::fd_token_protocol`]),
//! - the per-request handlers ([`crate::fd_token_service`]),
//! - and the actual `sendmsg`/`recvmsg` syscalls on a Unix domain socket.
//!
//! Each worker connects to the broker on a dedicated control socket
//! (one per worker). The broker accept-loop spawns a thread per accepted
//! connection that reads a 16-byte request frame plus an optional
//! `SCM_RIGHTS`-attached fd, dispatches via `handle_request`, and writes
//! a 16-byte response frame plus an optional outgoing fd.
//!
//! # Recv side: SCM_RIGHTS handling
//!
//! `recvmsg(2)` is invoked with a control buffer sized for one fd. The
//! buffer is unioned with `cmsghdr` to guarantee proper alignment, then
//! walked via `CMSG_FIRSTHDR`/`CMSG_NXTHDR`. Any `SCM_RIGHTS` ancillary
//! is processed strictly: a message that announces an unexpected fd
//! count is treated as a protocol violation and the socket is closed.
//! Truncated control messages (`MSG_CTRUNC`) are likewise fatal.
//!
//! `MSG_CMSG_CLOEXEC` ensures the inherited fd is `O_CLOEXEC` so a
//! subsequent fork+exec inside this thread (none today, but defence in
//! depth) cannot leak it.
//!
//! # Send side
//!
//! `sendmsg(2)` carries the response frame and (when present) the
//! materialized fd. A short send fails the connection — control frames
//! are 16 bytes plus at most one fd, well below any kernel buffer.
//!
//! # Phase boundary
//!
//! This module is **Phase 3b-iii** of the cross-worker fd transport
//! plan: a real, accept-looping listener exercising `handle_request`
//! end-to-end over a Unix socket. It is not yet started by the broker
//! main loop; that wire-up is part of Phase 3c, after the worker side
//! exists.

use crate::fd_token_service::{HandlerFatal, handle_request};
use crate::fd_tokens::BrokerFdTokenRegistry;
use litebox_common_linux::fd_token_protocol::{CTRL_FRAME_LEN, Frame, decode};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing::{debug, info, warn};

/// Errors observed while reading or writing one control-frame round.
/// All variants close the connection.
#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("client closed control connection")]
    PeerClosed,

    #[error("io error on control socket: {0}")]
    Io(#[from] std::io::Error),

    #[error("control frame truncated: read {read} bytes, expected {CTRL_FRAME_LEN}")]
    FrameShortRead { read: usize },

    #[error("control frame had truncated SCM_RIGHTS payload")]
    CmsgTruncated,

    #[error("control frame announced opcode requires {expected} fd(s), got {actual}")]
    FdCountMismatch { expected: usize, actual: usize },

    #[error("malformed SCM_RIGHTS cmsg header")]
    MalformedCmsg,

    #[error("protocol decode error: {0}")]
    Decode(litebox_common_linux::fd_token_protocol::ProtocolError),

    #[error("handler reported fatal protocol violation: {0}")]
    HandlerFatal(#[from] HandlerFatal),
}

/// Reads exactly one request frame plus zero or one `SCM_RIGHTS` fd
/// from `stream`. Returns `(frame, optional_fd)` on success.
fn read_request(stream: &UnixStream) -> Result<(Frame, Option<OwnedFd>), ConnError> {
    // Control buffer big enough for exactly one fd.
    // SAFETY: CMSG_SPACE is `const unsafe fn` but is purely a layout calculation.
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
    // SAFETY: zero-initialised union; reading the `buf` field is sound.
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    let raw_fd = stream.as_raw_fd();
    // SAFETY: raw_fd is the owned UnixStream's fd; msg points at properly
    // initialised local buffers.
    let n = unsafe { libc::recvmsg(raw_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if n == 0 {
        return Err(ConnError::PeerClosed);
    }
    #[allow(clippy::cast_sign_loss)] // n > 0 here
    let n_usize = n as usize;
    if n_usize != CTRL_FRAME_LEN {
        return Err(ConnError::FrameShortRead { read: n_usize });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(ConnError::CmsgTruncated);
    }

    // Walk the control messages looking for SCM_RIGHTS.
    let mut received_fd: Option<OwnedFd> = None;
    // SAFETY: msg was filled by a successful recvmsg; CMSG_FIRSTHDR/NXTHDR
    // are the standard cmsg-walking primitives.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: cmsg is a kernel-validated pointer returned by CMSG_FIRSTHDR.
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: kernel places the fd array immediately after the cmsghdr.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            // SAFETY: CMSG_LEN(0) returns the cmsghdr-size baseline; comparing
            // against cmsg_len bounds the data region.
            let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
            if (hdr.cmsg_len as usize) < header_len {
                return Err(ConnError::MalformedCmsg);
            }
            let fd_count = ((hdr.cmsg_len as usize) - header_len) / size_of::<i32>();
            if fd_count > 1 {
                // Reject and close all received fds to avoid a leak.
                for i in 0..fd_count {
                    // SAFETY: data_ptr points to fd_count consecutive i32 values
                    // owned by this process after recvmsg.
                    let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                    // SAFETY: `raw` is an fd just produced by the kernel into this
                    // process; we own it and must close it on the error path.
                    drop(unsafe { OwnedFd::from_raw_fd(raw) });
                }
                return Err(ConnError::FdCountMismatch {
                    expected: 0,
                    actual: fd_count,
                });
            }
            if fd_count == 1 {
                // SAFETY: kernel-allocated fd; this process owns it now.
                let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
                // SAFETY: ditto.
                received_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        // SAFETY: standard cmsg iteration; CMSG_NXTHDR may return null.
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    let frame = decode(&frame_buf).map_err(ConnError::Decode)?;

    // We deliberately do NOT validate frame.opcode.expected_fd_count() against
    // the received fd count here — that's a per-opcode protocol check, owned
    // by the handlers (handle_register, handle_materialize, handle_release).
    // The handlers turn an opcode/fd-count mismatch into a StatusCode::Protocol
    // response so the worker can observe and recover; closing the socket from
    // the framing layer would deny the worker that diagnostic.

    Ok((frame, received_fd))
}

/// Sends a response frame plus an optional `SCM_RIGHTS` fd over `stream`.
fn write_response(
    stream: &UnixStream,
    frame: Frame,
    out_fd: Option<OwnedFd>,
) -> Result<(), ConnError> {
    // CMSG_SPACE for at most one fd.
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

    let cmsg_present = out_fd.is_some();
    if cmsg_present {
        // SAFETY: zero-initialised union, reading buf field is sound.
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = CMSG_SPACE as _;
        }

        // Populate the SCM_RIGHTS cmsg.
        // SAFETY: cmsg_buf is large enough for one fd (CMSG_SPACE above).
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        debug_assert!(!cmsg.is_null());
        // SAFETY: cmsg points into our local buffer; we own it.
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
            }
            // Place the fd in the cmsg payload.
            let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
            std::ptr::write_unaligned(data_ptr, out_fd.as_ref().unwrap().as_raw_fd());
        }
    }

    // SAFETY: stream is open; msg points at properly initialised buffers.
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    if (n as usize) != CTRL_FRAME_LEN {
        return Err(ConnError::Io(std::io::Error::other(format!(
            "short sendmsg on control socket: wrote {n}/{CTRL_FRAME_LEN} bytes",
        ))));
    }

    // out_fd drops here, closing the broker's reference. The kernel
    // duplicated it into the receiver's process during sendmsg.
    drop(out_fd);
    Ok(())
}

/// Runs the per-connection request/response loop until the peer closes
/// or an error is observed. Terminates the connection on any error.
pub fn handle_control_connection(stream: UnixStream, registry: Arc<BrokerFdTokenRegistry>) {
    loop {
        match read_request(&stream) {
            Ok((frame, in_fd)) => {
                let result = match handle_request(&registry, frame, in_fd) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "fd-token control: closing socket on fatal handler error");
                        return;
                    }
                };
                if let Err(e) = write_response(&stream, result.frame, result.out_fd) {
                    warn!(error = %e, "fd-token control: closing socket on write error");
                    return;
                }
            }
            Err(ConnError::PeerClosed) => {
                debug!("fd-token control: peer closed");
                return;
            }
            Err(e) => {
                warn!(error = %e, "fd-token control: closing socket on read error");
                return;
            }
        }
    }
}

/// Spawns a thread that listens on `path` (a Unix socket) and handles
/// each accepted connection on its own per-connection thread.
///
/// The listener thread runs until the listener is closed or an
/// unrecoverable accept error occurs. Returns the `JoinHandle` so the
/// broker main can join on shutdown if desired.
///
/// On entry, any pre-existing file at `path` is unlinked (`unlink(2)`),
/// matching the behaviour of `bind(2)` for fresh Unix sockets.
pub fn spawn_control_listener(
    path: &Path,
    registry: Arc<BrokerFdTokenRegistry>,
) -> std::io::Result<JoinHandle<()>> {
    // Best-effort unlink of any stale socket file from a prior run.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path)?;
    info!(path = %path.display(), "fd-token control listener bound");

    let path_owned = path.to_owned();
    let join = thread::Builder::new()
        .name("fd-token-listener".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let registry = Arc::clone(&registry);
                        if let Err(e) = thread::Builder::new()
                            .name("fd-token-conn".into())
                            .spawn(move || handle_control_connection(stream, registry))
                        {
                            warn!(error = %e, "failed to spawn fd-token connection thread");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path_owned.display(), "fd-token listener accept error");
                        // Most accept errors are transient; loop continues.
                    }
                }
            }
        })?;
    Ok(join)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::fd_token_protocol::{Opcode, StatusCode};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use tempfile::tempdir;

    /// Send a frame + optional fd from a client UnixStream. Mirrors the
    /// broker's write_response but is repackaged as a client helper.
    fn client_send(stream: &UnixStream, frame: Frame, fd: Option<&OwnedFd>) {
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
            msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
            #[allow(clippy::cast_possible_truncation)]
            {
                msg.msg_controllen = CMSG_SPACE as _;
            }
            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
            assert!(!cmsg.is_null());
            unsafe {
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                #[allow(clippy::cast_possible_truncation)]
                {
                    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
                }
                let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
                std::ptr::write_unaligned(data_ptr, f.as_raw_fd());
            }
        }

        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
        assert!(n > 0, "sendmsg failed: {}", std::io::Error::last_os_error());
        assert_eq!(n as usize, CTRL_FRAME_LEN);
    }

    /// Receive a frame + optional fd via a client UnixStream.
    fn client_recv(stream: &UnixStream) -> (Frame, Option<OwnedFd>) {
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
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = CMSG_SPACE as _;
        }

        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        assert!(
            n > 0,
            "recvmsg failed or peer closed: n={n}, errno={}",
            std::io::Error::last_os_error()
        );
        assert_eq!(n as usize, CTRL_FRAME_LEN);

        let mut received_fd: Option<OwnedFd> = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        while !cmsg.is_null() {
            let hdr = unsafe { &*cmsg };
            if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
                let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
                received_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
        }

        let frame = decode(&frame_buf).expect("decode response");
        (frame, received_fd)
    }

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        })
    }

    /// Spawn a listener and return (path, registry-arc, joinhandle).
    fn spawn_test_listener() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        Arc<BrokerFdTokenRegistry>,
    ) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let registry = Arc::new(BrokerFdTokenRegistry::new());
        let _ = spawn_control_listener(&path, Arc::clone(&registry)).expect("spawn listener");
        // Wait briefly for bind to settle (the spawn returns once bound).
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(path.exists(), "listener socket did not appear");
        (dir, path, registry)
    }

    #[test]
    fn end_to_end_register_materialize_release() {
        let (_dir, path, registry) = spawn_test_listener();
        let stream = UnixStream::connect(&path).expect("connect");

        // 1. Register a pipe read-end.
        let (r, w) = pipe_pair();
        client_send(&stream, Frame::register_request(), Some(&r));
        drop(r); // broker now holds the only reference; tests below verify aliasing.

        let (resp, fd) = client_recv(&stream);
        assert_eq!(resp.opcode, Opcode::RegisterResponse);
        assert_eq!(resp.status, StatusCode::Ok);
        assert!(fd.is_none());
        let token_id = resp.payload;
        assert!(token_id > 0);
        assert_eq!(registry.live_token_count(), 1);

        // 2. Materialize and read through the new fd.
        client_send(&stream, Frame::materialize_request(token_id), None);
        let (resp, fd) = client_recv(&stream);
        assert_eq!(resp.opcode, Opcode::MaterializeResponse);
        assert_eq!(resp.status, StatusCode::Ok);
        let mat_fd = fd.expect("response carries an fd");

        // Write through the original write end (still in this process).
        let mut writer = std::fs::File::from(w);
        writer.write_all(b"crossworker").unwrap();
        drop(writer);

        let mut reader = std::fs::File::from(mat_fd);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"crossworker");

        // 3. Release.
        client_send(&stream, Frame::release_request(token_id), None);
        let (resp, fd) = client_recv(&stream);
        assert_eq!(resp.opcode, Opcode::ReleaseResponse);
        assert_eq!(resp.status, StatusCode::Ok);
        assert!(fd.is_none());

        // Give the broker a moment to drop the registry entry (it does so
        // synchronously inside handle_request before sendmsg, so this should
        // already be observable).
        assert_eq!(registry.live_token_count(), 0);
    }

    #[test]
    fn unknown_token_returns_error_status() {
        let (_dir, path, _registry) = spawn_test_listener();
        let stream = UnixStream::connect(&path).expect("connect");

        client_send(&stream, Frame::materialize_request(999_999), None);
        let (resp, fd) = client_recv(&stream);
        assert_eq!(resp.opcode, Opcode::MaterializeResponse);
        assert_eq!(resp.status, StatusCode::UnknownToken);
        assert!(fd.is_none());

        client_send(&stream, Frame::release_request(999_999), None);
        let (resp, _fd) = client_recv(&stream);
        assert_eq!(resp.opcode, Opcode::ReleaseResponse);
        assert_eq!(resp.status, StatusCode::UnknownToken);
    }

    #[test]
    fn register_without_fd_yields_protocol_error() {
        let (_dir, path, registry) = spawn_test_listener();
        let stream = UnixStream::connect(&path).expect("connect");

        client_send(&stream, Frame::register_request(), None);
        let (resp, _fd) = client_recv(&stream);
        assert_eq!(resp.opcode, Opcode::RegisterResponse);
        assert_eq!(resp.status, StatusCode::Protocol);
        assert_eq!(registry.live_token_count(), 0);
    }

    #[test]
    fn multiple_concurrent_clients() {
        // Each client opens its own connection; the broker should service
        // them in parallel via per-connection threads.
        let (_dir, path, registry) = spawn_test_listener();
        let n_clients = 4;
        let mut handles = Vec::new();
        for _ in 0..n_clients {
            let path = path.clone();
            handles.push(thread::spawn(move || {
                let stream = UnixStream::connect(&path).expect("connect");
                let (r, _w) = pipe_pair();
                client_send(&stream, Frame::register_request(), Some(&r));
                let (resp, _fd) = client_recv(&stream);
                assert_eq!(resp.status, StatusCode::Ok);
                let token_id = resp.payload;

                client_send(&stream, Frame::release_request(token_id), None);
                let (resp, _fd) = client_recv(&stream);
                assert_eq!(resp.status, StatusCode::Ok);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(registry.live_token_count(), 0);
    }

    #[test]
    fn many_requests_over_one_connection() {
        // Stresses the per-connection loop: 100 register/release pairs on
        // a single socket. Verifies request/response framing stays in sync.
        let (_dir, path, registry) = spawn_test_listener();
        let stream = UnixStream::connect(&path).expect("connect");

        for _ in 0..100 {
            let (r, _w) = pipe_pair();
            client_send(&stream, Frame::register_request(), Some(&r));
            let (resp, _fd) = client_recv(&stream);
            assert_eq!(resp.status, StatusCode::Ok);
            let token_id = resp.payload;
            client_send(&stream, Frame::release_request(token_id), None);
            let (resp, _fd) = client_recv(&stream);
            assert_eq!(resp.status, StatusCode::Ok);
        }
        assert_eq!(registry.live_token_count(), 0);
    }
}
