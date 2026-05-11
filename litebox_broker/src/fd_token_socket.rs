// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker control-socket I/O.
//!
//! Reads variable-length [`Frame`]s with optional `SCM_RIGHTS` fd
//! attachment, dispatches to the matching handler in
//! [`crate::fd_token_service`] (host-fd ops) and — once Phase B-Step6
//! lands — `crate::state_service` (eventfd and other state-object ops).

use crate::fd_token_service::{HandlerFatal, handle_request};
use crate::fd_tokens::BrokerFdTokenRegistry;
use litebox_common_linux::fd_token_protocol::{
    BODY_MAX, CTRL_HEADER_LEN, Opcode, OwnedFrame, ProtocolError, decode,
};
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

    #[error("control header short-read: got {got} bytes, expected {CTRL_HEADER_LEN}")]
    HeaderShortRead { got: usize },

    #[error("control body short-read: got {got} bytes, expected {need}")]
    BodyShortRead { got: usize, need: usize },

    #[error("control frame had truncated SCM_RIGHTS payload")]
    CmsgTruncated,

    #[error("control frame had {count} attached fds; at most 1 supported")]
    TooManyFds { count: usize },

    #[error("malformed SCM_RIGHTS cmsg header")]
    MalformedCmsg,

    #[error("protocol decode error: {0}")]
    Decode(ProtocolError),

    #[error("handler reported fatal protocol violation: {0}")]
    HandlerFatal(#[from] HandlerFatal),
}

/// Reads one complete frame plus zero or one `SCM_RIGHTS` fd.
/// Returns `(encoded_bytes, optional_fd)`. Bytes can then be `decode`d.
fn read_request(stream: &UnixStream) -> Result<(Vec<u8>, Option<OwnedFd>), ConnError> {
    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let mut header = [0u8; CTRL_HEADER_LEN];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: CTRL_HEADER_LEN,
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

    let raw_fd = stream.as_raw_fd();
    let n = unsafe { libc::recvmsg(raw_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if n == 0 {
        return Err(ConnError::PeerClosed);
    }
    #[allow(clippy::cast_sign_loss)]
    let n_usize = n as usize;
    if n_usize != CTRL_HEADER_LEN {
        return Err(ConnError::HeaderShortRead { got: n_usize });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(ConnError::CmsgTruncated);
    }

    // Extract SCM_RIGHTS fd if any (at most 1).
    let mut received_fd: Option<OwnedFd> = None;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
            if (hdr.cmsg_len as usize) < header_len {
                return Err(ConnError::MalformedCmsg);
            }
            let fd_count = ((hdr.cmsg_len as usize) - header_len) / size_of::<i32>();
            if fd_count > 1 {
                // Reject; close all received fds.
                for i in 0..fd_count {
                    #[allow(clippy::cast_ptr_alignment)]
                    let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                    drop(unsafe { OwnedFd::from_raw_fd(raw) });
                }
                return Err(ConnError::TooManyFds { count: fd_count });
            }
            if fd_count == 1 {
                #[allow(clippy::cast_ptr_alignment)]
                let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
                received_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    // Read body bytes if any.
    let body_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if body_len > BODY_MAX {
        return Err(ConnError::Decode(ProtocolError::BodyTooLarge {
            body_len,
            max: BODY_MAX,
        }));
    }
    let mut full = Vec::with_capacity(CTRL_HEADER_LEN + body_len as usize);
    full.extend_from_slice(&header);
    if body_len > 0 {
        let mut remaining = body_len as usize;
        let mut body_buf = vec![0u8; body_len as usize];
        let mut offset = 0;
        while remaining > 0 {
            let r = unsafe {
                libc::recv(
                    raw_fd,
                    body_buf.as_mut_ptr().add(offset).cast(),
                    remaining,
                    libc::MSG_WAITALL,
                )
            };
            if r < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            #[allow(clippy::cast_sign_loss)]
            let r_usize = r as usize;
            if r_usize == 0 {
                return Err(ConnError::BodyShortRead {
                    got: offset,
                    need: body_len as usize,
                });
            }
            offset += r_usize;
            remaining -= r_usize;
        }
        full.extend_from_slice(&body_buf);
    }

    Ok((full, received_fd))
}

/// Sends an [`OwnedFrame`] plus an optional fd via `sendmsg`.
fn write_response(
    stream: &UnixStream,
    frame: OwnedFrame,
    out_fd: Option<OwnedFd>,
) -> Result<(), ConnError> {
    let bytes = frame.encode().map_err(ConnError::Decode)?;

    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    if let Some(f) = &out_fd {
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = CMSG_SPACE as _;
        }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        debug_assert!(!cmsg.is_null());
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
            }
            #[allow(clippy::cast_ptr_alignment)]
            let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
            std::ptr::write_unaligned(data_ptr, f.as_raw_fd());
        }
    }

    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    if (n as usize) != bytes.len() {
        return Err(ConnError::Io(std::io::Error::other(format!(
            "short sendmsg: wrote {n}/{} bytes",
            bytes.len()
        ))));
    }

    drop(out_fd);
    Ok(())
}

/// Runs the per-connection request/response loop until the peer
/// closes or an error is observed.
pub fn handle_control_connection(stream: UnixStream, registry: Arc<BrokerFdTokenRegistry>) {
    loop {
        match read_request(&stream) {
            Ok((bytes, in_fd)) => {
                let frame = match decode(&bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = ?e, "fd-token control: decode failed; closing");
                        return;
                    }
                };
                // For Phase B-Step5 only the host-fd opcodes are wired
                // through this dispatcher. Non-host-fd opcodes panic
                // in the service; in Step 6 we'll add the state_service
                // dispatch alongside.
                let is_host_fd_opcode = matches!(
                    frame.opcode,
                    Opcode::Register | Opcode::Materialize | Opcode::Release
                );
                if !is_host_fd_opcode {
                    warn!(
                        opcode = ?frame.opcode,
                        "fd-token control: non-host-fd opcode not yet handled; closing"
                    );
                    return;
                }
                let result = match handle_request(&registry, &frame, in_fd) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "fd-token control: fatal handler error");
                        return;
                    }
                };
                if let Err(e) = write_response(&stream, result.frame, result.out_fd) {
                    warn!(error = %e, "fd-token control: write error");
                    return;
                }
            }
            Err(ConnError::PeerClosed) => {
                debug!("fd-token control: peer closed");
                return;
            }
            Err(e) => {
                warn!(error = %e, "fd-token control: read error");
                return;
            }
        }
    }
}

/// Spawns a thread that listens on `path` and handles each accepted
/// connection on its own thread.
pub fn spawn_control_listener(
    path: &Path,
    registry: Arc<BrokerFdTokenRegistry>,
) -> std::io::Result<JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!(path = %path.display(), "fd-token control listener bound");
    let path_owned = path.to_owned();
    thread::Builder::new()
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
                        warn!(error = %e, path = %path_owned.display(), "fd-token accept error");
                    }
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
    use std::io::{Read, Write};
    use std::thread;
    use tempfile::tempdir;

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        })
    }

    fn spawn_test_listener() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        Arc<BrokerFdTokenRegistry>,
    ) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let registry = Arc::new(BrokerFdTokenRegistry::new());
        let _ = spawn_control_listener(&path, Arc::clone(&registry)).expect("spawn");
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        (dir, path, registry)
    }

    #[test]
    fn end_to_end_host_fd_lifecycle() {
        let (_dir, path, registry) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        let (r, w) = pipe_pair();
        let handle_id = client.register(r).expect("register");
        assert!(handle_id > 0);
        assert_eq!(registry.live_token_count(), 1);

        let mat_fd = client.materialize(handle_id).expect("materialize");
        let mut writer = std::fs::File::from(w);
        writer.write_all(b"crossworker").unwrap();
        drop(writer);
        let mut reader = std::fs::File::from(mat_fd);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"crossworker");

        client.release(handle_id).expect("release");
        assert_eq!(registry.live_token_count(), 0);
    }

    #[test]
    fn unknown_handle_returns_typed_error() {
        let (_dir, path, _registry) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        match client.materialize(99_999) {
            Err(ClientError::UnknownHandle { handle_id }) => assert_eq!(handle_id, 99_999),
            other => panic!("expected UnknownHandle, got {other:?}"),
        }

        match client.release(99_999) {
            Err(ClientError::UnknownHandle { handle_id }) => assert_eq!(handle_id, 99_999),
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }

    #[test]
    fn many_requests_over_one_connection() {
        let (_dir, path, registry) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");
        for _ in 0..50 {
            let (r, _w) = pipe_pair();
            let id = client.register(r).expect("register");
            client.release(id).expect("release");
        }
        assert_eq!(registry.live_token_count(), 0);
    }
}
