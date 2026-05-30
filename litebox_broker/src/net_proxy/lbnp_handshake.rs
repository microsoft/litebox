// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::time::{Duration, Instant};

use tracing::info;

use crate::sock_compat::{self, IpcStream, POLLIN, POLLOUT, PollFd};

use super::device::DEVICE_MTU;

/// IPC handshake magic bytes.
pub(super) const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";

/// Handshake protocol version.
pub(super) const HANDSHAKE_VERSION: u16 = 1;

/// Perform the IPC handshake (broker side).
///
/// Reads all 8 bytes (magic + version + MTU), validates, and sends the
/// response.  Used only by the `--network-proxy-fd` path where the runner
/// passes the fd directly.
pub(super) fn perform_handshake(fd: &IpcStream) -> Result<(), Box<dyn std::error::Error>> {
    // Wait for handshake with 10s timeout.
    let mut pfd = PollFd {
        fd: fd.raw(),
        events: POLLIN,
        revents: 0,
    };
    let ret = sock_compat::poll_fds(std::slice::from_mut(&mut pfd), 10_000);
    if ret <= 0 {
        return Err("IPC handshake timeout".into());
    }

    // Read handshake: magic (4) + version (2) + MTU (2) = 8 bytes.
    // Handles would-block/short reads on non-blocking sockets.
    let mut buf = [0u8; 8];
    let mut read = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while read < 8 {
        let ret = sock_compat::recv_nb(fd.raw(), &mut buf[read..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                read += ret as usize;
            }
        } else if ret == 0 {
            return Err("IPC handshake: peer closed".into());
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                if Instant::now() > deadline {
                    return Err("IPC handshake read timeout".into());
                }
                let mut rpfd = PollFd {
                    fd: fd.raw(),
                    events: POLLIN,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut rpfd), 100);
                continue;
            }
            return Err(format!("IPC handshake read failed: errno {err}").into());
        }
    }

    validate_handshake_request(&buf)?;
    send_handshake_response(fd)
}

pub(super) fn validate_handshake_request(buf: &[u8; 8]) -> Result<(), Box<dyn std::error::Error>> {
    if &buf[0..4] != HANDSHAKE_MAGIC {
        return Err(format!(
            "IPC handshake: bad magic {:02x?}, expected {:02x?}",
            &buf[0..4],
            HANDSHAKE_MAGIC
        )
        .into());
    }

    let version = u16::from_le_bytes([buf[4], buf[5]]);
    let mtu = u16::from_le_bytes([buf[6], buf[7]]);
    info!(version, mtu, "IPC handshake received");

    if version != HANDSHAKE_VERSION {
        return Err(format!(
            "IPC handshake: unsupported version {version}, expected {HANDSHAKE_VERSION}"
        )
        .into());
    }

    #[allow(clippy::cast_possible_truncation)]
    let our_mtu = DEVICE_MTU as u16;
    if mtu != our_mtu {
        return Err(
            format!("IPC handshake: MTU mismatch — peer sent {mtu}, we expect {our_mtu}").into(),
        );
    }
    Ok(())
}

pub(super) fn send_handshake_response(fd: &IpcStream) -> Result<(), Box<dyn std::error::Error>> {
    // Send handshake response (retry on would-block).
    #[allow(clippy::cast_possible_truncation)]
    let response_mtu = DEVICE_MTU as u16;
    let mut response = [0u8; 8];
    response[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    response[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    response[6..8].copy_from_slice(&response_mtu.to_le_bytes());

    let mut sent = 0usize;
    while sent < 8 {
        let ret = sock_compat::send_nb(fd.raw(), &response[sent..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                sent += ret as usize;
            }
        } else if ret == 0 {
            return Err("IPC handshake response: peer closed".into());
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                let mut wpfd = PollFd {
                    fd: fd.raw(),
                    events: POLLOUT,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut wpfd), 100);
                continue;
            }
            return Err(format!("IPC handshake response send failed: errno {err}").into());
        }
    }

    Ok(())
}

