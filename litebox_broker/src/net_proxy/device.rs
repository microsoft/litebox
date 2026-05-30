// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LBNP IPC framing helpers.

use crate::sock_compat::{self, RawSock, MSG_PEEK};

use tracing::error;

/// MTU retained for the LBNP handshake contract.
pub const DEVICE_MTU: usize = 1600;

pub(super) enum IpcDrainResult {
    Frame,
    WouldBlock,
    Closed,
    ProtocolError,
}

/// Drain one legacy length-prefixed IPC frame from a non-blocking LBNP stream.
pub(super) fn drain_one_ipc_frame(fd: RawSock) -> IpcDrainResult {
    let mut len_buf = [0u8; 4];
    let ret = sock_compat::recv_nb(fd, &mut len_buf, MSG_PEEK);
    if ret == 0 {
        return IpcDrainResult::Closed;
    }
    if ret < 0 {
        let err = sock_compat::last_socket_error();
        if sock_compat::is_would_block(err) {
            return IpcDrainResult::WouldBlock;
        }
        return IpcDrainResult::Closed;
    }
    #[allow(clippy::cast_sign_loss)]
    if (ret as usize) < len_buf.len() {
        return IpcDrainResult::WouldBlock;
    }

    let pkt_len = u32::from_le_bytes(len_buf) as usize;
    consume_exact(fd, len_buf.len());
    if pkt_len == 0 {
        return IpcDrainResult::Closed;
    }
    if pkt_len > DEVICE_MTU {
        error!("IPC protocol error: frame length {pkt_len} exceeds MTU {DEVICE_MTU}, closing");
        return IpcDrainResult::ProtocolError;
    }

    let mut remaining = pkt_len;
    let mut buf = [0u8; 256];
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        let ret = sock_compat::recv_nb(fd, &mut buf[..chunk], 0);
        if ret == 0 {
            return IpcDrainResult::Closed;
        }
        if ret < 0 {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                return IpcDrainResult::WouldBlock;
            }
            return IpcDrainResult::Closed;
        }
        #[allow(clippy::cast_sign_loss)]
        {
            remaining -= ret as usize;
        }
    }

    IpcDrainResult::Frame
}

pub(super) fn send_shutdown(fd: RawSock) {
    let frame = 0u32.to_le_bytes();
    let _ = sock_compat::send_nb(fd, &frame, 0);
}

fn consume_exact(fd: RawSock, n: usize) {
    let mut buf = [0u8; 16];
    let mut consumed = 0;
    while consumed < n {
        let chunk = (n - consumed).min(buf.len());
        let ret = sock_compat::recv_nb(fd, &mut buf[..chunk], 0);
        if ret <= 0 {
            break;
        }
        #[allow(clippy::cast_sign_loss)]
        {
            consumed += ret as usize;
        }
    }
}
