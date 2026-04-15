// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Inter-process stream multiplexer for fork workers.
//!
//! Framed protocol over an OS `socketpair(AF_UNIX, SOCK_SEQPACKET)`.
//! Each message:
//!
//! ```text
//! ┌──────────┬───────────┬──────┬──────┬──────────┐
//! │ len (u32)│stream (u32)│ type │flags │  data    │
//! │  LE      │  LE        │ (u8) │(u8)  │(len-10)  │
//! └──────────┴───────────┴──────┴──────┴──────────┘
//! ```
//!
//! `SOCK_SEQPACKET` preserves message boundaries, so each `recv()` returns
//! exactly one frame.  Shared-memory ring transport can be added later as an
//! optimization.

use alloc::vec::Vec;

/// Data payload message.
pub const MSG_TYPE_DATA: u8 = 0;
/// Control message (ioctl/termios/window-size forwarding).
pub const MSG_TYPE_CONTROL: u8 = 1;
/// EOF — stream closed by sender.
pub const MSG_FLAG_EOF: u8 = 1;
/// RESET — stream aborted (maps to EPIPE/SIGPIPE for writers, EOF for readers).
pub const MSG_FLAG_RESET: u8 = 2;
/// Total header size: len(4) + stream_id(4) + type(1) + flags(1).
pub const HEADER_SIZE: usize = 10;

/// A single framed multiplexer message.
pub struct MuxMessage {
    pub stream_id: u32,
    pub msg_type: u8,
    pub flags: u8,
    pub data: Vec<u8>,
}

impl MuxMessage {
    /// Create a data message carrying `data` for the given stream.
    pub fn data(stream_id: u32, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            msg_type: MSG_TYPE_DATA,
            flags: 0,
            data,
        }
    }

    /// Create an EOF marker for the given stream (no payload).
    pub fn eof(stream_id: u32) -> Self {
        Self {
            stream_id,
            msg_type: MSG_TYPE_DATA,
            flags: MSG_FLAG_EOF,
            data: Vec::new(),
        }
    }

    /// Create a RESET marker for the given stream (no payload).
    pub fn reset(stream_id: u32) -> Self {
        Self {
            stream_id,
            msg_type: MSG_TYPE_DATA,
            flags: MSG_FLAG_RESET,
            data: Vec::new(),
        }
    }

    /// Serialize into a byte buffer suitable for sending over the transport.
    #[allow(clippy::cast_possible_truncation)]
    pub fn serialize(&self) -> Vec<u8> {
        debug_assert!(
            self.data.len() <= u32::MAX as usize - HEADER_SIZE,
            "mux payload too large: {}",
            self.data.len()
        );
        let len = (HEADER_SIZE + self.data.len()) as u32;
        let mut buf = Vec::with_capacity(len as usize);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.push(self.msg_type);
        buf.push(self.flags);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize from a byte buffer received from the transport.
    ///
    /// Returns `None` if the buffer is too short or the length field is
    /// inconsistent.
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len < HEADER_SIZE {
            return None;
        }
        if buf.len() < len {
            return None;
        }
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let msg_type = buf[8];
        let flags = buf[9];
        let data = buf[HEADER_SIZE..len].to_vec();
        Some(Self {
            stream_id,
            msg_type,
            flags,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_data_message() {
        let msg = MuxMessage::data(42, alloc::vec![1, 2, 3, 4]);
        let bytes = msg.serialize();
        let decoded = MuxMessage::deserialize(&bytes).unwrap();
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.msg_type, MSG_TYPE_DATA);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.data, &[1, 2, 3, 4]);
    }

    #[test]
    fn round_trip_eof_message() {
        let msg = MuxMessage::eof(7);
        let bytes = msg.serialize();
        let decoded = MuxMessage::deserialize(&bytes).unwrap();
        assert_eq!(decoded.stream_id, 7);
        assert_eq!(decoded.flags, MSG_FLAG_EOF);
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn deserialize_too_short() {
        assert!(MuxMessage::deserialize(&[0; 5]).is_none());
    }

    #[test]
    fn deserialize_length_mismatch() {
        // Header says length 20 but buffer is only 10 bytes.
        let mut buf = [0u8; 10];
        buf[0..4].copy_from_slice(&20u32.to_le_bytes());
        assert!(MuxMessage::deserialize(&buf).is_none());
    }
}
