// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wire format for cross-worker `SCM_RIGHTS` over the broker-mediated TCP
//! transport in `UnixTransport::Tcp`.
//!
//! # Why this exists
//!
//! Same-worker Unix sockets carry a `Message { data, passed_fds }` directly
//! through an in-memory channel; the `passed_fds` ride alongside the data
//! payload as `Vec<PassedFd>`. Cross-worker Unix sockets, however, are
//! tunnelled through the broker's smoltcp TCP proxy as a raw byte stream
//! (`UnixTransport::Tcp` in `litebox_shim_linux/src/syscalls/unix.rs`).
//! Today that byte stream carries `data` only — `passed_fds` are silently
//! dropped at the send side (see line ~704 of that file). The receiver
//! observes the bytes but never sees the fds, so cross-worker
//! `SCM_RIGHTS` is broken.
//!
//! This module defines a small, length-prefixed framing layer that lets
//! both ends agree on message boundaries *and* an out-of-band fd-token
//! list per message. It carries:
//!
//! - the original `data` payload (verbatim bytes),
//! - the count of passed fds,
//! - a token id (u64) per passed fd — opaque to this layer; the broker's
//!   `BrokerFdTokenRegistry` is the authority for what each id refers to.
//!
//! A single `UnixTransport::Tcp` carries a sequence of these frames.
//! Stream sockets concatenate frames; seqpacket sockets emit one frame
//! per message. Either way the framing tells the receiver where one
//! `Message` ends and the next begins, which is exactly what the
//! in-memory `Channel` variant gets for free.
//!
//! # Wire format (little-endian)
//!
//! ```text
//! offset  size  field
//! ──────  ────  ──────────────────────────────────────────────
//!   0      4    magic = 0x4C42_4644 ("LBFD")        // u32
//!   4      2    version = 1                         // u16
//!   6      2    flags = 0                           // u16 (reserved)
//!   8      4    data_len    (≤ DATA_MAX)            // u32
//!  12      4    fd_count    (≤ FD_COUNT_MAX)        // u32
//!  16      8    token[0]                            // u64
//!  24      8    token[1]                            // u64
//!   …      …    …                                   //
//!  16+8K    L   data[0..L]                          // raw bytes
//! ```
//!
//! Total frame length = `16 + 8 * fd_count + data_len`. A zero-fd
//! frame is the common case and adds 16 bytes of overhead per message.
//!
//! # No regression risk to same-worker traffic
//!
//! `UnixTransport::Channel` does not use this format and is not affected.
//! Phase 3 wires this format only into the `UnixTransport::Tcp` arm of
//! `try_sendto`/`try_recvfrom`.
//!
//! # Phase boundary
//!
//! This module is **Phase 3a** of the cross-worker fd transport plan:
//! pure data + tests, no IPC integration, no broker round-trips. Phase
//! 3b will add broker control opcodes that turn host fds into token ids
//! and back. Phase 3c will plumb `passed_fds` → tokens (via 3b) →
//! frames (this module) → wire → frames → tokens → host fds.

use alloc::vec::Vec;

/// Wire-format magic number ("LBFD" — LiteBox Fd Frame).
pub const FRAME_MAGIC: u32 = 0x4C42_4644;

/// Wire-format version. Receivers reject mismatched versions.
pub const FRAME_VERSION: u16 = 1;

/// Maximum payload bytes per frame. Matches `UNIX_BUF_SIZE` in
/// `litebox_shim_linux/src/syscalls/unix.rs`. Frames larger than this
/// would never fit in a single recv buffer round trip on the receiver.
pub const DATA_MAX: u32 = 65_536;

/// Maximum fds per frame. The Linux kernel's `SCM_MAX_FD` is 253; we use
/// the same cap to stay aligned with what `sendmsg` accepts on the
/// originating side. A passed fd here is 8 bytes on the wire (token id),
/// so the worst-case fd-only overhead is ~2 KiB.
pub const FD_COUNT_MAX: u32 = 253;

/// Size in bytes of the fixed-size frame header.
pub const FRAME_HEADER_LEN: usize = 16;

/// Errors produced by [`FdTransferFrame::decode`] and [`FdTransferFrame::encoded_len`].
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Available bytes are smaller than the fixed header.
    HeaderTruncated { have: usize, need: usize },
    /// Available bytes are smaller than the announced full-frame length
    /// (header + tokens + data).
    BodyTruncated { have: usize, need: usize },
    /// Magic word did not match [`FRAME_MAGIC`]. Indicates a desynchronised
    /// stream or wire-format corruption.
    BadMagic { found: u32 },
    /// Receiver does not implement the announced version.
    UnsupportedVersion { version: u16 },
    /// `data_len` exceeded [`DATA_MAX`]. Treated as malformed input.
    DataTooLarge { data_len: u32, max: u32 },
    /// `fd_count` exceeded [`FD_COUNT_MAX`]. Treated as malformed input.
    FdCountTooLarge { fd_count: u32, max: u32 },
    /// `flags` had a non-zero bit set; reserved flags must be zero in
    /// version 1. Forward-compatible decoders that wish to ignore unknown
    /// flags can choose to suppress this error, but the canonical decoder
    /// rejects so a future flag rollout does not silently misbehave.
    UnknownFlags { flags: u16 },
    /// Same as [`FrameError::DataTooLarge`] but at encode time: caller
    /// supplied a payload that exceeds the wire limit.
    EncodeDataTooLarge { data_len: usize, max: u32 },
    /// Same as [`FrameError::FdCountTooLarge`] but at encode time.
    EncodeFdCountTooLarge { fd_count: usize, max: u32 },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::HeaderTruncated { have, need } => {
                write!(f, "frame header truncated: have {have}, need {need}")
            }
            FrameError::BodyTruncated { have, need } => {
                write!(f, "frame body truncated: have {have}, need {need}")
            }
            FrameError::BadMagic { found } => {
                write!(
                    f,
                    "bad frame magic: found 0x{found:08x}, expected 0x{FRAME_MAGIC:08x}"
                )
            }
            FrameError::UnsupportedVersion { version } => {
                write!(f, "unsupported frame version: {version}")
            }
            FrameError::DataTooLarge { data_len, max } => {
                write!(f, "decoded data_len {data_len} exceeds max {max}")
            }
            FrameError::FdCountTooLarge { fd_count, max } => {
                write!(f, "decoded fd_count {fd_count} exceeds max {max}")
            }
            FrameError::UnknownFlags { flags } => {
                write!(f, "unknown reserved flags: 0x{flags:04x}")
            }
            FrameError::EncodeDataTooLarge { data_len, max } => {
                write!(f, "encode data_len {data_len} exceeds max {max}")
            }
            FrameError::EncodeFdCountTooLarge { fd_count, max } => {
                write!(f, "encode fd_count {fd_count} exceeds max {max}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameError {}

/// A decoded frame referencing borrowed payload bytes from the receive
/// buffer. The `tokens` are owned (small allocation, ≤ 253 × 8 bytes); the
/// data slice borrows from the input to avoid copying the bulk payload.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    pub tokens: Vec<u64>,
    pub data: &'a [u8],
    /// Total bytes consumed from the input (header + tokens + data). The
    /// caller advances its read cursor by this many bytes.
    pub consumed: usize,
}

/// An encodable frame. The `tokens` and `data` references describe a
/// single message's worth of payload + fd-token list.
pub struct FdTransferFrame<'a> {
    pub tokens: &'a [u64],
    pub data: &'a [u8],
}

impl FdTransferFrame<'_> {
    /// Returns the number of bytes that [`Self::encode`] will write, or an
    /// error if the inputs exceed the wire limits.
    pub fn encoded_len(&self) -> Result<usize, FrameError> {
        if self.data.len() > DATA_MAX as usize {
            return Err(FrameError::EncodeDataTooLarge {
                data_len: self.data.len(),
                max: DATA_MAX,
            });
        }
        if self.tokens.len() > FD_COUNT_MAX as usize {
            return Err(FrameError::EncodeFdCountTooLarge {
                fd_count: self.tokens.len(),
                max: FD_COUNT_MAX,
            });
        }
        Ok(FRAME_HEADER_LEN + 8 * self.tokens.len() + self.data.len())
    }

    /// Appends the encoded frame to `out`. Returns the number of bytes
    /// appended on success, or a [`FrameError`] if the inputs exceed the
    /// wire limits (in which case `out` is left unchanged).
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<usize, FrameError> {
        let total = self.encoded_len()?;
        out.reserve(total);
        let start = out.len();

        out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags reserved
        // SAFETY of casts: encoded_len() above already validated that
        // self.data.len() ≤ DATA_MAX (u32) and self.tokens.len() ≤
        // FD_COUNT_MAX (u32), so the truncation cannot lose information.
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.tokens.len() as u32).to_le_bytes());

        for &t in self.tokens {
            out.extend_from_slice(&t.to_le_bytes());
        }

        out.extend_from_slice(self.data);

        debug_assert_eq!(out.len() - start, total);
        Ok(total)
    }
}

/// Decodes one frame from the start of `buf`. Returns the decoded frame
/// (with `tokens` owned and `data` borrowing from `buf`) plus the number
/// of bytes consumed from `buf`. The caller is responsible for advancing
/// its read cursor by `decoded.consumed`.
///
/// Returns:
/// - `Err(HeaderTruncated)` if `buf` is shorter than [`FRAME_HEADER_LEN`].
/// - `Err(BodyTruncated)` if the announced body extends beyond `buf`.
/// - `Err(BadMagic)` / `Err(UnsupportedVersion)` / `Err(UnknownFlags)`
///   for protocol violations (caller should treat as a fatal stream error).
/// - `Err(DataTooLarge)` / `Err(FdCountTooLarge)` for malformed sizes.
pub fn decode_frame(buf: &[u8]) -> Result<DecodedFrame<'_>, FrameError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::HeaderTruncated {
            have: buf.len(),
            need: FRAME_HEADER_LEN,
        });
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != FRAME_MAGIC {
        return Err(FrameError::BadMagic { found: magic });
    }

    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion { version });
    }

    let flags = u16::from_le_bytes([buf[6], buf[7]]);
    if flags != 0 {
        return Err(FrameError::UnknownFlags { flags });
    }

    let data_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if data_len > DATA_MAX {
        return Err(FrameError::DataTooLarge {
            data_len,
            max: DATA_MAX,
        });
    }

    let fd_count = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if fd_count > FD_COUNT_MAX {
        return Err(FrameError::FdCountTooLarge {
            fd_count,
            max: FD_COUNT_MAX,
        });
    }

    let tokens_len = 8usize * fd_count as usize;
    let total = FRAME_HEADER_LEN + tokens_len + data_len as usize;
    if buf.len() < total {
        return Err(FrameError::BodyTruncated {
            have: buf.len(),
            need: total,
        });
    }

    let tokens_start = FRAME_HEADER_LEN;
    let data_start = tokens_start + tokens_len;
    let data_end = data_start + data_len as usize;

    let mut tokens = Vec::with_capacity(fd_count as usize);
    for i in 0..fd_count as usize {
        let off = tokens_start + 8 * i;
        let id = u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        tokens.push(id);
    }

    Ok(DecodedFrame {
        tokens,
        data: &buf[data_start..data_end],
        consumed: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_empty_data_no_fds() {
        let frame = FdTransferFrame {
            tokens: &[],
            data: &[],
        };
        let mut buf = Vec::new();
        let n = frame.encode(&mut buf).expect("encode");
        assert_eq!(n, FRAME_HEADER_LEN);
        assert_eq!(buf.len(), FRAME_HEADER_LEN);

        let decoded = decode_frame(&buf).expect("decode");
        assert!(decoded.tokens.is_empty());
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.consumed, FRAME_HEADER_LEN);
    }

    #[test]
    fn round_trip_data_only() {
        let payload = b"hello cross-worker world";
        let frame = FdTransferFrame {
            tokens: &[],
            data: payload,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        let decoded = decode_frame(&buf).expect("decode");
        assert!(decoded.tokens.is_empty());
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, FRAME_HEADER_LEN + payload.len());
    }

    #[test]
    fn round_trip_tokens_only() {
        let tokens = [1u64, 42, 0xdead_beef_cafe_babe];
        let frame = FdTransferFrame {
            tokens: &tokens,
            data: &[],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        let decoded = decode_frame(&buf).expect("decode");
        assert_eq!(decoded.tokens, tokens);
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.consumed, FRAME_HEADER_LEN + 8 * tokens.len());
    }

    #[test]
    fn round_trip_full_frame() {
        let tokens = [7u64, 8, 9];
        let payload = b"some bytes plus three fd tokens";
        let frame = FdTransferFrame {
            tokens: &tokens,
            data: payload,
        };
        let mut buf = Vec::new();
        let n = frame.encode(&mut buf).expect("encode");
        assert_eq!(n, FRAME_HEADER_LEN + 24 + payload.len());

        let decoded = decode_frame(&buf).expect("decode");
        assert_eq!(decoded.tokens, tokens);
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, n);
    }

    #[test]
    fn back_to_back_frames_share_buffer() {
        // The receiver must be able to peel one frame off and keep going.
        let p1 = b"first";
        let p2 = b"second message";
        let mut buf = Vec::new();

        FdTransferFrame {
            tokens: &[1, 2],
            data: p1,
        }
        .encode(&mut buf)
        .expect("encode 1");
        FdTransferFrame {
            tokens: &[3],
            data: p2,
        }
        .encode(&mut buf)
        .expect("encode 2");

        let f1 = decode_frame(&buf).expect("decode 1");
        assert_eq!(f1.tokens, [1u64, 2]);
        assert_eq!(f1.data, p1);

        let f2 = decode_frame(&buf[f1.consumed..]).expect("decode 2");
        assert_eq!(f2.tokens, [3u64]);
        assert_eq!(f2.data, p2);

        assert_eq!(f1.consumed + f2.consumed, buf.len());
    }

    #[test]
    fn header_truncation_returns_specific_error() {
        let short = [0u8; FRAME_HEADER_LEN - 1];
        match decode_frame(&short) {
            Err(FrameError::HeaderTruncated { have, need }) => {
                assert_eq!(have, FRAME_HEADER_LEN - 1);
                assert_eq!(need, FRAME_HEADER_LEN);
            }
            other => panic!("expected HeaderTruncated, got {other:?}"),
        }
    }

    #[test]
    fn body_truncation_returns_specific_error() {
        // Encode a frame, then truncate one byte off the data tail.
        let mut buf = Vec::new();
        FdTransferFrame {
            tokens: &[],
            data: b"abc",
        }
        .encode(&mut buf)
        .unwrap();
        buf.truncate(buf.len() - 1);

        match decode_frame(&buf) {
            Err(FrameError::BodyTruncated { have, need }) => {
                assert_eq!(have, buf.len());
                assert_eq!(need, FRAME_HEADER_LEN + 3);
            }
            other => panic!("expected BodyTruncated, got {other:?}"),
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = Vec::from([0u8; FRAME_HEADER_LEN]);
        // Leave magic = 0; valid header would have FRAME_MAGIC.
        match decode_frame(&buf) {
            Err(FrameError::BadMagic { found: 0 }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
        // A different non-magic value also rejected.
        buf[..4].copy_from_slice(&0xdeadbeef_u32.to_le_bytes());
        match decode_frame(&buf) {
            Err(FrameError::BadMagic { found: 0xdeadbeef }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut buf = Vec::new();
        FdTransferFrame {
            tokens: &[],
            data: &[],
        }
        .encode(&mut buf)
        .unwrap();
        // Tamper version field to 99.
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());

        match decode_frame(&buf) {
            Err(FrameError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut buf = Vec::new();
        FdTransferFrame {
            tokens: &[],
            data: &[],
        }
        .encode(&mut buf)
        .unwrap();
        buf[6..8].copy_from_slice(&1u16.to_le_bytes()); // any non-zero

        match decode_frame(&buf) {
            Err(FrameError::UnknownFlags { flags: 1 }) => {}
            other => panic!("expected UnknownFlags, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_data_len() {
        let mut buf = Vec::from([0u8; FRAME_HEADER_LEN]);
        buf[..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        // flags = 0 already
        let oversized = DATA_MAX + 1;
        buf[8..12].copy_from_slice(&oversized.to_le_bytes());
        // fd_count = 0 already

        match decode_frame(&buf) {
            Err(FrameError::DataTooLarge { data_len, max }) => {
                assert_eq!(data_len, oversized);
                assert_eq!(max, DATA_MAX);
            }
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_fd_count() {
        let mut buf = Vec::from([0u8; FRAME_HEADER_LEN]);
        buf[..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        let oversized = FD_COUNT_MAX + 1;
        buf[12..16].copy_from_slice(&oversized.to_le_bytes());

        match decode_frame(&buf) {
            Err(FrameError::FdCountTooLarge { fd_count, max }) => {
                assert_eq!(fd_count, oversized);
                assert_eq!(max, FD_COUNT_MAX);
            }
            other => panic!("expected FdCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_oversized_data() {
        let big = vec![0u8; DATA_MAX as usize + 1];
        let frame = FdTransferFrame {
            tokens: &[],
            data: &big,
        };
        let mut out = Vec::new();
        match frame.encode(&mut out) {
            Err(FrameError::EncodeDataTooLarge { data_len, max }) => {
                assert_eq!(data_len, big.len());
                assert_eq!(max, DATA_MAX);
            }
            other => panic!("expected EncodeDataTooLarge, got {other:?}"),
        }
        assert!(out.is_empty(), "out must be unchanged on encode failure");
    }

    #[test]
    fn encode_rejects_oversized_fd_count() {
        let many = vec![0u64; FD_COUNT_MAX as usize + 1];
        let frame = FdTransferFrame {
            tokens: &many,
            data: &[],
        };
        let mut out = Vec::new();
        match frame.encode(&mut out) {
            Err(FrameError::EncodeFdCountTooLarge { fd_count, max }) => {
                assert_eq!(fd_count, many.len());
                assert_eq!(max, FD_COUNT_MAX);
            }
            other => panic!("expected EncodeFdCountTooLarge, got {other:?}"),
        }
        assert!(out.is_empty(), "out must be unchanged on encode failure");
    }

    #[test]
    fn boundary_max_data_len_round_trips() {
        let payload = vec![0xa5u8; DATA_MAX as usize];
        let frame = FdTransferFrame {
            tokens: &[1, 2, 3],
            data: &payload,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode at max");
        let decoded = decode_frame(&buf).expect("decode at max");
        assert_eq!(decoded.tokens, [1u64, 2, 3]);
        assert_eq!(decoded.data.len(), DATA_MAX as usize);
        assert!(decoded.data.iter().all(|&b| b == 0xa5));
    }

    #[test]
    fn boundary_max_fd_count_round_trips() {
        let tokens: Vec<u64> = (0..u64::from(FD_COUNT_MAX)).collect();
        let frame = FdTransferFrame {
            tokens: &tokens,
            data: b"x",
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode at max fd_count");
        let decoded = decode_frame(&buf).expect("decode at max fd_count");
        assert_eq!(decoded.tokens, tokens);
        assert_eq!(decoded.data, b"x");
    }

    #[test]
    fn frame_constants_match_doc() {
        // Sanity: FRAME_HEADER_LEN is the documented 16-byte layout.
        assert_eq!(FRAME_HEADER_LEN, 16);
        // ASCII for "LBFD" little-endian.
        assert_eq!(&FRAME_MAGIC.to_le_bytes(), b"DFBL");
    }
}
