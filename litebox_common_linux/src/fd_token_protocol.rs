// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wire protocol for the broker fd-token control channel.
//!
//! # Why this exists
//!
//! Phase 3a defined the *data-plane* framing on `UnixTransport::Tcp`
//! (`fd_transfer_frame`): each cross-worker `Message` is wrapped in an
//! LBFD frame whose header includes a list of opaque [`u64`] token ids.
//!
//! That data-plane framing alone is not enough: the *sender* needs a way
//! to turn its host fds into token ids before encoding the frame, and the
//! *receiver* needs a way to turn token ids back into host fds after
//! decoding. Both directions must round-trip through the broker — the
//! broker holds the canonical [`BrokerFdTokenRegistry`] and is the only
//! process that can keep an fd alive across worker boundaries.
//!
//! This module defines a small request/response control protocol that
//! every worker speaks to the broker over a *dedicated* control socket
//! (one per worker), separate from:
//!
//! - the **network IPC connection** (smoltcp packet frames over Unix/TCP)
//! - the **9P channel** (LB9P handshake → memfd-backed shm ring)
//!
//! Keeping the control plane on its own socket avoids two failure modes:
//! (a) head-of-line blocking on the smoltcp data path, and (b) coupling
//! token traffic to the 9P shm ring's single-producer/single-consumer
//! invariants.
//!
//! # Wire format (little-endian throughout)
//!
//! Each request and each response is a single fixed-size frame followed
//! by zero or one passed fd via `SCM_RIGHTS`. Frame layout:
//!
//! ```text
//!  offset  size  field
//! ───────  ────  ──────────────────────────────────────────────
//!    0      4    magic = 0x4C42_4644 ("LBFD")        // u32
//!    4      2    version = 1                         // u16
//!    6      1    opcode                              // u8 (Opcode)
//!    7      1    status                              // u8 (StatusCode; req → 0, resp → see below)
//!    8      8    payload                             // u64 (opcode-specific)
//! ───────  ────
//!   16  total bytes
//! ```
//!
//! The `payload` field carries:
//!
//! | Opcode                  | Direction      | Payload meaning            | SCM_RIGHTS    |
//! |-------------------------|----------------|----------------------------|---------------|
//! | `Register` (req)        | worker→broker  | reserved (must be 0)       | 1 fd attached |
//! | `RegisterResponse`      | broker→worker  | token id                   | none          |
//! | `Materialize` (req)     | worker→broker  | token id                   | none          |
//! | `MaterializeResponse`   | broker→worker  | reserved (must be 0)       | 1 fd attached |
//! | `Release` (req)         | worker→broker  | token id                   | none          |
//! | `ReleaseResponse`       | broker→worker  | reserved (must be 0)       | none          |
//!
//! Errors use the request's matching response opcode with a non-zero
//! `status`. The payload field on an error response is reserved and
//! should be ignored by the caller; future versions may use it for
//! diagnostic info.
//!
//! # Concurrency
//!
//! The protocol is strictly request/response on a single socket; each
//! request must complete (or fail) before the next is sent. Workers that
//! need parallelism open multiple control sockets to the broker.
//!
//! # Phase boundary
//!
//! This module is **Phase 3b-i** of the cross-worker fd transport plan:
//! pure protocol structs + tests, no socket I/O. Phase 3b-ii will add
//! broker-side handlers that consume parsed requests, mutate the
//! [`BrokerFdTokenRegistry`], and produce responses. Phase 3c will plumb
//! the worker side through `litebox_shim_linux/src/syscalls/unix.rs`.

use core::convert::TryFrom;

/// Wire-format magic — same value as the Phase 3a data-plane frame
/// (`fd_transfer_frame::FRAME_MAGIC`). The magic is shared because the
/// two protocols never appear on the same socket: control traffic goes
/// only on the dedicated control channel, and data-plane LBFD frames go
/// only on `UnixTransport::Tcp`. Sharing the constant simplifies test
/// fixtures and makes wire dumps mutually distinguishable by opcode.
pub const CTRL_MAGIC: u32 = 0x4C42_4644;

/// Wire-format version. Receivers reject mismatched versions.
pub const CTRL_VERSION: u16 = 1;

/// Total fixed-size length of a control frame, in bytes. The protocol
/// has no variable-length payload; every request and every response is
/// exactly this many bytes plus an optional `SCM_RIGHTS` ancillary fd.
pub const CTRL_FRAME_LEN: usize = 16;

/// Opcodes carried in the `opcode` byte of the control frame. Request
/// opcodes occupy the low half of the value space; their matching
/// response opcodes are `request | 0x80`. This lets a peer derive the
/// expected response opcode from the request without a lookup table.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Register = 0x01,
    Materialize = 0x02,
    Release = 0x03,

    RegisterResponse = 0x81,
    MaterializeResponse = 0x82,
    ReleaseResponse = 0x83,
}

impl Opcode {
    /// Returns the matching response opcode for a request opcode, or
    /// `None` if `self` is not a request opcode.
    pub fn response_for(self) -> Option<Opcode> {
        match self {
            Opcode::Register => Some(Opcode::RegisterResponse),
            Opcode::Materialize => Some(Opcode::MaterializeResponse),
            Opcode::Release => Some(Opcode::ReleaseResponse),
            Opcode::RegisterResponse | Opcode::MaterializeResponse | Opcode::ReleaseResponse => {
                None
            }
        }
    }

    /// Returns true if `self` is a request opcode.
    pub fn is_request(self) -> bool {
        matches!(
            self,
            Opcode::Register | Opcode::Materialize | Opcode::Release
        )
    }

    /// Returns the number of fds expected to accompany this opcode via
    /// `SCM_RIGHTS`. Used by request/response readers to validate that
    /// the kernel's ancillary data matches the protocol.
    pub fn expected_fd_count(self) -> usize {
        match self {
            // Register sends a host fd to the broker; MaterializeResponse
            // sends one back. Both sides of the registry transfer use a
            // single fd via SCM_RIGHTS.
            Opcode::Register | Opcode::MaterializeResponse => 1,
            Opcode::Materialize
            | Opcode::Release
            | Opcode::RegisterResponse
            | Opcode::ReleaseResponse => 0,
        }
    }
}

impl TryFrom<u8> for Opcode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Opcode::Register),
            0x02 => Ok(Opcode::Materialize),
            0x03 => Ok(Opcode::Release),
            0x81 => Ok(Opcode::RegisterResponse),
            0x82 => Ok(Opcode::MaterializeResponse),
            0x83 => Ok(Opcode::ReleaseResponse),
            other => Err(ProtocolError::UnknownOpcode { opcode: other }),
        }
    }
}

/// Status codes carried in the `status` byte of response frames.
/// Requests always have `status == 0`. The response with `status == 0`
/// indicates success; non-zero values are error codes.
///
/// Codes are stable across protocol versions. New codes use values
/// starting at `0x10` to keep the low range reserved for the most
/// common error cases.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    /// Operation succeeded.
    Ok = 0x00,
    /// The presented token id was unknown to the broker registry.
    /// Returned by `Materialize` and `Release` for stale or forged ids.
    UnknownToken = 0x01,
    /// `Register` failed because the broker could not insert the fd
    /// (e.g. registry-internal exhaustion).
    RegisterFailed = 0x02,
    /// `Materialize` succeeded at the registry level but `dup(2)` of the
    /// underlying host fd failed.
    MaterializeFailed = 0x03,
    /// The request frame violated the protocol (unknown opcode,
    /// mismatched fd count, malformed magic/version, etc.). The broker
    /// SHOULD close the control socket after returning this status — a
    /// protocol-violating peer is unlikely to recover.
    Protocol = 0x10,
    /// Generic broker-internal error not covered by another code.
    Internal = 0x11,
}

impl TryFrom<u8> for StatusCode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(StatusCode::Ok),
            0x01 => Ok(StatusCode::UnknownToken),
            0x02 => Ok(StatusCode::RegisterFailed),
            0x03 => Ok(StatusCode::MaterializeFailed),
            0x10 => Ok(StatusCode::Protocol),
            0x11 => Ok(StatusCode::Internal),
            other => Err(ProtocolError::UnknownStatus { status: other }),
        }
    }
}

/// Errors produced by the codec. These are protocol-level errors —
/// distinct from operation-level errors carried in [`StatusCode`].
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// Buffer was shorter than [`CTRL_FRAME_LEN`].
    Truncated { have: usize, need: usize },
    /// Magic word did not match [`CTRL_MAGIC`].
    BadMagic { found: u32 },
    /// Receiver does not implement the announced version.
    UnsupportedVersion { version: u16 },
    /// The opcode byte did not match any known [`Opcode`] value.
    UnknownOpcode { opcode: u8 },
    /// The status byte did not match any known [`StatusCode`] value.
    UnknownStatus { status: u8 },
    /// A request frame had a non-zero `status` byte (status is reserved
    /// for responses on the wire).
    NonZeroStatusOnRequest { status: u8 },
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::Truncated { have, need } => {
                write!(f, "control frame truncated: have {have}, need {need}")
            }
            ProtocolError::BadMagic { found } => {
                write!(
                    f,
                    "bad control magic: found 0x{found:08x}, expected 0x{CTRL_MAGIC:08x}"
                )
            }
            ProtocolError::UnsupportedVersion { version } => {
                write!(f, "unsupported control version: {version}")
            }
            ProtocolError::UnknownOpcode { opcode } => {
                write!(f, "unknown control opcode: 0x{opcode:02x}")
            }
            ProtocolError::UnknownStatus { status } => {
                write!(f, "unknown control status: 0x{status:02x}")
            }
            ProtocolError::NonZeroStatusOnRequest { status } => {
                write!(
                    f,
                    "request frame had non-zero status byte 0x{status:02x}; status is reserved for responses"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}

/// A decoded control frame. The frame is a fixed 16-byte structure; this
/// type is what callers obtain from [`decode`] and pass to
/// [`Frame::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub opcode: Opcode,
    /// On a request frame this MUST be [`StatusCode::Ok`] (i.e. `0`).
    /// On a response frame it carries the operation result.
    pub status: StatusCode,
    /// Opcode-specific u64 payload. Reserved fields must be zero.
    pub payload: u64,
}

impl Frame {
    /// Encodes the frame into the first [`CTRL_FRAME_LEN`] bytes of `out`.
    /// Returns `CTRL_FRAME_LEN`.
    ///
    /// # Panics
    ///
    /// Panics if `out.len() < CTRL_FRAME_LEN`. Callers should size their
    /// buffers using the constant rather than rely on dynamic checks.
    pub fn encode(&self, out: &mut [u8]) -> usize {
        assert!(
            out.len() >= CTRL_FRAME_LEN,
            "Frame::encode buffer too small: have {}, need {CTRL_FRAME_LEN}",
            out.len()
        );
        out[0..4].copy_from_slice(&CTRL_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&CTRL_VERSION.to_le_bytes());
        out[6] = self.opcode as u8;
        out[7] = self.status as u8;
        out[8..16].copy_from_slice(&self.payload.to_le_bytes());
        CTRL_FRAME_LEN
    }

    /// Encodes the frame into a freshly-allocated array. Convenience for
    /// callers that don't have an output buffer to reuse.
    pub fn encode_to_array(&self) -> [u8; CTRL_FRAME_LEN] {
        let mut out = [0u8; CTRL_FRAME_LEN];
        self.encode(&mut out);
        out
    }
}

/// Decodes a frame from the first [`CTRL_FRAME_LEN`] bytes of `buf`.
///
/// Validates magic, version, opcode, and status; rejects request frames
/// that carry a non-zero status byte (status is reserved for responses).
pub fn decode(buf: &[u8]) -> Result<Frame, ProtocolError> {
    if buf.len() < CTRL_FRAME_LEN {
        return Err(ProtocolError::Truncated {
            have: buf.len(),
            need: CTRL_FRAME_LEN,
        });
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != CTRL_MAGIC {
        return Err(ProtocolError::BadMagic { found: magic });
    }

    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != CTRL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { version });
    }

    let opcode = Opcode::try_from(buf[6])?;

    if opcode.is_request() && buf[7] != 0 {
        return Err(ProtocolError::NonZeroStatusOnRequest { status: buf[7] });
    }
    let status = StatusCode::try_from(buf[7])?;

    let payload = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);

    Ok(Frame {
        opcode,
        status,
        payload,
    })
}

// -- High-level constructors -------------------------------------------------

impl Frame {
    /// A `Register` request. Reserved payload is zero. The caller MUST
    /// attach exactly one fd via `SCM_RIGHTS` when sending this frame.
    pub fn register_request() -> Self {
        Self {
            opcode: Opcode::Register,
            status: StatusCode::Ok,
            payload: 0,
        }
    }

    /// A successful `Register` response carrying the freshly-allocated
    /// token id.
    pub fn register_response_ok(token_id: u64) -> Self {
        Self {
            opcode: Opcode::RegisterResponse,
            status: StatusCode::Ok,
            payload: token_id,
        }
    }

    /// A `Materialize` request for a previously-registered token id.
    /// The response will arrive with one fd attached via `SCM_RIGHTS`.
    pub fn materialize_request(token_id: u64) -> Self {
        Self {
            opcode: Opcode::Materialize,
            status: StatusCode::Ok,
            payload: token_id,
        }
    }

    /// A successful `Materialize` response. The caller MUST attach
    /// exactly one fd via `SCM_RIGHTS` when sending this frame.
    pub fn materialize_response_ok() -> Self {
        Self {
            opcode: Opcode::MaterializeResponse,
            status: StatusCode::Ok,
            payload: 0,
        }
    }

    /// A `Release` request decrementing the token's refcount.
    pub fn release_request(token_id: u64) -> Self {
        Self {
            opcode: Opcode::Release,
            status: StatusCode::Ok,
            payload: token_id,
        }
    }

    /// A successful `Release` response.
    pub fn release_response_ok() -> Self {
        Self {
            opcode: Opcode::ReleaseResponse,
            status: StatusCode::Ok,
            payload: 0,
        }
    }

    /// An error response. The matching response opcode is derived from
    /// `request_opcode`; if the caller supplies a response opcode here
    /// (e.g. when forwarding an error from inside a handler) it is used
    /// directly.
    pub fn error_response(response_opcode: Opcode, status: StatusCode) -> Self {
        Self {
            opcode: response_opcode,
            status,
            payload: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip_through_u8() {
        for op in [
            Opcode::Register,
            Opcode::Materialize,
            Opcode::Release,
            Opcode::RegisterResponse,
            Opcode::MaterializeResponse,
            Opcode::ReleaseResponse,
        ] {
            assert_eq!(Opcode::try_from(op as u8).unwrap(), op);
        }
    }

    #[test]
    fn opcode_unknown_value_rejected() {
        for v in [0x00u8, 0x04, 0x7f, 0x80, 0xff] {
            assert_eq!(
                Opcode::try_from(v),
                Err(ProtocolError::UnknownOpcode { opcode: v })
            );
        }
    }

    #[test]
    fn opcode_response_for_matches_request_pairs() {
        assert_eq!(
            Opcode::Register.response_for(),
            Some(Opcode::RegisterResponse)
        );
        assert_eq!(
            Opcode::Materialize.response_for(),
            Some(Opcode::MaterializeResponse)
        );
        assert_eq!(
            Opcode::Release.response_for(),
            Some(Opcode::ReleaseResponse)
        );
        assert_eq!(Opcode::RegisterResponse.response_for(), None);
    }

    #[test]
    fn opcode_expected_fd_count_matches_design() {
        assert_eq!(Opcode::Register.expected_fd_count(), 1);
        assert_eq!(Opcode::MaterializeResponse.expected_fd_count(), 1);
        assert_eq!(Opcode::Materialize.expected_fd_count(), 0);
        assert_eq!(Opcode::Release.expected_fd_count(), 0);
        assert_eq!(Opcode::RegisterResponse.expected_fd_count(), 0);
        assert_eq!(Opcode::ReleaseResponse.expected_fd_count(), 0);
    }

    #[test]
    fn status_round_trip_through_u8() {
        for st in [
            StatusCode::Ok,
            StatusCode::UnknownToken,
            StatusCode::RegisterFailed,
            StatusCode::MaterializeFailed,
            StatusCode::Protocol,
            StatusCode::Internal,
        ] {
            assert_eq!(StatusCode::try_from(st as u8).unwrap(), st);
        }
    }

    #[test]
    fn frame_register_request_round_trip() {
        let f = Frame::register_request();
        let bytes = f.encode_to_array();
        let g = decode(&bytes).expect("decode");
        assert_eq!(f, g);
        assert_eq!(g.opcode, Opcode::Register);
        assert_eq!(g.status, StatusCode::Ok);
        assert_eq!(g.payload, 0);
    }

    #[test]
    fn frame_register_response_round_trip() {
        let f = Frame::register_response_ok(0xdead_beef_cafe_babe);
        let bytes = f.encode_to_array();
        let g = decode(&bytes).expect("decode");
        assert_eq!(f, g);
        assert_eq!(g.payload, 0xdead_beef_cafe_babe);
    }

    #[test]
    fn frame_materialize_round_trip() {
        let req = Frame::materialize_request(42);
        let resp = Frame::materialize_response_ok();
        assert_eq!(decode(&req.encode_to_array()).unwrap(), req);
        assert_eq!(decode(&resp.encode_to_array()).unwrap(), resp);
    }

    #[test]
    fn frame_release_round_trip() {
        let req = Frame::release_request(7);
        let resp = Frame::release_response_ok();
        assert_eq!(decode(&req.encode_to_array()).unwrap(), req);
        assert_eq!(decode(&resp.encode_to_array()).unwrap(), resp);
    }

    #[test]
    fn frame_error_response_carries_status() {
        let f = Frame::error_response(Opcode::MaterializeResponse, StatusCode::UnknownToken);
        let bytes = f.encode_to_array();
        let g = decode(&bytes).expect("decode");
        assert_eq!(g.opcode, Opcode::MaterializeResponse);
        assert_eq!(g.status, StatusCode::UnknownToken);
        assert_eq!(g.payload, 0);
    }

    #[test]
    fn decode_truncated_buffer() {
        let buf = [0u8; CTRL_FRAME_LEN - 1];
        assert_eq!(
            decode(&buf),
            Err(ProtocolError::Truncated {
                have: CTRL_FRAME_LEN - 1,
                need: CTRL_FRAME_LEN,
            })
        );
    }

    #[test]
    fn decode_bad_magic() {
        let mut buf = Frame::register_request().encode_to_array();
        buf[0..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        assert_eq!(
            decode(&buf),
            Err(ProtocolError::BadMagic { found: 0xdead_beef })
        );
    }

    #[test]
    fn decode_bad_version() {
        let mut buf = Frame::register_request().encode_to_array();
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            decode(&buf),
            Err(ProtocolError::UnsupportedVersion { version: 99 })
        );
    }

    #[test]
    fn decode_unknown_opcode() {
        let mut buf = Frame::register_request().encode_to_array();
        buf[6] = 0x55;
        assert_eq!(
            decode(&buf),
            Err(ProtocolError::UnknownOpcode { opcode: 0x55 })
        );
    }

    #[test]
    fn decode_request_with_nonzero_status_rejected() {
        let mut buf = Frame::register_request().encode_to_array();
        buf[7] = 0x01;
        assert_eq!(
            decode(&buf),
            Err(ProtocolError::NonZeroStatusOnRequest { status: 0x01 })
        );
    }

    #[test]
    fn decode_response_with_unknown_status() {
        let mut buf = Frame::register_response_ok(0).encode_to_array();
        buf[7] = 0x77;
        assert_eq!(
            decode(&buf),
            Err(ProtocolError::UnknownStatus { status: 0x77 })
        );
    }

    #[test]
    fn frame_constants_match_doc() {
        assert_eq!(CTRL_FRAME_LEN, 16);
        assert_eq!(&CTRL_MAGIC.to_le_bytes(), b"DFBL");
        assert_eq!(CTRL_VERSION, 1);
    }
}
