// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Control protocol for the broker fd-token / state-object control socket.
//!
//! Each worker maintains a long-lived TCP-style Unix-domain socket to
//! the broker. The protocol is strictly request/response: the worker
//! writes one [`Frame`] (header + body, plus optional `SCM_RIGHTS` fd
//! attachment), the broker writes back exactly one response Frame.
//!
//! # Wire format (little-endian)
//!
//! ```text
//!  offset  size  field
//! ───────  ────  ──────────────────────────────────────────────
//!    0      4    magic = 0x4C42_4644 ("LBFD")          // u32
//!    4      2    version = 1                           // u16
//!    6      1    opcode                                // u8 (Opcode)
//!    7      1    status                                // u8 (StatusCode)
//!    8      4    body_len  (≤ BODY_MAX)                // u32
//!   12      4    reserved  (must be zero)              // u32
//! ───────
//!   16  total header bytes, followed by `body_len` body bytes.
//! ```
//!
//! Each opcode defines its own fixed body shape; the body is treated
//! as raw bytes by the framing layer and as a typed struct by the
//! handlers in [`crate::fd_token_client`] / `litebox_broker::fd_token_service`.
//! `SCM_RIGHTS` attachment is per-opcode (see [`Opcode::expected_fd_count`]).
//!
//! # Opcodes
//!
//! Handle-lifecycle (work for any subsystem):
//! - [`Opcode::Register`] / [`Opcode::RegisterResponse`] — register a
//!   host fd (SCM_RIGHTS) and get back a handle id. Used for the
//!   host-fd registry (`fd_tokens`).
//! - [`Opcode::Materialize`] / [`Opcode::MaterializeResponse`] —
//!   resolve a handle id to a fresh host fd (SCM_RIGHTS).
//! - [`Opcode::Release`] / [`Opcode::ReleaseResponse`] — decrement
//!   refcount; works for both host-fd and state-object handles
//!   (broker dispatches by recorded `SubsystemTag`).
//!
//! Notification-ring setup (worker→broker, once per worker):
//! - [`Opcode::RegisterNotificationRing`] / its response — worker
//!   sends one `SCM_RIGHTS` fd (the writer half of its broker→worker
//!   notification ring); broker takes ownership and associates it
//!   with this worker.
//!
//! Eventfd state-object ops:
//! - [`Opcode::CreateEventfd`] / response — broker creates a new
//!   `EventfdState` and returns its handle id.
//! - [`Opcode::ReadEventfd`] / response — broker performs the
//!   `read()` op on the named handle.
//! - [`Opcode::WriteEventfd`] / response — broker performs the
//!   `write(value)` op.
//! - [`Opcode::SubscribeEventfd`] / response — register a
//!   subscription on the handle, bound to this worker's notification
//!   ring (the one previously sent via `RegisterNotificationRing`).
//! - [`Opcode::Unsubscribe`] / response — remove a subscription.
//!
//! # Bounds
//!
//! [`BODY_MAX`] caps the body size. The largest defined body in v1
//! is 24 bytes (Subscribe), so this is comfortably generous; the
//! cap exists primarily to bound memory on a malformed peer.

use alloc::vec::Vec;

/// Wire-format magic ("LBFD" — LiteBox FD).
pub const CTRL_MAGIC: u32 = 0x4C42_4644;

/// Wire-format version.
pub const CTRL_VERSION: u16 = 1;

/// Size of the fixed header. Body bytes follow.
pub const CTRL_HEADER_LEN: usize = 16;

/// Maximum body length the codec will encode or accept. Defensive
/// upper bound — far larger than any legitimate v1 body.
pub const BODY_MAX: u32 = 4096;

/// Opcodes carried in the `opcode` byte of the control frame.
///
/// Naming convention: request opcodes have arbitrary values; response
/// opcodes are `request | 0x80`. The handler dispatcher can derive
/// the response opcode from the request without a lookup table.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Register = 0x01,
    Materialize = 0x02,
    Release = 0x03,
    RegisterNotificationRing = 0x04,
    CreateEventfd = 0x10,
    ReadEventfd = 0x11,
    WriteEventfd = 0x12,
    SubscribeEventfd = 0x13,
    Unsubscribe = 0x14,

    RegisterResponse = 0x81,
    MaterializeResponse = 0x82,
    ReleaseResponse = 0x83,
    RegisterNotificationRingResponse = 0x84,
    CreateEventfdResponse = 0x90,
    ReadEventfdResponse = 0x91,
    WriteEventfdResponse = 0x92,
    SubscribeEventfdResponse = 0x93,
    UnsubscribeResponse = 0x94,
}

impl Opcode {
    /// Returns the matching response opcode for a request opcode, or
    /// `None` if `self` is itself a response.
    pub fn response_for(self) -> Option<Opcode> {
        match self {
            Opcode::Register => Some(Opcode::RegisterResponse),
            Opcode::Materialize => Some(Opcode::MaterializeResponse),
            Opcode::Release => Some(Opcode::ReleaseResponse),
            Opcode::RegisterNotificationRing => Some(Opcode::RegisterNotificationRingResponse),
            Opcode::CreateEventfd => Some(Opcode::CreateEventfdResponse),
            Opcode::ReadEventfd => Some(Opcode::ReadEventfdResponse),
            Opcode::WriteEventfd => Some(Opcode::WriteEventfdResponse),
            Opcode::SubscribeEventfd => Some(Opcode::SubscribeEventfdResponse),
            Opcode::Unsubscribe => Some(Opcode::UnsubscribeResponse),
            _ => None,
        }
    }

    /// True if this opcode is a request.
    pub fn is_request(self) -> bool {
        matches!(
            self,
            Opcode::Register
                | Opcode::Materialize
                | Opcode::Release
                | Opcode::RegisterNotificationRing
                | Opcode::CreateEventfd
                | Opcode::ReadEventfd
                | Opcode::WriteEventfd
                | Opcode::SubscribeEventfd
                | Opcode::Unsubscribe
        )
    }

    /// Returns the number of `SCM_RIGHTS` fds that MUST accompany
    /// this opcode (request side for `Register`/`RegisterNotificationRing`,
    /// response side for `MaterializeResponse`).
    pub fn expected_fd_count(self) -> usize {
        match self {
            // RegisterNotificationRing sends both memfds of a
            // ShmemRingPair (we use only the writer side; the unused
            // direction is inert).
            Opcode::RegisterNotificationRing => 2,
            Opcode::Register | Opcode::MaterializeResponse => 1,
            _ => 0,
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
            0x04 => Ok(Opcode::RegisterNotificationRing),
            0x10 => Ok(Opcode::CreateEventfd),
            0x11 => Ok(Opcode::ReadEventfd),
            0x12 => Ok(Opcode::WriteEventfd),
            0x13 => Ok(Opcode::SubscribeEventfd),
            0x14 => Ok(Opcode::Unsubscribe),
            0x81 => Ok(Opcode::RegisterResponse),
            0x82 => Ok(Opcode::MaterializeResponse),
            0x83 => Ok(Opcode::ReleaseResponse),
            0x84 => Ok(Opcode::RegisterNotificationRingResponse),
            0x90 => Ok(Opcode::CreateEventfdResponse),
            0x91 => Ok(Opcode::ReadEventfdResponse),
            0x92 => Ok(Opcode::WriteEventfdResponse),
            0x93 => Ok(Opcode::SubscribeEventfdResponse),
            0x94 => Ok(Opcode::UnsubscribeResponse),
            other => Err(ProtocolError::UnknownOpcode { opcode: other }),
        }
    }
}

/// Status code carried in the `status` byte. Requests MUST set 0;
/// responses use 0 for success, non-zero for operation-level errors.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Ok = 0x00,
    UnknownHandle = 0x01,
    RegisterFailed = 0x02,
    MaterializeFailed = 0x03,
    /// Eventfd op would block per Linux semantics (counter is 0 on
    /// read, or `EVENTFD_MAX` reached on write).
    WouldBlock = 0x04,
    /// `write(u64::MAX)` — Linux EINVAL.
    InvalidValue = 0x05,
    /// Subscription id already in use for the target state.
    DuplicateSubscription = 0x06,
    /// Subscription id not found.
    UnknownSubscription = 0x07,
    /// The handle's subsystem tag doesn't match the operation
    /// (e.g. ReadEventfd against a host-fd-tagged handle).
    SubsystemMismatch = 0x08,
    /// The worker hasn't yet registered a notification ring; the
    /// requested op requires one (e.g. SubscribeEventfd).
    NoNotificationRing = 0x09,

    /// Generic protocol violation.
    Protocol = 0x10,
    /// Generic broker-internal error.
    Internal = 0x11,
}

impl TryFrom<u8> for StatusCode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(StatusCode::Ok),
            0x01 => Ok(StatusCode::UnknownHandle),
            0x02 => Ok(StatusCode::RegisterFailed),
            0x03 => Ok(StatusCode::MaterializeFailed),
            0x04 => Ok(StatusCode::WouldBlock),
            0x05 => Ok(StatusCode::InvalidValue),
            0x06 => Ok(StatusCode::DuplicateSubscription),
            0x07 => Ok(StatusCode::UnknownSubscription),
            0x08 => Ok(StatusCode::SubsystemMismatch),
            0x09 => Ok(StatusCode::NoNotificationRing),
            0x10 => Ok(StatusCode::Protocol),
            0x11 => Ok(StatusCode::Internal),
            other => Err(ProtocolError::UnknownStatus { status: other }),
        }
    }
}

/// Errors produced by the codec. Distinct from operation-level
/// errors carried in [`StatusCode`].
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    HeaderTruncated {
        have: usize,
        need: usize,
    },
    BodyTruncated {
        have: usize,
        need: usize,
    },
    BadMagic {
        found: u32,
    },
    UnsupportedVersion {
        version: u16,
    },
    UnknownOpcode {
        opcode: u8,
    },
    UnknownStatus {
        status: u8,
    },
    NonZeroStatusOnRequest {
        status: u8,
    },
    NonZeroReserved {
        reserved: u32,
    },
    BodyTooLarge {
        body_len: u32,
        max: u32,
    },
    /// Caller passed a body whose length doesn't match the opcode's
    /// expected body shape.
    WrongBodyLen {
        opcode: Opcode,
        got: usize,
        want: usize,
    },
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::HeaderTruncated { have, need } => {
                write!(f, "control header truncated: have {have}, need {need}")
            }
            ProtocolError::BodyTruncated { have, need } => {
                write!(f, "control body truncated: have {have}, need {need}")
            }
            ProtocolError::BadMagic { found } => {
                write!(
                    f,
                    "bad control magic: 0x{found:08x}, expected 0x{CTRL_MAGIC:08x}"
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
                write!(f, "request frame had non-zero status 0x{status:02x}")
            }
            ProtocolError::NonZeroReserved { reserved } => {
                write!(f, "non-zero reserved field: 0x{reserved:08x}")
            }
            ProtocolError::BodyTooLarge { body_len, max } => {
                write!(f, "body_len {body_len} exceeds max {max}")
            }
            ProtocolError::WrongBodyLen { opcode, got, want } => {
                write!(
                    f,
                    "wrong body length for opcode {opcode:?}: got {got}, expected {want}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}

/// A decoded frame, with body bytes borrowed from the source buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub opcode: Opcode,
    pub status: StatusCode,
    pub body: &'a [u8],
    /// Total bytes consumed (header + body). Caller advances by this.
    pub consumed: usize,
}

/// An owned, pre-encoded frame ready to write to a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedFrame {
    pub opcode: Opcode,
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl OwnedFrame {
    /// Encodes the frame to a contiguous byte buffer.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let body_len = self.body.len();
        if body_len > BODY_MAX as usize {
            return Err(ProtocolError::BodyTooLarge {
                #[allow(clippy::cast_possible_truncation)]
                body_len: body_len as u32,
                max: BODY_MAX,
            });
        }
        let mut out = Vec::with_capacity(CTRL_HEADER_LEN + body_len);
        out.extend_from_slice(&CTRL_MAGIC.to_le_bytes());
        out.extend_from_slice(&CTRL_VERSION.to_le_bytes());
        out.push(self.opcode as u8);
        out.push(self.status as u8);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(body_len as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

/// Decodes a single frame from the start of `buf`. Returns the frame
/// (borrowing body bytes from `buf`) and the number of bytes consumed.
pub fn decode(buf: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    if buf.len() < CTRL_HEADER_LEN {
        return Err(ProtocolError::HeaderTruncated {
            have: buf.len(),
            need: CTRL_HEADER_LEN,
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
    let body_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if body_len > BODY_MAX {
        return Err(ProtocolError::BodyTooLarge {
            body_len,
            max: BODY_MAX,
        });
    }
    let reserved = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    let total = CTRL_HEADER_LEN + body_len as usize;
    if buf.len() < total {
        return Err(ProtocolError::BodyTruncated {
            have: buf.len(),
            need: total,
        });
    }
    Ok(Frame {
        opcode,
        status,
        body: &buf[CTRL_HEADER_LEN..total],
        consumed: total,
    })
}

// -- Typed body builders --------------------------------------------------
//
// Each opcode has a fixed body layout. These helpers construct the
// matching `OwnedFrame` from typed arguments and decode body bytes
// from the wire into typed views.

/// Body for [`Opcode::Register`] — empty (host fd attached via SCM_RIGHTS).
pub fn build_register_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::Register,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::RegisterResponse`]: handle id (u64 LE).
pub fn build_register_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterResponse,
        status: StatusCode::Ok,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::Materialize`]: handle id (u64 LE).
pub fn build_materialize_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::Materialize,
        status: StatusCode::Ok,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::MaterializeResponse`]: empty (fd attached via SCM_RIGHTS).
pub fn build_materialize_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::MaterializeResponse,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::Release`]: handle id.
pub fn build_release_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::Release,
        status: StatusCode::Ok,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReleaseResponse`]: empty.
pub fn build_release_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReleaseResponse,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::RegisterNotificationRing`]: empty (ring fd via SCM_RIGHTS).
pub fn build_register_notification_ring_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterNotificationRing,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for the matching response: empty.
pub fn build_register_notification_ring_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterNotificationRingResponse,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::CreateEventfd`]: (initial: u64, semaphore: u8, pad: 7).
pub fn build_create_eventfd_request(initial: u64, semaphore: bool) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&initial.to_le_bytes());
    body.push(u8::from(semaphore));
    body.extend_from_slice(&[0u8; 7]);
    OwnedFrame {
        opcode: Opcode::CreateEventfd,
        status: StatusCode::Ok,
        body,
    }
}

/// Decodes the body of a CreateEventfd request frame.
pub fn parse_create_eventfd_body(body: &[u8]) -> Result<(u64, bool), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateEventfd,
            got: body.len(),
            want: 16,
        });
    }
    let initial = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let semaphore = body[8] != 0;
    // bytes 9..16 must be zero (forward-compat).
    if body[9..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((initial, semaphore))
}

/// Body for [`Opcode::CreateEventfdResponse`]: handle id.
pub fn build_create_eventfd_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateEventfdResponse,
        status: StatusCode::Ok,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadEventfd`]: handle id.
pub fn build_read_eventfd_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadEventfd,
        status: StatusCode::Ok,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadEventfdResponse`]: value (u64 LE).
pub fn build_read_eventfd_response_ok(value: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadEventfdResponse,
        status: StatusCode::Ok,
        body: value.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::WriteEventfd`]: (handle: u64, value: u64).
pub fn build_write_eventfd_request(handle_id: u64, value: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&value.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::WriteEventfd,
        status: StatusCode::Ok,
        body,
    }
}

/// Decodes the body of a WriteEventfd request.
pub fn parse_write_eventfd_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WriteEventfd,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let value = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    Ok((handle, value))
}

/// Body for [`Opcode::WriteEventfdResponse`]: empty.
pub fn build_write_eventfd_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::WriteEventfdResponse,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::SubscribeEventfd`]: (handle: u64, sub_id: u64, events: u32, pad: 4).
pub fn build_subscribe_eventfd_request(
    handle_id: u64,
    subscription_id: u64,
    events_mask: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&subscription_id.to_le_bytes());
    body.extend_from_slice(&events_mask.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::SubscribeEventfd,
        status: StatusCode::Ok,
        body,
    }
}

/// Decodes the body of a SubscribeEventfd request.
pub fn parse_subscribe_eventfd_body(body: &[u8]) -> Result<(u64, u64, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SubscribeEventfd,
            got: body.len(),
            want: 24,
        });
    }
    let handle = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let sub_id = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let events = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
    if body[20..24].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((handle, sub_id, events))
}

/// Body for SubscribeEventfdResponse: empty.
pub fn build_subscribe_eventfd_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SubscribeEventfdResponse,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::Unsubscribe`]: (handle: u64, sub_id: u64).
pub fn build_unsubscribe_request(handle_id: u64, subscription_id: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&subscription_id.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::Unsubscribe,
        status: StatusCode::Ok,
        body,
    }
}

/// Decodes the body of an Unsubscribe request.
pub fn parse_unsubscribe_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::Unsubscribe,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let sub_id = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    Ok((handle, sub_id))
}

/// Body for UnsubscribeResponse: empty.
pub fn build_unsubscribe_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::UnsubscribeResponse,
        status: StatusCode::Ok,
        body: Vec::new(),
    }
}

/// Constructs an error response. The caller supplies the response
/// opcode (derived from the request via [`Opcode::response_for`]) and
/// a non-`Ok` status.
pub fn build_error_response(response_opcode: Opcode, status: StatusCode) -> OwnedFrame {
    OwnedFrame {
        opcode: response_opcode,
        status,
        body: Vec::new(),
    }
}

/// Decode a body whose layout is exactly a single `u64`. Used for
/// `Materialize`/`Release`/`ReadEventfd`/`RegisterResponse`/...
pub fn parse_handle_body(body: &[u8], opcode: Opcode) -> Result<u64, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 8,
        });
    }
    Ok(u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip() {
        for op in [
            Opcode::Register,
            Opcode::Materialize,
            Opcode::Release,
            Opcode::RegisterNotificationRing,
            Opcode::CreateEventfd,
            Opcode::ReadEventfd,
            Opcode::WriteEventfd,
            Opcode::SubscribeEventfd,
            Opcode::Unsubscribe,
            Opcode::RegisterResponse,
            Opcode::MaterializeResponse,
            Opcode::ReleaseResponse,
            Opcode::RegisterNotificationRingResponse,
            Opcode::CreateEventfdResponse,
            Opcode::ReadEventfdResponse,
            Opcode::WriteEventfdResponse,
            Opcode::SubscribeEventfdResponse,
            Opcode::UnsubscribeResponse,
        ] {
            assert_eq!(Opcode::try_from(op as u8).unwrap(), op);
        }
    }

    #[test]
    fn response_for_pairs() {
        assert_eq!(
            Opcode::Register.response_for(),
            Some(Opcode::RegisterResponse)
        );
        assert_eq!(
            Opcode::CreateEventfd.response_for(),
            Some(Opcode::CreateEventfdResponse)
        );
        assert_eq!(
            Opcode::Unsubscribe.response_for(),
            Some(Opcode::UnsubscribeResponse)
        );
        assert_eq!(Opcode::ReadEventfdResponse.response_for(), None);
    }

    #[test]
    fn expected_fd_count() {
        assert_eq!(Opcode::Register.expected_fd_count(), 1);
        assert_eq!(Opcode::RegisterNotificationRing.expected_fd_count(), 2);
        assert_eq!(Opcode::MaterializeResponse.expected_fd_count(), 1);
        for op in [
            Opcode::Materialize,
            Opcode::Release,
            Opcode::CreateEventfd,
            Opcode::ReadEventfd,
            Opcode::WriteEventfd,
            Opcode::SubscribeEventfd,
            Opcode::Unsubscribe,
            Opcode::RegisterResponse,
            Opcode::CreateEventfdResponse,
            Opcode::ReadEventfdResponse,
        ] {
            assert_eq!(op.expected_fd_count(), 0, "{op:?}");
        }
    }

    #[test]
    fn round_trip_register_request() {
        let f = build_register_request();
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        assert_eq!(g.opcode, Opcode::Register);
        assert_eq!(g.status, StatusCode::Ok);
        assert!(g.body.is_empty());
        assert_eq!(g.consumed, CTRL_HEADER_LEN);
    }

    #[test]
    fn round_trip_register_response() {
        let f = build_register_response_ok(0xdead_beef_cafe_babe);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        assert_eq!(g.opcode, Opcode::RegisterResponse);
        assert_eq!(
            parse_handle_body(g.body, g.opcode).unwrap(),
            0xdead_beef_cafe_babe
        );
    }

    #[test]
    fn round_trip_create_eventfd_request() {
        let f = build_create_eventfd_request(42, true);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        assert_eq!(g.opcode, Opcode::CreateEventfd);
        let (init, sema) = parse_create_eventfd_body(g.body).unwrap();
        assert_eq!(init, 42);
        assert!(sema);
    }

    #[test]
    fn round_trip_create_eventfd_response() {
        let f = build_create_eventfd_response_ok(7);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        assert_eq!(g.opcode, Opcode::CreateEventfdResponse);
        assert_eq!(parse_handle_body(g.body, g.opcode).unwrap(), 7);
    }

    #[test]
    fn round_trip_write_eventfd_request() {
        let f = build_write_eventfd_request(0xabc, 0x123);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        let (handle, value) = parse_write_eventfd_body(g.body).unwrap();
        assert_eq!(handle, 0xabc);
        assert_eq!(value, 0x123);
    }

    #[test]
    fn round_trip_subscribe_eventfd_request() {
        let f = build_subscribe_eventfd_request(11, 22, 0x0001);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        let (handle, sub, events) = parse_subscribe_eventfd_body(g.body).unwrap();
        assert_eq!(handle, 11);
        assert_eq!(sub, 22);
        assert_eq!(events, 0x0001);
    }

    #[test]
    fn round_trip_unsubscribe_request() {
        let f = build_unsubscribe_request(11, 22);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        let (handle, sub) = parse_unsubscribe_body(g.body).unwrap();
        assert_eq!(handle, 11);
        assert_eq!(sub, 22);
    }

    #[test]
    fn back_to_back_frames_share_buffer() {
        let f1 = build_register_response_ok(7);
        let f2 = build_create_eventfd_response_ok(11);
        let mut buf = f1.encode().unwrap();
        buf.extend_from_slice(&f2.encode().unwrap());

        let g1 = decode(&buf).unwrap();
        assert_eq!(g1.opcode, Opcode::RegisterResponse);
        let g2 = decode(&buf[g1.consumed..]).unwrap();
        assert_eq!(g2.opcode, Opcode::CreateEventfdResponse);
    }

    #[test]
    fn decode_header_truncation() {
        let buf = [0u8; CTRL_HEADER_LEN - 1];
        match decode(&buf) {
            Err(ProtocolError::HeaderTruncated { have, need }) => {
                assert_eq!(have, CTRL_HEADER_LEN - 1);
                assert_eq!(need, CTRL_HEADER_LEN);
            }
            other => panic!("expected HeaderTruncated, got {other:?}"),
        }
    }

    #[test]
    fn decode_body_truncation() {
        // Encode a frame with non-zero body, then strip a byte off the end.
        let f = build_create_eventfd_request(0, false);
        let mut bytes = f.encode().unwrap();
        bytes.pop();
        match decode(&bytes) {
            Err(ProtocolError::BodyTruncated { .. }) => {}
            other => panic!("expected BodyTruncated, got {other:?}"),
        }
    }

    #[test]
    fn decode_bad_magic() {
        let mut buf = build_register_request().encode().unwrap();
        buf[0..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        match decode(&buf) {
            Err(ProtocolError::BadMagic { found: 0xdead_beef }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn decode_bad_version() {
        let mut buf = build_register_request().encode().unwrap();
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());
        match decode(&buf) {
            Err(ProtocolError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn decode_unknown_opcode() {
        let mut buf = build_register_request().encode().unwrap();
        buf[6] = 0x55;
        match decode(&buf) {
            Err(ProtocolError::UnknownOpcode { opcode: 0x55 }) => {}
            other => panic!("expected UnknownOpcode, got {other:?}"),
        }
    }

    #[test]
    fn decode_nonzero_status_on_request_rejected() {
        let mut buf = build_register_request().encode().unwrap();
        buf[7] = 1;
        match decode(&buf) {
            Err(ProtocolError::NonZeroStatusOnRequest { status: 1 }) => {}
            other => panic!("expected NonZeroStatusOnRequest, got {other:?}"),
        }
    }

    #[test]
    fn decode_nonzero_reserved_rejected() {
        let mut buf = build_register_request().encode().unwrap();
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());
        match decode(&buf) {
            Err(ProtocolError::NonZeroReserved { reserved: 1 }) => {}
            other => panic!("expected NonZeroReserved, got {other:?}"),
        }
    }

    #[test]
    fn decode_body_too_large_rejected() {
        // Manually build a header announcing oversize body.
        let mut buf = [0u8; CTRL_HEADER_LEN];
        buf[0..4].copy_from_slice(&CTRL_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&CTRL_VERSION.to_le_bytes());
        buf[6] = Opcode::Register as u8;
        buf[8..12].copy_from_slice(&(BODY_MAX + 1).to_le_bytes());
        match decode(&buf) {
            Err(ProtocolError::BodyTooLarge { .. }) => {}
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_handle_body_wrong_size_rejected() {
        match parse_handle_body(&[0u8; 7], Opcode::Materialize) {
            Err(ProtocolError::WrongBodyLen {
                opcode: Opcode::Materialize,
                got: 7,
                want: 8,
            }) => {}
            other => panic!("expected WrongBodyLen, got {other:?}"),
        }
    }

    #[test]
    fn parse_create_eventfd_body_nonzero_padding_rejected() {
        let mut body = [0u8; 16];
        body[9] = 1; // pad byte
        match parse_create_eventfd_body(&body) {
            Err(ProtocolError::NonZeroReserved { .. }) => {}
            other => panic!("expected NonZeroReserved, got {other:?}"),
        }
    }

    #[test]
    fn error_response_carries_status() {
        let f = build_error_response(Opcode::MaterializeResponse, StatusCode::UnknownHandle);
        let bytes = f.encode().unwrap();
        let g = decode(&bytes).unwrap();
        assert_eq!(g.opcode, Opcode::MaterializeResponse);
        assert_eq!(g.status, StatusCode::UnknownHandle);
    }
}
