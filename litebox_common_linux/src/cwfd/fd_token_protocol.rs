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
//! Process state-object ops (Phase G):
//! - [`Opcode::RegisterProcess`] / response — broker allocates a guest pid.
//! - [`Opcode::SubscribeProcessExit`] / response — subscribe to exit readiness
//!   and receive a cached exit-code snapshot if already exited.
//! - [`Opcode::MarkProcessExited`] / response — worker records final exit state.
//!
//! # Bounds
//!
//! [`BODY_MAX`] caps the body size. The largest defined body in v1
//! is 24 bytes (Subscribe), so this is comfortably generous; the
//! cap exists primarily to bound memory on a malformed peer.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use alloc::vec::Vec;

/// Wire-format magic ("LBFD" — LiteBox FD).
pub const CTRL_MAGIC: u32 = 0x4C42_4644;

/// Wire-format version.
pub const CTRL_VERSION: u16 = 1;

/// Size of the fixed header. Body bytes follow.
pub const CTRL_HEADER_LEN: usize = 16;

/// Maximum body length the codec will encode or accept. Defensive
/// upper bound — far larger than any legitimate v1 body.
pub const BODY_MAX: u32 = 65536;

/// Opcodes carried in the `opcode` byte of the control frame.
///
/// Naming convention: request opcodes have arbitrary values; response
/// opcodes are `request | 0x80`. The handler dispatcher can derive
/// the response opcode from the request without a lookup table.
///
/// # Opcode range allocation
///
/// To let the broker-managed-fd kinds grow independently, each kind
/// owns a 16-byte opcode range. New kinds append within their range;
/// the response opcode is the request opcode with bit 7 set.
///
/// | Range            | Owner                       |
/// |------------------|-----------------------------|
/// | `0x00`–`0x0F`    | Token registry + transport  |
/// | `0x10`–`0x1F`    | Eventfd state (P2.0)        |
/// | `0x20`–`0x2F`    | Pidfd state (P2.B)          |
/// | `0x30`–`0x3F`    | UnixSocket state (P2.A)     |
/// | `0x40`–`0x4F`    | Signalfd state (P2.C)       |
/// | `0x50`–`0x5F`    | Pipe state (Phase C)        |
/// | `0x60`–`0x6F`    | Pty state (Phase E)         |
/// | `0x70`–`0x78`    | Process state (Phase G)     |
/// | `0x79`–`0x7C`    | TCP conn state (BrokerTcpConn) |
///
/// Within a kind's range, follow the eventfd template:
/// `0xN0` = create, `0xN1` = read-like primary op, `0xN2` = write-like
/// primary op, `0xN3` = subscribe, etc. Unsubscribe / DupHandle live
/// in the shared `0x14` / `0x15` slots — they're kind-agnostic.
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
    CreateSignalfd = 0x40,
    ReadSiginfo = 0x41,
    PushSiginfo = 0x42,
    CreatePipe = 0x50,
    ReadPipe = 0x51,
    WritePipe = 0x52,
    CreateSocketPair = 0x30,
    ReadSocketPair = 0x31,
    WriteSocketPair = 0x32,
    ShutdownSocketPairWrite = 0x33,
    CreatePty = 0x60,
    OpenPtySlave = 0x65,
    PtyRead = 0x61,
    PtyWrite = 0x62,
    SubscribePty = 0x63,
    PtyIoctl = 0x64,
    Unsubscribe = 0x14,
    DupHandle = 0x15,
    CreatePidfd = 0x20,
    PidfdExited = 0x21,
    /// Broker-hosted process registration. Allocates a globally-
    /// unique guest pid in the broker's `process_registry`. The
    /// response carries the new pid as a `StateHandle` id (low 32
    /// bits are the Linux pid). Phase 1: empty request body.
    RegisterProcess = 0x70,
    /// Subscribe this worker's notification ring to broker-owned process exit.
    SubscribeProcessExit = 0x71,
    /// Mark a broker-owned process as exited and wake exit subscribers.
    MarkProcessExited = 0x72,
    /// Phase F.5+ PE.1 Step D: release every (pid, *) entry this
    /// connection holds for the given guest pid. Sent by the shim
    /// during `prepare_for_exit` after `close_all_fds`. Body:
    /// `pid: u32` followed by 4 reserved bytes (must be zero).
    /// Response body: `released_count: u32` (number of refs
    /// decremented across both state and process registries),
    /// then 4 reserved bytes.
    ReleaseAllForPid = 0x73,
    /// Subscribe this worker's notification ring to pgrp signal delivery.
    SubscribeSignalInbox = 0x74,
    /// Remove this worker's pgrp signal delivery subscription.
    UnsubscribeSignalInbox = 0x75,
    /// Ask the broker to dispatch a pgrp signal through PgrpSignalInbox.
    DeliverSignalInbox = 0x76,
    /// Stamp a process-group change in the broker before the shim cache mutates.
    SetPgid = 0x77,
    /// Stamp session creation in the broker before the shim cache mutates.
    SetSid = 0x78,
    ReadTcpConn = 0x79,
    WriteTcpConn = 0x7A,
    ShutdownTcpConn = 0x7B,
    PollTcpConnEvents = 0x7C,

    RegisterResponse = 0x81,
    MaterializeResponse = 0x82,
    ReleaseResponse = 0x83,
    RegisterNotificationRingResponse = 0x84,
    CreateEventfdResponse = 0x90,
    ReadEventfdResponse = 0x91,
    WriteEventfdResponse = 0x92,
    SubscribeEventfdResponse = 0x93,
    CreateSignalfdResponse = 0xC0,
    ReadSiginfoResponse = 0xC1,
    PushSiginfoResponse = 0xC2,
    CreatePipeResponse = 0xD0,
    ReadPipeResponse = 0xD1,
    WritePipeResponse = 0xD2,
    CreateSocketPairResponse = 0xB0,
    ReadSocketPairResponse = 0xB1,
    WriteSocketPairResponse = 0xB2,
    ShutdownSocketPairWriteResponse = 0xB3,
    CreatePtyResponse = 0xE0,
    OpenPtySlaveResponse = 0xE5,
    PtyReadResponse = 0xE1,
    PtyWriteResponse = 0xE2,
    SubscribePtyResponse = 0xE3,
    PtyIoctlResponse = 0xE4,
    UnsubscribeResponse = 0x94,
    DupHandleResponse = 0x95,
    CreatePidfdResponse = 0xA0,
    PidfdExitedResponse = 0xA1,
    RegisterProcessResponse = 0xF0,
    SubscribeProcessExitResponse = 0xF1,
    MarkProcessExitedResponse = 0xF2,
    /// Response for [`Opcode::ReleaseAllForPid`].
    ReleaseAllForPidResponse = 0xF3,
    SubscribeSignalInboxResponse = 0xF4,
    UnsubscribeSignalInboxResponse = 0xF5,
    DeliverSignalInboxResponse = 0xF6,
    SetPgidResponse = 0xF7,
    SetSidResponse = 0xF8,
    ReadTcpConnResponse = 0xF9,
    WriteTcpConnResponse = 0xFA,
    ShutdownTcpConnResponse = 0xFB,
    PollTcpConnEventsResponse = 0xFC,
}

/// Reserved opcode ranges per kind. P2.B/A/C subagents append their
/// opcodes within these ranges, then add `from_u8` arms + a
/// `response_for` mapping. The reservation here documents the
/// allocation contract; the actual `Opcode::CreateXxx` variants
/// land in their respective subphase commits.
pub mod opcode_ranges {
    /// Pidfd state (P2.B): create / exit-query / subscribe.
    pub const PIDFD_BASE: u8 = 0x20;
    pub const PIDFD_RESPONSE_BASE: u8 = 0xA0;

    /// UnixSocket state (P2.A): create / sendmsg / recvmsg / shutdown / subscribe.
    pub const UNIX_SOCKET_BASE: u8 = 0x30;
    pub const UNIX_SOCKET_RESPONSE_BASE: u8 = 0xB0;

    /// Signalfd state (P2.C): create / read-siginfo / subscribe.
    pub const SIGNALFD_BASE: u8 = 0x40;
    pub const SIGNALFD_RESPONSE_BASE: u8 = 0xC0;

    /// Pipe state (Phase C): create / read / write / subscribe / close-end.
    pub const PIPE_BASE: u8 = 0x50;
    pub const PIPE_RESPONSE_BASE: u8 = 0xD0;

    /// Pty state (Phase E): create / read / write / subscribe / ioctl.
    pub const PTY_BASE: u8 = 0x60;
    pub const PTY_RESPONSE_BASE: u8 = 0xE0;

    /// Process state (Phase G): 0x70 RegisterProcess, 0x71 SubscribeProcessExit,
    /// 0x72 MarkProcessExited.
    pub const PROCESS_BASE: u8 = 0x70;
    pub const PROCESS_RESPONSE_BASE: u8 = 0xF0;

    /// Connected TCP state: read / write / shutdown / poll-events.
    pub const TCP_CONN_BASE: u8 = 0x79;
    pub const TCP_CONN_RESPONSE_BASE: u8 = 0xF9;
}

/// Endpoint side for a broker-hosted PTY handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyEndpoint {
    Master = 0,
    Slave = 1,
}

impl PtyEndpoint {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Master),
            1 => Some(Self::Slave),
            _ => None,
        }
    }
}

/// Pty ioctl multiplex sub-opcode carried by [`Opcode::PtyIoctl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PtyIoctlOp {
    Tcgets = 1,
    Tcsets = 2,
    Tiocgwinsz = 3,
    Tiocswinsz = 4,
    Tiocgpgrp = 5,
    Tiocspgrp = 6,
    Tiocsctty = 7,
    Tiocgptn = 8,
    Tiocsptlk = 9,
    Tiocgsid = 10,
}

impl PtyIoctlOp {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Tcgets),
            2 => Some(Self::Tcsets),
            3 => Some(Self::Tiocgwinsz),
            4 => Some(Self::Tiocswinsz),
            5 => Some(Self::Tiocgpgrp),
            6 => Some(Self::Tiocspgrp),
            7 => Some(Self::Tiocsctty),
            8 => Some(Self::Tiocgptn),
            9 => Some(Self::Tiocsptlk),
            10 => Some(Self::Tiocgsid),
            _ => None,
        }
    }
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
            Opcode::CreateSignalfd => Some(Opcode::CreateSignalfdResponse),
            Opcode::ReadSiginfo => Some(Opcode::ReadSiginfoResponse),
            Opcode::PushSiginfo => Some(Opcode::PushSiginfoResponse),
            Opcode::CreatePipe => Some(Opcode::CreatePipeResponse),
            Opcode::ReadPipe => Some(Opcode::ReadPipeResponse),
            Opcode::WritePipe => Some(Opcode::WritePipeResponse),
            Opcode::CreateSocketPair => Some(Opcode::CreateSocketPairResponse),
            Opcode::ReadSocketPair => Some(Opcode::ReadSocketPairResponse),
            Opcode::WriteSocketPair => Some(Opcode::WriteSocketPairResponse),
            Opcode::ShutdownSocketPairWrite => Some(Opcode::ShutdownSocketPairWriteResponse),
            Opcode::CreatePty => Some(Opcode::CreatePtyResponse),
            Opcode::OpenPtySlave => Some(Opcode::OpenPtySlaveResponse),
            Opcode::PtyRead => Some(Opcode::PtyReadResponse),
            Opcode::PtyWrite => Some(Opcode::PtyWriteResponse),
            Opcode::SubscribePty => Some(Opcode::SubscribePtyResponse),
            Opcode::PtyIoctl => Some(Opcode::PtyIoctlResponse),
            Opcode::Unsubscribe => Some(Opcode::UnsubscribeResponse),
            Opcode::DupHandle => Some(Opcode::DupHandleResponse),
            Opcode::CreatePidfd => Some(Opcode::CreatePidfdResponse),
            Opcode::PidfdExited => Some(Opcode::PidfdExitedResponse),
            Opcode::RegisterProcess => Some(Opcode::RegisterProcessResponse),
            Opcode::SubscribeProcessExit => Some(Opcode::SubscribeProcessExitResponse),
            Opcode::MarkProcessExited => Some(Opcode::MarkProcessExitedResponse),
            Opcode::ReleaseAllForPid => Some(Opcode::ReleaseAllForPidResponse),
            Opcode::SubscribeSignalInbox => Some(Opcode::SubscribeSignalInboxResponse),
            Opcode::UnsubscribeSignalInbox => Some(Opcode::UnsubscribeSignalInboxResponse),
            Opcode::DeliverSignalInbox => Some(Opcode::DeliverSignalInboxResponse),
            Opcode::SetPgid => Some(Opcode::SetPgidResponse),
            Opcode::SetSid => Some(Opcode::SetSidResponse),
            Opcode::ReadTcpConn => Some(Opcode::ReadTcpConnResponse),
            Opcode::WriteTcpConn => Some(Opcode::WriteTcpConnResponse),
            Opcode::ShutdownTcpConn => Some(Opcode::ShutdownTcpConnResponse),
            Opcode::PollTcpConnEvents => Some(Opcode::PollTcpConnEventsResponse),
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
                | Opcode::CreateSignalfd
                | Opcode::ReadSiginfo
                | Opcode::PushSiginfo
                | Opcode::CreatePipe
                | Opcode::ReadPipe
                | Opcode::WritePipe
                | Opcode::CreateSocketPair
                | Opcode::ReadSocketPair
                | Opcode::WriteSocketPair
                | Opcode::ShutdownSocketPairWrite
                | Opcode::CreatePty
                | Opcode::OpenPtySlave
                | Opcode::PtyRead
                | Opcode::PtyWrite
                | Opcode::SubscribePty
                | Opcode::PtyIoctl
                | Opcode::Unsubscribe
                | Opcode::DupHandle
                | Opcode::CreatePidfd
                | Opcode::PidfdExited
                | Opcode::RegisterProcess
                | Opcode::SubscribeProcessExit
                | Opcode::MarkProcessExited
                | Opcode::ReleaseAllForPid
                | Opcode::SubscribeSignalInbox
                | Opcode::UnsubscribeSignalInbox
                | Opcode::DeliverSignalInbox
                | Opcode::SetPgid
                | Opcode::SetSid
                | Opcode::ReadTcpConn
                | Opcode::WriteTcpConn
                | Opcode::ShutdownTcpConn
                | Opcode::PollTcpConnEvents
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
            0x40 => Ok(Opcode::CreateSignalfd),
            0x41 => Ok(Opcode::ReadSiginfo),
            0x42 => Ok(Opcode::PushSiginfo),
            0x50 => Ok(Opcode::CreatePipe),
            0x51 => Ok(Opcode::ReadPipe),
            0x52 => Ok(Opcode::WritePipe),
            0x30 => Ok(Opcode::CreateSocketPair),
            0x31 => Ok(Opcode::ReadSocketPair),
            0x32 => Ok(Opcode::WriteSocketPair),
            0x33 => Ok(Opcode::ShutdownSocketPairWrite),
            0x60 => Ok(Opcode::CreatePty),
            0x65 => Ok(Opcode::OpenPtySlave),
            0x61 => Ok(Opcode::PtyRead),
            0x62 => Ok(Opcode::PtyWrite),
            0x63 => Ok(Opcode::SubscribePty),
            0x64 => Ok(Opcode::PtyIoctl),
            0x14 => Ok(Opcode::Unsubscribe),
            0x15 => Ok(Opcode::DupHandle),
            0x20 => Ok(Opcode::CreatePidfd),
            0x21 => Ok(Opcode::PidfdExited),
            0x70 => Ok(Opcode::RegisterProcess),
            0x71 => Ok(Opcode::SubscribeProcessExit),
            0x72 => Ok(Opcode::MarkProcessExited),
            0x73 => Ok(Opcode::ReleaseAllForPid),
            0x74 => Ok(Opcode::SubscribeSignalInbox),
            0x75 => Ok(Opcode::UnsubscribeSignalInbox),
            0x76 => Ok(Opcode::DeliverSignalInbox),
            0x77 => Ok(Opcode::SetPgid),
            0x78 => Ok(Opcode::SetSid),
            0x79 => Ok(Opcode::ReadTcpConn),
            0x7A => Ok(Opcode::WriteTcpConn),
            0x7B => Ok(Opcode::ShutdownTcpConn),
            0x7C => Ok(Opcode::PollTcpConnEvents),
            0x81 => Ok(Opcode::RegisterResponse),
            0x82 => Ok(Opcode::MaterializeResponse),
            0x83 => Ok(Opcode::ReleaseResponse),
            0x84 => Ok(Opcode::RegisterNotificationRingResponse),
            0x90 => Ok(Opcode::CreateEventfdResponse),
            0x91 => Ok(Opcode::ReadEventfdResponse),
            0x92 => Ok(Opcode::WriteEventfdResponse),
            0x93 => Ok(Opcode::SubscribeEventfdResponse),
            0xC0 => Ok(Opcode::CreateSignalfdResponse),
            0xC1 => Ok(Opcode::ReadSiginfoResponse),
            0xC2 => Ok(Opcode::PushSiginfoResponse),
            0xD0 => Ok(Opcode::CreatePipeResponse),
            0xD1 => Ok(Opcode::ReadPipeResponse),
            0xD2 => Ok(Opcode::WritePipeResponse),
            0xB0 => Ok(Opcode::CreateSocketPairResponse),
            0xB1 => Ok(Opcode::ReadSocketPairResponse),
            0xB2 => Ok(Opcode::WriteSocketPairResponse),
            0xB3 => Ok(Opcode::ShutdownSocketPairWriteResponse),
            0xE0 => Ok(Opcode::CreatePtyResponse),
            0xE5 => Ok(Opcode::OpenPtySlaveResponse),
            0xE1 => Ok(Opcode::PtyReadResponse),
            0xE2 => Ok(Opcode::PtyWriteResponse),
            0xE3 => Ok(Opcode::SubscribePtyResponse),
            0xE4 => Ok(Opcode::PtyIoctlResponse),
            0x94 => Ok(Opcode::UnsubscribeResponse),
            0x95 => Ok(Opcode::DupHandleResponse),
            0xA0 => Ok(Opcode::CreatePidfdResponse),
            0xA1 => Ok(Opcode::PidfdExitedResponse),
            0xF0 => Ok(Opcode::RegisterProcessResponse),
            0xF1 => Ok(Opcode::SubscribeProcessExitResponse),
            0xF2 => Ok(Opcode::MarkProcessExitedResponse),
            0xF3 => Ok(Opcode::ReleaseAllForPidResponse),
            0xF4 => Ok(Opcode::SubscribeSignalInboxResponse),
            0xF5 => Ok(Opcode::UnsubscribeSignalInboxResponse),
            0xF6 => Ok(Opcode::DeliverSignalInboxResponse),
            0xF7 => Ok(Opcode::SetPgidResponse),
            0xF8 => Ok(Opcode::SetSidResponse),
            0xF9 => Ok(Opcode::ReadTcpConnResponse),
            0xFA => Ok(Opcode::WriteTcpConnResponse),
            0xFB => Ok(Opcode::ShutdownTcpConnResponse),
            0xFC => Ok(Opcode::PollTcpConnEventsResponse),
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
    /// Phase F.5+ PE.1: guest pid of the caller. 0 = unspecified
    /// (pre-PE.1 caller, or response frame). Used by the broker to
    /// attribute refcount changes to a guest process.
    pub caller_pid: u32,
    pub body: &'a [u8],
    /// Total bytes consumed (header + body). Caller advances by this.
    pub consumed: usize,
}

/// An owned, pre-encoded frame ready to write to a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedFrame {
    pub opcode: Opcode,
    pub status: StatusCode,
    /// Phase F.5+ PE.1: guest pid of the caller. 0 = unspecified.
    /// Initial value when building via the existing helpers; the
    /// shim sets this just before send via `with_caller_pid` or
    /// the equivalent.
    pub caller_pid: u32,
    pub body: Vec<u8>,
}

impl OwnedFrame {
    /// Sets the caller_pid field (builder style). Use this on the
    /// shim side just before sending. Returns self for chaining.
    pub fn with_caller_pid(mut self, pid: u32) -> Self {
        self.caller_pid = pid;
        self
    }

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
        // Phase F.5+ PE.1 Step A: bytes 12-15 carry the caller's
        // guest pid (formerly "reserved must be zero"). 0 = unspecified
        // (pre-PE.1 callers). Backwards compatible: legacy senders
        // pass 0 here, legacy receivers can treat 0 as "anonymous".
        out.extend_from_slice(&self.caller_pid.to_le_bytes());
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
    // Phase F.5+ PE.1 Step A: bytes 12-15 are now caller_pid (was
    // reserved-must-be-zero). 0 is valid (means unspecified). Any
    // non-zero is the caller's guest pid.
    let caller_pid = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
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
        caller_pid,
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
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::RegisterResponse`]: handle id (u64 LE).
pub fn build_register_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::Materialize`]: handle id (u64 LE).
pub fn build_materialize_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::Materialize,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::MaterializeResponse`]: empty (fd attached via SCM_RIGHTS).
pub fn build_materialize_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::MaterializeResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::Release`]: handle id.
pub fn build_release_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::Release,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReleaseResponse`]: empty.
pub fn build_release_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReleaseResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::RegisterProcess`]: empty (allocates a fresh pid).
pub fn build_register_process_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterProcess,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::RegisterProcessResponse`]: handle id (= pid as u64).
pub fn build_register_process_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterProcessResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::SubscribeProcessExit`]: (pid handle: u64, sub_id: u64, events: u32, pad: 4).
pub fn build_subscribe_process_exit_request(
    pid: u32,
    subscription_id: u64,
    events_mask: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&u64::from(pid).to_le_bytes());
    body.extend_from_slice(&subscription_id.to_le_bytes());
    body.extend_from_slice(&events_mask.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::SubscribeProcessExit,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a SubscribeProcessExit request.
pub fn parse_subscribe_process_exit_body(body: &[u8]) -> Result<(u64, u64, u32), ProtocolError> {
    parse_subscribe_body(body, Opcode::SubscribeProcessExit)
}

/// Body for SubscribeProcessExitResponse: (exited: u8, pad: 3, exit_code: i32).
pub fn build_subscribe_process_exit_response_ok(exit_code: Option<i32>) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.push(u8::from(exit_code.is_some()));
    body.extend_from_slice(&[0u8; 3]);
    body.extend_from_slice(&exit_code.unwrap_or(0).to_le_bytes());
    OwnedFrame {
        opcode: Opcode::SubscribeProcessExitResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes a SubscribeProcessExitResponse success body.
pub fn parse_subscribe_process_exit_response_ok(body: &[u8]) -> Result<Option<i32>, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SubscribeProcessExitResponse,
            got: body.len(),
            want: 8,
        });
    }
    if body[1..4].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    let code = i32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    match body[0] {
        0 => Ok(None),
        1 => Ok(Some(code)),
        _ => Err(ProtocolError::NonZeroReserved {
            reserved: u32::from(body[0]),
        }),
    }
}

/// Body for [`Opcode::MarkProcessExited`]: (pid handle: u64, exit_code: i32, pad: 4).
pub fn build_mark_process_exited_request(pid: u32, exit_code: i32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&u64::from(pid).to_le_bytes());
    body.extend_from_slice(&exit_code.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::MarkProcessExited,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a MarkProcessExited request.
pub fn parse_mark_process_exited_body(body: &[u8]) -> Result<(u64, i32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::MarkProcessExited,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let exit_code = i32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    if body[12..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((handle, exit_code))
}

/// Body for [`Opcode::MarkProcessExitedResponse`]: empty.
pub fn build_mark_process_exited_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::MarkProcessExitedResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::SetPgid`]: `(caller_pid: u32, target_pid: u32, new_pgid: u32, pad: 4)`.
pub fn build_set_pgid_request(caller_pid: u32, target_pid: u32, new_pgid: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&caller_pid.to_le_bytes());
    body.extend_from_slice(&target_pid.to_le_bytes());
    body.extend_from_slice(&new_pgid.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::SetPgid,
        status: StatusCode::Ok,
        caller_pid,
        body,
    }
}

pub fn parse_set_pgid_body(body: &[u8]) -> Result<(u32, u32, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SetPgid,
            got: body.len(),
            want: 16,
        });
    }
    if body[12..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((
        u32::from_le_bytes(body[0..4].try_into().expect("slice length checked")),
        u32::from_le_bytes(body[4..8].try_into().expect("slice length checked")),
        u32::from_le_bytes(body[8..12].try_into().expect("slice length checked")),
    ))
}

pub fn build_set_pgid_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SetPgidResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::SetSid`]: `(caller_pid: u32, pad: 4)`.
pub fn build_set_sid_request(caller_pid: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&caller_pid.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::SetSid,
        status: StatusCode::Ok,
        caller_pid,
        body,
    }
}

pub fn parse_set_sid_body(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SetSid,
            got: body.len(),
            want: 8,
        });
    }
    if body[4..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(u32::from_le_bytes(
        body[0..4].try_into().expect("slice length checked"),
    ))
}

pub fn build_set_sid_response_ok(new_pgid: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&new_pgid.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::SetSidResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_set_sid_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SetSidResponse,
            got: body.len(),
            want: 8,
        });
    }
    if body[4..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(u32::from_le_bytes(
        body[0..4].try_into().expect("slice length checked"),
    ))
}

/// Body for [`Opcode::SubscribeSignalInbox`]:
/// `(pgid: u32, signal_mask: u32, subscription_id: u64, events: u32, pad: 4)`.
pub fn build_subscribe_signal_inbox_request(
    pgid: u32,
    signal_mask: u32,
    subscription_id: u64,
    events_mask: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&pgid.to_le_bytes());
    body.extend_from_slice(&signal_mask.to_le_bytes());
    body.extend_from_slice(&subscription_id.to_le_bytes());
    body.extend_from_slice(&events_mask.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::SubscribeSignalInbox,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_subscribe_signal_inbox_body(
    body: &[u8],
) -> Result<(u32, u32, u64, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SubscribeSignalInbox,
            got: body.len(),
            want: 24,
        });
    }
    let pgid = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let signal_mask = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let subscription_id = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let events_mask = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
    if body[20..24].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((pgid, signal_mask, subscription_id, events_mask))
}

pub fn build_subscribe_signal_inbox_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SubscribeSignalInboxResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::UnsubscribeSignalInbox`]: `(pgid: u32, subscription_id: u64, pad: 4)`.
pub fn build_unsubscribe_signal_inbox_request(pgid: u32, subscription_id: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&pgid.to_le_bytes());
    body.extend_from_slice(&subscription_id.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::UnsubscribeSignalInbox,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_unsubscribe_signal_inbox_body(body: &[u8]) -> Result<(u32, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnsubscribeSignalInbox,
            got: body.len(),
            want: 16,
        });
    }
    let pgid = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let subscription_id = u64::from_le_bytes([
        body[4], body[5], body[6], body[7], body[8], body[9], body[10], body[11],
    ]);
    if body[12..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((pgid, subscription_id))
}

pub fn build_unsubscribe_signal_inbox_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::UnsubscribeSignalInboxResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_deliver_signal_inbox_request(pgid: u32, signum: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&pgid.to_le_bytes());
    body.extend_from_slice(&signum.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::DeliverSignalInbox,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_deliver_signal_inbox_body(body: &[u8]) -> Result<(u32, u32), ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::DeliverSignalInbox,
            got: body.len(),
            want: 8,
        });
    }
    let pgid = u32::from_le_bytes(body[0..4].try_into().expect("slice length checked"));
    let signum = u32::from_le_bytes(body[4..8].try_into().expect("slice length checked"));
    Ok((pgid, signum))
}

pub fn build_deliver_signal_inbox_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::DeliverSignalInboxResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::ReleaseAllForPid`]: (pid: u32, pad: 4).
pub fn build_release_all_for_pid_request(pid: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&pid.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::ReleaseAllForPid,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a ReleaseAllForPid request.
pub fn parse_release_all_for_pid_body(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReleaseAllForPid,
            got: body.len(),
            want: 8,
        });
    }
    let pid = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if body[4..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(pid)
}

/// Body for [`Opcode::ReleaseAllForPidResponse`]:
/// `(released_count: u32, pad: 4)`.
pub fn build_release_all_for_pid_response_ok(released: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&released.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::ReleaseAllForPidResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decode a ReleaseAllForPidResponse OK body.
pub fn parse_release_all_for_pid_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReleaseAllForPidResponse,
            got: body.len(),
            want: 8,
        });
    }
    let released = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if body[4..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(released)
}

/// Body for [`Opcode::RegisterNotificationRing`]: empty (ring fd via SCM_RIGHTS).
pub fn build_register_notification_ring_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterNotificationRing,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for the matching response: empty.
pub fn build_register_notification_ring_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterNotificationRingResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
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
        caller_pid: 0,
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
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::CreatePidfd`]: target host pid (u32 LE).
pub fn build_create_pidfd_request(target_host_pid: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreatePidfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: target_host_pid.to_le_bytes().to_vec(),
    }
}

/// Decodes the body of a CreatePidfd request frame.
pub fn parse_create_pidfd_body(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreatePidfd,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes([body[0], body[1], body[2], body[3]]))
}

/// Body for [`Opcode::CreatePidfdResponse`]: handle id.
pub fn build_create_pidfd_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreatePidfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Decodes the body of a CreatePidfdResponse success frame.
pub fn parse_create_pidfd_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::CreatePidfdResponse)
}

/// Body for [`Opcode::PidfdExited`]: handle id.
pub fn build_pidfd_exited_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::PidfdExited,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Decodes the body of a PidfdExited request frame.
pub fn parse_pidfd_exited_request(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::PidfdExited)
}

/// Body for [`Opcode::PidfdExitedResponse`]: exited flag (u8).
pub fn build_pidfd_exited_response_ok(exited: bool) -> OwnedFrame {
    let mut body = Vec::with_capacity(1);
    body.push(u8::from(exited));
    OwnedFrame {
        opcode: Opcode::PidfdExitedResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a PidfdExitedResponse success frame.
pub fn parse_pidfd_exited_response_ok(body: &[u8]) -> Result<bool, ProtocolError> {
    if body.len() != 1 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PidfdExitedResponse,
            got: body.len(),
            want: 1,
        });
    }
    Ok(body[0] != 0)
}

/// Body for [`Opcode::ReadEventfd`]: handle id.
pub fn build_read_eventfd_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadEventfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadEventfdResponse`]: value (u64 LE).
pub fn build_read_eventfd_response_ok(value: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadEventfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
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
        caller_pid: 0,
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
        caller_pid: 0,
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
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a SubscribeEventfd request.
pub fn parse_subscribe_eventfd_body(body: &[u8]) -> Result<(u64, u64, u32), ProtocolError> {
    parse_subscribe_body(body, Opcode::SubscribeEventfd)
}

fn parse_subscribe_body(body: &[u8], opcode: Opcode) -> Result<(u64, u64, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
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
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::CreateSignalfd`]: (sigmask_lo: u64, sigmask_hi: u64).
pub fn build_create_signalfd_request(sigmask_lo: u64, sigmask_hi: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&sigmask_lo.to_le_bytes());
    body.extend_from_slice(&sigmask_hi.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreateSignalfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a CreateSignalfd request.
pub fn parse_create_signalfd_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateSignalfd,
            got: body.len(),
            want: 16,
        });
    }
    let lo = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let hi = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    Ok((lo, hi))
}

/// Body for [`Opcode::CreateSignalfdResponse`]: handle id.
pub fn build_create_signalfd_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateSignalfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadSiginfo`]: handle id.
pub fn build_read_siginfo_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadSiginfo,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadSiginfoResponse`]: (payload_len: u32, pad: u32, payload bytes).
pub fn build_read_siginfo_response_ok(payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + payload.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::ReadSiginfoResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes a ReadSiginfo response body.
pub fn parse_read_siginfo_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadSiginfoResponse,
            got: body.len(),
            want: 8,
        });
    }
    let len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let reserved = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 8 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadSiginfoResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

/// Body for [`Opcode::PushSiginfo`]: (handle id, payload_len: u32, pad: u32, payload bytes).
pub fn build_push_siginfo_request(handle_id: u64, payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + payload.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::PushSiginfo,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Body for [`Opcode::PushSiginfoResponse`]: empty on success.
pub fn build_push_siginfo_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::PushSiginfoResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Decodes a PushSiginfo request body.
pub fn parse_push_siginfo_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PushSiginfo,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 16 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PushSiginfo,
            got: body.len(),
            want: 16 + len,
        });
    }
    Ok((handle, body[16..].to_vec()))
}

/// Body for [`Opcode::CreatePipe`]: (capacity: u64, atomic_write_size: u64).
pub fn build_create_pipe_request(capacity: u64, atomic_write_size: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&capacity.to_le_bytes());
    body.extend_from_slice(&atomic_write_size.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreatePipe,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_create_pipe_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreatePipe,
            got: body.len(),
            want: 16,
        });
    }
    let capacity = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let atomic = u64::from_le_bytes(body[8..16].try_into().unwrap());
    Ok((capacity, atomic))
}

pub fn build_create_pipe_response_ok(read_handle_id: u64, write_handle_id: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&read_handle_id.to_le_bytes());
    body.extend_from_slice(&write_handle_id.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreatePipeResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_create_pipe_response_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreatePipeResponse,
            got: body.len(),
            want: 16,
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

/// Body for [`Opcode::ReadPipe`]: (handle: u64, max_len: u64).
pub fn build_read_pipe_request(handle_id: u64, max_len: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::ReadPipe,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_read_pipe_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadPipe,
            got: body.len(),
            want: 16,
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

/// Body for [`Opcode::ReadPipeResponse`]: (len: u32, pad: u32, bytes...).
pub fn build_read_pipe_response_ok(bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::ReadPipeResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_read_pipe_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadPipeResponse,
            got: body.len(),
            want: 8,
        });
    }
    let len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 8 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadPipeResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

/// Body for [`Opcode::WritePipe`]: (handle: u64, len: u32, pad: u32, bytes...).
pub fn build_write_pipe_request(handle_id: u64, bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + bytes.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::WritePipe,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_write_pipe_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WritePipe,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 16 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WritePipe,
            got: body.len(),
            want: 16 + len,
        });
    }
    Ok((handle, body[16..].to_vec()))
}

pub fn build_write_pipe_response_ok(written: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::WritePipeResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: written.to_le_bytes().to_vec(),
    }
}

pub fn parse_write_pipe_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::WritePipeResponse)
}

// =====================================================================
// SocketPair (AF_UNIX SOCK_STREAM) wire format. Phase F.
//
// Byte-for-byte mirror of the Pipe ops with new opcodes — same shape:
// capacity/atomic on create, (handle, max_len) on read, (handle, bytes)
// on write. The two response handle_ids correspond to endpoints A and B.
// =====================================================================

/// Body for [`Opcode::CreateSocketPair`]: (capacity: u64, atomic_write_size: u64).
pub fn build_create_socketpair_request(capacity: u64, atomic_write_size: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&capacity.to_le_bytes());
    body.extend_from_slice(&atomic_write_size.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreateSocketPair,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_create_socketpair_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateSocketPair,
            got: body.len(),
            want: 16,
        });
    }
    let capacity = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let atomic = u64::from_le_bytes(body[8..16].try_into().unwrap());
    Ok((capacity, atomic))
}

/// Response carries (endpoint_a_handle_id: u64, endpoint_b_handle_id: u64).
pub fn build_create_socketpair_response_ok(
    endpoint_a_handle_id: u64,
    endpoint_b_handle_id: u64,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&endpoint_a_handle_id.to_le_bytes());
    body.extend_from_slice(&endpoint_b_handle_id.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreateSocketPairResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_create_socketpair_response_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateSocketPairResponse,
            got: body.len(),
            want: 16,
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

/// Body for [`Opcode::ReadSocketPair`]: (handle: u64, max_len: u64).
pub fn build_read_socketpair_request(handle_id: u64, max_len: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::ReadSocketPair,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_read_socketpair_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadSocketPair,
            got: body.len(),
            want: 16,
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

/// Body for [`Opcode::ReadSocketPairResponse`]: (len: u32, pad: u32, bytes...).
/// Overhead = 8 bytes; safe payload `BODY_MAX - 8`.
pub fn build_read_socketpair_response_ok(bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::ReadSocketPairResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_read_socketpair_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadSocketPairResponse,
            got: body.len(),
            want: 8,
        });
    }
    let len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 8 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadSocketPairResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

/// Body for [`Opcode::WriteSocketPair`]: (handle: u64, len: u32, pad: u32, bytes...).
/// Overhead = 16 bytes; safe payload `BODY_MAX - 16`.
pub fn build_write_socketpair_request(handle_id: u64, bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + bytes.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::WriteSocketPair,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_write_socketpair_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WriteSocketPair,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 16 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WriteSocketPair,
            got: body.len(),
            want: 16 + len,
        });
    }
    Ok((handle, body[16..].to_vec()))
}

pub fn build_write_socketpair_response_ok(written: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::WriteSocketPairResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: written.to_le_bytes().to_vec(),
    }
}

pub fn parse_write_socketpair_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::WriteSocketPairResponse)
}

/// Body for [`Opcode::ShutdownSocketPairWrite`]: (handle: u64).
pub fn build_shutdown_socketpair_write_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ShutdownSocketPairWrite,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_shutdown_socketpair_write_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::ShutdownSocketPairWrite)
}

pub fn build_shutdown_socketpair_write_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ShutdownSocketPairWriteResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

// =====================================================================
// BrokerTcpConn wire format.
// =====================================================================

pub fn build_read_tcp_conn_request(handle_id: u64, max_len: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::ReadTcpConn,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_read_tcp_conn_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadTcpConn,
            got: body.len(),
            want: 16,
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

pub fn build_read_tcp_conn_response_ok(bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::ReadTcpConnResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_read_tcp_conn_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadTcpConnResponse,
            got: body.len(),
            want: 8,
        });
    }
    let len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 8 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ReadTcpConnResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

pub fn build_write_tcp_conn_request(handle_id: u64, bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + bytes.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::WriteTcpConn,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_write_tcp_conn_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WriteTcpConn,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 16 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::WriteTcpConn,
            got: body.len(),
            want: 16 + len,
        });
    }
    Ok((handle, body[16..].to_vec()))
}

pub fn build_write_tcp_conn_response_ok(written: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::WriteTcpConnResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: written.to_le_bytes().to_vec(),
    }
}

pub fn parse_write_tcp_conn_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::WriteTcpConnResponse)
}

pub fn build_shutdown_tcp_conn_request(handle_id: u64, read: bool, write: bool) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.push(u8::from(read));
    body.push(u8::from(write));
    body.extend_from_slice(&[0u8; 6]);
    OwnedFrame {
        opcode: Opcode::ShutdownTcpConn,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_shutdown_tcp_conn_body(body: &[u8]) -> Result<(u64, bool, bool), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::ShutdownTcpConn,
            got: body.len(),
            want: 16,
        });
    }
    if body[10..16].iter().any(|&b| b != 0) || body[8] > 1 || body[9] > 1 {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        body[8] != 0,
        body[9] != 0,
    ))
}

pub fn build_shutdown_tcp_conn_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ShutdownTcpConnResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_poll_tcp_conn_events_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::PollTcpConnEvents,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_poll_tcp_conn_events_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::PollTcpConnEvents)
}

pub fn build_poll_tcp_conn_events_response_ok(events: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&events.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::PollTcpConnEventsResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_poll_tcp_conn_events_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PollTcpConnEventsResponse,
            got: body.len(),
            want: 8,
        });
    }
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
}

/// Body for [`Opcode::CreatePty`]: empty (allocates one master/slave pair).
pub fn build_create_pty_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreatePty,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::CreatePtyResponse`]: master handle, slave handle, pty id, reserved.
pub fn build_create_pty_response_ok(
    master_handle: u64,
    slave_handle: u64,
    pty_id: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&master_handle.to_le_bytes());
    body.extend_from_slice(&slave_handle.to_le_bytes());
    body.extend_from_slice(&pty_id.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreatePtyResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Body for [`Opcode::OpenPtySlave`]: pty id + reserved.
pub fn build_open_pty_slave_request(pty_id: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&pty_id.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::OpenPtySlave,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_open_pty_slave_body(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::OpenPtySlave,
            got: body.len(),
            want: 8,
        });
    }
    if body[4..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
}

/// Body for [`Opcode::OpenPtySlaveResponse`]: slave handle + pty id + reserved.
pub fn build_open_pty_slave_response_ok(slave_handle: u64, pty_id: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&slave_handle.to_le_bytes());
    body.extend_from_slice(&pty_id.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::OpenPtySlaveResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_open_pty_slave_response_ok(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::OpenPtySlaveResponse,
            got: body.len(),
            want: 16,
        });
    }
    if body[12..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}

pub fn parse_create_pty_response_ok(body: &[u8]) -> Result<(u64, u64, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreatePtyResponse,
            got: body.len(),
            want: 24,
        });
    }
    let master = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let slave = u64::from_le_bytes(body[8..16].try_into().unwrap());
    let pty_id = u32::from_le_bytes(body[16..20].try_into().unwrap());
    if body[20..24].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((master, slave, pty_id))
}

/// Body for [`Opcode::PtyRead`]: handle id + max byte count.
pub fn build_pty_read_request(handle_id: u64, max_len: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::PtyRead,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_pty_read_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PtyRead,
            got: body.len(),
            want: 16,
        });
    }
    if body[12..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}

pub fn build_pty_read_response_ok(data: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + data.len());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(data);
    OwnedFrame {
        opcode: Opcode::PtyReadResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_pty_read_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    parse_len_prefixed_body(body, Opcode::PtyReadResponse)
}

/// Body for [`Opcode::PtyWrite`]: handle id + length-prefixed payload.
pub fn build_pty_write_request(handle_id: u64, data: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + data.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(data);
    OwnedFrame {
        opcode: Opcode::PtyWrite,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_pty_write_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PtyWrite,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    if body[12..16].iter().any(|&b| b != 0) || body.len() != 16 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PtyWrite,
            got: body.len(),
            want: 16 + len,
        });
    }
    Ok((handle, body[16..].to_vec()))
}

pub fn build_pty_write_response_ok(bytes_written: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::PtyWriteResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: bytes_written.to_le_bytes().to_vec(),
    }
}

pub fn parse_pty_write_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PtyWriteResponse,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes(body.try_into().unwrap()))
}

pub fn build_subscribe_pty_request(
    handle_id: u64,
    subscription_id: u64,
    events_mask: u32,
) -> OwnedFrame {
    let mut frame = build_subscribe_eventfd_request(handle_id, subscription_id, events_mask);
    frame.opcode = Opcode::SubscribePty;
    frame
}

pub fn parse_subscribe_pty_body(body: &[u8]) -> Result<(u64, u64, u32), ProtocolError> {
    parse_subscribe_eventfd_body(body)
}

pub fn build_subscribe_pty_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SubscribePtyResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_pty_ioctl_request(handle_id: u64, op: PtyIoctlOp, payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + payload.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&(op as u16).to_le_bytes());
    body.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::PtyIoctl,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_pty_ioctl_body(body: &[u8]) -> Result<(u64, PtyIoctlOp, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PtyIoctl,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let op_raw = u16::from_le_bytes(body[8..10].try_into().unwrap());
    let len = u16::from_le_bytes(body[10..12].try_into().unwrap()) as usize;
    if body[12..16].iter().any(|&b| b != 0) || body.len() != 16 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::PtyIoctl,
            got: body.len(),
            want: 16 + len,
        });
    }
    let Some(op) = PtyIoctlOp::from_u16(op_raw) else {
        return Err(ProtocolError::NonZeroReserved {
            reserved: u32::from(op_raw),
        });
    };
    Ok((handle, op, body[16..].to_vec()))
}

pub fn build_pty_ioctl_response_ok(payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + payload.len());
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::PtyIoctlResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_pty_ioctl_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    parse_len_prefixed_body(body, Opcode::PtyIoctlResponse)
}

fn parse_len_prefixed_body(body: &[u8], opcode: Opcode) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 8,
        });
    }
    let len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 8 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

/// Body for [`Opcode::Unsubscribe`]: (handle: u64, sub_id: u64).
pub fn build_unsubscribe_request(handle_id: u64, subscription_id: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&subscription_id.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::Unsubscribe,
        status: StatusCode::Ok,
        caller_pid: 0,
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
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::DupHandle`]: existing handle id.
/// Semantics: broker increments the refcount of `handle_id` so a
/// receiver worker can adopt it. Sender invokes this BEFORE shipping
/// the handle over the data plane; receiver constructs an
/// `EventFile::new_broker_backed` referencing the same handle, and
/// when the receiver's EventFile drops it calls `release` to balance.
pub fn build_dup_handle_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::DupHandle,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::DupHandleResponse`]: empty.
pub fn build_dup_handle_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::DupHandleResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
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
        caller_pid: 0,
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
            Opcode::CreatePidfd,
            Opcode::PidfdExited,
            Opcode::SubscribeProcessExit,
            Opcode::MarkProcessExited,
            Opcode::RegisterResponse,
            Opcode::MaterializeResponse,
            Opcode::ReleaseResponse,
            Opcode::RegisterNotificationRingResponse,
            Opcode::CreateEventfdResponse,
            Opcode::ReadEventfdResponse,
            Opcode::WriteEventfdResponse,
            Opcode::SubscribeEventfdResponse,
            Opcode::UnsubscribeResponse,
            Opcode::CreatePidfdResponse,
            Opcode::PidfdExitedResponse,
            Opcode::SubscribeProcessExit,
            Opcode::MarkProcessExited,
            Opcode::SubscribeProcessExitResponse,
            Opcode::MarkProcessExitedResponse,
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
        assert_eq!(
            Opcode::CreatePidfd.response_for(),
            Some(Opcode::CreatePidfdResponse)
        );
        assert_eq!(
            Opcode::PidfdExited.response_for(),
            Some(Opcode::PidfdExitedResponse)
        );
        assert_eq!(
            Opcode::SubscribeProcessExit.response_for(),
            Some(Opcode::SubscribeProcessExitResponse)
        );
        assert_eq!(
            Opcode::MarkProcessExited.response_for(),
            Some(Opcode::MarkProcessExitedResponse)
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
            Opcode::CreatePidfd,
            Opcode::PidfdExited,
            Opcode::SubscribeProcessExit,
            Opcode::MarkProcessExited,
            Opcode::RegisterResponse,
            Opcode::CreateEventfdResponse,
            Opcode::ReadEventfdResponse,
            Opcode::CreatePidfdResponse,
            Opcode::PidfdExitedResponse,
            Opcode::SubscribeProcessExitResponse,
            Opcode::MarkProcessExitedResponse,
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
    fn round_trip_pidfd_messages() {
        let create = build_create_pidfd_request(1234);
        let bytes = create.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::CreatePidfd);
        assert_eq!(parse_create_pidfd_body(decoded.body).unwrap(), 1234);

        let create_resp = build_create_pidfd_response_ok(0xabc);
        let bytes = create_resp.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::CreatePidfdResponse);
        assert_eq!(parse_create_pidfd_response_ok(decoded.body).unwrap(), 0xabc);

        let exited = build_pidfd_exited_request(0xdef);
        let bytes = exited.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::PidfdExited);
        assert_eq!(parse_pidfd_exited_request(decoded.body).unwrap(), 0xdef);

        let exited_resp = build_pidfd_exited_response_ok(true);
        let bytes = exited_resp.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::PidfdExitedResponse);
        assert!(parse_pidfd_exited_response_ok(decoded.body).unwrap());
    }

    #[test]
    fn signal_inbox_protocol_frames_round_trip() {
        let sub = build_subscribe_signal_inbox_request(42, 1u32 << 28, 7, 0x0001);
        let bytes = sub.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::SubscribeSignalInbox);
        assert_eq!(
            parse_subscribe_signal_inbox_body(decoded.body).unwrap(),
            (42, 1u32 << 28, 7, 0x0001)
        );
        assert_eq!(
            decoded.opcode.response_for(),
            Some(Opcode::SubscribeSignalInboxResponse)
        );

        let unsub = build_unsubscribe_signal_inbox_request(42, 7);
        let bytes = unsub.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::UnsubscribeSignalInbox);
        assert_eq!(
            parse_unsubscribe_signal_inbox_body(decoded.body).unwrap(),
            (42, 7)
        );
        assert_eq!(
            decoded.opcode.response_for(),
            Some(Opcode::UnsubscribeSignalInboxResponse)
        );
    }

    #[test]
    fn round_trip_process_exit_messages() {
        let sub = build_subscribe_process_exit_request(123, 456, 0x0001);
        let bytes = sub.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::SubscribeProcessExit);
        assert_eq!(
            parse_subscribe_process_exit_body(decoded.body).unwrap(),
            (123, 456, 0x0001)
        );

        let sub_resp = build_subscribe_process_exit_response_ok(Some(17));
        let bytes = sub_resp.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::SubscribeProcessExitResponse);
        assert_eq!(
            parse_subscribe_process_exit_response_ok(decoded.body).unwrap(),
            Some(17)
        );

        let mark = build_mark_process_exited_request(123, 9);
        let bytes = mark.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::MarkProcessExited);
        assert_eq!(
            parse_mark_process_exited_body(decoded.body).unwrap(),
            (123, 9)
        );

        let mark_resp = build_mark_process_exited_response_ok();
        let bytes = mark_resp.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.opcode, Opcode::MarkProcessExitedResponse);
        assert!(decoded.body.is_empty());
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
    fn decode_caller_pid_roundtrip() {
        // Phase F.5+ PE.1: bytes 12-15 (formerly "reserved must be
        // zero") now carry caller_pid. A non-zero value should round
        // trip through decode, not be rejected.
        let mut buf = build_register_request().encode().unwrap();
        buf[12..16].copy_from_slice(&42u32.to_le_bytes());
        match decode(&buf) {
            Ok(frame) => assert_eq!(frame.caller_pid, 42),
            other => panic!("expected Ok with caller_pid=42, got {other:?}"),
        }
    }

    #[test]
    fn caller_pid_zero_by_default() {
        // Builders default caller_pid to 0 (legacy / unspecified).
        let frame = build_register_request();
        assert_eq!(frame.caller_pid, 0);
        let buf = frame.encode().unwrap();
        assert_eq!(&buf[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn with_caller_pid_sets_field() {
        let frame = build_register_request().with_caller_pid(7);
        assert_eq!(frame.caller_pid, 7);
        let buf = frame.encode().unwrap();
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.caller_pid, 7);
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

    /// C.5c follow-up: property-style round-trip test for the
    /// `WritePipe` wire format that exhaustively covers the
    /// `BODY_MAX` boundary. The C.5c bug was the shim passing a
    /// >64 KB write payload to `build_write_pipe_request` in one
    /// shot, which encoded successfully but failed `decode()` with
    /// `BodyTooLarge`. The fix chunks in the shim, but the
    /// underlying invariant — "writes up to `BODY_MAX - header
    /// overhead` round-trip; writes above fail at the encoder, not
    /// silently corrupt" — needs explicit test coverage.
    ///
    /// `WritePipe` body shape: 8-byte handle_id + 4-byte len +
    /// 4-byte reserved + len bytes of payload. So the maximum
    /// safe payload is `BODY_MAX - 16`. Cases:
    ///   - tiny (0, 1, 1 KB): trivial, should round-trip
    ///   - exactly at the safe boundary: must round-trip
    ///   - exactly one byte over: must fail at `encode()` with
    ///     `BodyTooLarge`
    ///   - well over: same failure
    #[test]
    fn write_pipe_round_trip_body_max_boundary() {
        let max_payload = (BODY_MAX as usize) - 16; // header overhead
        let cases: &[(usize, bool)] = &[
            (0, true),
            (1, true),
            (1024, true),
            (60 * 1024, true), // matches the shim's WRITE_PIPE_CHUNK constant
            (max_payload, true),
            (max_payload + 1, false),
            (max_payload + 16, false),
            (BODY_MAX as usize, false),
        ];
        for &(payload_len, expect_ok) in cases {
            let bytes = alloc::vec![0xA5u8; payload_len];
            let frame = build_write_pipe_request(0xDEAD_BEEF_CAFE_BABE, &bytes);
            match (frame.encode(), expect_ok) {
                (Ok(encoded), true) => {
                    let decoded = decode(&encoded).expect("decode should succeed");
                    assert_eq!(decoded.opcode, Opcode::WritePipe);
                    let (handle, payload) =
                        parse_write_pipe_body(decoded.body).expect("body parse should succeed");
                    assert_eq!(handle, 0xDEAD_BEEF_CAFE_BABE);
                    assert_eq!(payload.len(), payload_len);
                    assert!(
                        payload.iter().all(|&b| b == 0xA5),
                        "payload corrupted at len={payload_len}"
                    );
                }
                (Err(ProtocolError::BodyTooLarge { .. }), false) => {
                    // Expected failure path. C.5c confirmed encoder
                    // rejects oversize bodies cleanly.
                }
                (Ok(_), false) => {
                    panic!("expected BodyTooLarge for payload_len={payload_len}, got Ok")
                }
                (Err(e), true) => {
                    panic!("expected Ok for payload_len={payload_len}, got Err({e:?})")
                }
                (Err(e), false) => {
                    panic!(
                        "expected BodyTooLarge for payload_len={payload_len}, got unexpected Err({e:?})"
                    )
                }
            }
        }
    }

    /// C.5c follow-up: same boundary check on the symmetric
    /// `ReadPipeResponse` wire format. Response body shape:
    /// 4-byte len + 4-byte reserved + len bytes of payload. Max safe
    /// payload is `BODY_MAX - 8`.
    #[test]
    fn read_pipe_response_round_trip_body_max_boundary() {
        let max_payload = (BODY_MAX as usize) - 8; // 4-byte len + 4-byte reserved
        let cases: &[(usize, bool)] = &[
            (0, true),
            (1, true),
            (60 * 1024, true), // shim's READ_PIPE_CHUNK
            (max_payload, true),
            (max_payload + 1, false),
        ];
        for &(payload_len, expect_ok) in cases {
            let bytes = alloc::vec![0x5Au8; payload_len];
            let frame = build_read_pipe_response_ok(&bytes);
            match (frame.encode(), expect_ok) {
                (Ok(encoded), true) => {
                    let decoded = decode(&encoded).expect("decode should succeed");
                    assert_eq!(decoded.opcode, Opcode::ReadPipeResponse);
                    let payload = parse_read_pipe_response_body(decoded.body)
                        .expect("body parse should succeed");
                    assert_eq!(payload.len(), payload_len);
                }
                (Err(ProtocolError::BodyTooLarge { .. }), false) => {}
                (Ok(_), false) => {
                    panic!("expected BodyTooLarge for response payload_len={payload_len}, got Ok")
                }
                (Err(e), true) => {
                    panic!("expected Ok for response payload_len={payload_len}, got Err({e:?})")
                }
                (Err(e), false) => panic!(
                    "expected BodyTooLarge for response payload_len={payload_len}, got unexpected Err({e:?})"
                ),
            }
        }
    }

    /// Phase F: socketpair wire format mirrors the pipe ops. Verifies
    /// `WriteSocketPair` round-trip at the BODY_MAX boundary
    /// (overhead = 16 bytes).
    #[test]
    fn write_socketpair_round_trip_body_max_boundary() {
        let max_payload = (BODY_MAX as usize) - 16;
        let cases: &[(usize, bool)] = &[
            (0, true),
            (1, true),
            (1024, true),
            (60 * 1024, true),
            (max_payload, true),
            (max_payload + 1, false),
            (max_payload + 16, false),
            (BODY_MAX as usize, false),
        ];
        for &(payload_len, expect_ok) in cases {
            let bytes = alloc::vec![0xC3u8; payload_len];
            let frame = build_write_socketpair_request(0xFEED_FACE_DEAD_BEEF, &bytes);
            match (frame.encode(), expect_ok) {
                (Ok(encoded), true) => {
                    let decoded = decode(&encoded).expect("decode should succeed");
                    assert_eq!(decoded.opcode, Opcode::WriteSocketPair);
                    let (handle, payload) = parse_write_socketpair_body(decoded.body)
                        .expect("body parse should succeed");
                    assert_eq!(handle, 0xFEED_FACE_DEAD_BEEF);
                    assert_eq!(payload.len(), payload_len);
                    assert!(
                        payload.iter().all(|&b| b == 0xC3),
                        "payload corrupted at len={payload_len}"
                    );
                }
                (Err(ProtocolError::BodyTooLarge { .. }), false) => {}
                (Ok(_), false) => {
                    panic!("expected BodyTooLarge for payload_len={payload_len}, got Ok")
                }
                (Err(e), true) => {
                    panic!("expected Ok for payload_len={payload_len}, got Err({e:?})")
                }
                (Err(e), false) => panic!(
                    "expected BodyTooLarge for payload_len={payload_len}, got unexpected Err({e:?})"
                ),
            }
        }
    }

    /// Phase F: `ReadSocketPairResponse` BODY_MAX boundary
    /// (overhead = 8 bytes: 4-byte len + 4-byte reserved).
    #[test]
    fn read_socketpair_response_round_trip_body_max_boundary() {
        let max_payload = (BODY_MAX as usize) - 8;
        let cases: &[(usize, bool)] = &[
            (0, true),
            (1, true),
            (60 * 1024, true),
            (max_payload, true),
            (max_payload + 1, false),
        ];
        for &(payload_len, expect_ok) in cases {
            let bytes = alloc::vec![0x3Cu8; payload_len];
            let frame = build_read_socketpair_response_ok(&bytes);
            match (frame.encode(), expect_ok) {
                (Ok(encoded), true) => {
                    let decoded = decode(&encoded).expect("decode should succeed");
                    assert_eq!(decoded.opcode, Opcode::ReadSocketPairResponse);
                    let payload = parse_read_socketpair_response_body(decoded.body)
                        .expect("body parse should succeed");
                    assert_eq!(payload.len(), payload_len);
                }
                (Err(ProtocolError::BodyTooLarge { .. }), false) => {}
                (Ok(_), false) => {
                    panic!("expected BodyTooLarge for response payload_len={payload_len}, got Ok")
                }
                (Err(e), true) => {
                    panic!("expected Ok for response payload_len={payload_len}, got Err({e:?})")
                }
                (Err(e), false) => panic!(
                    "expected BodyTooLarge for response payload_len={payload_len}, got unexpected Err({e:?})"
                ),
            }
        }
    }

    /// Phase F: CreateSocketPair / Read / Write request and response
    /// body parsers reject malformed inputs (wrong length, non-zero
    /// reserved). Mirrors the pipe-side test discipline.
    #[test]
    fn socketpair_parsers_reject_malformed() {
        // CreateSocketPair: wrong length
        assert!(parse_create_socketpair_body(&[0u8; 8]).is_err());
        assert!(parse_create_socketpair_body(&[0u8; 17]).is_err());
        // ReadSocketPair: wrong length
        assert!(parse_read_socketpair_body(&[0u8; 8]).is_err());
        // WriteSocketPair: non-zero reserved
        let mut bad = alloc::vec![0u8; 16];
        bad[12] = 1; // reserved byte 0
        assert!(parse_write_socketpair_body(&bad).is_err());
        // ReadSocketPair response: non-zero reserved
        let mut bad = alloc::vec![0u8; 8];
        bad[4] = 1;
        assert!(parse_read_socketpair_response_body(&bad).is_err());
        // ReadSocketPair response: claimed len doesn't match body len
        let mut bad = alloc::vec![0u8; 8];
        bad[0] = 4; // claims 4 bytes payload, but body has only 8 bytes (header) and 0 payload
        assert!(parse_read_socketpair_response_body(&bad).is_err());
    }
}
