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
//! is 48 bytes (TimerfdSettime), so this is comfortably generous; the
//! cap exists primarily to bound memory on a malformed peer.

use crate::cwfd::broker_timerfd_provider::BrokerTimerfdSpec;
use crate::cwfd::fd_transfer_frame::PassedToken;
#[cfg(debug_assertions)]
use alloc::string::String;
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
/// | `0x79`–`0x7C`    | TCP conn data ops (BrokerTcpConn) |
/// | `0x48`–`0x4D`    | Inet listener state (Phase A/F.2) |
/// | `0x34`–`0x38`    | Inet TCP conn lifecycle/name ops |
/// | `0x3C`–`0x3F`    | Inet raw socket state (Phase D) |
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
    CreateTimerfd = 0x17,
    ReadTimerfd = 0x18,
    SetTimerfd = 0x19,
    GetTimerfd = 0x1A,
    CreateSignalfd = 0x40,
    ReadSiginfo = 0x41,
    PushSiginfo = 0x42,
    InotifyInit1 = 0x43,
    InotifyAddWatch = 0x44,
    InotifyRmWatch = 0x45,
    InotifyRead = 0x46,
    InotifyQueryEvents = 0x47,
    InetListenerCreate = 0x48,
    InetListenerBind = 0x49,
    InetListenerListen = 0x4A,
    InetListenerAccept = 0x4B,
    InetListenerQueryEvents = 0x4C,
    InetListenerSetSockOpt = 0x4D,
    InetListenerGetSockName = 0x4E,
    InetListenerGetSockOpt = 0x4F,
    CreatePipe = 0x50,
    ReadPipe = 0x51,
    WritePipe = 0x52,
    /// Legacy-pipes Phase 3 (D2): SCM_RIGHTS-pass a host fd to the
    /// broker, which takes ownership and exposes it as a
    /// BrokerPipe-shaped state handle. Body: `(direction: u8,
    /// _reserved: [u8; 7])` — 8 bytes. Direction values: 0=Read,
    /// 1=Write, 2=ReadWrite. The host fd itself rides in the
    /// SCM_RIGHTS cmsg (exactly one fd; protocol error otherwise).
    AttachHostFd = 0x53,
    /// Legacy-pipes Phase 3 (D3): register an open 9P fid in the
    /// broker-global OFD registry so the worker can later clone the
    /// underlying open file description with shared POSIX position.
    /// Body: `(fid: u32, _reserved: [u8; 4])` — 8 bytes. Issued on
    /// the **parent's** fd-token-socket; the handler resolves `fid`
    /// against the **parent's own** 9P `Server::fids` map.
    RegisterOfd = 0x54,
    /// Legacy-pipes Phase 3 (D3): clone a previously-registered
    /// open file description into a fresh 9P fid on the worker's
    /// own 9P server. Body: `(open_file_id: u64, new_fid: u32,
    /// _reserved: [u8; 4])` — 16 bytes. Issued on the **worker's**
    /// fd-token-socket.
    CloneOfd = 0x55,
    /// Legacy-pipes Phase 3 (D3 step 2d.2): pair this fd-token-socket
    /// connection with a 9P session by its broker-assigned conn_id.
    /// The runner receives its 9P conn_id in the bootstrap ACK from
    /// `connect_nine_p_channel` and issues this op early on the
    /// fd-token-socket so subsequent `RegisterOfd` / `CloneOfd` ops
    /// can resolve fids against the paired 9P `Server`. Body:
    /// `(nine_p_conn_id: u64)` — 8 bytes. Empty response on success;
    /// returns `UnknownNinePSession` on unknown conn_id.
    BindNinePSession = 0x56,
    CreateSocketDgram = 0x57,
    SocketDgramBind = 0x58,
    SocketDgramConnect = 0x59,
    SocketDgramSendTo = 0x5A,
    SocketDgramRecvFrom = 0x5B,
    SocketDgramShutdown = 0x5C,
    SocketDgramGetSockName = 0x5D,
    SocketDgramGetPeerName = 0x5E,
    CreateSocketPair = 0x30,
    ReadSocketPair = 0x31,
    WriteSocketPair = 0x32,
    ShutdownSocketPairWrite = 0x33,
    InetRawCreate = 0x3C,
    InetRawSendTo = 0x3D,
    InetRawRecvFrom = 0x3E,
    InetRawQueryEvents = 0x3F,
    InetTcpConnCreate = 0x34,
    InetTcpConnConnect = 0x35,
    InetTcpConnQueryEvents = 0x36,
    InetTcpConnGetSockName = 0x37,
    InetTcpConnGetPeerName = 0x38,
    CreatePty = 0x60,
    OpenPtySlave = 0x65,
    CreateSocketSeqPacket = 0x66,
    SocketSeqPacketBind = 0x67,
    SocketSeqPacketListen = 0x68,
    SocketSeqPacketAccept = 0x69,
    SocketSeqPacketConnect = 0x6A,
    SocketSeqPacketSend = 0x6B,
    SocketSeqPacketRecv = 0x6C,
    SocketSeqPacketShutdown = 0x6D,
    SocketSeqPacketGetSockName = 0x6E,
    SocketSeqPacketGetPeerName = 0x6F,
    // UnixStream (AF_UNIX SOCK_STREAM, named) — scattered free request slots.
    CreateUnixStream = 0x0D,
    UnixStreamBind = 0x0E,
    UnixStreamListen = 0x0F,
    UnixStreamAccept = 0x1B,
    UnixStreamConnect = 0x1C,
    UnixStreamSend = 0x1D,
    UnixStreamRecv = 0x1E,
    UnixStreamShutdown = 0x1F,
    UnixStreamGetSockName = 0x2D,
    UnixStreamGetPeerName = 0x2E,
    PtyRead = 0x61,
    PtyWrite = 0x62,
    SubscribePty = 0x63,
    PtyIoctl = 0x64,
    Unsubscribe = 0x14,
    DupHandle = 0x15,
    /// Synchronous "what events are currently set" query on a
    /// broker-held state handle. Body: `handle_id: u64`. Response:
    /// `events: u32` (a bitmask of `NOTIFY_EVENT_*` bits computed
    /// from the broker's current authoritative state). Designed for
    /// shim-side `poll`/`select`/`epoll_wait` readiness checks so the
    /// worker never relies on a stale local cache of broker state.
    QueryEvents = 0x16,
    CreatePidfd = 0x20,
    PidfdExited = 0x21,
    InetDgramCreate = 0x22,
    InetDgramBind = 0x23,
    InetDgramConnect = 0x24,
    InetDgramSendTo = 0x25,
    InetDgramRecvFrom = 0x26,
    InetDgramShutdown = 0x27,
    InetDgramGetSockName = 0x28,
    InetDgramGetPeerName = 0x29,
    InetDgramSetSockOpt = 0x2A,
    InetDgramGetSockOpt = 0x2B,
    InetDgramQueryEvents = 0x2C,
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
    InetTcpConnSetSockOpt = 0x7E,
    InetTcpConnGetSockOpt = 0x7F,
    #[cfg(debug_assertions)]
    DebugQueryStateObject = 0x7D,

    RegisterResponse = 0x81,
    MaterializeResponse = 0x82,
    ReleaseResponse = 0x83,
    RegisterNotificationRingResponse = 0x84,
    CreateEventfdResponse = 0x90,
    ReadEventfdResponse = 0x91,
    WriteEventfdResponse = 0x92,
    SubscribeEventfdResponse = 0x93,
    CreateTimerfdResponse = 0x97,
    ReadTimerfdResponse = 0x98,
    SetTimerfdResponse = 0x99,
    GetTimerfdResponse = 0x9A,
    CreateSignalfdResponse = 0xC0,
    ReadSiginfoResponse = 0xC1,
    PushSiginfoResponse = 0xC2,
    InotifyInit1Response = 0xC3,
    InotifyAddWatchResponse = 0xC4,
    InotifyRmWatchResponse = 0xC5,
    InotifyReadResponse = 0xC6,
    InotifyQueryEventsResponse = 0xC7,
    InetListenerCreateResponse = 0xC8,
    InetListenerBindResponse = 0xC9,
    InetListenerListenResponse = 0xCA,
    InetListenerAcceptResponse = 0xCB,
    InetListenerQueryEventsResponse = 0xCC,
    InetListenerSetSockOptResponse = 0xCD,
    InetListenerGetSockNameResponse = 0xCE,
    InetListenerGetSockOptResponse = 0xCF,
    CreatePipeResponse = 0xD0,
    ReadPipeResponse = 0xD1,
    WritePipeResponse = 0xD2,
    /// Response for [`Opcode::AttachHostFd`]. Body on success:
    /// `(handle_id: u64)` — 8 bytes.
    AttachHostFdResponse = 0xD3,
    /// Response for [`Opcode::RegisterOfd`]. Body on success:
    /// `(open_file_id: u64)` — 8 bytes.
    RegisterOfdResponse = 0xD4,
    /// Response for [`Opcode::CloneOfd`]. Empty body on success.
    CloneOfdResponse = 0xD5,
    /// Response for [`Opcode::BindNinePSession`]. Empty body on success.
    BindNinePSessionResponse = 0xD6,
    CreateSocketDgramResponse = 0xD7,
    SocketDgramBindResponse = 0xD8,
    SocketDgramConnectResponse = 0xD9,
    SocketDgramSendToResponse = 0xDA,
    SocketDgramRecvFromResponse = 0xDB,
    SocketDgramShutdownResponse = 0xDC,
    SocketDgramGetSockNameResponse = 0xDD,
    SocketDgramGetPeerNameResponse = 0xDE,
    CreateSocketPairResponse = 0xB0,
    ReadSocketPairResponse = 0xB1,
    WriteSocketPairResponse = 0xB2,
    ShutdownSocketPairWriteResponse = 0xB3,
    InetRawCreateResponse = 0xBC,
    InetRawSendToResponse = 0xBD,
    InetRawRecvFromResponse = 0xBE,
    InetRawQueryEventsResponse = 0xBF,
    InetTcpConnCreateResponse = 0xB4,
    InetTcpConnConnectResponse = 0xB5,
    InetTcpConnQueryEventsResponse = 0xB6,
    InetTcpConnGetSockNameResponse = 0xB7,
    InetTcpConnGetPeerNameResponse = 0xB8,
    CreatePtyResponse = 0xE0,
    OpenPtySlaveResponse = 0xE5,
    CreateSocketSeqPacketResponse = 0xE6,
    SocketSeqPacketBindResponse = 0xE7,
    SocketSeqPacketListenResponse = 0xE8,
    SocketSeqPacketAcceptResponse = 0xE9,
    SocketSeqPacketConnectResponse = 0xEA,
    SocketSeqPacketSendResponse = 0xEB,
    SocketSeqPacketRecvResponse = 0xEC,
    SocketSeqPacketShutdownResponse = 0xED,
    SocketSeqPacketGetSockNameResponse = 0xEE,
    SocketSeqPacketGetPeerNameResponse = 0xEF,
    // UnixStream responses (= request opcode + 0x80).
    CreateUnixStreamResponse = 0x8D,
    UnixStreamBindResponse = 0x8E,
    UnixStreamListenResponse = 0x8F,
    UnixStreamAcceptResponse = 0x9B,
    UnixStreamConnectResponse = 0x9C,
    UnixStreamSendResponse = 0x9D,
    UnixStreamRecvResponse = 0x9E,
    UnixStreamShutdownResponse = 0x9F,
    UnixStreamGetSockNameResponse = 0xAD,
    UnixStreamGetPeerNameResponse = 0xAE,
    PtyReadResponse = 0xE1,
    PtyWriteResponse = 0xE2,
    SubscribePtyResponse = 0xE3,
    PtyIoctlResponse = 0xE4,
    UnsubscribeResponse = 0x94,
    DupHandleResponse = 0x95,
    /// Response for [`Opcode::QueryEvents`]. Body: `events: u32`.
    QueryEventsResponse = 0x96,
    CreatePidfdResponse = 0xA0,
    PidfdExitedResponse = 0xA1,
    InetDgramCreateResponse = 0xA2,
    InetDgramBindResponse = 0xA3,
    InetDgramConnectResponse = 0xA4,
    InetDgramSendToResponse = 0xA5,
    InetDgramRecvFromResponse = 0xA6,
    InetDgramShutdownResponse = 0xA7,
    InetDgramGetSockNameResponse = 0xA8,
    InetDgramGetPeerNameResponse = 0xA9,
    InetDgramSetSockOptResponse = 0xAA,
    InetDgramGetSockOptResponse = 0xAB,
    InetDgramQueryEventsResponse = 0xAC,
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
    InetTcpConnSetSockOptResponse = 0xFE,
    InetTcpConnGetSockOptResponse = 0xFF,
    #[cfg(debug_assertions)]
    DebugQueryStateObjectResponse = 0xFD,
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

    /// Inet UDP datagram state: create / bind / connect / datagram I/O / socket options.
    pub const INET_DGRAM_BASE: u8 = 0x22;
    pub const INET_DGRAM_RESPONSE_BASE: u8 = 0xA2;

    /// Socket-pair state (P2.A), with 0x34-0x38 used by Inet TCP lifecycle/name ops.
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

    /// Inet listener state: create / bind / listen / accept / query-events.
    pub const INET_LISTENER_BASE: u8 = 0x48;
    pub const INET_LISTENER_RESPONSE_BASE: u8 = 0xC8;

    /// Connected TCP data ops: read / write / shutdown / poll-events.
    pub const TCP_CONN_BASE: u8 = 0x79;
    pub const TCP_CONN_RESPONSE_BASE: u8 = 0xF9;

    /// Inet TCP lifecycle/name ops: create / connect / query-events / getsockname / getpeername.
    pub const INET_TCP_CONN_BASE: u8 = 0x34;
    pub const INET_TCP_CONN_RESPONSE_BASE: u8 = 0xB4;

    /// Inet raw socket state: create / sendto / recvfrom / query-events.
    pub const INET_RAW_BASE: u8 = 0x3C;
    pub const INET_RAW_RESPONSE_BASE: u8 = 0xBC;
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
            Opcode::CreateTimerfd => Some(Opcode::CreateTimerfdResponse),
            Opcode::ReadTimerfd => Some(Opcode::ReadTimerfdResponse),
            Opcode::SetTimerfd => Some(Opcode::SetTimerfdResponse),
            Opcode::GetTimerfd => Some(Opcode::GetTimerfdResponse),
            Opcode::CreateSignalfd => Some(Opcode::CreateSignalfdResponse),
            Opcode::ReadSiginfo => Some(Opcode::ReadSiginfoResponse),
            Opcode::PushSiginfo => Some(Opcode::PushSiginfoResponse),
            Opcode::InotifyInit1 => Some(Opcode::InotifyInit1Response),
            Opcode::InotifyAddWatch => Some(Opcode::InotifyAddWatchResponse),
            Opcode::InotifyRmWatch => Some(Opcode::InotifyRmWatchResponse),
            Opcode::InotifyRead => Some(Opcode::InotifyReadResponse),
            Opcode::InotifyQueryEvents => Some(Opcode::InotifyQueryEventsResponse),
            Opcode::InetListenerCreate => Some(Opcode::InetListenerCreateResponse),
            Opcode::InetListenerBind => Some(Opcode::InetListenerBindResponse),
            Opcode::InetListenerListen => Some(Opcode::InetListenerListenResponse),
            Opcode::InetListenerAccept => Some(Opcode::InetListenerAcceptResponse),
            Opcode::InetListenerQueryEvents => Some(Opcode::InetListenerQueryEventsResponse),
            Opcode::InetListenerSetSockOpt => Some(Opcode::InetListenerSetSockOptResponse),
            Opcode::InetListenerGetSockName => Some(Opcode::InetListenerGetSockNameResponse),
            Opcode::InetListenerGetSockOpt => Some(Opcode::InetListenerGetSockOptResponse),
            Opcode::CreatePipe => Some(Opcode::CreatePipeResponse),
            Opcode::ReadPipe => Some(Opcode::ReadPipeResponse),
            Opcode::WritePipe => Some(Opcode::WritePipeResponse),
            Opcode::AttachHostFd => Some(Opcode::AttachHostFdResponse),
            Opcode::RegisterOfd => Some(Opcode::RegisterOfdResponse),
            Opcode::CloneOfd => Some(Opcode::CloneOfdResponse),
            Opcode::BindNinePSession => Some(Opcode::BindNinePSessionResponse),
            Opcode::CreateSocketDgram => Some(Opcode::CreateSocketDgramResponse),
            Opcode::SocketDgramBind => Some(Opcode::SocketDgramBindResponse),
            Opcode::SocketDgramConnect => Some(Opcode::SocketDgramConnectResponse),
            Opcode::SocketDgramSendTo => Some(Opcode::SocketDgramSendToResponse),
            Opcode::SocketDgramRecvFrom => Some(Opcode::SocketDgramRecvFromResponse),
            Opcode::SocketDgramShutdown => Some(Opcode::SocketDgramShutdownResponse),
            Opcode::SocketDgramGetSockName => Some(Opcode::SocketDgramGetSockNameResponse),
            Opcode::SocketDgramGetPeerName => Some(Opcode::SocketDgramGetPeerNameResponse),
            Opcode::CreateSocketPair => Some(Opcode::CreateSocketPairResponse),
            Opcode::ReadSocketPair => Some(Opcode::ReadSocketPairResponse),
            Opcode::WriteSocketPair => Some(Opcode::WriteSocketPairResponse),
            Opcode::ShutdownSocketPairWrite => Some(Opcode::ShutdownSocketPairWriteResponse),
            Opcode::InetRawCreate => Some(Opcode::InetRawCreateResponse),
            Opcode::InetRawSendTo => Some(Opcode::InetRawSendToResponse),
            Opcode::InetRawRecvFrom => Some(Opcode::InetRawRecvFromResponse),
            Opcode::InetRawQueryEvents => Some(Opcode::InetRawQueryEventsResponse),
            Opcode::InetTcpConnCreate => Some(Opcode::InetTcpConnCreateResponse),
            Opcode::InetTcpConnConnect => Some(Opcode::InetTcpConnConnectResponse),
            Opcode::InetTcpConnQueryEvents => Some(Opcode::InetTcpConnQueryEventsResponse),
            Opcode::InetTcpConnGetSockName => Some(Opcode::InetTcpConnGetSockNameResponse),
            Opcode::InetTcpConnGetPeerName => Some(Opcode::InetTcpConnGetPeerNameResponse),
            Opcode::CreatePty => Some(Opcode::CreatePtyResponse),
            Opcode::OpenPtySlave => Some(Opcode::OpenPtySlaveResponse),
            Opcode::CreateSocketSeqPacket => Some(Opcode::CreateSocketSeqPacketResponse),
            Opcode::SocketSeqPacketBind => Some(Opcode::SocketSeqPacketBindResponse),
            Opcode::SocketSeqPacketListen => Some(Opcode::SocketSeqPacketListenResponse),
            Opcode::SocketSeqPacketAccept => Some(Opcode::SocketSeqPacketAcceptResponse),
            Opcode::SocketSeqPacketConnect => Some(Opcode::SocketSeqPacketConnectResponse),
            Opcode::SocketSeqPacketSend => Some(Opcode::SocketSeqPacketSendResponse),
            Opcode::SocketSeqPacketRecv => Some(Opcode::SocketSeqPacketRecvResponse),
            Opcode::SocketSeqPacketShutdown => Some(Opcode::SocketSeqPacketShutdownResponse),
            Opcode::SocketSeqPacketGetSockName => Some(Opcode::SocketSeqPacketGetSockNameResponse),
            Opcode::SocketSeqPacketGetPeerName => Some(Opcode::SocketSeqPacketGetPeerNameResponse),
            Opcode::CreateUnixStream => Some(Opcode::CreateUnixStreamResponse),
            Opcode::UnixStreamBind => Some(Opcode::UnixStreamBindResponse),
            Opcode::UnixStreamListen => Some(Opcode::UnixStreamListenResponse),
            Opcode::UnixStreamAccept => Some(Opcode::UnixStreamAcceptResponse),
            Opcode::UnixStreamConnect => Some(Opcode::UnixStreamConnectResponse),
            Opcode::UnixStreamSend => Some(Opcode::UnixStreamSendResponse),
            Opcode::UnixStreamRecv => Some(Opcode::UnixStreamRecvResponse),
            Opcode::UnixStreamShutdown => Some(Opcode::UnixStreamShutdownResponse),
            Opcode::UnixStreamGetSockName => Some(Opcode::UnixStreamGetSockNameResponse),
            Opcode::UnixStreamGetPeerName => Some(Opcode::UnixStreamGetPeerNameResponse),
            Opcode::PtyRead => Some(Opcode::PtyReadResponse),
            Opcode::PtyWrite => Some(Opcode::PtyWriteResponse),
            Opcode::SubscribePty => Some(Opcode::SubscribePtyResponse),
            Opcode::PtyIoctl => Some(Opcode::PtyIoctlResponse),
            Opcode::Unsubscribe => Some(Opcode::UnsubscribeResponse),
            Opcode::DupHandle => Some(Opcode::DupHandleResponse),
            Opcode::QueryEvents => Some(Opcode::QueryEventsResponse),
            Opcode::CreatePidfd => Some(Opcode::CreatePidfdResponse),
            Opcode::PidfdExited => Some(Opcode::PidfdExitedResponse),
            Opcode::InetDgramCreate => Some(Opcode::InetDgramCreateResponse),
            Opcode::InetDgramBind => Some(Opcode::InetDgramBindResponse),
            Opcode::InetDgramConnect => Some(Opcode::InetDgramConnectResponse),
            Opcode::InetDgramSendTo => Some(Opcode::InetDgramSendToResponse),
            Opcode::InetDgramRecvFrom => Some(Opcode::InetDgramRecvFromResponse),
            Opcode::InetDgramShutdown => Some(Opcode::InetDgramShutdownResponse),
            Opcode::InetDgramGetSockName => Some(Opcode::InetDgramGetSockNameResponse),
            Opcode::InetDgramGetPeerName => Some(Opcode::InetDgramGetPeerNameResponse),
            Opcode::InetDgramSetSockOpt => Some(Opcode::InetDgramSetSockOptResponse),
            Opcode::InetDgramGetSockOpt => Some(Opcode::InetDgramGetSockOptResponse),
            Opcode::InetDgramQueryEvents => Some(Opcode::InetDgramQueryEventsResponse),
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
            Opcode::InetTcpConnSetSockOpt => Some(Opcode::InetTcpConnSetSockOptResponse),
            Opcode::InetTcpConnGetSockOpt => Some(Opcode::InetTcpConnGetSockOptResponse),
            #[cfg(debug_assertions)]
            Opcode::DebugQueryStateObject => Some(Opcode::DebugQueryStateObjectResponse),
            #[cfg(debug_assertions)]
            Opcode::DebugQueryStateObjectResponse => None,
            Opcode::RegisterResponse
            | Opcode::MaterializeResponse
            | Opcode::ReleaseResponse
            | Opcode::RegisterNotificationRingResponse
            | Opcode::CreateEventfdResponse
            | Opcode::ReadEventfdResponse
            | Opcode::WriteEventfdResponse
            | Opcode::SubscribeEventfdResponse
            | Opcode::CreateTimerfdResponse
            | Opcode::ReadTimerfdResponse
            | Opcode::SetTimerfdResponse
            | Opcode::GetTimerfdResponse
            | Opcode::CreateSignalfdResponse
            | Opcode::ReadSiginfoResponse
            | Opcode::PushSiginfoResponse
            | Opcode::InotifyInit1Response
            | Opcode::InotifyAddWatchResponse
            | Opcode::InotifyRmWatchResponse
            | Opcode::InotifyReadResponse
            | Opcode::InotifyQueryEventsResponse
            | Opcode::InetListenerCreateResponse
            | Opcode::InetListenerBindResponse
            | Opcode::InetListenerListenResponse
            | Opcode::InetListenerAcceptResponse
            | Opcode::InetListenerQueryEventsResponse
            | Opcode::InetListenerSetSockOptResponse
            | Opcode::InetListenerGetSockNameResponse
            | Opcode::InetListenerGetSockOptResponse
            | Opcode::CreatePipeResponse
            | Opcode::ReadPipeResponse
            | Opcode::WritePipeResponse
            | Opcode::AttachHostFdResponse
            | Opcode::RegisterOfdResponse
            | Opcode::CloneOfdResponse
            | Opcode::BindNinePSessionResponse
            | Opcode::CreateSocketDgramResponse
            | Opcode::SocketDgramBindResponse
            | Opcode::SocketDgramConnectResponse
            | Opcode::SocketDgramSendToResponse
            | Opcode::SocketDgramRecvFromResponse
            | Opcode::SocketDgramShutdownResponse
            | Opcode::SocketDgramGetSockNameResponse
            | Opcode::SocketDgramGetPeerNameResponse
            | Opcode::CreateSocketPairResponse
            | Opcode::ReadSocketPairResponse
            | Opcode::WriteSocketPairResponse
            | Opcode::ShutdownSocketPairWriteResponse
            | Opcode::InetRawCreateResponse
            | Opcode::InetRawSendToResponse
            | Opcode::InetRawRecvFromResponse
            | Opcode::InetRawQueryEventsResponse
            | Opcode::InetTcpConnCreateResponse
            | Opcode::InetTcpConnConnectResponse
            | Opcode::InetTcpConnQueryEventsResponse
            | Opcode::InetTcpConnGetSockNameResponse
            | Opcode::InetTcpConnGetPeerNameResponse
            | Opcode::CreatePtyResponse
            | Opcode::OpenPtySlaveResponse
            | Opcode::CreateSocketSeqPacketResponse
            | Opcode::SocketSeqPacketBindResponse
            | Opcode::SocketSeqPacketListenResponse
            | Opcode::SocketSeqPacketAcceptResponse
            | Opcode::SocketSeqPacketConnectResponse
            | Opcode::SocketSeqPacketSendResponse
            | Opcode::SocketSeqPacketRecvResponse
            | Opcode::SocketSeqPacketShutdownResponse
            | Opcode::SocketSeqPacketGetSockNameResponse
            | Opcode::SocketSeqPacketGetPeerNameResponse
            | Opcode::CreateUnixStreamResponse
            | Opcode::UnixStreamBindResponse
            | Opcode::UnixStreamListenResponse
            | Opcode::UnixStreamAcceptResponse
            | Opcode::UnixStreamConnectResponse
            | Opcode::UnixStreamSendResponse
            | Opcode::UnixStreamRecvResponse
            | Opcode::UnixStreamShutdownResponse
            | Opcode::UnixStreamGetSockNameResponse
            | Opcode::UnixStreamGetPeerNameResponse
            | Opcode::PtyReadResponse
            | Opcode::PtyWriteResponse
            | Opcode::SubscribePtyResponse
            | Opcode::PtyIoctlResponse
            | Opcode::UnsubscribeResponse
            | Opcode::DupHandleResponse
            | Opcode::QueryEventsResponse
            | Opcode::CreatePidfdResponse
            | Opcode::PidfdExitedResponse
            | Opcode::InetDgramCreateResponse
            | Opcode::InetDgramBindResponse
            | Opcode::InetDgramConnectResponse
            | Opcode::InetDgramSendToResponse
            | Opcode::InetDgramRecvFromResponse
            | Opcode::InetDgramShutdownResponse
            | Opcode::InetDgramGetSockNameResponse
            | Opcode::InetDgramGetPeerNameResponse
            | Opcode::InetDgramSetSockOptResponse
            | Opcode::InetDgramGetSockOptResponse
            | Opcode::InetDgramQueryEventsResponse
            | Opcode::RegisterProcessResponse
            | Opcode::SubscribeProcessExitResponse
            | Opcode::MarkProcessExitedResponse
            | Opcode::ReleaseAllForPidResponse
            | Opcode::SubscribeSignalInboxResponse
            | Opcode::UnsubscribeSignalInboxResponse
            | Opcode::DeliverSignalInboxResponse
            | Opcode::SetPgidResponse
            | Opcode::SetSidResponse
            | Opcode::ReadTcpConnResponse
            | Opcode::WriteTcpConnResponse
            | Opcode::ShutdownTcpConnResponse
            | Opcode::PollTcpConnEventsResponse
            | Opcode::InetTcpConnSetSockOptResponse
            | Opcode::InetTcpConnGetSockOptResponse => None,
        }
    }

    /// True if this opcode is a request.
    pub fn is_request(self) -> bool {
        #[cfg(debug_assertions)]
        if matches!(self, Opcode::DebugQueryStateObject) {
            return true;
        }
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
                | Opcode::CreateTimerfd
                | Opcode::ReadTimerfd
                | Opcode::SetTimerfd
                | Opcode::GetTimerfd
                | Opcode::CreateSignalfd
                | Opcode::ReadSiginfo
                | Opcode::PushSiginfo
                | Opcode::InotifyInit1
                | Opcode::InotifyAddWatch
                | Opcode::InotifyRmWatch
                | Opcode::InotifyRead
                | Opcode::InotifyQueryEvents
                | Opcode::InetListenerCreate
                | Opcode::InetListenerBind
                | Opcode::InetListenerListen
                | Opcode::InetListenerAccept
                | Opcode::InetListenerQueryEvents
                | Opcode::InetListenerSetSockOpt
                | Opcode::CreatePipe
                | Opcode::ReadPipe
                | Opcode::WritePipe
                | Opcode::AttachHostFd
                | Opcode::RegisterOfd
                | Opcode::CloneOfd
                | Opcode::BindNinePSession
                | Opcode::CreateSocketPair
                | Opcode::ReadSocketPair
                | Opcode::WriteSocketPair
                | Opcode::ShutdownSocketPairWrite
                | Opcode::InetRawCreate
                | Opcode::InetRawSendTo
                | Opcode::InetRawRecvFrom
                | Opcode::InetRawQueryEvents
                | Opcode::InetTcpConnCreate
                | Opcode::InetTcpConnConnect
                | Opcode::InetTcpConnQueryEvents
                | Opcode::InetTcpConnGetSockName
                | Opcode::InetTcpConnGetPeerName
                | Opcode::CreatePty
                | Opcode::OpenPtySlave
                | Opcode::CreateSocketSeqPacket
                | Opcode::SocketSeqPacketBind
                | Opcode::SocketSeqPacketListen
                | Opcode::SocketSeqPacketAccept
                | Opcode::SocketSeqPacketConnect
                | Opcode::SocketSeqPacketSend
                | Opcode::SocketSeqPacketRecv
                | Opcode::SocketSeqPacketShutdown
                | Opcode::SocketSeqPacketGetSockName
                | Opcode::SocketSeqPacketGetPeerName
                | Opcode::PtyRead
                | Opcode::PtyWrite
                | Opcode::SubscribePty
                | Opcode::PtyIoctl
                | Opcode::Unsubscribe
                | Opcode::DupHandle
                | Opcode::QueryEvents
                | Opcode::CreatePidfd
                | Opcode::PidfdExited
                | Opcode::InetDgramCreate
                | Opcode::InetDgramBind
                | Opcode::InetDgramConnect
                | Opcode::InetDgramSendTo
                | Opcode::InetDgramRecvFrom
                | Opcode::InetDgramShutdown
                | Opcode::InetDgramGetSockName
                | Opcode::InetDgramGetPeerName
                | Opcode::InetDgramSetSockOpt
                | Opcode::InetDgramGetSockOpt
                | Opcode::InetDgramQueryEvents
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
                | Opcode::InetTcpConnSetSockOpt
                | Opcode::InetTcpConnGetSockOpt
        )
    }

    /// Returns the number of `SCM_RIGHTS` fds that MUST accompany
    /// this opcode (request side for `Register`/`RegisterNotificationRing`,
    /// response side for `MaterializeResponse`).
    pub fn expected_fd_count(self) -> usize {
        // reason: large protocol enum; most opcodes intentionally carry no SCM_RIGHTS fds.
        #[allow(clippy::wildcard_enum_match_arm)]
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
            0x17 => Ok(Opcode::CreateTimerfd),
            0x18 => Ok(Opcode::ReadTimerfd),
            0x19 => Ok(Opcode::SetTimerfd),
            0x1A => Ok(Opcode::GetTimerfd),
            0x0D => Ok(Opcode::CreateUnixStream),
            0x0E => Ok(Opcode::UnixStreamBind),
            0x0F => Ok(Opcode::UnixStreamListen),
            0x1B => Ok(Opcode::UnixStreamAccept),
            0x1C => Ok(Opcode::UnixStreamConnect),
            0x1D => Ok(Opcode::UnixStreamSend),
            0x1E => Ok(Opcode::UnixStreamRecv),
            0x1F => Ok(Opcode::UnixStreamShutdown),
            0x2D => Ok(Opcode::UnixStreamGetSockName),
            0x2E => Ok(Opcode::UnixStreamGetPeerName),
            0x40 => Ok(Opcode::CreateSignalfd),
            0x41 => Ok(Opcode::ReadSiginfo),
            0x42 => Ok(Opcode::PushSiginfo),
            0x43 => Ok(Opcode::InotifyInit1),
            0x44 => Ok(Opcode::InotifyAddWatch),
            0x45 => Ok(Opcode::InotifyRmWatch),
            0x46 => Ok(Opcode::InotifyRead),
            0x47 => Ok(Opcode::InotifyQueryEvents),
            0x48 => Ok(Opcode::InetListenerCreate),
            0x49 => Ok(Opcode::InetListenerBind),
            0x4A => Ok(Opcode::InetListenerListen),
            0x4B => Ok(Opcode::InetListenerAccept),
            0x4C => Ok(Opcode::InetListenerQueryEvents),
            0x4D => Ok(Opcode::InetListenerSetSockOpt),
            0x4E => Ok(Opcode::InetListenerGetSockName),
            0x4F => Ok(Opcode::InetListenerGetSockOpt),
            0x50 => Ok(Opcode::CreatePipe),
            0x51 => Ok(Opcode::ReadPipe),
            0x52 => Ok(Opcode::WritePipe),
            0x53 => Ok(Opcode::AttachHostFd),
            0x54 => Ok(Opcode::RegisterOfd),
            0x55 => Ok(Opcode::CloneOfd),
            0x56 => Ok(Opcode::BindNinePSession),
            0x57 => Ok(Opcode::CreateSocketDgram),
            0x58 => Ok(Opcode::SocketDgramBind),
            0x59 => Ok(Opcode::SocketDgramConnect),
            0x5A => Ok(Opcode::SocketDgramSendTo),
            0x5B => Ok(Opcode::SocketDgramRecvFrom),
            0x5C => Ok(Opcode::SocketDgramShutdown),
            0x5D => Ok(Opcode::SocketDgramGetSockName),
            0x5E => Ok(Opcode::SocketDgramGetPeerName),
            0x30 => Ok(Opcode::CreateSocketPair),
            0x31 => Ok(Opcode::ReadSocketPair),
            0x32 => Ok(Opcode::WriteSocketPair),
            0x33 => Ok(Opcode::ShutdownSocketPairWrite),
            0x3C => Ok(Opcode::InetRawCreate),
            0x3D => Ok(Opcode::InetRawSendTo),
            0x3E => Ok(Opcode::InetRawRecvFrom),
            0x3F => Ok(Opcode::InetRawQueryEvents),
            0x34 => Ok(Opcode::InetTcpConnCreate),
            0x35 => Ok(Opcode::InetTcpConnConnect),
            0x36 => Ok(Opcode::InetTcpConnQueryEvents),
            0x37 => Ok(Opcode::InetTcpConnGetSockName),
            0x38 => Ok(Opcode::InetTcpConnGetPeerName),
            0x60 => Ok(Opcode::CreatePty),
            0x65 => Ok(Opcode::OpenPtySlave),
            0x66 => Ok(Opcode::CreateSocketSeqPacket),
            0x67 => Ok(Opcode::SocketSeqPacketBind),
            0x68 => Ok(Opcode::SocketSeqPacketListen),
            0x69 => Ok(Opcode::SocketSeqPacketAccept),
            0x6A => Ok(Opcode::SocketSeqPacketConnect),
            0x6B => Ok(Opcode::SocketSeqPacketSend),
            0x6C => Ok(Opcode::SocketSeqPacketRecv),
            0x6D => Ok(Opcode::SocketSeqPacketShutdown),
            0x6E => Ok(Opcode::SocketSeqPacketGetSockName),
            0x6F => Ok(Opcode::SocketSeqPacketGetPeerName),
            0x61 => Ok(Opcode::PtyRead),
            0x62 => Ok(Opcode::PtyWrite),
            0x63 => Ok(Opcode::SubscribePty),
            0x64 => Ok(Opcode::PtyIoctl),
            0x14 => Ok(Opcode::Unsubscribe),
            0x15 => Ok(Opcode::DupHandle),
            0x16 => Ok(Opcode::QueryEvents),
            0x20 => Ok(Opcode::CreatePidfd),
            0x21 => Ok(Opcode::PidfdExited),
            0x22 => Ok(Opcode::InetDgramCreate),
            0x23 => Ok(Opcode::InetDgramBind),
            0x24 => Ok(Opcode::InetDgramConnect),
            0x25 => Ok(Opcode::InetDgramSendTo),
            0x26 => Ok(Opcode::InetDgramRecvFrom),
            0x27 => Ok(Opcode::InetDgramShutdown),
            0x28 => Ok(Opcode::InetDgramGetSockName),
            0x29 => Ok(Opcode::InetDgramGetPeerName),
            0x2A => Ok(Opcode::InetDgramSetSockOpt),
            0x2B => Ok(Opcode::InetDgramGetSockOpt),
            0x2C => Ok(Opcode::InetDgramQueryEvents),
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
            0x7E => Ok(Opcode::InetTcpConnSetSockOpt),
            0x7F => Ok(Opcode::InetTcpConnGetSockOpt),
            #[cfg(debug_assertions)]
            0x7D => Ok(Opcode::DebugQueryStateObject),
            0x81 => Ok(Opcode::RegisterResponse),
            0x82 => Ok(Opcode::MaterializeResponse),
            0x83 => Ok(Opcode::ReleaseResponse),
            0x84 => Ok(Opcode::RegisterNotificationRingResponse),
            0x90 => Ok(Opcode::CreateEventfdResponse),
            0x91 => Ok(Opcode::ReadEventfdResponse),
            0x92 => Ok(Opcode::WriteEventfdResponse),
            0x93 => Ok(Opcode::SubscribeEventfdResponse),
            0x97 => Ok(Opcode::CreateTimerfdResponse),
            0x98 => Ok(Opcode::ReadTimerfdResponse),
            0x99 => Ok(Opcode::SetTimerfdResponse),
            0x9A => Ok(Opcode::GetTimerfdResponse),
            0x8D => Ok(Opcode::CreateUnixStreamResponse),
            0x8E => Ok(Opcode::UnixStreamBindResponse),
            0x8F => Ok(Opcode::UnixStreamListenResponse),
            0x9B => Ok(Opcode::UnixStreamAcceptResponse),
            0x9C => Ok(Opcode::UnixStreamConnectResponse),
            0x9D => Ok(Opcode::UnixStreamSendResponse),
            0x9E => Ok(Opcode::UnixStreamRecvResponse),
            0x9F => Ok(Opcode::UnixStreamShutdownResponse),
            0xAD => Ok(Opcode::UnixStreamGetSockNameResponse),
            0xAE => Ok(Opcode::UnixStreamGetPeerNameResponse),
            0xC0 => Ok(Opcode::CreateSignalfdResponse),
            0xC1 => Ok(Opcode::ReadSiginfoResponse),
            0xC2 => Ok(Opcode::PushSiginfoResponse),
            0xC3 => Ok(Opcode::InotifyInit1Response),
            0xC4 => Ok(Opcode::InotifyAddWatchResponse),
            0xC5 => Ok(Opcode::InotifyRmWatchResponse),
            0xC6 => Ok(Opcode::InotifyReadResponse),
            0xC7 => Ok(Opcode::InotifyQueryEventsResponse),
            0xC8 => Ok(Opcode::InetListenerCreateResponse),
            0xC9 => Ok(Opcode::InetListenerBindResponse),
            0xCA => Ok(Opcode::InetListenerListenResponse),
            0xCB => Ok(Opcode::InetListenerAcceptResponse),
            0xCC => Ok(Opcode::InetListenerQueryEventsResponse),
            0xCD => Ok(Opcode::InetListenerSetSockOptResponse),
            0xCE => Ok(Opcode::InetListenerGetSockNameResponse),
            0xCF => Ok(Opcode::InetListenerGetSockOptResponse),
            0xD0 => Ok(Opcode::CreatePipeResponse),
            0xD1 => Ok(Opcode::ReadPipeResponse),
            0xD2 => Ok(Opcode::WritePipeResponse),
            0xD3 => Ok(Opcode::AttachHostFdResponse),
            0xD4 => Ok(Opcode::RegisterOfdResponse),
            0xD5 => Ok(Opcode::CloneOfdResponse),
            0xD6 => Ok(Opcode::BindNinePSessionResponse),
            0xD7 => Ok(Opcode::CreateSocketDgramResponse),
            0xD8 => Ok(Opcode::SocketDgramBindResponse),
            0xD9 => Ok(Opcode::SocketDgramConnectResponse),
            0xDA => Ok(Opcode::SocketDgramSendToResponse),
            0xDB => Ok(Opcode::SocketDgramRecvFromResponse),
            0xDC => Ok(Opcode::SocketDgramShutdownResponse),
            0xDD => Ok(Opcode::SocketDgramGetSockNameResponse),
            0xDE => Ok(Opcode::SocketDgramGetPeerNameResponse),
            0xB0 => Ok(Opcode::CreateSocketPairResponse),
            0xB1 => Ok(Opcode::ReadSocketPairResponse),
            0xB2 => Ok(Opcode::WriteSocketPairResponse),
            0xB3 => Ok(Opcode::ShutdownSocketPairWriteResponse),
            0xBC => Ok(Opcode::InetRawCreateResponse),
            0xBD => Ok(Opcode::InetRawSendToResponse),
            0xBE => Ok(Opcode::InetRawRecvFromResponse),
            0xBF => Ok(Opcode::InetRawQueryEventsResponse),
            0xB4 => Ok(Opcode::InetTcpConnCreateResponse),
            0xB5 => Ok(Opcode::InetTcpConnConnectResponse),
            0xB6 => Ok(Opcode::InetTcpConnQueryEventsResponse),
            0xB7 => Ok(Opcode::InetTcpConnGetSockNameResponse),
            0xB8 => Ok(Opcode::InetTcpConnGetPeerNameResponse),
            0xE0 => Ok(Opcode::CreatePtyResponse),
            0xE5 => Ok(Opcode::OpenPtySlaveResponse),
            0xE6 => Ok(Opcode::CreateSocketSeqPacketResponse),
            0xE7 => Ok(Opcode::SocketSeqPacketBindResponse),
            0xE8 => Ok(Opcode::SocketSeqPacketListenResponse),
            0xE9 => Ok(Opcode::SocketSeqPacketAcceptResponse),
            0xEA => Ok(Opcode::SocketSeqPacketConnectResponse),
            0xEB => Ok(Opcode::SocketSeqPacketSendResponse),
            0xEC => Ok(Opcode::SocketSeqPacketRecvResponse),
            0xED => Ok(Opcode::SocketSeqPacketShutdownResponse),
            0xEE => Ok(Opcode::SocketSeqPacketGetSockNameResponse),
            0xEF => Ok(Opcode::SocketSeqPacketGetPeerNameResponse),
            0xE1 => Ok(Opcode::PtyReadResponse),
            0xE2 => Ok(Opcode::PtyWriteResponse),
            0xE3 => Ok(Opcode::SubscribePtyResponse),
            0xE4 => Ok(Opcode::PtyIoctlResponse),
            0x94 => Ok(Opcode::UnsubscribeResponse),
            0x95 => Ok(Opcode::DupHandleResponse),
            0x96 => Ok(Opcode::QueryEventsResponse),
            0xA0 => Ok(Opcode::CreatePidfdResponse),
            0xA1 => Ok(Opcode::PidfdExitedResponse),
            0xA2 => Ok(Opcode::InetDgramCreateResponse),
            0xA3 => Ok(Opcode::InetDgramBindResponse),
            0xA4 => Ok(Opcode::InetDgramConnectResponse),
            0xA5 => Ok(Opcode::InetDgramSendToResponse),
            0xA6 => Ok(Opcode::InetDgramRecvFromResponse),
            0xA7 => Ok(Opcode::InetDgramShutdownResponse),
            0xA8 => Ok(Opcode::InetDgramGetSockNameResponse),
            0xA9 => Ok(Opcode::InetDgramGetPeerNameResponse),
            0xAA => Ok(Opcode::InetDgramSetSockOptResponse),
            0xAB => Ok(Opcode::InetDgramGetSockOptResponse),
            0xAC => Ok(Opcode::InetDgramQueryEventsResponse),
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
            0xFE => Ok(Opcode::InetTcpConnSetSockOptResponse),
            0xFF => Ok(Opcode::InetTcpConnGetSockOptResponse),
            #[cfg(debug_assertions)]
            0xFD => Ok(Opcode::DebugQueryStateObjectResponse),
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
    /// Operation is blocked by broker policy or host permissions.
    PermissionDenied = 0x0A,
    /// Requested protocol is not supported by this broker subsystem.
    ProtocolNotSupported = 0x0B,
    /// Runtime I/O failure — the operation is well-formed and the
    /// handle is known, but the underlying broker-hosted resource
    /// cannot perform it. Distinct from `Internal` (broker bug) and
    /// `InvalidValue` (caller error). The canonical case is a PTY
    /// write when the peer endpoint is closed — Linux returns `EIO`
    /// for this transition; the shim maps `Io` → `Errno::EIO`.
    Io = 0x0C,

    /// Generic protocol violation.
    Protocol = 0x10,
    /// Generic broker-internal error.
    Internal = 0x11,
    /// Legacy-pipes Phase 3 (D3 step 2d.2): `BindNinePSession` was
    /// issued with a 9P conn_id that the broker doesn't know about
    /// (either never opened, or already torn down).
    UnknownNinePSession = 0x12,
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
            0x0A => Ok(StatusCode::PermissionDenied),
            0x0B => Ok(StatusCode::ProtocolNotSupported),
            0x0C => Ok(StatusCode::Io),
            0x10 => Ok(StatusCode::Protocol),
            0x11 => Ok(StatusCode::Internal),
            0x12 => Ok(StatusCode::UnknownNinePSession),
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

/// Body for [`Opcode::CreateTimerfd`]: (clockid: i32, flags: u32).
pub fn build_create_timerfd_request(clockid: i32, flags: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&clockid.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::CreateTimerfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a CreateTimerfd request frame.
pub fn parse_create_timerfd_body(body: &[u8]) -> Result<(i32, u32), ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateTimerfd,
            got: body.len(),
            want: 8,
        });
    }
    let clockid = i32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let flags = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    Ok((clockid, flags))
}

/// Body for [`Opcode::CreateTimerfdResponse`]: handle id.
pub fn build_create_timerfd_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateTimerfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadTimerfd`]: handle id.
pub fn build_read_timerfd_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadTimerfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::ReadTimerfdResponse`]: expiration count.
pub fn build_read_timerfd_response_ok(expirations: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::ReadTimerfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: expirations.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::SetTimerfd`]: (handle: u64, flags: u32, pad: u32, itimerspec).
pub fn build_set_timerfd_request(
    handle_id: u64,
    new_value: BrokerTimerfdSpec,
    flags: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(48);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    encode_timerfd_spec(&mut body, new_value);
    OwnedFrame {
        opcode: Opcode::SetTimerfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a SetTimerfd request frame.
pub fn parse_set_timerfd_body(body: &[u8]) -> Result<(u64, BrokerTimerfdSpec, u32), ProtocolError> {
    if body.len() != 48 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SetTimerfd,
            got: body.len(),
            want: 48,
        });
    }
    let handle = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let flags = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    if body[12..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((handle, decode_timerfd_spec(&body[16..48])?, flags))
}

/// Body for [`Opcode::SetTimerfdResponse`]: empty.
pub fn build_set_timerfd_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SetTimerfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::GetTimerfd`]: handle id.
pub fn build_get_timerfd_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::GetTimerfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Body for [`Opcode::GetTimerfdResponse`]: itimerspec.
pub fn build_get_timerfd_response_ok(value: BrokerTimerfdSpec) -> OwnedFrame {
    let mut body = Vec::with_capacity(32);
    encode_timerfd_spec(&mut body, value);
    OwnedFrame {
        opcode: Opcode::GetTimerfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Decodes the body of a GetTimerfdResponse success frame.
pub fn parse_get_timerfd_response_ok(body: &[u8]) -> Result<BrokerTimerfdSpec, ProtocolError> {
    decode_timerfd_spec_with_opcode(body, Opcode::GetTimerfdResponse)
}

fn encode_timerfd_spec(body: &mut Vec<u8>, spec: BrokerTimerfdSpec) {
    body.extend_from_slice(&spec.interval_sec.to_le_bytes());
    body.extend_from_slice(&spec.interval_nsec.to_le_bytes());
    body.extend_from_slice(&spec.value_sec.to_le_bytes());
    body.extend_from_slice(&spec.value_nsec.to_le_bytes());
}

fn decode_timerfd_spec(body: &[u8]) -> Result<BrokerTimerfdSpec, ProtocolError> {
    decode_timerfd_spec_with_opcode(body, Opcode::SetTimerfd)
}

fn decode_timerfd_spec_with_opcode(
    body: &[u8],
    opcode: Opcode,
) -> Result<BrokerTimerfdSpec, ProtocolError> {
    if body.len() != 32 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 32,
        });
    }
    Ok(BrokerTimerfdSpec {
        interval_sec: u64::from_le_bytes([
            body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
        ]),
        interval_nsec: u64::from_le_bytes([
            body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
        ]),
        value_sec: u64::from_le_bytes([
            body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
        ]),
        value_nsec: u64::from_le_bytes([
            body[24], body[25], body[26], body[27], body[28], body[29], body[30], body[31],
        ]),
    })
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

/// Body for [`Opcode::InotifyInit1`]: flags (u32) + reserved (u32).
pub fn build_inotify_init1_request(flags: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InotifyInit1,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inotify_init1_body(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyInit1,
            got: body.len(),
            want: 8,
        });
    }
    let flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok(flags)
}

pub fn build_inotify_init1_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InotifyInit1Response,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn build_inotify_add_watch_request(handle_id: u64, path: &str, mask: u32) -> OwnedFrame {
    let path_bytes = path.as_bytes();
    let mut body = Vec::with_capacity(24 + path_bytes.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(path_bytes);
    OwnedFrame {
        opcode: Opcode::InotifyAddWatch,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inotify_add_watch_body(
    body: &[u8],
) -> Result<(u64, u32, alloc::string::String), ProtocolError> {
    if body.len() < 20 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyAddWatch,
            got: body.len(),
            want: 20,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mask = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[16..20].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 20 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyAddWatch,
            got: body.len(),
            want: 20 + len,
        });
    }
    alloc::string::String::from_utf8(body[20..].to_vec())
        .map(|path| (handle, mask, path))
        .map_err(|_| ProtocolError::NonZeroReserved { reserved: 1 })
}

pub fn build_inotify_add_watch_response_ok(wd: i32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&wd.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InotifyAddWatchResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inotify_add_watch_response_ok(body: &[u8]) -> Result<i32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyAddWatchResponse,
            got: body.len(),
            want: 8,
        });
    }
    let wd = i32::from_le_bytes(body[0..4].try_into().unwrap());
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok(wd)
}

pub fn build_inotify_rm_watch_request(handle_id: u64, wd: i32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&wd.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InotifyRmWatch,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inotify_rm_watch_body(body: &[u8]) -> Result<(u64, i32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyRmWatch,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let wd = i32::from_le_bytes(body[8..12].try_into().unwrap());
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((handle, wd))
}

pub fn build_inotify_rm_watch_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InotifyRmWatchResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_inotify_read_request(handle_id: u64, max_len: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InotifyRead,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inotify_read_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyRead,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let max_len = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((handle, max_len))
}

pub fn build_inotify_read_response_ok(payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + payload.len());
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::InotifyReadResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inotify_read_response_body(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InotifyReadResponse,
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
            opcode: Opcode::InotifyReadResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

/// Body for [`Opcode::InetListenerCreate`]: family (u8: 0=v4, 1=v6) + reserved (7 bytes).
pub fn build_inet_listener_create_request(family: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.push(family);
    body.extend_from_slice(&[0u8; 7]);
    OwnedFrame {
        opcode: Opcode::InetListenerCreate,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_create_body(body: &[u8]) -> Result<u8, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerCreate,
            got: body.len(),
            want: 8,
        });
    }
    if body[1..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(body[0])
}

pub fn build_inet_listener_create_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerCreateResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_listener_create_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetListenerCreateResponse)
}

/// Body for [`Opcode::InetListenerBind`]: handle id + 28-byte sockaddr_storage.
pub fn build_inet_listener_bind_request(handle_id: u64, sockaddr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(36);
    body.extend_from_slice(&handle_id.to_le_bytes());
    let mut addr = [0u8; 28];
    let n = core::cmp::min(sockaddr.len(), addr.len());
    addr[..n].copy_from_slice(&sockaddr[..n]);
    body.extend_from_slice(&addr);
    OwnedFrame {
        opcode: Opcode::InetListenerBind,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_bind_body(body: &[u8]) -> Result<(u64, [u8; 28]), ProtocolError> {
    if body.len() != 36 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerBind,
            got: body.len(),
            want: 36,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    Ok((handle, sockaddr))
}

pub fn build_inet_listener_bind_response_ok(actual_sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerBindResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: actual_sockaddr.to_vec(),
    }
}

pub fn parse_inet_listener_bind_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    if body.len() != 28 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerBindResponse,
            got: body.len(),
            want: 28,
        });
    }
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(body);
    Ok(sockaddr)
}

/// Body for [`Opcode::InetListenerListen`]: handle id + backlog (u32) + reserved (u32).
pub fn build_inet_listener_listen_request(handle_id: u64, backlog: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&backlog.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetListenerListen,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_listen_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerListen,
            got: body.len(),
            want: 16,
        });
    }
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}

pub fn build_inet_listener_listen_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerListenResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::InetListenerAccept`]: handle id.
pub fn build_inet_listener_accept_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerAccept,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_listener_accept_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetListenerAccept)
}

pub fn build_inet_listener_accept_response_ok(
    conn_handle_id: u64,
    peer_sockaddr: &[u8; 28],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(36);
    body.extend_from_slice(&conn_handle_id.to_le_bytes());
    body.extend_from_slice(peer_sockaddr);
    OwnedFrame {
        opcode: Opcode::InetListenerAcceptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_accept_response_ok(
    body: &[u8],
) -> Result<(u64, [u8; 28]), ProtocolError> {
    if body.len() != 36 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerAcceptResponse,
            got: body.len(),
            want: 36,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut peer = [0u8; 28];
    peer.copy_from_slice(&body[8..36]);
    Ok((handle, peer))
}

/// Body for [`Opcode::InetListenerSetSockOpt`]: handle, level, optname, optval.
pub fn build_inet_listener_setsockopt_request(
    handle_id: u64,
    level: u32,
    optname: u32,
    optval: &[u8],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24 + optval.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&level.to_le_bytes());
    body.extend_from_slice(&optname.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(optval.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(optval);
    OwnedFrame {
        opcode: Opcode::InetListenerSetSockOpt,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_setsockopt_body(
    body: &[u8],
) -> Result<(u64, u32, u32, Vec<u8>), ProtocolError> {
    parse_sockopt_set_body(body, Opcode::InetListenerSetSockOpt)
}

pub fn build_inet_listener_setsockopt_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerSetSockOptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::InetListenerGetSockName`]: handle id.
pub fn build_inet_listener_getsockname_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerGetSockName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_listener_getsockname_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetListenerGetSockName)
}

pub fn build_inet_listener_getsockname_response_ok(sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerGetSockNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
    }
}

pub fn parse_inet_listener_getsockname_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    if body.len() != 28 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerGetSockNameResponse,
            got: body.len(),
            want: 28,
        });
    }
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(body);
    Ok(sockaddr)
}

/// Body for [`Opcode::InetListenerGetSockOpt`]: handle, level, optname, optlen.
pub fn build_inet_listener_getsockopt_request(
    handle_id: u64,
    level: u32,
    optname: u32,
    optlen: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&level.to_le_bytes());
    body.extend_from_slice(&optname.to_le_bytes());
    body.extend_from_slice(&optlen.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetListenerGetSockOpt,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_getsockopt_body(
    body: &[u8],
) -> Result<(u64, u32, u32, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerGetSockOpt,
            got: body.len(),
            want: 24,
        });
    }
    let reserved = u32::from_le_bytes(body[20..24].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
        u32::from_le_bytes(body[12..16].try_into().unwrap()),
        u32::from_le_bytes(body[16..20].try_into().unwrap()),
    ))
}

pub fn build_inet_listener_getsockopt_response_ok(value: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + value.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(value.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(value);
    OwnedFrame {
        opcode: Opcode::InetListenerGetSockOptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_listener_getsockopt_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerGetSockOptResponse,
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
            opcode: Opcode::InetListenerGetSockOptResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

/// Body for [`Opcode::InetListenerQueryEvents`]: handle id.
pub fn build_inet_listener_query_events_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerQueryEvents,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_listener_query_events_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetListenerQueryEvents)
}

pub fn build_inet_listener_query_events_response_ok(events: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetListenerQueryEventsResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: events.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_listener_query_events_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetListenerQueryEventsResponse,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
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
// AttachHostFd wire format. Legacy-pipes Phase 3 (D2).
//
// SCM_RIGHTS-pass a host fd to the broker, which takes ownership and
// exposes it as a BrokerPipe-shaped state handle. The host fd itself
// rides in the cmsg attached to the request frame; the body carries
// only the direction byte (so subsequent ReadPipe/WritePipe RPCs
// against the returned handle can be validated against the original
// direction).
// =====================================================================

/// Direction wire codes for `Opcode::AttachHostFd`. Allocated separately
/// from `BrokerPipeEnd` to keep the wire surface stable independent of
/// the shim-side type evolution.
pub mod host_fd_direction {
    /// Worker may only `ReadPipe` against the returned handle.
    pub const READ: u8 = 0;
    /// Worker may only `WritePipe` against the returned handle.
    pub const WRITE: u8 = 1;
    /// Worker may both `ReadPipe` and `WritePipe` (full duplex, e.g.
    /// for an attached socket).
    pub const READ_WRITE: u8 = 2;
}

/// Body for [`Opcode::AttachHostFd`]: `(direction: u8, _reserved: [u8; 7])` —
/// 8 bytes, 8-byte-aligned. The host fd rides in the SCM_RIGHTS cmsg
/// (caller must include exactly one fd).
pub fn build_attach_host_fd_request(direction: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.push(direction);
    body.extend_from_slice(&[0u8; 7]);
    OwnedFrame {
        opcode: Opcode::AttachHostFd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_attach_host_fd_body(body: &[u8]) -> Result<u8, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::AttachHostFd,
            got: body.len(),
            want: 8,
        });
    }
    // Reserved bytes are tolerated but must be zero for forward
    // compatibility.
    if body[1..].iter().any(|&b| b != 0) {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::AttachHostFd,
            got: body.len(),
            want: 8,
        });
    }
    Ok(body[0])
}

/// Body for [`Opcode::AttachHostFdResponse`] on success: `(handle_id: u64)`.
pub fn build_attach_host_fd_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::AttachHostFdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_attach_host_fd_response_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::AttachHostFdResponse)
}

// =====================================================================
// RegisterOfd / CloneOfd wire format. Legacy-pipes Phase 3 (D3).
//
// RegisterOfd is issued on the parent shim's fd-token-socket; the
// broker handler resolves `fid` against the parent's own 9P
// `Server::fids` map, calls `try_clone()` on the underlying host
// file, stashes the dup in the broker-global `OfdRegistry`, and
// returns a fresh `OpenFileId` the caller can later ship to the
// worker (via the existing `--broker-fd-bridge` CLI mechanism).
//
// CloneOfd is issued on the worker shim's fd-token-socket; the
// broker handler looks up `open_file_id` in the registry, calls
// `try_clone()` on the stashed file (= `dup(2)` → shares the
// kernel OFD with the parent's original fid), and installs a
// freshly-constructed `FidState` at `new_fid` on the worker's
// own 9P `Server::fids` map. Subsequent worker-side 9P reads
// and writes against `new_fid` go through the worker's 9P
// connection as normal — there is no per-RPC broker hop.
// =====================================================================

/// Body for [`Opcode::RegisterOfd`]: `(fid: u32, _reserved: [u8; 4])` — 8 bytes.
#[must_use]
pub fn build_register_ofd_request(fid: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&fid.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::RegisterOfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Parse the body of an [`Opcode::RegisterOfd`] request into the requested fid.
///
/// # Errors
///
/// Returns [`ProtocolError::WrongBodyLen`] if `body.len() != 8` or
/// the reserved trailing bytes are non-zero.
pub fn parse_register_ofd_body(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::RegisterOfd,
            got: body.len(),
            want: 8,
        });
    }
    if body[4..].iter().any(|&b| b != 0) {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::RegisterOfd,
            got: body.len(),
            want: 8,
        });
    }
    let mut fid_bytes = [0u8; 4];
    fid_bytes.copy_from_slice(&body[0..4]);
    Ok(u32::from_le_bytes(fid_bytes))
}

/// Body for [`Opcode::RegisterOfdResponse`] on success: `(open_file_id: u64)`.
#[must_use]
pub fn build_register_ofd_response_ok(open_file_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::RegisterOfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: open_file_id.to_le_bytes().to_vec(),
    }
}

/// Parse the body of an [`Opcode::RegisterOfdResponse`] success frame.
///
/// # Errors
///
/// Returns [`ProtocolError::WrongBodyLen`] if `body.len() != 8`.
pub fn parse_register_ofd_response_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::RegisterOfdResponse)
}

/// Body for [`Opcode::CloneOfd`]:
/// `(open_file_id: u64, new_fid: u32, _reserved: [u8; 4])` — 16 bytes.
#[must_use]
pub fn build_clone_ofd_request(open_file_id: u64, new_fid: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&open_file_id.to_le_bytes());
    body.extend_from_slice(&new_fid.to_le_bytes());
    body.extend_from_slice(&[0u8; 4]);
    OwnedFrame {
        opcode: Opcode::CloneOfd,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

/// Parse the body of an [`Opcode::CloneOfd`] request into
/// `(open_file_id, new_fid)`.
///
/// # Errors
///
/// Returns [`ProtocolError::WrongBodyLen`] if `body.len() != 16` or
/// the reserved trailing bytes are non-zero.
pub fn parse_clone_ofd_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CloneOfd,
            got: body.len(),
            want: 16,
        });
    }
    if body[12..].iter().any(|&b| b != 0) {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CloneOfd,
            got: body.len(),
            want: 16,
        });
    }
    let mut ofid_bytes = [0u8; 8];
    ofid_bytes.copy_from_slice(&body[0..8]);
    let mut fid_bytes = [0u8; 4];
    fid_bytes.copy_from_slice(&body[8..12]);
    Ok((
        u64::from_le_bytes(ofid_bytes),
        u32::from_le_bytes(fid_bytes),
    ))
}

/// Body for [`Opcode::CloneOfdResponse`] on success: empty.
#[must_use]
pub fn build_clone_ofd_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CloneOfdResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Verify a [`Opcode::CloneOfdResponse`] success frame body is empty.
///
/// # Errors
///
/// Returns [`ProtocolError::WrongBodyLen`] if `body.len() != 0`.
pub fn parse_clone_ofd_response_body(body: &[u8]) -> Result<(), ProtocolError> {
    if !body.is_empty() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CloneOfdResponse,
            got: body.len(),
            want: 0,
        });
    }
    Ok(())
}

// =====================================================================
// BindNinePSession wire format. Legacy-pipes Phase 3 (D3 step 2d.2).
//
// Pairs an fd-token-socket connection with a 9P session by its
// broker-assigned conn_id (obtained from the bootstrap ACK of
// `connect_nine_p_channel`). Must be issued before any RegisterOfd /
// CloneOfd op against the same fd-token-socket connection.
// =====================================================================

/// Body for [`Opcode::BindNinePSession`]: `(nine_p_conn_id: u64)` — 8 bytes.
#[must_use]
pub fn build_bind_nine_p_session_request(nine_p_conn_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::BindNinePSession,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: nine_p_conn_id.to_le_bytes().to_vec(),
    }
}

/// Parse the body of an [`Opcode::BindNinePSession`] request.
///
/// # Errors
///
/// Returns [`ProtocolError::WrongBodyLen`] if `body.len() != 8`.
pub fn parse_bind_nine_p_session_body(body: &[u8]) -> Result<u64, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::BindNinePSession,
            got: body.len(),
            want: 8,
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&body[..8]);
    Ok(u64::from_le_bytes(buf))
}

/// Build a successful [`Opcode::BindNinePSessionResponse`] frame.
#[must_use]
pub fn build_bind_nine_p_session_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::BindNinePSessionResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Verify a [`Opcode::BindNinePSessionResponse`] success frame body is empty.
///
/// # Errors
///
/// Returns [`ProtocolError::WrongBodyLen`] if `body.len() != 0`.
pub fn parse_bind_nine_p_session_response_body(body: &[u8]) -> Result<(), ProtocolError> {
    if !body.is_empty() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::BindNinePSessionResponse,
            got: body.len(),
            want: 0,
        });
    }
    Ok(())
}

// =====================================================================
// SocketDgram (AF_UNIX SOCK_DGRAM) wire format.
//
// Unix addresses are encoded by the broker/shim as:
//   kind: u8 (0=unnamed, 1=filesystem path bytes, 2=abstract bytes),
//   len: u32 little-endian, then `len` bytes.
// Empty address vectors in SendTo mean "use connected peer".
// =====================================================================

pub const SOCKET_DGRAM_RECV_FLAG_TRUNC: u32 = INET_DGRAM_RECV_FLAG_TRUNC;

pub fn build_create_socket_dgram_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateSocketDgram,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn parse_create_socket_dgram_body(body: &[u8]) -> Result<(), ProtocolError> {
    if !body.is_empty() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateSocketDgram,
            got: body.len(),
            want: 0,
        });
    }
    Ok(())
}

pub fn build_create_socket_dgram_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateSocketDgramResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_create_socket_dgram_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::CreateSocketDgramResponse)
}

fn push_len_bytes(body: &mut Vec<u8>, bytes: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(bytes);
}

fn parse_len_bytes<'a>(
    body: &'a [u8],
    offset: &mut usize,
    opcode: Opcode,
) -> Result<&'a [u8], ProtocolError> {
    if body.len() < *offset + 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: *offset + 4,
        });
    }
    let len = u32::from_le_bytes(body[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if body.len() < *offset + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: *offset + len,
        });
    }
    let out = &body[*offset..*offset + len];
    *offset += len;
    Ok(out)
}

pub fn build_socket_dgram_bind_request(handle_id: u64, addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(12 + addr.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketDgramBind,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_bind_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramBind,
            got: body.len(),
            want: 12,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramBind)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramBind,
            got: body.len(),
            want: off,
        });
    }
    Ok((handle, addr))
}

pub fn build_socket_dgram_bind_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(4 + addr.len());
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketDgramBindResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_bind_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramBindResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramBindResponse,
            got: body.len(),
            want: off,
        });
    }
    Ok(addr)
}

pub fn build_socket_dgram_connect_request(handle_id: u64, addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(12 + addr.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketDgramConnect,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_connect_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramConnect,
            got: body.len(),
            want: 12,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramConnect)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramConnect,
            got: body.len(),
            want: off,
        });
    }
    Ok((handle, addr))
}

pub fn build_socket_dgram_connect_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketDgramConnectResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_socket_dgram_sendto_request(
    handle_id: u64,
    addr: &[u8],
    payload: &[u8],
) -> OwnedFrame {
    build_socket_dgram_sendto_request_with_tokens(handle_id, addr, payload, &[])
}

pub fn build_socket_dgram_sendto_request_with_tokens(
    handle_id: u64,
    addr: &[u8],
    payload: &[u8],
    tokens: &[PassedToken],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(20 + addr.len() + payload.len() + 8 * tokens.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    push_len_bytes(&mut body, addr);
    body.extend_from_slice(&(tokens.len() as u32).to_le_bytes());
    for token in tokens {
        body.extend_from_slice(&token.raw().to_le_bytes());
    }
    push_len_bytes(&mut body, payload);
    OwnedFrame {
        opcode: Opcode::SocketDgramSendTo,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_sendto_body(
    body: &[u8],
) -> Result<(u64, Vec<u8>, Vec<PassedToken>, Vec<u8>), ProtocolError> {
    if body.len() < 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramSendTo,
            got: body.len(),
            want: 16,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramSendTo)?.to_vec();
    if off + 4 > body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramSendTo,
            got: body.len(),
            want: off + 4,
        });
    }
    let token_count = u32::from_le_bytes(body[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let token_bytes = token_count
        .checked_mul(8)
        .ok_or(ProtocolError::BodyTooLarge {
            body_len: u32::MAX,
            max: BODY_MAX,
        })?;
    if off + token_bytes > body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramSendTo,
            got: body.len(),
            want: off + token_bytes,
        });
    }
    let mut tokens = Vec::with_capacity(token_count);
    for i in 0..token_count {
        let start = off + 8 * i;
        tokens.push(PassedToken::from_raw(u64::from_le_bytes(
            body[start..start + 8].try_into().unwrap(),
        )));
    }
    off += token_bytes;
    let payload = parse_len_bytes(body, &mut off, Opcode::SocketDgramSendTo)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramSendTo,
            got: body.len(),
            want: off,
        });
    }
    Ok((handle, addr, tokens, payload))
}

pub fn build_socket_dgram_sendto_response_ok(written: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketDgramSendToResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: written.to_le_bytes().to_vec(),
    }
}

pub fn parse_socket_dgram_sendto_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::SocketDgramSendToResponse)
}

pub fn build_socket_dgram_recvfrom_request(handle_id: u64, max_len: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::SocketDgramRecvFrom,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_recvfrom_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramRecvFrom,
            got: body.len(),
            want: 16,
        });
    }
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}

pub fn build_socket_dgram_recvfrom_response_ok(
    addr: &[u8],
    payload: &[u8],
    flags: u32,
) -> OwnedFrame {
    build_socket_dgram_recvfrom_response_ok_with_tokens(addr, payload, flags, &[])
}

pub fn build_socket_dgram_recvfrom_response_ok_with_tokens(
    addr: &[u8],
    payload: &[u8],
    flags: u32,
    tokens: &[PassedToken],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(16 + addr.len() + payload.len() + 8 * tokens.len());
    body.extend_from_slice(&flags.to_le_bytes());
    push_len_bytes(&mut body, addr);
    body.extend_from_slice(&(tokens.len() as u32).to_le_bytes());
    for token in tokens {
        body.extend_from_slice(&token.raw().to_le_bytes());
    }
    push_len_bytes(&mut body, payload);
    OwnedFrame {
        opcode: Opcode::SocketDgramRecvFromResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_recvfrom_response_ok(
    body: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u32, Vec<PassedToken>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramRecvFromResponse,
            got: body.len(),
            want: 12,
        });
    }
    let flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let mut off = 4;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramRecvFromResponse)?.to_vec();
    if off + 4 > body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramRecvFromResponse,
            got: body.len(),
            want: off + 4,
        });
    }
    let token_count = u32::from_le_bytes(body[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let token_bytes = token_count
        .checked_mul(8)
        .ok_or(ProtocolError::BodyTooLarge {
            body_len: u32::MAX,
            max: BODY_MAX,
        })?;
    if off + token_bytes > body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramRecvFromResponse,
            got: body.len(),
            want: off + token_bytes,
        });
    }
    let mut tokens = Vec::with_capacity(token_count);
    for i in 0..token_count {
        let start = off + 8 * i;
        tokens.push(PassedToken::from_raw(u64::from_le_bytes(
            body[start..start + 8].try_into().unwrap(),
        )));
    }
    off += token_bytes;
    let payload = parse_len_bytes(body, &mut off, Opcode::SocketDgramRecvFromResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramRecvFromResponse,
            got: body.len(),
            want: off,
        });
    }
    Ok((addr, payload, flags, tokens))
}

pub fn build_socket_dgram_shutdown_request(handle_id: u64, how: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.push(how);
    body.extend_from_slice(&[0; 7]);
    OwnedFrame {
        opcode: Opcode::SocketDgramShutdown,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_shutdown_body(body: &[u8]) -> Result<(u64, u8), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramShutdown,
            got: body.len(),
            want: 16,
        });
    }
    if body[9..16].iter().any(|b| *b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((u64::from_le_bytes(body[0..8].try_into().unwrap()), body[8]))
}

pub fn build_socket_dgram_shutdown_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketDgramShutdownResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_socket_dgram_getsockname_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketDgramGetSockName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn build_socket_dgram_getpeername_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketDgramGetPeerName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn build_socket_dgram_getsockname_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(4 + addr.len());
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketDgramGetSockNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn build_socket_dgram_getpeername_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(4 + addr.len());
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketDgramGetPeerNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_socket_dgram_getsockname_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramGetSockNameResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramGetSockNameResponse,
            got: body.len(),
            want: off,
        });
    }
    Ok(addr)
}

pub fn parse_socket_dgram_getpeername_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketDgramGetPeerNameResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketDgramGetPeerNameResponse,
            got: body.len(),
            want: off,
        });
    }
    Ok(addr)
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
// BrokerInetRaw wire format.
// =====================================================================

/// Body for [`Opcode::InetRawCreate`]: family (u8: 0=v4, 1=v6), protocol (u8), reserved (6 bytes).
pub fn build_inet_raw_create_request(family: u8, protocol: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.push(family);
    body.push(protocol);
    body.extend_from_slice(&[0u8; 6]);
    OwnedFrame {
        opcode: Opcode::InetRawCreate,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_raw_create_body(body: &[u8]) -> Result<(u8, u8), ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawCreate,
            got: body.len(),
            want: 8,
        });
    }
    if body[2..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((body[0], body[1]))
}

pub fn build_inet_raw_create_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetRawCreateResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_raw_create_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetRawCreateResponse)
}

/// Body for [`Opcode::InetRawSendTo`]: handle id + 28-byte sockaddr + payload length/reserved + payload.
pub fn build_inet_raw_sendto_request(handle_id: u64, sockaddr: &[u8], bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(44 + bytes.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    let mut addr = [0u8; 28];
    let n = core::cmp::min(sockaddr.len(), addr.len());
    addr[..n].copy_from_slice(&sockaddr[..n]);
    body.extend_from_slice(&addr);
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::InetRawSendTo,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_raw_sendto_body(body: &[u8]) -> Result<(u64, [u8; 28], Vec<u8>), ProtocolError> {
    if body.len() < 44 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawSendTo,
            got: body.len(),
            want: 44,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    let len = u32::from_le_bytes(body[36..40].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[40..44].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 44 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawSendTo,
            got: body.len(),
            want: 44 + len,
        });
    }
    Ok((handle, sockaddr, body[44..].to_vec()))
}

pub fn build_inet_raw_sendto_response_ok(written: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetRawSendToResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: written.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_raw_sendto_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawSendToResponse,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
}

/// Body for [`Opcode::InetRawRecvFrom`]: handle id + max_len.
pub fn build_inet_raw_recvfrom_request(handle_id: u64, max_len: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetRawRecvFrom,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_raw_recvfrom_body(body: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawRecvFrom,
            got: body.len(),
            want: 16,
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

pub fn build_inet_raw_recvfrom_response_ok(sockaddr: &[u8; 28], bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(36 + bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(sockaddr);
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::InetRawRecvFromResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_raw_recvfrom_response_ok(
    body: &[u8],
) -> Result<([u8; 28], Vec<u8>), ProtocolError> {
    if body.len() < 36 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawRecvFromResponse,
            got: body.len(),
            want: 36,
        });
    }
    let len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 36 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawRecvFromResponse,
            got: body.len(),
            want: 36 + len,
        });
    }
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    Ok((sockaddr, body[36..].to_vec()))
}

pub fn build_inet_raw_query_events_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetRawQueryEvents,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_raw_query_events_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetRawQueryEvents)
}

pub fn build_inet_raw_query_events_response_ok(events: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetRawQueryEventsResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: events.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_raw_query_events_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetRawQueryEventsResponse,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
}

// =====================================================================
// BrokerTcpConn wire format.
// =====================================================================

/// Body for [`Opcode::InetTcpConnCreate`]: family (u8: 0=v4, 1=v6) + reserved (7 bytes).
pub fn build_inet_tcp_conn_create_request(family: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.push(family);
    body.extend_from_slice(&[0u8; 7]);
    OwnedFrame {
        opcode: Opcode::InetTcpConnCreate,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_tcp_conn_create_body(body: &[u8]) -> Result<u8, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetTcpConnCreate,
            got: body.len(),
            want: 8,
        });
    }
    if body[1..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(body[0])
}

pub fn build_inet_tcp_conn_create_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnCreateResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_tcp_conn_create_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetTcpConnCreateResponse)
}

/// Body for [`Opcode::InetTcpConnConnect`]: handle id + 28-byte sockaddr_storage + timeout_ms.
pub fn build_inet_tcp_conn_connect_request(
    handle_id: u64,
    sockaddr: &[u8],
    timeout_ms: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(40);
    body.extend_from_slice(&handle_id.to_le_bytes());
    let mut addr = [0u8; 28];
    let n = core::cmp::min(sockaddr.len(), addr.len());
    addr[..n].copy_from_slice(&sockaddr[..n]);
    body.extend_from_slice(&addr);
    body.extend_from_slice(&timeout_ms.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetTcpConnConnect,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_tcp_conn_connect_body(
    body: &[u8],
) -> Result<(u64, [u8; 28], u32), ProtocolError> {
    if body.len() != 40 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetTcpConnConnect,
            got: body.len(),
            want: 40,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    let timeout_ms = u32::from_le_bytes(body[36..40].try_into().unwrap());
    Ok((handle, sockaddr, timeout_ms))
}

pub fn build_inet_tcp_conn_connect_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnConnectResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

/// Body for [`Opcode::InetTcpConnQueryEvents`]: handle id.
pub fn build_inet_tcp_conn_query_events_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnQueryEvents,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_tcp_conn_query_events_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetTcpConnQueryEvents)
}

pub fn build_inet_tcp_conn_query_events_response_ok(events: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnQueryEventsResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: events.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_tcp_conn_query_events_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetTcpConnQueryEventsResponse,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
}

pub fn build_inet_tcp_conn_getsockname_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnGetSockName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_tcp_conn_getsockname_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetTcpConnGetSockName)
}

pub fn build_inet_tcp_conn_getsockname_response_ok(sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnGetSockNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
    }
}

pub fn parse_inet_tcp_conn_getsockname_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    parse_inet_tcp_sockaddr_response(body, Opcode::InetTcpConnGetSockNameResponse)
}

pub fn build_inet_tcp_conn_getpeername_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnGetPeerName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_tcp_conn_getpeername_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetTcpConnGetPeerName)
}

pub fn build_inet_tcp_conn_getpeername_response_ok(sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnGetPeerNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
    }
}

pub fn parse_inet_tcp_conn_getpeername_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    parse_inet_tcp_sockaddr_response(body, Opcode::InetTcpConnGetPeerNameResponse)
}

fn parse_inet_tcp_sockaddr_response(
    body: &[u8],
    opcode: Opcode,
) -> Result<[u8; 28], ProtocolError> {
    if body.len() != 28 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 28,
        });
    }
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(body);
    Ok(sockaddr)
}

pub fn build_inet_tcp_conn_setsockopt_request(
    handle_id: u64,
    level: u32,
    optname: u32,
    optval: &[u8],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24 + optval.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&level.to_le_bytes());
    body.extend_from_slice(&optname.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(optval.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(optval);
    OwnedFrame {
        opcode: Opcode::InetTcpConnSetSockOpt,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_tcp_conn_setsockopt_body(
    body: &[u8],
) -> Result<(u64, u32, u32, Vec<u8>), ProtocolError> {
    parse_sockopt_set_body(body, Opcode::InetTcpConnSetSockOpt)
}

fn parse_sockopt_set_body(
    body: &[u8],
    opcode: Opcode,
) -> Result<(u64, u32, u32, Vec<u8>), ProtocolError> {
    if body.len() < 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 24,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let level = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let optname = u32::from_le_bytes(body[12..16].try_into().unwrap());
    let len = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[20..24].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 24 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 24 + len,
        });
    }
    Ok((handle, level, optname, body[24..].to_vec()))
}

pub fn build_inet_tcp_conn_setsockopt_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetTcpConnSetSockOptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_inet_tcp_conn_getsockopt_request(
    handle_id: u64,
    level: u32,
    optname: u32,
    optlen: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&level.to_le_bytes());
    body.extend_from_slice(&optname.to_le_bytes());
    body.extend_from_slice(&optlen.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetTcpConnGetSockOpt,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_tcp_conn_getsockopt_body(
    body: &[u8],
) -> Result<(u64, u32, u32, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetTcpConnGetSockOpt,
            got: body.len(),
            want: 24,
        });
    }
    let reserved = u32::from_le_bytes(body[20..24].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
        u32::from_le_bytes(body[12..16].try_into().unwrap()),
        u32::from_le_bytes(body[16..20].try_into().unwrap()),
    ))
}

pub fn build_inet_tcp_conn_getsockopt_response_ok(bytes: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(bytes);
    OwnedFrame {
        opcode: Opcode::InetTcpConnGetSockOptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_tcp_conn_getsockopt_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetTcpConnGetSockOptResponse,
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
            opcode: Opcode::InetTcpConnGetSockOptResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

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

// =====================================================================
// BrokerInetDgram wire format.
// =====================================================================

/// [`InetDgramRecvFromResponse`] flag: original datagram was larger than the returned payload.
pub const INET_DGRAM_RECV_FLAG_TRUNC: u32 = 0x1;

pub fn build_inet_dgram_create_request(family: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.push(family);
    body.extend_from_slice(&[0u8; 7]);
    OwnedFrame {
        opcode: Opcode::InetDgramCreate,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_create_body(body: &[u8]) -> Result<u8, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramCreate,
            got: body.len(),
            want: 8,
        });
    }
    if body[1..8].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok(body[0])
}

pub fn build_inet_dgram_create_response_ok(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramCreateResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_dgram_create_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetDgramCreateResponse)
}

fn build_inet_dgram_handle_sockaddr_request(
    opcode: Opcode,
    handle_id: u64,
    sockaddr: &[u8],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(36);
    body.extend_from_slice(&handle_id.to_le_bytes());
    let mut addr = [0u8; 28];
    let n = core::cmp::min(sockaddr.len(), addr.len());
    addr[..n].copy_from_slice(&sockaddr[..n]);
    body.extend_from_slice(&addr);
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

fn parse_inet_dgram_handle_sockaddr_body(
    body: &[u8],
    opcode: Opcode,
) -> Result<(u64, [u8; 28]), ProtocolError> {
    if body.len() != 36 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 36,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    Ok((handle, sockaddr))
}

pub fn build_inet_dgram_bind_request(handle_id: u64, sockaddr: &[u8]) -> OwnedFrame {
    build_inet_dgram_handle_sockaddr_request(Opcode::InetDgramBind, handle_id, sockaddr)
}

pub fn parse_inet_dgram_bind_body(body: &[u8]) -> Result<(u64, [u8; 28]), ProtocolError> {
    parse_inet_dgram_handle_sockaddr_body(body, Opcode::InetDgramBind)
}

pub fn build_inet_dgram_bind_response_ok(sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramBindResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
    }
}

pub fn parse_inet_dgram_bind_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    parse_inet_dgram_sockaddr_response(body, Opcode::InetDgramBindResponse)
}

pub fn build_inet_dgram_connect_request(handle_id: u64, sockaddr: &[u8]) -> OwnedFrame {
    build_inet_dgram_handle_sockaddr_request(Opcode::InetDgramConnect, handle_id, sockaddr)
}

pub fn parse_inet_dgram_connect_body(body: &[u8]) -> Result<(u64, [u8; 28]), ProtocolError> {
    parse_inet_dgram_handle_sockaddr_body(body, Opcode::InetDgramConnect)
}

pub fn build_inet_dgram_connect_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramConnectResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_inet_dgram_sendto_request(
    handle_id: u64,
    sockaddr: &[u8],
    payload: &[u8],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(44 + payload.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    let mut addr = [0u8; 28];
    let n = core::cmp::min(sockaddr.len(), addr.len());
    addr[..n].copy_from_slice(&sockaddr[..n]);
    body.extend_from_slice(&addr);
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::InetDgramSendTo,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_sendto_body(
    body: &[u8],
) -> Result<(u64, [u8; 28], Vec<u8>), ProtocolError> {
    if body.len() < 44 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramSendTo,
            got: body.len(),
            want: 44,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    let len = u32::from_le_bytes(body[36..40].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[40..44].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 44 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramSendTo,
            got: body.len(),
            want: 44 + len,
        });
    }
    Ok((handle, sockaddr, body[44..].to_vec()))
}

pub fn build_inet_dgram_sendto_response_ok(written: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramSendToResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: written.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_dgram_sendto_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetDgramSendToResponse)
}

pub fn build_inet_dgram_recvfrom_request(handle_id: u64, max_len: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetDgramRecvFrom,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_recvfrom_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramRecvFrom,
            got: body.len(),
            want: 16,
        });
    }
    let reserved = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}

pub fn build_inet_dgram_recvfrom_response_ok(
    peer_sockaddr: &[u8; 28],
    payload: &[u8],
    flags: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(36 + payload.len());
    body.extend_from_slice(peer_sockaddr);
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(payload);
    OwnedFrame {
        opcode: Opcode::InetDgramRecvFromResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_recvfrom_response_ok(
    body: &[u8],
) -> Result<([u8; 28], Vec<u8>, u32), ProtocolError> {
    if body.len() < 36 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramRecvFromResponse,
            got: body.len(),
            want: 36,
        });
    }
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[0..28]);
    let len = u32::from_le_bytes(body[28..32].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(body[32..36].try_into().unwrap());
    if body.len() != 36 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramRecvFromResponse,
            got: body.len(),
            want: 36 + len,
        });
    }
    Ok((sockaddr, body[36..].to_vec(), flags))
}

pub fn build_inet_dgram_shutdown_request(handle_id: u64, how: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.push(how);
    body.extend_from_slice(&[0u8; 7]);
    OwnedFrame {
        opcode: Opcode::InetDgramShutdown,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_shutdown_body(body: &[u8]) -> Result<(u64, u8), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramShutdown,
            got: body.len(),
            want: 16,
        });
    }
    if body[9..16].iter().any(|&b| b != 0) {
        return Err(ProtocolError::NonZeroReserved { reserved: 1 });
    }
    Ok((u64::from_le_bytes(body[0..8].try_into().unwrap()), body[8]))
}

pub fn build_inet_dgram_shutdown_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramShutdownResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_inet_dgram_getsockname_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramGetSockName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_dgram_getsockname_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetDgramGetSockName)
}

pub fn build_inet_dgram_getsockname_response_ok(sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramGetSockNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
    }
}

pub fn parse_inet_dgram_getsockname_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    parse_inet_dgram_sockaddr_response(body, Opcode::InetDgramGetSockNameResponse)
}

pub fn build_inet_dgram_getpeername_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramGetPeerName,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_dgram_getpeername_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetDgramGetPeerName)
}

pub fn build_inet_dgram_getpeername_response_ok(sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramGetPeerNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
    }
}

pub fn parse_inet_dgram_getpeername_response_ok(body: &[u8]) -> Result<[u8; 28], ProtocolError> {
    parse_inet_dgram_sockaddr_response(body, Opcode::InetDgramGetPeerNameResponse)
}

fn parse_inet_dgram_sockaddr_response(
    body: &[u8],
    opcode: Opcode,
) -> Result<[u8; 28], ProtocolError> {
    if body.len() != 28 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            got: body.len(),
            want: 28,
        });
    }
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(body);
    Ok(sockaddr)
}

pub fn build_inet_dgram_setsockopt_request(
    handle_id: u64,
    level: i32,
    name: i32,
    value: &[u8],
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24 + value.len());
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&level.to_le_bytes());
    body.extend_from_slice(&name.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(value.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(value);
    OwnedFrame {
        opcode: Opcode::InetDgramSetSockOpt,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_setsockopt_body(
    body: &[u8],
) -> Result<(u64, i32, i32, Vec<u8>), ProtocolError> {
    if body.len() < 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramSetSockOpt,
            got: body.len(),
            want: 24,
        });
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let level = i32::from_le_bytes(body[8..12].try_into().unwrap());
    let name = i32::from_le_bytes(body[12..16].try_into().unwrap());
    let len = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
    let reserved = u32::from_le_bytes(body[20..24].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    if body.len() != 24 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramSetSockOpt,
            got: body.len(),
            want: 24 + len,
        });
    }
    Ok((handle, level, name, body[24..].to_vec()))
}

pub fn build_inet_dgram_setsockopt_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramSetSockOptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_inet_dgram_getsockopt_request(
    handle_id: u64,
    level: i32,
    name: i32,
    max_len: u32,
) -> OwnedFrame {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&handle_id.to_le_bytes());
    body.extend_from_slice(&level.to_le_bytes());
    body.extend_from_slice(&name.to_le_bytes());
    body.extend_from_slice(&max_len.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetDgramGetSockOpt,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_getsockopt_body(
    body: &[u8],
) -> Result<(u64, i32, i32, u32), ProtocolError> {
    if body.len() != 24 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramGetSockOpt,
            got: body.len(),
            want: 24,
        });
    }
    let reserved = u32::from_le_bytes(body[20..24].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::NonZeroReserved { reserved });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        i32::from_le_bytes(body[8..12].try_into().unwrap()),
        i32::from_le_bytes(body[12..16].try_into().unwrap()),
        u32::from_le_bytes(body[16..20].try_into().unwrap()),
    ))
}

pub fn build_inet_dgram_getsockopt_response_ok(value: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + value.len());
    #[allow(clippy::cast_possible_truncation)]
    body.extend_from_slice(&(value.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(value);
    OwnedFrame {
        opcode: Opcode::InetDgramGetSockOptResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_getsockopt_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramGetSockOptResponse,
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
            opcode: Opcode::InetDgramGetSockOptResponse,
            got: body.len(),
            want: 8 + len,
        });
    }
    Ok(body[8..].to_vec())
}

pub fn build_inet_dgram_query_events_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::InetDgramQueryEvents,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

pub fn parse_inet_dgram_query_events_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::InetDgramQueryEvents)
}

pub fn build_inet_dgram_query_events_response_ok(events: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&events.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::InetDgramQueryEventsResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn parse_inet_dgram_query_events_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::InetDgramQueryEventsResponse,
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

/// Body for [`Opcode::QueryEvents`]: handle id.
pub fn build_query_events_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::QueryEvents,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

/// Decodes the body of a [`Opcode::QueryEvents`] request frame.
pub fn parse_query_events_request(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::QueryEvents)
}

/// Body for [`Opcode::QueryEventsResponse`]: `events: u32` LE — the
/// broker's current view of which `NOTIFY_EVENT_*` bits are set on
/// the queried handle. The caller filters with its own event mask.
pub fn build_query_events_response_ok(events: u32) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::QueryEventsResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: events.to_le_bytes().to_vec(),
    }
}

/// Decodes the body of a [`Opcode::QueryEventsResponse`] success frame.
pub fn parse_query_events_response_ok(body: &[u8]) -> Result<u32, ProtocolError> {
    if body.len() != 4 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::QueryEventsResponse,
            got: body.len(),
            want: 4,
        });
    }
    Ok(u32::from_le_bytes([body[0], body[1], body[2], body[3]]))
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugStateObjectInfo {
    pub kind_tag: u8,
    pub refcount: u32,
    pub debug_info: String,
}

#[cfg(debug_assertions)]
pub fn build_debug_query_state_object_request(handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::DebugQueryStateObject,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

#[cfg(debug_assertions)]
pub fn parse_debug_query_state_object_request(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::DebugQueryStateObject)
}

#[cfg(debug_assertions)]
pub fn build_debug_query_state_object_response_ok(
    kind_tag: u8,
    refcount: u32,
    debug_info: &str,
) -> OwnedFrame {
    let info = debug_info.as_bytes();
    let len = info.len().min(u16::MAX as usize);
    let mut body = Vec::with_capacity(7 + len);
    body.push(kind_tag);
    body.extend_from_slice(&refcount.to_le_bytes());
    body.extend_from_slice(&(len as u16).to_le_bytes());
    body.extend_from_slice(&info[..len]);
    OwnedFrame {
        opcode: Opcode::DebugQueryStateObjectResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

#[cfg(debug_assertions)]
pub fn parse_debug_query_state_object_response_body(
    body: &[u8],
) -> Result<DebugStateObjectInfo, ProtocolError> {
    if body.len() < 7 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::DebugQueryStateObjectResponse,
            got: body.len(),
            want: 7,
        });
    }
    let kind_tag = body[0];
    let refcount = u32::from_le_bytes([body[1], body[2], body[3], body[4]]);
    let len = u16::from_le_bytes([body[5], body[6]]) as usize;
    if body.len() != 7 + len {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::DebugQueryStateObjectResponse,
            got: body.len(),
            want: 7 + len,
        });
    }
    let debug_info =
        String::from_utf8(body[7..].to_vec()).map_err(|_| ProtocolError::WrongBodyLen {
            opcode: Opcode::DebugQueryStateObjectResponse,
            got: body.len(),
            want: 7 + len,
        })?;
    Ok(DebugStateObjectInfo {
        kind_tag,
        refcount,
        debug_info,
    })
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

    macro_rules! define_opcode_test_helpers {
        ($($(#[$meta:meta])* $variant:ident),+ $(,)?) => {
            fn all_opcodes() -> &'static [Opcode] {
                &[
                    $(
                        $(#[$meta])*
                        Opcode::$variant,
                    )+
                ]
            }

            fn opcode_exhaustiveness_guard(op: Opcode) {
                match op {
                    $(
                        $(#[$meta])*
                        Opcode::$variant => {}
                    )+
                }
            }
        };
    }

    define_opcode_test_helpers! {
        Register,
        Materialize,
        Release,
        RegisterNotificationRing,
        CreateEventfd,
        ReadEventfd,
        WriteEventfd,
        SubscribeEventfd,
        CreateTimerfd,
        ReadTimerfd,
        SetTimerfd,
        GetTimerfd,
        CreateSignalfd,
        ReadSiginfo,
        PushSiginfo,
        InotifyInit1,
        InotifyAddWatch,
        InotifyRmWatch,
        InotifyRead,
        InotifyQueryEvents,
        InetListenerCreate,
        InetListenerBind,
        InetListenerListen,
        InetListenerAccept,
        InetListenerQueryEvents,
        InetListenerSetSockOpt,
        InetListenerGetSockName,
        InetListenerGetSockOpt,
        CreatePipe,
        ReadPipe,
        WritePipe,
        AttachHostFd,
        RegisterOfd,
        CloneOfd,
        BindNinePSession,
        CreateSocketDgram,
        SocketDgramBind,
        SocketDgramConnect,
        SocketDgramSendTo,
        SocketDgramRecvFrom,
        SocketDgramShutdown,
        SocketDgramGetSockName,
        SocketDgramGetPeerName,
        CreateSocketPair,
        ReadSocketPair,
        WriteSocketPair,
        ShutdownSocketPairWrite,
        InetRawCreate,
        InetRawSendTo,
        InetRawRecvFrom,
        InetRawQueryEvents,
        InetTcpConnCreate,
        InetTcpConnConnect,
        InetTcpConnQueryEvents,
        InetTcpConnGetSockName,
        InetTcpConnGetPeerName,
        CreatePty,
        OpenPtySlave,
        CreateSocketSeqPacket,
        SocketSeqPacketBind,
        SocketSeqPacketListen,
        SocketSeqPacketAccept,
        SocketSeqPacketConnect,
        SocketSeqPacketSend,
        SocketSeqPacketRecv,
        SocketSeqPacketShutdown,
        SocketSeqPacketGetSockName,
        SocketSeqPacketGetPeerName,
        CreateUnixStream,
        UnixStreamBind,
        UnixStreamListen,
        UnixStreamAccept,
        UnixStreamConnect,
        UnixStreamSend,
        UnixStreamRecv,
        UnixStreamShutdown,
        UnixStreamGetSockName,
        UnixStreamGetPeerName,
        PtyRead,
        PtyWrite,
        SubscribePty,
        PtyIoctl,
        Unsubscribe,
        DupHandle,
        QueryEvents,
        CreatePidfd,
        PidfdExited,
        InetDgramCreate,
        InetDgramBind,
        InetDgramConnect,
        InetDgramSendTo,
        InetDgramRecvFrom,
        InetDgramShutdown,
        InetDgramGetSockName,
        InetDgramGetPeerName,
        InetDgramSetSockOpt,
        InetDgramGetSockOpt,
        InetDgramQueryEvents,
        RegisterProcess,
        SubscribeProcessExit,
        MarkProcessExited,
        ReleaseAllForPid,
        SubscribeSignalInbox,
        UnsubscribeSignalInbox,
        DeliverSignalInbox,
        SetPgid,
        SetSid,
        ReadTcpConn,
        WriteTcpConn,
        ShutdownTcpConn,
        PollTcpConnEvents,
        InetTcpConnSetSockOpt,
        InetTcpConnGetSockOpt,
        #[cfg(debug_assertions)]
        DebugQueryStateObject,
        RegisterResponse,
        MaterializeResponse,
        ReleaseResponse,
        RegisterNotificationRingResponse,
        CreateEventfdResponse,
        ReadEventfdResponse,
        WriteEventfdResponse,
        SubscribeEventfdResponse,
        CreateTimerfdResponse,
        ReadTimerfdResponse,
        SetTimerfdResponse,
        GetTimerfdResponse,
        CreateSignalfdResponse,
        ReadSiginfoResponse,
        PushSiginfoResponse,
        InotifyInit1Response,
        InotifyAddWatchResponse,
        InotifyRmWatchResponse,
        InotifyReadResponse,
        InotifyQueryEventsResponse,
        InetListenerCreateResponse,
        InetListenerBindResponse,
        InetListenerListenResponse,
        InetListenerAcceptResponse,
        InetListenerQueryEventsResponse,
        InetListenerSetSockOptResponse,
        InetListenerGetSockNameResponse,
        InetListenerGetSockOptResponse,
        CreatePipeResponse,
        ReadPipeResponse,
        WritePipeResponse,
        AttachHostFdResponse,
        RegisterOfdResponse,
        CloneOfdResponse,
        BindNinePSessionResponse,
        CreateSocketDgramResponse,
        SocketDgramBindResponse,
        SocketDgramConnectResponse,
        SocketDgramSendToResponse,
        SocketDgramRecvFromResponse,
        SocketDgramShutdownResponse,
        SocketDgramGetSockNameResponse,
        SocketDgramGetPeerNameResponse,
        CreateSocketPairResponse,
        ReadSocketPairResponse,
        WriteSocketPairResponse,
        ShutdownSocketPairWriteResponse,
        InetRawCreateResponse,
        InetRawSendToResponse,
        InetRawRecvFromResponse,
        InetRawQueryEventsResponse,
        InetTcpConnCreateResponse,
        InetTcpConnConnectResponse,
        InetTcpConnQueryEventsResponse,
        InetTcpConnGetSockNameResponse,
        InetTcpConnGetPeerNameResponse,
        CreatePtyResponse,
        OpenPtySlaveResponse,
        CreateSocketSeqPacketResponse,
        SocketSeqPacketBindResponse,
        SocketSeqPacketListenResponse,
        SocketSeqPacketAcceptResponse,
        SocketSeqPacketConnectResponse,
        SocketSeqPacketSendResponse,
        SocketSeqPacketRecvResponse,
        SocketSeqPacketShutdownResponse,
        SocketSeqPacketGetSockNameResponse,
        SocketSeqPacketGetPeerNameResponse,
        CreateUnixStreamResponse,
        UnixStreamBindResponse,
        UnixStreamListenResponse,
        UnixStreamAcceptResponse,
        UnixStreamConnectResponse,
        UnixStreamSendResponse,
        UnixStreamRecvResponse,
        UnixStreamShutdownResponse,
        UnixStreamGetSockNameResponse,
        UnixStreamGetPeerNameResponse,
        PtyReadResponse,
        PtyWriteResponse,
        SubscribePtyResponse,
        PtyIoctlResponse,
        UnsubscribeResponse,
        DupHandleResponse,
        QueryEventsResponse,
        CreatePidfdResponse,
        PidfdExitedResponse,
        InetDgramCreateResponse,
        InetDgramBindResponse,
        InetDgramConnectResponse,
        InetDgramSendToResponse,
        InetDgramRecvFromResponse,
        InetDgramShutdownResponse,
        InetDgramGetSockNameResponse,
        InetDgramGetPeerNameResponse,
        InetDgramSetSockOptResponse,
        InetDgramGetSockOptResponse,
        InetDgramQueryEventsResponse,
        RegisterProcessResponse,
        SubscribeProcessExitResponse,
        MarkProcessExitedResponse,
        ReleaseAllForPidResponse,
        SubscribeSignalInboxResponse,
        UnsubscribeSignalInboxResponse,
        DeliverSignalInboxResponse,
        SetPgidResponse,
        SetSidResponse,
        ReadTcpConnResponse,
        WriteTcpConnResponse,
        ShutdownTcpConnResponse,
        PollTcpConnEventsResponse,
        InetTcpConnSetSockOptResponse,
        InetTcpConnGetSockOptResponse,
        #[cfg(debug_assertions)]
        DebugQueryStateObjectResponse,
    }

    fn expected_response_for(op: Opcode) -> Option<Opcode> {
        match op {
            Opcode::Register => Some(Opcode::RegisterResponse),
            Opcode::Materialize => Some(Opcode::MaterializeResponse),
            Opcode::Release => Some(Opcode::ReleaseResponse),
            Opcode::RegisterNotificationRing => Some(Opcode::RegisterNotificationRingResponse),
            Opcode::CreateEventfd => Some(Opcode::CreateEventfdResponse),
            Opcode::ReadEventfd => Some(Opcode::ReadEventfdResponse),
            Opcode::WriteEventfd => Some(Opcode::WriteEventfdResponse),
            Opcode::SubscribeEventfd => Some(Opcode::SubscribeEventfdResponse),
            Opcode::CreateTimerfd => Some(Opcode::CreateTimerfdResponse),
            Opcode::ReadTimerfd => Some(Opcode::ReadTimerfdResponse),
            Opcode::SetTimerfd => Some(Opcode::SetTimerfdResponse),
            Opcode::GetTimerfd => Some(Opcode::GetTimerfdResponse),
            Opcode::CreateSignalfd => Some(Opcode::CreateSignalfdResponse),
            Opcode::ReadSiginfo => Some(Opcode::ReadSiginfoResponse),
            Opcode::PushSiginfo => Some(Opcode::PushSiginfoResponse),
            Opcode::InotifyInit1 => Some(Opcode::InotifyInit1Response),
            Opcode::InotifyAddWatch => Some(Opcode::InotifyAddWatchResponse),
            Opcode::InotifyRmWatch => Some(Opcode::InotifyRmWatchResponse),
            Opcode::InotifyRead => Some(Opcode::InotifyReadResponse),
            Opcode::InotifyQueryEvents => Some(Opcode::InotifyQueryEventsResponse),
            Opcode::InetListenerCreate => Some(Opcode::InetListenerCreateResponse),
            Opcode::InetListenerBind => Some(Opcode::InetListenerBindResponse),
            Opcode::InetListenerListen => Some(Opcode::InetListenerListenResponse),
            Opcode::InetListenerAccept => Some(Opcode::InetListenerAcceptResponse),
            Opcode::InetListenerQueryEvents => Some(Opcode::InetListenerQueryEventsResponse),
            Opcode::InetListenerSetSockOpt => Some(Opcode::InetListenerSetSockOptResponse),
            Opcode::InetListenerGetSockName => Some(Opcode::InetListenerGetSockNameResponse),
            Opcode::InetListenerGetSockOpt => Some(Opcode::InetListenerGetSockOptResponse),
            Opcode::CreatePipe => Some(Opcode::CreatePipeResponse),
            Opcode::ReadPipe => Some(Opcode::ReadPipeResponse),
            Opcode::WritePipe => Some(Opcode::WritePipeResponse),
            Opcode::AttachHostFd => Some(Opcode::AttachHostFdResponse),
            Opcode::RegisterOfd => Some(Opcode::RegisterOfdResponse),
            Opcode::CloneOfd => Some(Opcode::CloneOfdResponse),
            Opcode::BindNinePSession => Some(Opcode::BindNinePSessionResponse),
            Opcode::CreateSocketDgram => Some(Opcode::CreateSocketDgramResponse),
            Opcode::SocketDgramBind => Some(Opcode::SocketDgramBindResponse),
            Opcode::SocketDgramConnect => Some(Opcode::SocketDgramConnectResponse),
            Opcode::SocketDgramSendTo => Some(Opcode::SocketDgramSendToResponse),
            Opcode::SocketDgramRecvFrom => Some(Opcode::SocketDgramRecvFromResponse),
            Opcode::SocketDgramShutdown => Some(Opcode::SocketDgramShutdownResponse),
            Opcode::SocketDgramGetSockName => Some(Opcode::SocketDgramGetSockNameResponse),
            Opcode::SocketDgramGetPeerName => Some(Opcode::SocketDgramGetPeerNameResponse),
            Opcode::CreateSocketPair => Some(Opcode::CreateSocketPairResponse),
            Opcode::ReadSocketPair => Some(Opcode::ReadSocketPairResponse),
            Opcode::WriteSocketPair => Some(Opcode::WriteSocketPairResponse),
            Opcode::ShutdownSocketPairWrite => Some(Opcode::ShutdownSocketPairWriteResponse),
            Opcode::InetRawCreate => Some(Opcode::InetRawCreateResponse),
            Opcode::InetRawSendTo => Some(Opcode::InetRawSendToResponse),
            Opcode::InetRawRecvFrom => Some(Opcode::InetRawRecvFromResponse),
            Opcode::InetRawQueryEvents => Some(Opcode::InetRawQueryEventsResponse),
            Opcode::InetTcpConnCreate => Some(Opcode::InetTcpConnCreateResponse),
            Opcode::InetTcpConnConnect => Some(Opcode::InetTcpConnConnectResponse),
            Opcode::InetTcpConnQueryEvents => Some(Opcode::InetTcpConnQueryEventsResponse),
            Opcode::InetTcpConnGetSockName => Some(Opcode::InetTcpConnGetSockNameResponse),
            Opcode::InetTcpConnGetPeerName => Some(Opcode::InetTcpConnGetPeerNameResponse),
            Opcode::CreatePty => Some(Opcode::CreatePtyResponse),
            Opcode::OpenPtySlave => Some(Opcode::OpenPtySlaveResponse),
            Opcode::CreateSocketSeqPacket => Some(Opcode::CreateSocketSeqPacketResponse),
            Opcode::SocketSeqPacketBind => Some(Opcode::SocketSeqPacketBindResponse),
            Opcode::SocketSeqPacketListen => Some(Opcode::SocketSeqPacketListenResponse),
            Opcode::SocketSeqPacketAccept => Some(Opcode::SocketSeqPacketAcceptResponse),
            Opcode::SocketSeqPacketConnect => Some(Opcode::SocketSeqPacketConnectResponse),
            Opcode::SocketSeqPacketSend => Some(Opcode::SocketSeqPacketSendResponse),
            Opcode::SocketSeqPacketRecv => Some(Opcode::SocketSeqPacketRecvResponse),
            Opcode::SocketSeqPacketShutdown => Some(Opcode::SocketSeqPacketShutdownResponse),
            Opcode::SocketSeqPacketGetSockName => Some(Opcode::SocketSeqPacketGetSockNameResponse),
            Opcode::SocketSeqPacketGetPeerName => Some(Opcode::SocketSeqPacketGetPeerNameResponse),
            Opcode::CreateUnixStream => Some(Opcode::CreateUnixStreamResponse),
            Opcode::UnixStreamBind => Some(Opcode::UnixStreamBindResponse),
            Opcode::UnixStreamListen => Some(Opcode::UnixStreamListenResponse),
            Opcode::UnixStreamAccept => Some(Opcode::UnixStreamAcceptResponse),
            Opcode::UnixStreamConnect => Some(Opcode::UnixStreamConnectResponse),
            Opcode::UnixStreamSend => Some(Opcode::UnixStreamSendResponse),
            Opcode::UnixStreamRecv => Some(Opcode::UnixStreamRecvResponse),
            Opcode::UnixStreamShutdown => Some(Opcode::UnixStreamShutdownResponse),
            Opcode::UnixStreamGetSockName => Some(Opcode::UnixStreamGetSockNameResponse),
            Opcode::UnixStreamGetPeerName => Some(Opcode::UnixStreamGetPeerNameResponse),
            Opcode::PtyRead => Some(Opcode::PtyReadResponse),
            Opcode::PtyWrite => Some(Opcode::PtyWriteResponse),
            Opcode::SubscribePty => Some(Opcode::SubscribePtyResponse),
            Opcode::PtyIoctl => Some(Opcode::PtyIoctlResponse),
            Opcode::Unsubscribe => Some(Opcode::UnsubscribeResponse),
            Opcode::DupHandle => Some(Opcode::DupHandleResponse),
            Opcode::QueryEvents => Some(Opcode::QueryEventsResponse),
            Opcode::CreatePidfd => Some(Opcode::CreatePidfdResponse),
            Opcode::PidfdExited => Some(Opcode::PidfdExitedResponse),
            Opcode::InetDgramCreate => Some(Opcode::InetDgramCreateResponse),
            Opcode::InetDgramBind => Some(Opcode::InetDgramBindResponse),
            Opcode::InetDgramConnect => Some(Opcode::InetDgramConnectResponse),
            Opcode::InetDgramSendTo => Some(Opcode::InetDgramSendToResponse),
            Opcode::InetDgramRecvFrom => Some(Opcode::InetDgramRecvFromResponse),
            Opcode::InetDgramShutdown => Some(Opcode::InetDgramShutdownResponse),
            Opcode::InetDgramGetSockName => Some(Opcode::InetDgramGetSockNameResponse),
            Opcode::InetDgramGetPeerName => Some(Opcode::InetDgramGetPeerNameResponse),
            Opcode::InetDgramSetSockOpt => Some(Opcode::InetDgramSetSockOptResponse),
            Opcode::InetDgramGetSockOpt => Some(Opcode::InetDgramGetSockOptResponse),
            Opcode::InetDgramQueryEvents => Some(Opcode::InetDgramQueryEventsResponse),
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
            Opcode::InetTcpConnSetSockOpt => Some(Opcode::InetTcpConnSetSockOptResponse),
            Opcode::InetTcpConnGetSockOpt => Some(Opcode::InetTcpConnGetSockOptResponse),
            #[cfg(debug_assertions)]
            Opcode::DebugQueryStateObject => Some(Opcode::DebugQueryStateObjectResponse),
            Opcode::RegisterResponse => None,
            Opcode::MaterializeResponse => None,
            Opcode::ReleaseResponse => None,
            Opcode::RegisterNotificationRingResponse => None,
            Opcode::CreateEventfdResponse => None,
            Opcode::ReadEventfdResponse => None,
            Opcode::WriteEventfdResponse => None,
            Opcode::SubscribeEventfdResponse => None,
            Opcode::CreateTimerfdResponse => None,
            Opcode::ReadTimerfdResponse => None,
            Opcode::SetTimerfdResponse => None,
            Opcode::GetTimerfdResponse => None,
            Opcode::CreateSignalfdResponse => None,
            Opcode::ReadSiginfoResponse => None,
            Opcode::PushSiginfoResponse => None,
            Opcode::InotifyInit1Response => None,
            Opcode::InotifyAddWatchResponse => None,
            Opcode::InotifyRmWatchResponse => None,
            Opcode::InotifyReadResponse => None,
            Opcode::InotifyQueryEventsResponse => None,
            Opcode::InetListenerCreateResponse => None,
            Opcode::InetListenerBindResponse => None,
            Opcode::InetListenerListenResponse => None,
            Opcode::InetListenerAcceptResponse => None,
            Opcode::InetListenerQueryEventsResponse => None,
            Opcode::InetListenerSetSockOptResponse => None,
            Opcode::InetListenerGetSockNameResponse => None,
            Opcode::InetListenerGetSockOptResponse => None,
            Opcode::CreatePipeResponse => None,
            Opcode::ReadPipeResponse => None,
            Opcode::WritePipeResponse => None,
            Opcode::AttachHostFdResponse => None,
            Opcode::RegisterOfdResponse => None,
            Opcode::CloneOfdResponse => None,
            Opcode::BindNinePSessionResponse => None,
            Opcode::CreateSocketDgramResponse => None,
            Opcode::SocketDgramBindResponse => None,
            Opcode::SocketDgramConnectResponse => None,
            Opcode::SocketDgramSendToResponse => None,
            Opcode::SocketDgramRecvFromResponse => None,
            Opcode::SocketDgramShutdownResponse => None,
            Opcode::SocketDgramGetSockNameResponse => None,
            Opcode::SocketDgramGetPeerNameResponse => None,
            Opcode::CreateSocketPairResponse => None,
            Opcode::ReadSocketPairResponse => None,
            Opcode::WriteSocketPairResponse => None,
            Opcode::ShutdownSocketPairWriteResponse => None,
            Opcode::InetRawCreateResponse => None,
            Opcode::InetRawSendToResponse => None,
            Opcode::InetRawRecvFromResponse => None,
            Opcode::InetRawQueryEventsResponse => None,
            Opcode::InetTcpConnCreateResponse => None,
            Opcode::InetTcpConnConnectResponse => None,
            Opcode::InetTcpConnQueryEventsResponse => None,
            Opcode::InetTcpConnGetSockNameResponse => None,
            Opcode::InetTcpConnGetPeerNameResponse => None,
            Opcode::CreatePtyResponse => None,
            Opcode::OpenPtySlaveResponse => None,
            Opcode::CreateSocketSeqPacketResponse => None,
            Opcode::SocketSeqPacketBindResponse => None,
            Opcode::SocketSeqPacketListenResponse => None,
            Opcode::SocketSeqPacketAcceptResponse => None,
            Opcode::SocketSeqPacketConnectResponse => None,
            Opcode::SocketSeqPacketSendResponse => None,
            Opcode::SocketSeqPacketRecvResponse => None,
            Opcode::SocketSeqPacketShutdownResponse => None,
            Opcode::SocketSeqPacketGetSockNameResponse => None,
            Opcode::SocketSeqPacketGetPeerNameResponse => None,
            Opcode::CreateUnixStreamResponse => None,
            Opcode::UnixStreamBindResponse => None,
            Opcode::UnixStreamListenResponse => None,
            Opcode::UnixStreamAcceptResponse => None,
            Opcode::UnixStreamConnectResponse => None,
            Opcode::UnixStreamSendResponse => None,
            Opcode::UnixStreamRecvResponse => None,
            Opcode::UnixStreamShutdownResponse => None,
            Opcode::UnixStreamGetSockNameResponse => None,
            Opcode::UnixStreamGetPeerNameResponse => None,
            Opcode::PtyReadResponse => None,
            Opcode::PtyWriteResponse => None,
            Opcode::SubscribePtyResponse => None,
            Opcode::PtyIoctlResponse => None,
            Opcode::UnsubscribeResponse => None,
            Opcode::DupHandleResponse => None,
            Opcode::QueryEventsResponse => None,
            Opcode::CreatePidfdResponse => None,
            Opcode::PidfdExitedResponse => None,
            Opcode::InetDgramCreateResponse => None,
            Opcode::InetDgramBindResponse => None,
            Opcode::InetDgramConnectResponse => None,
            Opcode::InetDgramSendToResponse => None,
            Opcode::InetDgramRecvFromResponse => None,
            Opcode::InetDgramShutdownResponse => None,
            Opcode::InetDgramGetSockNameResponse => None,
            Opcode::InetDgramGetPeerNameResponse => None,
            Opcode::InetDgramSetSockOptResponse => None,
            Opcode::InetDgramGetSockOptResponse => None,
            Opcode::InetDgramQueryEventsResponse => None,
            Opcode::RegisterProcessResponse => None,
            Opcode::SubscribeProcessExitResponse => None,
            Opcode::MarkProcessExitedResponse => None,
            Opcode::ReleaseAllForPidResponse => None,
            Opcode::SubscribeSignalInboxResponse => None,
            Opcode::UnsubscribeSignalInboxResponse => None,
            Opcode::DeliverSignalInboxResponse => None,
            Opcode::SetPgidResponse => None,
            Opcode::SetSidResponse => None,
            Opcode::ReadTcpConnResponse => None,
            Opcode::WriteTcpConnResponse => None,
            Opcode::ShutdownTcpConnResponse => None,
            Opcode::PollTcpConnEventsResponse => None,
            Opcode::InetTcpConnSetSockOptResponse => None,
            Opcode::InetTcpConnGetSockOptResponse => None,
            #[cfg(debug_assertions)]
            Opcode::DebugQueryStateObjectResponse => None,
        }
    }

    #[test]
    fn opcode_round_trip() {
        let mut seen = [false; 256];

        for &op in all_opcodes() {
            opcode_exhaustiveness_guard(op);
            let byte = op as u8;
            assert!(
                !seen[usize::from(byte)],
                "duplicate opcode byte 0x{byte:02X} for {op:?}"
            );
            seen[usize::from(byte)] = true;
            assert_eq!(
                Opcode::try_from(byte).unwrap(),
                op,
                "opcode byte 0x{byte:02X}"
            );
        }
    }

    #[test]
    fn response_for_pairs() {
        for &op in all_opcodes() {
            assert_eq!(
                op.response_for(),
                expected_response_for(op),
                "response_for({op:?})"
            );
        }
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
            Opcode::QueryEvents,
            Opcode::QueryEventsResponse,
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
        // 0x00 is outside the allocated opcode ranges. Update if it ever gets allocated.
        buf[6] = 0x00;
        match decode(&buf) {
            Err(ProtocolError::UnknownOpcode { opcode: 0x00 }) => {}
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

    /// Legacy-pipes Phase 3 (D2): `AttachHostFd` wire format
    /// round-trip. Request body shape: 1 direction byte + 7 reserved
    /// bytes (8-byte-aligned). Response body shape: 8-byte handle id.
    #[test]
    fn attach_host_fd_request_round_trip() {
        for &dir in &[
            host_fd_direction::READ,
            host_fd_direction::WRITE,
            host_fd_direction::READ_WRITE,
        ] {
            let frame = build_attach_host_fd_request(dir);
            let encoded = frame.encode().expect("encode");
            let decoded = decode(&encoded).expect("decode");
            assert_eq!(decoded.opcode, Opcode::AttachHostFd);
            let parsed = parse_attach_host_fd_body(decoded.body).expect("parse body");
            assert_eq!(parsed, dir);
        }
    }

    /// `parse_attach_host_fd_body` rejects wrong body length.
    #[test]
    fn attach_host_fd_request_rejects_wrong_body_len() {
        assert!(parse_attach_host_fd_body(&[]).is_err());
        assert!(parse_attach_host_fd_body(&[0u8; 4]).is_err());
        assert!(parse_attach_host_fd_body(&[0u8; 7]).is_err());
        assert!(parse_attach_host_fd_body(&[0u8; 9]).is_err());
    }

    /// `parse_attach_host_fd_body` rejects non-zero reserved bytes
    /// (forward-compat reservation).
    #[test]
    fn attach_host_fd_request_rejects_nonzero_reserved() {
        let mut body = alloc::vec![0u8; 8];
        body[0] = host_fd_direction::READ;
        body[3] = 0xFF; // non-zero reserved byte
        assert!(parse_attach_host_fd_body(&body).is_err());
    }

    /// `AttachHostFdResponse` round-trip with a representative handle id.
    #[test]
    fn attach_host_fd_response_round_trip() {
        let handle_id = 0xDEAD_BEEF_CAFE_BABE_u64;
        let frame = build_attach_host_fd_response_ok(handle_id);
        let encoded = frame.encode().expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.opcode, Opcode::AttachHostFdResponse);
        let parsed = parse_attach_host_fd_response_body(decoded.body).expect("parse body");
        assert_eq!(parsed, handle_id);
    }

    /// `Opcode::AttachHostFd` is classified as a request and its
    /// response pairing is correct.
    #[test]
    fn attach_host_fd_opcode_classification() {
        assert!(Opcode::AttachHostFd.is_request());
        assert_eq!(
            Opcode::AttachHostFd.response_for(),
            Some(Opcode::AttachHostFdResponse)
        );
        assert_eq!(Opcode::try_from(0x53u8).unwrap(), Opcode::AttachHostFd);
        assert_eq!(
            Opcode::try_from(0xD3u8).unwrap(),
            Opcode::AttachHostFdResponse
        );
    }

    /// Legacy-pipes Phase 3 (D3): `RegisterOfd` request body shape
    /// `(fid: u32, _reserved: [u8; 4])` round-trips for varied fid
    /// values.
    #[test]
    fn register_ofd_request_round_trip() {
        for &fid in &[0u32, 1, 7, 0x100, u32::MAX] {
            let frame = build_register_ofd_request(fid);
            let encoded = frame.encode().expect("encode");
            let decoded = decode(&encoded).expect("decode");
            assert_eq!(decoded.opcode, Opcode::RegisterOfd);
            let parsed = parse_register_ofd_body(decoded.body).expect("parse body");
            assert_eq!(parsed, fid);
        }
    }

    /// `parse_register_ofd_body` rejects wrong body length and
    /// non-zero reserved bytes.
    #[test]
    fn register_ofd_request_rejects_malformed() {
        assert!(parse_register_ofd_body(&[]).is_err());
        assert!(parse_register_ofd_body(&[0u8; 4]).is_err());
        assert!(parse_register_ofd_body(&[0u8; 7]).is_err());
        assert!(parse_register_ofd_body(&[0u8; 9]).is_err());
        let mut body = alloc::vec![0u8; 8];
        body[5] = 0xFF; // non-zero reserved byte
        assert!(parse_register_ofd_body(&body).is_err());
    }

    /// `RegisterOfdResponse` round-trip with a representative id.
    #[test]
    fn register_ofd_response_round_trip() {
        let open_file_id = 0xABCD_1234_5678_9ABC_u64;
        let frame = build_register_ofd_response_ok(open_file_id);
        let encoded = frame.encode().expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.opcode, Opcode::RegisterOfdResponse);
        let parsed = parse_register_ofd_response_body(decoded.body).expect("parse body");
        assert_eq!(parsed, open_file_id);
    }

    /// `CloneOfd` request body shape `(open_file_id: u64, new_fid:
    /// u32, _reserved: [u8; 4])` round-trips.
    #[test]
    fn clone_ofd_request_round_trip() {
        for &(ofid, fid) in &[
            (0u64, 0u32),
            (1, 1),
            (0xDEAD_BEEF_u64, 42),
            (u64::MAX, u32::MAX),
        ] {
            let frame = build_clone_ofd_request(ofid, fid);
            let encoded = frame.encode().expect("encode");
            let decoded = decode(&encoded).expect("decode");
            assert_eq!(decoded.opcode, Opcode::CloneOfd);
            let parsed = parse_clone_ofd_body(decoded.body).expect("parse body");
            assert_eq!(parsed, (ofid, fid));
        }
    }

    /// `parse_clone_ofd_body` rejects wrong body length and
    /// non-zero reserved bytes.
    #[test]
    fn clone_ofd_request_rejects_malformed() {
        assert!(parse_clone_ofd_body(&[]).is_err());
        assert!(parse_clone_ofd_body(&[0u8; 8]).is_err());
        assert!(parse_clone_ofd_body(&[0u8; 15]).is_err());
        assert!(parse_clone_ofd_body(&[0u8; 17]).is_err());
        let mut body = alloc::vec![0u8; 16];
        body[13] = 0xFF; // non-zero reserved byte
        assert!(parse_clone_ofd_body(&body).is_err());
    }

    /// `CloneOfdResponse` Ok body is empty and round-trips.
    #[test]
    fn clone_ofd_response_round_trip() {
        let frame = build_clone_ofd_response_ok();
        let encoded = frame.encode().expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.opcode, Opcode::CloneOfdResponse);
        assert!(decoded.body.is_empty());
        parse_clone_ofd_response_body(decoded.body).expect("parse body");
    }

    /// D3 opcodes classify as requests and pair to their responses.
    #[test]
    fn register_clone_ofd_opcode_classification() {
        assert!(Opcode::RegisterOfd.is_request());
        assert!(Opcode::CloneOfd.is_request());
        assert_eq!(
            Opcode::RegisterOfd.response_for(),
            Some(Opcode::RegisterOfdResponse)
        );
        assert_eq!(
            Opcode::CloneOfd.response_for(),
            Some(Opcode::CloneOfdResponse)
        );
        assert_eq!(Opcode::try_from(0x54u8).unwrap(), Opcode::RegisterOfd);
        assert_eq!(Opcode::try_from(0x55u8).unwrap(), Opcode::CloneOfd);
        assert_eq!(
            Opcode::try_from(0xD4u8).unwrap(),
            Opcode::RegisterOfdResponse
        );
        assert_eq!(Opcode::try_from(0xD5u8).unwrap(), Opcode::CloneOfdResponse);
    }

    /// Legacy-pipes Phase 3 (D3 step 2d.2): `BindNinePSession` is an
    /// 8-byte request body carrying the broker-assigned 9P conn_id,
    /// and the response is an empty Ok or `UnknownNinePSession`.
    #[test]
    fn bind_nine_p_session_round_trip() {
        let frame = build_bind_nine_p_session_request(0x1234_5678_9ABC_DEF0);
        let bytes = frame.encode().expect("encode");
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.opcode, Opcode::BindNinePSession);
        assert_eq!(decoded.status, StatusCode::Ok);
        let id = parse_bind_nine_p_session_body(decoded.body).expect("parse body");
        assert_eq!(id, 0x1234_5678_9ABC_DEF0);

        let resp = build_bind_nine_p_session_response_ok();
        let resp_bytes = resp.encode().expect("encode resp");
        let decoded_resp = decode(&resp_bytes).expect("decode resp");
        assert_eq!(decoded_resp.opcode, Opcode::BindNinePSessionResponse);
        parse_bind_nine_p_session_response_body(decoded_resp.body).expect("parse resp body");
    }

    #[test]
    fn bind_nine_p_session_body_rejects_wrong_length() {
        assert!(parse_bind_nine_p_session_body(&[]).is_err());
        assert!(parse_bind_nine_p_session_body(&[0u8; 7]).is_err());
        assert!(parse_bind_nine_p_session_body(&[0u8; 9]).is_err());
    }

    #[test]
    fn bind_nine_p_session_opcode_classification() {
        assert!(Opcode::BindNinePSession.is_request());
        assert_eq!(
            Opcode::BindNinePSession.response_for(),
            Some(Opcode::BindNinePSessionResponse)
        );
        assert_eq!(Opcode::try_from(0x56u8).unwrap(), Opcode::BindNinePSession);
        assert_eq!(
            Opcode::try_from(0xD6u8).unwrap(),
            Opcode::BindNinePSessionResponse
        );
        // `UnknownNinePSession` status round-trips.
        assert_eq!(
            StatusCode::try_from(0x12u8).unwrap(),
            StatusCode::UnknownNinePSession
        );
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

// SocketSeqPacket (AF_UNIX SOCK_SEQPACKET) wire format.
// Ancillary data and abstract namespace addresses are intentionally deferred.
pub const SOCKET_SEQPACKET_RECV_FLAG_TRUNC: u32 = INET_DGRAM_RECV_FLAG_TRUNC;

fn put_u64(body: &mut Vec<u8>, value: u64) {
    body.extend_from_slice(&value.to_le_bytes());
}

fn build_handle_request(opcode: Opcode, handle_id: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    put_u64(&mut body, handle_id);
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

fn build_handle_response(opcode: Opcode, handle_id: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(8);
    put_u64(&mut body, handle_id);
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}

pub fn build_create_socket_seqpacket_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateSocketSeqPacket,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}
pub fn build_create_socket_seqpacket_pair_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateSocketSeqPacket,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::from([1]),
    }
}
pub fn parse_create_socket_seqpacket_body(body: &[u8]) -> Result<bool, ProtocolError> {
    match body {
        [] => Ok(false),
        [1] => Ok(true),
        _ => Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateSocketSeqPacket,
            want: 0,
            got: body.len(),
        }),
    }
}
pub fn build_create_socket_seqpacket_response_ok(handle_id: u64) -> OwnedFrame {
    build_handle_response(Opcode::CreateSocketSeqPacketResponse, handle_id)
}
pub fn parse_create_socket_seqpacket_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::CreateSocketSeqPacketResponse)
}
pub fn build_create_socket_seqpacket_pair_response_ok(a: u64, b: u64) -> OwnedFrame {
    let mut body = Vec::with_capacity(16);
    put_u64(&mut body, a);
    put_u64(&mut body, b);
    OwnedFrame {
        opcode: Opcode::CreateSocketSeqPacketResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_create_socket_seqpacket_pair_response_ok(
    body: &[u8],
) -> Result<(u64, u64), ProtocolError> {
    if body.len() != 16 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::CreateSocketSeqPacketResponse,
            want: 16,
            got: body.len(),
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
    ))
}

fn build_seqpacket_addr_request(opcode: Opcode, handle_id: u64, addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(12 + addr.len());
    put_u64(&mut body, handle_id);
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
fn parse_seqpacket_addr_body(body: &[u8], opcode: Opcode) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            want: 12,
            got: body.len(),
        });
    }
    let handle_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let addr = parse_len_bytes(body, &mut off, opcode)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            want: off,
            got: body.len(),
        });
    }
    Ok((handle_id, addr))
}
pub fn build_socket_seqpacket_bind_request(handle_id: u64, addr: &[u8]) -> OwnedFrame {
    build_seqpacket_addr_request(Opcode::SocketSeqPacketBind, handle_id, addr)
}
pub fn parse_socket_seqpacket_bind_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    parse_seqpacket_addr_body(body, Opcode::SocketSeqPacketBind)
}
pub fn build_socket_seqpacket_bind_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::new();
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketBindResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_bind_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::SocketSeqPacketBindResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketBindResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(addr)
}
pub fn build_socket_seqpacket_listen_request(handle_id: u64, backlog: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(12);
    put_u64(&mut body, handle_id);
    body.extend_from_slice(&backlog.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketListen,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_listen_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketListen,
            want: 12,
            got: body.len(),
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}
pub fn build_socket_seqpacket_listen_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketListenResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}
pub fn build_socket_seqpacket_accept_request(handle_id: u64) -> OwnedFrame {
    build_handle_request(Opcode::SocketSeqPacketAccept, handle_id)
}
pub fn parse_socket_seqpacket_accept_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::SocketSeqPacketAccept)
}
pub fn build_socket_seqpacket_accept_response_ok(handle_id: u64) -> OwnedFrame {
    build_handle_response(Opcode::SocketSeqPacketAcceptResponse, handle_id)
}
pub fn parse_socket_seqpacket_accept_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::SocketSeqPacketAcceptResponse)
}
pub fn build_socket_seqpacket_connect_request(handle_id: u64, addr: &[u8]) -> OwnedFrame {
    build_seqpacket_addr_request(Opcode::SocketSeqPacketConnect, handle_id, addr)
}
pub fn parse_socket_seqpacket_connect_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    parse_seqpacket_addr_body(body, Opcode::SocketSeqPacketConnect)
}
pub fn build_socket_seqpacket_connect_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketConnectResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}
pub fn build_socket_seqpacket_send_request(handle_id: u64, payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(12 + payload.len());
    put_u64(&mut body, handle_id);
    push_len_bytes(&mut body, payload);
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketSend,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_send_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketSend,
            want: 12,
            got: body.len(),
        });
    }
    let handle_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let payload = parse_len_bytes(body, &mut off, Opcode::SocketSeqPacketSend)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketSend,
            want: off,
            got: body.len(),
        });
    }
    Ok((handle_id, payload))
}
pub fn build_socket_seqpacket_send_response_ok(written: u64) -> OwnedFrame {
    build_handle_response(Opcode::SocketSeqPacketSendResponse, written)
}
pub fn parse_socket_seqpacket_send_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::SocketSeqPacketSendResponse)
}
pub fn build_socket_seqpacket_recv_request(handle_id: u64, max_len: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(12);
    put_u64(&mut body, handle_id);
    body.extend_from_slice(&max_len.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketRecv,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_recv_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketRecv,
            want: 12,
            got: body.len(),
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}
pub fn build_socket_seqpacket_recv_response_ok(payload: &[u8], flags: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(8 + payload.len());
    body.extend_from_slice(&flags.to_le_bytes());
    push_len_bytes(&mut body, payload);
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketRecvResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_recv_response_ok(
    body: &[u8],
) -> Result<(Vec<u8>, u32), ProtocolError> {
    if body.len() < 8 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketRecvResponse,
            want: 8,
            got: body.len(),
        });
    }
    let flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let mut off = 4;
    let payload = parse_len_bytes(body, &mut off, Opcode::SocketSeqPacketRecvResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketRecvResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok((payload, flags))
}
pub fn build_socket_seqpacket_shutdown_request(handle_id: u64, how: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(9);
    put_u64(&mut body, handle_id);
    body.push(how);
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketShutdown,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_shutdown_body(body: &[u8]) -> Result<(u64, u8), ProtocolError> {
    if body.len() != 9 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketShutdown,
            want: 9,
            got: body.len(),
        });
    }
    Ok((u64::from_le_bytes(body[0..8].try_into().unwrap()), body[8]))
}
pub fn build_socket_seqpacket_shutdown_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketShutdownResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}
pub fn build_socket_seqpacket_getsockname_request(handle_id: u64) -> OwnedFrame {
    build_handle_request(Opcode::SocketSeqPacketGetSockName, handle_id)
}
pub fn build_socket_seqpacket_getpeername_request(handle_id: u64) -> OwnedFrame {
    build_handle_request(Opcode::SocketSeqPacketGetPeerName, handle_id)
}
pub fn build_socket_seqpacket_getsockname_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::new();
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketGetSockNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn build_socket_seqpacket_getpeername_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::new();
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::SocketSeqPacketGetPeerNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_socket_seqpacket_getsockname_response_ok(
    body: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr =
        parse_len_bytes(body, &mut off, Opcode::SocketSeqPacketGetSockNameResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketGetSockNameResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(addr)
}
pub fn parse_socket_seqpacket_getpeername_response_ok(
    body: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr =
        parse_len_bytes(body, &mut off, Opcode::SocketSeqPacketGetPeerNameResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::SocketSeqPacketGetPeerNameResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(addr)
}

// UnixStream (AF_UNIX SOCK_STREAM, named) wire format. Connection-oriented like
// seqpacket but with byte-stream data semantics (send/recv carry bytes, no
// packet boundary / TRUNC). `SCM_RIGHTS` is framed inline in the byte stream by
// the shim; the broker carries the framed bytes opaquely.
pub fn build_create_unix_stream_request() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::CreateUnixStream,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}
pub fn build_create_unix_stream_response_ok(handle_id: u64) -> OwnedFrame {
    build_handle_response(Opcode::CreateUnixStreamResponse, handle_id)
}
pub fn parse_create_unix_stream_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::CreateUnixStreamResponse)
}

fn build_unix_stream_addr_request(opcode: Opcode, handle_id: u64, addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(12 + addr.len());
    put_u64(&mut body, handle_id);
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
fn parse_unix_stream_addr_body(
    body: &[u8],
    opcode: Opcode,
) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            want: 12,
            got: body.len(),
        });
    }
    let handle_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let addr = parse_len_bytes(body, &mut off, opcode)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode,
            want: off,
            got: body.len(),
        });
    }
    Ok((handle_id, addr))
}

pub fn build_unix_stream_bind_request(handle_id: u64, addr: &[u8]) -> OwnedFrame {
    build_unix_stream_addr_request(Opcode::UnixStreamBind, handle_id, addr)
}
pub fn parse_unix_stream_bind_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    parse_unix_stream_addr_body(body, Opcode::UnixStreamBind)
}
pub fn build_unix_stream_bind_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::new();
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::UnixStreamBindResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_bind_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::UnixStreamBindResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamBindResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(addr)
}

pub fn build_unix_stream_listen_request(handle_id: u64, backlog: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(12);
    put_u64(&mut body, handle_id);
    body.extend_from_slice(&backlog.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::UnixStreamListen,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_listen_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamListen,
            want: 12,
            got: body.len(),
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}
pub fn build_unix_stream_listen_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::UnixStreamListenResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_unix_stream_accept_request(handle_id: u64) -> OwnedFrame {
    build_handle_request(Opcode::UnixStreamAccept, handle_id)
}
pub fn parse_unix_stream_accept_body(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::UnixStreamAccept)
}
pub fn build_unix_stream_accept_response_ok(handle_id: u64) -> OwnedFrame {
    build_handle_response(Opcode::UnixStreamAcceptResponse, handle_id)
}
pub fn parse_unix_stream_accept_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::UnixStreamAcceptResponse)
}

pub fn build_unix_stream_connect_request(handle_id: u64, addr: &[u8]) -> OwnedFrame {
    build_unix_stream_addr_request(Opcode::UnixStreamConnect, handle_id, addr)
}
pub fn parse_unix_stream_connect_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    parse_unix_stream_addr_body(body, Opcode::UnixStreamConnect)
}
pub fn build_unix_stream_connect_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::UnixStreamConnectResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_unix_stream_send_request(handle_id: u64, payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(12 + payload.len());
    put_u64(&mut body, handle_id);
    push_len_bytes(&mut body, payload);
    OwnedFrame {
        opcode: Opcode::UnixStreamSend,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_send_body(body: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
    if body.len() < 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamSend,
            want: 12,
            got: body.len(),
        });
    }
    let handle_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut off = 8;
    let payload = parse_len_bytes(body, &mut off, Opcode::UnixStreamSend)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamSend,
            want: off,
            got: body.len(),
        });
    }
    Ok((handle_id, payload))
}
pub fn build_unix_stream_send_response_ok(written: u64) -> OwnedFrame {
    build_handle_response(Opcode::UnixStreamSendResponse, written)
}
pub fn parse_unix_stream_send_response_ok(body: &[u8]) -> Result<u64, ProtocolError> {
    parse_handle_body(body, Opcode::UnixStreamSendResponse)
}

pub fn build_unix_stream_recv_request(handle_id: u64, max_len: u32) -> OwnedFrame {
    let mut body = Vec::with_capacity(12);
    put_u64(&mut body, handle_id);
    body.extend_from_slice(&max_len.to_le_bytes());
    OwnedFrame {
        opcode: Opcode::UnixStreamRecv,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_recv_body(body: &[u8]) -> Result<(u64, u32), ProtocolError> {
    if body.len() != 12 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamRecv,
            want: 12,
            got: body.len(),
        });
    }
    Ok((
        u64::from_le_bytes(body[0..8].try_into().unwrap()),
        u32::from_le_bytes(body[8..12].try_into().unwrap()),
    ))
}
pub fn build_unix_stream_recv_response_ok(payload: &[u8]) -> OwnedFrame {
    let mut body = Vec::with_capacity(4 + payload.len());
    push_len_bytes(&mut body, payload);
    OwnedFrame {
        opcode: Opcode::UnixStreamRecvResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_recv_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let payload = parse_len_bytes(body, &mut off, Opcode::UnixStreamRecvResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamRecvResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(payload)
}

pub fn build_unix_stream_shutdown_request(handle_id: u64, how: u8) -> OwnedFrame {
    let mut body = Vec::with_capacity(9);
    put_u64(&mut body, handle_id);
    body.push(how);
    OwnedFrame {
        opcode: Opcode::UnixStreamShutdown,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_shutdown_body(body: &[u8]) -> Result<(u64, u8), ProtocolError> {
    if body.len() != 9 {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamShutdown,
            want: 9,
            got: body.len(),
        });
    }
    Ok((u64::from_le_bytes(body[0..8].try_into().unwrap()), body[8]))
}
pub fn build_unix_stream_shutdown_response_ok() -> OwnedFrame {
    OwnedFrame {
        opcode: Opcode::UnixStreamShutdownResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

pub fn build_unix_stream_getsockname_request(handle_id: u64) -> OwnedFrame {
    build_handle_request(Opcode::UnixStreamGetSockName, handle_id)
}
pub fn build_unix_stream_getpeername_request(handle_id: u64) -> OwnedFrame {
    build_handle_request(Opcode::UnixStreamGetPeerName, handle_id)
}
pub fn build_unix_stream_getsockname_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::new();
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::UnixStreamGetSockNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn build_unix_stream_getpeername_response_ok(addr: &[u8]) -> OwnedFrame {
    let mut body = Vec::new();
    push_len_bytes(&mut body, addr);
    OwnedFrame {
        opcode: Opcode::UnixStreamGetPeerNameResponse,
        status: StatusCode::Ok,
        caller_pid: 0,
        body,
    }
}
pub fn parse_unix_stream_getsockname_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::UnixStreamGetSockNameResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamGetSockNameResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(addr)
}
pub fn parse_unix_stream_getpeername_response_ok(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut off = 0;
    let addr = parse_len_bytes(body, &mut off, Opcode::UnixStreamGetPeerNameResponse)?.to_vec();
    if off != body.len() {
        return Err(ProtocolError::WrongBodyLen {
            opcode: Opcode::UnixStreamGetPeerNameResponse,
            want: off,
            got: body.len(),
        });
    }
    Ok(addr)
}
