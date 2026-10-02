// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ABI between a ring-3 LiteBox runner and the LiteBox VM kernel shim.
//! Independent of the runner's shim: the service a runner provides (e.g.
//! OP-TEE) defines only its messages, process identity, and images.
//!
//! # Calls
//!
//! `kernel_calls!` binds each [`CallId`] to one request and one reply type:
//! `#[repr(C)]`, fixed-size, no padding. Both sides decode with
//! [`zerocopy::TryFromBytes`], so invalid discriminants never reach a handler.
//!
//! x86-64 `syscall` convention:
//!
//! | register | input           | output     |
//! |----------|-----------------|------------|
//! | `rax`    | [`CallId`]      | [`Status`] |
//! | `rdi`    | request address | preserved  |
//! | `rsi`    | request size    | preserved  |
//! | `rdx`    | reply address   | preserved  |
//! | `r10`    | reply size      | preserved  |
//!
//! - `rcx` and `r11` are clobbered; [`CallId::Ready`] and
//!   [`CallId::ReplyAndWait`] also reset extended state and the GS base.
//! - The reply is written only on [`Status::Ok`].
//! - Reserved fields must be zero ([`Status::InvalidArgument`]), so that they
//!   can gain a meaning later.
//! - Only a `syscall` in the runner's [`GATE_SECTION`] is a call; any other is
//!   a guest's and becomes an upcall.
//!
//! # Upcalls
//!
//! The kernel enters [`ReadyRequest::upcall_entry`] with an [`UpcallFrame`]:
//!
//! - [`UpcallKind::Syscall`]: registers as `syscall` leaves them (`rcx` =
//!   return address, `r11` = flags), number in `orig_rax`.
//! - [`UpcallKind::Exception`]: an exception the kernel could not resolve;
//!   `rip` is the faulting instruction.
//!
//! The runner resumes the guest itself. Without an upcall entry, an upcall
//! kills the process.
//!
//! # Messages
//!
//! The runner serves requests: [`CallId::Ready`] and [`CallId::ReplyAndWait`]
//! return the next request, and `ReplyAndWait` sends the reply to the current
//! one. Both are a [`Message`]: an [`envelope`] at the start of
//! [`StartupInfo::message_window`] that wraps the service's own ABI. The
//! kernel checks a reply's framing, not its parts.
//!
//! # Memory
//!
//! - [`RUNNER_MANAGED_MIN`]..[`RUNNER_MANAGED_MAX`]: the low user space, as
//!   for a guest on other LiteBox kernels; laid out by the runner, with exact
//!   ranges. The kernel's own record of these mappings is authoritative; the
//!   kernel never relies on the runner's. Disagreement only makes the
//!   runner's calls fail ([`Status::Exists`]) or no-op.
//! - [`RUNNER_MANAGED_MAX`]..[`USER_END`]: laid out by the kernel only
//!   ([`StartupInfo`]), including the runner image; kernel-placed objects go
//!   only here.
//!
//! # Trust
//!
//! The runner is untrusted: the guest shares its address space and can make
//! any call. Every call is scoped to the calling process, and identity-bound
//! results (derived keys) bind to [`StartupInfo::identity`], fixed at process
//! creation.

#![no_std]

pub mod envelope;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

/// Must change with any incompatible change to this crate.
pub const ABI_VERSION: u32 = 1;

/// The section holding the runner's only `syscall` instruction.
pub const GATE_SECTION: &str = ".kabi_gate";

/// Start of the runner-managed area (see [Memory](crate#memory)); lower
/// pages are guards.
pub const RUNNER_MANAGED_MIN: u64 = 0x1_0000;

/// Exclusive end of the runner-managed area.
pub const RUNNER_MANAGED_MAX: u64 = 0x7F00_0000_0000;

/// Exclusive end of the user address space; the last user page is a guard.
pub const USER_END: u64 = 0x7FFF_FFFF_F000;

/// Every address and length in this ABI is a multiple of this.
pub const PAGE_SIZE: u64 = 4096;

/// Largest [`LogRequest::message`].
pub const MAX_LOG_LEN: u64 = 4096;

/// Largest [`DeriveKeyRequest::context`].
pub const MAX_KDF_CONTEXT_LEN: u64 = 1024;

/// Length of [`DeriveKeyReply::key`].
pub const DERIVED_KEY_LEN: usize = 32;

/// Length of [`StartupInfo::identity`].
pub const IDENTITY_LEN: usize = 32;

/// Length of [`StartupInfo::images`].
pub const MAX_IMAGES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u32)]
pub enum Status {
    Ok = 0,
    UnknownCall = 1,
    /// The request or reply size does not match the [`CallId`].
    BadSize = 2,
    /// Undecodable, or violates a documented constraint.
    InvalidArgument = 3,
    /// A request, reply, or referenced buffer is inaccessible.
    Fault = 4,
    NoMemory = 5,
    /// Overlaps a mapping under [`Placement::NoReplace`].
    Exists = 6,
    /// Not permitted in the process's current state.
    Denied = 7,
    Unsupported = 8,
}

impl Status {
    pub fn from_raw(raw: u64) -> Option<Self> {
        let raw = u32::try_from(raw).ok()?;
        Self::try_read_from_bytes(raw.as_bytes()).ok()
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A request type and its reply, as bound by `kernel_calls!`. Sealed.
pub trait KernelCall:
    sealed::Sealed + IntoBytes + TryFromBytes + KnownLayout + Immutable + Sized
{
    const ID: CallId;
    type Reply: IntoBytes + TryFromBytes + KnownLayout + Immutable + Sized;
}

macro_rules! kernel_calls {
    ($( $(#[$meta:meta])* $id:literal => $name:ident($request:ty) -> $reply:ty; )*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum CallId {
            $( $(#[$meta])* $name = $id, )*
        }

        impl CallId {
            pub fn from_raw(raw: u64) -> Option<Self> {
                match raw {
                    $( $id => Some(Self::$name), )*
                    _ => None,
                }
            }

            pub const fn request_size(self) -> usize {
                match self {
                    $( Self::$name => size_of::<$request>(), )*
                }
            }

            pub const fn reply_size(self) -> usize {
                match self {
                    $( Self::$name => size_of::<$reply>(), )*
                }
            }
        }

        #[derive(Debug)]
        pub enum Request {
            $( $(#[$meta])* $name($request), )*
        }

        impl Request {
            /// # Errors
            ///
            /// [`Status::BadSize`] if the length is wrong and
            /// [`Status::InvalidArgument`] if the bytes are not a valid value
            /// or a reserved field is nonzero.
            pub fn decode(id: CallId, bytes: &[u8]) -> Result<Self, Status> {
                if bytes.len() != id.request_size() {
                    return Err(Status::BadSize);
                }
                let request = match id {
                    $( CallId::$name => <$request>::try_read_from_bytes(bytes)
                        .map(Self::$name)
                        .map_err(|_| Status::InvalidArgument)?, )*
                };
                if request.reserved_is_zero() {
                    Ok(request)
                } else {
                    Err(Status::InvalidArgument)
                }
            }
        }

        $(
            impl sealed::Sealed for $request {}
            impl KernelCall for $request {
                const ID: CallId = CallId::$name;
                type Reply = $reply;
            }
        )*
    };
}

kernel_calls! {
    /// Waits for the first request. Allowed once, at startup; `abi_version`
    /// must equal [`ABI_VERSION`].
    1 => Ready(ReadyRequest) -> Message;
    /// Replies to the request being served and waits for the next. Allowed
    /// only while serving a request.
    2 => ReplyAndWait(Message) -> Message;
    /// Zeroed anonymous pages. Writable and executable together is
    /// [`Status::Denied`].
    3 => Map(MapRequest) -> MapReply;
    /// Unmapped pages in the range are ignored.
    4 => Unmap(UnmapRequest) -> ();
    /// Unmapped pages in the range are ignored. Writable and executable
    /// together is [`Status::Denied`].
    5 => Protect(ProtectRequest) -> ();
    /// `litebox_broker_protocol` wire frames. Allowed once.
    6 => BrokerHandshake(BrokerHandshakeFrame) -> WireFrame;
    /// `litebox_broker_protocol` wire frames; payloads in
    /// [`StartupInfo::broker_shared_memory`].
    7 => BrokerCall(BrokerRequestFrame) -> WireFrame;
    /// The key is bound to [`StartupInfo::identity`] and `context`.
    8 => DeriveKey(DeriveKeyRequest) -> DeriveKeyReply;
    9 => Log(LogRequest) -> ();
    /// Does not return.
    10 => Exit(ExitRequest) -> ();
}

impl Request {
    /// Exhaustive: a new call must name its reserved fields.
    fn reserved_is_zero(&self) -> bool {
        match self {
            Self::Ready(r) => r.reserved == 0,
            Self::Map(r) => r.reserved == 0,
            Self::Protect(r) => r.reserved == 0,
            Self::Log(r) => r.reserved == 0,
            Self::ReplyAndWait(_)
            | Self::Unmap(_)
            | Self::BrokerHandshake(_)
            | Self::BrokerCall(_)
            | Self::DeriveKey(_)
            | Self::Exit(_) => true,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct UserBytes {
    pub addr: u64,
    pub len: u64,
}

/// Page-aligned.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct UserRegion {
    pub start: u64,
    pub len: u64,
}

impl UserRegion {
    /// Saturates on overflow.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    pub const fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end()
    }
}

/// Every combination is a variant so that decoding validates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u32)]
pub enum Prot {
    None = 0,
    Read = 1,
    Write = 2,
    ReadWrite = 3,
    Exec = 4,
    ReadExec = 5,
    WriteExec = 6,
    ReadWriteExec = 7,
}

impl Prot {
    pub const fn from_rwx(read: bool, write: bool, exec: bool) -> Self {
        match (read, write, exec) {
            (false, false, false) => Self::None,
            (true, false, false) => Self::Read,
            (false, true, false) => Self::Write,
            (true, true, false) => Self::ReadWrite,
            (false, false, true) => Self::Exec,
            (true, false, true) => Self::ReadExec,
            (false, true, true) => Self::WriteExec,
            (true, true, true) => Self::ReadWriteExec,
        }
    }

    pub const fn read(self) -> bool {
        (self as u32) & 1 != 0
    }

    pub const fn write(self) -> bool {
        (self as u32) & 2 != 0
    }

    pub const fn exec(self) -> bool {
        (self as u32) & 4 != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u32)]
pub enum Placement {
    /// Overlap is [`Status::Exists`].
    NoReplace = 0,
    /// Overlap is unmapped first.
    Replace = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u32)]
pub enum Populate {
    /// On first access.
    Lazy = 0,
    /// Before the call returns.
    Now = 1,
}

/// Maps exactly `addr..addr + len`: nonempty, page-aligned, within the
/// runner-managed area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MapRequest {
    pub addr: u64,
    pub len: u64,
    pub prot: Prot,
    pub placement: Placement,
    pub populate: Populate,
    pub reserved: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MapReply {
    pub addr: u64,
}

/// Same range constraints as [`MapRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct UnmapRequest {
    pub addr: u64,
    pub len: u64,
}

/// Same range constraints as [`MapRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ProtectRequest {
    pub addr: u64,
    pub len: u64,
    pub prot: Prot,
    pub reserved: u32,
}

/// Inline wire frame; holds any broker control message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct WireFrame {
    pub len: u32,
    pub bytes: [u8; WireFrame::CAPACITY],
}

impl WireFrame {
    pub const CAPACITY: usize = 124;

    pub fn new(bytes: &[u8]) -> Option<Self> {
        let mut frame = Self {
            len: u32::try_from(bytes.len()).ok()?,
            bytes: [0; Self::CAPACITY],
        };
        frame.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(frame)
    }

    /// `None` if `len` exceeds [`Self::CAPACITY`].
    pub fn as_slice(&self) -> Option<&[u8]> {
        self.bytes.get(..usize::try_from(self.len).ok()?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct BrokerHandshakeFrame(pub WireFrame);

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct BrokerRequestFrame(pub WireFrame);

/// `context.len` ≤ [`MAX_KDF_CONTEXT_LEN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct DeriveKeyRequest {
    pub context: UserBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct DeriveKeyReply {
    pub key: [u8; DERIVED_KEY_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u32)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

/// `message.len` ≤ [`MAX_LOG_LEN`]; UTF-8 expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct LogRequest {
    pub level: LogLevel,
    pub reserved: u32,
    pub message: UserBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ExitRequest {
    pub code: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ReadyRequest {
    pub abi_version: u32,
    pub reserved: u32,
    /// Entered with `rdi` = the [`UpcallFrame`] on
    /// [`StartupInfo::upcall_stack`]. Zero: upcalls kill the process.
    pub upcall_entry: u64,
}

/// An [`envelope`] of `len` bytes at the start of
/// [`StartupInfo::message_window`], at most its length. A reply must parse
/// ([`Status::InvalidArgument`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Message {
    pub len: u64,
}

/// `len` bytes at the start of `region`; both empty if unused.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct Image {
    pub region: UserRegion,
    pub len: u64,
}

/// Same layout as Linux's x86-64 `pt_regs`.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct Registers {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u32)]
pub enum UpcallKind {
    Exception = 0,
    Syscall = 1,
}

/// See [Upcalls](crate#upcalls). An upcall while `rsp` is on the upcall stack
/// kills the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct UpcallFrame {
    pub kind: UpcallKind,
    pub reserved: u32,
    pub regs: Registers,
    /// Exceptions only.
    pub vector: u64,
    /// Exceptions only.
    pub error_code: u64,
    /// Page faults only (CR2).
    pub fault_address: u64,
}

/// Read-only; its address is the entry point's `rdi`. Regions are in
/// [`RUNNER_MANAGED_MAX`]..[`USER_END`] and fixed for the process's
/// lifetime.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct StartupInfo {
    pub abi_version: u32,
    /// Most verbose [`LogLevel`] the kernel keeps; zero: none.
    pub max_log_level: u32,
    /// `rdtsc` is allowed in ring 3.
    pub tsc_khz: u64,
    /// Fixed at creation; its meaning is the protocol's (e.g.
    /// [`envelope::Protocol::OPTEE_MSG`]).
    pub identity: [u8; IDENTITY_LEN],
    /// Read-only, in the order given at creation; their meaning is the
    /// protocol's.
    pub images: [Image; MAX_IMAGES],
    pub heap: UserRegion,
    /// The entry `rsp` is its end.
    pub stack: UserRegion,
    pub upcall_stack: UserRegion,
    /// See [Messages](crate#messages).
    pub message_window: UserRegion,
    /// Accessed by the kernel only during the process's broker calls.
    pub broker_shared_memory: UserRegion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_ids() {
        assert_eq!(CallId::Map.request_size(), size_of::<MapRequest>());
        assert_eq!(CallId::Map.reply_size(), size_of::<MapReply>());
        assert_eq!(CallId::Exit.reply_size(), 0);
        assert_eq!(size_of::<Registers>(), 21 * 8);
        assert_eq!(size_of::<WireFrame>(), 128);
    }

    #[test]
    fn decode_rejects_invalid_discriminants() {
        let request = MapRequest {
            addr: RUNNER_MANAGED_MIN,
            len: PAGE_SIZE,
            prot: Prot::ReadWrite,
            placement: Placement::NoReplace,
            populate: Populate::Lazy,
            reserved: 0,
        };
        assert!(matches!(
            Request::decode(CallId::Map, request.as_bytes()),
            Ok(Request::Map(r)) if r == request
        ));
        let mut bytes = [0u8; size_of::<MapRequest>()];
        bytes.copy_from_slice(request.as_bytes());
        bytes[16] = 8; // `prot` out of range
        assert_eq!(
            Request::decode(CallId::Map, &bytes).unwrap_err(),
            Status::InvalidArgument
        );
        bytes.copy_from_slice(request.as_bytes());
        bytes[28] = 1; // `reserved`
        assert_eq!(
            Request::decode(CallId::Map, &bytes).unwrap_err(),
            Status::InvalidArgument
        );
        assert_eq!(
            Request::decode(CallId::Map, &bytes[1..]).unwrap_err(),
            Status::BadSize
        );
    }

    #[test]
    fn upcall_frames_validate_their_kind() {
        let frame = UpcallFrame {
            kind: UpcallKind::Syscall,
            reserved: 0,
            regs: Registers::default(),
            vector: 0,
            error_code: 0,
            fault_address: 0,
        };
        let mut bytes = [0u8; size_of::<UpcallFrame>()];
        bytes.copy_from_slice(frame.as_bytes());
        assert_eq!(UpcallFrame::try_read_from_bytes(&bytes).unwrap(), frame);
        bytes[0] = 2;
        assert!(UpcallFrame::try_read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn unknown_ids_and_statuses() {
        assert_eq!(CallId::from_raw(0), None);
        assert_eq!(CallId::from_raw(1 << 32 | 1), None);
        assert_eq!(Status::from_raw(0), Some(Status::Ok));
        assert_eq!(Status::from_raw(1 << 32), None);
        assert_eq!(Status::from_raw(99), None);
    }

    #[test]
    fn wire_frame_bounds() {
        let frame = WireFrame::new(&[1, 2, 3]).unwrap();
        assert_eq!(frame.as_slice(), Some(&[1, 2, 3][..]));
        assert!(WireFrame::new(&[0; WireFrame::CAPACITY + 1]).is_none());
        let bad = WireFrame {
            len: 200,
            bytes: [0; WireFrame::CAPACITY],
        };
        assert!(bad.as_slice().is_none());
    }
}
