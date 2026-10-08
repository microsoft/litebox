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
//! | register | input           | output             |
//! |----------|-----------------|--------------------|
//! | `rax`    | [`CallId`]      | 0, or a [`Status`] |
//! | `rdi`    | request address | preserved          |
//! | `rsi`    | request size    | preserved          |
//! | `rdx`    | reply address   | preserved          |
//! | `r10`    | reply size      | preserved          |
//!
//! - `rcx` and `r11` are clobbered; [`CallId::Ready`] and
//!   [`CallId::ReplyAndWait`] also reset extended state and the GS base.
//! - The reply is meaningful only on success; a failed call may have
//!   written part of it. [`CallId::Ready`] and [`CallId::ReplyAndWait`]
//!   write their reply when the next message is delivered, and an
//!   inaccessible reply buffer then kills the process.
//! - Reserved fields must be zero ([`Status::InvalidArgument`]), so that they
//!   can gain a meaning later. Their type, `Reserved`, decodes only zero.
//! - Only a `syscall` in the runner's [`GATE_SECTION`] is a call; any other,
//!   the guest's or a stray one in the runner, becomes an upcall.
//!
//! # Upcalls
//!
//! The kernel enters [`ReadyRequest::upcall_entry`] with an [`UpcallFrame`]:
//!
//! - [`UpcallKind::Syscall`]: registers as `syscall` leaves them (`rcx` =
//!   return address, `r11` = flags), number in `orig_rax`, `rax` = `-ENOSYS`.
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
//! # Lockdown
//!
//! [`CallId::Restrict`] irrevocably narrows the allowed calls, broker
//! operations, and page permissions. A violation kills the process.
//! [`CallId::Exit`] is always allowed.
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

/// The ranges of [`MapRequest`], [`UnmapRequest`], [`ProtectRequest`], and
/// [`StartupInfo`] are multiples of this.
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
/// Why a call failed; a successful call returns 0.
pub enum Status {
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
    /// `rax` after a call.
    pub const fn to_raw(result: Result<(), Self>) -> u64 {
        match result {
            Ok(()) => 0,
            Err(status) => status as u64,
        }
    }

    /// `None` for a value the ABI does not define.
    pub fn from_raw(raw: u64) -> Option<Result<(), Self>> {
        if raw == 0 {
            return Some(Ok(()));
        }
        let raw = u32::try_from(raw).ok()?;
        Self::try_read_from_bytes(raw.as_bytes()).ok().map(Err)
    }
}

/// A reserved field: zero on the wire, and decoding rejects anything else.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(u32)]
pub enum Reserved {
    #[default]
    Zero = 0,
}

mod sealed {
    pub trait Sealed {}
}

/// A request type and its reply, as bound by `kernel_calls!`. Sealed.
pub trait KernelCall:
    sealed::Sealed + IntoBytes + TryFromBytes + KnownLayout + Immutable + Sized
{
    const ID: CallId;
    type Reply: IntoBytes + FromBytes + KnownLayout + Immutable + Sized;
}

macro_rules! kernel_calls {
    ($( $(#[$meta:meta])* $id:literal => $name:ident($request:ty) -> $reply:ty; )*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum CallId {
            $( $(#[$meta])* $name = $id, )*
        }

        impl CallSet {
            pub const ALL: Self = Self(0 $( | 1 << $id )*);
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
            /// [`Status::InvalidArgument`] if the bytes are not a valid value,
            /// including a nonzero reserved field.
            pub fn decode(id: CallId, bytes: &[u8]) -> Result<Self, Status> {
                if bytes.len() != id.request_size() {
                    return Err(Status::BadSize);
                }
                match id {
                    $( CallId::$name => <$request>::try_read_from_bytes(bytes)
                        .map(Self::$name)
                        .map_err(|_| Status::InvalidArgument), )*
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
    /// `litebox_broker_protocol` wire frames. One attempt, successful or not;
    /// later ones are [`Status::Denied`].
    6 => BrokerHandshake(BrokerHandshakeFrame) -> WireFrame;
    /// `litebox_broker_protocol` wire frames; payloads in
    /// [`StartupInfo::broker_shared_memory`].
    7 => BrokerCall(BrokerRequestFrame) -> WireFrame;
    /// The key is bound to [`StartupInfo::identity`] and `context`.
    8 => DeriveKey(DeriveKeyRequest) -> DeriveKeyReply;
    9 => Log(LogRequest) -> ();
    /// Does not return.
    10 => Exit(ExitRequest) -> ();
    /// See [Lockdown](crate#lockdown).
    11 => Restrict(RestrictRequest) -> ();
}

/// One bit per [`CallId`] value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct CallSet(u64);

impl CallSet {
    pub const EMPTY: Self = Self(0);

    /// `None` for unknown bits.
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn with(self, id: CallId) -> Self {
        Self(self.0 | 1 << id as u32)
    }

    #[must_use]
    pub const fn without(self, id: CallId) -> Self {
        Self(self.0 & !(1 << id as u32))
    }

    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn contains(self, id: CallId) -> bool {
        self.0 & 1 << id as u32 != 0
    }
}

/// One bit per [`Prot`] value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct ProtSet(u32);

impl ProtSet {
    pub const EMPTY: Self = Self(0);
    pub const NO_EXEC: Self = Self::EMPTY
        .with(Prot::None)
        .with(Prot::Read)
        .with(Prot::Write)
        .with(Prot::ReadWrite);
    pub const ALL: Self = Self::NO_EXEC
        .with(Prot::Exec)
        .with(Prot::ReadExec)
        .with(Prot::WriteExec)
        .with(Prot::ReadWriteExec);

    /// `None` for unknown bits.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn with(self, prot: Prot) -> Self {
        Self(self.0 | 1 << prot as u32)
    }

    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn contains(self, prot: Prot) -> bool {
        self.0 & 1 << prot as u32 != 0
    }
}

macro_rules! broker_ops {
    ($( $name:ident = $id:literal, )*) => {
        /// `litebox_broker_protocol::message::BrokerOperation` variants. The
        /// numbers are this ABI's ([`BrokerOpSet`] bits), not the protocol's.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum BrokerOp {
            $( $name = $id, )*
        }

        impl BrokerOpSet {
            pub const ALL: Self = Self(0 $( | 1 << $id )*);
        }
    };
}

broker_ops! {
    CreateThread = 0,
    ExitThread = 1,
    CloseObject = 2,
    CheckReadiness = 3,
    GetStatusFlags = 4,
    SetStatusFlags = 5,
    Event = 6,
    Pipe = 7,
    Socket = 8,
    FillRandom = 9,
    File = 10,
    StartChildProcess = 11,
    GetProcessExitStatus = 12,
    ExitChildProcess = 13,
    ReportExitStatus = 14,
    SetChildReaping = 15,
    DuplicateObjectsToChild = 16,
    Timer = 17,
    Signal = 18,
    WriteChildMemory = 19,
}

/// One bit per [`BrokerOp`] value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct BrokerOpSet(u64);

impl BrokerOpSet {
    pub const EMPTY: Self = Self(0);

    /// `None` for unknown bits.
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn with(self, op: BrokerOp) -> Self {
        Self(self.0 | 1 << op as u32)
    }

    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn contains(self, op: BrokerOp) -> bool {
        self.0 & 1 << op as u32 != 0
    }
}

/// Each set is intersected with the process's current one. Unknown bits are
/// [`Status::InvalidArgument`]. Dropping [`CallId::Restrict`] from `calls`
/// makes the lockdown final.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RestrictRequest {
    pub calls: CallSet,
    pub broker_ops: BrokerOpSet,
    /// For [`CallId::Map`] and [`CallId::Protect`].
    pub prots: ProtSet,
    reserved: Reserved,
}

impl RestrictRequest {
    pub const fn new(calls: CallSet, broker_ops: BrokerOpSet, prots: ProtSet) -> Self {
        Self {
            calls,
            broker_ops,
            prots,
            reserved: Reserved::Zero,
        }
    }
}

/// Addresses `start..start + len` in the runner process. Page-aligned where
/// [`PAGE_SIZE`] says so.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct UserRange {
    pub start: u64,
    pub len: u64,
}

impl UserRange {
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
        (self as u32) & (Self::Read as u32) != 0
    }

    pub const fn write(self) -> bool {
        (self as u32) & (Self::Write as u32) != 0
    }

    pub const fn exec(self) -> bool {
        (self as u32) & (Self::Exec as u32) != 0
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

/// Maps exactly `range`: nonempty, page-aligned, within the runner-managed
/// area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MapRequest {
    pub range: UserRange,
    pub prot: Prot,
    pub placement: Placement,
    pub populate: Populate,
    reserved: Reserved,
}

impl MapRequest {
    pub const fn new(
        range: UserRange,
        prot: Prot,
        placement: Placement,
        populate: Populate,
    ) -> Self {
        Self {
            range,
            prot,
            placement,
            populate,
            reserved: Reserved::Zero,
        }
    }
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
    pub range: UserRange,
}

/// Same range constraints as [`MapRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ProtectRequest {
    pub range: UserRange,
    pub prot: Prot,
    reserved: Reserved,
}

impl ProtectRequest {
    pub const fn new(range: UserRange, prot: Prot) -> Self {
        Self {
            range,
            prot,
            reserved: Reserved::Zero,
        }
    }
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
    pub context: UserRange,
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
    reserved: Reserved,
    pub message: UserRange,
}

impl LogRequest {
    pub const fn new(level: LogLevel, message: UserRange) -> Self {
        Self {
            level,
            reserved: Reserved::Zero,
            message,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ExitRequest {
    pub code: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ReadyRequest {
    pub abi_version: u32,
    reserved: Reserved,
    /// Entered with `rdi` = the [`UpcallFrame`] on
    /// [`StartupInfo::upcall_stack`]. Zero: upcalls kill the process.
    /// Otherwise in the runner's executable segments, or
    /// [`Status::InvalidArgument`].
    pub upcall_entry: u64,
}

impl ReadyRequest {
    /// For this [`ABI_VERSION`].
    pub const fn new(upcall_entry: u64) -> Self {
        Self {
            abi_version: ABI_VERSION,
            reserved: Reserved::Zero,
            upcall_entry,
        }
    }
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
    pub region: UserRange,
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
    reserved: Reserved,
    pub regs: Registers,
    /// Exceptions only.
    pub vector: u64,
    /// Exceptions only.
    pub error_code: u64,
    /// Page faults only (CR2).
    pub fault_address: u64,
}

impl UpcallFrame {
    pub const fn new(
        kind: UpcallKind,
        regs: Registers,
        vector: u64,
        error_code: u64,
        fault_address: u64,
    ) -> Self {
        Self {
            kind,
            reserved: Reserved::Zero,
            regs,
            vector,
            error_code,
            fault_address,
        }
    }
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
    pub heap: UserRange,
    /// The entry `rsp` is its end.
    pub stack: UserRange,
    pub upcall_stack: UserRange,
    /// See [Messages](crate#messages).
    pub message_window: UserRange,
    /// Accessed by the kernel only during the process's broker calls.
    pub broker_shared_memory: UserRange,
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
            range: UserRange {
                start: RUNNER_MANAGED_MIN,
                len: PAGE_SIZE,
            },
            prot: Prot::ReadWrite,
            placement: Placement::NoReplace,
            populate: Populate::Lazy,
            reserved: Reserved::Zero,
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
    fn decode_survives_any_bytes() {
        let ids = (0..64).filter_map(CallId::from_raw);
        for id in ids {
            let size = id.request_size();
            assert_eq!(Request::decode(id, &[]).err(), Some(Status::BadSize));
            let (zeros, ones) = ([0u8; 512], [0xffu8; 512]);
            assert_eq!(
                Request::decode(id, &zeros[..=size]).err(),
                Some(Status::BadSize)
            );
            if let Err(status) = Request::decode(id, &ones[..size]) {
                assert_eq!(status, Status::InvalidArgument, "{id:?}");
            }
        }
    }

    #[test]
    fn reserved_fields_must_be_zero() {
        let range = UserRange {
            start: RUNNER_MANAGED_MIN,
            len: PAGE_SIZE,
        };
        let check = |id: CallId, valid: &[u8], reserved_at: usize| {
            assert!(Request::decode(id, valid).is_ok(), "{id:?}");
            let mut bytes = [0u8; 512];
            bytes[..valid.len()].copy_from_slice(valid);
            bytes[reserved_at] = 1;
            assert_eq!(
                Request::decode(id, &bytes[..valid.len()]).err(),
                Some(Status::InvalidArgument),
                "{id:?}"
            );
        };
        check(CallId::Ready, ReadyRequest::new(0).as_bytes(), 4);
        check(
            CallId::Protect,
            ProtectRequest::new(range, Prot::Read).as_bytes(),
            20,
        );
        check(
            CallId::Log,
            LogRequest::new(LogLevel::Info, range).as_bytes(),
            4,
        );
    }

    #[test]
    fn statuses_round_trip() {
        assert_eq!(Status::from_raw(Status::to_raw(Ok(()))), Some(Ok(())));
        for raw in 1..=u64::from(u8::MAX) {
            if let Some(result) = Status::from_raw(raw) {
                assert_eq!(Status::to_raw(result), raw);
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn upcall_frames_validate_their_kind() {
        let frame = UpcallFrame {
            kind: UpcallKind::Syscall,
            reserved: Reserved::Zero,
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
    fn call_sets() {
        assert!(CallSet::ALL.contains(CallId::Ready) && CallSet::ALL.contains(CallId::Restrict));
        assert_eq!(CallSet::ALL.bits() & 1, 0);
        let set = CallSet::EMPTY.with(CallId::Map).with(CallId::Log);
        assert!(set.contains(CallId::Map) && !set.contains(CallId::Unmap));
        assert_eq!(
            set.intersection(CallSet::ALL.without(CallId::Log)),
            CallSet::EMPTY.with(CallId::Map)
        );
        assert_eq!(CallSet::from_bits(CallSet::ALL.bits()), Some(CallSet::ALL));
        assert_eq!(CallSet::from_bits(1), None);
        let next_free_id = (CallSet::ALL.bits() + 1).next_power_of_two();
        assert_eq!(CallSet::from_bits(next_free_id), None);
        assert!(ProtSet::NO_EXEC.contains(Prot::ReadWrite));
        assert!(!ProtSet::NO_EXEC.contains(Prot::ReadExec));
        assert_eq!(ProtSet::from_bits(0x100), None);
        assert!(BrokerOpSet::ALL.contains(BrokerOp::WriteChildMemory));
        assert_eq!(BrokerOpSet::from_bits(BrokerOpSet::ALL.bits() + 1), None);
        let random = BrokerOpSet::EMPTY.with(BrokerOp::FillRandom);
        assert!(random.contains(BrokerOp::FillRandom) && !random.contains(BrokerOp::File));
    }

    #[test]
    fn unknown_ids_and_statuses() {
        assert_eq!(CallId::from_raw(0), None);
        assert_eq!(CallId::from_raw(1 << 32 | 1), None);
        assert_eq!(Status::from_raw(0), Some(Ok(())));
        assert_eq!(Status::from_raw(7), Some(Err(Status::Denied)));
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
