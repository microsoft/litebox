// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall decoding.

use litebox::utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_broker_protocol::fs::FileMode;
#[cfg(target_arch = "aarch64")]
use litebox_common_linux::PtRegs;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    MmapFlags, OpenFlags, VmProtection,
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

/// AArch64 Darwin uses bare BSD numbers in x16.
pub mod nr {
    pub const EXIT: usize = 1;
    pub const READ: usize = 3;
    pub const WRITE: usize = 4;
    pub const OPEN: usize = 5;
    pub const CLOSE: usize = 6;
    pub const GETPID: usize = 20;
    pub const GETUID: usize = 24;
    pub const GETEUID: usize = 25;
    pub const ACCESS: usize = 33;
    pub const CROSSARCH_TRAP: usize = 38;
    pub const GETPPID: usize = 39;
    pub const SIGPROCMASK: usize = 48;
    pub const IOCTL: usize = 54;
    pub const CSOPS: usize = 169;
    pub const CSOPS_AUDITTOKEN: usize = 170;
    pub const ISSETUGID: usize = 327;
    pub const STAT64: usize = 338;
    pub const FSTAT64: usize = 339;
    pub const LSTAT64: usize = 340;
    pub const MAC_SYSCALL: usize = 381;
    pub const OPENAT: usize = 463;
    pub const OPENAT_NOCANCEL: usize = 464;
    pub const CSRCTL: usize = 483;
    pub const TERMINATE_WITH_PAYLOAD: usize = 520;
    pub const ABORT_WITH_PAYLOAD: usize = 521;
    pub const MAP_WITH_LINKING_NP: usize = 550;
    pub const DUP: usize = 41;
    pub const DUP2: usize = 90;
    pub const FCNTL: usize = 92;
    pub const FCNTL_NOCANCEL: usize = 406;
    pub const GETEGID: usize = 43;
    pub const GETGID: usize = 47;
    pub const MUNMAP: usize = 73;
    pub const MPROTECT: usize = 74;
    pub const MMAP: usize = 197;
    pub const SYSCTL: usize = 202;
    pub const FSCTL: usize = 242;
    pub const SHARED_REGION_CHECK_NP: usize = 294;
    pub const THREAD_SELFID: usize = 372;
    pub const READ_NOCANCEL: usize = 396;
    pub const WRITE_NOCANCEL: usize = 397;
    pub const OPEN_NOCANCEL: usize = 398;
    pub const CLOSE_NOCANCEL: usize = 399;
    pub const GETENTROPY: usize = 500;
}

/// Selector of XNU's AArch64 machine-dependent `platform_syscall` trap
/// (`PLATFORM_SYSCALL_TRAP_NO`). It is negative as an `int`, but XNU checks it
/// before dispatching Mach traps.
pub const PLATFORM_SYSCALL_SELECTOR: u32 = 0x8000_0000;

/// Whether the low 32 bits of an AArch64 syscall selector encode XNU's
/// machine-dependent platform trap.
pub fn is_platform_syscall_selector(number: usize) -> bool {
    TruncateExt::<u32>::trunc(number) == PLATFORM_SYSCALL_SELECTOR
}

/// Whether the low 32 bits of an AArch64 syscall selector encode a Mach trap.
/// XNU interprets the selector as signed `int`, regardless of x16's upper bits.
pub fn is_mach_trap_selector(number: usize) -> bool {
    let selector: i32 = number.reinterpret_as_signed().trunc();
    selector < 0 && !is_platform_syscall_selector(number)
}

/// A request to XNU's AArch64 `platform_syscall`, selected by the low 32 bits
/// of x3. It never sets the carry flag and changes x0 only for
/// [`Self::GetCthreadSelf`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformSyscall {
    /// Code 2, `thread_set_cthread_self(x0)`: set the TSD base (TPIDRRO_EL0).
    SetCthreadSelf { tsd_base: usize },
    /// Code 3, `thread_get_cthread_self()`: return the TSD base in x0.
    GetCthreadSelf,
    /// Codes 0 and 1 (removed cache flushes) and unknown codes: no effect.
    Ignored { code: u32 },
}

impl PlatformSyscall {
    pub fn from_args(x0: usize, x3: usize) -> Self {
        match TruncateExt::<u32>::trunc(x3) {
            2 => Self::SetCthreadSelf { tsd_base: x0 },
            3 => Self::GetCthreadSelf,
            code => Self::Ignored { code },
        }
    }
}

/// Mach trap numbers. AArch64 Darwin passes their negation in w16.
pub mod mach_trap {
    /// `mach_absolute_time()`.
    pub const MACH_ABSOLUTE_TIME: u32 = 3;
    pub const MACH_VM_ALLOCATE: u32 = 10;
    pub const MACH_VM_DEALLOCATE: u32 = 12;
    pub const MACH_VM_PROTECT: u32 = 14;
    pub const MACH_VM_MAP: u32 = 15;
    pub const TASK_SELF: u32 = 28;
    /// `mach_timebase_info(mach_timebase_info_t)`.
    pub const MACH_TIMEBASE_INFO: u32 = 89;
    /// `mach_wait_until(deadline)`.
    pub const MACH_WAIT_UNTIL: u32 = 90;
}

/// Synthetic Mach port name returned by the minimal single-task shim.
///
/// These names are ABI-visible handles, not host Mach rights. They only let
/// dyld identify the shim's one task, one thread, and one host endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachPortName(pub u32);

impl From<MachPortName> for usize {
    fn from(value: MachPortName) -> Self {
        value.0 as Self
    }
}

/// Stable synthetic names. Keep them distinct from `MACH_PORT_NULL` and from
/// descriptors allocated later by a future Mach IPC implementation.
pub mod synthetic_port {
    use super::MachPortName;

    pub const TASK_SELF: MachPortName = MachPortName(0x103);
}

bitflags::bitflags! {
    /// Raw Mach VM flags. XNU combines behavioral bits with a VM allocation tag,
    /// so callers retain unknown bits even though the shim only honors `ANYWHERE`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MachVmFlags: i32 {
        const ANYWHERE = 0x0000_0001;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachVmAddressMask(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachVmProtection {
    permissions: VmProtection,
    copy: bool,
}

impl MachVmProtection {
    const COPY: i32 = 0x10;

    pub const fn new(permissions: VmProtection, copy: bool) -> Self {
        Self { permissions, copy }
    }

    fn from_raw(raw: i32) -> Option<Self> {
        let permissions = VmProtection::from_bits(raw & !Self::COPY)?;
        (raw & !(Self::COPY | VmProtection::all().bits()) == 0).then_some(Self {
            permissions,
            copy: raw & Self::COPY != 0,
        })
    }

    pub const fn permissions(self) -> VmProtection {
        self.permissions
    }

    pub const fn requests_copy(self) -> bool {
        self.copy
    }
}

impl MachVmAddressMask {
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Darwin's `mach_timebase_info_data_t` output structure.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

bitflags::bitflags! {
    /// `access` mode bits (`sys/unistd.h`). Decoded with every bit retained:
    /// `faccessat_internal` ignores the bits it does not know.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AccessFlags: i32 {
        const F_OK = 0;
        const X_OK = 1 << 0;
        const W_OK = 1 << 1;
        const R_OK = 1 << 2;
        const _READ_OK = 1 << 9;
        const _WRITE_OK = 1 << 10;
        const _EXECUTE_OK = 1 << 11;
        const _DELETE_OK = 1 << 12;
        const _APPEND_OK = 1 << 13;
        const _RMFILE_OK = 1 << 14;
        const _RATTR_OK = 1 << 15;
        const _WATTR_OK = 1 << 16;
        const _REXT_OK = 1 << 17;
        const _WEXT_OK = 1 << 18;
        const _RPERM_OK = 1 << 19;
        const _WPERM_OK = 1 << 20;
        const _CHOWN_OK = 1 << 21;
    }
}

impl AccessFlags {
    /// `_ACCESS_EXTENDED_MASK`: the `_READ_OK` .. `_CHOWN_OK` rights.
    pub const EXTENDED_MASK: Self = Self::_READ_OK
        .union(Self::_WRITE_OK)
        .union(Self::_EXECUTE_OK)
        .union(Self::_DELETE_OK)
        .union(Self::_APPEND_OK)
        .union(Self::_RMFILE_OK)
        .union(Self::_REXT_OK)
        .union(Self::_WEXT_OK)
        .union(Self::_RATTR_OK)
        .union(Self::_WATTR_OK)
        .union(Self::_RPERM_OK)
        .union(Self::_WPERM_OK)
        .union(Self::_CHOWN_OK);
}

/// `ioctl` request codes the shim serves (`sys/filio.h`). The request is a
/// `u_long` that XNU compares at full width, so these match only zero-extended.
pub mod ioctl {
    pub const FIOCLEX: usize = 0x2000_6601;
    pub const FIONCLEX: usize = 0x2000_6602;
    pub const FIONREAD: usize = 0x4004_667f;
    pub const FIONBIO: usize = 0x8004_667e;
    pub const FIOASYNC: usize = 0x8004_667d;
}

/// An `ioctl` request. Decoding never fails: `ioctl` checks the request's
/// parameter size and copies its input in before it looks the descriptor up,
/// and unknown requests fail only after both.
#[derive(Clone, Copy, Debug)]
pub enum IoctlArg {
    /// `FIOCLEX`: set close-on-exec.
    SetCloseOnExec,
    /// `FIONCLEX`: clear close-on-exec.
    ClearCloseOnExec,
    /// `FIONREAD`: the bytes left to read.
    ReadableBytes(UserPtrMut<i32>),
    /// `FIONBIO`: non-blocking I/O when the `int` is nonzero.
    SetNonBlocking(UserPtr<i32>),
    /// `FIOASYNC`: `O_ASYNC` when the `int` is nonzero.
    SetAsync(UserPtr<i32>),
    /// Any other request.
    Raw { command: usize, data: usize },
}

impl IoctlArg {
    fn from_args(command: usize, data: usize) -> Self {
        match command {
            ioctl::FIOCLEX => Self::SetCloseOnExec,
            ioctl::FIONCLEX => Self::ClearCloseOnExec,
            ioctl::FIONREAD => Self::ReadableBytes(UserPtrMut::from_usize(data)),
            ioctl::FIONBIO => Self::SetNonBlocking(UserPtr::from_usize(data)),
            ioctl::FIOASYNC => Self::SetAsync(UserPtr::from_usize(data)),
            command => Self::Raw { command, data },
        }
    }
}

/// `fcntl` commands the shim decodes (`sys/fcntl.h`).
pub mod fcntl {
    pub const F_DUPFD: i32 = 0;
    pub const F_GETFD: i32 = 1;
    pub const F_SETFD: i32 = 2;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    pub const F_NOCACHE: i32 = 48;
    pub const F_GETPATH: i32 = 50;
    pub const F_DUPFD_CLOEXEC: i32 = 67;
    pub const F_ADDFILESIGS_RETURN: i32 = 97;
    pub const F_CHECK_LV: i32 = 98;
    pub const F_GETPATH_NOFIRMLINK: i32 = 102;
}

/// An `fcntl` command and its argument. Decoding never fails: `fcntl` looks
/// the descriptor up before it switches on the command.
#[derive(Clone, Copy, Debug)]
pub enum FcntlArg {
    /// `F_DUPFD` and `F_DUPFD_CLOEXEC`: duplicate to the lowest free
    /// descriptor at or above `min_fd`.
    DupFd { cloexec: bool, min_fd: i32 },
    /// `F_GETFD`.
    GetFd,
    /// `F_SETFD`: only `FD_CLOEXEC` counts.
    SetFd(crate::FileDescriptorFlags),
    /// `F_GETFL`.
    GetFl,
    /// `F_SETFL`, with every bit retained; only `FCNTLFLAGS` count.
    SetFl(OpenFlags),
    /// `F_NOCACHE`: turn data caching off (true) or on.
    NoCache(bool),
    /// `F_GETPATH` and `F_GETPATH_NOFIRMLINK`: a `MAXPATHLEN` buffer.
    GetPath(UserPtrMut<u8>),
    /// `F_CHECK_LV`: an `fchecklv_t`.
    CheckLv(UserPtr<u8>),
    /// `F_ADDFILESIGS_RETURN`: an `fsignatures_t`.
    AddFileSigsReturn(UserPtrMut<u8>),
    /// Any other command.
    Raw { command: i32, argument: usize },
}

impl FcntlArg {
    fn from_args(command: i32, argument: usize) -> Self {
        // XNU reads these as `CAST_DOWN_EXPLICIT(int, uap->arg)`.
        let int_argument = TruncateExt::<u32>::trunc(argument);
        match command {
            fcntl::F_DUPFD | fcntl::F_DUPFD_CLOEXEC => Self::DupFd {
                cloexec: command == fcntl::F_DUPFD_CLOEXEC,
                min_fd: int_argument.cast_signed(),
            },
            fcntl::F_GETFD => Self::GetFd,
            fcntl::F_SETFD => {
                Self::SetFd(crate::FileDescriptorFlags::from_bits_truncate(int_argument))
            }
            fcntl::F_GETFL => Self::GetFl,
            fcntl::F_SETFL => Self::SetFl(OpenFlags::from_bits_retain(int_argument.cast_signed())),
            fcntl::F_NOCACHE => Self::NoCache(argument != 0),
            fcntl::F_GETPATH | fcntl::F_GETPATH_NOFIRMLINK => {
                Self::GetPath(UserPtrMut::from_usize(argument))
            }
            fcntl::F_CHECK_LV => Self::CheckLv(UserPtr::from_usize(argument)),
            fcntl::F_ADDFILESIGS_RETURN => {
                Self::AddFileSigsReturn(UserPtrMut::from_usize(argument))
            }
            command => Self::Raw { command, argument },
        }
    }
}

/// `sigprocmask`'s `how` (`sys/signal.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigmaskHow {
    /// `SIG_BLOCK`.
    Block,
    /// `SIG_UNBLOCK`.
    Unblock,
    /// `SIG_SETMASK`.
    SetMask,
    /// Any other value: EINVAL, but only once the new mask is read; XNU
    /// ignores `how` without one.
    Unknown(i32),
}

impl From<i32> for SigmaskHow {
    fn from(how: i32) -> Self {
        match how {
            1 => Self::Block,
            2 => Self::Unblock,
            3 => Self::SetMask,
            how => Self::Unknown(how),
        }
    }
}

/// Darwin `sigset_t`: bit `n - 1` is signal `n`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct SigSet(pub u32);

#[derive(Clone, Copy, Debug)]
pub enum SyscallRequest {
    Exit {
        status: i32,
    },
    Read {
        fd: i32,
        buf: UserPtrMut<u8>,
        count: usize,
    },
    Write {
        fd: i32,
        buf: UserPtr<u8>,
        count: usize,
    },
    Open {
        path: UserPtr<core::ffi::c_char>,
        flags: OpenFlags,
        mode: FileMode,
    },
    Openat {
        dirfd: i32,
        path: UserPtr<core::ffi::c_char>,
        flags: OpenFlags,
        mode: FileMode,
    },
    Ioctl {
        fd: i32,
        arg: IoctlArg,
    },
    Close {
        fd: i32,
    },
    Dup {
        fd: i32,
    },
    Dup2 {
        old: i32,
        new: i32,
    },
    Fcntl {
        fd: i32,
        arg: FcntlArg,
    },
    Sysctl {
        name: UserPtr<i32>,
        name_length: u32,
        old_value: UserPtrMut<u8>,
        old_length: UserPtrMut<usize>,
        new_value: UserPtr<u8>,
        new_length: usize,
    },
    Fsctl {
        path: UserPtr<core::ffi::c_char>,
        command: u32,
        data: usize,
        options: u32,
    },
    Mmap {
        address: usize,
        length: usize,
        protection: VmProtection,
        flags: MmapFlags,
        fd: i32,
        offset: i64,
    },
    Munmap {
        address: usize,
        length: usize,
    },
    Mprotect {
        address: usize,
        length: usize,
        protection: VmProtection,
    },
    Access {
        path: UserPtr<core::ffi::c_char>,
        mode: AccessFlags,
    },
    CrossarchTrap {
        name: u32,
    },
    Sigprocmask {
        how: SigmaskHow,
        mask: Option<UserPtr<SigSet>>,
        old_mask: Option<UserPtrMut<SigSet>>,
    },
    Csops {
        pid: i32,
        operation: u32,
        buffer: UserPtrMut<u8>,
        size: usize,
        audit_token: Option<UserPtr<[u32; 8]>>,
    },
    Issetugid,
    Stat64 {
        path: UserPtr<core::ffi::c_char>,
        buffer: UserPtrMut<crate::Stat64>,
        follow: bool,
    },
    Fstat64 {
        fd: i32,
        buffer: UserPtrMut<crate::Stat64>,
    },
    MacSyscall {
        policy: UserPtr<core::ffi::c_char>,
        call: i32,
        argument: usize,
    },
    Csrctl {
        operation: u32,
        buffer: UserPtrMut<u32>,
        size: usize,
    },
    AbortWithPayload {
        reason_namespace: u32,
        reason_code: u64,
        reason_string: UserPtr<core::ffi::c_char>,
    },
    TerminateWithPayload {
        pid: i32,
        reason_namespace: u32,
        reason_code: u64,
        reason_string: UserPtr<core::ffi::c_char>,
    },
    MapWithLinkingNp,
    Getpid,
    Getppid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    ThreadSelfid,
    Getentropy {
        buffer: UserPtrMut<u8>,
        count: usize,
    },
    MachVmAllocate {
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        flags: MachVmFlags,
    },
    MachVmDeallocate {
        target: MachPortName,
        address: usize,
        size: usize,
    },
    MachVmProtect {
        target: MachPortName,
        address: usize,
        size: usize,
        set_maximum: bool,
        protection: MachVmProtection,
    },
    MachVmMap {
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        mask: MachVmAddressMask,
        flags: MachVmFlags,
        current_protection: MachVmProtection,
    },
    MachTaskSelf,
    SharedRegionCheckNp {
        start_address: UserPtrMut<usize>,
    },
    MachAbsoluteTime,
    MachTimebaseInfo {
        info: UserPtrMut<MachTimebaseInfo>,
    },
    MachWaitUntil {
        deadline: u64,
    },
}

impl SyscallRequest {
    /// Convert raw register arguments into a typed BSD syscall request.
    pub fn from_args(number: usize, args: [usize; 8]) -> Result<Self, Errno> {
        let int_arg = |i: usize| -> i32 { args[i].reinterpret_as_signed().trunc() };
        let u64_arg = |i: usize| -> u64 { args[i] as u64 };
        let port_arg = |i: usize| MachPortName(TruncateExt::<u32>::trunc(args[i]));
        if is_platform_syscall_selector(number) {
            // Not a BSD or Mach request; see `PlatformSyscall`.
            return Err(Errno::ENOSYS);
        }
        if is_mach_trap_selector(number) {
            let selector: i32 = number.reinterpret_as_signed().trunc();
            let trap = selector.wrapping_neg().reinterpret_as_unsigned();
            return match trap {
                mach_trap::MACH_ABSOLUTE_TIME => Ok(Self::MachAbsoluteTime),
                mach_trap::MACH_VM_ALLOCATE => Ok(Self::MachVmAllocate {
                    target: port_arg(0),
                    address: UserPtrMut::from_usize(args[1]),
                    size: args[2],
                    flags: MachVmFlags::from_bits_retain(int_arg(3)),
                }),
                mach_trap::MACH_VM_DEALLOCATE => Ok(Self::MachVmDeallocate {
                    target: port_arg(0),
                    address: args[1],
                    size: args[2],
                }),
                mach_trap::MACH_VM_PROTECT => Ok(Self::MachVmProtect {
                    target: port_arg(0),
                    address: args[1],
                    size: args[2],
                    set_maximum: args[3] != 0,
                    protection: MachVmProtection::from_raw(int_arg(4)).ok_or(Errno::EINVAL)?,
                }),
                mach_trap::MACH_VM_MAP => Ok(Self::MachVmMap {
                    target: port_arg(0),
                    address: UserPtrMut::from_usize(args[1]),
                    size: args[2],
                    mask: MachVmAddressMask(args[3]),
                    flags: MachVmFlags::from_bits_retain(int_arg(4)),
                    current_protection: MachVmProtection::from_raw(int_arg(5))
                        .ok_or(Errno::EINVAL)?,
                }),
                mach_trap::TASK_SELF => Ok(Self::MachTaskSelf),
                mach_trap::MACH_TIMEBASE_INFO => Ok(Self::MachTimebaseInfo {
                    info: UserPtrMut::from_usize(args[0]),
                }),
                mach_trap::MACH_WAIT_UNTIL => Ok(Self::MachWaitUntil {
                    deadline: u64_arg(0),
                }),
                _ => Err(Errno::ENOSYS),
            };
        }
        Ok(match number {
            nr::EXIT => Self::Exit { status: int_arg(0) },
            nr::READ | nr::READ_NOCANCEL => Self::Read {
                fd: int_arg(0),
                buf: UserPtrMut::from_usize(args[1]),
                count: args[2],
            },
            nr::WRITE | nr::WRITE_NOCANCEL => Self::Write {
                fd: int_arg(0),
                buf: UserPtr::from_usize(args[1]),
                count: args[2],
            },
            nr::OPEN | nr::OPEN_NOCANCEL => Self::Open {
                path: UserPtr::from_usize(args[0]),
                flags: OpenFlags::from_bits_retain(int_arg(1)),
                mode: FileMode::from_u32_bits_truncate(int_arg(2).reinterpret_as_unsigned()),
            },
            nr::OPENAT | nr::OPENAT_NOCANCEL => Self::Openat {
                dirfd: int_arg(0),
                path: UserPtr::from_usize(args[1]),
                flags: OpenFlags::from_bits_retain(int_arg(2)),
                mode: FileMode::from_u32_bits_truncate(int_arg(3).reinterpret_as_unsigned()),
            },
            nr::IOCTL => Self::Ioctl {
                fd: int_arg(0),
                arg: IoctlArg::from_args(args[1], args[2]),
            },
            nr::CLOSE | nr::CLOSE_NOCANCEL => Self::Close { fd: int_arg(0) },
            nr::DUP => Self::Dup { fd: int_arg(0) },
            nr::DUP2 => Self::Dup2 {
                old: int_arg(0),
                new: int_arg(1),
            },
            nr::FCNTL | nr::FCNTL_NOCANCEL => Self::Fcntl {
                fd: int_arg(0),
                arg: FcntlArg::from_args(int_arg(1), args[2]),
            },
            nr::SYSCTL => Self::Sysctl {
                name: UserPtr::from_usize(args[0]),
                name_length: TruncateExt::<u32>::trunc(args[1]),
                old_value: UserPtrMut::from_usize(args[2]),
                old_length: UserPtrMut::from_usize(args[3]),
                new_value: UserPtr::from_usize(args[4]),
                new_length: args[5],
            },
            nr::FSCTL => Self::Fsctl {
                path: UserPtr::from_usize(args[0]),
                command: TruncateExt::<u32>::trunc(args[1]),
                data: args[2],
                options: TruncateExt::<u32>::trunc(args[3]),
            },
            nr::MMAP => Self::Mmap {
                address: args[0],
                length: args[1],
                protection: VmProtection::from_bits(int_arg(2)).ok_or(Errno::EINVAL)?,
                flags: MmapFlags::from_bits(int_arg(3) & !crate::MAP_UNIX03)
                    .ok_or(Errno::EINVAL)?,
                fd: int_arg(4),
                offset: args[5].reinterpret_as_signed() as i64,
            },
            nr::MUNMAP => Self::Munmap {
                address: args[0],
                length: args[1],
            },
            nr::MPROTECT => Self::Mprotect {
                address: args[0],
                length: args[1],
                protection: VmProtection::from_bits(int_arg(2)).ok_or(Errno::EINVAL)?,
            },
            nr::GETPID => Self::Getpid,
            nr::ACCESS => Self::Access {
                path: UserPtr::from_usize(args[0]),
                mode: AccessFlags::from_bits_retain(int_arg(1)),
            },
            nr::CROSSARCH_TRAP => Self::CrossarchTrap {
                name: TruncateExt::<u32>::trunc(args[0]),
            },
            nr::SIGPROCMASK => Self::Sigprocmask {
                how: SigmaskHow::from(int_arg(0)),
                mask: (args[1] != 0).then(|| UserPtr::from_usize(args[1])),
                old_mask: (args[2] != 0).then(|| UserPtrMut::from_usize(args[2])),
            },
            nr::CSOPS_AUDITTOKEN if args[4] == 0 => return Err(Errno::EINVAL),
            nr::CSOPS | nr::CSOPS_AUDITTOKEN => Self::Csops {
                pid: int_arg(0),
                operation: TruncateExt::<u32>::trunc(args[1]),
                buffer: UserPtrMut::from_usize(args[2]),
                size: args[3],
                audit_token: (number == nr::CSOPS_AUDITTOKEN).then(|| UserPtr::from_usize(args[4])),
            },
            nr::ISSETUGID => Self::Issetugid,
            nr::STAT64 | nr::LSTAT64 => Self::Stat64 {
                path: UserPtr::from_usize(args[0]),
                buffer: UserPtrMut::from_usize(args[1]),
                follow: number == nr::STAT64,
            },
            nr::FSTAT64 => Self::Fstat64 {
                fd: int_arg(0),
                buffer: UserPtrMut::from_usize(args[1]),
            },
            nr::MAC_SYSCALL => Self::MacSyscall {
                policy: UserPtr::from_usize(args[0]),
                call: int_arg(1),
                argument: args[2],
            },
            nr::CSRCTL => Self::Csrctl {
                operation: TruncateExt::<u32>::trunc(args[0]),
                buffer: UserPtrMut::from_usize(args[1]),
                size: args[2],
            },
            nr::ABORT_WITH_PAYLOAD => Self::AbortWithPayload {
                reason_namespace: TruncateExt::<u32>::trunc(args[0]),
                reason_code: u64_arg(1),
                reason_string: UserPtr::from_usize(args[4]),
            },
            nr::TERMINATE_WITH_PAYLOAD => Self::TerminateWithPayload {
                pid: int_arg(0),
                reason_namespace: TruncateExt::<u32>::trunc(args[1]),
                reason_code: u64_arg(2),
                reason_string: UserPtr::from_usize(args[5]),
            },
            nr::MAP_WITH_LINKING_NP => Self::MapWithLinkingNp,
            nr::GETENTROPY => Self::Getentropy {
                buffer: UserPtrMut::from_usize(args[0]),
                count: args[1],
            },
            nr::GETPPID => Self::Getppid,
            nr::GETUID => Self::Getuid,
            nr::GETEUID => Self::Geteuid,
            nr::GETGID => Self::Getgid,
            nr::GETEGID => Self::Getegid,
            nr::THREAD_SELFID => Self::ThreadSelfid,
            nr::SHARED_REGION_CHECK_NP => Self::SharedRegionCheckNp {
                start_address: UserPtrMut::from_usize(args[0]),
            },
            _ => return Err(Errno::ENOSYS),
        })
    }

    /// Decode arguments from the saved x0–x7 registers. The caller supplies
    /// the syscall number from x16. Only selectors the decoder does not know
    /// (ENOSYS) are reported through `log_unsupported`; malformed arguments of
    /// known calls are ordinary errors.
    #[cfg(target_arch = "aarch64")]
    pub fn try_from_raw(
        number: usize,
        ctx: &PtRegs,
        log_unsupported: impl Fn(core::fmt::Arguments<'_>),
    ) -> Result<Self, Errno> {
        Self::from_args(number, core::array::from_fn(|i| ctx.regs[i])).inspect_err(|error| {
            if *error == Errno::ENOSYS {
                log_unsupported(format_args!("unsupported Darwin syscall {number:#x}"));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_arguments_and_aliases() {
        for number in [nr::READ, nr::READ_NOCANCEL] {
            let request =
                SyscallRequest::from_args(number, [usize::MAX, 0x1234, 99, 0, 0, 0, 0, 0]).unwrap();
            let SyscallRequest::Read { fd, buf, count } = request else {
                panic!()
            };
            let _: UserPtrMut<u8> = buf;
            assert_eq!((fd, buf.as_usize(), count), (-1, 0x1234, 99));
        }
        let SyscallRequest::Exit { status } =
            SyscallRequest::from_args(nr::EXIT, [0xffff_ffff, 0, 0, 0, 0, 0, 0, 0]).unwrap()
        else {
            panic!()
        };
        assert_eq!(status, -1);
        for number in [0, 0x0200_0004] {
            assert!(matches!(
                SyscallRequest::from_args(number, [0; 8]),
                Err(Errno::ENOSYS)
            ));
        }
        // Native stubs write a negative selector through w16, zero-extending it in x16.
        assert!(matches!(
            SyscallRequest::from_args(u32::MAX as usize - 2, [0; 8]),
            Ok(SyscallRequest::MachAbsoluteTime)
        ));
        for number in [
            0u32.wrapping_sub(47) as usize,
            (-47isize).reinterpret_as_unsigned(),
        ] {
            assert_eq!(
                SyscallRequest::from_args(number, [0; 8]).unwrap_err(),
                Errno::ENOSYS
            );
        }
        let request = SyscallRequest::from_args(
            nr::MMAP,
            [0x4000, 0x8000, 5, 0x40012, usize::MAX, 0x1234, 0, 0],
        )
        .unwrap();
        assert!(matches!(
            request,
            SyscallRequest::Mmap {
                address: 0x4000,
                length: 0x8000,
                protection,
                flags,
                fd: -1,
                offset: 0x1234,
            } if protection == (VmProtection::READ | VmProtection::EXECUTE)
                && flags == (MmapFlags::PRIVATE | MmapFlags::FIXED)
        ));
        for (protection, flags) in [(8, 2), (1, 4)] {
            assert_eq!(
                SyscallRequest::from_args(
                    nr::MMAP,
                    [0, 0x4000, protection, flags, usize::MAX, 0, 0, 0],
                )
                .unwrap_err(),
                Errno::EINVAL
            );
        }
    }

    #[test]
    fn platform_syscall_precedes_mach_trap_classification() {
        for number in [0x8000_0000usize, 0xffff_ffff_8000_0000] {
            assert!(is_platform_syscall_selector(number));
            assert!(!is_mach_trap_selector(number));
            assert_eq!(
                SyscallRequest::from_args(number, [0; 8]).unwrap_err(),
                Errno::ENOSYS
            );
        }
        for number in [0x7fff_ffffusize, 0x8000_0001, 0, nr::EXIT] {
            assert!(!is_platform_syscall_selector(number));
        }
        assert!(is_mach_trap_selector(0x8000_0001));
        assert!(is_mach_trap_selector(u32::MAX as usize));
    }

    #[test]
    fn mach_vm_protection_preserves_copy_semantics() {
        let mach_protect = SyscallRequest::from_args(
            0u32.wrapping_sub(mach_trap::MACH_VM_PROTECT) as usize,
            [0x103, 0x2001, 1, 0, 0x13, 0, 0, 0],
        )
        .unwrap();
        assert!(matches!(
            mach_protect,
            SyscallRequest::MachVmProtect { protection, .. }
                if protection.permissions() == (VmProtection::READ | VmProtection::WRITE)
                    && protection.requests_copy()
        ));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn darwin_argument_registers() {
        let mut ctx = PtRegs::default();
        ctx.regs[0] = 7;
        ctx.orig_x0 = 99;
        ctx.regs[16] = nr::EXIT;
        assert!(matches!(
            SyscallRequest::try_from_raw(ctx.regs[16], &ctx, |_| {}),
            Ok(SyscallRequest::Exit { status: 7 })
        ));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn unknown_selectors_fail_with_enosys_and_are_logged() {
        let logged = core::cell::Cell::new(0);
        let log = |_: core::fmt::Arguments<'_>| logged.set(logged.get() + 1);
        let mut ctx = PtRegs::default();
        // A known call with a malformed argument (mmap protection 8) is EINVAL and not logged.
        ctx.regs[16] = nr::MMAP;
        ctx.regs[2] = 8;
        ctx.regs[3] = 2;
        assert_eq!(
            SyscallRequest::try_from_raw(ctx.regs[16], &ctx, log).unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(logged.get(), 0);
        ctx.regs[16] = 999;
        assert_eq!(
            SyscallRequest::try_from_raw(ctx.regs[16], &ctx, log).unwrap_err(),
            Errno::ENOSYS
        );
        assert_eq!(logged.get(), 1);
    }

    #[test]
    fn access_ioctl_fcntl_and_sigprocmask_arguments() {
        // faccessat_internal ignores unknown bits: they are retained, not rejected.
        assert!(matches!(
            SyscallRequest::from_args(nr::ACCESS, [0x1000, 0x4000_0204, 0, 0, 0, 0, 0, 0]),
            Ok(SyscallRequest::Access { mode, .. })
                if mode.bits() == 0x4000_0204
                    && mode.contains(AccessFlags::R_OK | AccessFlags::_READ_OK)
        ));
        let ioctl = |command: usize| {
            let Ok(SyscallRequest::Ioctl { fd: 3, arg }) =
                SyscallRequest::from_args(nr::IOCTL, [3, command, 0x2000, 0, 0, 0, 0, 0])
            else {
                panic!()
            };
            arg
        };
        assert!(matches!(ioctl(0x2000_6601), IoctlArg::SetCloseOnExec));
        assert!(matches!(ioctl(0x2000_6602), IoctlArg::ClearCloseOnExec));
        assert!(matches!(ioctl(0x4004_667f), IoctlArg::ReadableBytes(p) if p.as_usize() == 0x2000));
        assert!(
            matches!(ioctl(0x8004_667e), IoctlArg::SetNonBlocking(p) if p.as_usize() == 0x2000)
        );
        assert!(matches!(ioctl(0x8004_667d), IoctlArg::SetAsync(p) if p.as_usize() == 0x2000));
        // `u_long` requests compare at full width: a sign-extended FIONBIO is
        // not FIONBIO, and unknown requests (TIOCGWINSZ) keep every bit.
        assert!(matches!(
            ioctl(0xffff_ffff_8004_667e),
            IoctlArg::Raw {
                command: 0xffff_ffff_8004_667e,
                data: 0x2000
            }
        ));
        assert!(matches!(
            ioctl(0xffff_ffff_4008_7468),
            IoctlArg::Raw {
                command: 0xffff_ffff_4008_7468,
                data: 0x2000
            }
        ));
        let fcntl = |command: usize, argument: usize| {
            let Ok(SyscallRequest::Fcntl { fd: 3, arg }) =
                SyscallRequest::from_args(nr::FCNTL, [3, command, argument, 0, 0, 0, 0, 0])
            else {
                panic!()
            };
            arg
        };
        assert!(matches!(
            fcntl(67, 0x1_0000_0005),
            FcntlArg::DupFd {
                cloexec: true,
                min_fd: 5
            }
        ));
        assert!(matches!(
            fcntl(0, 7),
            FcntlArg::DupFd {
                cloexec: false,
                min_fd: 7
            }
        ));
        assert!(matches!(fcntl(1, 0), FcntlArg::GetFd));
        assert!(matches!(
            fcntl(2, 3),
            FcntlArg::SetFd(flags) if flags == crate::FileDescriptorFlags::FD_CLOEXEC
        ));
        assert!(matches!(fcntl(3, 0), FcntlArg::GetFl));
        assert!(matches!(
            fcntl(4, 0x8000_0044),
            FcntlArg::SetFl(flags) if flags.bits() == 0x8000_0044_u32.cast_signed()
        ));
        // F_NOCACHE tests the whole argument.
        assert!(matches!(fcntl(48, 1 << 32), FcntlArg::NoCache(true)));
        for command in [50, 102] {
            assert!(
                matches!(fcntl(command, 0x3000), FcntlArg::GetPath(p) if p.as_usize() == 0x3000)
            );
        }
        assert!(matches!(fcntl(98, 0x3000), FcntlArg::CheckLv(p) if p.as_usize() == 0x3000));
        assert!(
            matches!(fcntl(97, 0x3000), FcntlArg::AddFileSigsReturn(p) if p.as_usize() == 0x3000)
        );
        assert!(matches!(
            fcntl(usize::MAX, 9),
            FcntlArg::Raw {
                command: -1,
                argument: 9
            }
        ));
        for (how, expected) in [
            (1, SigmaskHow::Block),
            (2, SigmaskHow::Unblock),
            (3, SigmaskHow::SetMask),
            (0, SigmaskHow::Unknown(0)),
            (0xffff_ffff, SigmaskHow::Unknown(-1)),
        ] {
            assert!(matches!(
                SyscallRequest::from_args(nr::SIGPROCMASK, [how, 0x1000, 0, 0, 0, 0, 0, 0]),
                Ok(SyscallRequest::Sigprocmask { how, mask: Some(mask), old_mask: None })
                    if how == expected && mask.as_usize() == 0x1000
            ));
        }
    }

    #[test]
    fn csops_audittoken_requires_a_token() {
        // kern_proc.c csops_audittoken: a NULL token is EINVAL, not a plain csops.
        assert_eq!(
            SyscallRequest::from_args(nr::CSOPS_AUDITTOKEN, [0, 0, 0x1000, 4, 0, 0, 0, 0])
                .unwrap_err(),
            Errno::EINVAL
        );
        assert!(matches!(
            SyscallRequest::from_args(nr::CSOPS_AUDITTOKEN, [0, 0, 0x1000, 4, 0x2000, 0, 0, 0]),
            Ok(SyscallRequest::Csops { audit_token: Some(token), .. }) if token.as_usize() == 0x2000
        ));
        assert!(matches!(
            SyscallRequest::from_args(nr::CSOPS, [0, 0, 0x1000, 4, 0x2000, 0, 0, 0]),
            Ok(SyscallRequest::Csops {
                audit_token: None,
                ..
            })
        ));
    }
}
