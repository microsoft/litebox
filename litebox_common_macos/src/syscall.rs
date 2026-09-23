// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall decoding.

use core::mem::size_of;
use litebox::utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_broker_protocol::fs::FileMode;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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
    pub const CROSSARCH_TRAP: usize = 38;
    pub const GETPPID: usize = 39;
    pub const DUP: usize = 41;
    pub const GETEGID: usize = 43;
    pub const GETGID: usize = 47;
    pub const SIGPROCMASK: usize = 48;
    pub const MUNMAP: usize = 73;
    pub const MPROTECT: usize = 74;
    pub const DUP2: usize = 90;
    pub const FCNTL: usize = 92;
    pub const CSOPS: usize = 169;
    pub const MMAP: usize = 197;
    pub const SYSCTL: usize = 202;
    pub const FSCTL: usize = 242;
    pub const SHARED_REGION_CHECK_NP: usize = 294;
    pub const STAT64: usize = 338;
    pub const FSTAT64: usize = 339;
    pub const STATFS64: usize = 345;
    pub const BSDTHREAD_CREATE: usize = 360;
    pub const THREAD_SELFID: usize = 372;
    pub const MAC_SYSCALL: usize = 381;
    pub const READ_NOCANCEL: usize = 396;
    pub const WRITE_NOCANCEL: usize = 397;
    pub const OPEN_NOCANCEL: usize = 398;
    pub const CLOSE_NOCANCEL: usize = 399;
    pub const CSRCTL: usize = 483;
    pub const GETENTROPY: usize = 500;
    pub const ABORT_WITH_PAYLOAD: usize = 521;
    pub const SHARED_REGION_MAP_AND_SLIDE_2_NP: usize = 536;
}

/// Whether the low 32 bits of an AArch64 syscall selector encode a Mach trap.
/// XNU interprets the selector as signed `int`, regardless of x16's upper bits.
pub fn is_mach_trap_selector(number: usize) -> bool {
    let selector: i32 = number.reinterpret_as_signed().trunc();
    selector < 0
}

/// Mach trap numbers. AArch64 Darwin passes their negation in w16.
pub mod mach_trap {
    /// `mach_absolute_time()`.
    pub const MACH_ABSOLUTE_TIME: u32 = 3;
    pub const MACH_VM_ALLOCATE: u32 = 10;
    pub const MACH_VM_DEALLOCATE: u32 = 12;
    pub const MACH_VM_PROTECT: u32 = 14;
    pub const MACH_VM_MAP: u32 = 15;
    pub const MACH_REPLY_PORT: u32 = 26;
    pub const THREAD_SELF: u32 = 27;
    pub const TASK_SELF: u32 = 28;
    pub const HOST_SELF: u32 = 29;
    pub const MACH_MSG2: u32 = 47;
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

    pub const HOST_SELF: MachPortName = MachPortName(0x102);
    pub const TASK_SELF: MachPortName = MachPortName(0x103);
    pub const THREAD_SELF: MachPortName = MachPortName(0x104);
    pub const REPLY: MachPortName = MachPortName(0x105);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalMaskOperation {
    Block,
    Unblock,
    SetMask,
}

impl TryFrom<i32> for SignalMaskOperation {
    type Error = Errno;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Block),
            2 => Ok(Self::Unblock),
            3 => Ok(Self::SetMask),
            _ => Err(Errno::EINVAL),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FcntlCommand {
    /// Darwin `F_GETPATH`; writes a NUL-terminated path to the argument buffer.
    GetPath,
    Unsupported(i32),
}

impl From<i32> for FcntlCommand {
    fn from(value: i32) -> Self {
        if value == 50 {
            Self::GetPath
        } else {
            Self::Unsupported(value)
        }
    }
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

bitflags::bitflags! {
    /// Options used by `mach_msg2_trap`. Only receive-only probes are currently
    /// accepted; Mach message sending is not emulated.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MachMessageOptions: u64 {
        const SEND = 0x0000_0001;
        const RECEIVE = 0x0000_0002;
        const RECEIVE_LARGE = 0x0000_0004;
        const SEND_TIMEOUT = 0x0000_0010;
        const RECEIVE_TIMEOUT = 0x0000_0100;
    }
}

/// Darwin's `mach_timebase_info_data_t` output structure.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct DarwinTimespec {
    pub seconds: i64,
    pub nanoseconds: i64,
}

/// Darwin arm64 `struct stat` layout used by the `*stat64` compatibility calls.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct DarwinStat64 {
    pub device: i32,
    pub mode: u16,
    pub link_count: u16,
    pub inode: u64,
    pub user_id: u32,
    pub group_id: u32,
    pub raw_device: i32,
    pub padding: i32,
    pub access_time: DarwinTimespec,
    pub modification_time: DarwinTimespec,
    pub change_time: DarwinTimespec,
    pub birth_time: DarwinTimespec,
    pub size: i64,
    pub blocks: i64,
    pub block_size: i32,
    pub flags: u32,
    pub generation: u32,
    pub spare: i32,
    pub qspare: [i64; 2],
}

const _: () = assert!(size_of::<DarwinStat64>() == 144);

/// Darwin arm64 `struct statfs` layout. The shim reports one synthetic APFS
/// mount because its filesystem is broker-backed rather than a host mount.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct DarwinStatFs64 {
    pub block_size: u32,
    pub io_size: i32,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub filesystem_id: [i32; 2],
    pub owner: u32,
    pub filesystem_type: u32,
    pub flags: u32,
    pub subtype: u32,
    pub type_name: [u8; 16],
    pub mount_point: [u8; 1024],
    pub mounted_from: [u8; 1024],
    pub extended_flags: u32,
    pub reserved: [u32; 7],
}

impl Default for DarwinStatFs64 {
    fn default() -> Self {
        Self {
            block_size: 16 * 1024,
            io_size: 16 * 1024,
            blocks: 0,
            blocks_free: 0,
            blocks_available: 0,
            files: 0,
            files_free: 0,
            filesystem_id: [0; 2],
            owner: 0,
            filesystem_type: 0,
            flags: 0,
            subtype: 0,
            type_name: [0; 16],
            mount_point: [0; 1024],
            mounted_from: [0; 1024],
            extended_flags: 0,
            reserved: [0; 7],
        }
    }
}

const _: () = assert!(size_of::<DarwinStatFs64>() == 0x878);

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
    Close {
        fd: i32,
    },
    Getpid,
    Getuid,
    Geteuid,
    CrossarchTrap {
        name: u32,
    },
    Getppid,
    Dup {
        fd: i32,
    },
    Getegid,
    Getgid,
    Sigprocmask {
        how: i32,
        set: UserPtr<u32>,
        oldset: UserPtrMut<u32>,
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
    Dup2 {
        oldfd: i32,
        newfd: i32,
    },
    Fcntl {
        fd: i32,
        command: FcntlCommand,
        argument: UserPtrMut<u8>,
    },
    Csops {
        pid: i32,
        operation: u32,
        user_address: UserPtrMut<u8>,
        user_size: usize,
    },
    Mmap {
        address: usize,
        length: usize,
        protection: VmProtection,
        flags: MmapFlags,
        fd: i32,
        offset: i64,
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
        command: usize,
        data: UserPtrMut<u8>,
        options: u32,
    },
    SharedRegionCheckNp {
        start_address: UserPtrMut<usize>,
    },
    Stat64 {
        path: UserPtr<core::ffi::c_char>,
        buffer: UserPtrMut<DarwinStat64>,
    },
    Fstat64 {
        fd: i32,
        buffer: UserPtrMut<DarwinStat64>,
    },
    Statfs64 {
        path: UserPtr<core::ffi::c_char>,
        buffer: UserPtrMut<DarwinStatFs64>,
    },
    BsdthreadCreate {
        function: usize,
        function_argument: usize,
        stack: usize,
        pthread: usize,
        flags: u32,
    },
    ThreadSelfid,
    MacSyscall {
        policy: UserPtr<core::ffi::c_char>,
        operation: i32,
        argument: UserPtrMut<u8>,
    },
    Csrctl {
        operation: u32,
        user_address: UserPtrMut<u8>,
        user_size: usize,
    },
    Getentropy {
        buffer: UserPtrMut<u8>,
        count: usize,
    },
    AbortWithPayload {
        namespace: u32,
        code: u64,
        payload: UserPtr<u8>,
        payload_size: u32,
        reason: UserPtr<core::ffi::c_char>,
        reason_flags: u64,
    },
    SharedRegionMapAndSlide2Np {
        files_count: u32,
        files: UserPtr<u8>,
        mappings_count: u32,
        mappings: UserPtr<u8>,
    },

    MachAbsoluteTime,
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
    MachReplyPort,
    MachThreadSelf,
    MachTaskSelf,
    MachHostSelf,
    MachMsg2Trap {
        data: usize,
        options: MachMessageOptions,
        msgh_bits_and_send_size: u64,
        msgh_remote_and_local_port: u64,
        msgh_voucher_and_id: u64,
        descriptor_count_and_receive_name: u64,
        receive_size_and_priority: u64,
        timeout: u64,
    },
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
            nr::CLOSE | nr::CLOSE_NOCANCEL => Self::Close { fd: int_arg(0) },
            nr::DUP => Self::Dup { fd: int_arg(0) },
            nr::SYSCTL => Self::Sysctl {
                name: UserPtr::from_usize(args[0]),
                name_length: TruncateExt::<u32>::trunc(args[1]),
                old_value: UserPtrMut::from_usize(args[2]),
                old_length: UserPtrMut::from_usize(args[3]),
                new_value: UserPtr::from_usize(args[4]),
                new_length: args[5],
            },
            nr::MMAP => Self::Mmap {
                address: args[0],
                length: args[1],
                protection: VmProtection::from_bits(int_arg(2)).ok_or(Errno::EINVAL)?,
                flags: MmapFlags::from_bits(int_arg(3)).ok_or(Errno::EINVAL)?,
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
    /// the syscall number from x16.
    #[cfg(target_arch = "aarch64")]
    pub fn try_from_raw(
        number: usize,
        ctx: &crate::PtRegs,
        log_unsupported: impl Fn(core::fmt::Arguments<'_>),
    ) -> Result<Self, Errno> {
        Self::from_args(number, core::array::from_fn(|i| ctx.regs[i])).inspect_err(|_| {
            log_unsupported(format_args!("unsupported Darwin syscall {number:#x}"));
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
            0u32.wrapping_sub(mach_trap::MACH_MSG2) as usize,
            (-47isize).reinterpret_as_unsigned(),
        ] {
            assert_eq!(
                SyscallRequest::from_args(number, [0; 8]).unwrap_err(),
                Errno::ENOSYS
            );
        }
        let request = SyscallRequest::from_args(
            nr::MMAP,
            [0x4000, 0x8000, 5, 0x12, usize::MAX, 0x1234, 0, 0],
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
        let mut ctx = crate::PtRegs::default();
        ctx.regs[0] = 7;
        ctx.orig_x0 = 99;
        ctx.regs[16] = nr::EXIT;
        assert!(matches!(
            SyscallRequest::try_from_raw(ctx.regs[16], &ctx, |_| {}),
            Ok(SyscallRequest::Exit { status: 7 })
        ));
    }
}
