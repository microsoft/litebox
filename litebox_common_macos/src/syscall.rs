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
    pub const PTHREAD_KILL: usize = 328;
    pub const PTHREAD_SIGMASK: usize = 329;
    pub const DISABLE_THREADSIGNAL: usize = 331;
    pub const BSDTHREAD_CREATE: usize = 360;
    pub const BSDTHREAD_TERMINATE: usize = 361;
    pub const BSDTHREAD_REGISTER: usize = 366;
    pub const BSDTHREAD_CTL: usize = 478;
    pub const ULOCK_WAIT: usize = 515;
    pub const ULOCK_WAKE: usize = 516;
    pub const ULOCK_WAIT2: usize = 544;
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
    pub const SHARED_REGION_MAP_AND_SLIDE_2_NP: usize = 536;
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
    pub const MACH_PORT_ALLOCATE: u32 = 16;
    pub const MACH_PORT_DEALLOCATE: u32 = 18;
    pub const MACH_PORT_MOD_REFS: u32 = 19;
    pub const MACH_PORT_INSERT_RIGHT: u32 = 21;
    pub const MACH_PORT_CONSTRUCT: u32 = 24;
    pub const MACH_PORT_DESTRUCT: u32 = 25;
    pub const MACH_REPLY_PORT: u32 = 26;
    pub const THREAD_SELF: u32 = 27;
    pub const TASK_SELF: u32 = 28;
    pub const HOST_SELF: u32 = 29;
    pub const SEMAPHORE_SIGNAL: u32 = 33;
    pub const SEMAPHORE_WAIT: u32 = 36;
    pub const MACH_MSG2: u32 = 47;
    pub const SWTCH_PRI: u32 = 59;
    pub const SWTCH: u32 = 60;
    pub const THREAD_SWITCH: u32 = 61;
    /// `mach_timebase_info(mach_timebase_info_t)`.
    pub const MACH_TIMEBASE_INFO: u32 = 89;
    /// `mach_wait_until(deadline)`.
    pub const MACH_WAIT_UNTIL: u32 = 90;
}

/// A Mach port name in the guest task's IPC space (`mach_port_name_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MachPortName(pub u32);

impl MachPortName {
    pub const NULL: Self = Self(0);
}

impl From<MachPortName> for usize {
    fn from(value: MachPortName) -> Self {
        value.0 as Self
    }
}

bitflags::bitflags! {
    /// Raw Mach VM flags (`VM_FLAGS_*`). XNU combines behavioral bits with a
    /// VM allocation tag in the top byte.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MachVmFlags: i32 {
        const ANYWHERE = 0x0000_0001;
        const PURGABLE = 0x0000_0002;
        const CHUNK_4GB = 0x0000_0004;
        const RANDOM_ADDR = 0x0000_0008;
        const NO_CACHE = 0x0000_0010;
        const RESILIENT_CODESIGN = 0x0000_0020;
        const RESILIENT_MEDIA = 0x0000_0040;
        const PERMANENT = 0x0000_0080;
        const TPRO = 0x0000_1000;
        const MTE = 0x0000_2000;
        const OVERWRITE = 0x0000_4000;
        const SUPERPAGE_MASK = 0x0007_0000;
        const RETURN_DATA_ADDR = 0x0010_0000;
        const GUARD_OBJECT_OPTOUT = 0x0040_0000;
        const RETURN_4K_DATA_ADDR = 0x0080_0000;
        const ALIAS_MASK = 0xff00_0000_u32.cast_signed();
    }
}

impl MachVmFlags {
    /// `VM_FLAGS_USER_ALLOCATE`: what `mach_vm_allocate` accepts.
    pub const USER_ALLOCATE: Self = Self::ANYWHERE
        .union(Self::PURGABLE)
        .union(Self::CHUNK_4GB)
        .union(Self::RANDOM_ADDR)
        .union(Self::NO_CACHE)
        .union(Self::PERMANENT)
        .union(Self::OVERWRITE)
        .union(Self::GUARD_OBJECT_OPTOUT)
        .union(Self::SUPERPAGE_MASK)
        .union(Self::TPRO)
        .union(Self::MTE)
        .union(Self::ALIAS_MASK);
    /// `VM_FLAGS_USER_MAP`: what `mach_vm_map` accepts.
    pub const USER_MAP: Self = Self::USER_ALLOCATE
        .union(Self::RETURN_4K_DATA_ADDR)
        .union(Self::RETURN_DATA_ADDR);
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
        command: u32,
        data: usize,
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
        command: i32,
        argument: usize,
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
        mode: i32,
    },
    CrossarchTrap {
        name: u32,
    },
    Sigprocmask {
        how: i32,
        mask: UserPtr<u32>,
        old_mask: UserPtrMut<u32>,
    },
    /// `__pthread_sigmask`: like `sigprocmask`, on the calling thread only.
    PthreadSigmask {
        how: i32,
        mask: UserPtr<u32>,
        old_mask: UserPtrMut<u32>,
    },
    /// `__pthread_kill(thread_port, sig)`.
    PthreadKill {
        thread: MachPortName,
        signal: i32,
    },
    DisableThreadsignal,
    /// `bsdthread_register(threadstart, wqthread, pthsize, data, data_size,
    /// dispatchqueue_offset)`; libpthread passes its registration data where
    /// `syscalls.master` names `stack_addr_hint` and `targetconc_ptr`.
    BsdthreadRegister {
        threadstart: usize,
        wqthread: usize,
        pthread_size: i32,
        data: usize,
        data_size: usize,
        dispatch_queue_offset: u32,
    },
    BsdthreadCreate {
        function: usize,
        argument: usize,
        stack: usize,
        pthread: usize,
        flags: u32,
    },
    BsdthreadTerminate {
        stack: usize,
        size: usize,
        port: MachPortName,
        /// A semaphore name, or the address of a ulock to wake.
        semaphore_or_ulock: usize,
    },
    BsdthreadCtl {
        command: usize,
        arguments: [usize; 3],
    },
    /// `ulock_wait` (timeout in microseconds) and `ulock_wait2` (timeout in
    /// nanoseconds, or a deadline with `ULF_DEADLINE`), normalized to
    /// nanoseconds.
    UlockWait {
        operation: u32,
        address: usize,
        value: u64,
        timeout: u64,
    },
    UlockWake {
        operation: u32,
        address: usize,
        wake_value: u64,
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
    MachThreadSelf,
    MachHostSelf,
    MachReplyPort,
    MachPortAllocate {
        target: MachPortName,
        right: u32,
        name: UserPtrMut<u32>,
    },
    MachPortDeallocate {
        target: MachPortName,
        name: MachPortName,
    },
    MachPortModRefs {
        target: MachPortName,
        name: MachPortName,
        right: u32,
        delta: i32,
    },
    MachPortInsertRight {
        target: MachPortName,
        name: MachPortName,
        poly: MachPortName,
        poly_disposition: u32,
    },
    MachPortConstruct {
        target: MachPortName,
        options: UserPtr<crate::mach::MachPortOptions>,
        context: u64,
        name: UserPtrMut<u32>,
    },
    MachPortDestruct {
        target: MachPortName,
        name: MachPortName,
        send_right_delta: i32,
        guard: u64,
    },
    /// `mach_msg2_trap`; the header arrives in registers.
    MachMsg2 {
        data: usize,
        options: crate::mach::MachMsgOptions,
        header: crate::mach::MachMsgHeader,
        send_size: u32,
        descriptor_count: u32,
        receive_name: MachPortName,
        receive_size: u32,
        priority: u32,
        timeout: u32,
    },
    SemaphoreSignal {
        semaphore: MachPortName,
    },
    SemaphoreWait {
        semaphore: MachPortName,
    },
    SwtchPri,
    Swtch,
    ThreadSwitch {
        thread: MachPortName,
        option: i32,
        option_time: u32,
    },
    SharedRegionCheckNp {
        start_address: UserPtrMut<usize>,
    },
    SharedRegionMapAndSlide2Np {
        files_count: u32,
        /// `struct shared_file_np[files_count]`.
        files: UserPtr<u8>,
        mappings_count: u32,
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
                mach_trap::THREAD_SELF => Ok(Self::MachThreadSelf),
                mach_trap::HOST_SELF => Ok(Self::MachHostSelf),
                mach_trap::MACH_REPLY_PORT => Ok(Self::MachReplyPort),
                mach_trap::MACH_PORT_ALLOCATE => Ok(Self::MachPortAllocate {
                    target: port_arg(0),
                    right: TruncateExt::<u32>::trunc(args[1]),
                    name: UserPtrMut::from_usize(args[2]),
                }),
                mach_trap::MACH_PORT_DEALLOCATE => Ok(Self::MachPortDeallocate {
                    target: port_arg(0),
                    name: port_arg(1),
                }),
                mach_trap::MACH_PORT_MOD_REFS => Ok(Self::MachPortModRefs {
                    target: port_arg(0),
                    name: port_arg(1),
                    right: TruncateExt::<u32>::trunc(args[2]),
                    delta: int_arg(3),
                }),
                mach_trap::MACH_PORT_INSERT_RIGHT => Ok(Self::MachPortInsertRight {
                    target: port_arg(0),
                    name: port_arg(1),
                    poly: port_arg(2),
                    poly_disposition: TruncateExt::<u32>::trunc(args[3]),
                }),
                mach_trap::MACH_PORT_CONSTRUCT => Ok(Self::MachPortConstruct {
                    target: port_arg(0),
                    options: UserPtr::from_usize(args[1]),
                    context: u64_arg(2),
                    name: UserPtrMut::from_usize(args[3]),
                }),
                mach_trap::MACH_PORT_DESTRUCT => Ok(Self::MachPortDestruct {
                    target: port_arg(0),
                    name: port_arg(1),
                    send_right_delta: int_arg(2),
                    guard: u64_arg(3),
                }),
                mach_trap::MACH_MSG2 => {
                    let low = |i: usize| TruncateExt::<u32>::trunc(args[i]);
                    let high = |i: usize| TruncateExt::<u32>::trunc(args[i] >> 32);
                    Ok(Self::MachMsg2 {
                        data: args[0],
                        options: crate::mach::MachMsgOptions::from_bits_retain(u64_arg(1)),
                        header: crate::mach::MachMsgHeader {
                            bits: low(2),
                            size: 0,
                            remote_port: low(3),
                            local_port: high(3),
                            voucher_port: low(4),
                            id: high(4).cast_signed(),
                        },
                        send_size: high(2),
                        descriptor_count: low(5),
                        receive_name: MachPortName(high(5)),
                        receive_size: low(6),
                        priority: high(6),
                        timeout: low(7),
                    })
                }
                mach_trap::SEMAPHORE_SIGNAL => Ok(Self::SemaphoreSignal {
                    semaphore: port_arg(0),
                }),
                mach_trap::SEMAPHORE_WAIT => Ok(Self::SemaphoreWait {
                    semaphore: port_arg(0),
                }),
                mach_trap::SWTCH_PRI => Ok(Self::SwtchPri),
                mach_trap::SWTCH => Ok(Self::Swtch),
                mach_trap::THREAD_SWITCH => Ok(Self::ThreadSwitch {
                    thread: port_arg(0),
                    option: int_arg(1),
                    option_time: TruncateExt::<u32>::trunc(args[2]),
                }),
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
                command: TruncateExt::<u32>::trunc(args[1]),
                data: args[2],
            },
            nr::CLOSE | nr::CLOSE_NOCANCEL => Self::Close { fd: int_arg(0) },
            nr::DUP => Self::Dup { fd: int_arg(0) },
            nr::DUP2 => Self::Dup2 {
                old: int_arg(0),
                new: int_arg(1),
            },
            nr::FCNTL | nr::FCNTL_NOCANCEL => Self::Fcntl {
                fd: int_arg(0),
                command: int_arg(1),
                argument: args[2],
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
                mode: int_arg(1),
            },
            nr::CROSSARCH_TRAP => Self::CrossarchTrap {
                name: TruncateExt::<u32>::trunc(args[0]),
            },
            nr::SIGPROCMASK => Self::Sigprocmask {
                how: int_arg(0),
                mask: UserPtr::from_usize(args[1]),
                old_mask: UserPtrMut::from_usize(args[2]),
            },
            nr::PTHREAD_SIGMASK => Self::PthreadSigmask {
                how: int_arg(0),
                mask: UserPtr::from_usize(args[1]),
                old_mask: UserPtrMut::from_usize(args[2]),
            },
            nr::PTHREAD_KILL => Self::PthreadKill {
                thread: port_arg(0),
                signal: int_arg(1),
            },
            nr::DISABLE_THREADSIGNAL => Self::DisableThreadsignal,
            nr::BSDTHREAD_REGISTER => Self::BsdthreadRegister {
                threadstart: args[0],
                wqthread: args[1],
                pthread_size: int_arg(2),
                data: args[3],
                data_size: args[4],
                dispatch_queue_offset: TruncateExt::<u32>::trunc(args[5]),
            },
            nr::BSDTHREAD_CREATE => Self::BsdthreadCreate {
                function: args[0],
                argument: args[1],
                stack: args[2],
                pthread: args[3],
                flags: TruncateExt::<u32>::trunc(args[4]),
            },
            nr::BSDTHREAD_TERMINATE => Self::BsdthreadTerminate {
                stack: args[0],
                size: args[1],
                port: port_arg(2),
                semaphore_or_ulock: args[3],
            },
            nr::BSDTHREAD_CTL => Self::BsdthreadCtl {
                command: args[0],
                arguments: [args[1], args[2], args[3]],
            },
            nr::ULOCK_WAIT => Self::UlockWait {
                operation: TruncateExt::<u32>::trunc(args[0]),
                address: args[1],
                value: u64_arg(2),
                // sys_ulock_wait: a 32-bit count of microseconds.
                timeout: u64::from(TruncateExt::<u32>::trunc(args[3])) * 1000,
            },
            nr::ULOCK_WAIT2 => Self::UlockWait {
                operation: TruncateExt::<u32>::trunc(args[0]),
                address: args[1],
                value: u64_arg(2),
                timeout: u64_arg(3),
            },
            nr::ULOCK_WAKE => Self::UlockWake {
                operation: TruncateExt::<u32>::trunc(args[0]),
                address: args[1],
                wake_value: u64_arg(2),
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
            nr::SHARED_REGION_MAP_AND_SLIDE_2_NP => Self::SharedRegionMapAndSlide2Np {
                files_count: TruncateExt::<u32>::trunc(args[0]),
                files: UserPtr::from_usize(args[1]),
                mappings_count: TruncateExt::<u32>::trunc(args[2]),
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
        // An unimplemented trap (`macx_swapon`).
        for number in [
            0u32.wrapping_sub(48) as usize,
            (-48isize).reinterpret_as_unsigned(),
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
        assert_eq!(
            PlatformSyscall::from_args(0x1234, 2),
            PlatformSyscall::SetCthreadSelf { tsd_base: 0x1234 }
        );
        assert_eq!(
            PlatformSyscall::from_args(0x1234, 0xffff_ffff_0000_0003),
            PlatformSyscall::GetCthreadSelf
        );
        for code in [0, 1, 4, u32::MAX] {
            assert_eq!(
                PlatformSyscall::from_args(0x1234, code as usize),
                PlatformSyscall::Ignored { code }
            );
        }
    }

    #[test]
    fn mach_msg2_unpacks_the_header_from_registers() {
        // libsyscall's MACH_MSG2_SHIFT_ARGS(lo, hi) = hi << 32 | lo.
        let request = SyscallRequest::from_args(
            0u32.wrapping_sub(mach_trap::MACH_MSG2) as usize,
            [
                0x1000,
                0x3,
                0x28_0000_1513,
                0x0000_0503_0000_0603,
                0x0000_00c8_0000_0000,
                0x0000_0603_0000_0000,
                0x0000_0000_0000_00c8,
                7,
            ],
        )
        .unwrap();
        let SyscallRequest::MachMsg2 {
            data,
            options,
            header,
            send_size,
            descriptor_count,
            receive_name,
            receive_size,
            priority,
            timeout,
        } = request
        else {
            panic!("{request:?}")
        };
        assert_eq!((data, options.bits()), (0x1000, 3));
        assert_eq!(
            header,
            crate::mach::MachMsgHeader {
                bits: 0x1513,
                size: 0,
                remote_port: 0x603,
                local_port: 0x503,
                voucher_port: 0,
                id: 200,
            }
        );
        assert_eq!((send_size, descriptor_count), (0x28, 0));
        assert_eq!((receive_name, receive_size), (MachPortName(0x603), 0xc8));
        assert_eq!((priority, timeout), (0, 7));
    }

    #[test]
    fn thread_and_ulock_arguments() {
        // libpthread's registration: data and its size where syscalls.master
        // names stack_addr_hint and targetconc_ptr; 32-bit pthsize and offset.
        assert!(matches!(
            SyscallRequest::from_args(
                nr::BSDTHREAD_REGISTER,
                [
                    0x1c14,
                    0x1c08,
                    0xdead_0000_4000,
                    0x7000,
                    0x38,
                    0x1_0000_00a0,
                    0,
                    0
                ],
            ),
            Ok(SyscallRequest::BsdthreadRegister {
                threadstart: 0x1c14,
                wqthread: 0x1c08,
                pthread_size: 0x4000,
                data: 0x7000,
                data_size: 0x38,
                dispatch_queue_offset: 0xa0,
            })
        ));
        assert!(matches!(
            SyscallRequest::from_args(
                nr::BSDTHREAD_CREATE,
                [1, 2, 3, 4, 0xffff_ffff_0100_0000, 0, 0, 0]
            ),
            Ok(SyscallRequest::BsdthreadCreate {
                function: 1,
                argument: 2,
                stack: 3,
                pthread: 4,
                flags: 0x0100_0000,
            })
        ));
        // ulock_wait's timeout is 32-bit microseconds; ulock_wait2's is 64-bit
        // nanoseconds. Both become nanoseconds.
        assert!(matches!(
            SyscallRequest::from_args(
                nr::ULOCK_WAIT,
                [
                    0x0100_0002,
                    0x1000,
                    0x1_0000_0003,
                    0xffff_ffff_0000_0007,
                    0,
                    0,
                    0,
                    0
                ],
            ),
            Ok(SyscallRequest::UlockWait {
                operation: 0x0100_0002,
                address: 0x1000,
                value: 0x1_0000_0003,
                timeout: 7000,
            })
        ));
        assert!(matches!(
            SyscallRequest::from_args(nr::ULOCK_WAIT2, [5, 0x1000, 3, 0x1_0000_0000, 9, 0, 0, 0]),
            Ok(SyscallRequest::UlockWait {
                operation: 5,
                timeout: 0x1_0000_0000,
                ..
            })
        ));
        assert!(matches!(
            SyscallRequest::from_args(
                0u32.wrapping_sub(mach_trap::THREAD_SWITCH) as usize,
                [0x103, 0xffff_ffff_ffff_ffff, 10, 0, 0, 0, 0, 0],
            ),
            Ok(SyscallRequest::ThreadSwitch {
                thread: MachPortName(0x103),
                option: -1,
                option_time: 10,
            })
        ));
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
    fn only_unknown_selectors_are_logged_as_unsupported() {
        let logged = core::cell::Cell::new(0);
        let log = |_: core::fmt::Arguments<'_>| logged.set(logged.get() + 1);
        let mut ctx = PtRegs::default();
        // A known call with a malformed argument (mmap protection 8) is EINVAL, not unsupported.
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
