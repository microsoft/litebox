// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall decoding.

use litebox::utils::{ReinterpretSignedExt as _, TruncateExt as _};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

/// AArch64 Darwin uses bare BSD numbers in x16.
pub mod nr {
    pub const EXIT: usize = 1;
    pub const READ: usize = 3;
    pub const WRITE: usize = 4;
    pub const CLOSE: usize = 6;
    pub const GETPID: usize = 20;
    pub const GETUID: usize = 24;
    pub const GETEUID: usize = 25;
    pub const GETPPID: usize = 39;
    pub const DUP: usize = 41;
    pub const GETEGID: usize = 43;
    pub const GETGID: usize = 47;
    pub const READ_NOCANCEL: usize = 396;
    pub const WRITE_NOCANCEL: usize = 397;
    pub const CLOSE_NOCANCEL: usize = 399;
}

/// Whether the low 32 bits of an AArch64 syscall selector encode a Mach trap.
/// XNU interprets the selector as signed `int`, regardless of x16's upper bits.
pub fn is_mach_trap_selector(number: usize) -> bool {
    let number: u32 = number.trunc();
    number.cast_signed() < 0
}

/// Mach trap numbers. AArch64 Darwin passes their negation in w16.
pub mod mach_trap {
    /// `mach_absolute_time()`.
    pub const MACH_ABSOLUTE_TIME: usize = 3;
    /// `mach_timebase_info(mach_timebase_info_t)`.
    pub const MACH_TIMEBASE_INFO: usize = 89;
    /// `mach_wait_until(deadline)`.
    pub const MACH_WAIT_UNTIL: usize = 90;
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
    Close {
        fd: i32,
    },
    Dup {
        fd: i32,
    },
    Getpid,
    Getppid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
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
        #[allow(clippy::cast_possible_truncation)] // usize is at most 64 bits on supported targets.
        let u64_arg = |i: usize| -> u64 { args[i] as u64 };
        if is_mach_trap_selector(number) {
            let selector: u32 = number.trunc();
            let trap = selector.cast_signed().wrapping_neg().cast_unsigned() as usize;
            return match trap {
                mach_trap::MACH_ABSOLUTE_TIME => Ok(Self::MachAbsoluteTime),
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
            nr::CLOSE | nr::CLOSE_NOCANCEL => Self::Close { fd: int_arg(0) },
            nr::DUP => Self::Dup { fd: int_arg(0) },
            nr::GETPID => Self::Getpid,
            nr::GETPPID => Self::Getppid,
            nr::GETUID => Self::Getuid,
            nr::GETEUID => Self::Geteuid,
            nr::GETGID => Self::Getgid,
            nr::GETEGID => Self::Getegid,
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
        for number in [0, 0x0200_0004, 0x8000_0000] {
            assert!(matches!(
                SyscallRequest::from_args(number, [0; 8]),
                Err(Errno::ENOSYS)
            ));
        }
        assert!(matches!(
            SyscallRequest::from_args((-3_isize).cast_unsigned(), [0; 8]),
            Ok(SyscallRequest::MachAbsoluteTime)
        ));
        assert!(matches!(
            SyscallRequest::from_args(u32::MAX as usize - 2, [0; 8]),
            Ok(SyscallRequest::MachAbsoluteTime)
        ));
        let request =
            SyscallRequest::from_args((-89_isize).cast_unsigned(), [0x1234, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
        let SyscallRequest::MachTimebaseInfo { info } = request else {
            panic!()
        };
        let _: UserPtrMut<MachTimebaseInfo> = info;
        assert_eq!(info.as_usize(), 0x1234);
        assert!(matches!(
            SyscallRequest::from_args(
                (-90_isize).cast_unsigned(),
                [0x1234_5678, 0, 0, 0, 0, 0, 0, 0]
            ),
            Ok(SyscallRequest::MachWaitUntil {
                deadline: 0x1234_5678
            })
        ));
        assert!(matches!(
            SyscallRequest::from_args((-2_isize).cast_unsigned(), [0; 8]),
            Err(Errno::ENOSYS)
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
