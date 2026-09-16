// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall decoding.

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
}

impl SyscallRequest {
    /// Decode without dereferencing guest memory. Darwin allows eight register
    /// arguments. C `int` arguments use the low 32 bits, including their sign.
    pub fn from_args(number: usize, args: [usize; 8]) -> Result<Self, Errno> {
        let int_arg = |i: usize| {
            // Truncate to the low 32 bits and interpret them as a signed C int.
            let bytes = args[i].to_le_bytes();
            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        };
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
        for number in [0, usize::MAX, 0x0200_0004, 0x8000_0000] {
            assert!(matches!(
                SyscallRequest::from_args(number, [0; 8]),
                Err(Errno::ENOSYS)
            ));
        }
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
