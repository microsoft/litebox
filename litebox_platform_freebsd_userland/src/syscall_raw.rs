//! FreeBSD host system call support.

#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "For comprehension we added an over-approximated syscall list. To be removed."
)]
pub(crate) enum SyscallTable {
    Exit = 1,
    Read = 3,
    Write = 4,
    Open = 5,
    Close = 6,
    Getpid = 20,
    Mount = 21,
    Unmount = 22,
    Setuid = 23,
    Getuid = 24,
    Geteuid = 25,
    Getegid = 43,
    Getgid = 47,
    Munmap = 73,
    Mprotect = 74,
    Sysctl = 202,
    ThrExit = 431,
    ThrSelf = 432,
    UmtxOp = 454,
    ThrNew = 455,
    Mmap = 477,
}

/// Direct syscall wrappers for FreeBSD x86_64
#[cfg(target_arch = "x86_64")]
pub(crate) mod syscalls {
    use super::SyscallTable;

    /// Syscall number alias for compatibility
    pub(crate) type Sysno = SyscallTable;

    /// Result type for syscalls
<<<<<<< HEAD
    pub type SyscallResult = Result<usize, crate::errno::Errno>;
=======
    pub(crate) type SyscallResult = Result<usize, isize>;
>>>>>>> d57fd01d0ee4fbd9bfaff77275cf275fd951cb1a

    /// Perform a syscall with no arguments
    #[inline]
    pub(crate) unsafe fn syscall0(num: SyscallTable) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with one argument
    #[inline]
    pub(crate) unsafe fn syscall1(num: SyscallTable, arg1: usize) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                in("rdi") arg1,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with two arguments
    #[inline]
    pub(crate) unsafe fn syscall2(num: SyscallTable, arg1: usize, arg2: usize) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                in("rdi") arg1,
                in("rsi") arg2,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with three arguments
    #[inline]
    pub(crate) unsafe fn syscall3(
        num: SyscallTable,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with four arguments
    #[expect(
        dead_code,
        reason = "To be comprehensive, we added all syscall interfaces for now. To be removed later on."
    )]
    #[inline]
    pub(crate) unsafe fn syscall4(
        num: SyscallTable,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
    ) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                in("r10") arg4,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with five arguments
    #[expect(
        dead_code,
        reason = "To be comprehensive, we added all syscall interfaces for now. To be removed later on."
    )]
    #[inline]
    pub(crate) unsafe fn syscall5(
        num: SyscallTable,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                in("r10") arg4,
                in("r8") arg5,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with six arguments
    #[inline]
    pub(crate) unsafe fn syscall6(
        num: SyscallTable,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> SyscallResult {
        let ret: usize;
        let carry: u8;
        unsafe {
            core::arch::asm!(
                "syscall",
                "setc {}",
                out(reg_byte) carry,
                in("rax") num as i32,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                in("r10") arg4,
                in("r8") arg5,
                in("r9") arg6,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
        }
        if carry != 0 {
            Err(crate::errno::Errno::try_from(ret as i32).unwrap_or(crate::errno::Errno::EINVAL))
        } else {
            Ok(ret)
        }
    }
}
<<<<<<< HEAD

/// Fallback for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub mod syscalls {
    use super::SyscallTable;

    /// Syscall number alias for compatibility
    #[allow(dead_code)]
    pub type Sysno = SyscallTable;

    /// Result type for syscalls
    pub type SyscallResult = Result<usize, crate::errno::Errno>;

    // Stub implementations that panic - FreeBSD syscalls are only supported on x86_64

    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall0(_num: SyscallTable) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }

    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall1(_num: SyscallTable, _arg1: usize) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }

    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall2(_num: SyscallTable, _arg1: usize, _arg2: usize) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }

    #[inline]
    pub unsafe fn syscall3(
        _num: SyscallTable,
        _arg1: usize,
        _arg2: usize,
        _arg3: usize,
    ) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }

    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall4(
        _num: SyscallTable,
        _arg1: usize,
        _arg2: usize,
        _arg3: usize,
        _arg4: usize,
    ) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }

    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall5(
        _num: SyscallTable,
        _arg1: usize,
        _arg2: usize,
        _arg3: usize,
        _arg4: usize,
        _arg5: usize,
    ) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }

    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall6(
        _num: SyscallTable,
        _arg1: usize,
        _arg2: usize,
        _arg3: usize,
        _arg4: usize,
        _arg5: usize,
        _arg6: usize,
    ) -> SyscallResult {
        panic!("FreeBSD syscalls are only supported on x86_64 architecture")
    }
}
=======
>>>>>>> d57fd01d0ee4fbd9bfaff77275cf275fd951cb1a
