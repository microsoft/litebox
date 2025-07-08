// Automatically generated — do not edit.
// Since the Rust package "syscalls" does not support FreeBSD,
// we define the syscall table manually here.

#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(dead_code)] // Allow unused syscall variants as this is a comprehensive syscall table
pub enum SyscallTable {
    Syscall = 0,
    Exit = 1,
    Fork = 2,
    Read = 3,
    Write = 4,
    Open = 5,
    Close = 6,
    Wait4 = 7,
    // 8 is old creat
    Link = 9,
    Unlink = 10,
    // 11 is obsolete execv
    Chdir = 12,
    Fchdir = 13,
    Freebsd11Mknod = 14,
    Chmod = 15,
    Chown = 16,
    Break = 17,
    // 18 is freebsd4 getfsstat
    // 19 is old lseek
    Getpid = 20,
    Mount = 21,
    Unmount = 22,
    Setuid = 23,
    Getuid = 24,
    Geteuid = 25,
    Ptrace = 26,
    Recvmsg = 27,
    Sendmsg = 28,
    Recvfrom = 29,
    Accept = 30,
    Getpeername = 31,
    Getsockname = 32,
    Access = 33,
    Chflags = 34,
    Fchflags = 35,
    Sync = 36,
    Kill = 37,
    // 38 is old stat
    Getppid = 39,
    // 40 is old lstat
    Dup = 41,
    Freebsd10Pipe = 42,
    Getegid = 43,
    Profil = 44,
    Ktrace = 45,
    // 46 is old sigaction
    Getgid = 47,
    // 48 is old sigprocmask
    Getlogin = 49,
    Setlogin = 50,
    Acct = 51,
    // 52 is old sigpending
    Sigaltstack = 53,
    Ioctl = 54,
    Reboot = 55,
    Revoke = 56,
    Symlink = 57,
    Readlink = 58,
    Execve = 59,
    Umask = 60,
    Chroot = 61,
    // Continue with key syscalls for file operations
    Msync = 65,
    Vfork = 66,
    Munmap = 73,
    Mprotect = 74,
    Madvise = 75,
    Mincore = 78,
    Getgroups = 79,
    Setgroups = 80,
    Getpgrp = 81,
    Setpgid = 82,
    Setitimer = 83,
    Swapon = 85,
    Getitimer = 86,
    Getdtablesize = 89,
    Dup2 = 90,
    Fcntl = 92,
    Select = 93,
    Fsync = 95,
    Setpriority = 96,
    Socket = 97,
    Connect = 98,
    Getpriority = 100,
    Bind = 104,
    Setsockopt = 105,
    Listen = 106,
    Gettimeofday = 116,
    Getrusage = 117,
    Getsockopt = 118,
    Readv = 120,
    Writev = 121,
    Settimeofday = 122,
    Fchown = 123,
    Fchmod = 124,
    Setreuid = 126,
    Setregid = 127,
    Rename = 128,
    Flock = 131,
    Mkfifo = 132,
    Sendto = 133,
    Shutdown = 134,
    Socketpair = 135,
    Mkdir = 136,
    Rmdir = 137,
    Utimes = 138,
    Adjtime = 140,
    Setsid = 147,
    Quotactl = 148,
    NlmSyscall = 154,
    Nfssvc = 155,
    Lgetfh = 160,
    Getfh = 161,
    Sysarch = 165,
    Rtprio = 166,
    Semsys = 169,
    Msgsys = 170,
    Shmsys = 171,
    Setfib = 175,
    NtpAdjtime = 176,
    Setgid = 181,
    Setegid = 182,
    Seteuid = 183,
    Freebsd11Stat = 188,
    Freebsd11Fstat = 189,
    Freebsd11Lstat = 190,
    Pathconf = 191,
    Fpathconf = 192,
    Getrlimit = 194,
    Setrlimit = 195,
    Freebsd11Getdirentries = 196,
    __Syscall = 198,
    Sysctl = 202,
    Mlock = 203,
    Munlock = 204,
    Undelete = 205,
    Futimes = 206,
    Getpgid = 207,
    Poll = 209,
    Freebsd7Semctl = 220,
    Semget = 221,
    Semop = 222,
    Freebsd7Msgctl = 224,
    Msgget = 225,
    Msgsnd = 226,
    Msgrcv = 227,
    Shmat = 228,
    Freebsd7Shmctl = 229,
    Shmdt = 230,
    Shmget = 231,
    ClockGettime = 232,
    ClockSettime = 233,
    ClockGetres = 234,
    KtimerCreate = 235,
    KtimerDelete = 236,
    KtimerSettime = 237,
    KtimerGettime = 238,
    KtimerGetoverrun = 239,
    Nanosleep = 240,
    ClockNanosleep = 244,
    ClockGetcpuclockid2 = 247,
    NtpGettime = 248,
    Minherit = 250,
    Rfork = 251,
    Issetugid = 253,
    Lchown = 254,
    AioRead = 255,
    AioWrite = 256,
    LioListio = 257,
    Freebsd11Getdents = 272,
    Lchmod = 274,
    Lutimes = 276,
    Freebsd11Nstat = 278,
    Freebsd11Nfstat = 279,
    Freebsd11Nlstat = 280,
    Preadv = 289,
    Pwritev = 290,
    Fhopen = 298,
    Freebsd11Fhstat = 299,
    Modnext = 300,
    Modstat = 301,
    Modfnext = 302,
    Modfind = 303,
    Kldload = 304,
    Kldunload = 305,
    Kldfind = 306,
    Kldnext = 307,
    Kldstat = 308,
    Kldfirstmod = 309,
    Getsid = 310,
    Setresuid = 311,
    Setresgid = 312,
    AioReturn = 314,
    AioSuspend = 315,
    AioCancel = 316,
    AioError = 317,
    Yield = 321,
    Mlockall = 324,
    Munlockall = 325,
    Getcwd = 326,
    SchedSetparam = 327,
    SchedGetparam = 328,
    SchedSetscheduler = 329,
    SchedGetscheduler = 330,
    SchedYield = 331,
    SchedGetPriorityMax = 332,
    SchedGetPriorityMin = 333,
    SchedRrGetInterval = 334,
    Utrace = 335,
    Kldsym = 337,
    Jail = 338,
    NnpfsSyscall = 339,
    Sigprocmask = 340,
    Sigsuspend = 341,
    Sigpending = 343,
    Sigtimedwait = 345,
    Sigwaitinfo = 346,
    AclGetFile = 347,
    AclSetFile = 348,
    AclGetFd = 349,
    AclSetFd = 350,
    AclDeleteFile = 351,
    AclDeleteFd = 352,
    AclAclcheckFile = 353,
    AclAclcheckFd = 354,
    Extattrctl = 355,
    ExtattrSetFile = 356,
    ExtattrGetFile = 357,
    ExtattrDeleteFile = 358,
    AioWaitcomplete = 359,
    Getresuid = 360,
    Getresgid = 361,
    Kqueue = 362,
    Freebsd11Kevent = 363,
    ExtattrSetFd = 371,
    ExtattrGetFd = 372,
    ExtattrDeleteFd = 373,
    Setugid = 374,
    Eaccess = 376,
    Afs3Syscall = 377,
    Nmount = 378,
    MacGetProc = 384,
    MacSetProc = 385,
    MacGetFd = 386,
    MacGetFile = 387,
    MacSetFd = 388,
    MacSetFile = 389,
    Kenv = 390,
    Lchflags = 391,
    Uuidgen = 392,
    Sendfile = 393,
    MacSyscall = 394,
    Freebsd11Getfsstat = 395,
    Freebsd11Statfs = 396,
    Freebsd11Fstatfs = 397,
    Freebsd11Fhstatfs = 398,
    KsemClose = 400,
    KsemPost = 401,
    KsemWait = 402,
    KsemTrywait = 403,
    KsemInit = 404,
    KsemOpen = 405,
    KsemUnlink = 406,
    KsemGetvalue = 407,
    KsemDestroy = 408,
    MacGetPid = 409,
    MacGetLink = 410,
    MacSetLink = 411,
    ExtattrSetLink = 412,
    ExtattrGetLink = 413,
    ExtattrDeleteLink = 414,
    MacExecve = 415,
    Sigaction = 416,
    Sigreturn = 417,
    Getcontext = 421,
    Setcontext = 422,
    Swapcontext = 423,
    Freebsd13Swapoff = 424,
    AclGetLink = 425,
    AclSetLink = 426,
    AclDeleteLink = 427,
    AclAclcheckLink = 428,
    Sigwait = 429,
    ThrCreate = 430,
    ThrExit = 431,
    ThrSelf = 432,
    ThrKill = 433,
    Freebsd10UmtxLock = 434,
    Freebsd10UmtxUnlock = 435,
    JailAttach = 436,
    ExtattrListFd = 437,
    ExtattrListFile = 438,
    ExtattrListLink = 439,
    KsemTimedwait = 441,
    ThrSuspend = 442,
    ThrWake = 443,
    Kldunloadf = 444,
    Audit = 445,
    Auditon = 446,
    Getauid = 447,
    Setauid = 448,
    Getaudit = 449,
    Setaudit = 450,
    GetauditAddr = 451,
    SetauditAddr = 452,
    Auditctl = 453,
    UmtxOp = 454,
    ThrNew = 455,
    Sigqueue = 456,
    KmqOpen = 457,
    KmqSetattr = 458,
    KmqTimedreceive = 459,
    KmqTimedsend = 460,
    KmqNotify = 461,
    KmqUnlink = 462,
    Abort2 = 463,
    ThrSetName = 464,
    AioFsync = 465,
    RtprioThread = 466,
    SctpPeeloff = 471,
    SctpGenericSendmsg = 472,
    SctpGenericSendmsgIov = 473,
    SctpGenericRecvmsg = 474,
    Pread = 475,
    Pwrite = 476,
    Mmap = 477,
    Lseek = 478,
    Truncate = 479,
    Ftruncate = 480,
    ThrKill2 = 481,
    Freebsd12ShmOpen = 482,
    ShmUnlink = 483,
    Cpuset = 484,
    CpusetSetid = 485,
    CpusetGetid = 486,
    CpusetGetaffinity = 487,
    CpusetSetaffinity = 488,
    Faccessat = 489,
    Fchmodat = 490,
    Fchownat = 491,
    Fexecve = 492,
    Freebsd11Fstatat = 493,
    Futimesat = 494,
    Linkat = 495,
    Mkdirat = 496,
    Mkfifoat = 497,
    Freebsd11Mknodat = 498,
    Openat = 499,
    Readlinkat = 500,
    Renameat = 501,
    Symlinkat = 502,
    Unlinkat = 503,
    PosixOpenpt = 504,
    JailGet = 506,
    JailSet = 507,
    JailRemove = 508,
    Freebsd12Closefrom = 509,
    Semctl = 510,
    Msgctl = 511,
    Shmctl = 512,
    Lpathconf = 513,
    CapRightsGet = 515,
    CapEnter = 516,
    CapGetmode = 517,
    Pdfork = 518,
    Pdkill = 519,
    Pdgetpid = 520,
    Pselect = 522,
    Getloginclass = 523,
    Setloginclass = 524,
    RctlGetRacct = 525,
    RctlGetRules = 526,
    RctlGetLimits = 527,
    RctlAddRule = 528,
    RctlRemoveRule = 529,
    PosixFallocate = 530,
    PosixFadvise = 531,
    Wait6 = 532,
    CapRightsLimit = 533,
    CapIoctlsLimit = 534,
    CapIoctlsGet = 535,
    CapFcntlsLimit = 536,
    CapFcntlsGet = 537,
    Bindat = 538,
    Connectat = 539,
    Chflagsat = 540,
    Accept4 = 541,
    Pipe2 = 542,
    AioMlock = 543,
    Procctl = 544,
    Ppoll = 545,
    Futimens = 546,
    Utimensat = 547,
    Fdatasync = 550,
    Fstat = 551,
    Fstatat = 552,
    Fhstat = 553,
    Getdirentries = 554,
    Statfs = 555,
    Fstatfs = 556,
    Getfsstat = 557,
    Fhstatfs = 558,
    Mknodat = 559,
    Kevent = 560,
    CpusetGetdomain = 561,
    CpusetSetdomain = 562,
    Getrandom = 563,
    Getfhat = 564,
    Fhlink = 565,
    Fhlinkat = 566,
    Fhreadlink = 567,
    Funlinkat = 568,
    CopyFileRange = 569,
    Sysctlbyname = 570,
    ShmOpen2 = 571,
    ShmRename = 572,
    Sigfastblock = 573,
    Realpathat = 574,
    CloseRange = 575,
    RpctlsSyscall = 576,
    Specialfd = 577,
    AioWritev = 578,
    AioReadv = 579,
    Fspacectl = 580,
    SchedGetcpu = 581,
    Swapoff = 582,
    Kqueuex = 583,
    Membarrier = 584,
    TimerfdCreate = 585,
    TimerfdGettime = 586,
    TimerfdSettime = 587,
    Kcmp = 588,
    Getrlimitusage = 589,
    Fchroot = 590,
    Setcred = 591,
    Exterrctl = 592,
}

/// Direct syscall wrappers for FreeBSD x86_64
#[cfg(target_arch = "x86_64")]
pub mod syscalls {
    use super::SyscallTable;

    /// Syscall number alias for compatibility
    #[allow(dead_code)]
    pub type Sysno = SyscallTable;

    /// Result type for syscalls
    pub type SyscallResult = Result<usize, isize>;

    /// Perform a syscall with no arguments
    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall0(num: SyscallTable) -> SyscallResult {
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with one argument
    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall1(num: SyscallTable, arg1: usize) -> SyscallResult {
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with two arguments
    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall2(num: SyscallTable, arg1: usize, arg2: usize) -> SyscallResult {
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with three arguments
    #[inline]
    pub unsafe fn syscall3(
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with four arguments
    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall4(
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with five arguments
    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall5(
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }

    /// Perform a syscall with six arguments
    #[allow(dead_code)]
    #[inline]
    pub unsafe fn syscall6(
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
            Err(ret as isize)
        } else {
            Ok(ret)
        }
    }
}

/// Fallback for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub mod syscalls {
    use super::SyscallTable;

    /// Syscall number alias for compatibility
    #[allow(dead_code)]
    pub type Sysno = SyscallTable;

    /// Result type for syscalls
    pub type SyscallResult = Result<usize, isize>;

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
