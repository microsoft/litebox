// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux signal handling definitions.

pub mod x86;
pub mod x86_64;

#[cfg(target_arch = "x86")]
use x86::Sigcontext;
#[cfg(target_arch = "x86_64")]
use x86_64::Sigcontext;

use int_enum::IntEnum;
use litebox::utils::ReinterpretSignedExt as _;
use zerocopy::{FromBytes, IntoBytes};

use crate::errno::Errno;

/// A Linux signal number guaranteed to be in the range 1..=64.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signal(i32);

impl Signal {
    pub const SIGHUP: Self = Self(1);
    pub const SIGINT: Self = Self(2);
    pub const SIGQUIT: Self = Self(3);
    pub const SIGILL: Self = Self(4);
    pub const SIGTRAP: Self = Self(5);
    pub const SIGABRT: Self = Self(6);
    pub const SIGIOT: Self = Self::SIGABRT;
    pub const SIGBUS: Self = Self(7);
    pub const SIGFPE: Self = Self(8);
    pub const SIGKILL: Self = Self(9);
    pub const SIGUSR1: Self = Self(10);
    pub const SIGSEGV: Self = Self(11);
    pub const SIGUSR2: Self = Self(12);
    pub const SIGPIPE: Self = Self(13);
    pub const SIGALRM: Self = Self(14);
    pub const SIGTERM: Self = Self(15);
    pub const SIGSTKFLT: Self = Self(16);
    pub const SIGCHLD: Self = Self(17);
    pub const SIGCONT: Self = Self(18);
    pub const SIGSTOP: Self = Self(19);
    pub const SIGTSTP: Self = Self(20);
    pub const SIGTTIN: Self = Self(21);
    pub const SIGTTOU: Self = Self(22);
    pub const SIGURG: Self = Self(23);
    pub const SIGXCPU: Self = Self(24);
    pub const SIGXFSZ: Self = Self(25);
    pub const SIGVTALRM: Self = Self(26);
    pub const SIGPROF: Self = Self(27);
    pub const SIGWINCH: Self = Self(28);
    pub const SIGIO: Self = Self(29);
    pub const SIGPOLL: Self = Self::SIGIO;
    pub const SIGPWR: Self = Self(30);
    pub const SIGSYS: Self = Self(31);
    pub const SIGUNUSED: Self = Self::SIGSYS;

    /// Get the signal number as an `i32`, the natural representation.
    pub const fn as_i32(&self) -> i32 {
        self.0
    }

    /// Returns true if this is a real-time signal.
    pub const fn is_rt_signal(&self) -> bool {
        self.0 >= SIGRTMIN
    }

    /// Get the documented default disposition of this signal.
    pub fn default_disposition(&self) -> SignalDisposition {
        match *self {
            Signal::SIGABRT
            | Signal::SIGBUS
            | Signal::SIGFPE
            | Signal::SIGILL
            | Signal::SIGQUIT
            | Signal::SIGSEGV
            | Signal::SIGSYS
            | Signal::SIGTRAP
            | Signal::SIGXCPU
            | Signal::SIGXFSZ => SignalDisposition::Core,
            Signal::SIGCHLD | Signal::SIGURG | Signal::SIGWINCH => SignalDisposition::Ignore,
            Signal::SIGCONT => SignalDisposition::Continue,
            Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU => {
                SignalDisposition::Stop
            }
            _ => SignalDisposition::Terminate,
        }
    }
}

impl TryFrom<i32> for Signal {
    type Error = Errno;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if (1..=64).contains(&value) {
            Ok(Self(value))
        } else {
            Err(Errno::EINVAL)
        }
    }
}
impl TryFrom<Signal> for litebox::shim::Signal {
    type Error = Signal;

    fn try_from(value: Signal) -> Result<Self, Self::Error> {
        match value {
            Signal::SIGINT => Ok(Self::SIGINT),
            Signal::SIGALRM => Ok(Self::SIGALRM),
            _ => Err(value),
        }
    }
}

/// The default disposition of a signal.
pub enum SignalDisposition {
    /// Terminate the process.
    Terminate,
    /// Ignore the signal.
    Ignore,
    /// Dump core and terminate the process.
    Core,
    /// Stop the process.
    Stop,
    /// Continue the process if it is stopped.
    Continue,
}

#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct SigSet(u64);

impl SigSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub const fn add(&mut self, signum: Signal) {
        self.0 |= 1 << (signum.as_i32() - 1);
    }

    #[must_use]
    pub const fn with(self, signum: Signal) -> Self {
        let mut new_set = self;
        new_set.add(signum);
        new_set
    }

    pub const fn remove(&mut self, signum: Signal) {
        self.0 &= !(1 << (signum.as_i32() - 1));
    }

    pub const fn contains(&self, signum: Signal) -> bool {
        (self.0 & (1 << (signum.as_i32() - 1))) != 0
    }

    /// Returns the lowest-numbered signal that is set in this set, or `None` if
    /// the set is empty.
    pub fn lowest_set(&self) -> Option<Signal> {
        if self.0 == 0 {
            None
        } else {
            let lsb_index = self.0.trailing_zeros().reinterpret_as_signed();
            Some(Signal(lsb_index + 1))
        }
    }

    /// Removes and returns the lowest-numbered signal in the set, or `None` if
    /// empty.
    pub fn pop_lowest(&mut self) -> Option<Signal> {
        if self.0 == 0 {
            return None;
        }
        let bit = self.0.trailing_zeros();
        self.0 &= !(1u64 << bit);
        Some(Signal(bit.reinterpret_as_signed() + 1))
    }

    /// Returns an iterator over the signals in this set, from lowest to
    /// highest.
    pub fn iter(self) -> SigSetIter {
        SigSetIter(self)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn from_u64(bits: u64) -> Self {
        Self(bits)
    }
}

impl core::ops::BitAnd for SigSet {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitOr for SigSet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::Not for SigSet {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

/// An iterator over the signals in a [`SigSet`], yielding them from lowest to
/// highest signal number.
#[derive(Clone)]
pub struct SigSetIter(SigSet);

impl Iterator for SigSetIter {
    type Item = Signal;

    fn next(&mut self) -> Option<Signal> {
        self.0.pop_lowest()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.0.0.count_ones() as usize;
        (count, Some(count))
    }
}

impl IntoIterator for SigSet {
    type Item = Signal;
    type IntoIter = SigSetIter;

    fn into_iter(self) -> SigSetIter {
        self.iter()
    }
}

/// Signal action flags for `rt_sigaction` syscall.
#[derive(Copy, Clone, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct SaFlags(u32);

bitflags::bitflags! {
    impl SaFlags: u32 {
        const NOCLDSTOP = 1;
        const NOCLDWAIT = 2;
        const SIGINFO = 4;
        const RESTORER  = 0x04000000;
        const ONSTACK   = 0x08000000;
        const RESTART   = 0x10000000;
        const NODEFER   = 0x40000000;
        const RESETHAND = 0x80000000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Linux's `sigaction` struct used by the `rt_sigaction` syscall.
#[repr(C)]
#[derive(Copy, Clone, FromBytes, IntoBytes)]
pub struct SigAction {
    pub sigaction: usize,
    pub flags: SaFlags,
    #[cfg(target_pointer_width = "64")]
    #[doc(hidden)]
    pub __pad: u32, // NOTE: Maybe `SaFlags` and `SigSet` need to be `usize`-backed too?
    pub restorer: usize,
    pub mask: SigSet,
}

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

#[repr(i32)]
#[derive(Debug, IntEnum)]
pub enum SigmaskHow {
    SIG_BLOCK = 0,
    SIG_UNBLOCK = 1,
    SIG_SETMASK = 2,
}

#[repr(C)]
#[derive(Copy, Clone, FromBytes, IntoBytes)]
pub struct SigAltStack {
    pub sp: usize,
    pub flags: SsFlags,
    #[cfg(target_pointer_width = "64")]
    #[doc(hidden)]
    pub __pad: u32,
    pub size: usize,
}

/// Signal stack flags.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct SsFlags(u32);

bitflags::bitflags! {
    impl SsFlags: u32 {
        /// Stack on signal stack
        const ONSTACK = 1;
        /// Stack disabled
        const DISABLE = 2;
        /// Automatically disarm the stack
        const AUTODISARM = 0x8000_0000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const MINSIGSTKSZ: usize = 2048;
#[cfg(target_arch = "aarch64")]
pub const MINSIGSTKSZ: usize = 5120;

pub const SIGRTMIN: i32 = 32;
pub const NSIG: usize = 64;

pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_QUEUE: i32 = -1;
pub const SI_TIMER: i32 = -2;
pub const SI_MESGQ: i32 = -3;
pub const SI_ASYNCIO: i32 = -4;
pub const SI_SIGIO: i32 = -5;
pub const SI_TKILL: i32 = -6;
pub const SI_DETHREAD: i32 = -7;
pub const SI_ASYNCNL: i32 = -60;

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct Ucontext {
    pub flags: usize,
    pub link: usize, // *mut Ucontext,
    pub stack: SigAltStack,
    pub mcontext: Sigcontext,
    pub sigmask: SigSet,
}

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct Siginfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    #[cfg(target_pointer_width = "64")]
    #[doc(hidden)]
    pub __pad: u32,
    pub data: SiginfoData,
}

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
pub struct SiginfoData {
    pub pad: [u32; 28],
}

impl SiginfoData {
    pub fn new_addr(addr: usize) -> Self {
        let mut pad = [0u32; 28];
        pad.as_mut_bytes()[..core::mem::size_of::<usize>()].copy_from_slice(&addr.to_ne_bytes());
        Self { pad }
    }
}
