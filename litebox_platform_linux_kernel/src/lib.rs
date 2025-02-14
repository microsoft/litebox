//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![no_std]

use core::sync::atomic::AtomicU64;
use core::{arch::asm, sync::atomic::AtomicU32};

use host::linux::sigset_t;
use litebox::platform::RawMutex as _;
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, ImmediatelyWokenUp, Provider, Punchthrough,
    PunchthroughError, PunchthroughProvider, PunchthroughToken, RawMutexProvider, TimeProvider,
    UnblockedOrTimedOut,
};

extern crate alloc;

pub mod error;
pub mod host;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`]
/// and a task that implements the [`Task`] trait.
pub struct LinuxKernel<Host: HostInterface, T: Task> {
    host_and_task: core::marker::PhantomData<(Host, T)>,
}

/// Analogous to `task struct` in Linux
pub trait Task {
    fn current<'a>() -> Option<&'a Self>;

    /// Shared memory may be mapped to different address spaces in host and guest kernel.
    /// This function is to convert a kernel pointer to host address space.
    fn convert_ptr_to_host<T>(&self, ptr: *const T) -> *const T;
    /// Similar to [`Self::convert_ptr_to_host`], but for mutable pointers
    fn convert_mut_ptr_to_host<T>(&self, ptr: *mut T) -> *mut T;
}

/// Punchthrough for syscalls
/// Note we assume all punchthroughs are non-blocking
pub enum LinuxPunchthrough {
    RtSigprocmask {
        how: i32,
        set: Option<*const sigset_t>,
        old_set: Option<*mut sigset_t>,
        sigsetsize: usize,
    },
    // TODO: Add more syscalls
}

impl Punchthrough for LinuxPunchthrough {
    type ReturnSuccess = usize;
    type ReturnFailure = error::Errno;
}

pub struct LinuxPunchthroughToken<Host: HostInterface> {
    punchthrough: LinuxPunchthrough,
    host: core::marker::PhantomData<Host>,
}

impl<Host: HostInterface> PunchthroughToken for LinuxPunchthroughToken<Host> {
    type Punchthrough = LinuxPunchthrough;

    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        let r = match self.punchthrough {
            LinuxPunchthrough::RtSigprocmask {
                how,
                set,
                old_set,
                sigsetsize,
            } => Host::rt_sigprocmask(how, set, old_set, sigsetsize),
        };
        match r {
            Ok(v) => Ok(v),
            Err(e) => Err(litebox::platform::PunchthroughError::Failure(e)),
        }
    }
}

impl<Host: HostInterface, T: Task> Provider for LinuxKernel<Host, T> {}

impl<Host: HostInterface, T: Task> PunchthroughProvider for LinuxKernel<Host, T> {
    type PunchthroughToken = LinuxPunchthroughToken<Host>;

    fn get_punchthrough_token_for(
        &mut self,
        punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(LinuxPunchthroughToken {
            punchthrough,
            host: core::marker::PhantomData,
        })
    }
}

impl<Host: HostInterface, T: Task> LinuxKernel<Host, T> {
    pub fn init(&self, cpu_mhz: u64) {
        CPU_MHZ.store(cpu_mhz, core::sync::atomic::Ordering::Relaxed);
    }

    /// rt_sigprocmask: examine and change blocked signals.
    /// sigprocmask() is used to fetch and/or change the signal mask of the calling thread.
    /// The signal mask is the set of signals whose delivery is currently blocked for the
    /// caller (see also signal(7) for more details).
    ///
    ///The behavior of the call is dependent on the value of how, as follows.
    ///
    /// *SIG_BLOCK*
    /// The set of blocked signals is the union of the current set and the set argument.
    ///
    /// *SIG_UNBLOCK*
    /// The signals in set are removed from the current set of blocked signals. It is permissible to attempt to unblock a signal which is not blocked.
    ///
    /// *SIG_SETMASK*
    /// The set of blocked signals is set to the argument set.
    /// If oldset is non-NULL, the previous value of the signal mask is stored in oldset.
    /// If set is NULL, then the signal mask is unchanged (i.e., how is ignored), but the current value of the signal mask is nevertheless returned in oldset (if it is not NULL).
    /// The use of sigprocmask() is unspecified in a multithreaded process; see pthread_sigmask(3).
    ///
    /// **Return Value**
    ///
    /// sigprocmask() returns 0 on success and -1 on error.
    ///
    /// **Errors**
    ///
    /// *EFAULT* the set or oldset argument points outside the process's allocated address space.
    ///
    /// *EINVAL* The value specified in how was invalid.
    ///
    /// set and old_set are pointers in user space
    pub fn rt_sigprocmask(
        &mut self,
        how: i32,
        set: Option<*const sigset_t>,
        old_set: Option<*mut sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, PunchthroughError<error::Errno>> {
        let punchthrough = LinuxPunchthrough::RtSigprocmask {
            how,
            set,
            old_set,
            sigsetsize,
        };
        let token = self
            .get_punchthrough_token_for(punchthrough)
            .ok_or(PunchthroughError::Unsupported)?;
        token.execute()
    }

    /// Allocate 2^order pages from host
    #[allow(dead_code)]
    fn alloc(&self, order: u32) -> Result<u64, error::Errno> {
        Host::alloc(order)
    }

    #[allow(dead_code)]
    fn exit(&self) {
        Host::exit();
    }

    #[allow(dead_code)]
    fn terminate(&self, reason_set: u64, reason_code: u64) -> ! {
        Host::terminate(reason_set, reason_code)
    }
}

impl<Host: HostInterface, T: Task> RawMutexProvider for LinuxKernel<Host, T> {
    type RawMutex = RawMutex<Host, T>;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        Self::RawMutex {
            inner: AtomicU32::new(0),
            host: core::marker::PhantomData,
        }
    }
}

/// An implementation of [`litebox::platform::RawMutex`]
pub struct RawMutex<Host: HostInterface, T: Task> {
    inner: AtomicU32,
    host: core::marker::PhantomData<(Host, T)>,
}

unsafe impl<Host: HostInterface, T: Task> Send for RawMutex<Host, T> {}
unsafe impl<Host: HostInterface, T: Task> Sync for RawMutex<Host, T> {}

/// TODO: common mutex implementation could be moved to a shared crate
impl<Host: HostInterface, T: Task> litebox::platform::RawMutex for RawMutex<Host, T> {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        Host::wake_many::<T>(&self.inner, n).unwrap()
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<litebox::platform::UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(time))
    }
}

impl<Host: HostInterface, T: Task> RawMutex<Host, T> {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        loop {
            // No need to wait if the value already changed.
            if self
                .underlying_atomic()
                .load(core::sync::atomic::Ordering::Relaxed)
                != val
            {
                return Err(ImmediatelyWokenUp);
            }

            let ret = Host::block_or_maybe_timeout::<T>(&self.inner, val, timeout);

            match ret {
                Ok(_) => {
                    if self
                        .underlying_atomic()
                        .load(core::sync::atomic::Ordering::Relaxed)
                        != val
                    {
                        return Ok(UnblockedOrTimedOut::Unblocked);
                    } else {
                        continue;
                    }
                }
                Err(error::Errno::EAGAIN) => {
                    // If the futex value does not match val, then the call fails
                    // immediately with the error EAGAIN.
                    return Err(ImmediatelyWokenUp);
                }
                Err(error::Errno::EINTR) => {
                    // return Err(ImmediatelyWokenUp);
                    todo!("EINTR");
                }
                Err(error::Errno::ETIMEDOUT) => {
                    return Ok(UnblockedOrTimedOut::TimedOut);
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }
    }
}

impl<Host: HostInterface, T: Task> DebugLogProvider for LinuxKernel<Host, T> {
    fn debug_log_print(&self, msg: &str) {
        Host::log(msg);
    }
}

/// An implementation of [`litebox::platform::Instant`]
pub struct Instant(u64);

impl<Host: HostInterface, T: Task> TimeProvider for LinuxKernel<Host, T> {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.0.checked_sub(earlier.0).map(|v| {
            core::time::Duration::from_micros(
                v / CPU_MHZ.load(core::sync::atomic::Ordering::Relaxed),
            )
        })
    }
}

impl Instant {
    fn rdtsc() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }

    fn now() -> Self {
        // let tsc = Self::rdtsc();
        // let ms = tsc / cpu_mhz;
        Instant(Self::rdtsc())
    }
}

impl<Host: HostInterface, T: Task> IPInterfaceProvider for LinuxKernel<Host, T> {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        match Host::send_ip_packet(packet) {
            Ok(n) => {
                if n != packet.len() {
                    unimplemented!()
                }
                Ok(())
            }
            Err(e) => {
                unimplemented!("Error: {:?}", e)
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        match Host::receive_ip_packet(packet) {
            Ok(n) => Ok(n),
            Err(e) => {
                unimplemented!("Error: {:?}", e)
            }
        }
    }
}

/// Platform-Host Interface
pub trait HostInterface {
    /// For memory allocation
    fn alloc(order: u32) -> Result<u64, error::Errno>;

    /// Exit
    ///
    /// Exit allows to come back to handle some requests from host,
    /// but it should not return back to the caller.
    fn exit() -> !;

    /// Terminate LiteBox
    fn terminate(reason_set: u64, reason_code: u64) -> !;

    /// For Punchthrough
    fn rt_sigprocmask(
        how: i32,
        set: Option<*const sigset_t>,
        old_set: Option<*mut sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, error::Errno>;

    fn wake_many<T: Task>(mutex: &AtomicU32, n: usize) -> Result<usize, error::Errno>;

    fn block_or_maybe_timeout<T: Task>(
        mutex: &AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), error::Errno>;

    /// For Network
    fn send_ip_packet(packet: &[u8]) -> Result<usize, error::Errno>;

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, error::Errno>;

    /// For Debugging
    fn log(msg: &str);
}
