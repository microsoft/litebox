//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![no_std]

use core::{arch::asm, sync::atomic::AtomicU32};

use litebox::platform::RawMutex as _;
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, ImmediatelyWokenUp, Provider, Punchthrough,
    PunchthroughError, PunchthroughProvider, PunchthroughToken, RawMutexProvider, TimeProvider,
    UnblockedOrTimedOut,
};

pub mod error;
pub mod host;

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`]
/// and a task that implements the [`Task`] trait.
pub struct LinuxKernel<Host: HostInterface, T: Task> {
    cpu_mhz: u64,
    host_and_task: core::marker::PhantomData<(Host, T)>,
}

/// Analogous to `task struct` in Linux
pub trait Task {
    fn current<'a>() -> Option<&'a mut Self>;

    /// Shared memory may be mapped to different address spaces in host and guest.
    /// This function is to convert the pointer to host address space.
    fn convert_ptr_to_host<T>(&self, ptr: *const T) -> *const T;
    /// Similar to [`Self::convert_ptr_to_host`], but for mutable pointers
    fn convert_mut_ptr_to_host<T>(&self, ptr: *mut T) -> *mut T;
}

/// Punchthrough for syscalls
///
/// The generic parameter `N` is the number of arguments for the syscall
/// The generic parameter `ID` is the syscall number
pub struct SyscallN<const N: usize, const ID: u32> {
    /// Arguments for the syscall
    args: [u64; N],
}

pub const NR_SYSCALL_FUTEX: u32 = 202;

/// Punchthrough for syscalls
pub enum LinuxPunchthrough {
    Futex(SyscallN<6, NR_SYSCALL_FUTEX>),
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
            LinuxPunchthrough::Futex(syscall) => Host::syscalls(syscall),
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
    /// Call futex syscall
    ///
    /// uaddr and uaddr2 are pointers to the underlying integer obtained from
    /// e.g., [`core::sync::atomic::AtomicU32::as_ptr`].
    /// Note all pointers should be in user space
    #[allow(clippy::too_many_arguments)]
    pub fn sys_futex(
        &mut self,
        uaddr: Option<*mut u32>,
        futex_op: i32,
        val: u32,
        timeout: Option<*const host::linux::Timespec>,
        uaddr2: Option<*mut u32>,
        val3: u32,
    ) -> Result<usize, PunchthroughError<error::Errno>> {
        let punchthrough = LinuxPunchthrough::Futex(SyscallN {
            args: [
                uaddr.map_or(0, |v| v as u64),
                futex_op as u64,
                val as u64,
                timeout.map_or(0, |t| t as u64),
                uaddr2.map_or(0, |v| v as u64),
                val3 as u64,
            ],
        });
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
            inner: Host::alloc_raw_mutex(),
            host: core::marker::PhantomData,
        }
    }
}

/// An implementation of [`litebox::platform::RawMutex`]
pub struct RawMutex<Host: HostInterface, T: Task> {
    inner: *mut AtomicU32,
    host: core::marker::PhantomData<(Host, T)>,
}

unsafe impl<Host: HostInterface, T: Task> Send for RawMutex<Host, T> {}
unsafe impl<Host: HostInterface, T: Task> Sync for RawMutex<Host, T> {}

impl<Host: HostInterface, T: Task> Drop for RawMutex<Host, T> {
    fn drop(&mut self) {
        Host::release_raw_mutex(self.inner);
    }
}

/// TODO: common mutex implementation could be moved to a shared crate
impl<Host: HostInterface, T: Task> litebox::platform::RawMutex for RawMutex<Host, T> {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        unsafe { &mut *self.inner }
    }

    fn wake_many(&self, n: usize) -> usize {
        Host::wake_many::<T>(self.inner, n).unwrap()
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

            let ret = Host::block_or_maybe_timeout::<T>(self.inner, val, timeout);

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
        Instant::now(self.cpu_mhz)
    }
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.0
            .checked_sub(earlier.0)
            .map(core::time::Duration::from_micros)
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

    fn now(cpu_mhz: u64) -> Self {
        let tsc = Self::rdtsc();
        let ms = tsc / cpu_mhz;
        Instant(ms)
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

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;

/// Platform-Host Interface
pub trait HostInterface {
    /// For memory allocation
    fn alloc(order: u32) -> Result<u64, error::Errno>;

    /// For exit/terminate
    ///
    /// Exit allows to come back to handle some requests from host,
    /// but it should not return back to the caller.
    /// TODO: add a callback func as argument
    fn exit();
    fn terminate(reason_set: u64, reason_code: u64) -> !;

    /// For Punchthrough
    fn syscalls<const N: usize, const ID: u32>(arg: SyscallN<N, ID>)
        -> Result<usize, error::Errno>;

    /// For RawMutex
    fn alloc_raw_mutex() -> *mut AtomicU32;

    fn release_raw_mutex(mutex: *mut AtomicU32);

    fn wake_many<T: Task>(mutex: *mut AtomicU32, n: usize) -> Result<usize, error::Errno> {
        let mutex = T::current().unwrap().convert_mut_ptr_to_host(mutex);
        Self::syscalls(crate::SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [mutex as u64, FUTEX_WAKE as u64, n as u64, 0, 0, 0],
        })
    }

    fn block_or_maybe_timeout<T: Task>(
        mutex: *mut AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), error::Errno> {
        let timeout = timeout.map(|t| host::linux::Timespec {
            tv_sec: t.as_secs() as i64,
            tv_nsec: t.subsec_nanos() as i64,
        });
        let mutex = T::current().unwrap().convert_mut_ptr_to_host(mutex);
        Self::syscalls(crate::SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [
                mutex as u64,
                FUTEX_WAIT as u64,
                val as u64,
                timeout.as_ref().map_or(0, |t| t as *const _ as u64),
                0,
                0,
            ],
        })
        .map(|_| ())
    }

    /// For Network
    fn send_ip_packet(packet: &[u8]) -> Result<usize, error::Errno>;

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, error::Errno>;

    /// For Debugging
    fn log(msg: &str);
}
