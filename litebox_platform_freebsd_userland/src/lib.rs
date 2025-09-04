//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland FreeBSD.

// Restrict this crate to only work on FreeBSD. For now, we are restricting this to only x86-64
// FreeBSD, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer};
use litebox::platform::{ThreadLocalStorageProvider, UnblockedOrTimedOut};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{ProtFlags, PunchthroughSyscall};

mod syscall_raw;
use syscall_raw::syscalls;

mod errno;

mod freebsd_types;

extern crate alloc;

/// Connector to a shim-exposed syscall-handling interface.
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<FreeBSDUserland>) -> usize;

/// The syscall handler passed down from the shim.
static SYSCALL_HANDLER: std::sync::RwLock<Option<SyscallHandler>> = std::sync::RwLock::new(None);

/// The userland FreeBSD platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct FreeBSDUserland {
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
}

const SELFPROC_MAPS_PATH: &str = "/proc/curproc/map";

impl FreeBSDUserland {
    /// Create a new userland-FreeBSD platform for use in `LiteBox`.
    pub fn new() -> &'static Self {
        let platform = Self {
            reserved_pages: Self::read_proc_self_maps(),
        };

        platform.set_init_tls();
        Box::leak(Box::new(platform))
    }

    /// Register the syscall handler (provided by the Linux shim)
    ///
    /// # Panics
    ///
    /// Panics if the function has already been invoked earlier.
    pub fn register_syscall_handler(&self, syscall_handler: SyscallHandler) {
        let old = SYSCALL_HANDLER.write().unwrap().replace(syscall_handler);
        assert!(
            old.is_none(),
            "Should not register more than one syscall_handler"
        );
    }

    fn read_proc_self_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is same as the on in LinuxUserland and might have
        // similar issues to be resolved.

        let path = SELFPROC_MAPS_PATH;

        let c_path = match std::ffi::CString::new(path) {
            Ok(p) => p,
            Err(_) => return alloc::vec::Vec::new(),
        };

        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Open,
                c_path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };

        let fd = match fd {
            Ok(fd) => fd,
            Err(_) => return alloc::vec::Vec::new(),
        };

        let mut buf = [0u8; 8192];
        let mut total_read = 0;

        loop {
            if total_read >= buf.len() {
                break;
            }

            let remaining = buf.len() - total_read;
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::Read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    remaining,
                )
            };

            match n {
                Ok(0) => break,
                Ok(bytes_read) => {
                    if bytes_read <= remaining {
                        total_read += bytes_read;
                    } else {
                        break;
                    }
                }
                Err(_) => {
                    // Close the file descriptor before returning
                    let _ = unsafe { syscalls::syscall1(syscalls::Sysno::Close, fd) };
                    return alloc::vec::Vec::new();
                }
            }
        }

        // Close the file descriptor
        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::Close, fd) };

        if total_read == 0 {
            return alloc::vec::Vec::new();
        }

        let content = match core::str::from_utf8(&buf[..total_read]) {
            Ok(s) => s,
            Err(_) => return alloc::vec::Vec::new(),
        };

        let mut reserved_pages = alloc::vec::Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: alloc::vec::Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 2 {
                continue;
            }

            // Parse FreeBSD format: start_addr end_addr ...other_fields...
            let start_str = parts[0].strip_prefix("0x").unwrap_or(parts[0]);
            let end_str = parts[1].strip_prefix("0x").unwrap_or(parts[1]);

            let start = match usize::from_str_radix(start_str, 16) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let end = match usize::from_str_radix(end_str, 16) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            if start <= end {
                reserved_pages.push(start..end);
            }
        }

        reserved_pages
    }

    fn get_user_info() -> litebox_common_linux::Credentials {
        litebox_common_linux::Credentials {
            uid: unsafe { syscalls::syscall0(syscalls::Sysno::Getuid) }.expect("getuid failed"),
            euid: unsafe { syscalls::syscall0(syscalls::Sysno::Geteuid) }.expect("geteuid failed"),
            gid: unsafe { syscalls::syscall0(syscalls::Sysno::Getgid) }.expect("getgid failed"),
            egid: unsafe { syscalls::syscall0(syscalls::Sysno::Getegid) }.expect("getegid failed"),
        }
    }

    fn set_init_tls(&self) {
        let mut tid: isize = 0;
        unsafe {
            syscalls::syscall1(syscalls::Sysno::ThrSelf, &mut tid as *mut isize as usize)
                .expect("thr_self failed");
        }

        let tid = i32::try_from(tid).expect("tid should fit in i32");
        let ppid =
            unsafe { syscalls::syscall0(syscalls::Sysno::Getppid) }.expect("Failed to get PPID");
        let ppid: i32 = i32::try_from(ppid).expect("ppid should fit in i32");
        let task = alloc::boxed::Box::new(litebox_common_linux::Task {
            pid: tid,
            tid,
            ppid,
            clear_child_tid: None,
            robust_list: None,
            credentials: alloc::sync::Arc::new(Self::get_user_info()),
        });

        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }
}

impl litebox::platform::Provider for FreeBSDUserland {}

impl litebox::platform::ExitProvider for FreeBSDUserland {
    type ExitCode = i32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;

    fn exit(&self, code: Self::ExitCode) -> ! {
        let Self { reserved_pages: _ } = self;

        unsafe { syscalls::syscall1(syscalls::Sysno::Exit, code as usize) }
            .expect("Failed to exit group");

        unreachable!("exit_group should not return");
    }
}

/// The arguments passed to the thread start function.
struct ThreadStartArgs {
    pt_regs: Box<litebox_common_linux::PtRegs>,
    thread_args: Box<litebox_common_linux::NewThreadArgs<FreeBSDUserland>>,
    entry_point: usize,
    /// Note `child_tid` is i32 on Linux but `long` on FreeBSD (though it always fits into i32).
    /// Have a separate field here instead of using the `tid` in [`litebox_common_linux::Task`]
    /// which is i32.
    child_tid: isize,
}

/// Thread start trampoline function for FreeBSD.
/// This is called by FreeBSD's thr_new and it unpacks the thread arguments.
extern "C" fn thread_start(arg: *mut ThreadStartArgs) {
    // SAFETY: The arg pointer is guaranteed to be valid and point to a ThreadStartArgs
    // that was created via Box::into_raw in spawn_thread.
    let mut thread_start_args = unsafe { Box::from_raw(arg) };

    // Store the pt_regs onto the stack (for restoration later)
    let pt_regs_stack = *(thread_start_args.pt_regs);

    // Reset TLS for the new thread
    unsafe {
        litebox_common_linux::wrgsbase(0);
    }

    thread_start_args.thread_args.task.tid = thread_start_args.child_tid.truncate();

    // Set up thread-local storage for the new thread. This is done by
    // calling the actual thread callback with the unpacked arguments
    (thread_start_args.thread_args.callback)(*(thread_start_args.thread_args));

    // Restore the context
    unsafe {
        core::arch::asm!(
            "mov rbx, {0}",
            "xor rax, rax",
            "mov rsp, {1}",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rcx",      // skip pt_regs.rax
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "add rsp, 24",  // skip orig_rax, rip, cs, eflags
            "popfq",
            "pop rsp",      // restore the stack pointer (which points to the entry point of the thread)
            "jmp rbx",
            in(reg) thread_start_args.entry_point,
            in(reg) &raw const pt_regs_stack.r11, // restore registers, starting from r11
            out("rax") _,
            options(nostack, preserves_flags)
        );
    }
}

impl litebox::platform::ThreadProvider for FreeBSDUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadArgs = litebox_common_linux::NewThreadArgs<FreeBSDUserland>;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;
    type ThreadId = usize;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        stack: TransparentMutPtr<u8>,
        stack_size: usize,
        entry_point: usize,
        thread_args: Box<Self::ThreadArgs>,
    ) -> Result<usize, Self::ThreadSpawnError> {
        let mut copied_pt_regs = Box::new(*ctx);

        // Reset the child stack pointer to the top of the allocated thread stack.
        copied_pt_regs.rsp = stack.as_usize() + stack_size - 0x8;

        let thread_start_args = ThreadStartArgs {
            pt_regs: copied_pt_regs,
            thread_args: thread_args,
            entry_point: entry_point,
            child_tid: 0,
        };

        // We should always use heap to pass the parameter to `thr_new`. This is to avoid using the parents'
        // stack, which may be freed (race-condition) before the child thread starts.
        let thread_start_arg_ptr = Box::into_raw(Box::new(thread_start_args));

        let parent_tid = core::mem::MaybeUninit::<isize>::uninit();

        let thr_param = freebsd_types::ThrParam {
            start_func: thread_start as usize as u64, // the child will enter `thread_start`
            arg: thread_start_arg_ptr as u64,         // thread start arguments
            stack_base: stack.as_usize() as u64,
            stack_size: stack_size as u64,
            tls_base: 0, // set by our callback
            tls_size: 0, // no need to specify it
            child_tid: thread_start_arg_ptr as u64
                + core::mem::offset_of!(ThreadStartArgs, child_tid) as u64,
            parent_tid: parent_tid.as_ptr() as u64,
            flags: 0,
            _pad: 0,
            rtp: 0, // we do not use real-time priority for now
        };

        // The parent will resume execution after this syscall `thr_new`.
        let result = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::ThrNew,
                &raw const thr_param as usize,
                size_of::<freebsd_types::ThrParam>(),
            )
        };

        match result {
            Ok(_) => {
                // FreeBSD `thr_new` returns 0 (to the parent) on success. The actual thread ID will
                // be written to `parent_tid` by the kernel. We need to read it from the structure.
                Ok(unsafe { parent_tid.assume_init() }.reinterpret_as_unsigned())
            }
            Err(errno) => Err(match errno {
                crate::errno::Errno::EACCES => litebox_common_linux::errno::Errno::EACCES,
                crate::errno::Errno::EAGAIN => litebox_common_linux::errno::Errno::EAGAIN,
                crate::errno::Errno::EBUSY => litebox_common_linux::errno::Errno::EBUSY,
                crate::errno::Errno::EEXIST => litebox_common_linux::errno::Errno::EEXIST,
                crate::errno::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                crate::errno::Errno::ENOMEM => litebox_common_linux::errno::Errno::ENOMEM,
                crate::errno::Errno::ENOSPC => litebox_common_linux::errno::Errno::ENOSPC,
                crate::errno::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
                _ => panic!("Unexpected error from thr_new: {errno}"),
            }),
        }
    }

    fn terminate_thread(&self, _code: Self::ExitCode) -> ! {
        // Use thr_exit to terminate the current thread
        unsafe {
            syscalls::syscall1(syscalls::Sysno::ThrExit, core::ptr::null::<()>() as usize)
                .expect("thr_exit should not fail");
        }
        // This should never be reached as thr_exit does not return
        unreachable!("thr_exit should not return")
    }
}

impl litebox::platform::RawMutexProvider for FreeBSDUserland {
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            inner: AtomicU32::new(0),
            num_to_wake_up: AtomicU32::new(0),
        }
    }
}

/// Raw mutex for FreeBSD.
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
    num_to_wake_up: AtomicU32,
}

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        use core::sync::atomic::Ordering::SeqCst;

        // We immediately wake up (without even hitting syscalls) if we can clearly see that the
        // value is different.
        if self.inner.load(SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        // Track some initial information.
        let mut first_time = true;
        let start = std::time::Instant::now();

        // We'll be looping unless we find a good reason to exit out of the loop, either due to a
        // wake-up or a time-out. We do a singular (only as a one-off) check for the
        // immediate-wake-up purely as an optimization, but otherwise, the only way to exit this
        // loop is to actually hit an `Ok` state out for this function.
        loop {
            let remaining_time = match timeout {
                None => None,
                Some(timeout) => match timeout.checked_sub(start.elapsed()) {
                    None => {
                        break Ok(UnblockedOrTimedOut::TimedOut);
                    }
                    Some(remaining_time) => Some(remaining_time),
                },
            };

            // We wait on the umtx_op, with a timeout if needed; the timeout is based on how much time
            // remains to be elapsed.
            match umtx_op_operation_timeout(
                &self.num_to_wake_up,
                freebsd_types::UmtxOpOperation::UMTX_OP_WAIT_UINT,
                /* expected value */ 0,
                remaining_time,
            ) {
                Ok(0) => {
                    // Fallthrough: just let the waker to clean up the value.
                    return Ok(UnblockedOrTimedOut::Unblocked);
                }
                Err(e) if e == i32::from(crate::errno::Errno::EAGAIN) as isize => {
                    // A wake-up was already in progress when we attempted to wait. Has someone
                    // already touched inner value? We only check this on the first time around,
                    // anything else could be a true wake.
                    if first_time && self.inner.load(SeqCst) != val {
                        // Ah, we seem to have actually been immediately woken up! Let us not
                        // miss this.
                        return Err(ImmediatelyWokenUp);
                    } else {
                        // Try again.
                        first_time = false;
                    }
                }
                Err(e) => {
                    panic!("Unexpected errno={e} for UMTX_OP_WAIT")
                }
                _ => unreachable!(),
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    /// Wake up multiple waiters.
    /// Always returns `n` on success, and `0` on failure.
    fn wake_many(&self, n: usize) -> usize {
        use core::sync::atomic::Ordering::SeqCst;

        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();
        // The highest two bits are always reserved as "lock bits".
        let n = n.min((1 << 30) - 1);

        // For FreeBSD, we can't do the same requeue trick as Linux futex, nor can we infer
        // the actually woken up count, so we always clear the `num_to_wake_up` value
        // and let the kernel decide the number of threads to wake up.

        // Set the number of waiters we want allowed to know that they can wake up, while
        // also grabbing the "lock bit"s.
        while self
            .num_to_wake_up
            .compare_exchange(0, n | (0b11 << 30), SeqCst, SeqCst)
            .is_err()
        {
            // If someone else is _also_ attempting to wake waiters up, then we should just spin
            // until the other waker is done with their job and brings the value down.
            core::hint::spin_loop();
        }

        // Now we can actually wake them up using FreeBSD's umtx_op and it always returns 0
        // on success. We cannot ask the kernel how many were woken up.
        match umtx_op_operation_timeout(
            &self.num_to_wake_up,
            freebsd_types::UmtxOpOperation::UMTX_OP_WAKE,
            n as usize, // Number of threads to wake
            None,       // No timeout for wake operations
        ) {
            Err(_) => {
                // Wake failed.
                return 0;
            }
            Ok(_) => {
                // Unlock the lock bits and clean up the value, allowing other wakers to run.
                self.num_to_wake_up.store(0, SeqCst);
                return n as usize;
            }
        };
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
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl litebox::platform::IPInterfaceProvider for FreeBSDUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        unimplemented!(
            "send_ip_packet is not implemented for FreeBSD yet. packet length: {}",
            packet.len()
        );
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        unimplemented!(
            "receive_ip_packet is not implemented for FreeBSD yet. packet length: {}",
            packet.len()
        );
    }
}

impl litebox::platform::TimeProvider for FreeBSDUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: litebox_common_linux::Timespec {
                tv_sec: i64::from(t.tv_sec),
                tv_nsec: u64::from(t.tv_nsec.reinterpret_as_unsigned()),
            },
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: litebox_common_linux::Timespec {
                tv_sec: i64::from(t.tv_sec),
                tv_nsec: u64::from(t.tv_nsec.reinterpret_as_unsigned()),
            },
        }
    }
}

pub struct Instant {
    inner: litebox_common_linux::Timespec,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.inner.sub_timespec(&earlier.inner).ok()
    }
}

impl From<litebox_common_linux::Timespec> for Instant {
    fn from(inner: litebox_common_linux::Timespec) -> Self {
        Instant { inner }
    }
}

pub struct SystemTime {
    inner: litebox_common_linux::Timespec,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: litebox_common_linux::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .sub_timespec(&earlier.inner)
            .map_err(|_errno| earlier.inner.sub_timespec(&self.inner).unwrap())
    }
}

pub struct PunchthroughToken {
    punchthrough: PunchthroughSyscall<FreeBSDUserland>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = PunchthroughSyscall<FreeBSDUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                unsafe { litebox_common_linux::wrfsbase(addr) };
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase { addr } => {
                use litebox::platform::RawMutPointer as _;
                let fs_base = unsafe { litebox_common_linux::rdfsbase() };
                unsafe { addr.write_at_offset(0, fs_base) }.ok_or(
                    litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EFAULT,
                    ),
                )?;
                Ok(0)
            }
            PunchthroughSyscall::WakeByAddress { addr } => unsafe {
                syscalls::syscall5(
                    syscalls::Sysno::UmtxOp,
                    addr.as_usize(),
                    freebsd_types::UmtxOpOperation::UMTX_OP_WAKE as usize,
                    1,
                    addr.as_usize(),
                    0,
                )
            }
            .map_err(|err| match err {
                errno::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                _ => panic!("unexpected error {err}"),
            })
            .map_err(litebox::platform::PunchthroughError::Failure),
            _ => {
                unimplemented!(
                    "PunchthroughToken for FreeBSDUserland is not fully implemented yet"
                );
            }
        }
    }
}

impl litebox::platform::PunchthroughProvider for FreeBSDUserland {
    type PunchthroughToken = PunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for FreeBSDUserland {
    fn debug_log_print(&self, msg: &str) {
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Write,
                freebsd_types::STDERR_FILENO as usize,
                msg.as_ptr() as usize,
                msg.len(),
            )
        };
    }
}

// Several _umtx_op() operations allow the blocking time to
// be limited, failing the request if it cannot be satisfied
// in the specified time period. The timeout is specified
// by passing either the address of struct timespec, or its
// extended variant, struct _umtx_time, as the uaddr2 argu-
// ment of _umtx_op(). They are distinguished by the uaddr
// value, which must be equal to the size of the structure
// pointed to by uaddr2, casted to uintptr_t.
fn umtx_op_operation_timeout(
    obj: &AtomicU32,
    op: freebsd_types::UmtxOpOperation,
    val: usize,
    timeout: Option<Duration>,
) -> Result<usize, isize> {
    let obj_ptr = obj as *const AtomicU32 as usize;
    let op: i32 = op as _;
    let timeout_spec = timeout.map(|t| {
        let tv_sec = t.as_secs() as i64;
        let tv_nsec = t.subsec_nanos() as i64;
        libc::timespec { tv_sec, tv_nsec }
    });

    let (uaddr, uaddr2) = if let Some(ref ts) = timeout_spec {
        // When timeout is provided, uaddr must be size of timespec
        // and uddr2 must point to the timespec structure.
        (
            core::mem::size_of::<libc::timespec>(),
            ts as *const libc::timespec as usize,
        )
    } else {
        (obj_ptr, 0)
    };

    unsafe {
        syscalls::syscall5(
            syscalls::Sysno::UmtxOp,
            obj_ptr,
            op as usize,
            val as usize,
            uaddr,
            uaddr2,
        )
    }
    .map_err(|err| i32::from(err) as isize)
}

impl litebox::platform::RawPointerProvider for FreeBSDUserland {
    type RawConstPointer<T: Clone> = litebox::platform::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = litebox::platform::trivial_providers::TransparentMutPtr<T>;
}

fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for FreeBSDUserland {
    const TASK_ADDR_MIN: usize = 0x1000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        // Use FreeBSD's mmap flags
        let map_flags = freebsd_types::MapFlags::MAP_PRIVATE
            | freebsd_types::MapFlags::MAP_ANONYMOUS
            | (if fixed_address {
                freebsd_types::MapFlags::MAP_FIXED
            } else {
                freebsd_types::MapFlags::empty()
            } | if can_grow_down {
                freebsd_types::MapFlags::MAP_STACK
            } else {
                freebsd_types::MapFlags::empty()
            } | if populate_pages_immediately {
                freebsd_types::MapFlags::MAP_PREFAULT_READ
            } else {
                freebsd_types::MapFlags::empty()
            });

        let ptr = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::Mmap,
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                map_flags.bits().reinterpret_as_unsigned() as usize,
                -1isize as usize,
                0,
            )
        }
        .expect("mmap failed");

        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: ptr as *mut u8,
        })
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::Munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        unimplemented!(
            "remap_pages is not implemented for FreeBSDUserland. old_range: {:?}, new_range: {:?}",
            old_range,
            new_range
        );
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

impl litebox::platform::StdioProvider for FreeBSDUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        use std::io::Read as _;
        std::io::stdin().read(buf).map_err(|err| {
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                litebox::platform::StdioReadError::Closed
            } else {
                panic!("unhandled error {err}")
            }
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        match unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Write,
                usize::try_from(match stream {
                    litebox::platform::StdioOutStream::Stdout => freebsd_types::STDOUT_FILENO,
                    litebox::platform::StdioOutStream::Stderr => freebsd_types::STDERR_FILENO,
                })
                .unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
            )
        } {
            Ok(n) => Ok(n),
            Err(err) => panic!("unhandled error {err}"),
        }
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        use litebox::platform::StdioStream;
        use std::io::IsTerminal as _;
        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, FreeBSDUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for FreeBSDUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );
        unsafe {
            syscalls::syscall6(
                syscalls::Sysno::Mmap,
                0,
                size,
                ProtFlags::PROT_READ_WRITE.bits().reinterpret_as_unsigned() as usize,
                ((freebsd_types::MapFlags::MAP_PRIVATE | freebsd_types::MapFlags::MAP_ANON)
                    .bits()
                    .reinterpret_as_unsigned()) as usize,
                usize::MAX,
                0,
            )
        }
        .map(|addr| (addr, size))
        .ok()
    }

    unsafe fn free(_addr: usize) {
        todo!();
    }
}

core::arch::global_asm!(
    "
    .text
    .align  4
    .globl  syscall_callback
    .type   syscall_callback,@function
syscall_callback:
    /* TODO: save float and vector registers (xsave or fxsave) */
    /* Save caller-saved registers */
    push    0x2b       /* pt_regs->ss = __USER_DS */
    push    rsp        /* pt_regs->sp */
    pushfq             /* pt_regs->eflags */
    push    0x33       /* pt_regs->cs = __USER_CS */
    push    rcx
    mov     rcx, [rsp + 0x28] /* get the return address from the stack */
    xchg    rcx, [rsp] /* pt_regs->ip */
    push    rax        /* pt_regs->orig_ax */

    push    rdi         /* pt_regs->di */
    push    rsi         /* pt_regs->si */
    push    rdx         /* pt_regs->dx */
    push    rcx         /* pt_regs->cx */
    push    -38         /* pt_regs->ax = ENOSYS */
    push    r8          /* pt_regs->r8 */
    push    r9          /* pt_regs->r9 */
    push    r10         /* pt_regs->r10 */
    push    r11         /* pt_regs->r11 */
    push    rbx         /* pt_regs->bx */
    push    rbp         /* pt_regs->bp */

    sub rsp, 32         /* skip r12-r15 */

    /* Save the original stack pointer */
    mov  rbp, rsp

    /* Align the stack to 16 bytes */
    and rsp, -16

    /* Pass the syscall number to the syscall dispatcher */
    mov rdi, rax
    /* Pass pt_regs saved on stack to syscall_dispatcher */
    mov rsi, rbp

    /* Call syscall_handler */
    call syscall_handler

    /* Restore the original stack pointer */
    mov  rsp, rbp
    add  rsp, 32         /* skip r12-r15 */

    /* Restore caller-saved registers */
    pop  rbp
    pop  rbx
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rcx             /* skip pt_regs->ax */
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi

    add  rsp, 24         /* skip orig_rax, rip, cs */
    popfq
    add  rsp, 16         /* skip rsp, ss */

    /* Return to the caller */
    ret
"
);

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
#[unsafe(no_mangle)]
unsafe extern "C" fn syscall_handler(
    syscall_number: usize,
    ctx: *mut litebox_common_linux::PtRegs,
) -> usize {
    // SAFETY: By the requirements of this function, it's safe to dereference a valid pointer to `PtRegs`.
    let ctx = unsafe { &mut *ctx };
    match litebox_common_linux::SyscallRequest::try_from_raw(syscall_number, ctx) {
        Ok(d) => {
            let syscall_handler: SyscallHandler = SYSCALL_HANDLER
                .read()
                .unwrap()
                .expect("Should have run `register_syscall_handler` by now");
            syscall_handler(d)
        }
        Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
    }
}

impl litebox::platform::SystemInfoProvider for FreeBSDUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

impl FreeBSDUserland {
    fn get_thread_local_storage() -> *mut litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>
    {
        let tls = unsafe { litebox_common_linux::rdgsbase() };
        if tls == 0 {
            return core::ptr::null_mut();
        }
        tls as *mut litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>
    }
}

/// Similar to libc, we use fs/gs registers to store thread-local storage (TLS).
/// To avoid conflicts with libc's TLS, we choose to use gs on x86_64 and fs on x86
/// as libc uses fs on x86_64 and gs on x86.
impl litebox::platform::ThreadLocalStorageProvider for FreeBSDUserland {
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>;

    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        let old_gs_base = unsafe { litebox_common_linux::rdgsbase() };
        assert!(old_gs_base == 0, "TLS already set for this thread");
        let tls = Box::new(tls);
        unsafe { litebox_common_linux::wrgsbase(Box::into_raw(tls) as usize) };
    }

    fn release_thread_local_storage(&self) -> Self::ThreadLocalStorage {
        let tls = Self::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before releasing it");
        unsafe {
            litebox_common_linux::wrgsbase(0);
        }
        let tls = unsafe { Box::from_raw(tls) };
        assert!(!tls.borrowed, "TLS must not be borrowed when releasing it");
        *tls
    }

    fn with_thread_local_storage_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::ThreadLocalStorage) -> R,
    {
        let tls = Self::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before accessing it");
        let tls = unsafe { &mut *tls };
        assert!(!tls.borrowed, "TLS is already borrowed");
        tls.borrowed = true; // Mark as borrowed
        let res = f(tls);
        tls.borrowed = false; // Mark as not borrowed anymore
        res
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use litebox::platform::RawMutex;
    use litebox::platform::ThreadLocalStorageProvider as _;
    use std::thread::sleep;

    use crate::FreeBSDUserland;
    use litebox::platform::{DebugLogProvider, PageManagementProvider};

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
            num_to_wake_up: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = FreeBSDUserland::new();

        platform.debug_log_print("msg from FreeBSDUserland test_reserved_pages\n");

        let reserved_pages: Vec<_> =
            <FreeBSDUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    #[test]
    fn test_tls() {
        let platform = FreeBSDUserland::new();
        let tls = FreeBSDUserland::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS should not be null");
        let tid = unsafe { (*tls).current_task.tid };

        platform.with_thread_local_storage_mut(|tls| {
            assert_eq!(
                tls.current_task.tid, tid,
                "TLS should have the correct task ID"
            );
            tls.current_task.tid = 0x1234; // Change the task ID
        });
        let tls = platform.release_thread_local_storage();
        assert_eq!(
            tls.current_task.tid, 0x1234,
            "TLS should have the correct task ID"
        );

        let tls = FreeBSDUserland::get_thread_local_storage();
        assert!(tls.is_null(), "TLS should be null after releasing it");
    }
}
