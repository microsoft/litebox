//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland FreeBSD.

// Restrict this crate to only work on FreeBSD. For now, we are restricting this to only x86/x86-64
// FreeBSD, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(
    target_os = "freebsd",
    any(target_arch = "x86_64", target_arch = "x86")
))]
use core::panic;
// use core::num;
// use std::os::fd::{AsRawFd as _, FromRawFd as _};
use core::sync::atomic::AtomicU32;
// use std::sync::atomic::Ordering::SeqCst;
use core::mem::size_of;
use core::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer, RawMutPointer};
use litebox::platform::{ThreadLocalStorageProvider, UnblockedOrTimedOut};
// use litebox::platform::{ImmediatelyWokenUp, RawConstPointer, ThreadLocalStorageProvider};
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox_common_linux::{ProtFlags, PunchthroughSyscall};
// use litebox_common_linux::{CloneFlags, MRemapFlags, MapFlags, ProtFlags, PunchthroughSyscall};

pub mod syscall_raw;
use syscall_raw::syscalls;

pub mod errno;

mod freebsd_types;
// todo(chuqi): we do not use systrap for now as there's no sccomp interception on FreeBSD.
// mod syscall_intercept;

extern crate alloc;

/// Connector to a shim-exposed syscall-handling interface.
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<FreeBSDUserland>) -> isize;

/// The syscall handler passed down from the shim.
static SYSCALL_HANDLER: std::sync::RwLock<Option<SyscallHandler>> = std::sync::RwLock::new(None);

/// The userland FreeBSD platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
#[allow(dead_code)]
pub struct FreeBSDUserland {
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    // seccomp_interception_enabled: std::sync::atomic::AtomicBool,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
}

const SELFPROC_MAPS_PATH: &str = "/proc/curproc/map";

impl FreeBSDUserland {
    /// Create a new userland-FreeBSD platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(_tun_device_name: Option<&str>) -> &'static Self {
        // todo(chuqi): ignore tun device for now
        let tun_socket_fd = std::sync::RwLock::new(None);

        let platform = Self {
            tun_socket_fd,
            // seccomp_interception_enabled: std::sync::atomic::AtomicBool::new(false),
            reserved_pages: Self::read_proc_self_maps(),
        };

        platform.set_init_tls();
        Box::leak(Box::new(platform))
    }

    /// Register the syscall handler (provided by the FreeBSD shim)
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

    /// Enable seccomp syscall interception on the platform.
    ///
    /// # Panics
    ///
    /// Panics if this function has already been invoked on the platform earlier.
    pub fn enable_seccomp_based_syscall_interception(&self) {
        // todo(chuqi): we do not support seccomp for FreeBSD
        unimplemented!("seccomp interception is not supported on FreeBSD");
    }

    // todo(chuqi): the /procfs is not guaranteed to be mounted for FreeBSD,
    // in the future, we should use `sysctl` syscall to do this.
    fn read_proc_self_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.

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

        let task = alloc::boxed::Box::new(litebox_common_linux::Task {
            tid: i32::try_from(tid).expect("tid should fit in i32"),
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
        let Self {
            tun_socket_fd: _,
            reserved_pages: _,
        } = self;

        // todo(chuqi): ignore tun device for now
        // drop::<Option<std::os::fd::OwnedFd>>(tun_socket_fd.write().unwrap().take());

        // And then we actually exit
        unsafe { syscalls::syscall1(syscalls::Sysno::Exit, code as usize) }
            .expect("Failed to exit group");

        unreachable!("exit_group should not return");
    }
}

/// The arguments passed to the thread start function.
pub struct ThreadStartArgs {
    pub pt_regs: Box<litebox_common_linux::PtRegs>,
    pub thread_args: Box<litebox_common_linux::NewThreadArgs<FreeBSDUserland>>,
    pub entry_point: usize,
}

/// Thread start trampoline function for FreeBSD.
/// This is called by FreeBSD's thr_new and unpacks the thread arguments.
extern "C" fn thread_start(arg: *mut ThreadStartArgs) {
    // SAFETY: The arg pointer is guaranteed to be valid and point to a ThreadStartArgs
    // that was created via Box::into_raw in spawn_thread.
    let thread_start_args = unsafe { Box::from_raw(arg) };

    // SAFETY: Similarly, the pointers inside ThreadStartArgs are valid and were created
    // via Box::into_raw in spawn_thread.
    let pt_regs = thread_start_args.pt_regs;
    let thread_args = thread_start_args.thread_args;

    let entry_point = thread_start_args.entry_point;
    let pt_regs_stack = *pt_regs;

    // Reset TLS for the new thread
    // todo(chuqi): support x86
    unsafe {
        litebox_common_linux::wrgsbase(0);
    }

    // Set up thread-local storage for the new thread. This is done by
    // calling the actual thread callback with the unpacked arguments
    (thread_args.callback)(*thread_args);

    // Restore the context
    // todo(chuqi): support x86
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
            in(reg) entry_point,
            in(reg) &raw const pt_regs_stack.r11, // restore registers, starting from r11
            out("rax") _,
            options(nostack, preserves_flags)
        );
    }
}

pub type ThreadLocalDescriptor = u8;

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
        mut thread_args: Box<Self::ThreadArgs>,
    ) -> Result<usize, Self::ThreadSpawnError> {
        let child_tid_ptr = core::ptr::from_mut(thread_args.task.as_mut()) as u64
            + core::mem::offset_of!(litebox_common_linux::Task<FreeBSDUserland>, tid) as u64;

        let mut copied_pt_regs = Box::new(*ctx);

        // Reset the child stack pointer to the top of the allocated thread stack.
        copied_pt_regs.rsp = stack.as_usize() + stack_size - 0x8;

        let thread_args = thread_args;

        let thread_start_args = ThreadStartArgs {
            pt_regs: copied_pt_regs,
            thread_args: thread_args,
            entry_point: entry_point,
        };

        // we should use heap to pass the parameter to avoid using the parents'
        // stack, which may be freed (race-condition) before the thread starts.
        let thread_start_arg_ptr = Box::into_raw(Box::new(thread_start_args));

        let thr_param = freebsd_types::ThrParam {
            start_func: thread_start as usize as u64,
            arg: thread_start_arg_ptr as u64,
            stack_base: stack.as_usize() as u64,
            stack_size: stack_size as u64,
            tls_base: 0, // set by our callback
            tls_size: 0, // no need to specify it
            child_tid: child_tid_ptr,
            parent_tid: 0,
            flags: 0,
            _pad: 0,
            rtp: 0, // we do not use real-time priority for now
        };

        // todo(chuqi): distinguish between x86 and x86_64
        let result = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::ThrNew,
                &raw const thr_param as usize,
                size_of::<freebsd_types::ThrParam>(),
            )
        };

        match result {
            Ok(_) => {
                // FreeBSD thr_new returns 0 on success. The actual thread ID will be written
                // to child_tid_ptr by the kernel. We need to read it from the structure.
                Ok(unsafe { *(child_tid_ptr as *const i32) as usize })
            }
            Err(errno) => {
                // todo(chuqi): handle errno properly
                Err(
                    litebox_common_linux::errno::Errno::try_from(i32::from(errno))
                        .unwrap_or(litebox_common_linux::errno::Errno::EINVAL),
                )
            }
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

// This raw-mutex design takes up more space than absolutely ideal and may possibly be optimized if
// we can allow for spurious wake-ups. However, the current design makes sure that spurious wake-ups
// do not actually occur, and that something that is `block`ed can only be woken up by a `wake`.
#[allow(dead_code)]
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
    // The `num_to_wake_up` is the actually what the futexes rely upon, and is a bit-field.
    //
    // The uppermost two bits (1<<31, and 1<<30) act as a "lock bit" for the waker (we use two of
    // them to make it easier to catch accidental integer wrapping bugs more easily, at the cost of
    // supporting "only" 1-billion waiters being woken up at once), preventing multiple wakers from
    // running at the same time.
    //
    // The lower 30 bits indicate how many waiters the waker wants to wake up. The waiters
    // themselves will decrement this number as they wake up, but should make sure not to overflow
    // (this is why we use two bits for the lock bit---to catch implementation bugs of this kind).
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
                    // Fallthrough: check if spurious.
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
                        // Fallthrough: check if spurious. A wake-up was already in progress
                        // when we attempted to wait, so we can do a proper check.
                    }
                }
                Err(e) => {
                    panic!("Unexpected errno={e} for UMTX_OP_WAIT")
                }
                _ => unreachable!(),
            }

            // We have either been woken up, or this is spurious. Let us check if we were
            // actually woken up.
            match self.num_to_wake_up.fetch_update(SeqCst, SeqCst, |n| {
                if n & (1 << 31) == 0 {
                    // No waker in play, do nothing to the value
                    None
                } else if n & ((1 << 30) - 1) > 0 {
                    // There is a waker, and there is still capacity to wake up
                    Some(n - 1)
                } else {
                    // There is a waker, but capacity is gone
                    None
                }
            }) {
                Ok(_) => {
                    // We marked ourselves as having woken up, we can exit, marking
                    // ourselves as no longer waiting.
                    break Ok(UnblockedOrTimedOut::Unblocked);
                }
                Err(_) => {
                    // We have not yet been asked to wake up, this is spurious. Spin that
                    // loop again.
                    first_time = false;
                }
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        use core::sync::atomic::Ordering::SeqCst;

        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        // We restrict ourselves to a max of ~1 billion waiters being woken up at once, which should
        // be good enough, but makes sure we are not clobbering the "lock bits".
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
        // on success, so we cannot ask the kernel how many were woken up.
        let num_woken_up = match umtx_op_operation_timeout(
            &self.num_to_wake_up,
            freebsd_types::UmtxOpOperation::UMTX_OP_WAKE,
            n,    // number of threads to wake
            None, // no timeout for wake operations
        ) {
            Ok(_) => n,  // todo(chuqi): always assume all were woken up on success returns.
            Err(_) => 0, // If wake fails, assume 0 were woken
        };

        // Unlock the lock bits, allowing other wakers to run.
        let remain = n - num_woken_up;

        while let Err(v) = self.num_to_wake_up.fetch_update(SeqCst, SeqCst, |v| {
            // Due to spurious or immediate wake-ups (i.e., unexpected wakeups that may decrease `num_to_wake_up`),
            // `num_to_wake_up` might end up being less than expected. Thus, we check `<=` rather than `==`.
            // If some threads are successfully woken up, `num_to_wake_up` should be larger than remain, the `else`
            // condition will be triggered.
            // The waker will spin until `num_to_wake_up` is decremented by the wait thread.
            if v & ((1 << 30) - 1) <= remain {
                Some(0)
            } else {
                // If the waker successfully woke up some threads, we just fall through here
                // and wait for the wait thread to decrement the `num_to_wake_up` value.
                None
            }
        }) {
            // Confirm that no one has clobbered the lock bits (which would indicate an implementation
            // failure somewhere).
            debug_assert_eq!(v >> 30, 0b11, "lock bits should remain unclobbered");
            core::hint::spin_loop();
        }

        // Return the number that were actually woken up
        num_woken_up.try_into().unwrap()
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

    fn now(&self) -> Self::Instant {
        Instant {
            inner: std::time::Instant::now(),
        }
    }
}

pub struct Instant {
    inner: std::time::Instant,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.inner.checked_duration_since(earlier.inner)
    }
}

/// Check if the CPU supports FSGSBASE instructions on FreeBSD.
///
/// On FreeBSD, we can detect this using the CPUID instruction directly
/// or fall back to sysctl if available. For now, we'll use a conservative
/// approach and try the instruction with error handling.
// todo(chuqi): x86 support
fn has_fsgsbase_support() -> bool {
    // On FreeBSD, we can check for FSGSBASE support using CPUID
    // FSGSBASE is indicated by CPUID.(EAX=07H, ECX=0):EBX[bit 0]
    unsafe {
        let eax = 7u32;
        let ecx = 0u32;
        let ebx: u32;

        // Save and restore rbx since it's used by LLVM
        core::arch::asm!(
            "mov {rbx_save}, rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "mov rbx, {rbx_save}",
            rbx_save = out(reg) _,
            ebx_out = out(reg) ebx,
            in("eax") eax,
            in("ecx") ecx,
            out("edx") _,
        );

        // FSGSBASE is bit 0 of EBX when EAX=7, ECX=0
        (ebx & 1) != 0
    }
}

/// Get the current fs base register value.
///
/// Depending on whether `fsgsbase` instructions are enabled, we choose
/// between `arch_prctl` or `rdfsbase` to get the fs base.
#[cfg(target_arch = "x86_64")]
fn get_fs_base() -> Result<usize, litebox_common_linux::errno::Errno> {
    /// Function pointer to get the current fs base.
    static GET_FS_BASE: spin::Once<fn() -> Result<usize, litebox_common_linux::errno::Errno>> =
        spin::Once::new();
    GET_FS_BASE.call_once(|| {
        if has_fsgsbase_support() {
            || Ok(unsafe { litebox_common_linux::rdfsbase() })
        } else {
            get_fs_base_arch_prctl
        }
    })()
}

/// Set the fs base register value.
///
/// Depending on whether `fsgsbase` instructions are enabled, we choose
/// between `arch_prctl` or `wrfsbase` to set the fs base.
#[cfg(target_arch = "x86_64")]
fn set_fs_base(fs_base: usize) -> Result<usize, litebox_common_linux::errno::Errno> {
    static SET_FS_BASE: spin::Once<fn(usize) -> Result<usize, litebox_common_linux::errno::Errno>> =
        spin::Once::new();
    SET_FS_BASE.call_once(|| {
        if has_fsgsbase_support() {
            |fs_base| {
                unsafe { litebox_common_linux::wrfsbase(fs_base) };
                Ok(0)
            }
        } else {
            set_fs_base_arch_prctl
        }
    })(fs_base)
}

/// Get fs register value via syscall `sysarch` (FreeBSD equivalent of Linux arch_prctl).
// todo(chuqi): x86 support
fn get_fs_base_arch_prctl() -> Result<usize, litebox_common_linux::errno::Errno> {
    let mut fs_base = core::mem::MaybeUninit::<usize>::uninit();
    unsafe {
        syscalls::syscall2(
            syscall_raw::SyscallTable::Sysarch,
            freebsd_types::AMD64_GET_FSBASE as usize,
            fs_base.as_mut_ptr() as usize,
        )
    }
    .map_err(|err| match err {
        errno::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        errno::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
        _ => unimplemented!("unexpected error {err}"),
    })?;
    Ok(unsafe { fs_base.assume_init() })
}

/// Set fs register value via syscall `arch_prctl`.
// todo(chuqi): x86 support
fn set_fs_base_arch_prctl(fs_base: usize) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe {
        syscalls::syscall2(
            syscall_raw::SyscallTable::Sysarch,
            freebsd_types::AMD64_SET_FSBASE as usize,
            fs_base,
        )
    }
    .map_err(|err| match err {
        errno::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        errno::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
        _ => unimplemented!("unexpected error {err}"),
    })
}

#[allow(dead_code)]
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
            PunchthroughSyscall::RtSigprocmask { how, set, oldset } => {
                // FreeBSD uses sigprocmask instead of rt_sigprocmask
                // and doesn't need sigsetsize parameter
                
                // Convert Linux SigmaskHow to FreeBSD values (they should be the same)
                let how_val = how as usize;
                
                // Handle the set parameter
                let set_ptr = if let Some(set) = set {
                    // Read the signal set from the provided pointer
                    let sig_set = unsafe { set.read_at_offset(0) }
                        .ok_or(litebox::platform::PunchthroughError::Failure(
                            litebox_common_linux::errno::Errno::EFAULT,
                        ))?
                        .into_owned();
                    
                    // Note: FreeBSD doesn't require special handling of SIGSYS
                    // since it doesn't use Seccomp
                    core::ptr::from_ref(&sig_set) as usize
                } else {
                    0
                };
                
                // Handle the oldset parameter
                let oldset_ptr = oldset.map_or(0, |ptr| ptr.as_usize());
                
                // Call FreeBSD's sigprocmask syscall
                unsafe {
                    syscalls::syscall3(
                        syscall_raw::SyscallTable::Sigprocmask,
                        how_val,
                        set_ptr,
                        oldset_ptr,
                    )
                }
                .map_err(|err| match err {
                    errno::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    errno::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::RtSigaction {
                signum,
                act,
                oldact,
            } => {
                // FreeBSD uses sigaction instead of rt_sigaction
                let act_ptr = act.map_or(0, |ptr| ptr.as_usize());
                let oldact_ptr = oldact.map_or(0, |ptr| ptr.as_usize());
                
                unsafe {
                    syscalls::syscall3(
                        syscall_raw::SyscallTable::Sigaction,
                        signum as usize,
                        act_ptr,
                        oldact_ptr,
                    )
                }
                .map_err(|err| match err {
                    errno::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    errno::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::SetFsBase { addr } => {
                set_fs_base(addr).map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::GetFsBase { addr } => {
                let fs_base =
                    get_fs_base().map_err(litebox::platform::PunchthroughError::Failure)?;
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
            // todo(chuqi): add more punchthroughs
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
    val: u32,
    timeout: Option<Duration>,
) -> Result<usize, isize> {
    let obj_ptr = obj as *const AtomicU32 as usize;
    let op: i32 = op as _;
    let timeout_spec = timeout.map(|t| {
        const TEN_POWER_NINE: u128 = 1_000_000_000;
        let nanos: u128 = t.as_nanos();
        let tv_sec = nanos
            .checked_div(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        let tv_nsec = nanos
            .checked_rem(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
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
            if timeout_spec.is_some() {
                obj_ptr
            } else {
                uaddr
            },
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
    fn allocate_pages(
        &self,
        range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        // Use FreeBSD's mmap flags
        let map_flags = freebsd_types::MapFlags::MAP_PRIVATE
            | freebsd_types::MapFlags::MAP_ANONYMOUS
            | freebsd_types::MapFlags::MAP_FIXED
            | (if can_grow_down {
                freebsd_types::MapFlags::MAP_STACK
            } else {
                freebsd_types::MapFlags::empty()
            } | if populate_pages {
                freebsd_types::MapFlags::MAP_PREFAULT_READ
            } else {
                freebsd_types::MapFlags::empty()
            });

        let ptr = unsafe {
            syscalls::syscall6(
                // todo(chuqi): add x86 support
                syscalls::Sysno::Mmap,
                range.start,
                range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                map_flags.bits().reinterpret_as_unsigned() as usize,
                usize::MAX, // -1 for anonymous mapping
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
            // todo(chuqi): handle EPIPE
            // Err(syscalls::Errno::EPIPE) => Err(litebox::platform::StdioWriteError::Closed),
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
                syscalls::Sysno::Mmap, // todo(chuqi): add x86 support
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

// todo(chuqi): differentiate between x86 and x86_64
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
) -> isize {
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
        Err(err) => err.as_neg() as isize,
    }
}

impl litebox::platform::SystemInfoProvider for FreeBSDUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as usize
    }
}

impl FreeBSDUserland {
    // todo(chuqi): support x86
    fn get_thread_local_storage() -> *mut litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>
    {
        let tls = unsafe { litebox_common_linux::rdgsbase() };
        if tls == 0 {
            return core::ptr::null_mut();
        }
        tls as *mut litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>
    }

    // // todo(chuqi): support x86
    // fn set_fs_selector(fss: u16) {
    //     unsafe {
    //         // Set the fs selector to the given value
    //         core::arch::asm!(
    //             "mov fs, {0:x}",
    //             in(reg) fss,
    //             options(nostack, preserves_flags)
    //         );
    //     }
    // }
}

/// Similar to libc, we use fs/gs registers to store thread-local storage (TLS).
/// To avoid conflicts with libc's TLS, we choose to use gs on x86_64 and fs on x86
/// as libc uses fs on x86_64 and gs on x86.
impl litebox::platform::ThreadLocalStorageProvider for FreeBSDUserland {
    // todo(chuqi): we may change the TLS type later on to adapt FreeBSD's robust_list
    // tbd anyways
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>;

    // todo(chuqi): support x86
    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        // todo(chuqi): temporarily disable the check for FreeBSD, because FreeBSD's
        // child thread (from thr_new) creation will inherit the parent's gs

        // let old_gs_base = unsafe { litebox_common_linux::rdgsbase() };
        // assert!(old_gs_base == 0, "TLS already set for this thread");
        let tls = Box::new(tls);
        unsafe { litebox_common_linux::wrgsbase(Box::into_raw(tls) as usize) };
    }

    // todo(chuqi): support x86
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
    use litebox::platform::{RawMutex, ThreadLocalStorageProvider as _};
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
        let platform = FreeBSDUserland::new(None);

        platform.debug_log_print("msg from FreeBSDUserland test_reserved_pages\n");

        let reserved_pages: Vec<_> =
            <FreeBSDUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        println!("SASS, reserved pages: {:?}", reserved_pages);

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
        let platform = FreeBSDUserland::new(None);
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
