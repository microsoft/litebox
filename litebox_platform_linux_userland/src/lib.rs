//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86/x86-64
// Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]

use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer, ThreadLocalStorageProvider};
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{CloneFlags, MRemapFlags, MapFlags, ProtFlags, PunchthroughSyscall};

mod syscall_intercept;

extern crate alloc;

/// Connector to a shim-exposed syscall-handling interface.
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<LinuxUserland>) -> isize;

/// The syscall handler passed down from the shim.
static SYSCALL_HANDLER: std::sync::RwLock<Option<SyscallHandler>> = std::sync::RwLock::new(None);

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    seccomp_interception_enabled: std::sync::atomic::AtomicBool,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
}

impl LinuxUserland {
    /// Create a new userland-Linux platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        let tun_socket_fd = tun_device_name
            .map(|tun_device_name| {
                let tun_fd = nix::fcntl::open(
                    "/dev/net/tun",
                    nix::fcntl::OFlag::O_RDWR
                        | nix::fcntl::OFlag::O_CLOEXEC
                        | nix::fcntl::OFlag::O_NONBLOCK,
                    nix::sys::stat::Mode::empty(),
                )
                .unwrap();

                nix::ioctl_write_ptr!(tunsetiff, b'T', 202, ::core::ffi::c_int);
                let ifreq = libc::ifreq {
                    ifr_name: {
                        let mut name = [0i8; 16];
                        assert!(tun_device_name.len() < 16); // Note: strictly-less-than 16, to ensure it fits
                        for (i, b) in tun_device_name.char_indices() {
                            let b = b as u32;
                            assert!(b < 128);
                            name[i] = i8::try_from(b).unwrap();
                        }
                        name
                    },
                    ifr_ifru: nix::libc::__c_anonymous_ifr_ifru {
                        // IFF_NO_PI: no tun header
                        // IFF_TUN: create tun (i.e., IP)
                        ifru_flags: i16::try_from(nix::libc::IFF_TUN | nix::libc::IFF_NO_PI)
                            .unwrap(),
                    },
                };
                let ifreq: *const libc::ifreq = &ifreq as _;
                let ifreq: *const i32 = ifreq.cast();
                unsafe { tunsetiff(tun_fd, ifreq) }.unwrap();

                // By taking ownership, we are letting the drop handler automatically run `libc::close`
                // when necessary.
                unsafe { std::os::fd::OwnedFd::from_raw_fd(tun_fd) }
            })
            .into();

        let platform = Self {
            tun_socket_fd,
            seccomp_interception_enabled: std::sync::atomic::AtomicBool::new(false),
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

    /// Enable seccomp syscall interception on the platform.
    ///
    /// # Panics
    ///
    /// Panics if this function has already been invoked on the platform earlier.
    pub fn enable_seccomp_based_syscall_interception(&self) {
        assert!(
            self.seccomp_interception_enabled
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst
                )
                .is_ok()
        );
        syscall_intercept::init_sys_intercept();
    }

    fn read_proc_self_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.
        let path = "/proc/self/maps";
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let Ok(fd) = fd else {
            return alloc::vec::Vec::new();
        };
        let mut buf = [0u8; 8192];
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    buf.len() - total_read,
                )
            }
            .expect("read failed");
            if n == 0 {
                break;
            }
            total_read += n;
        }
        assert!(total_read < buf.len(), "buffer too small");

        let mut reserved_pages = alloc::vec::Vec::new();
        let s = core::str::from_utf8(&buf[..total_read]).expect("invalid UTF-8");
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let range = parts[0].split('-').collect::<Vec<&str>>();
            let start = usize::from_str_radix(range[0], 16).expect("invalid start address");
            let end = usize::from_str_radix(range[1], 16).expect("invalid end address");
            reserved_pages.push(start..end);
        }
        reserved_pages
    }

    fn set_init_tls(&self) {
        let tid =
            unsafe { syscalls::syscall!(syscalls::Sysno::gettid) }.expect("Failed to get TID");

        let task = alloc::boxed::Box::new(litebox_common_linux::Task {
            tid: i32::try_from(tid).expect("tid should fit in i32"),
            clear_child_tid: None,
        });
        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }
}

impl litebox::platform::Provider for LinuxUserland {}

impl litebox::platform::ExitProvider for LinuxUserland {
    type ExitCode = i32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;

    fn exit(&self, code: Self::ExitCode) -> ! {
        let Self {
            tun_socket_fd,
            seccomp_interception_enabled: _,
            reserved_pages: _,
        } = self;
        // We don't need to explicitly drop this, but doing so clarifies our intent that we want to
        // close it out :). The type itself is re-specified here to make sure we look at this
        // particular function in case we decide to change up the types within `LinuxUserland`.
        drop::<Option<std::os::fd::OwnedFd>>(tun_socket_fd.write().unwrap().take());
        // And then we actually exit
        unsafe {
            syscalls::syscall2(
                syscalls::Sysno::exit_group,
                (code as isize).reinterpret_as_unsigned(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("Failed to exit group");

        unreachable!("exit_group should not return");
    }
}

#[unsafe(no_mangle)]
extern "C" fn thread_start(
    pt_regs: *mut litebox_common_linux::PtRegs,
    thread_args: *mut litebox_common_linux::NewThreadArgs<LinuxUserland>,
) -> ! {
    let pt_regs = unsafe { alloc::boxed::Box::from_raw(pt_regs) };
    // copy pt_regs from heap to stack
    let copied = *pt_regs;
    drop(pt_regs);

    // Reset TLS for the new thread
    #[cfg(target_arch = "x86_64")]
    unsafe {
        litebox_common_linux::wrgsbase(0);
    }
    #[cfg(target_arch = "x86")]
    LinuxUserland::set_fs_selector(0);

    // Allow caller to run some code before we return to the new thread.
    let thread_args = unsafe { alloc::boxed::Box::from_raw(thread_args) };
    (thread_args.callback)(*thread_args);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "xor rax, rax",
            "mov rsp, {0}",
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
            "ret",
            in(reg) &raw const copied.r11, // restore registers, starting from r11
            out("rax") _,
            options(nostack, preserves_flags)
        );
    }

    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!(
            "xor eax, eax",
            "mov esp, {0}",
            "pop ebx",
            "pop ecx",
            "pop edx",
            "pop esi",
            "pop edi",
            "pop ebp",
            "add esp, 32", // skip eax, xds, xes, xfs, xgs, orig_eax, eip, xcs,
            "popfd",
            "pop esp", // restore the stack pointer (which points to the entry point of the thread
            "ret",
            in(reg) &raw const copied,
            out("eax") _,
            options(nostack, preserves_flags)
        );
    }

    unreachable!();
}

impl litebox::platform::ThreadProvider for LinuxUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadArgs = litebox_common_linux::NewThreadArgs<LinuxUserland>;
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
            + core::mem::offset_of!(litebox_common_linux::Task<LinuxUserland>, tid) as u64;
        // new process/thread may have a different stack and thus does not have access to
        // the pt_regs (on the original stack), so we need to copy it to heap.
        let new_pt_regs = Box::into_raw(Box::new(*ctx));
        let thread_args = Box::into_raw(thread_args);
        let flags = CloneFlags::THREAD
            | CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::SYSVSEM
            | CloneFlags::CHILD_SETTID;

        let clone_args = litebox_common_linux::CloneArgs {
            flags,
            pidfd: 0,
            child_tid: child_tid_ptr,
            parent_tid: 0,
            exit_signal: 0,
            stack: stack.as_usize() as u64,
            stack_size: stack_size as u64,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        let mut ret: usize;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "syscall",
                "cmp rax, 0",
                "jne 2f",
                "push {0}", // push the return address
                "mov rdi, {1}",
                "mov [rdi + {rsp_offset}], rsp",    // save the current stack pointer to pt_regs.rsp
                "mov rsi, {2}",
                "jmp thread_start",
                // should never return
                "hlt",
                "2:",
                in(reg) entry_point,
                in(reg) new_pt_regs,
                in(reg) thread_args,
                rsp_offset = const core::mem::offset_of!(litebox_common_linux::PtRegs, rsp),
                inlateout("rax") syscalls::Sysno::clone3 as usize => ret,
                in("rdi") &raw const clone_args,
                in("rsi") size_of::<litebox_common_linux::CloneArgs>(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                in("rdx") syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
                out("rcx") _, // rcx is used to store old rip
                out("r11") _, // r11 is used to store old rflags
                options(nostack, preserves_flags)
            );
        }
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!(
                "int 0x80",
                "cmp eax, 0",
                "jne 2f",
                "push {0}", // save the return address
                "mov ebx, {1}",
                "mov [ebx + {esp_offset}], esp", // save the current stack pointer to pt_regs.esp
                "push {2}",
                "push ebx",
                "call thread_start",
                // should never return
                "hlt",
                "2:",
                in(reg) entry_point,
                in(reg) new_pt_regs,
                in(reg) thread_args,
                esp_offset = const core::mem::offset_of!(litebox_common_linux::PtRegs, esp),
                inlateout("eax") syscalls::Sysno::clone3 as usize => ret,
                in("ebx") &raw const clone_args,
                in("ecx") size_of::<litebox_common_linux::CloneArgs>(),
                options(nostack, preserves_flags)
            );
        }
        if ret > (-4096isize).reinterpret_as_unsigned() {
            drop(unsafe { alloc::boxed::Box::from_raw(new_pt_regs) });
            drop(unsafe { alloc::boxed::Box::from_raw(thread_args) });
            let errno: i32 = ret.reinterpret_as_signed().truncate();
            let err = syscalls::Errno::new(-errno);
            return Err(match err {
                syscalls::Errno::EACCES => litebox_common_linux::errno::Errno::EACCES,
                syscalls::Errno::EAGAIN => litebox_common_linux::errno::Errno::EAGAIN,
                syscalls::Errno::EBUSY => litebox_common_linux::errno::Errno::EBUSY,
                syscalls::Errno::EEXIST => litebox_common_linux::errno::Errno::EEXIST,
                syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                syscalls::Errno::ENOMEM => litebox_common_linux::errno::Errno::ENOMEM,
                syscalls::Errno::ENOSPC => litebox_common_linux::errno::Errno::ENOSPC,
                syscalls::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
                _ => panic!("unexpected error {err}"),
            });
        }
        Ok(ret)
    }

    fn terminate_thread(&self, code: Self::ExitCode) -> ! {
        unsafe {
            syscalls::syscall2(
                syscalls::Sysno::exit,
                (code as isize).reinterpret_as_unsigned(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("Failed to exit");

        unreachable!("exit should not return");
    }
}

impl litebox::platform::RawMutexProvider for LinuxUserland {
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

            // We wait on the futex, with a timeout if needed; the timeout is based on how much time
            // remains to be elapsed.
            match futex_timeout(
                &self.num_to_wake_up,
                FutexOperation::Wait,
                /* expected value */ 0,
                remaining_time,
                /* ignored */ None,
                /* ignored */ 0,
            ) {
                Ok(0) => {
                    // Fallthrough: check if spurious.
                }
                Err(syscalls::Errno::EAGAIN) => {
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
                    panic!("Unexpected errno={e} for FUTEX_WAIT")
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
        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        // We restrict ourselves to a max of ~1 billion waiters being woken up at once, which should
        // be good enough, but makes sure we are not clobbering the "lock bits".
        let n = n.min((1 << 30) - 1);

        // We first requeue all the waiters into a temporary queue, so that anyone else showing up
        // to block is not going to be impacted.
        let temp_q = AtomicU32::new(0);
        match futex_val2(
            &self.num_to_wake_up,
            FutexOperation::Requeue,
            /* number to wake up */ 0,
            /* number to requeue */ i32::MAX as u32,
            Some(&temp_q),
            /* val3: ignored */ 0,
        ) {
            Ok(_) => {
                // On success, returns the number of tasks requeued or woken, which we ignore
            }
            _ => unreachable!(),
        }

        // Then, we set the number of waiters we want allowed to know that they can wake up, while
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

        // Now we can actually wake them up; if anyone is left unwoken though, we should move them
        // back into the main queue.
        let num_woken_or_requeued = futex_val2(
            &temp_q,
            FutexOperation::Requeue,
            /* number to wake up */ n,
            /* number to requeue */ i32::MAX as u32,
            Some(&self.num_to_wake_up),
            /* val3: ignored */ 0,
        )
        .unwrap();
        let num_woken_up = core::cmp::min(n, u32::try_from(num_woken_or_requeued).unwrap());

        // Unlock the lock bits, allowing other wakers to run.
        let remain = n - num_woken_up;
        while let Err(v) = self.num_to_wake_up.fetch_update(SeqCst, SeqCst, |v| {
            // Due to spurious or immediate wake-ups (i.e., unexpected wakeups that may decrease `num_to_wake_up`),
            // `num_to_wake_up` might end up being less than expected. Thus, we check `<=` rather than `==`.
            if v & ((1 << 30) - 1) <= remain {
                Some(0)
            } else {
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

impl litebox::platform::IPInterfaceProvider for LinuxUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        match unsafe {
            syscalls::syscall4(
                syscalls::Sysno::write,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_ptr() as usize,
                packet.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        } {
            Ok(n) => {
                if n != packet.len() {
                    unimplemented!("unexpected size {n}")
                }
                Ok(())
            }
            Err(errno) => {
                unimplemented!("unexpected error {errno}")
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::read,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_mut_ptr() as usize,
                packet.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .map_err(|errno| match errno {
            #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
            syscalls::Errno::EWOULDBLOCK | syscalls::Errno::EAGAIN => {
                litebox::platform::ReceiveError::WouldBlock
            }
            _ => unimplemented!("unexpected error {errno}"),
        })
    }
}

impl litebox::platform::TimeProvider for LinuxUserland {
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

// from asm/hwcap2.h
#[cfg(target_arch = "x86_64")]
const HWCAP2_FSGSBASE: u64 = 1 << 1;

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
        if unsafe { libc::getauxval(libc::AT_HWCAP2) } & HWCAP2_FSGSBASE != 0 {
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
        if unsafe { libc::getauxval(libc::AT_HWCAP2) } & HWCAP2_FSGSBASE != 0 {
            |fs_base| {
                unsafe { litebox_common_linux::wrfsbase(fs_base) };
                Ok(0)
            }
        } else {
            set_fs_base_arch_prctl
        }
    })(fs_base)
}

/// Get fs register value via syscall `arch_prctl`.
#[cfg(target_arch = "x86_64")]
fn get_fs_base_arch_prctl() -> Result<usize, litebox_common_linux::errno::Errno> {
    let mut fs_base = core::mem::MaybeUninit::<usize>::uninit();
    unsafe {
        syscalls::syscall3(
            syscalls::Sysno::arch_prctl,
            litebox_common_linux::ArchPrctlCode::GetFs as usize,
            fs_base.as_mut_ptr() as usize,
            // Unused by the syscall but would be checked by Seccomp filter if enabled.
            syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
        )
    }
    .map_err(|err| match err {
        syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        syscalls::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
        _ => unimplemented!("unexpected error {err}"),
    })?;
    Ok(unsafe { fs_base.assume_init() })
}

/// Set fs register value via syscall `arch_prctl`.
#[cfg(target_arch = "x86_64")]
fn set_fs_base_arch_prctl(fs_base: usize) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe {
        syscalls::syscall3(
            syscalls::Sysno::arch_prctl,
            litebox_common_linux::ArchPrctlCode::SetFs as usize,
            fs_base,
            // Unused by the syscall but would be checked by Seccomp filter if enabled.
            syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
        )
    }
    .map_err(|err| match err {
        syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        syscalls::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
        _ => unimplemented!("unexpected error {err}"),
    })
}

#[cfg(target_arch = "x86")]
fn set_thread_area(
    user_desc: litebox::platform::trivial_providers::TransparentMutPtr<
        litebox_common_linux::UserDesc,
    >,
) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe { syscalls::syscall1(syscalls::Sysno::set_thread_area, user_desc.as_usize()) }.map_err(
        |err| match err {
            syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
            syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
            syscalls::Errno::ENOSYS => litebox_common_linux::errno::Errno::ENOSYS,
            syscalls::Errno::ESRCH => litebox_common_linux::errno::Errno::ESRCH,
            _ => panic!("unexpected error {err}"),
        },
    )
}

pub struct PunchthroughToken {
    punchthrough: PunchthroughSyscall<LinuxUserland>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = PunchthroughSyscall<LinuxUserland>;
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
                let set = match set {
                    Some(ptr) => {
                        let mut set = unsafe { ptr.read_at_offset(0) }
                            .ok_or(litebox::platform::PunchthroughError::Failure(
                                litebox_common_linux::errno::Errno::EFAULT,
                            ))?
                            .into_owned();
                        // never block SIGSYS (required by Seccomp to intercept syscalls)
                        set.remove(litebox_common_linux::Signal::SIGSYS);
                        Some(set)
                    }
                    None => None,
                };
                unsafe {
                    syscalls::syscall5(
                        syscalls::Sysno::rt_sigprocmask,
                        how as usize,
                        if let Some(set) = set.as_ref() {
                            core::ptr::from_ref(set) as usize
                        } else {
                            0
                        },
                        oldset.map_or(0, |ptr| ptr.as_usize()),
                        size_of::<litebox_common_linux::SigSet>(),
                        // Unused by the syscall but would be checked by Seccomp filter if enabled.
                        syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
                    )
                }
                .map_err(|err| match err {
                    syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::RtSigaction {
                signum,
                act,
                oldact,
            } => {
                if signum == litebox_common_linux::Signal::SIGSYS && act.is_some() {
                    // don't allow changing the SIGSYS handler
                    return Err(litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EINVAL,
                    ));
                }

                let act = act.map_or(0, |ptr| ptr.as_usize());
                let oldact = oldact.map_or(0, |ptr| ptr.as_usize());
                unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::rt_sigaction,
                        signum as usize,
                        act,
                        oldact,
                        size_of::<litebox_common_linux::SigSet>(),
                    )
                }
                .map_err(|err| match err {
                    syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::SetFsBase { addr } => {
                set_fs_base(addr).map_err(litebox::platform::PunchthroughError::Failure)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::GetFsBase { addr } => {
                use litebox::platform::RawMutPointer as _;
                let fs_base =
                    get_fs_base().map_err(litebox::platform::PunchthroughError::Failure)?;
                unsafe { addr.write_at_offset(0, fs_base) }.ok_or(
                    litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EFAULT,
                    ),
                )?;
                Ok(0)
            }
            #[cfg(target_arch = "x86")]
            PunchthroughSyscall::SetThreadArea { user_desc } => {
                set_thread_area(user_desc).map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::WakeByAddress { addr } => unsafe {
                syscalls::syscall6(
                    syscalls::Sysno::futex,
                    addr.as_usize(),
                    usize::try_from(FutexOperation::Wake as i32).unwrap(),
                    1,
                    0,
                    0,
                    0,
                )
            }
            .map_err(|err| match err {
                syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                _ => panic!("unexpected error {err}"),
            })
            .map_err(litebox::platform::PunchthroughError::Failure),
        }
    }
}

impl litebox::platform::PunchthroughProvider for LinuxUserland {
    type PunchthroughToken = PunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for LinuxUserland {
    fn debug_log_print(&self, msg: &str) {
        let _ = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::write,
                libc::STDERR_FILENO as usize,
                msg.as_ptr() as usize,
                msg.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        };
    }
}

impl litebox::platform::RawPointerProvider for LinuxUserland {
    type RawConstPointer<T: Clone> = litebox::platform::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = litebox::platform::trivial_providers::TransparentMutPtr<T>;
}

/// Operations currently supported by the safer variants of the Linux futex syscall
/// ([`futex_timeout`] and [`futex_val2`]).
#[repr(i32)]
enum FutexOperation {
    Wait = libc::FUTEX_WAIT,
    Requeue = libc::FUTEX_REQUEUE,
    Wake = libc::FUTEX_WAKE,
}

/// Safer invocation of the Linux futex syscall, with the "timeout" variant of the arguments.
#[expect(clippy::similar_names, reason = "sec/nsec are as needed by libc")]
fn futex_timeout(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    timeout: Option<Duration>,
    uaddr2: Option<&AtomicU32>,
    val3: u32,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = uaddr as _;
    let futex_op: i32 = futex_op as _;
    let timeout = timeout.map(|t| {
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
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            syscalls::Sysno::futex,
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            if let Some(t) = timeout.as_ref() {
                core::ptr::from_ref(t) as usize
            } else {
                0 // No timeout
            },
            uaddr2 as usize,
            val3 as usize,
        )
    }
}

/// Safer invocation of the Linux futex syscall, with the "val2" variant of the arguments.
fn futex_val2(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    val2: u32,
    uaddr2: Option<&AtomicU32>,
    val3: u32,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = uaddr as _;
    let futex_op: i32 = futex_op as _;
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            syscalls::Sysno::futex,
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            val2 as usize,
            uaddr2 as usize,
            val3 as usize,
        )
    }
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

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    fn allocate_pages(
        &self,
        range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | MapFlags::MAP_FIXED
            | (if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            } | if populate_pages {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            });
        let ptr = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                range.start,
                range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                (flags.bits().reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::systrap::MMAP_FLAG_MAGIC) as usize,
                usize::MAX,
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
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::munmap,
                range.start,
                range.len(),
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let res = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                (MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_MAYMOVE).bits() as usize,
                new_range.start,
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
            .expect("mremap failed")
        };
        assert_eq!(res, new_range.start);
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: res as *mut u8,
        })
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

impl litebox::platform::StdioProvider for LinuxUserland {
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
            syscalls::syscall4(
                syscalls::Sysno::write,
                usize::try_from(match stream {
                    litebox::platform::StdioOutStream::Stdout => libc::STDOUT_FILENO,
                    litebox::platform::StdioOutStream::Stderr => libc::STDERR_FILENO,
                })
                .unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        } {
            Ok(n) => Ok(n),
            Err(syscalls::Errno::EPIPE) => Err(litebox::platform::StdioWriteError::Closed),
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
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, LinuxUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for LinuxUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );
        unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                0,
                size,
                ProtFlags::PROT_READ_WRITE.bits().reinterpret_as_unsigned() as usize,
                ((MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON)
                    .bits()
                    .reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::systrap::MMAP_FLAG_MAGIC) as usize,
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

#[cfg(target_arch = "x86_64")]
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
    pushf              /* pt_regs->eflags */
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
    popf
    add  rsp, 16         /* skip rsp, ss */

    /* Return to the caller */
    ret
"
);

/*
 * Syscall callback function for 32-bit x86
 *
 * The stack layout at the entry of the callback (see litebox_syscall_rewriter
 * for more details):
 *
 * Addr |   data   |
 * 0    | sysno    |
 * -4:  | ret addr |  <-- esp
 *
 * The first two instructions adjust the stack such that it saves one
 * instruction (i.e., `pop sysno`) from the caller (trampoline code).
*/
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    "
    .text
    .align  4
    .globl  syscall_callback
    .type   syscall_callback,@function
syscall_callback:
    pop  eax        /* pop ret addr */
    xchg eax, [esp] /* exchange it with sysno */

    /* Save registers and constructs pt_regs */
    push    0x2b       /* pt_regs->xss = __USER_DS */
    push    esp        /* pt_regs->esp */
    pushf              /* pt_regs->eflags */
    push    0x33       /* pt_regs->xcs = __USER_CS */
    push    ecx
    mov     ecx, [esp + 0x14] /* get the return address from the stack */
    xchg    ecx, [esp] /* pt_regs->eip */
    push    eax        /* pt_regs->orig_ax */

    sub esp, 16         /* skip xgs, fs, xes, and xds */

    push    -38         /* pt_regs->eax = ENOSYS */
    push    ebp          /* pt_regs->ebp */
    push    edi         /* pt_regs->edi */
    push    esi         /* pt_regs->esi */
    push    edx         /* pt_regs->edx */
    push    ecx         /* pt_regs->ecx */
    push    ebx         /* pt_regs->ebx */

    /* Save the original stack pointer */
    mov ebp, esp
    /* Align the stack to 16 bytes */
    and esp, -16

    /* Pass the sysno and pointer to pt_regs to syscall_handler */
    push ebp
    push eax

    call syscall_handler

    mov esp, ebp
    pop ebx
    pop ecx
    pop edx
    pop esi
    pop edi
    pop ebp

    add esp, 32         /* skip eax, xds, xes, xfs, xgs, orig_eax, eip, xcs */
    popf
    add  esp, 8         /* skip esp, ss */

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

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as usize
    }
}

impl LinuxUserland {
    #[cfg(target_arch = "x86_64")]
    fn get_thread_local_storage() -> *mut litebox_common_linux::ThreadLocalStorage<LinuxUserland> {
        let tls = unsafe { litebox_common_linux::rdgsbase() };
        if tls == 0 {
            return core::ptr::null_mut();
        }
        tls as *mut litebox_common_linux::ThreadLocalStorage<LinuxUserland>
    }

    #[cfg(target_arch = "x86")]
    fn get_thread_local_storage() -> *mut litebox_common_linux::ThreadLocalStorage<LinuxUserland> {
        let mut fs_selector: u16;
        unsafe {
            core::arch::asm!(
                "mov {0:x}, fs",
                out(reg) fs_selector,
                options(nostack, preserves_flags)
            );
        }
        if fs_selector == 0 {
            return core::ptr::null_mut();
        }

        let mut addr: usize;
        unsafe {
            core::arch::asm!(
                "mov {0}, fs:{offset}",
                out(reg) addr,
                offset = const core::mem::offset_of!(litebox_common_linux::ThreadLocalStorage<LinuxUserland>, self_ptr),
                options(nostack, preserves_flags)
            );
        }
        addr as *mut litebox_common_linux::ThreadLocalStorage<LinuxUserland>
    }

    #[cfg(target_arch = "x86")]
    fn set_fs_selector(fss: u16) {
        unsafe {
            core::arch::asm!(
                "mov fs, {0:x}",
                in(reg) fss,
                options(nostack, preserves_flags)
            );
        }
    }
}

/// Similar to libc, we use fs/gs registers to store thread-local storage (TLS).
/// To avoid conflicts with libc's TLS, we choose to use gs on x86_64 and fs on x86
/// as libc uses fs on x86_64 and gs on x86.
impl litebox::platform::ThreadLocalStorageProvider for LinuxUserland {
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<LinuxUserland>;

    #[cfg(target_arch = "x86_64")]
    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        let old_gs_base = unsafe { litebox_common_linux::rdgsbase() };
        assert!(old_gs_base == 0, "TLS already set for this thread");
        let tls = Box::new(tls);
        unsafe { litebox_common_linux::wrgsbase(Box::into_raw(tls) as usize) };
    }

    #[cfg(target_arch = "x86")]
    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        let mut old_fs_selector: u16;
        unsafe {
            core::arch::asm!(
                "mov {0:x}, fs",
                out(reg) old_fs_selector,
                options(nostack, preserves_flags)
            );
        }
        assert!(old_fs_selector == 0, "TLS already set for this thread");

        let mut tls = Box::new(tls);
        tls.self_ptr = tls.as_mut();

        let mut flags = litebox_common_linux::UserDescFlags(0);
        flags.set_seg_32bit(true);
        flags.set_useable(true);
        let mut user_desc = litebox_common_linux::UserDesc {
            entry_number: u32::MAX,
            base_addr: Box::into_raw(tls) as u32,
            limit: u32::try_from(core::mem::size_of::<Self::ThreadLocalStorage>()).unwrap() - 1,
            flags,
        };
        let user_desc_ptr = litebox::platform::trivial_providers::TransparentMutPtr {
            inner: &raw mut user_desc,
        };
        set_thread_area(user_desc_ptr).expect("Failed to set thread area for TLS");

        let new_fs_selector = ((user_desc.entry_number & 0xfff) << 3) | 0x3; // user mode
        Self::set_fs_selector(new_fs_selector.truncate());
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86")]
    fn release_thread_local_storage(&self) -> Self::ThreadLocalStorage {
        let tls = Self::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before releasing it");
        Self::set_fs_selector(0); // reset fs selector

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
        tls.borrowed = true; // mark as borrowed
        let ret = f(tls);
        tls.borrowed = false; // mark as not borrowed anymore
        ret
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use litebox::platform::{RawMutex, ThreadLocalStorageProvider as _};

    use crate::LinuxUserland;
    use litebox::platform::PageManagementProvider;

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
        let platform = LinuxUserland::new(None);
        let reserved_pages: Vec<_> =
            <LinuxUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

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
        let platform = LinuxUserland::new(None);
        let tls = LinuxUserland::get_thread_local_storage();
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

        let tls = LinuxUserland::get_thread_local_storage();
        assert!(tls.is_null(), "TLS should be null after releasing it");
    }
}
